"""
Correlation Engine - Multi-tier event correlation, cross-source matching, and confidence scoring
"""
from typing import List, Dict, Any, Tuple
from datetime import datetime
from backend.models import NormalizedEvent, AttackNode, AttackEdge


class CorrelationEngine:
    @staticmethod
    def parse_iso(ts: str) -> datetime:
        try:
            return datetime.strptime(ts.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
        except Exception:
            try:
                return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
            except Exception:
                return datetime.utcnow()

    @classmethod
    def correlate(cls, events: List[NormalizedEvent]) -> Tuple[List[AttackNode], List[AttackEdge]]:
        """
        Processes normalized events and builds attack nodes and evidence-linked edges
        with confidence ratings and explanations.
        """
        # Sort events chronologically
        events = sorted(events, key=lambda e: e.timestamp)
        if not events:
            return [], []

        nodes: List[AttackNode] = []
        edges: List[AttackEdge] = []
        event_dict: Dict[str, NormalizedEvent] = {e.event_id: e for e in events}

        # Filter nodes: include all events that have indicators, warnings, errors, or privileged access
        # If dataset is small (< 50), include all events for full timeline completeness
        is_small_dataset = len(events) <= 60

        selected_events = []
        for e in events:
            is_suspicious = (
                len(e.attack_indicators) > 0
                or e.severity in ("MEDIUM", "HIGH", "CRITICAL")
                or e.event_category in ("RECONNAISSANCE", "AUTHENTICATION", "EXPLOITATION", "PRIVILEGE_ESCALATION", "EXECUTION", "PERSISTENCE", "EXFILTRATION", "SYSTEM_ERROR")
                or (e.status_code and e.status_code in (401, 403, 500))
                or is_small_dataset
            )
            if is_suspicious:
                selected_events.append(e)

        if not selected_events:
            selected_events = events  # Fallback to all

        # Build AttackNodes
        for idx, e in enumerate(selected_events):
            is_entry = idx == 0 or e.event_category in ("RECONNAISSANCE", "AUTHENTICATION")
            is_pivot = e.event_category in ("AUTHENTICATION", "EXPLOITATION", "PERSISTENCE") and e.severity in ("HIGH", "CRITICAL")
            
            label = f"{e.http_method or e.source_type.upper()} {e.endpoint or ''}".strip()
            if not label or label == "APP_LOG":
                label = f"[{e.source_type.upper()}] {e.attack_indicators[0] if e.attack_indicators else e.event_category}"

            node = AttackNode(
                id=e.event_id,
                label=label,
                timestamp=e.timestamp,
                event_category=e.event_category,
                severity=e.severity,
                source_type=e.source_type,
                endpoint=e.endpoint,
                source_ip=e.source_ip,
                session_id=e.session_id,
                status_code=e.status_code,
                attack_indicators=e.attack_indicators,
                raw_hash=e.raw_hash,
                mitre_technique=e.mitre_techniques[0] if e.mitre_techniques else None,
                is_pivot_node=is_pivot,
                is_entry_point=is_entry,
                evidence_classification=e.evidence_classification,
                source_citation=e.source_citation,
                factual_source_url=e.factual_source_url,
                details={
                    "source_file": e.source_file,
                    "line_number": e.line_number,
                    "user": e.user,
                    "request_id": e.request_id,
                    "query_params": e.query_params
                }
            )
            nodes.append(node)

        # Build Edges with Correlation Rules
        # Pairwise search in a forward sliding window (up to 40 events forward or 3600 seconds)
        for i in range(len(selected_events)):
            e1 = selected_events[i]
            t1 = cls.parse_iso(e1.timestamp)

            connected_forward = 0
            for j in range(i + 1, min(i + 40, len(selected_events))):
                e2 = selected_events[j]
                t2 = cls.parse_iso(e2.timestamp)
                time_delta = abs((t2 - t1).total_seconds())

                if time_delta > 7200:  # Exceeds 2 hours window
                    continue

                matched_rule = None
                conf_level = None
                conf_score = 0.0
                explanation = ""
                matching_fields = {}

                # RULE 1: Exact Request ID Trace (Cross-Source Ingress <-> App)
                if e1.request_id and e2.request_id and e1.request_id == e2.request_id:
                    matched_rule = "REQUEST_ID_TRACE"
                    conf_level = "STRONGLY_SUPPORTED"
                    conf_score = 0.98
                    explanation = f"Exact correlation trace ID '{e1.request_id}' verified across {e1.source_type} and {e2.source_type}."
                    matching_fields = {"request_id": e1.request_id}

                # RULE 2: WAF Alert to Web Server Log Match
                elif (
                    (e1.source_type == "waf_alert" and e2.source_type in ("nginx", "apache"))
                    or (e2.source_type == "waf_alert" and e1.source_type in ("nginx", "apache"))
                ) and e1.source_ip == e2.source_ip and time_delta <= 10.0:
                    matched_rule = "WAF_PERIMETER_DETECTION_MATCH"
                    conf_level = "STRONGLY_SUPPORTED"
                    conf_score = 0.95
                    explanation = f"Security gateway alert correlated directly with web request from IP {e1.source_ip} within {time_delta:.1f}s."
                    matching_fields = {"source_ip": e1.source_ip, "time_delta": f"{time_delta}s"}

                # RULE 3: Exact Session ID Match
                elif e1.session_id and e2.session_id and e1.session_id == e2.session_id:
                    matched_rule = "EXACT_SESSION_MATCH"
                    conf_level = "STRONGLY_SUPPORTED"
                    conf_score = 0.92
                    explanation = f"Shared authenticated session token '{e1.session_id[:12]}...' across sequential actions ({time_delta:.1f}s apart)."
                    matching_fields = {"session_id": e1.session_id}

                # RULE 4: Cross-Source Causal Exploit -> Backend Error
                elif (
                    e1.source_type in ("nginx", "apache")
                    and e2.source_type in ("app_log", "syslog")
                    and (e1.status_code == 500 or any("SQL" in ind or "INJECTION" in ind for ind in e1.attack_indicators))
                    and time_delta <= 15.0
                ):
                    matched_rule = "CROSS_SOURCE_CAUSAL_ERROR"
                    conf_level = "STRONGLY_SUPPORTED"
                    conf_score = 0.88
                    explanation = f"Exploit request to '{e1.endpoint}' immediately triggered backend application crash/exception ({time_delta:.1f}s)."
                    matching_fields = {"endpoint": e1.endpoint, "source_type_pair": f"{e1.source_type}->{e2.source_type}"}

                # RULE 5: PCAP Flow Match
                elif (
                    (e1.source_type == "pcap_network" or e2.source_type == "pcap_network")
                    and e1.source_ip == e2.source_ip
                    and time_delta <= 5.0
                ):
                    matched_rule = "PCAP_PACKET_CORRELATION"
                    conf_level = "STRONGLY_SUPPORTED"
                    conf_score = 0.94
                    explanation = f"Network packet capture confirms raw TCP/HTTP flow matching IP {e1.source_ip} ({time_delta:.1f}s delta)."
                    matching_fields = {"source_ip": e1.source_ip}

                # RULE 6: Same Source IP + Time Proximity (Attack Progression)
                elif e1.source_ip and e2.source_ip and e1.source_ip == e2.source_ip and time_delta <= 180.0:
                    matched_rule = "IP_BURST_PROGRESSION"
                    conf_level = "PARTIALLY_SUPPORTED"
                    conf_score = 0.78
                    explanation = f"Same origin IP {e1.source_ip} advancing sequentially from {e1.event_category} to {e2.event_category}."
                    matching_fields = {"source_ip": e1.source_ip, "time_delta": f"{time_delta:.1f}s"}

                # RULE 7: Same User Context Progression
                elif e1.user and e2.user and e1.user == e2.user and time_delta <= 1800.0:
                    matched_rule = "USER_IDENTITY_PROGRESSION"
                    conf_level = "PARTIALLY_SUPPORTED"
                    conf_score = 0.72
                    explanation = f"Identical user account '{e1.user}' executing actions within {time_delta:.0f} seconds."
                    matching_fields = {"user": e1.user}

                # RULE 0: Publicly Reported Fact Progression
                elif (
                    e1.evidence_classification == "Publicly Reported Fact"
                    and e2.evidence_classification == "Publicly Reported Fact"
                    and j == i + 1
                ):
                    matched_rule = "OFFICIAL_REPORTED_STEP_PROGRESSION"
                    conf_level = "STRONGLY_SUPPORTED"
                    conf_score = 0.99
                    explanation = f"Chronological attack step sequence verified directly from official public investigation report ({e1.source_citation or e1.source_file})."
                    matching_fields = {"official_report": e1.source_citation or e1.source_file, "sequence": f"{e1.event_category} -> {e2.event_category}"}

                # RULE 8: Speculative Causal Link (Cross-IP Causal Handoff or Recon-to-Exploit)
                elif (
                    time_delta <= 600.0
                    and e1.event_category in ("RECONNAISSANCE", "EXPLOITATION")
                    and e2.event_category in ("PERSISTENCE", "EXFILTRATION")
                    and e1.endpoint == e2.endpoint
                ):
                    matched_rule = "SPECULATIVE_TARGET_ALIGNMENT"
                    conf_level = "SPECULATIVE"
                    conf_score = 0.45
                    explanation = f"Temporal and endpoint correlation on target '{e1.endpoint}', though IPs or credentials differ."
                    matching_fields = {"endpoint": e1.endpoint}

                if matched_rule:
                    edge = AttackEdge(
                        source_event_id=e1.event_id,
                        target_event_id=e2.event_id,
                        rule_name=matched_rule,
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        explanation=explanation,
                        time_delta_seconds=time_delta,
                        matching_fields=matching_fields,
                        supporting_evidence_ids=[e1.event_id, e2.event_id],
                        hypothesis_tags=["HYP-PRIMARY"]
                    )
                    edges.append(edge)
                    connected_forward += 1
                    # Avoid over-clustering: connect to at most 3 strongest forward candidates per node
                    if connected_forward >= 3:
                        break

        return nodes, edges
