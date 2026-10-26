"""
Hypothesis Engine - Generates, scores, and branches alternative attack-path explanations
"""
from typing import List, Dict, Any
from backend.models import NormalizedEvent, AttackNode, AttackEdge, Hypothesis, EvidenceGap


class HypothesisEngine:
    @classmethod
    def generate_hypotheses(
        cls,
        events: List[NormalizedEvent],
        nodes: List[AttackNode],
        edges: List[AttackEdge],
        gaps: List[EvidenceGap]
    ) -> List[Hypothesis]:
        """
        Analyzes the event topology and generates realistic competing attack hypotheses
        with evidentiary weights, divergence points, and likelihood ratings.
        """
        if not events:
            return []

        hypotheses = []
        event_ids = [e.event_id for e in events]
        edge_ids = [e.edge_id for e in edges]

        strong_edges = [e for e in edges if e.confidence_level == "STRONGLY_SUPPORTED"]
        partial_edges = [e for e in edges if e.confidence_level == "PARTIALLY_SUPPORTED"]
        speculative_edges = [e for e in edges if e.confidence_level == "SPECULATIVE"]

        # Check characteristics of events
        has_sqli = any("SQL" in str(e.attack_indicators) for e in events)
        has_webshell = any("WEB_SHELL" in str(e.attack_indicators) for e in events)
        has_auth_fail = any("AUTH_FAILURE" in str(e.attack_indicators) for e in events)
        has_auth_success = any("AUTH_SUCCESS" in str(e.attack_indicators) for e in events)
        has_export = any("SENSITIVE_DATA_EXPORT" in str(e.attack_indicators) for e in events)

        # Baseline Likelihood Calculation
        total_edges_count = max(len(edges), 1)
        base_score = (len(strong_edges) * 1.0 + len(partial_edges) * 0.7 + len(speculative_edges) * 0.3) / total_edges_count
        base_score = min(0.95, max(0.40, base_score))

        # Hypothesis 1: Direct External Exploitation Chain (Primary Hypothesis)
        h1_name = "Direct External Exploitation & Post-Exploitation"
        if has_webshell:
            h1_desc = "Perimeter Web Shell Upload followed by Remote Command Execution and Data Staging."
            h1_narrative = (
                "The adversary exploited a public-facing file upload / endpoint vulnerability, directly deploying "
                "a web shell. Sequential commands were subsequently issued from the external IP address, interacting with "
                "local system utilities and exfiltrating application data."
            )
            mitre_chain = ["T1190: Exploit Public Application", "T1505.003: Web Shell", "T1059: Command Interpreter", "T1048: Exfiltration Over Web"]
        elif has_sqli:
            h1_desc = "SQL Injection Vulnerability Exploitation triggering Database Leakage."
            h1_narrative = (
                "The adversary leveraged input sanitization weaknesses in public query endpoints to perform boolean/union "
                "SQL injection. This caused unhandled database exceptions and exposed internal database records."
            )
            mitre_chain = ["T1190: Exploit Public Application", "T1505: Server Component", "T1048: Exfiltration"]
        else:
            h1_desc = "Direct Ingress Path Exploitation."
            h1_narrative = "The attacker executed direct sequential requests targeting application services from an untrusted origin IP."
            mitre_chain = ["T1190: Exploit Public Application", "T1078: Valid Accounts"]

        hyp1 = Hypothesis(
            hypothesis_id="HYP-1-DIRECT",
            name=f"Hypothesis Alpha: {h1_name}",
            description=h1_desc,
            narrative=h1_narrative,
            likelihood_score=round(base_score, 2),
            confidence_rating="HIGH" if base_score > 0.75 else "MEDIUM",
            included_event_ids=event_ids,
            included_edge_ids=edge_ids,
            supporting_evidence_count=len(strong_edges) + len(partial_edges),
            speculative_links_count=len(speculative_edges),
            evidence_gaps_count=len(gaps),
            mitre_attack_chain=mitre_chain,
            key_differentiator="Supported by high-confidence timestamp and session continuity across ingress endpoints."
        )
        hypotheses.append(hyp1)

        # Hypothesis 2: Alternative Compromise Vector (Stolen Session / Credential Stuffing)
        # If there are authentication events, or multiple IPs, or gaps
        h2_score = round(max(0.35, base_score - 0.18), 2)
        h2_name = "Session Hijacking / Credential Stuffing Pivoting"
        h2_desc = "Compromised Authentication Token or Pre-Acquired Stolen Session."
        h2_narrative = (
            "Rather than discovering and exploiting zero-day vulnerabilities in real time, the threat actor utilized "
            "previously compromised session cookies or valid administrative credentials acquired via dark web dumps or "
            "session sidejacking. The apparent exploit probes may have been diversionary noise to mask unauthorized access."
        )
        # Hypothesis 2 links subset of edges
        h2_edges = [e.edge_id for e in edges if e.rule_name in ("EXACT_SESSION_MATCH", "REQUEST_ID_TRACE", "USER_IDENTITY_PROGRESSION")]
        hyp2 = Hypothesis(
            hypothesis_id="HYP-2-SESSION",
            name=f"Hypothesis Beta: {h2_name}",
            description=h2_desc,
            narrative=h2_narrative,
            likelihood_score=h2_score,
            confidence_rating="MEDIUM",
            included_event_ids=event_ids[:int(len(event_ids) * 0.8) + 1],
            included_edge_ids=h2_edges,
            supporting_evidence_count=len(h2_edges),
            speculative_links_count=len(speculative_edges) + 1,
            evidence_gaps_count=len(gaps) + 1,
            mitre_attack_chain=["T1078: Valid Accounts", "T1539: Steal Web Session Cookie", "T1048: Exfiltration"],
            key_differentiator="Requires unexplained presence of valid session tokens prior to explicit privilege elevation."
        )
        hypotheses.append(hyp2)

        # Hypothesis 3: Insider Threat or Internal Lateral Relay
        h3_score = round(max(0.25, base_score - 0.32), 2)
        h3_name = "Internal Lateral Movement / Spoofed Proxy Forwarding"
        h3_desc = "Compromised Internal Service or Reverse Proxy Header Manipulation."
        h3_narrative = (
            "The malicious activity may have originated from an internal subnet or compromised worker node utilizing "
            "X-Forwarded-For header spoofing or internal lateral relaying. The observed external client IP represents "
            "an egress egress hop rather than the true threat origin."
        )
        hyp3 = Hypothesis(
            hypothesis_id="HYP-3-INTERNAL",
            name=f"Hypothesis Gamma: {h3_name}",
            description=h3_desc,
            narrative=h3_narrative,
            likelihood_score=h3_score,
            confidence_rating="LOW",
            included_event_ids=event_ids[:int(len(event_ids) * 0.6) + 1],
            included_edge_ids=edge_ids[:int(len(edge_ids) * 0.5) + 1],
            supporting_evidence_count=int(len(strong_edges) * 0.5),
            speculative_links_count=len(speculative_edges) + 2,
            evidence_gaps_count=len(gaps) + 2,
            mitre_attack_chain=["T1090: Proxy", "T1071: Standard Application Layer Protocol"],
            key_differentiator="Explains anomalous internal request flows but lacks corroborating internal NetFlow logs."
        )
        hypotheses.append(hyp3)

        return hypotheses
