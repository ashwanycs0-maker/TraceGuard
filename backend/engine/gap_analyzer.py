"""
Evidence Gap Analyzer - Detects missing logs, blind spots, and uncorroborated inferences
"""
from typing import List
from backend.models import NormalizedEvent, EvidenceGap


class EvidenceGapAnalyzer:
    @classmethod
    def analyze_gaps(cls, events: List[NormalizedEvent]) -> List[EvidenceGap]:
        """
        Scans normalized events for uncorroborated transitions, unauthenticated privileged
        access, missing database audit trails, and missing host/network telemetry.
        """
        gaps: List[EvidenceGap] = []
        if not events:
            return gaps

        has_auth_success = any("AUTH_SUCCESS" in e.attack_indicators or (e.endpoint and "/login" in e.endpoint and e.status_code == 200) for e in events)
        has_privileged_access = any("PRIVILEGED_ENDPOINT_ACCESS" in e.attack_indicators or (e.endpoint and any(p in e.endpoint for p in ["/admin", "/export", "/backup", "/api/v1/users"])) for e in events)
        has_sqli = any("SQL_INJECTION_ATTEMPT" in e.attack_indicators for e in events)
        has_db_log = any(e.source_type == "app_log" and "sql" in str(e.extra_metadata).lower() for e in events)
        has_webshell = any("WEB_SHELL" in str(e.attack_indicators) or "COMMAND_INJECTION" in str(e.attack_indicators) for e in events)
        has_edr_log = any(e.source_type in ("syslog", "edr", "auditd") and "process" in str(e.extra_metadata).lower() for e in events)
        has_exfiltration = any("SENSITIVE_DATA_EXPORT" in str(e.attack_indicators) for e in events)
        has_netflow = any(e.source_type == "pcap_network" for e in events)
        has_waf = any(e.source_type == "waf_alert" for e in events)

        # Gap 1: Privileged Access without Prior Authentication Log
        if has_privileged_access and not has_auth_success:
            gaps.append(EvidenceGap(
                gap_id="GAP-AUTH-01",
                title="Missing Authentication Record Prior to Privileged Access",
                description=(
                    "Privileged endpoints (e.g. /admin, /api/v1/export) were accessed and executed successfully, "
                    "but no corresponding authentication event, SSO audit record, or login session initialization was observed."
                ),
                severity="HIGH",
                expected_log_type="Identity Provider / Application Auth Log (/login, OAuth2/OIDC)",
                recommended_action="Incorporate IdP/SSO authentication logs or inspect session token generation service.",
                affected_hypotheses=["HYP-1-DIRECT", "HYP-2-SESSION"]
            ))

        # Gap 2: Exploit Attempt / Data Extraction without Database Audit Trail
        if has_sqli and not has_db_log:
            gaps.append(EvidenceGap(
                gap_id="GAP-DB-02",
                title="Missing Database Execution & Query Audit Trail",
                description=(
                    "SQL injection syntax was directed at web application endpoints causing 500 errors or successful data returns, "
                    "but granular database transaction logs (MySQL General Log, Postgres pg_stat_statements) are absent to prove whether rows were dumped."
                ),
                severity="HIGH",
                expected_log_type="Relational Database Audit / Slow Query Log",
                recommended_action="Ingest DB audit logs to confirm exact executed SQL statements and records accessed.",
                affected_hypotheses=["HYP-1-DIRECT"]
            ))

        # Gap 3: Web Shell / Command Injection without Host Process Telemetry
        if has_webshell and not has_edr_log:
            gaps.append(EvidenceGap(
                gap_id="GAP-HOST-03",
                title="Missing Host Process Execution Audit (EDR/Sysmon)",
                description=(
                    "Web server received requests with web shell commands (e.g. cmd=whoami, cat /etc/passwd), "
                    "but endpoint detection logs (Linux auditd / Sysmon Event ID 1) are missing to verify if child processes were spawned by web worker."
                ),
                severity="HIGH",
                expected_log_type="Host EDR / Sysmon / Linux Auditd",
                recommended_action="Correlate host OS process creation logs to confirm whether the web shell achieved code execution.",
                affected_hypotheses=["HYP-1-DIRECT", "HYP-3-INTERNAL"]
            ))

        # Gap 4: Data Exfiltration without Outbound NetFlow Confirmation
        if has_exfiltration and not has_netflow:
            gaps.append(EvidenceGap(
                gap_id="GAP-NET-04",
                title="Missing Perimeter Egress NetFlow Confirmation",
                description=(
                    "Application records indicate substantial data payload generation or export, but network firewall "
                    "or VPC NetFlow records are missing to definitively verify outbound byte transmission to external adversary."
                ),
                severity="MEDIUM",
                expected_log_type="Firewall Traffic Logs / VPC Flow Logs / Full PCAP",
                recommended_action="Upload perimeter firewall egress logs or full packet capture covering this incident window.",
                affected_hypotheses=["HYP-1-DIRECT", "HYP-2-SESSION"]
            ))

        # Gap 5: High-Severity Web Attacks without Correlating WAF Alerts
        if (has_sqli or has_webshell) and not has_waf:
            gaps.append(EvidenceGap(
                gap_id="GAP-WAF-05",
                title="Unmonitored Gateway or WAF Inspection Bypass",
                description=(
                    "Exploitation attempts reached the web application server directly without corresponding ModSecurity / WAF "
                    "blocking or alert entries, suggesting either perimeter WAF bypass or uninspected ingress route."
                ),
                severity="LOW",
                expected_log_type="Web Application Firewall (WAF) / CDN Security Logs",
                recommended_action="Verify WAF rule coverage and inspect CDN routing rules for bypassed subdomains.",
                affected_hypotheses=["HYP-1-DIRECT", "HYP-3-INTERNAL"]
            ))

        return gaps
