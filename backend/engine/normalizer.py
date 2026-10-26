"""
Event Normalizer - Unifies multi-source events, detects attack indicators, and maps to MITRE ATT&CK
"""
import re
from typing import Dict, Any, List, Tuple
from backend.models import NormalizedEvent


class EventNormalizer:
    # Attack Indicator Signatures
    SQLI_PATTERNS = [
        re.compile(r'(?:union\s+select|select\s+.*\s+from|or\s+1=1|drop\s+table|insert\s+into|information_schema|waitfor\s+delay|sleep\(\d+\)|benchmark\()', re.IGNORECASE),
        re.compile(r'(?:%27|%22|\'|\")(?:.*)(?:or|and|union|select)', re.IGNORECASE)
    ]

    TRAVERSAL_PATTERNS = [
        re.compile(r'(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)', re.IGNORECASE),
        re.compile(r'(?:/etc/passwd|/windows/win\.ini|/proc/version|/etc/shadow)', re.IGNORECASE)
    ]

    COMMAND_INJ_PATTERNS = [
        re.compile(r'(?:;|\||&&|`|\$\()(?:.*)(?:whoami|id|cat\s+/|ls\s+-|nc\s+-|bash\s+-i|curl\s+http|wget\s+http)', re.IGNORECASE),
        re.compile(r'(?:cmd\.exe|/bin/sh|/bin/bash|powershell|chmod\s+\+x)', re.IGNORECASE)
    ]

    WEBSHELL_PATTERNS = [
        re.compile(r'(?:\.php|\.jsp|\.asp|\.aspx|\.phtml|\.cgi)(?:\?.*(?:cmd=|exec=|command=|c=|act=))', re.IGNORECASE),
        re.compile(r'(?:uploader\.php|shell\.php|c99\.php|r57\.php|b374k|weevely|alfa\.php)', re.IGNORECASE)
    ]

    SSRF_PATTERNS = [
        re.compile(r'(?:169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])', re.IGNORECASE)
    ]

    XSS_PATTERNS = [
        re.compile(r'(?:<script.*?>|javascript:|onload=|onerror=|alert\(|document\.cookie)', re.IGNORECASE)
    ]

    SENSITIVE_PATHS = [
        re.compile(r'(?:/admin|/backup|/dump|/export|/config|\.env|\.git|/api/v1/users|/api/v1/export|/db_backup|/metrics)', re.IGNORECASE)
    ]

    SCANNER_AGENTS = [
        re.compile(r'(?:sqlmap|nikto|nmap|acunetix|gobuster|dirbuster|wfuzz|nessus|masscan)', re.IGNORECASE)
    ]

    @classmethod
    def detect_indicators(cls, event_data: Dict[str, Any]) -> Tuple[List[str], List[str], List[str], str, str]:
        """
        Analyzes event fields and returns:
        (indicators, mitre_tactics, mitre_techniques, category, severity)
        """
        raw = event_data.get("raw_record", "")
        endpoint = event_data.get("endpoint") or ""
        query = event_data.get("query_params") or ""
        agent = event_data.get("user_agent") or ""
        status = event_data.get("status_code")
        source_type = event_data.get("source_type", "")
        extra = event_data.get("extra_metadata", {})

        target_str = f"{raw} {endpoint} {query} {agent} {str(extra)}"

        indicators = []
        tactics = []
        techniques = []
        category = "BENIGN_OR_ANOMALOUS"
        severity = "INFO"

        # Check Scanner Agents
        if cls.SCANNER_AGENTS[0].search(agent) or "scanner" in target_str.lower():
            indicators.append("AUTOMATED_SCANNER_DETECTED")
            tactics.append("Reconnaissance")
            techniques.append("T1595: Active Scanning")
            category = "RECONNAISSANCE"
            severity = "LOW"

        # Check SQL Injection
        for pat in cls.SQLI_PATTERNS:
            if pat.search(target_str):
                indicators.append("SQL_INJECTION_ATTEMPT")
                tactics.append("Initial Access")
                techniques.append("T1190: Exploit Public-Facing Application")
                category = "EXPLOITATION"
                severity = "HIGH" if (status == 200 or status == 500) else "MEDIUM"
                break

        # Check Directory Traversal
        for pat in cls.TRAVERSAL_PATTERNS:
            if pat.search(target_str):
                indicators.append("PATH_TRAVERSAL_ATTEMPT")
                tactics.append("Discovery")
                techniques.append("T1083: File and Directory Discovery")
                category = "EXPLOITATION"
                severity = "HIGH" if status == 200 else "MEDIUM"
                break

        # Check Web Shell
        for pat in cls.WEBSHELL_PATTERNS:
            if pat.search(target_str):
                indicators.append("WEB_SHELL_ACTIVITY")
                tactics.append("Persistence")
                techniques.append("T1505.003: Web Shell")
                category = "PERSISTENCE"
                severity = "CRITICAL"
                break

        # Check Command Injection
        for pat in cls.COMMAND_INJ_PATTERNS:
            if pat.search(target_str):
                indicators.append("COMMAND_INJECTION_EXEC")
                tactics.append("Execution")
                techniques.append("T1059: Command and Scripting Interpreter")
                category = "EXECUTION"
                severity = "CRITICAL"
                break

        # Check SSRF
        for pat in cls.SSRF_PATTERNS:
            if pat.search(target_str):
                indicators.append("SSRF_CLOUD_METADATA_PROBE")
                tactics.append("Discovery")
                techniques.append("T1552: Cloud Metadata API")
                category = "EXPLOITATION"
                severity = "HIGH"
                break

        # Check XSS
        for pat in cls.XSS_PATTERNS:
            if pat.search(target_str):
                indicators.append("XSS_PAYLOAD_DETECTED")
                category = "EXPLOITATION"
                severity = "MEDIUM"
                break

        # Check Sensitive Paths / Exfiltration
        for pat in cls.SENSITIVE_PATHS:
            if pat.search(endpoint) or pat.search(query):
                if any(w in endpoint.lower() for w in ["backup", "dump", "export", "database"]):
                    indicators.append("SENSITIVE_DATA_EXPORT")
                    tactics.append("Exfiltration")
                    techniques.append("T1048: Exfiltration Over Web Protocol")
                    category = "EXFILTRATION"
                    severity = "CRITICAL" if status == 200 else "HIGH"
                else:
                    indicators.append("PRIVILEGED_ENDPOINT_ACCESS")
                    if category == "BENIGN_OR_ANOMALOUS":
                        category = "PRIVILEGE_ESCALATION"
                        severity = "MEDIUM"
                break

        # Check Authentication Events
        if any(w in endpoint.lower() for w in ["/login", "/auth", "/signin", "/token", "/session"]):
            if status in (401, 403):
                indicators.append("AUTH_FAILURE")
                tactics.append("Credential Access")
                techniques.append("T1110: Brute Force")
                category = "AUTHENTICATION"
                severity = "MEDIUM"
            elif status == 200:
                indicators.append("AUTH_SUCCESS")
                tactics.append("Initial Access")
                techniques.append("T1078: Valid Accounts")
                category = "AUTHENTICATION"
                severity = "INFO"

        # Check Application Exceptions / Server Errors
        if status == 500 or "database error" in target_str.lower() or "exception" in target_str.lower():
            indicators.append("APPLICATION_ERROR_CRASH")
            if category == "BENIGN_OR_ANOMALOUS":
                category = "SYSTEM_ERROR"
                severity = "HIGH" if any("SQL" in ind for ind in indicators) else "MEDIUM"

        # WAF Alerts
        if source_type == "waf_alert":
            indicators.append("SECURITY_GATEWAY_TRIGGER")
            severity = "CRITICAL" if "SQL" in str(extra) or "shell" in str(extra) else "HIGH"
            category = "EXPLOITATION"

        return indicators, list(set(tactics)), list(set(techniques)), category, severity

    @classmethod
    def normalize(
        cls,
        raw_dict: Dict[str, Any],
        file_id: str,
        default_classification: str = "Imported Evidence"
    ) -> NormalizedEvent:
        indicators, tactics, techniques, category, severity = cls.detect_indicators(raw_dict)
        
        # Override severity if raw_dict explicitly had a higher one
        provided_sev = raw_dict.get("severity")
        sev_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if provided_sev and sev_rank.get(provided_sev, 0) > sev_rank.get(severity, 0):
            severity = provided_sev

        classification = raw_dict.get("evidence_classification") or default_classification

        return NormalizedEvent(
            file_id=file_id,
            source_type=raw_dict.get("source_type", "unknown"),
            source_file=raw_dict.get("source_file", "unknown"),
            line_number=raw_dict.get("line_number", 0),
            byte_offset=raw_dict.get("byte_offset", 0),
            raw_record=raw_dict.get("raw_record", ""),
            raw_hash=raw_dict.get("raw_hash", ""),
            timestamp=raw_dict.get("timestamp"),
            source_ip=raw_dict.get("source_ip"),
            dest_ip=raw_dict.get("dest_ip"),
            user=raw_dict.get("user"),
            session_id=raw_dict.get("session_id"),
            request_id=raw_dict.get("request_id"),
            http_method=raw_dict.get("http_method"),
            endpoint=raw_dict.get("endpoint"),
            query_params=raw_dict.get("query_params"),
            status_code=raw_dict.get("status_code"),
            user_agent=raw_dict.get("user_agent"),
            event_category=category,
            attack_indicators=indicators,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            severity=severity,
            evidence_classification=classification,
            source_citation=raw_dict.get("source_citation"),
            factual_source_url=raw_dict.get("factual_source_url"),
            extra_metadata=raw_dict.get("extra_metadata", {})
        )
