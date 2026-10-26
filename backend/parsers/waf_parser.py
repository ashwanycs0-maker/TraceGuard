"""
WAF and Security Alert Log Parser - Handles ModSecurity, AWS WAF, and Snort/Suricata alerts
"""
import re
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any


class WAFAlertParser:
    # ModSecurity Single-Line Alert Log Format:
    # [2026-08-19 14:22:15] [client 198.51.100.45] ModSecurity: Access denied with code 403 (phase 2). Pattern match "(?i:(?:select.*from|union.*select))" at ARGS:id. [file "..."] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"] [uri "/api/v1/search"]
    MODSEC_REGEX = re.compile(
        r'^\[(?P<time>[^\]]+)\]\s+\[client\s+(?P<ip>[^\]:]+)(?::\d+)?\]\s+ModSecurity:\s+(?P<action>[^\[]+)\s+\[id\s+"(?P<rule_id>[^"]+)"\]\s+\[msg\s+"(?P<msg>[^"]+)"\](?:\s+\[data\s+"(?P<data>[^"]+)"\])?(?:\s+\[severity\s+"(?P<severity>[^"]+)"\])?(?:\s+\[uri\s+"(?P<uri>[^"]+)"\])?'
    )

    SURICATA_FAST_REGEX = re.compile(
        r'^(?P<time>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>[^\[\*]+)\s+\[\*\*\]\s+\[Classification:\s*(?P<class>[^\]]+)\]\s+\[Priority:\s*(?P<prio>\d+)\]\s+\{(?P<proto>\S+)\}\s+(?P<src_ip>\S+)(?::\d+)?\s+->\s+(?P<dst_ip>\S+)(?::\d+)?'
    )

    @staticmethod
    def parse_timestamp(timestr: str) -> str:
        timestr = timestr.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%m/%d/%Y-%H:%M:%S.%f",
            "%m/%d/%Y-%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(timestr, fmt)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
        if "T" in timestr and len(timestr) >= 19:
            return timestr[:19] + "Z"
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def parse_line(cls, line: str, line_num: int, filename: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        raw_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

        # 1. Check if JSON (e.g. AWS WAF, Cloudflare WAF, Suricata EVE JSON)
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                time_val = (
                    payload.get("timestamp")
                    or payload.get("time")
                    or payload.get("@timestamp")
                    or ""
                )
                ip = (
                    payload.get("httpRequest", {}).get("clientIp")
                    or payload.get("src_ip")
                    or payload.get("client_ip")
                    or payload.get("source_ip")
                )
                uri = (
                    payload.get("httpRequest", {}).get("uri")
                    or payload.get("uri")
                    or payload.get("http", {}).get("url")
                )
                rule = (
                    payload.get("terminatingRuleId")
                    or payload.get("alert", {}).get("signature")
                    or payload.get("rule_name")
                    or "WAF_RULE_MATCH"
                )
                msg = (
                    payload.get("alert", {}).get("signature")
                    or payload.get("action")
                    or payload.get("message")
                    or "WAF Alert"
                )

                return {
                    "source_type": "waf_alert",
                    "source_file": filename,
                    "line_number": line_num,
                    "raw_record": line,
                    "raw_hash": raw_hash,
                    "timestamp": cls.parse_timestamp(str(time_val)) if time_val else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "source_ip": ip,
                    "endpoint": uri,
                    "severity": "CRITICAL" if "sql" in str(rule).lower() or "command" in str(rule).lower() or "shell" in str(rule).lower() else "HIGH",
                    "extra_metadata": {
                        "rule_id": rule,
                        "alert_message": msg,
                        "waf_engine": "EVE/Cloudflare/AWS_WAF",
                        "raw_payload": payload
                    }
                }
            except Exception:
                pass

        # 2. ModSecurity log match
        m = cls.MODSEC_REGEX.match(line)
        if m:
            gd = m.groupdict()
            sev = (gd.get("severity") or "HIGH").upper()
            return {
                "source_type": "waf_alert",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": cls.parse_timestamp(gd.get("time", "")),
                "source_ip": gd.get("ip"),
                "endpoint": gd.get("uri"),
                "severity": "CRITICAL" if sev == "CRITICAL" else "HIGH",
                "extra_metadata": {
                    "rule_id": gd.get("rule_id"),
                    "alert_message": gd.get("msg"),
                    "matched_data": gd.get("data"),
                    "action_taken": gd.get("action")
                }
            }

        # 3. Suricata Fast log match
        m = cls.SURICATA_FAST_REGEX.match(line)
        if m:
            gd = m.groupdict()
            return {
                "source_type": "waf_alert",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": cls.parse_timestamp(gd.get("time", "")),
                "source_ip": gd.get("src_ip"),
                "dest_ip": gd.get("dst_ip"),
                "severity": "HIGH",
                "extra_metadata": {
                    "sid": gd.get("sid"),
                    "alert_message": gd.get("msg"),
                    "classification": gd.get("class"),
                    "priority": gd.get("prio")
                }
            }

        # Fallback if line mentions ModSecurity or WAF
        if "modsecurity" in line.lower() or "waf" in line.lower() or "threat" in line.lower():
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            return {
                "source_type": "waf_alert",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip": ip_m.group(0) if ip_m else None,
                "severity": "HIGH",
                "extra_metadata": {"alert_message": line}
            }

        return None
