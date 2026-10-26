"""
Application Log Parser - Handles JSON logs, Python/Node/Java stack traces, and Syslog format
"""
import re
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any


class AppLogParser:
    TEXT_LOG_REGEX = re.compile(
        r'^(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?:\[(?P<level>[A-Z]+)\]|(?P<level_alt>[A-Z]+))\s*(?:\[(?P<req_id>[A-Za-z0-9\-_]+)\])?\s*(?:\[(?P<logger>[^\]]+)\])?\s*[:-]?\s*(?P<msg>.*)$'
    )

    SYSLOG_REGEX = re.compile(
        r'^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<app>[A-Za-z0-9\-_]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$'
    )

    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    REQ_ID_REGEX = re.compile(r'(?:req(?:uest)?[-_]?id|trace[-_]?id)[=:\s]+([A-Za-z0-9\-_]+)', re.IGNORECASE)
    SESSION_REGEX = re.compile(r'(?:session(?:[-_]?id)?|sid)[=:\s]+([A-Za-z0-9\-_]+)', re.IGNORECASE)
    USER_REGEX = re.compile(r'(?:user(?:name)?|account)[=:\s]+["\']?([A-Za-z0-9\._@\-]+)["\']?', re.IGNORECASE)

    @staticmethod
    def parse_timestamp(timestr: str) -> str:
        timestr = timestr.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S,%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%b %d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(timestr, fmt)
                if dt.year == 1900:  # syslog without year
                    dt = dt.replace(year=datetime.utcnow().year)
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

        # 1. Try JSON log format first
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                time_val = (
                    payload.get("timestamp")
                    or payload.get("time")
                    or payload.get("@timestamp")
                    or payload.get("datetime")
                    or ""
                )
                level = str(payload.get("level") or payload.get("severity") or "INFO").upper()
                msg = payload.get("message") or payload.get("msg") or str(payload)
                req_id = (
                    payload.get("requestId")
                    or payload.get("request_id")
                    or payload.get("traceId")
                    or payload.get("trace_id")
                )
                user = payload.get("userId") or payload.get("user") or payload.get("username")
                session_id = payload.get("sessionId") or payload.get("session_id")
                ip = payload.get("ip") or payload.get("clientIp") or payload.get("source_ip")
                endpoint = payload.get("endpoint") or payload.get("path") or payload.get("url")

                # If IP or user wasn't directly in json keys, search msg
                if not ip:
                    ip_match = cls.IP_REGEX.search(msg)
                    if ip_match:
                        ip = ip_match.group(0)

                return {
                    "source_type": "app_log",
                    "source_file": filename,
                    "line_number": line_num,
                    "raw_record": line,
                    "raw_hash": raw_hash,
                    "timestamp": cls.parse_timestamp(str(time_val)) if time_val else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "source_ip": ip,
                    "user": str(user) if user else None,
                    "session_id": str(session_id) if session_id else None,
                    "request_id": str(req_id) if req_id else None,
                    "http_method": payload.get("method"),
                    "endpoint": endpoint,
                    "status_code": payload.get("status") or payload.get("statusCode"),
                    "severity": "CRITICAL" if level in ("FATAL", "CRITICAL") else ("HIGH" if level in ("ERROR", "EXCEPTION") else ("MEDIUM" if level in ("WARN", "WARNING") else "INFO")),
                    "extra_metadata": {
                        "log_format": "json",
                        "level": level,
                        "message": msg,
                        "raw_payload": payload
                    }
                }
            except Exception:
                pass

        # 2. Try structured text log regex
        m = cls.TEXT_LOG_REGEX.match(line)
        if m:
            gd = m.groupdict()
            time_val = gd.get("time") or ""
            level = (gd.get("level") or gd.get("level_alt") or "INFO").upper()
            msg = gd.get("msg") or ""
            req_id = gd.get("req_id")

            # Extract contextual clues from msg
            ip_m = cls.IP_REGEX.search(msg)
            ip = ip_m.group(0) if ip_m else None

            if not req_id:
                req_m = cls.REQ_ID_REGEX.search(msg)
                if req_m:
                    req_id = req_m.group(1)

            sess_m = cls.SESSION_REGEX.search(msg)
            session_id = sess_m.group(1) if sess_m else None

            user_m = cls.USER_REGEX.search(msg)
            user = user_m.group(1) if user_m else None

            return {
                "source_type": "app_log",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": cls.parse_timestamp(time_val),
                "source_ip": ip,
                "user": user,
                "session_id": session_id,
                "request_id": req_id,
                "endpoint": None,
                "severity": "HIGH" if level in ("ERROR", "FATAL", "CRITICAL") else ("MEDIUM" if level in ("WARN", "WARNING") else "INFO"),
                "extra_metadata": {
                    "log_format": "text",
                    "logger": gd.get("logger"),
                    "level": level,
                    "message": msg
                }
            }

        # 3. Try syslog regex
        m = cls.SYSLOG_REGEX.match(line)
        if m:
            gd = m.groupdict()
            msg = gd.get("msg") or ""
            ip_m = cls.IP_REGEX.search(msg)
            ip = ip_m.group(0) if ip_m else None

            return {
                "source_type": "syslog",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": cls.parse_timestamp(gd.get("time") or ""),
                "source_ip": ip,
                "severity": "MEDIUM" if any(w in msg.lower() for w in ["fail", "error", "alert", "denied"]) else "INFO",
                "extra_metadata": {
                    "host": gd.get("host"),
                    "app": gd.get("app"),
                    "message": msg
                }
            }

        # Fallback raw line
        return {
            "source_type": "app_log",
            "source_file": filename,
            "line_number": line_num,
            "raw_record": line,
            "raw_hash": raw_hash,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "severity": "INFO",
            "extra_metadata": {"message": line}
        }
