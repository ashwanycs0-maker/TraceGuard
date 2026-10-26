"""
Web Server Log Parser - Supports Nginx, Apache (Common, Combined, Extended) and Ingress logs
"""
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
import hashlib
from urllib.parse import urlparse, parse_qs


class WebLogParser:
    # Common Log Format (CLF): IP - User [Date] "Method Endpoint Proto" Status Bytes
    CLF_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)\s*(?P<proto>[^"]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
    )

    # Combined Log Format: CLF + "Referer" "User-Agent"
    COMBINED_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)\s*(?P<proto>[^"]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
    )

    # Extended Format with Request-ID and Cookie / Session
    EXTENDED_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)\s*(?P<proto>[^"]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"(?:\s+"(?P<request_id>[^"]*)")?(?:\s+"(?P<cookie>[^"]*)")?'
    )

    # ISO Timestamp Container/Ingress Format: 2026-08-19T14:22:01.123Z ...
    ISO_INGRESS_REGEX = re.compile(
        r'^(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?:\[(?P<tag>[^\]]+)\]\s+)?(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)\s*(?P<proto>[^"]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)")?(?:\s+"(?P<agent>[^"]*)")?(?:\s+req_id=(?P<request_id>\S+))?'
    )

    @staticmethod
    def parse_timestamp(timestr: str) -> str:
        """Normalizes various log timestamp formats to ISO-8601 UTC string"""
        timestr = timestr.strip()
        # Apache / Nginx default: 19/Aug/2026:14:22:01 +0000 or 19/Aug/2026:14:22:01
        for fmt in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(timestr, fmt)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue

        # If already starts with YYYY-MM-DDTHH:MM:SS
        if "T" in timestr and len(timestr) >= 19:
            return timestr[:19] + "Z"
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def extract_session_id(cls, cookie_str: Optional[str]) -> Optional[str]:
        if not cookie_str or cookie_str == "-":
            return None
        # Look for common session keys: session_id, sessionid, token, jsessionid, sid, phpsessid
        patterns = [
            r'(?:session_id|sessionid|sid|token|jsessionid|phpsessid)\s*=\s*([^;,\s]+)',
            r'bearer\s+([A-Za-z0-9\-\._~+/]+=*)',
            r'auth_token=([A-Za-z0-9\-_]+)'
        ]
        for pat in patterns:
            m = re.search(pat, cookie_str, re.IGNORECASE)
            if m:
                return m.group(1)[:32]  # Truncate clean session token
        return None

    @classmethod
    def parse_line(cls, line: str, line_num: int, filename: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        data = None
        # Try Extended first, then Combined, then Ingress, then CLF
        m = cls.EXTENDED_REGEX.match(line)
        if m:
            data = m.groupdict()
        else:
            m = cls.COMBINED_REGEX.match(line)
            if m:
                data = m.groupdict()
            else:
                m = cls.ISO_INGRESS_REGEX.match(line)
                if m:
                    data = m.groupdict()
                else:
                    m = cls.CLF_REGEX.match(line)
                    if m:
                        data = m.groupdict()

        if not data:
            return None

        # Clean fields
        raw_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        url = data.get("url", "")
        parsed_url = urlparse(url)
        endpoint = parsed_url.path or "/"
        query_params = parsed_url.query

        user = data.get("user")
        if user == "-":
            user = None

        cookie = data.get("cookie")
        session_id = cls.extract_session_id(cookie)
        request_id = data.get("request_id")
        if request_id == "-":
            request_id = None

        status_code = int(data.get("status", 0)) if data.get("status") else None

        return {
            "source_type": "nginx" if "nginx" in filename.lower() else "apache",
            "source_file": filename,
            "line_number": line_num,
            "raw_record": line,
            "raw_hash": raw_hash,
            "timestamp": cls.parse_timestamp(data.get("time", "")),
            "source_ip": data.get("ip"),
            "user": user,
            "session_id": session_id,
            "request_id": request_id,
            "http_method": data.get("method"),
            "endpoint": endpoint,
            "query_params": query_params if query_params else None,
            "status_code": status_code,
            "user_agent": data.get("agent") if data.get("agent") != "-" else None,
            "extra_metadata": {
                "referer": data.get("referer"),
                "bytes_sent": data.get("bytes"),
                "cookie_raw": cookie if cookie and cookie != "-" else None
            }
        }
