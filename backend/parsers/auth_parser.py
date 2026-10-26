"""
Authentication and CSV Log Parser - Parses authentication events, CSV dumps,
and security audit logs into normalized records.
"""
import csv
import io
import re
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional


class AuthAndCSVParser:
    SSHD_FAIL_REGEX = re.compile(
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)',
        re.IGNORECASE
    )
    SSHD_ACCEPT_REGEX = re.compile(
        r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)',
        re.IGNORECASE
    )

    @classmethod
    def parse_csv_content(cls, csv_text: str, filename: str) -> List[Dict[str, Any]]:
        """Parses generic security or web CSV exports into event records"""
        records = []
        f = io.StringIO(csv_text.strip())
        reader = csv.DictReader(f)
        
        for idx, row in enumerate(reader, 1):
            raw_repr = ",".join(f"{k}={v}" for k, v in row.items())
            raw_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

            # Find common fields
            ip = row.get("source_ip") or row.get("client_ip") or row.get("ip") or row.get("src_ip")
            user = row.get("user") or row.get("username") or row.get("account")
            endpoint = row.get("endpoint") or row.get("uri") or row.get("url") or row.get("path")
            method = row.get("method") or row.get("http_method")
            status = row.get("status") or row.get("status_code")
            ts = row.get("timestamp") or row.get("time") or row.get("date") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            status_code = None
            if status:
                try:
                    status_code = int(status)
                except ValueError:
                    pass

            records.append({
                "source_type": "csv_export",
                "source_file": filename,
                "line_number": idx,
                "byte_offset": idx * 64,
                "raw_record": raw_repr,
                "raw_hash": raw_hash,
                "timestamp": ts,
                "source_ip": ip,
                "user": user,
                "endpoint": endpoint,
                "http_method": method,
                "status_code": status_code,
                "severity": "MEDIUM" if status_code and status_code >= 400 else "INFO",
                "evidence_classification": "Imported Evidence",
                "extra_metadata": {"csv_row": row}
            })

        return records

    @classmethod
    def parse_auth_line(cls, line: str, line_num: int, filename: str) -> Optional[Dict[str, Any]]:
        """Parses authentication log line (e.g. pam, sshd, auth api)"""
        line = line.strip()
        if not line:
            return None

        raw_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        m_fail = cls.SSHD_FAIL_REGEX.search(line)
        if m_fail:
            return {
                "source_type": "auth_log",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip": m_fail.group("ip"),
                "user": m_fail.group("user"),
                "endpoint": "/auth/ssh",
                "status_code": 401,
                "severity": "MEDIUM",
                "evidence_classification": "Imported Evidence",
                "extra_metadata": {"auth_event": "FAILURE", "port": m_fail.group("port")}
            }

        m_ok = cls.SSHD_ACCEPT_REGEX.search(line)
        if m_ok:
            return {
                "source_type": "auth_log",
                "source_file": filename,
                "line_number": line_num,
                "raw_record": line,
                "raw_hash": raw_hash,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip": m_ok.group("ip"),
                "user": m_ok.group("user"),
                "endpoint": "/auth/ssh",
                "status_code": 200,
                "severity": "INFO",
                "evidence_classification": "Imported Evidence",
                "extra_metadata": {"auth_event": "SUCCESS", "port": m_ok.group("port")}
            }

        return None
