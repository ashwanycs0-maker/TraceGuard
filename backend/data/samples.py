"""
Pre-packaged Realistic Multi-Source Investigation Scenarios for TraceGuard
"""
from typing import Dict, Any, List


SAMPLE_SCENARIOS = {
    "CASE-2026-0819": {
        "title": "FinTech Web Shell Deployment & Host Reconnaissance",
        "description": "Multi-tier breach involving file upload exploitation, remote command execution via uploader.php web shell, and data staging.",
        "investigator": "Agent Sarah Chen (Senior Incident Responder)",
        "files": [
            {
                "filename": "apache_access.log",
                "source_type": "apache",
                "content": """198.51.100.45 - - [19/Aug/2026:14:20:02 +0000] "GET / HTTP/1.1" 200 4520 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "req-1001" "-"
198.51.100.45 - - [19/Aug/2026:14:20:15 +0000] "GET /portal/login HTTP/1.1" 200 2890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "req-1002" "-"
198.51.100.45 - - [19/Aug/2026:14:21:05 +0000] "POST /portal/upload.php HTTP/1.1" 200 840 "https://target.corp/portal/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "req-1003" "sessionid=sess_a9f82d41"
198.51.100.45 - - [19/Aug/2026:14:22:10 +0000] "GET /uploads/uploader.php?cmd=whoami HTTP/1.1" 200 18 "-" "curl/7.68.0" "req-1004" "-"
198.51.100.45 - - [19/Aug/2026:14:22:35 +0000] "GET /uploads/uploader.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1890 "-" "curl/7.68.0" "req-1005" "-"
198.51.100.45 - - [19/Aug/2026:14:23:40 +0000] "GET /uploads/uploader.php?cmd=ls+-la+/var/data/exports HTTP/1.1" 200 640 "-" "curl/7.68.0" "req-1006" "-"
198.51.100.45 - - [19/Aug/2026:14:24:18 +0000] "GET /uploads/uploader.php?cmd=tar+-czf+/tmp/backup.tar.gz+/var/data/exports HTTP/1.1" 200 48 "-" "curl/7.68.0" "req-1007" "-"
198.51.100.45 - - [19/Aug/2026:14:25:50 +0000] "GET /download.php?file=/tmp/backup.tar.gz HTTP/1.1" 200 16184000 "-" "Mozilla/5.0" "req-1008" "sessionid=sess_a9f82d41"
"""
            },
            {
                "filename": "node_app_backend.log",
                "source_type": "app_log",
                "content": """{"timestamp": "2026-08-19T14:20:02Z", "level": "info", "requestId": "req-1001", "message": "Static asset served for /", "clientIp": "198.51.100.45"}
{"timestamp": "2026-08-19T14:21:05Z", "level": "warn", "requestId": "req-1003", "sessionId": "sess_a9f82d41", "message": "File written to disk: /var/www/uploads/uploader.php [MIME: application/x-php]", "clientIp": "198.51.100.45"}
{"timestamp": "2026-08-19T14:22:10Z", "level": "error", "requestId": "req-1004", "message": "Child process spawned by web worker: sh -c 'whoami'", "clientIp": "198.51.100.45"}
{"timestamp": "2026-08-19T14:22:35Z", "level": "error", "requestId": "req-1005", "message": "Sensitive file accessed via exec: /etc/passwd", "clientIp": "198.51.100.45"}
{"timestamp": "2026-08-19T14:25:50Z", "level": "info", "requestId": "req-1008", "sessionId": "sess_a9f82d41", "message": "Bulk binary archive streamed: 16184000 bytes", "clientIp": "198.51.100.45"}
"""
            },
            {
                "filename": "modsecurity_waf.log",
                "source_type": "waf_alert",
                "content": """[2026-08-19 14:22:35] [client 198.51.100.45] ModSecurity: Warning. Matched "(?i:(?:etc/passwd|windows/win.ini))" [id "930100"] [msg "Path Traversal / Local File Inclusion in query string"] [severity "CRITICAL"] [uri "/uploads/uploader.php"]
[2026-08-19 14:24:18] [client 198.51.100.45] ModSecurity: Warning. Matched "(?i:(?:tar\s+-|gzip|bzip2))" [id "932150"] [msg "System Archive Utility Invocation detected"] [severity "HIGH"] [uri "/uploads/uploader.php"]
"""
            }
        ]
    },
    "CASE-2026-0822": {
        "title": "Healthcare API SQL Injection & Patient Data Exfiltration",
        "description": "Cross-source correlation between Nginx access logs, Python Flask backend stack traces, and perimeter Snort IDS alerts.",
        "investigator": "Agent Alex Rivera (Cyber Forensics Specialist)",
        "files": [
            {
                "filename": "nginx_access.log",
                "source_type": "nginx",
                "content": """203.0.113.88 - - [22/Aug/2026:09:12:01 +0000] "GET /api/v1/patient/records?id=42 HTTP/1.1" 200 1250 "-" "sqlmap/1.6.4#stable" "trace-8801" "-"
203.0.113.88 - - [22/Aug/2026:09:12:15 +0000] "GET /api/v1/patient/records?id=42%20AND%201=1 HTTP/1.1" 200 1250 "-" "sqlmap/1.6.4#stable" "trace-8802" "-"
203.0.113.88 - - [22/Aug/2026:09:12:28 +0000] "GET /api/v1/patient/records?id=42%20UNION%20SELECT%20null,table_name,null%20FROM%20information_schema.tables HTTP/1.1" 500 480 "-" "sqlmap/1.6.4#stable" "trace-8803" "-"
203.0.113.88 - - [22/Aug/2026:09:13:05 +0000] "GET /api/v1/patient/records?id=42%20UNION%20SELECT%20id,username,password_hash%20FROM%20app_users HTTP/1.1" 200 4580 "-" "sqlmap/1.6.4#stable" "trace-8804" "-"
203.0.113.88 - - [22/Aug/2026:09:14:20 +0000] "POST /api/v1/admin/export_all HTTP/1.1" 200 328000 "-" "Mozilla/5.0" "trace-8805" "auth_token=jwt_991823bb"
"""
            },
            {
                "filename": "flask_app.log",
                "source_type": "app_log",
                "content": """2026-08-22 09:12:01,102 [INFO] [trace-8801] [api.patient]: Query patient id=42 completed from IP 203.0.113.88
2026-08-22 09:12:28,450 [ERROR] [trace-8803] [database.core]: psycopg2.errors.SyntaxError: syntax error at or near 'UNION' in query 'SELECT id, name FROM patients WHERE id = 42 UNION SELECT null,table_name,null FROM information_schema.tables'
2026-08-22 09:13:05,890 [WARN] [trace-8804] [api.patient]: Database query returned multi-table schema resultset (columns mismatched)
2026-08-22 09:14:20,310 [INFO] [trace-8805] [api.admin]: Bulk patient database dump initiated by user 'admin_extracted'
"""
            },
            {
                "filename": "suricata_alerts.log",
                "source_type": "waf_alert",
                "content": """08/22/2026-09:12:28.450123 [**] [1:2010018:2] ET EXPLOIT SQL Injection in URI (UNION SELECT) [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.88:48201 -> 10.0.0.15:443
"""
            }
        ]
    },
    "CASE-2026-0824": {
        "title": "Credential Stuffing & Financial API Account Takeover",
        "description": "Distributed authentication brute forcing leading to unauthorized session acquisition and wire transfer execution.",
        "investigator": "Agent Marcus Vance (Threat Intelligence Lead)",
        "files": [
            {
                "filename": "nginx_access.log",
                "source_type": "nginx",
                "content": """198.51.100.12 - - [24/Aug/2026:16:01:05 +0000] "POST /api/v2/auth/login HTTP/1.1" 401 120 "-" "Python-requests/2.28" "req-201" "-"
198.51.100.13 - - [24/Aug/2026:16:01:12 +0000] "POST /api/v2/auth/login HTTP/1.1" 401 120 "-" "Python-requests/2.28" "req-202" "-"
198.51.100.14 - - [24/Aug/2026:16:01:19 +0000] "POST /api/v2/auth/login HTTP/1.1" 401 120 "-" "Python-requests/2.28" "req-203" "-"
198.51.100.99 - - [24/Aug/2026:16:02:40 +0000] "POST /api/v2/auth/login HTTP/1.1" 200 480 "-" "Mozilla/5.0 (Macintosh)" "req-204" "sessionid=sess_wire_9921"
198.51.100.99 - - [24/Aug/2026:16:03:15 +0000] "GET /api/v2/accounts/balance HTTP/1.1" 200 890 "-" "Mozilla/5.0 (Macintosh)" "req-205" "sessionid=sess_wire_9921"
198.51.100.99 - - [24/Aug/2026:16:04:02 +0000] "POST /api/v2/wire/transfer HTTP/1.1" 200 240 "-" "Mozilla/5.0 (Macintosh)" "req-206" "sessionid=sess_wire_9921"
"""
            },
            {
                "filename": "auth_service.log",
                "source_type": "app_log",
                "content": """{"timestamp": "2026-08-24T16:01:05Z", "level": "warn", "requestId": "req-201", "userId": "jsmith@fin.org", "message": "Authentication failed: invalid password", "clientIp": "198.51.100.12"}
{"timestamp": "2026-08-24T16:01:12Z", "level": "warn", "requestId": "req-202", "userId": "bwayne@fin.org", "message": "Authentication failed: invalid password", "clientIp": "198.51.100.13"}
{"timestamp": "2026-08-24T16:01:19Z", "level": "warn", "requestId": "req-203", "userId": "cfinance@fin.org", "message": "Authentication failed: invalid password", "clientIp": "198.51.100.14"}
{"timestamp": "2026-08-24T16:02:40Z", "level": "info", "requestId": "req-204", "userId": "cfinance@fin.org", "sessionId": "sess_wire_9921", "message": "Authentication successful: session token issued", "clientIp": "198.51.100.99"}
{"timestamp": "2026-08-24T16:04:02Z", "level": "warn", "requestId": "req-206", "userId": "cfinance@fin.org", "sessionId": "sess_wire_9921", "message": "Wire transfer executed: $450,000 to offshore account", "clientIp": "198.51.100.99"}
"""
            }
        ]
    }
}
