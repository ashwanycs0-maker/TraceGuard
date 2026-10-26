"""
PCAP Network Packet Parser - Uses Scapy to extract HTTP, DNS, and TCP flow metadata
"""
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional
import os


class PCAPParser:
    @staticmethod
    def parse_pcap_file(filepath: str, max_packets: int = 1500) -> List[Dict[str, Any]]:
        """Parses a binary PCAP or PCAPNG file using Scapy"""
        events = []
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
        except ImportError:
            return events

        if not os.path.exists(filepath):
            return events

        filename = os.path.basename(filepath)
        try:
            packets = rdpcap(filepath)
        except Exception as e:
            # Fallback or error
            return events

        packet_idx = 0
        for pkt in packets:
            packet_idx += 1
            if packet_idx > max_packets:
                break

            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt.getlayer(IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_time = datetime.utcfromtimestamp(float(pkt.time)).strftime("%Y-%m-%dT%H:%M:%SZ")
            raw_summary = pkt.summary()
            raw_hash = hashlib.sha256(raw_summary.encode("utf-8")).hexdigest()

            # Inspect HTTP payload if TCP
            http_method = None
            endpoint = None
            status_code = None
            user_agent = None

            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload_bytes = bytes(pkt[Raw].load)
                try:
                    payload_text = payload_bytes.decode('utf-8', errors='ignore')
                    first_line = payload_text.splitlines()[0] if payload_text else ""
                    # HTTP Request
                    for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]:
                        if first_line.startswith(m + " "):
                            parts = first_line.split()
                            http_method = parts[0]
                            endpoint = parts[1] if len(parts) > 1 else "/"
                            break
                    # HTTP Response
                    if first_line.startswith("HTTP/"):
                        parts = first_line.split()
                        if len(parts) > 1 and parts[1].isdigit():
                            status_code = int(parts[1])

                    # Check for User-Agent
                    if "User-Agent:" in payload_text:
                        for line in payload_text.splitlines():
                            if line.lower().startswith("user-agent:"):
                                user_agent = line.split(":", 1)[1].strip()
                                break
                except Exception:
                    pass

            # Inspect DNS queries
            dns_query = None
            if pkt.haslayer(DNS):
                try:
                    dns = pkt.getlayer(DNS)
                    if dns.qd:
                        dns_query = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                except Exception:
                    pass

            # Only retain packets with HTTP, DNS, or notable TCP flags
            if http_method or status_code or dns_query or (pkt.haslayer(TCP) and pkt[TCP].flags in (0x02, 0x04)): # SYN, RST
                events.append({
                    "source_type": "pcap_network",
                    "source_file": filename,
                    "line_number": packet_idx,
                    "raw_record": raw_summary,
                    "raw_hash": raw_hash,
                    "timestamp": pkt_time,
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "http_method": http_method,
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "user_agent": user_agent,
                    "extra_metadata": {
                        "packet_number": packet_idx,
                        "dns_query": dns_query,
                        "tcp_sport": pkt[TCP].sport if pkt.haslayer(TCP) else None,
                        "tcp_dport": pkt[TCP].dport if pkt.haslayer(TCP) else None,
                        "ip_proto": ip_layer.proto
                    }
                })

        return events
