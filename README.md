# TraceGuard: Web Attack Path Reconstruction System

> **A Defensible, Evidence-Linked Cyber Attack Reconstruction Platform for Web Application Incidents.**

TraceGuard enables cybersecurity investigators and incident responders to reconstruct how suspicious activity develops across modern web architectures. Rather than presenting opaque conclusions, TraceGuard correlates multi-tier telemetry (Nginx, Apache, application stack traces, WAF alerts, and network PCAPs) into an **interactive, evidence-linked attack graph**, evaluates **competing attack hypotheses**, highlights **evidence gaps**, and maintains **forensic chain-of-custody preservation** through cryptographic SHA-256 verification.

---

## 🌟 The 5 Core Innovations

### 1. Evidence-Linked Attack Graph
Every connection and node in the visual graph is interactive and directly clickable. Clicking opens the **original, verbatim log line** alongside byte offsets, line numbers, extracted fields, and cryptographic digests. Investigators can defend conclusions in court or executive briefings by pointing directly to the underlying raw evidence.

### 2. Cross-Source Event Correlation
Connects telemetry across disparate tiers even when formats and representations differ:
- Web Server Access Logs (Nginx/Apache Common, Combined, Ingress)
- Backend Application Logs (Node.js Winston, Python Flask/Django stack traces, Java Spring, Syslog)
- Perimeter Security Telemetry (ModSecurity WAF, AWS WAF, Suricata / Snort)
- Network Packet Captures (Scapy PCAP / PCAPNG HTTP stream extraction)
Correlations leverage exact trace IDs, session tokens, causal exploit-to-crash sequences, and time-bounded sliding IP windows.

### 3. Alternative Attack-Path Hypotheses
Real-world incident investigations rarely have a single confirmed explanation from day one. Instead of forcing a single sequence, TraceGuard computes and visualizes **competing attack hypotheses**:
- **Hypothesis Alpha**: Direct External Exploitation Chain (e.g., File Upload $\rightarrow$ Web Shell $\rightarrow$ Data Staging)
- **Hypothesis Beta**: Stolen Session / Pre-Acquired Credential Abuse
- **Hypothesis Gamma**: Internal Lateral Movement / Spoofed Proxy Forwarding
Each hypothesis includes calculated likelihood ratings, supporting evidence weights, and divergence indicators.

### 4. Evidence Confidence & Missing-Evidence Analysis
Every link is labeled with a defensible confidence level:
- **Strongly Supported**: Exact trace/session ID, WAF perimeter match, or causal exploit-to-stacktrace link.
- **Partially Supported**: Consistent source IP + tight temporal proximity.
- **Speculative**: Inferred target alignment without cryptographic or session continuity.
TraceGuard scans for **Evidence Gaps** (e.g., missing authentication logs prior to privileged actions, absent database audit trails during SQL injection, or unmonitored egress flows).

### 5. Forensic Evidence Preservation
Logs are preserved immutably upon upload. TraceGuard computes SHA-256 hashes for all imported evidence files and individual records. An integrated cryptographic verification engine allows one-click tamper auditing, certifying that no records were altered during analysis.

---

## 🏛️ System Architecture

```
TraceGuard/
├── backend/
│   ├── app.py                     # FastAPI server & REST API endpoints
│   ├── models.py                  # Pydantic data schemas (Events, Graph, Hypotheses, Gaps)
│   ├── parsers/
│   │   ├── web_parser.py          # Nginx / Apache Common, Combined, Extended parser
│   │   ├── app_parser.py          # Node.js, Python, Java JSON and text stack trace parser
│   │   ├── waf_parser.py          # ModSecurity and Suricata / Snort alert parser
│   │   └── pcap_parser.py         # Scapy PCAP HTTP / DNS flow parser
│   ├── engine/
│   │   ├── normalizer.py          # Attack indicator detection & MITRE ATT&CK taxonomy
│   │   ├── correlation_engine.py  # Multi-tier cross-source heuristic correlation
│   │   ├── hypothesis_engine.py   # Competing hypothesis generator & likelihood scoring
│   │   ├── gap_analyzer.py        # Missing telemetry and blind spot detector
│   │   ├── forensics.py           # SHA-256 cryptographic hashing & tamper verification
│   │   └── report_generator.py    # Defensible PDF & JSON forensic report generator
│   ├── data/
│   │   └── samples.py             # 3 Authentic pre-packaged multi-source scenarios
│   └── evaluation/
│       └── benchmark.py           # Ground-truth simulation evaluation benchmark suite
├── static/
│   ├── index.html                 # Cybersecurity investigation workstation UI
│   ├── css/
│   │   └── style.css              # Dark cybersecurity design system with glassmorphism
│   └── js/
│       ├── app.js                 # Core application controller
│       ├── graph.js               # Interactive SVG force graph with pan/zoom & hypothesis highlighting
│       ├── timeline.js            # Chronological swimlane stream with filters
│       ├── evidence_drawer.js     # Evidence inspector with SHA-256 certificate
│       ├── hypotheses.js          # Competing hypothesis matrix switcher
│       ├── gaps.js                # Evidence gaps radar
│       ├── forensics.js           # Chain of custody and hash attestation
│       └── benchmark.js           # Simulation evaluation runner
├── cases_storage/                 # Persistent investigation case database
└── run.py                         # Server launcher script
```

---

## 🚀 Quick Start Guide

### 1. Requirements
- Python 3.10+ (Tested on Python 3.11)
- Dependencies installed: `fastapi`, `uvicorn`, `reportlab`, `scapy`, `pydantic`

### 2. Launching TraceGuard
Run the launcher script from the project root:

```bash
python run.py
```

The system will start on `http://127.0.0.1:8000` and automatically open your default browser.

---

## 🔍 Pre-Packaged Incident Scenarios

TraceGuard comes pre-loaded with 3 authentic multi-source scenarios ready for immediate inspection:

1. **CASE-2026-0819: FinTech Web Shell Deployment & Host Reconnaissance**
   - Telemetry: Apache access logs + Node.js backend logs + ModSecurity WAF alerts.
   - Attack Chain: Initial access $\rightarrow$ POST `/portal/upload.php` file upload exploit $\rightarrow$ execution of `uploader.php?cmd=whoami` $\rightarrow$ command execution `/etc/passwd` $\rightarrow$ data staging `/tmp/backup.tar.gz`.
   - Innovations Highlighted: Cross-source causal error linking, missing EDR host process gap, and exact request trace correlation.

2. **CASE-2026-0822: Healthcare API SQL Injection & Patient Data Exfiltration**
   - Telemetry: Nginx access logs + Python Flask SQLAlchemy stack traces + Suricata IDS alerts.
   - Attack Chain: Automated sqlmap reconnaissance on `/api/v1/patient/records` $\rightarrow$ boolean/UNION SQL injection $\rightarrow$ HTTP 500 unhandled database crash $\rightarrow$ database schema discovery $\rightarrow$ privileged exfiltration.
   - Innovations Highlighted: Cross-tier request ID tracing, missing database slow query audit gap.

3. **CASE-2026-0824: Credential Stuffing & Financial API Account Takeover**
   - Telemetry: Distributed residential IP access logs + Auth service logs.
   - Attack Chain: Rapid credential stuffing failures $\rightarrow$ successful session issuance for target executive $\rightarrow$ unauthorized wire transfer execution.
   - Innovations Highlighted: Competing hypotheses (Direct Brute Force vs Pre-Existing Session Hijacking vs Rogue Insider) with evidentiary likelihood rankings.

---

## 📊 Evaluation & Simulation Benchmark

Step 7 of TraceGuard incorporates a ground-truth simulation benchmark:
- Evaluates reconstructed attack sequences against known simulated attack milestones.
- Computes:
  * **Sequence Reconstruction Accuracy**
  * **Correlation Precision & Recall**
  * **Entry Point Identification Rate**
  * **Forensic Integrity Defensibility** (100% cryptographic attestation)
Run the benchmark directly from the UI toolbar or via:
```bash
python -c "from backend.evaluation.benchmark import BenchmarkEvaluator; print(BenchmarkEvaluator.run_benchmark()['summary_scores'])"
```

---

## 📄 Defensible Forensic PDF Reports

TraceGuard generates court-admissible, executive-ready PDF investigation dossiers directly via Python `reportlab`:
- Executive summary & suspected entry points
- Timeline and reconstructed sequence tables
- Competing hypotheses comparison matrix
- Missing telemetry gap analysis
- Forensic chain-of-custody table with SHA-256 digests
- Cryptographic sign-off certification

Click **Export Report $\rightarrow$ Forensic PDF Dossier** in the UI to generate and download the PDF.
#   T r a c e G u a r d  
 