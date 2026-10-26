"""
TraceGuard FastAPI Server - Web Attack Path Reconstruction API and Application Host
Enhanced with the 5 Real Cybersecurity Incident Case Studies, File Preservation,
Controlled Testing Scenarios, and Simplified English Terminology.
"""
import os
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.models import (
    Case, EvidenceFile, NormalizedEvent, AttackNode, AttackEdge, Hypothesis, EvidenceGap, IntegrityVerification, CustodyAction
)
from backend.parsers.web_parser import WebLogParser
from backend.parsers.app_parser import AppLogParser
from backend.parsers.waf_parser import WAFAlertParser
from backend.parsers.pcap_parser import PCAPParser
from backend.parsers.pdf_parser import PDFReportParser
from backend.parsers.auth_parser import AuthAndCSVParser
from backend.engine.normalizer import EventNormalizer
from backend.engine.correlation_engine import CorrelationEngine
from backend.engine.hypothesis_engine import HypothesisEngine
from backend.engine.gap_analyzer import EvidenceGapAnalyzer
from backend.engine.forensics import ForensicEngine
from backend.engine.report_generator import ReportGenerator
from backend.evaluation.benchmark import BenchmarkEvaluator, CONTROLLED_TEST_SCENARIOS
from backend.data.samples import SAMPLE_SCENARIOS
from backend.data.real_cases import REAL_CYBERSECURITY_CASES


app = FastAPI(
    title="TraceGuard: Web Attack Path Reconstruction System",
    description="Defensible, Evidence-Linked Cyber Attack Reconstruction Platform",
    version="2.5.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CASES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cases_storage")
os.makedirs(CASES_DIR, exist_ok=True)

EVIDENCE_FILES_DIR = os.path.join(CASES_DIR, "evidence_files")
os.makedirs(EVIDENCE_FILES_DIR, exist_ok=True)

# In-memory case cache
CASES: Dict[str, Case] = {}


def process_case_pipeline(case: Case):
    """Executes the full correlation, hypothesis generation, and gap analysis pipeline for a case"""
    # 1. Correlate events into attack nodes and edges
    nodes, edges = CorrelationEngine.correlate(case.events)
    case.nodes = nodes
    case.edges = edges

    # 2. Analyze evidence gaps
    gaps = EvidenceGapAnalyzer.analyze_gaps(case.events)
    case.evidence_gaps = gaps

    # 3. Generate alternative hypotheses
    hypotheses = HypothesisEngine.generate_hypotheses(case.events, nodes, edges, gaps)
    case.hypotheses = hypotheses

    # 4. Summary metrics
    critical_events = [e for e in case.events if e.severity in ("HIGH", "CRITICAL")]
    strong_edges = [e for e in case.edges if e.confidence_level == "STRONGLY_SUPPORTED"]
    partial_edges = [e for e in case.edges if e.confidence_level == "PARTIALLY_SUPPORTED"]
    speculative_edges = [e for e in case.edges if e.confidence_level == "SPECULATIVE"]

    case.summary_metrics = {
        "total_events": len(case.events),
        "total_evidence_files": len(case.evidence_files),
        "reconstructed_steps": len(case.nodes),
        "established_links": len(case.edges),
        "critical_events_count": len(critical_events),
        "strongly_supported_links": len(strong_edges),
        "partially_supported_links": len(partial_edges),
        "speculative_links": len(speculative_edges),
        "evidence_gaps_count": len(case.evidence_gaps),
        "competing_hypotheses_count": len(case.hypotheses),
        "primary_likelihood_pct": int(hypotheses[0].likelihood_score * 100) if hypotheses else 0
    }

    save_case_to_disk(case)


def save_case_to_disk(case: Case):
    filepath = os.path.join(CASES_DIR, f"{case.case_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(case.model_dump_json(indent=2))


def load_cases_from_disk():
    for fname in os.listdir(CASES_DIR):
        if fname.endswith(".json"):
            filepath = os.path.join(CASES_DIR, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    case = Case(**data)
                    CASES[case.case_id] = case
            except Exception as e:
                print(f"Error loading case {fname}: {e}")


def initialize_real_cases():
    """Initializes the 5 real-world cybersecurity incident case studies if not already loaded"""
    for cid, rdata in REAL_CYBERSECURITY_CASES.items():
        if cid in CASES:
            # Refresh metadata in case of updates
            existing = CASES[cid]
            existing.simple_explanation = rdata.get("simple_explanation")
            existing.what_happened = rdata.get("what_happened")
            existing.what_was_affected = rdata.get("what_was_affected")
            existing.documented_response = rdata.get("documented_response")
            existing.official_sources = rdata.get("official_sources", [])
            existing.factual_claims = rdata.get("factual_claims", [])
            existing.known_attack_steps = rdata.get("known_attack_steps", [])
            existing.available_evidence = rdata.get("available_evidence", [])
            existing.missing_information = rdata.get("missing_information", [])
            existing.country = rdata.get("country")
            existing.year = rdata.get("year")
            existing.industry = rdata.get("industry")
            existing.case_type = "REAL_INCIDENT"
            existing.is_demo_mode = False
            save_case_to_disk(existing)
            continue

        # Create virtual evidence file representing official report
        source_title = rdata["official_sources"][0]["title"] if rdata.get("official_sources") else f"{rdata['title']} Report"
        source_url = rdata["official_sources"][0]["url"] if rdata.get("official_sources") else ""
        report_content = (
            f"OFFICIAL INVESTIGATION REPORT SUMMARY: {rdata['title']}\n"
            f"Source Authority / Citation: {source_title}\n"
            f"Document URL: {source_url}\n\n"
            f"WHAT HAPPENED:\n{rdata['what_happened']}\n\n"
            f"WHAT WAS AFFECTED:\n{rdata['what_was_affected']}\n\n"
            f"DOCUMENTED RESPONSE:\n{rdata['documented_response']}\n"
        )

        efile = ForensicEngine.register_evidence_file(
            filename=f"{cid.lower()}_official_report.txt",
            content=report_content,
            source_type="public_report",
            custody_officer=rdata["investigator"],
            evidence_type="Publicly Reported Fact"
        )

        # Build normalized events strictly from documented attack steps
        events = []
        for step in rdata.get("known_attack_steps", []):
            raw_rec = f"[{step['phase']}] {step['action']}"
            step_evt = NormalizedEvent(
                file_id=efile.file_id,
                source_type="public_report",
                source_file=efile.filename,
                line_number=step["step_order"],
                byte_offset=step["step_order"] * 100,
                raw_record=raw_rec,
                raw_hash=ForensicEngine.compute_sha256(raw_rec),
                timestamp=step["timestamp"],
                endpoint=step["phase"],
                event_category=step["phase"].upper().replace(" ", "_"),
                severity="HIGH" if step["step_order"] > 2 else "INFO",
                evidence_classification="Publicly Reported Fact",
                source_citation=step.get("source_citation"),
                factual_source_url=step.get("source_url")
            )
            events.append(step_evt)

        case = Case(
            case_id=cid,
            title=rdata["title"],
            description=rdata["what_happened"][:280] + "...",
            investigator=rdata["investigator"],
            case_type="REAL_INCIDENT",
            year=rdata.get("year"),
            country=rdata.get("country"),
            industry=rdata.get("industry"),
            simple_explanation=rdata.get("simple_explanation"),
            what_happened=rdata.get("what_happened"),
            what_was_affected=rdata.get("what_was_affected"),
            documented_response=rdata.get("documented_response"),
            official_sources=rdata.get("official_sources", []),
            factual_claims=rdata.get("factual_claims", []),
            known_attack_steps=rdata.get("known_attack_steps", []),
            available_evidence=rdata.get("available_evidence", []),
            missing_information=rdata.get("missing_information", []),
            is_demo_mode=False,
            evidence_files=[efile],
            events=events,
            custody_actions=[
                CustodyAction(
                    officer=rdata["investigator"],
                    action_type="IMPORT",
                    details=f"Official investigation findings indexed from {source_title}."
                )
            ]
        )
        process_case_pipeline(case)
        CASES[cid] = case


def initialize_sample_scenarios():
    """Populates pre-packaged realistic demonstration scenarios"""
    scenario_metadata = {
        "CASE-2026-0819": {"industry": "Financial Technology", "year": 2026, "country": "Simulation Lab (Global)"},
        "CASE-2026-0822": {"industry": "Healthcare Provider", "year": 2026, "country": "Simulation Lab (Global)"},
        "CASE-2026-0824": {"industry": "Commercial Banking", "year": 2026, "country": "Simulation Lab (Global)"}
    }

    for case_id, scenario in SAMPLE_SCENARIOS.items():
        if case_id in CASES:
            # Mark demo mode explicitly
            existing = CASES[case_id]
            existing.is_demo_mode = True
            existing.case_type = "SIMULATION"
            meta = scenario_metadata.get(case_id, {})
            existing.industry = meta.get("industry", "Technology")
            existing.year = meta.get("year", 2026)
            existing.country = meta.get("country", "Simulation Lab")
            existing.simple_explanation = scenario.get("description")
            save_case_to_disk(existing)
            continue

        meta = scenario_metadata.get(case_id, {})
        events = []
        evidence_files = []
        for file_data in scenario["files"]:
            fname = file_data["filename"]
            stype = file_data["source_type"]
            content = file_data["content"]

            efile = ForensicEngine.register_evidence_file(
                fname, content, stype, scenario["investigator"], evidence_type="Simulated Demo Data"
            )
            evidence_files.append(efile)

            for line_idx, line in enumerate(content.splitlines(), 1):
                if not line.strip():
                    continue
                if stype in ("nginx", "apache"):
                    raw_dict = WebLogParser.parse_line(line, line_idx, fname)
                elif stype == "waf_alert":
                    raw_dict = WAFAlertParser.parse_line(line, line_idx, fname)
                else:
                    raw_dict = AppLogParser.parse_line(line, line_idx, fname)

                if raw_dict:
                    norm_evt = EventNormalizer.normalize(raw_dict, efile.file_id, "Simulated Demo Data")
                    events.append(norm_evt)

        case = Case(
            case_id=case_id,
            title=scenario["title"],
            description=scenario["description"],
            investigator=scenario["investigator"],
            case_type="SIMULATION",
            is_demo_mode=True,
            year=meta.get("year", 2026),
            country=meta.get("country", "Simulation Lab"),
            industry=meta.get("industry", "Technology"),
            simple_explanation=scenario.get("description"),
            evidence_files=evidence_files,
            events=events,
            custody_actions=[
                CustodyAction(
                    officer=scenario["investigator"],
                    action_type="IMPORT",
                    details="Synthetic benchmark demonstration logs loaded into sandbox."
                )
            ]
        )
        process_case_pipeline(case)
        CASES[case_id] = case


# Initialize cases
load_cases_from_disk()
initialize_real_cases()
initialize_sample_scenarios()


# ==========================================
# API Endpoints
# ==========================================

@app.get("/api/cases")
def list_cases():
    """List all available investigation cases (real incidents and demonstration cases)"""
    case_list = []
    for cid, case in CASES.items():
        case_list.append({
            "case_id": case.case_id,
            "title": case.title,
            "description": case.description,
            "simple_explanation": case.simple_explanation,
            "created_at": case.created_at,
            "investigator": case.investigator,
            "status": case.status,
            "case_type": case.case_type,
            "is_demo_mode": case.is_demo_mode,
            "country": case.country,
            "year": case.year,
            "industry": case.industry,
            "metrics": case.summary_metrics,
            "files_count": len(case.evidence_files),
            "events_count": len(case.events)
        })
    # Real cases first, then sort by year descending
    return sorted(case_list, key=lambda c: (c["case_type"] == "REAL_INCIDENT", c.get("year") or 0), reverse=True)


@app.get("/api/case-library")
def get_case_library():
    """Returns the comprehensive professional Case Library with all 5 real incidents + demonstration scenarios"""
    real_cases = []
    demo_cases = []

    for cid, case in CASES.items():
        case_obj = {
            "case_id": case.case_id,
            "title": case.title,
            "year": case.year,
            "country": case.country,
            "industry": case.industry,
            "case_type": case.case_type,
            "is_demo_mode": case.is_demo_mode,
            "simple_explanation": case.simple_explanation or case.description,
            "what_happened": case.what_happened,
            "what_was_affected": case.what_was_affected,
            "documented_response": case.documented_response,
            "official_sources": case.official_sources,
            "factual_claims": case.factual_claims,
            "known_attack_steps": case.known_attack_steps,
            "available_evidence": case.available_evidence,
            "missing_information": case.missing_information,
            "files_count": len(case.evidence_files),
            "events_count": len(case.events),
            "steps_count": len(case.nodes),
            "links_count": len(case.edges)
        }
        if case.case_type == "REAL_INCIDENT":
            real_cases.append(case_obj)
        else:
            demo_cases.append(case_obj)

    return {
        "india_incidents": [c for c in real_cases if c.get("country") == "India"],
        "worldwide_incidents": [c for c in real_cases if c.get("country") != "India"],
        "all_real_cases": real_cases,
        "demonstration_cases": demo_cases
    }


@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: str):
    """Retrieve full case details"""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")
    return CASES[case_id]


class CreateCaseRequest(BaseModel):
    title: str
    description: str
    investigator: Optional[str] = "Lead Incident Investigator"
    country: Optional[str] = "Custom Jurisdiction"
    industry: Optional[str] = "Enterprise IT"


@app.post("/api/cases")
def create_case(req: CreateCaseRequest):
    """Create a new blank investigation case"""
    case_id = f"CASE-{datetime.utcnow().strftime('%Y')}-{str(uuid.uuid4())[:4].upper()}"
    case = Case(
        case_id=case_id,
        title=req.title,
        description=req.description,
        simple_explanation=req.description,
        investigator=req.investigator or "Lead Incident Investigator",
        case_type="USER_INVESTIGATION",
        country=req.country,
        industry=req.industry,
        custody_actions=[
            CustodyAction(
                officer=req.investigator or "Lead Incident Investigator",
                action_type="IMPORT",
                details="Investigation case initialized."
            )
        ]
    )
    process_case_pipeline(case)
    CASES[case_id] = case
    return case


class ImportLogRequest(BaseModel):
    filename: str
    source_type: str  # nginx, apache, app_log, waf_alert, pcap, auth_log, csv
    content: str
    custody_officer: Optional[str] = "Lead Incident Investigator"
    evidence_type: Optional[str] = "Imported Evidence"


@app.post("/api/cases/{case_id}/import")
def import_log(case_id: str, req: ImportLogRequest):
    """
    Imports a raw log string into the case, preserves it, immutably hashes it,
    normalizes events, records custody actions, and updates attack reconstruction.
    """
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]

    # Preserve file content to disk
    safe_fname = "".join(c for c in req.filename if c.isalnum() or c in "._-")
    disk_path = os.path.join(EVIDENCE_FILES_DIR, f"{case_id}_{safe_fname}")
    try:
        with open(disk_path, "w", encoding="utf-8") as f:
            f.write(req.content)
    except Exception as e:
        print(f"Warning: unable to preserve file to disk: {e}")
        disk_path = None

    efile = ForensicEngine.register_evidence_file(
        filename=req.filename,
        content=req.content,
        source_type=req.source_type,
        custody_officer=req.custody_officer or case.investigator,
        evidence_type=req.evidence_type or "Imported Evidence",
        disk_filepath=disk_path
    )
    case.evidence_files.append(efile)

    # Parse and normalize records
    new_events = []
    if req.source_type == "csv":
        csv_records = AuthAndCSVParser.parse_csv_content(req.content, req.filename)
        for r in csv_records:
            new_events.append(EventNormalizer.normalize(r, efile.file_id, req.evidence_type or "Imported Evidence"))
    else:
        for line_idx, line in enumerate(req.content.splitlines(), 1):
            if not line.strip():
                continue
            if req.source_type in ("nginx", "apache"):
                raw_dict = WebLogParser.parse_line(line, line_idx, req.filename)
            elif req.source_type == "waf_alert":
                raw_dict = WAFAlertParser.parse_line(line, line_idx, req.filename)
            elif req.source_type == "auth_log":
                raw_dict = AuthAndCSVParser.parse_auth_line(line, line_idx, req.filename)
                if not raw_dict:
                    raw_dict = AppLogParser.parse_line(line, line_idx, req.filename)
            else:
                raw_dict = AppLogParser.parse_line(line, line_idx, req.filename)

            if raw_dict:
                norm_evt = EventNormalizer.normalize(raw_dict, efile.file_id, req.evidence_type or "Imported Evidence")
                new_events.append(norm_evt)

    case.events.extend(new_events)

    # Record custody action
    case.custody_actions.append(CustodyAction(
        officer=req.custody_officer or case.investigator,
        action_type="IMPORT",
        details=f"Uploaded and preserved {req.filename} ({len(new_events)} records parsed, SHA-256: {efile.sha256[:12]}...).",
        file_id=efile.file_id,
        sha256=efile.sha256
    ))

    process_case_pipeline(case)
    return {
        "status": "SUCCESS",
        "file_id": efile.file_id,
        "sha256": efile.sha256,
        "records_imported": len(new_events),
        "total_case_events": len(case.events),
        "preserved_disk_path": disk_path
    }


@app.post("/api/cases/{case_id}/upload")
async def upload_log_file(
    case_id: str,
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    custody_officer: str = Form("Lead Incident Investigator"),
    evidence_type: str = Form("Imported Evidence")
):
    """
    Accepts uploaded log files (TXT, CSV, JSON, Apache/Nginx, PCAP, and PDF source reports).
    Preserves original file on disk, computes SHA-256 hash, extracts structured events,
    and updates the evidence handling audit record.
    """
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    fname = file.filename or "uploaded.log"
    content_bytes = await file.read()

    # Validate file size (max 50 MB)
    if len(content_bytes) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds maximum 50MB size limit")

    # Preserve file on disk
    safe_fname = "".join(c for c in fname if c.isalnum() or c in "._-")
    saved_disk_path = os.path.join(EVIDENCE_FILES_DIR, f"{case_id}_{safe_fname}")
    with open(saved_disk_path, "wb") as f:
        f.write(content_bytes)

    file_hash = ForensicEngine.compute_file_sha256(content_bytes)

    # 1. PCAP format
    if fname.endswith((".pcap", ".pcapng")):
        pcap_events = PCAPParser.parse_pcap_file(saved_disk_path)
        efile = EvidenceFile(
            filename=fname,
            source_type="pcap_network",
            sha256=file_hash,
            size_bytes=len(content_bytes),
            line_count=len(pcap_events),
            custody_officer=custody_officer,
            evidence_type=evidence_type,
            original_filepath=saved_disk_path
        )
        case.evidence_files.append(efile)
        new_events = [EventNormalizer.normalize(ev, efile.file_id, evidence_type) for ev in pcap_events]
        case.events.extend(new_events)

        case.custody_actions.append(CustodyAction(
            officer=custody_officer,
            action_type="IMPORT",
            details=f"Preserved and parsed network PCAP capture {fname} ({len(new_events)} packet flows).",
            file_id=efile.file_id,
            sha256=file_hash
        ))
        process_case_pipeline(case)
        return {"status": "SUCCESS", "records_imported": len(new_events), "sha256": file_hash}

    # 2. PDF report format
    if fname.lower().endswith(".pdf"):
        if not PDFReportParser.is_available():
            raise HTTPException(status_code=500, detail="PyMuPDF library not available for PDF text extraction")

        pdf_records = PDFReportParser.parse_pdf_bytes(content_bytes, fname)
        efile = EvidenceFile(
            filename=fname,
            source_type="pdf_report",
            sha256=file_hash,
            size_bytes=len(content_bytes),
            line_count=len(pdf_records),
            custody_officer=custody_officer,
            evidence_type="Publicly Reported Fact" if "report" in fname.lower() or "advisory" in fname.lower() else evidence_type,
            original_filepath=saved_disk_path
        )
        case.evidence_files.append(efile)
        new_events = [EventNormalizer.normalize(r, efile.file_id, efile.evidence_type) for r in pdf_records]
        case.events.extend(new_events)

        case.custody_actions.append(CustodyAction(
            officer=custody_officer,
            action_type="IMPORT",
            details=f"Preserved and extracted text lines from PDF source report {fname} ({len(new_events)} records).",
            file_id=efile.file_id,
            sha256=file_hash
        ))
        process_case_pipeline(case)
        return {"status": "SUCCESS", "records_imported": len(new_events), "sha256": file_hash}

    # 3. Text/CSV/Log format
    try:
        content_text = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decode file content as text")

    # Detect format
    if source_type == "auto":
        fname_lower = fname.lower()
        if fname_lower.endswith(".csv"):
            stype = "csv"
        elif "nginx" in fname_lower:
            stype = "nginx"
        elif "apache" in fname_lower:
            stype = "apache"
        elif "waf" in fname_lower or "modsec" in fname_lower or "suricata" in fname_lower:
            stype = "waf_alert"
        elif "auth" in fname_lower or "secure" in fname_lower or "sshd" in fname_lower:
            stype = "auth_log"
        else:
            stype = "app_log"
    else:
        stype = source_type

    req = ImportLogRequest(
        filename=fname,
        source_type=stype,
        content=content_text,
        custody_officer=custody_officer,
        evidence_type=evidence_type
    )
    return import_log(case_id, req)


@app.get("/api/cases/{case_id}/graph")
def get_attack_graph(case_id: str, hypothesis_id: Optional[str] = None):
    """
    Returns visual attack graph nodes, edges, hypotheses, and indicators.
    Allows filtering by selected competing hypothesis.
    """
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    nodes = case.nodes
    edges = case.edges

    # If filtered by hypothesis
    if hypothesis_id:
        hyp = next((h for h in case.hypotheses if h.hypothesis_id == hypothesis_id), None)
        if hyp and hyp.included_edge_ids:
            edges = [e for e in edges if e.edge_id in hyp.included_edge_ids]
            valid_node_ids = set()
            for e in edges:
                valid_node_ids.add(e.source_event_id)
                valid_node_ids.add(e.target_event_id)
            if valid_node_ids:
                nodes = [n for n in nodes if n.id in valid_node_ids]

    return {
        "case_id": case.case_id,
        "nodes": nodes,
        "edges": edges,
        "hypotheses": case.hypotheses,
        "evidence_gaps": case.evidence_gaps,
        "metrics": case.summary_metrics
    }


@app.get("/api/cases/{case_id}/timeline")
def get_timeline(case_id: str, severity: Optional[str] = None, source: Optional[str] = None):
    """Returns chronological event stream with filtering capabilities"""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    evts = sorted(case.events, key=lambda e: e.timestamp)

    if severity:
        evts = [e for e in evts if e.severity.upper() == severity.upper()]
    if source:
        evts = [e for e in evts if e.source_type.lower() == source.lower()]

    return evts


@app.get("/api/cases/{case_id}/evidence/{event_id}")
def get_evidence_proof(case_id: str, event_id: str):
    """
    Returns the complete immutable evidence record, byte offset, line number,
    original raw text, SHA-256 hash, and tamper verification.
    """
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    proof = ForensicEngine.get_evidence_proof(case, event_id)
    if "error" in proof:
        raise HTTPException(status_code=404, detail=proof["error"])
    return proof


@app.post("/api/cases/{case_id}/verify-integrity")
def verify_integrity(case_id: str):
    """
    Re-hashes all evidence files on disk and stored event records to cryptographically
    certify whether any evidence has been altered or tampered with.
    """
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    res = ForensicEngine.verify_case_integrity(case)
    save_case_to_disk(case)
    return res


class CustodyNoteRequest(BaseModel):
    officer: str
    action_type: str = "NOTE"
    details: str


@app.post("/api/cases/{case_id}/custody-action")
def add_custody_action(case_id: str, req: CustodyNoteRequest):
    """Appends an evidence-handling or investigator action to the custody audit log"""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    action = CustodyAction(
        officer=req.officer,
        action_type=req.action_type,
        details=req.details
    )
    case.custody_actions.append(action)
    save_case_to_disk(case)
    return action


@app.get("/api/cases/{case_id}/report/preview")
def get_report_preview(case_id: str):
    """Returns structured preview data for the Download Case Report view"""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    return ReportGenerator.generate_json_report(case)


@app.get("/api/cases/{case_id}/report/pdf")
def export_pdf_report(case_id: str):
    """Generates and downloads the official forensic investigation PDF report"""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    try:
        pdf_bytes = ReportGenerator.generate_pdf_report(case)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="TraceGuard_Report_{case.case_id}.pdf"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@app.get("/api/cases/{case_id}/report/json")
def export_json_report(case_id: str):
    """Downloads full JSON investigation bundle"""
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")

    case = CASES[case_id]
    dossier = ReportGenerator.generate_json_report(case)
    return JSONResponse(
        content=dossier,
        headers={
            "Content-Disposition": f'attachment; filename="TraceGuard_Investigation_{case.case_id}.json"'
        }
    )


@app.get("/api/evaluation/run")
def run_evaluation_benchmark():
    """Runs controlled attack simulation benchmarks against ground-truth and test scenarios"""
    return BenchmarkEvaluator.run_benchmark()


@app.get("/api/evaluation/scenarios")
def get_evaluation_scenarios():
    """Returns the five controlled testing scenarios with detection results and explanations"""
    return BenchmarkEvaluator.get_test_scenarios_list()


@app.post("/api/cases/reset-samples")
def reset_samples():
    """Restores default real cases and sample scenarios"""
    initialize_real_cases()
    initialize_sample_scenarios()
    return {"status": "SUCCESS", "message": "Cases reloaded successfully."}


# Mount static assets
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "TraceGuard API Online. Visit /static/index.html"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
