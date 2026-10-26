"""
TraceGuard Models - Data Structures for Web Attack Path Reconstruction
Enhanced with evidentiary classifications, real-world case metadata, and custody auditing.
"""
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class EvidenceFile(BaseModel):
    file_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    filename: str
    source_type: str  # nginx, apache, app_log, waf_alert, pcap, pdf_report, auth_log, csv
    sha256: str
    size_bytes: int
    line_count: int
    imported_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    custody_officer: str = "Lead Incident Investigator"
    evidence_type: str = "Imported Evidence"  # Publicly Reported Fact, Imported Evidence, Simulated Demo Data
    original_filepath: Optional[str] = None
    stored_hash_match: Optional[bool] = True
    last_verified_at: Optional[str] = None


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: "EVT-" + str(uuid.uuid4())[:8].upper())
    file_id: str
    source_type: str  # nginx, apache, app_log, waf_alert, pcap, public_report, auth_log
    source_file: str
    line_number: int
    byte_offset: Optional[int] = 0
    raw_record: str
    raw_hash: str  # SHA-256 of raw line for tamper evidence
    timestamp: str  # ISO-8601 string
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    query_params: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    event_category: str = "BENIGN_OR_UNKNOWN"
    attack_indicators: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    evidence_classification: str = "Imported Evidence"  # Publicly Reported Fact, Imported Evidence, Analyst's Interpretation, Simulated Demo Data, Unverified Information
    source_citation: Optional[str] = None
    factual_source_url: Optional[str] = None
    extra_metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackNode(BaseModel):
    id: str  # event_id
    label: str
    timestamp: str
    event_category: str
    severity: str
    source_type: str
    endpoint: Optional[str] = None
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    status_code: Optional[int] = None
    attack_indicators: List[str] = Field(default_factory=list)
    raw_hash: str
    mitre_technique: Optional[str] = None
    is_pivot_node: bool = False
    is_entry_point: bool = False
    evidence_classification: str = "Imported Evidence"  # Publicly Reported Fact, Imported Evidence, Analyst's Interpretation, Simulated Demo Data, Unverified Information
    source_citation: Optional[str] = None
    factual_source_url: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class AttackEdge(BaseModel):
    edge_id: str = Field(default_factory=lambda: "EDGE-" + str(uuid.uuid4())[:8].upper())
    source_event_id: str
    target_event_id: str
    rule_name: str
    confidence_level: str  # STRONGLY_SUPPORTED, PARTIALLY_SUPPORTED, SPECULATIVE
    confidence_score: float  # 0.0 to 1.0
    explanation: str
    time_delta_seconds: float
    matching_fields: Dict[str, Any] = Field(default_factory=dict)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    hypothesis_tags: List[str] = Field(default_factory=list)
    evidence_classification: str = "Analyst's Interpretation"  # All correlation links represent analytical connections


class EvidenceGap(BaseModel):
    gap_id: str = Field(default_factory=lambda: "GAP-" + str(uuid.uuid4())[:6].upper())
    title: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW
    expected_log_type: str
    observed_before_id: Optional[str] = None
    observed_after_id: Optional[str] = None
    recommended_action: str
    affected_hypotheses: List[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: "HYP-" + str(uuid.uuid4())[:6].upper())
    name: str
    description: str
    narrative: str
    likelihood_score: float  # 0.0 to 1.0
    confidence_rating: str  # HIGH, MEDIUM, LOW
    included_event_ids: List[str] = Field(default_factory=list)
    included_edge_ids: List[str] = Field(default_factory=list)
    supporting_evidence_count: int = 0
    speculative_links_count: int = 0
    evidence_gaps_count: int = 0
    mitre_attack_chain: List[str] = Field(default_factory=list)
    key_differentiator: str = ""


class CustodyAction(BaseModel):
    action_id: str = Field(default_factory=lambda: "ACT-" + str(uuid.uuid4())[:6].upper())
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    officer: str
    action_type: str  # IMPORT, VERIFICATION, EXPORT, NOTE
    details: str
    file_id: Optional[str] = None
    sha256: Optional[str] = None


class IntegrityVerification(BaseModel):
    overall_valid: bool
    files_verified: int
    records_verified: int
    mismatches: List[str] = Field(default_factory=list)
    verified_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    hash_algorithm: str = "SHA-256"
    disclaimer: str = (
        "A matching hash confirms that the file matches the version used to create the stored hash; "
        "it does not prove that the original file was authentic before import."
    )


class Case(BaseModel):
    case_id: str
    title: str
    description: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    investigator: str = "Lead Incident Responder"
    status: str = "ACTIVE"
    case_type: str = "SIMULATION"  # REAL_INCIDENT, SIMULATION, USER_INVESTIGATION
    year: Optional[int] = None
    country: Optional[str] = None
    industry: Optional[str] = None
    simple_explanation: Optional[str] = None
    what_happened: Optional[str] = None
    what_was_affected: Optional[str] = None
    documented_response: Optional[str] = None
    official_sources: List[Dict[str, str]] = Field(default_factory=list)
    factual_claims: List[Dict[str, str]] = Field(default_factory=list)
    known_attack_steps: List[Dict[str, Any]] = Field(default_factory=list)
    available_evidence: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    is_demo_mode: bool = False
    evidence_files: List[EvidenceFile] = Field(default_factory=list)
    events: List[NormalizedEvent] = Field(default_factory=list)
    nodes: List[AttackNode] = Field(default_factory=list)
    edges: List[AttackEdge] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    custody_actions: List[CustodyAction] = Field(default_factory=list)
    summary_metrics: Dict[str, Any] = Field(default_factory=dict)
