"""
Forensic Evidence Preservation - Cryptographic hashing, immutability checks, and chain of custody
Adheres to strict forensic defensibility standards and immutable SHA-256 integrity verification.
"""
import os
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime
from backend.models import Case, EvidenceFile, NormalizedEvent, IntegrityVerification, CustodyAction


class ForensicEngine:
    HASH_DISCLAIMER = (
        "A matching hash confirms that the file matches the version used to create the stored hash; "
        "it does not prove that the original file was authentic before import."
    )

    @staticmethod
    def compute_sha256(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_file_sha256(file_bytes: bytes) -> str:
        return hashlib.sha256(file_bytes).hexdigest()

    @classmethod
    def register_evidence_file(
        cls,
        filename: str,
        content: str,
        source_type: str,
        custody_officer: str = "Lead Incident Investigator",
        evidence_type: str = "Imported Evidence",
        disk_filepath: Optional[str] = None
    ) -> EvidenceFile:
        file_hash = cls.compute_sha256(content)
        lines = content.splitlines()
        now_ts = datetime.utcnow().isoformat() + "Z"
        
        return EvidenceFile(
            filename=filename,
            source_type=source_type,
            sha256=file_hash,
            size_bytes=len(content.encode('utf-8')),
            line_count=len(lines),
            imported_at=now_ts,
            custody_officer=custody_officer,
            evidence_type=evidence_type,
            original_filepath=disk_filepath,
            stored_hash_match=True,
            last_verified_at=now_ts
        )

    @classmethod
    def verify_case_integrity(cls, case: Case) -> IntegrityVerification:
        """
        Cryptographically verifies:
        1. All stored evidence files (re-computing SHA-256 from preserved disk files if present).
        2. All stored normalized events against raw log records.
        Records an audit action into case custody log.
        """
        mismatches = []
        records_verified = 0
        now_ts = datetime.utcnow().isoformat() + "Z"

        # 1. Verify files
        for efile in case.evidence_files:
            file_match = True
            if efile.original_filepath and os.path.exists(efile.original_filepath):
                try:
                    with open(efile.original_filepath, "rb") as f:
                        disk_hash = cls.compute_file_sha256(f.read())
                    if disk_hash != efile.sha256:
                        file_match = False
                        mismatches.append(
                            f"File integrity mismatch for {efile.filename}: recorded hash {efile.sha256[:12]}... "
                            f"does not match current disk hash {disk_hash[:12]}..."
                        )
                except Exception as e:
                    mismatches.append(f"Unable to read stored evidence file {efile.filename}: {e}")
                    file_match = False

            efile.stored_hash_match = file_match
            efile.last_verified_at = now_ts

        # 2. Verify individual event records
        for event in case.events:
            records_verified += 1
            expected_hash = cls.compute_sha256(event.raw_record)
            if expected_hash != event.raw_hash:
                mismatches.append(
                    f"Record tamper detected at event {event.event_id} (line {event.line_number} in {event.source_file}): "
                    f"stored hash {event.raw_hash[:12]}... does not match computed hash {expected_hash[:12]}..."
                )

        overall_valid = len(mismatches) == 0

        # Log custody action
        action_desc = (
            f"Cryptographic integrity check executed: {len(case.evidence_files)} files and {records_verified} records verified. "
            f"Status: {'PASSED (All Hashes Intact)' if overall_valid else f'FAILED ({len(mismatches)} mismatches)'}."
        )
        case.custody_actions.append(CustodyAction(
            officer=case.investigator or "System Integrity Monitor",
            action_type="VERIFICATION",
            details=action_desc
        ))

        return IntegrityVerification(
            overall_valid=overall_valid,
            files_verified=len(case.evidence_files),
            records_verified=records_verified,
            mismatches=mismatches,
            verified_at=now_ts,
            hash_algorithm="SHA-256",
            disclaimer=cls.HASH_DISCLAIMER
        )

    @classmethod
    def get_evidence_proof(cls, case: Case, event_id: str) -> Dict[str, Any]:
        """
        Retrieves complete forensic chain-of-custody and verification proof for a single event.
        """
        event = next((e for e in case.events if e.event_id == event_id), None)
        if not event:
            return {"error": "Event not found"}

        # Find corresponding evidence file
        evidence_file = next(
            (f for f in case.evidence_files if f.filename == event.source_file or f.file_id == event.file_id),
            None
        )

        recomputed_hash = cls.compute_sha256(event.raw_record)
        is_tamper_free = (recomputed_hash == event.raw_hash)

        return {
            "event_id": event.event_id,
            "source_file": event.source_file,
            "source_type": event.source_type,
            "line_number": event.line_number,
            "byte_offset": event.byte_offset,
            "timestamp": event.timestamp,
            "raw_record": event.raw_record,
            "raw_hash": event.raw_hash,
            "recomputed_hash": recomputed_hash,
            "is_tamper_free": is_tamper_free,
            "evidence_classification": event.evidence_classification,
            "source_citation": event.source_citation,
            "factual_source_url": event.factual_source_url,
            "file_sha256": evidence_file.sha256 if evidence_file else "N/A",
            "imported_at": evidence_file.imported_at if evidence_file else "N/A",
            "custody_officer": evidence_file.custody_officer if evidence_file else "Lead Incident Investigator",
            "disclaimer": cls.HASH_DISCLAIMER,
            "extracted_fields": {
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "user": event.user,
                "session_id": event.session_id,
                "request_id": event.request_id,
                "http_method": event.http_method,
                "endpoint": event.endpoint,
                "query_params": event.query_params,
                "status_code": event.status_code,
                "event_category": event.event_category,
                "severity": event.severity,
                "attack_indicators": event.attack_indicators,
                "mitre_tactics": event.mitre_tactics,
                "mitre_techniques": event.mitre_techniques
            }
        }
