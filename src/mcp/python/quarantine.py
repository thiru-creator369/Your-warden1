"""
quarantine.py: Cryptographic Human-in-the-Loop Quarantine Store
Manages review tokens and override decisions (APPROVE_RAW, ALLOW_SANITIZED, REJECT).
"""

from typing import Dict, Optional, List, Literal
import time
import uuid
from pydantic import BaseModel
from security import SecurityVerdict, DocumentMetadata

class QuarantinedRecord(BaseModel):
    review_token: str
    created_at: float
    source_name: str
    mime_type: str
    raw_text: str
    sanitized_text: str
    metadata: DocumentMetadata
    verdict: SecurityVerdict
    heuristic_matches: List[Dict[str, Any]]
    status: Literal["PENDING", "APPROVED_RAW", "ALLOWED_SANITIZED", "REJECTED"]
    resolved_at: Optional[float] = None
    override_decision: Optional[str] = None
    reviewer_note: Optional[str] = None

class QuarantineManager:
    def __init__(self):
        self._records: Dict[str, QuarantinedRecord] = {}

    def create_record(
        self,
        source_name: str,
        mime_type: str,
        raw_text: str,
        sanitized_text: str,
        metadata: DocumentMetadata,
        verdict: SecurityVerdict,
        heuristic_matches: List[Dict[str, Any]]
    ) -> QuarantinedRecord:
        token = f"SDG-HITL-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
        record = QuarantinedRecord(
            review_token=token,
            created_at=time.time(),
            source_name=source_name,
            mime_type=mime_type,
            raw_text=raw_text,
            sanitized_text=sanitized_text,
            metadata=metadata,
            verdict=verdict,
            heuristic_matches=heuristic_matches,
            status="PENDING"
        )
        self._records[token] = record
        return record

    def get_record(self, review_token: str) -> Optional[QuarantinedRecord]:
        return self._records.get(review_token.strip())

    def resolve_record(
        self,
        review_token: str,
        override_decision: Literal["APPROVE_RAW", "ALLOW_SANITIZED", "REJECT"],
        reviewer_note: Optional[str] = None
    ) -> QuarantinedRecord:
        record = self._records.get(review_token.strip())
        if not record:
            raise KeyError(f"Quarantine token '{review_token}' not found.")

        record.status = {
            "APPROVE_RAW": "APPROVED_RAW",
            "ALLOW_SANITIZED": "ALLOWED_SANITIZED",
            "REJECT": "REJECTED"
        }[override_decision]
        record.resolved_at = time.time()
        record.override_decision = override_decision
        record.reviewer_note = reviewer_note

        self._records[record.review_token] = record
        return record

    def list_records(self) -> List[QuarantinedRecord]:
        return sorted(self._records.values(), key=lambda r: r.created_at, reverse=True)

quarantine_store = QuarantineManager()
