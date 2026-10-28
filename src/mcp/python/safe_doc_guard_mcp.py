"""
safe-doc-guard-mcp (Python FastMCP Implementation)
Production Model Context Protocol (MCP) Server acting as a security intermediary
between untrusted PDF/text documents and LLM agents with database access.
"""

from typing import Literal, Optional, List, Dict, Any
from pydantic import BaseModel, Field
import base64
import hashlib
import re
import time
import io
from mcp.server.fastmcp import FastMCP
from pypdf import PdfReader

# Initialize FastMCP Server
mcp = FastMCP(
    "safe-doc-guard-mcp",
    dependencies=["pypdf", "pydantic", "mcp"]
)

# ---------------------------------------------------------
# Schemas & Types
# ---------------------------------------------------------

class SecurityVerdict(BaseModel):
    is_poisoned: bool = Field(description="Whether indirect prompt injection or exfiltration is detected")
    risk_score: float = Field(ge=0.0, le=1.0, description="Risk score from 0.0 to 1.0")
    detected_patterns: List[str] = Field(default_factory=list, description="List of flagged pattern IDs")
    suspicious_excerpts: List[str] = Field(default_factory=list, description="Extracted suspicious snippets")

class DocumentMetadata(BaseModel):
    source_name: str
    mime_type: str
    byte_length: int
    page_count: int
    title: Optional[str] = None
    author: Optional[str] = None
    subject: Optional[str] = None
    keywords: Optional[str] = None
    annotations: List[str] = Field(default_factory=list)
    sha256_fingerprint: str

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

# In-Memory HITL Quarantine Store
QUARANTINE_STORE: Dict[str, QuarantinedRecord] = {}

# ---------------------------------------------------------
# Heuristic Scanner & Extraction
# ---------------------------------------------------------

ZERO_WIDTH_CHARS = re.compile(r'[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]')
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')
OVERRIDE_REGEX = re.compile(
    r'\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|directives|rules|prompts)\b',
    re.IGNORECASE
)
SYSTEM_TAGS_REGEX = re.compile(r'(?:<\/?system>|\[\/?INST\]|<\|im_start\|>|<\|im_end\|>)', re.IGNORECASE)
SQL_EXFIL_REGEX = re.compile(
    r'\b(?:SELECT\s+[\w*,\s]+\s+FROM\s+(?:users|accounts|customer_api_keys|payroll|credentials)|UNION\s+SELECT)\b',
    re.IGNORECASE
)
BASE64_BLOB_REGEX = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b')

def decode_base64_payload(data: str) -> bytes:
    clean = re.sub(r'^data:[^;]+;base64,', '', data.strip())
    clean = re.sub(r'\s+', '', clean)
    return base64.b64decode(clean)

def extract_pdf_data(raw_bytes: bytes, source_name: str) -> tuple[str, List[str], DocumentMetadata]:
    reader = PdfReader(io.BytesIO(raw_bytes))
    visible_lines: List[str] = []
    annotations: List[str] = []

    for page in reader.pages:
        text = page.extract_text() or ""
        if text:
            visible_lines.append(text)
        if "/Annots" in page:
            for annot_ref in page["/Annots"]:
                annot_obj = annot_ref.get_object()
                if "/Contents" in annot_obj:
                    annotations.append(str(annot_obj["/Contents"]))

    info = reader.metadata or {}
    meta = DocumentMetadata(
        source_name=source_name,
        mime_type="application/pdf",
        byte_length=len(raw_bytes),
        page_count=len(reader.pages),
        title=info.get("/Title") or source_name,
        author=info.get("/Author") or "Unknown",
        subject=info.get("/Subject"),
        keywords=info.get("/Keywords"),
        annotations=annotations,
        sha256_fingerprint=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
    )
    return "\n".join(visible_lines), annotations, meta

# ---------------------------------------------------------
# MCP Tools Implementation
# ---------------------------------------------------------

@mcp.tool()
def inspect_and_read_document(
    mime_type: Literal["application/pdf", "text/plain", "text/markdown"] = "application/pdf",
    file_path: Optional[str] = None,
    base64_data: Optional[str] = None
) -> Dict[str, Any]:
    """
    Securely inspects and reads a document, intercepting indirect prompt injections,
    zero-width steganography, and SQL exfiltration payloads before LLM ingestion.
    """
    if not file_path and not base64_data:
        raise ValueError("Either file_path or base64_data must be provided.")

    if base64_data:
        raw_bytes = decode_base64_payload(base64_data)
        source_name = "inline_base64_payload"
    else:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        source_name = file_path

    # Extract text and metadata
    if mime_type == "application/pdf" or raw_bytes.startswith(b"%PDF-"):
        visible_text, annotations, meta = extract_pdf_data(raw_bytes, source_name)
    else:
        visible_text = raw_bytes.decode("utf-8", errors="replace")
        annotations = []
        meta = DocumentMetadata(
            source_name=source_name,
            mime_type=mime_type,
            byte_length=len(raw_bytes),
            page_count=1,
            title=source_name,
            author="Plaintext Stream",
            annotations=[],
            sha256_fingerprint=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
        )

    # Heuristic Pre-filter
    surface = visible_text + "\n" + "\n".join(annotations)
    detected_patterns: List[str] = []
    suspicious_excerpts: List[str] = []
    risk_score = 0.0

    zw_matches = ZERO_WIDTH_CHARS.findall(surface)
    if zw_matches:
        detected_patterns.append("ZERO_WIDTH_CHAR:STEGO_UNICODE")
        risk_score += 0.4
        suspicious_excerpts.append(f"Found {len(zw_matches)} zero-width Unicode characters")

    if OVERRIDE_REGEX.search(surface):
        detected_patterns.append("CLASSIC_OVERRIDE:IGNORE_INSTRUCTIONS")
        risk_score += 0.5
        suspicious_excerpts.append("Contains directive to ignore previous instructions")

    if SYSTEM_TAGS_REGEX.search(surface):
        detected_patterns.append("CLASSIC_OVERRIDE:SYSTEM_TAG_INJECTION")
        risk_score += 0.45
        suspicious_excerpts.append("Contains LLM system boundary tags (<system>, [INST])")

    if SQL_EXFIL_REGEX.search(surface):
        detected_patterns.append("SQL_EXFILTRATION:DATABASE_DUMP_COMMAND")
        risk_score += 0.6
        suspicious_excerpts.append("Contains SQL query targeting users/accounts credentials")

    for b64_cand in BASE64_BLOB_REGEX.findall(surface):
        try:
            dec = base64.b64decode(b64_cand).decode("utf-8", errors="ignore")
            if OVERRIDE_REGEX.search(dec) or SQL_EXFIL_REGEX.search(dec):
                detected_patterns.append("OBFUSCATED_BASE64:HIDDEN_PAYLOAD")
                risk_score += 0.55
                suspicious_excerpts.append(f"Embedded Base64 decoded to: {dec[:80]}")
        except Exception:
            pass

    risk_score = min(1.0, round(risk_score, 2))
    is_poisoned = risk_score >= 0.35 or len(detected_patterns) > 0

    verdict = SecurityVerdict(
        is_poisoned=is_poisoned,
        risk_score=risk_score if is_poisoned else 0.0,
        detected_patterns=detected_patterns,
        suspicious_excerpts=suspicious_excerpts
    )

    if not is_poisoned:
        return {
            "status": "SAFE",
            "verdict": verdict.model_dump(),
            "document": {
                "text": visible_text,
                "metadata": meta.model_dump()
            }
        }

    # Document is poisoned -> Quarantine
    token = f"SDG-HITL-{int(time.time())}-{hashlib.md5(surface.encode()).hexdigest()[:6].upper()}"
    sanitized_text = re.sub(
        r'(?i)(?:ignore\s+previous|system\s+prompt|SELECT\s+.*FROM|UNION\s+SELECT).*',
        '[REDACTED BY SAFE-DOC-GUARD-MCP: INSTRUCTION OMITTED]',
        visible_text
    )

    QUARANTINE_STORE[token] = QuarantinedRecord(
        review_token=token,
        created_at=time.time(),
        source_name=source_name,
        mime_type=mime_type,
        raw_text=visible_text,
        sanitized_text=sanitized_text,
        metadata=meta,
        verdict=verdict,
        heuristic_matches=[],
        status="PENDING"
    )

    return {
        "status": "INTERVENTION_REQUIRED",
        "review_token": token,
        "verdict": verdict.model_dump(),
        "warning_payload": {
            "message": "SECURITY INTERVENTION REQUIRED: Indirect prompt injection detected.",
            "sanitized_preview": sanitized_text,
            "flagged_snippets": suspicious_excerpts,
            "hitl_instructions": f'Invoke "approve_quarantined_content" with review_token="{token}".'
        }
    }

@mcp.tool()
def approve_quarantined_content(
    review_token: str,
    override_decision: Literal["APPROVE_RAW", "ALLOW_SANITIZED", "REJECT"],
    reviewer_note: Optional[str] = None
) -> Dict[str, Any]:
    """
    Human-in-the-loop (HITL) resolution tool to release or reject a quarantined document.
    """
    record = QUARANTINE_STORE.get(review_token.strip())
    if not record:
        raise ValueError(f"Review token '{review_token}' not found.")

    record.status = {
        "APPROVE_RAW": "APPROVED_RAW",
        "ALLOW_SANITIZED": "ALLOWED_SANITIZED",
        "REJECT": "REJECTED"
    }[override_decision]
    record.resolved_at = time.time()
    record.override_decision = override_decision
    record.reviewer_note = reviewer_note

    if override_decision == "REJECT":
        return {
            "status": "REJECTED",
            "review_token": review_token,
            "message": f"Document {record.source_name} rejected by security reviewer."
        }
    elif override_decision == "ALLOW_SANITIZED":
        return {
            "status": "RELEASED_SANITIZED",
            "review_token": review_token,
            "document": {
                "text": record.sanitized_text,
                "metadata": record.metadata.model_dump()
            },
            "message": "Sanitized document released with malicious instructions redacted."
        }
    else:
        return {
            "status": "RELEASED_RAW",
            "review_token": review_token,
            "document": {
                "text": record.raw_text,
                "metadata": record.metadata.model_dump()
            },
            "message": "Raw document released by explicit human override."
        }

if __name__ == "__main__":
    mcp.run()
