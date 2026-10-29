"""
safe-doc-guard-mcp (Self-Contained Standalone Production Server)
Single-file Python server combining FastMCP tools, document extraction,
heuristic regex pre-filtering, and quarantine store with ZERO external sibling imports.
"""

import sys
import time
import base64
import hashlib
import io
import re
import uuid
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from pypdf import PdfReader

# 1. Initialize FastMCP Server
mcp = FastMCP(
    name="safe-doc-guard-mcp",
    dependencies=["pypdf", "pydantic", "mcp"]
)

# 2. Pydantic Models & Security Schemas
class SecurityVerdict(BaseModel):
    is_poisoned: bool = Field(description="True if indirect injection or exfiltration is detected")
    risk_score: float = Field(ge=0.0, le=1.0, description="Risk score from 0.0 to 1.0")
    detected_patterns: List[str] = Field(default_factory=list, description="IDs of flagged patterns")
    suspicious_excerpts: List[str] = Field(default_factory=list, description="Flagged snippets")

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
    status: Literal["PENDING", "APPROVED_RAW", "ALLOWED_SANITIZED", "REJECTED"]
    resolved_at: Optional[float] = None
    override_decision: Optional[str] = None
    reviewer_note: Optional[str] = None

# In-Memory Quarantine Store
QUARANTINE_STORE: Dict[str, QuarantinedRecord] = {}

# 3. Heuristic Regex Pre-Filter
ZERO_WIDTH_REGEX = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]")
ASCII_CONTROL_REGEX = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
OVERRIDE_REGEX = re.compile(
    r"\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|directives|rules|prompts|boundaries)\b",
    re.IGNORECASE
)
SYSTEM_TAGS_REGEX = re.compile(r"(?:<\/?system>|\[\/?INST\]|<\|im_start\|>|<\|im_end\|>)", re.IGNORECASE)
SQL_EXFIL_REGEX = re.compile(
    r"\b(?:SELECT\s+[\w*,\s]+\s+FROM\s+(?:users|accounts|customer_api_keys|payroll|credentials|information_schema\.columns)|UNION\s+SELECT)\b",
    re.IGNORECASE
)
BASE64_BLOB_REGEX = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b")

def decode_base64_payload(data: str) -> bytes:
    cleaned = re.sub(r"^data:[^;]+;base64,", "", data.strip())
    cleaned = re.sub(r"\s+", "", cleaned)
    return base64.b64decode(cleaned)

def extract_document(file_path: Optional[str], base64_data: Optional[str], mime_type: str):
    if base64_data:
        raw_bytes = decode_base64_payload(base64_data)
        source_name = "inline_base64_document"
    elif file_path:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        source_name = file_path
    else:
        raise ValueError("Either file_path or base64_data must be provided.")

    sha256 = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"

    if mime_type == "application/pdf" or raw_bytes.startswith(b"%PDF-"):
        reader = PdfReader(io.BytesIO(raw_bytes))
        visible_lines = []
        annotations = []
        for page in reader.pages:
            t = page.extract_text() or ""
            if t:
                visible_lines.append(t)
            if "/Annots" in page:
                for annot_ref in page["/Annots"]:
                    try:
                        obj = annot_ref.get_object()
                        if "/Contents" in obj:
                            annotations.append(str(obj["/Contents"]))
                    except Exception:
                        pass
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
            sha256_fingerprint=sha256
        )
        visible_text = "\n".join(visible_lines)
        combined = visible_text + "\n" + "\n".join(annotations)
        return visible_text, annotations, meta, combined

    text = raw_bytes.decode("utf-8", errors="replace")
    meta = DocumentMetadata(
        source_name=source_name,
        mime_type=mime_type,
        byte_length=len(raw_bytes),
        page_count=1,
        title=source_name,
        author="Plaintext Stream",
        annotations=[],
        sha256_fingerprint=sha256
    )
    return text, [], meta, text

# 4. MCP Tools
@mcp.tool()
def inspect_and_read_document(
    mime_type: Literal["application/pdf", "text/plain", "text/markdown", "text/csv"] = "application/pdf",
    file_path: Optional[str] = None,
    base64_data: Optional[str] = None
) -> Dict[str, Any]:
    """Inspects document for prompt injections, zero-width chars, and SQL exfiltration payloads."""
    try:
        visible_text, annotations, meta, surface = extract_document(file_path, base64_data, mime_type)
        detected_patterns = []
        suspicious_excerpts = []
        risk_score = 0.0

        clean_surface = ZERO_WIDTH_REGEX.sub("", surface)

        zw_chars = ZERO_WIDTH_REGEX.findall(surface)
        if zw_chars:
            detected_patterns.append("ZERO_WIDTH_CHAR:STEGO_UNICODE")
            risk_score += 0.4
            suspicious_excerpts.append(f"Found {len(zw_chars)} zero-width characters")

        if OVERRIDE_REGEX.search(clean_surface):
            detected_patterns.append("CLASSIC_OVERRIDE:IGNORE_INSTRUCTIONS")
            risk_score += 0.5
            suspicious_excerpts.append("Contains override directive ('ignore previous instructions')")

        if SYSTEM_TAGS_REGEX.search(clean_surface):
            detected_patterns.append("CLASSIC_OVERRIDE:SYSTEM_TAGS")
            risk_score += 0.45
            suspicious_excerpts.append("Contains boundary tags (<system>, [INST])")

        if SQL_EXFIL_REGEX.search(clean_surface):
            detected_patterns.append("SQL_EXFILTRATION:DATABASE_QUERY")
            risk_score += 0.6
            suspicious_excerpts.append("Contains SQL query targeting credential tables")

        for b64_cand in BASE64_BLOB_REGEX.findall(clean_surface):
            try:
                dec = base64.b64decode(b64_cand).decode("utf-8", errors="ignore")
                if OVERRIDE_REGEX.search(dec) or SQL_EXFIL_REGEX.search(dec):
                    detected_patterns.append("OBFUSCATED_BASE64:PAYLOAD")
                    risk_score += 0.55
                    suspicious_excerpts.append(f"Decoded Base64: {dec[:80]}")
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
                "document": {"text": visible_text, "metadata": meta.model_dump()}
            }

        token = f"SDG-HITL-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
        sanitized = re.sub(
            r"(?i)(?:ignore\s+previous|system\s+prompt|SELECT\s+.*FROM|UNION\s+SELECT).*",
            "[REDACTED BY SAFE-DOC-GUARD-MCP: INJECTION OMITTED]",
            visible_text
        )

        QUARANTINE_STORE[token] = QuarantinedRecord(
            review_token=token,
            created_at=time.time(),
            source_name=meta.source_name,
            mime_type=meta.mime_type,
            raw_text=visible_text,
            sanitized_text=sanitized,
            metadata=meta,
            verdict=verdict,
            status="PENDING"
        )

        return {
            "status": "INTERVENTION_REQUIRED",
            "review_token": token,
            "verdict": verdict.model_dump(),
            "warning_payload": {
                "message": "SECURITY INTERVENTION REQUIRED: Prompt injection or SQL exfiltration detected.",
                "sanitized_preview": sanitized,
                "flagged_snippets": suspicious_excerpts,
                "hitl_instructions": f'Call approve_quarantined_content with review_token="{token}".'
            }
        }
    except Exception as exc:
        return {"error": str(exc), "status": "ERROR"}

@mcp.tool()
def approve_quarantined_content(
    review_token: str,
    override_decision: Literal["APPROVE_RAW", "ALLOW_SANITIZED", "REJECT"],
    reviewer_note: Optional[str] = None
) -> Dict[str, Any]:
    """Human-in-the-loop (HITL) resolution tool to approve or reject a quarantined document."""
    rec = QUARANTINE_STORE.get(review_token.strip())
    if not rec:
        return {"error": f"Review token '{review_token}' not found.", "status": "ERROR"}

    rec.status = {
        "APPROVE_RAW": "APPROVED_RAW",
        "ALLOW_SANITIZED": "ALLOWED_SANITIZED",
        "REJECT": "REJECTED"
    }[override_decision]
    rec.resolved_at = time.time()
    rec.override_decision = override_decision
    rec.reviewer_note = reviewer_note

    if override_decision == "REJECT":
        return {
            "status": "REJECTED",
            "review_token": review_token,
            "message": f"Document {rec.source_name} rejected. Zero contents released."
        }
    elif override_decision == "ALLOW_SANITIZED":
        return {
            "status": "RELEASED_SANITIZED",
            "review_token": review_token,
            "document": {"text": rec.sanitized_text, "metadata": rec.metadata.model_dump()},
            "message": "Sanitized document released with injection payloads scrubbed."
        }
    else:
        return {
            "status": "RELEASED_RAW",
            "review_token": review_token,
            "document": {"text": rec.raw_text, "metadata": rec.metadata.model_dump()},
            "message": "WARNING: Raw document released via explicit human override."
        }

if __name__ == "__main__":
    mcp.run()
# ---------------------------------------------------------------------------
# FastAPI ASGI Application & Swagger UI
# ---------------------------------------------------------------------------
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="safe-doc-guard-mcp Dashboard & API",
    description="Intermediary guarding database-connected LLM agents against indirect prompt injection.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "status": "online",
        "service": "safe-doc-guard-mcp",
        "docs": "/docs",
        "health": "/health",
        "message": "Safe Doc Guard MCP server is online!"
    }

@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    return {
        "status": "ok",
        "service": "safe-doc-guard-mcp",
        "quarantine_count": len(QUARANTINE_STORE)
    }

@app.post("/api/inspect-and-read")
def api_inspect(payload: dict):
    return inspect_and_read_document(
        mime_type=payload.get("mime_type", "application/pdf"),
        file_path=payload.get("file_path"),
        base64_data=payload.get("base64_data")
    )

@app.post("/api/approve-quarantined")
def api_approve(payload: dict):
    return approve_quarantined_content(
        review_token=payload.get("review_token", ""),
        override_decision=payload.get("override_decision", "ALLOW_SANITIZED"),
        reviewer_note=payload.get("reviewer_note")
    )

@app.get("/api/quarantine-records")
def api_records():
    return {"records": [r.model_dump() for r in QUARANTINE_STORE.values()]}
