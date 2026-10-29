"""
safe-doc-guard-mcp: Self-Contained Standalone Production Server
Runs stdio MCP for Claude Desktop, FastAPI REST endpoints, Swagger UI, and /sse transport on Render.
"""

import sys
import time
import base64
import hashlib
import io
import re
import uuid
import json
from pathlib import Path
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from mcp.server.mcpserver import MCPServer as FastMCP
    except ImportError:
        try:
            from fastmcp import FastMCP
        except ImportError:
            raise ImportError('FastMCP not found. Run: pip install "mcp[cli]<2.0.0"')

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pypdf import PdfReader

# ---------------------------------------------------------------------------
# 1. Initialize FastMCP Server & FastAPI App
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="safe-doc-guard-mcp",
    dependencies=["pypdf", "pydantic", "mcp", "fastapi", "uvicorn"]
)

app = FastAPI(
    title="safe-doc-guard-mcp API",
    description="Python FastAPI & FastMCP intermediary guarding database-connected LLM agents.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# 2. Pydantic Models & Security Schemas
# ---------------------------------------------------------------------------
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

# File-backed shared quarantine store path
QUARANTINE_FILE = Path(__file__).resolve().parent / "quarantine_store.json"
QUARANTINE_STORE: Dict[str, QuarantinedRecord] = {}

def load_quarantine_store() -> Dict[str, QuarantinedRecord]:
    global QUARANTINE_STORE
    if QUARANTINE_FILE.exists():
        try:
            with open(QUARANTINE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    QUARANTINE_STORE[k] = QuarantinedRecord.model_validate(v)
        except Exception:
            pass
    return QUARANTINE_STORE

def save_quarantine_store():
    try:
        data = {k: v.model_dump() for k, v in QUARANTINE_STORE.items()}
        with open(QUARANTINE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

load_quarantine_store()

# ---------------------------------------------------------------------------
# 3. Document Extraction & Heuristic Regexes
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 4. FastMCP Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def inspect_and_read_document(
    mime_type: Literal["application/pdf", "text/plain", "text/markdown", "text/csv"] = "application/pdf",
    file_path: Optional[str] = None,
    base64_data: Optional[str] = None
) -> Dict[str, Any]:
    """Inspects a document for prompt injection and SQL exfiltration before ingestion."""
    if not file_path and not base64_data:
        return {"error": "Provide either file_path or base64_data", "status": "ERROR"}

    try:
        if file_path:
            p = Path(file_path)
            if not p.is_file():
                return {"error": f"File '{file_path}' not found.", "status": "ERROR"}
            raw_bytes = p.read_bytes()
            source_name = p.name
        else:
            raw_bytes = decode_base64_payload(base64_data or "")
            source_name = "in_memory_payload"

        fingerprint = hashlib.sha256(raw_bytes).hexdigest()
        visible_text = ""
        annotations = []
        page_count = 1

        if mime_type == "application/pdf" or raw_bytes.startswith(b"%PDF"):
            reader = PdfReader(io.BytesIO(raw_bytes))
            page_count = max(1, len(reader.pages))
            for page in reader.pages:
                text = page.extract_text() or ""
                visible_text += text + "\n"
                if "/Annots" in page:
                    for ann in page["/Annots"]:
                        obj = ann.get_object()
                        if "/Contents" in obj:
                            annotations.append(str(obj["/Contents"]))
        else:
            visible_text = raw_bytes.decode("utf-8", errors="replace")

        meta = DocumentMetadata(
            source_name=source_name,
            mime_type=mime_type,
            byte_length=len(raw_bytes),
            page_count=page_count,
            annotations=annotations,
            sha256_fingerprint=fingerprint
        )

        detected_patterns = []
        suspicious_excerpts = []
        risk_score = 0.0

        if ZERO_WIDTH_REGEX.search(visible_text):
            detected_patterns.append("STEGANOGRAPHY:ZERO_WIDTH_CHARS")
            suspicious_excerpts.append("Zero-width hidden unicode characters detected")
            risk_score += 0.85

        if OVERRIDE_REGEX.search(visible_text):
            detected_patterns.append("CLASSIC_OVERRIDE:IGNORE_INSTRUCTIONS")
            suspicious_excerpts.append("Instruction override phrasing detected")
            risk_score += 0.95

        if SYSTEM_TAGS_REGEX.search(visible_text):
            detected_patterns.append("CLASSIC_OVERRIDE:SYSTEM_TAGS")
            suspicious_excerpts.append("Delimiters mimicking system role tags detected")
            risk_score += 0.90

        if SQL_EXFIL_REGEX.search(visible_text):
            detected_patterns.append("EXFILTRATION:SQL_CREDENTIAL_QUERY")
            suspicious_excerpts.append("SQL query targeting sensitive database tables detected")
            risk_score += 0.95

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
        save_quarantine_store()

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
    load_quarantine_store()
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
    save_quarantine_store()

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

# ---------------------------------------------------------------------------
# 5. FastAPI REST & Swagger Endpoints
# ---------------------------------------------------------------------------
@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "status": "online",
        "service": "safe-doc-guard-mcp",
        "docs": "/docs",
        "health": "/health",
        "sse": "/sse",
        "message": "Safe Doc Guard MCP server is running!"
    }

@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    return {
        "status": "ok",
        "service": "safe-doc-guard-mcp",
        "quarantine_pending": sum(1 for r in QUARANTINE_STORE.values() if r.status == "PENDING"),
        "total_quarantined": len(QUARANTINE_STORE)
    }

@app.post("/api/inspect-and-read")
def api_inspect_and_read(payload: Dict[str, Any]):
    return inspect_and_read_document(
        mime_type=payload.get("mime_type", "application/pdf"),
        file_path=payload.get("file_path"),
        base64_data=payload.get("base64_data"),
    )

@app.post("/api/approve-quarantined")
def api_approve_quarantined(payload: Dict[str, Any]):
    return approve_quarantined_content(
        review_token=payload.get("review_token", ""),
        override_decision=payload.get("override_decision", "ALLOW_SANITIZED"),
        reviewer_note=payload.get("reviewer_note"),
    )

@app.get("/api/quarantine-records")
def api_get_quarantine_records():
    load_quarantine_store()
    return {"records": [r.model_dump() for r in QUARANTINE_STORE.values()]}

# ---------------------------------------------------------------------------
# 6. MCP Remote SSE Transport (/sse & /messages for Claude Desktop)
# ---------------------------------------------------------------------------
try:
    from mcp.server.sse import SseServerTransport
    from starlette.requests import Request

    sse_transport = SseServerTransport("/messages")

    @app.api_route("/sse", methods=["GET", "POST"])
    async def handle_sse(request: Request):
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            init_options = mcp._mcp_server.create_initialization_options()
            await mcp._mcp_server.run(read_stream, write_stream, init_options)

    @app.api_route("/messages", methods=["GET", "POST"])
    async def handle_messages(request: Request):
        await sse_transport.handle_post_message(
            request.scope, request.receive, request._send
        )
except Exception as exc:
    print(f"Warning: SseServerTransport error: {exc}", file=sys.stderr)

if __name__ == "__main__":
    mcp.run()
