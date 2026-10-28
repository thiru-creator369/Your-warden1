"""
safe-doc-guard-mcp: Python FastAPI & FastMCP Production Server
Hybrid Model Context Protocol (MCP) + FastAPI REST/SSE security intermediary.
Detects indirect prompt injections, zero-width steganography, and SQL exfiltration payloads.
"""

from typing import Optional, List, Dict, Any, Literal
from contextlib import asynccontextmanager
import time
import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from mcp.server.fastmcp import FastMCP
from extractors import extract_document_contents
from security import (
    run_heuristic_prefilter,
    run_isolated_security_classifier,
    SecurityVerdict,
    DocumentMetadata,
)
from quarantine import quarantine_store, QuarantinedRecord

# -----------------------------------------------------------------------------
# Initialize FastMCP Server & FastAPI App
# -----------------------------------------------------------------------------
mcp = FastMCP(
    name="safe-doc-guard-mcp",
    dependencies=["fastapi", "uvicorn", "pypdf", "pydantic", "mcp[cli]"]
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize security rules and quarantine storage
    yield
    # Shutdown logic if required

app = FastAPI(
    title="safe-doc-guard-mcp API",
    description="Python FastAPI & FastMCP intermediary guarding database-connected LLM agents against indirect prompt injections and SQL exfiltration.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# -----------------------------------------------------------------------------
class InspectAndReadRequest(BaseModel):
    mime_type: Literal["application/pdf", "text/plain", "text/markdown", "text/csv"] = Field(
        default="application/pdf",
        description="MIME type of the target document"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Local path to the PDF or text document"
    )
    base64_data: Optional[str] = Field(
        default=None,
        description="RFC 4648 Base64-encoded PDF or text payload"
    )

class WarningPayload(BaseModel):
    message: str
    omitted_segment_count: int
    sanitized_preview: str
    flagged_snippets: List[str]
    metadata_summary: Dict[str, Any]
    hitl_instructions: str

class InspectAndReadResponse(BaseModel):
    status: Literal["SAFE", "INTERVENTION_REQUIRED"]
    verdict: SecurityVerdict
    review_token: Optional[str] = None
    document: Optional[Dict[str, Any]] = None
    warning_payload: Optional[WarningPayload] = None
    execution_time_ms: float

class ApproveQuarantinedRequest(BaseModel):
    review_token: str = Field(description="Review token issued during quarantine")
    override_decision: Literal["APPROVE_RAW", "ALLOW_SANITIZED", "REJECT"] = Field(
        description="Human operator override action"
    )
    reviewer_note: Optional[str] = Field(
        default=None,
        description="Audit log commentary"
    )

class ApproveQuarantinedResponse(BaseModel):
    status: Literal["RELEASED_RAW", "RELEASED_SANITIZED", "REJECTED"]
    review_token: str
    override_decision: str
    resolved_at: float
    verdict: SecurityVerdict
    document: Optional[Dict[str, Any]] = None
    message: str

# -----------------------------------------------------------------------------
# Core Security Pipeline Execution
# -----------------------------------------------------------------------------
def process_document_pipeline(
    mime_type: str,
    file_path: Optional[str] = None,
    base64_data: Optional[str] = None
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if not file_path and not base64_data:
        raise ValueError("Either file_path or base64_data must be provided.")

    # Step 1 & 2: Extract text, annotations, and metadata
    extracted = extract_document_contents(
        file_path=file_path,
        base64_data=base64_data,
        mime_type=mime_type
    )

    # Step 3: Heuristic Pre-Filter
    heuristics = run_heuristic_prefilter(extracted["combined_inspection_surface"])

    # Step 4: Isolated Security Classification
    classification = run_isolated_security_classifier(extracted, heuristics)
    verdict = classification["verdict"]

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    # Step 5: Response Delivery
    if not verdict.is_poisoned:
        return {
            "status": "SAFE",
            "verdict": verdict,
            "document": {
                "text": extracted["visible_text"],
                "metadata": extracted["metadata"],
            },
            "execution_time_ms": elapsed_ms,
        }

    # Document Poisoned -> Create Quarantine Record
    record = quarantine_store.create_record(
        source_name=extracted["metadata"].source_name,
        mime_type=extracted["metadata"].mime_type,
        raw_text=extracted["visible_text"],
        sanitized_text=classification["sanitized_text"],
        metadata=extracted["metadata"],
        verdict=verdict,
        heuristic_matches=heuristics["matches"]
    )

    return {
        "status": "INTERVENTION_REQUIRED",
        "review_token": record.review_token,
        "verdict": verdict,
        "warning_payload": {
            "message": "SECURITY INTERVENTION REQUIRED: Indirect prompt injection or data exfiltration payload detected.",
            "omitted_segment_count": classification["omitted_segment_count"],
            "sanitized_preview": classification["sanitized_text"],
            "flagged_snippets": verdict.suspicious_excerpts,
            "metadata_summary": {
                "source_name": extracted["metadata"].source_name,
                "mime_type": extracted["metadata"].mime_type,
                "byte_length": extracted["metadata"].byte_length,
                "page_count": extracted["metadata"].page_count,
                "sha256": extracted["metadata"].sha256_fingerprint,
            },
            "hitl_instructions": f'Call approve_quarantined_content with review_token="{record.review_token}".',
        },
        "execution_time_ms": elapsed_ms,
    }

# -----------------------------------------------------------------------------
# FastMCP Tools (Stdio Transport)
# -----------------------------------------------------------------------------
@mcp.tool()
def inspect_and_read_document(
    mime_type: Literal["application/pdf", "text/plain", "text/markdown", "text/csv"] = "application/pdf",
    file_path: Optional[str] = None,
    base64_data: Optional[str] = None
) -> Dict[str, Any]:
    """
    Securely inspects and reads a PDF or text document, intercepting indirect prompt
    injections, zero-width steganography, and SQL exfiltration payloads before LLM ingestion.
    """
    try:
        return process_document_pipeline(mime_type, file_path, base64_data)
    except Exception as exc:
        return {"error": str(exc), "status": "ERROR"}

@mcp.tool()
def approve_quarantined_content(
    review_token: str,
    override_decision: Literal["APPROVE_RAW", "ALLOW_SANITIZED", "REJECT"],
    reviewer_note: Optional[str] = None
) -> Dict[str, Any]:
    """
    Human-in-the-loop (HITL) resolution tool to approve (raw or sanitized) or reject
    a quarantined document.
    """
    try:
        record = quarantine_store.resolve_record(
            review_token=review_token,
            override_decision=override_decision,
            reviewer_note=reviewer_note
        )
        if override_decision == "REJECT":
            return {
                "status": "REJECTED",
                "review_token": review_token,
                "override_decision": override_decision,
                "resolved_at": record.resolved_at,
                "verdict": record.verdict,
                "message": f"Document {record.source_name} rejected. Zero contents delivered to agent."
            }
        elif override_decision == "ALLOW_SANITIZED":
            return {
                "status": "RELEASED_SANITIZED",
                "review_token": review_token,
                "override_decision": override_decision,
                "resolved_at": record.resolved_at,
                "verdict": record.verdict,
                "document": {
                    "text": record.sanitized_text,
                    "metadata": record.metadata,
                },
                "message": "Sanitized document released. Flagged injection lines and metadata scrubbed."
            }
        else:
            return {
                "status": "RELEASED_RAW",
                "review_token": review_token,
                "override_decision": override_decision,
                "resolved_at": record.resolved_at,
                "verdict": record.verdict,
                "document": {
                    "text": record.raw_text,
                    "metadata": record.metadata,
                },
                "message": "WARNING: Raw document released via explicit human override."
            }
    except Exception as exc:
        return {"error": str(exc), "status": "ERROR"}

# -----------------------------------------------------------------------------
# FastAPI HTTP REST Endpoints
# -----------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "safe-doc-guard-mcp",
        "framework": "FastAPI + FastMCP",
        "timestamp": time.time()
    }

@app.post("/api/inspect-and-read", response_model=InspectAndReadResponse, tags=["Inspection"])
def api_inspect_and_read(req: InspectAndReadRequest):
    try:
        res = process_document_pipeline(req.mime_type, req.file_path, req.base64_data)
        return res
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

@app.post("/api/approve-quarantined", response_model=ApproveQuarantinedResponse, tags=["Quarantine"])
def api_approve_quarantined(req: ApproveQuarantinedRequest):
    try:
        return approve_quarantined_content(req.review_token, req.override_decision, req.reviewer_note)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Token {req.review_token} not found")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@app.get("/api/quarantine-records", tags=["Quarantine"])
def api_list_quarantine():
    return {"records": quarantine_store.list_records()}

if __name__ == "__main__":
    # If run directly, run the FastMCP stdio server
    mcp.run()
