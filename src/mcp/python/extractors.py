"""
extractors.py: PDF & Plaintext Document Parser
Decodes RFC 4648 Base64 payloads and extracts visible text, PDF /Annots dictionaries,
and Document Info fields via pypdf.
"""

from typing import Dict, Any, List, Optional
import base64
import hashlib
import io
import re
from pypdf import PdfReader
from security import DocumentMetadata

def decode_base64_payload(data: str) -> bytes:
    """Validates and decodes RFC 4648 Base64 strings, stripping data URIs."""
    cleaned = re.sub(r"^data:[^;]+;base64,", "", data.strip())
    cleaned = re.sub(r"\s+", "", cleaned)
    if len(cleaned) % 4 != 0:
        raise ValueError("Malformed Base64 payload: invalid string length.")
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", cleaned):
        raise ValueError("Malformed Base64 payload: non-alphabet characters detected.")
    return base64.b64decode(cleaned)

def extract_pdf_data(raw_bytes: bytes, source_name: str) -> Dict[str, Any]:
    """Extracts visible text, hidden zero-rect annotations, and metadata dictionaries."""
    reader = PdfReader(io.BytesIO(raw_bytes))
    visible_lines: List[str] = []
    annotations: List[str] = []

    for page in reader.pages:
        page_text = page.extract_text() or ""
        if page_text:
            visible_lines.append(page_text)
        if "/Annots" in page:
            for annot_ref in page["/Annots"]:
                try:
                    annot_obj = annot_ref.get_object()
                    if "/Contents" in annot_obj:
                        annotations.append(str(annot_obj["/Contents"]))
                except Exception:
                    continue

    info = reader.metadata or {}
    sha256 = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"

    title = info.get("/Title") or source_name
    author = info.get("/Author") or "Unknown"
    subject = info.get("/Subject")
    keywords = info.get("/Keywords")

    meta = DocumentMetadata(
        source_name=source_name,
        mime_type="application/pdf",
        byte_length=len(raw_bytes),
        page_count=len(reader.pages),
        title=title,
        author=author,
        subject=subject,
        keywords=keywords,
        annotations=annotations,
        sha256_fingerprint=sha256,
        custom_properties={k.lstrip("/"): str(v) for k, v in info.items()}
    )

    combined_surface_parts = [
        "\n".join(visible_lines),
        *[f"[PDF_ANNOTATION] {a}" for a in annotations],
        f"[PDF_META_TITLE] {title}",
        f"[PDF_META_AUTHOR] {author}",
        f"[PDF_META_SUBJECT] {subject}" if subject else "",
        f"[PDF_META_KEYWORDS] {keywords}" if keywords else "",
    ]
    combined_surface = "\n".join(p for p in combined_surface_parts if p)

    return {
        "visible_text": "\n".join(visible_lines),
        "annotations": annotations,
        "metadata": meta,
        "combined_inspection_surface": combined_surface,
    }

def extract_document_contents(
    file_path: Optional[str] = None,
    base64_data: Optional[str] = None,
    mime_type: str = "application/pdf"
) -> Dict[str, Any]:
    """Universal dispatcher for PDF and plaintext streams."""
    if base64_data:
        raw_bytes = decode_base64_payload(base64_data)
        source_name = "inline_base64_payload"
    elif file_path:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        source_name = file_path
    else:
        raise ValueError("Neither file_path nor base64_data provided.")

    is_pdf = mime_type == "application/pdf" or raw_bytes.startswith(b"%PDF-")

    if is_pdf:
        return extract_pdf_data(raw_bytes, source_name)

    text = raw_bytes.decode("utf-8", errors="replace")
    sha256 = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"

    lines = text.split("\n")
    title = lines[0][:80].strip() if lines else source_name

    meta = DocumentMetadata(
        source_name=source_name,
        mime_type=mime_type,
        byte_length=len(raw_bytes),
        page_count=max(1, len(text) // 2500),
        title=title,
        author="Plaintext Stream",
        annotations=[],
        sha256_fingerprint=sha256,
        custom_properties={"encoding": "utf-8", "line_count": str(len(lines))}
    )

    return {
        "visible_text": text,
        "annotations": [],
        "metadata": meta,
        "combined_inspection_surface": text,
    }
