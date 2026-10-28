"""
security.py: Heuristic Regex Pre-Filter & Isolated Security Classifier
Enforces Pydantic SecurityVerdict and sanitizes malicious instructions.
"""

from typing import List, Dict, Any, Optional
import re
import base64
from pydantic import BaseModel, Field

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
    custom_properties: Dict[str, str] = Field(default_factory=dict)

# Regex Rules for Heuristic Pre-filter
ZERO_WIDTH_REGEX = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]")
ASCII_CONTROL_REGEX = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
OVERRIDE_REGEX = re.compile(
    r"\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|directives|rules|prompts|boundaries)\b",
    re.IGNORECASE
)
SYSTEM_TAGS_REGEX = re.compile(r"(?:<\/?system>|\[\/?INST\]|<\|im_start\|>|<\|im_end\|>)", re.IGNORECASE)
DEVELOPER_MODE_REGEX = re.compile(r"\b(?:developer\s+mode|jailbreak\s+mode|adopt\s+developer\s+mode|unrestricted\s+mode)\b", re.IGNORECASE)
SQL_EXFIL_REGEX = re.compile(
    r"\b(?:SELECT\s+[\w*,\s]+\s+FROM\s+(?:users|accounts|customer_api_keys|payroll|credentials|information_schema\.columns)|UNION\s+SELECT)\b",
    re.IGNORECASE
)
BASE64_CANDIDATE_REGEX = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b")

def run_heuristic_prefilter(surface: str) -> Dict[str, Any]:
    matches: List[Dict[str, Any]] = []
    decoded_blobs: List[str] = []

    # Strip zero-width chars to defeat split word evasion
    clean_surface = ZERO_WIDTH_REGEX.sub("", surface)

    # 1. Zero-width character scan
    zw_chars = ZERO_WIDTH_REGEX.findall(surface)
    if zw_chars:
        matches.append({
            "category": "ZERO_WIDTH_CHAR",
            "pattern_id": "STEGO_ZERO_WIDTH_UNICODE",
            "weight": 0.45,
            "snippet": f"Detected {len(zw_chars)} zero-width characters"
        })

    # 2. Control characters scan
    ctrl_chars = ASCII_CONTROL_REGEX.findall(surface)
    if ctrl_chars:
        matches.append({
            "category": "ASCII_CONTROL",
            "pattern_id": "ANOMALOUS_ASCII_CTRL",
            "weight": 0.3,
            "snippet": f"Detected {len(ctrl_chars)} anomalous ASCII control characters"
        })

    # 3. Base64 block deobfuscator
    for b64_cand in BASE64_CANDIDATE_REGEX.findall(clean_surface):
        try:
            decoded = base64.b64decode(b64_cand).decode("utf-8", errors="ignore")
            if OVERRIDE_REGEX.search(decoded) or SQL_EXFIL_REGEX.search(decoded):
                decoded_blobs.append(decoded)
                matches.append({
                    "category": "OBFUSCATED_BASE64",
                    "pattern_id": "HIDDEN_BASE64_PAYLOAD",
                    "weight": 0.55,
                    "snippet": f"Decoded Base64 payload contains command: {decoded[:75]}"
                })
        except Exception:
            pass

    combined_to_scan = clean_surface + "\n" + "\n".join(decoded_blobs)

    # 4. Prompt Override Checks
    if OVERRIDE_REGEX.search(combined_to_scan):
        matches.append({
            "category": "CLASSIC_OVERRIDE",
            "pattern_id": "OVR_IGNORE_PREVIOUS",
            "weight": 0.5,
            "snippet": "Contains directive to ignore previous instructions"
        })

    if SYSTEM_TAGS_REGEX.search(combined_to_scan):
        matches.append({
            "category": "CLASSIC_OVERRIDE",
            "pattern_id": "OVR_DELIMITER_TAGS",
            "weight": 0.45,
            "snippet": "Contains LLM boundary tags (<system>, [INST])"
        })

    if DEVELOPER_MODE_REGEX.search(combined_to_scan):
        matches.append({
            "category": "CLASSIC_OVERRIDE",
            "pattern_id": "OVR_SYSTEM_PROMPT",
            "weight": 0.4,
            "snippet": "Contains developer mode escalation request"
        })

    # 5. SQL Exfiltration Checks
    if SQL_EXFIL_REGEX.search(combined_to_scan):
        matches.append({
            "category": "SQL_EXFILTRATION",
            "pattern_id": "SQL_DATA_EXFILTRATION",
            "weight": 0.6,
            "snippet": "Contains SQL query targeting sensitive credentials tables"
        })

    raw_score = sum(m["weight"] for m in matches)
    heuristic_score = min(1.0, round(raw_score, 2))

    return {
        "flagged": len(matches) > 0,
        "heuristic_score": heuristic_score,
        "matches": matches,
        "decoded_blobs": decoded_blobs,
    }

def run_isolated_security_classifier(
    extracted: Dict[str, Any],
    heuristics: Dict[str, Any]
) -> Dict[str, Any]:
    surface = extracted["combined_inspection_surface"]
    detected_patterns = [f"{m['category']}:{m['pattern_id']}" for m in heuristics["matches"]]
    suspicious_excerpts = [m["snippet"] for m in heuristics["matches"]]

    # Semantic imperative check
    imperative_regex = re.compile(
        r"\b(?:before\s+summarizing|you\s+must\s+run|execute\s+sql|dump\s+table|transmit\s+.*https?://)\b",
        re.IGNORECASE
    )
    if imperative_regex.search(surface):
        detected_patterns.append("SEMANTIC:IMPERATIVE_AGENT_DIRECTIVE")
        suspicious_excerpts.append("Document directs agent to execute external query or transmit data")

    is_poisoned = heuristics["flagged"] or len(detected_patterns) > 0
    risk_score = max(heuristics["heuristic_score"], 0.85) if is_poisoned else 0.0

    verdict = SecurityVerdict(
        is_poisoned=is_poisoned,
        risk_score=risk_score,
        detected_patterns=detected_patterns,
        suspicious_excerpts=suspicious_excerpts[:6]
    )

    # Sanitize document text
    sanitized_lines = []
    omitted_count = 0
    for line in extracted["visible_text"].split("\n"):
        if (
            OVERRIDE_REGEX.search(line)
            or SQL_EXFIL_REGEX.search(line)
            or SYSTEM_TAGS_REGEX.search(line)
            or any(blob in line for blob in heuristics["decoded_blobs"])
        ):
            omitted_count += 1
            sanitized_lines.append("[REDACTED BY SAFE-DOC-GUARD-MCP: INJECTION PAYLOAD OMITTED]")
        else:
            sanitized_lines.append(line)

    return {
        "verdict": verdict,
        "sanitized_text": "\n".join(sanitized_lines),
        "omitted_segment_count": omitted_count,
    }
