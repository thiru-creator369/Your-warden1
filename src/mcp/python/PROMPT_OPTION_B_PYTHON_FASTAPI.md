# Prompt: Build Production `safe-doc-guard-mcp` in Python with FastAPI & FastMCP

You can copy and paste the prompt below into an AI model (e.g. Claude, Gemini, ChatGPT) or use it as an engineering specification to generate the complete Option B Python (FastAPI + FastMCP) codebase.

---

```markdown
# Role & Objective
You are a senior AI security systems engineer and Python backend infrastructure developer.
Your task is to implement a production-ready Model Context Protocol (MCP) server named `safe-doc-guard-mcp` using Python, FastAPI, and FastMCP (official `mcp` SDK).

The server acts as a secure intermediary between untrusted documents (PDF and plaintext) and an LLM agent holding database access tools (e.g., SQL execution privileges). Its primary purpose is to intercept indirect prompt injections, instruction overrides, zero-width steganography, and SQL credential exfiltration payloads before documents are ingested by downstream AI agents.

---

## Technical Stack
- **Language & Runtime:** Python 3.10+
- **MCP Framework:** `mcp[cli]` (Official Anthropic Model Context Protocol SDK / `FastMCP`)
- **HTTP / REST Layer:** `fastapi` + `uvicorn` (providing both Stdio MCP transport and HTTP REST/SSE endpoints)
- **PDF Extraction:** `pypdf` (extracting visible text streams, PDF `/Annots` dictionaries, and Document Info metadata)
- **Validation & Schemas:** `pydantic` v2 (for strict typed input/output validation)
- **Testing:** `pytest` + `pytest-asyncio`

---

## Project Directory Layout
Please generate the complete codebase with this exact layout:

```text
safe-doc-guard-mcp-python/
├── requirements.txt
├── server.py                  # FastMCP server + FastAPI hybrid ASGI entrypoint
├── extractors.py              # Base64 decoder + pypdf visible text and /Annots extractor
├── security.py                # Heuristic regex scanner + isolated verification classifier
├── quarantine.py              # Cryptographic HITL review_token quarantine manager
├── test_security_pipeline.py  # Pytest suite (Benign PDF, Adversarial SQL Exfil, HITL resolution)
└── claude_desktop_config.json # Claude Desktop configuration entry
```

---

## Functional Specifications

### 1. Tool 1: `inspect_and_read_document`
- **Inputs:**
  - `mime_type` (str: `application/pdf`, `text/plain`, `text/markdown`)
  - `file_path` (Optional[str], local path to PDF or text file)
  - `base64_data` (Optional[str], RFC 4648 Base64-encoded file payload)
  *(Validation: At least one of `file_path` or `base64_data` must be supplied)*

- **Processing Pipeline:**
  1. **Base64 Decoding & Validation:** Validate RFC 4648 padding/alphabet and decode into raw bytes.
  2. **Text & Metadata Extraction:**
     - Extract page text.
     - Extract hidden `/Annots` objects (including zero-rect /Contents entries that standard text extractors omit).
     - Extract PDF Document Info dictionary (`/Title`, `/Author`, `/Subject`, `/Keywords`).
     - Calculate SHA-256 document fingerprint.
  3. **Heuristic Pre-Filter:**
     - Scan for classic prompt overrides (`"ignore previous instructions"`, `"system prompt override"`, `"developer mode"`, `<system>`, `[INST]`).
     - Detect zero-width & invisible Unicode characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u2060`, `\u202A`-`\u202E`).
     - Detect anomalous ASCII control characters (`\x00-\x08`, `\x0B-\x0C`, `\x0E-\x1F`).
     - Detect and deobfuscate embedded Base64 and Hex strings hidden inside plain text, scanning their decoded payloads for nested instructions.
     - Detect SQL exfiltration payloads (`SELECT ... FROM (users|accounts|credentials|customer_api_keys|payroll)`, `UNION SELECT`, external webhook URLs).
  4. **Isolated Security Classification:**
     - Analyze combined surface using an isolated verification prompt pattern.
     - Enforce a strict Pydantic verdict schema:
       ```json
       {
         "is_poisoned": boolean,
         "risk_score": float, // 0.0 to 1.0
         "detected_patterns": string[],
         "suspicious_excerpts": string[]
       }
       ```
  5. **Response Delivery:**
     - If `is_poisoned is False`: Return `status="SAFE"` with full document text and metadata.
     - If `is_poisoned is True`: Return `status="INTERVENTION_REQUIRED"`, omit raw malicious instructions from the main text body (replace with `[REDACTED BY SAFE-DOC-GUARD-MCP]`), and return a sanitized warning payload with flagged snippets and a cryptographic `review_token` (e.g. `SDG-HITL-1730000000-ABCDEF`).

### 2. Tool 2: `approve_quarantined_content`
- **Inputs:**
  - `review_token` (str)
  - `override_decision` (Literal: `"APPROVE_RAW"`, `"ALLOW_SANITIZED"`, `"REJECT"`)
  - `reviewer_note` (Optional[str])
- **Behavior:**
  - `"ALLOW_SANITIZED"`: Releases the document text with malicious lines, poisoned metadata, and annotations redacted.
  - `"APPROVE_RAW"`: Releases full raw text after explicit human sign-off.
  - `"REJECT"`: Permanently rejects delivery, returning zero document contents to the LLM agent.

### 3. FastAPI Dual-Interface
- In addition to standard FastMCP stdio tool handlers, expose FastAPI endpoints:
  - `POST /api/inspect-and-read`
  - `POST /api/approve-quarantined`
  - `GET /api/quarantine-records`
  - `GET /health`

---

## Deliverables Required
1. Complete, runnable source code for all files (`requirements.txt`, `extractors.py`, `security.py`, `quarantine.py`, `server.py`).
2. Comprehensive `test_security_pipeline.py` with passing pytest test cases for:
   - Benign financial PDF (`is_poisoned == False`)
   - Adversarial PDF containing hidden SQL injection in text and annotations (`is_poisoned == True`)
   - Zero-width steganography text test
   - HITL approval lifecycle test
3. Working `claude_desktop_config.json` entry.
4. Exact execution instructions for running via `fastmcp dev`, `uv run`, `python server.py`, and `uvicorn server:app`.
```
