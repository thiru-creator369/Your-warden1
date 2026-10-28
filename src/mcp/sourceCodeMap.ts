import serverPyRaw from './python/server.py?raw';
import extractorsPyRaw from './python/extractors.py?raw';
import securityPyRaw from './python/security.py?raw';
import quarantinePyRaw from './python/quarantine.py?raw';
import testPipelinePyRaw from './python/test_security_pipeline.py?raw';
import requirementsTxtRaw from './python/requirements.txt?raw';
import claudeConfigPyRaw from './python/claude_desktop_config.json?raw';
import promptOptionBRaw from './python/PROMPT_OPTION_B_PYTHON_FASTAPI.md?raw';

export interface SourceFileEntry {
  path: string;
  language: 'typescript' | 'json' | 'markdown';
  description: string;
  lineCount: number;
  content: string;
}

export const PROJECT_DIRECTORY_TREE = `safe-doc-guard-mcp/
├── requirements.txt           # Python dependencies (FastAPI, FastMCP, pypdf, pydantic)
├── server.py                  # FastMCP server + FastAPI hybrid ASGI entrypoint
├── extractors.py              # Base64 RFC 4648 decoder + pypdf visible text and /Annots extractor
├── security.py                # Regex heuristic pre-filter + isolated classifier (strict SecurityVerdict)
├── quarantine.py              # Cryptographic HITL review_token store & state machine
├── test_security_pipeline.py  # Pytest test suite (benign, SQL exfiltration, HITL lifecycle)
└── claude_desktop_config.json # Claude Desktop configuration entry`;

export const COMPLETE_MCP_REPOSITORY_FILES: SourceFileEntry[] = [
  {
    path: 'server.py',
    language: 'typescript', // Used for IDE syntax highlighting
    description:
      'FastMCP tools (inspect_and_read_document, approve_quarantined_content) + FastAPI REST endpoints.',
    lineCount: serverPyRaw.split('\n').length,
    content: serverPyRaw,
  },
  {
    path: 'extractors.py',
    language: 'typescript',
    description:
      'Base64 RFC 4648 validation and decoding, pypdf text extraction, /Annots parsing, and SHA-256 fingerprinting.',
    lineCount: extractorsPyRaw.split('\n').length,
    content: extractorsPyRaw,
  },
  {
    path: 'security.py',
    language: 'typescript',
    description:
      'Heuristic regex pre-filter (overrides, zero-width chars, control chars, Base64/Hex blobs, SQL exfiltration) + isolated classifier.',
    lineCount: securityPyRaw.split('\n').length,
    content: securityPyRaw,
  },
  {
    path: 'quarantine.py',
    language: 'typescript',
    description:
      'In-memory HITL review_token store managing PENDING, APPROVED_RAW, ALLOWED_SANITIZED, and REJECTED states.',
    lineCount: quarantinePyRaw.split('\n').length,
    content: quarantinePyRaw,
  },
  {
    path: 'test_security_pipeline.py',
    language: 'typescript',
    description:
      'Comprehensive pytest suite verifying benign document pass-through, adversarial SQL exfiltration quarantine, and HITL release.',
    lineCount: testPipelinePyRaw.split('\n').length,
    content: testPipelinePyRaw,
  },
  {
    path: 'requirements.txt',
    language: 'markdown',
    description:
      'Python production requirements (fastapi, uvicorn, mcp[cli], pypdf, pydantic, pytest).',
    lineCount: requirementsTxtRaw.split('\n').length,
    content: requirementsTxtRaw,
  },
  {
    path: 'claude_desktop_config.json',
    language: 'json',
    description:
      'Ready-to-use Claude Desktop configuration for running safe-doc-guard-mcp with uv run or python.',
    lineCount: claudeConfigPyRaw.split('\n').length,
    content: claudeConfigPyRaw,
  },
  {
    path: 'PROMPT_OPTION_B_PYTHON_FASTAPI.md',
    language: 'markdown',
    description:
      'Master prompt specification for building Option B (Python + FastAPI + FastMCP).',
    lineCount: promptOptionBRaw.split('\n').length,
    content: promptOptionBRaw,
  },
];
