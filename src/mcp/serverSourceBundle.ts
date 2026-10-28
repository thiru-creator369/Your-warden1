export interface SourceFileEntry {
  path: string;
  language: 'typescript' | 'json' | 'markdown';
  description: string;
  lineCount: number;
  content: string;
}

export const PROJECT_DIRECTORY_TREE = `safe-doc-guard-mcp/
├── package.json
├── tsconfig.json
├── claude_desktop_config.json
├── src/
│   ├── index.ts                        # MCP Server entrypoint (@modelcontextprotocol/sdk StdioServerTransport)
│   ├── config/
│   │   └── policyConfig.ts             # Risk score thresholds, MIME allowlists, & HITL token TTLs
│   ├── types/
│   │   └── schema.ts                   # Zod input/output schemas & strict SecurityVerdict contract
│   ├── extractors/
│   │   └── documentExtractor.ts        # Base64 RFC 4648 validator + pdf-parse text/annotation/metadata extractor
│   ├── security/
│   │   ├── heuristicScanner.ts         # Regex overrides, zero-width Unicode, ASCII control, Base64/Hex deobfuscator
│   │   ├── isolatedClassifier.ts       # Isolated LLM/semantic verification prompt with strict JSON verdict
│   │   └── quarantineStore.ts          # Cryptographic HITL review_token store & state machine
│   └── tools/
│       ├── inspectAndRead.ts           # Tool 1: inspect_and_read_document handler
│       └── approveQuarantined.ts       # Tool 2: approve_quarantined_content HITL handler
└── tests/
    └── mcpSecurityPipeline.test.ts     # Benign vs. Adversarial SQL Exfiltration & HITL test suite`;

const INDEX_TS_CODE = `#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import {
  InspectAndReadDocumentInputSchema,
  ApproveQuarantinedContentInputSchema,
} from "./types/schema.js";
import { executeInspectAndReadDocument } from "./tools/inspectAndRead.js";
import { executeApproveQuarantinedContent } from "./tools/approveQuarantined.js";

/**
 * safe-doc-guard-mcp
 * Production Model Context Protocol (MCP) Server acting as a security intermediary
 * between untrusted PDF/text documents and LLM agents with database access.
 */
const server = new Server(
  {
    name: "safe-doc-guard-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "inspect_and_read_document",
        description:
          "Securely extracts and inspects a PDF or text document for indirect prompt injections, zero-width steganography, and SQL exfiltration payloads before returning content to the LLM agent.",
        inputSchema: {
          type: "object",
          properties: {
            file_path: {
              type: "string",
              description: "Local filesystem path to PDF or text document",
            },
            base64_data: {
              type: "string",
              description: "Base64-encoded PDF or text document payload",
            },
            mime_type: {
              type: "string",
              enum: ["application/pdf", "text/plain", "text/markdown", "text/csv"],
              default: "application/pdf",
              description: "Document MIME type",
            },
          },
          required: ["mime_type"],
        },
      },
      {
        name: "approve_quarantined_content",
        description:
          "Human-in-the-loop (HITL) resolution tool for releasing or rejecting a document quarantined with status INTERVENTION_REQUIRED.",
        inputSchema: {
          type: "object",
          properties: {
            review_token: {
              type: "string",
              description: "Quarantine review token (e.g., SDG-HITL-...)",
            },
            override_decision: {
              type: "string",
              enum: ["APPROVE_RAW", "ALLOW_SANITIZED", "REJECT"],
              description: "Human operator resolution decision",
            },
            reviewer_note: {
              type: "string",
              description: "Optional audit log justification",
            },
          },
          required: ["review_token", "override_decision"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    if (name === "inspect_and_read_document") {
      const validated = InspectAndReadDocumentInputSchema.parse(args);
      const result = await executeInspectAndReadDocument(validated);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
        isError: result.status === "INTERVENTION_REQUIRED",
      };
    }

    if (name === "approve_quarantined_content") {
      const validated = ApproveQuarantinedContentInputSchema.parse(args);
      const result = executeApproveQuarantinedContent(validated);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
        isError: result.status === "REJECTED",
      };
    }

    throw new McpError(ErrorCode.MethodNotFound, \`Unknown MCP tool: \${name}\`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: message }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[safe-doc-guard-mcp] Server listening on stdio transport");
}

main().catch((error) => {
  console.error("[safe-doc-guard-mcp] Fatal startup error:", error);
  process.exit(1);
});`;

const EXTRACTOR_NODE_CODE = `import fs from "node:fs/promises";
import crypto from "node:crypto";
import pdfParse from "pdf-parse";
import { DocumentMetadata, ExtractedDocument } from "../types/schema.js";

export function validateAndDecodeBase64Buffer(base64Input: string): Buffer {
  const cleaned = base64Input.trim().replace(/^data:[^;]+;base64,/i, "").replace(/\\s+/g, "");
  if (cleaned.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
    throw new Error("Invalid Base64 payload: fails RFC 4648 alphabet/padding validation.");
  }
  return Buffer.from(cleaned, "base64");
}

/**
 * Extracts visible text via pdf-parse AND scans raw PDF objects for hidden /Annot
 * and Document Info dictionary fields (/Title, /Author, /Subject, /Keywords).
 */
export async function extractDocumentNode(params: {
  file_path?: string;
  base64_data?: string;
  mime_type: string;
}): Promise<ExtractedDocument> {
  const buffer = params.base64_data
    ? validateAndDecodeBase64Buffer(params.base64_data)
    : await fs.readFile(params.file_path!);

  const sha256 = "sha256:" + crypto.createHash("sha256").update(buffer).digest("hex");
  const sourceName = params.file_path ?? "inline_base64_payload";

  if (params.mime_type === "application/pdf" || buffer.subarray(0, 5).toString() === "%PDF-") {
    const parsed = await pdfParse(buffer);
    const rawLatin1 = buffer.toString("latin1");

    // Extract hidden /Annot /Contents entries that pdf-parse omits from standard page text
    const annotations: string[] = [];
    const annotRegex = /\\/Type\\s*\\/Annot[\\s\\S]*?\\/Contents\\s*\\(((?:\\\\.|[^\\\\)])*)\\)/g;
    let m: RegExpExecArray | null;
    while ((m = annotRegex.exec(rawLatin1)) !== null) {
      annotations.push(m[1].replace(/\\\\\\(/g, "(").replace(/\\\\\\)/g, ")"));
    }

    const info = (parsed.info ?? {}) as Record<string, string>;
    const metadata: DocumentMetadata = {
      source_name: sourceName,
      mime_type: "application/pdf",
      byte_length: buffer.byteLength,
      page_count: parsed.numpages || 1,
      title: info.Title || sourceName,
      author: info.Author || "Unknown",
      subject: info.Subject,
      keywords: info.Keywords,
      creator: info.Creator,
      producer: info.Producer,
      annotations,
      custom_properties: info,
      sha256_fingerprint: sha256,
    };

    const combinedSurface = [
      parsed.text,
      ...annotations.map((a) => \`[PDF_ANNOTATION] \${a}\`),
      info.Subject ? \`[PDF_META_SUBJECT] \${info.Subject}\` : "",
      info.Keywords ? \`[PDF_META_KEYWORDS] \${info.Keywords}\` : "",
    ]
      .filter(Boolean)
      .join("\\n");

    return {
      visible_text: parsed.text,
      annotations,
      metadata,
      combined_inspection_surface: combinedSurface,
    };
  }

  const text = buffer.toString("utf-8");
  return {
    visible_text: text,
    annotations: [],
    metadata: {
      source_name: sourceName,
      mime_type: params.mime_type,
      byte_length: buffer.byteLength,
      page_count: 1,
      annotations: [],
      custom_properties: {},
      sha256_fingerprint: sha256,
    },
    combined_inspection_surface: text,
  };
}`;

const PACKAGE_JSON_CODE = `{
  "name": "safe-doc-guard-mcp",
  "version": "1.0.0",
  "description": "MCP security intermediary server for detecting indirect prompt injections and SQL exfiltration payloads in PDF and text documents",
  "type": "module",
  "bin": {
    "safe-doc-guard-mcp": "./dist/index.js"
  },
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "tsx src/index.ts",
    "test": "vitest run"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.4",
    "pdf-parse": "^1.1.1",
    "zod": "^3.24.1"
  },
  "devDependencies": {
    "@types/node": "^22.10.0",
    "@types/pdf-parse": "^1.1.4",
    "tsx": "^4.19.2",
    "typescript": "^5.7.2",
    "vitest": "^2.1.8"
  }
}`;

export const CLAUDE_DESKTOP_CONFIG_JSON = `{
  "mcpServers": {
    "safe-doc-guard-mcp": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/safe-doc-guard-mcp/dist/index.js"
      ],
      "env": {
        "SAFE_DOC_GUARD_RISK_THRESHOLD": "0.35",
        "SAFE_DOC_GUARD_QUARANTINE_TTL_SECONDS": "3600",
        "SAFE_DOC_GUARD_SCAN_PDF_ANNOTATIONS": "true",
        "SAFE_DOC_GUARD_DECODE_EMBEDDED_BLOBS": "true"
      }
    }
  }
}`;

const TEST_SUITE_CODE = `import { describe, it, expect } from "vitest";
import { executeInspectAndReadDocument } from "../src/mcp/tools/inspectAndRead.js";
import { executeApproveQuarantinedContent } from "../src/mcp/tools/approveQuarantined.js";
import { SAMPLE_DOCUMENT_FIXTURES } from "../src/mcp/fixtures/sampleDocuments.js";

describe("safe-doc-guard-mcp Security Pipeline", () => {
  it("Test Case 1 (Benign PDF): allows clean Q3 financial reconciliation PDF with is_poisoned === false", () => {
    const benignPdf = SAMPLE_DOCUMENT_FIXTURES.find((f) => f.id === "benign-pdf-treasury")!;
    const response = executeInspectAndReadDocument({
      base64_data: benignPdf.base64_data,
      mime_type: "application/pdf",
    });

    expect(response.status).toBe("SAFE");
    expect(response.verdict.is_poisoned).toBe(false);
    expect(response.verdict.risk_score).toBeLessThan(0.35);
    expect(response.verdict.detected_patterns).toHaveLength(0);
    if (response.status === "SAFE") {
      expect(response.document.text).toContain("Operating Cash Reserves: $42,810,400");
    }
  });

  it("Test Case 2 (Adversarial SQL Exfiltration PDF): blocks indirect prompt injection & issues HITL review_token", () => {
    const poisonedPdf = SAMPLE_DOCUMENT_FIXTURES.find((f) => f.id === "adversarial-pdf-sql-exfil")!;
    const response = executeInspectAndReadDocument({
      base64_data: poisonedPdf.base64_data,
      mime_type: "application/pdf",
    });

    expect(response.status).toBe("INTERVENTION_REQUIRED");
    expect(response.verdict.is_poisoned).toBe(true);
    expect(response.verdict.risk_score).toBeGreaterThanOrEqual(0.75);
    expect(response.verdict.detected_patterns.some((p) => p.includes("SQL_DATA_EXFILTRATION"))).toBe(true);

    if (response.status === "INTERVENTION_REQUIRED") {
      expect(response.review_token).toMatch(/^SDG-HITL-/);
      // Verify raw SQL exfiltration instruction is omitted from sanitized preview
      expect(response.warning_payload.sanitized_preview).not.toContain("SELECT user_id, email, ssn_last4");
      expect(response.warning_payload.sanitized_preview).toContain("[REDACTED BY SAFE-DOC-GUARD-MCP");

      // Verify Human-in-the-Loop resolution via approve_quarantined_content
      const hitlResult = executeApproveQuarantinedContent({
        review_token: response.review_token,
        override_decision: "ALLOW_SANITIZED",
        reviewer_note: "Approved sanitized vendor questionnaire after stripping SQL injection payload.",
      });
      expect(hitlResult.status).toBe("RELEASED_SANITIZED");
      expect(hitlResult.document?.text).toContain("AES-256-GCM");
      expect(hitlResult.document?.text).not.toContain("stripe_secret_token");
    }
  });
});`;

export const MCP_SOURCE_FILES: SourceFileEntry[] = [
  {
    path: 'src/index.ts',
    language: 'typescript',
    description:
      'Main MCP Server entry point registering inspect_and_read_document and approve_quarantined_content over StdioServerTransport.',
    lineCount: INDEX_TS_CODE.split('\n').length,
    content: INDEX_TS_CODE,
  },
  {
    path: 'src/extractors/documentExtractor.node.ts',
    language: 'typescript',
    description:
      'Production Node.js PDF & plaintext extractor using pdf-parse plus raw binary /Annot and Info dictionary inspection.',
    lineCount: EXTRACTOR_NODE_CODE.split('\n').length,
    content: EXTRACTOR_NODE_CODE,
  },
  {
    path: 'tests/mcpSecurityPipeline.test.ts',
    language: 'typescript',
    description:
      'Automated test suite verifying benign document pass-through, adversarial SQL exfiltration blocking, and HITL token approval.',
    lineCount: TEST_SUITE_CODE.split('\n').length,
    content: TEST_SUITE_CODE,
  },
  {
    path: 'package.json',
    language: 'json',
    description: 'Node.js package manifest with @modelcontextprotocol/sdk, pdf-parse, and zod.',
    lineCount: PACKAGE_JSON_CODE.split('\n').length,
    content: PACKAGE_JSON_CODE,
  },
  {
    path: 'claude_desktop_config.json',
    language: 'json',
    description: 'Sample MCP Client configuration for running safe-doc-guard-mcp in Claude Desktop.',
    lineCount: CLAUDE_DESKTOP_CONFIG_JSON.split('\n').length,
    content: CLAUDE_DESKTOP_CONFIG_JSON,
  },
];
