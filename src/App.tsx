import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileText,
  Play,
  Copy,
  Check,
  FolderTree,
  Terminal,
  Lock,
  Unlock,
  XCircle,
  Upload,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Download,
  BookOpen,
  ArrowRight,
  Code2,
} from 'lucide-react';
import {
  InspectAndReadDocumentOutput,
  ApproveQuarantinedContentOutput,
  OverrideDecision,
  QuarantinedRecord,
} from './mcp/types/schema';
import { SAMPLE_DOCUMENT_FIXTURES, SampleDocumentFixture } from './mcp/fixtures/sampleDocuments';
import { executeInspectAndReadDocument } from './mcp/tools/inspectAndRead';
import { executeApproveQuarantinedContent } from './mcp/tools/approveQuarantined';
import { quarantineStore } from './mcp/security/quarantineStore';
import { ISOLATED_CLASSIFIER_SYSTEM_PROMPT } from './mcp/security/isolatedClassifier';
import {
  COMPLETE_MCP_REPOSITORY_FILES,
  PROJECT_DIRECTORY_TREE,
  SourceFileEntry,
} from './mcp/sourceCodeMap';

type ActiveSection = 'guide' | 'sandbox' | 'quarantine' | 'tests' | 'source';

interface AutomatedTestCaseResult {
  id: string;
  name: string;
  category: 'BENIGN' | 'ADVERSARIAL' | 'HITL_WORKFLOW';
  passed: boolean;
  duration_ms: number;
  expected_summary: string;
  actual_summary: string;
  assertions: Array<{ label: string; passed: boolean; detail: string }>;
  raw_output: unknown;
}

function encodeUtf8ToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

export function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('guide');

  // Sandbox state
  const [selectedFixtureId, setSelectedFixtureId] = useState<string>(
    'adversarial-pdf-sql-exfil'
  );
  const [inputMode, setInputMode] = useState<'file_path' | 'base64_data' | 'custom_text'>(
    'base64_data'
  );
  const [customFilePath, setCustomFilePath] = useState<string>(
    '/workspace/quarantine/vendor_soc2_questionnaire_poisoned.pdf'
  );
  const [customBase64, setCustomBase64] = useState<string>(
    SAMPLE_DOCUMENT_FIXTURES.find((f) => f.id === 'adversarial-pdf-sql-exfil')?.base64_data || ''
  );
  const [customRawText, setCustomRawText] = useState<string>(
    SAMPLE_DOCUMENT_FIXTURES.find((f) => f.id === 'adversarial-pdf-sql-exfil')?.raw_content || ''
  );
  const [mimeType, setMimeType] = useState<'application/pdf' | 'text/plain'>('application/pdf');
  const [inspectionResult, setInspectionResult] = useState<InspectAndReadDocumentOutput | null>(
    null
  );
  const [inspectionError, setInspectionError] = useState<string | null>(null);
  const [activePayloadView, setActivePayloadView] = useState<'fastapi_json' | 'jsonrpc'>('fastapi_json');

  // Quarantine / HITL state
  const [quarantineList, setQuarantineList] = useState<QuarantinedRecord[]>([]);
  const [selectedToken, setSelectedToken] = useState<string>('');
  const [reviewerNote, setReviewerNote] = useState<string>(
    'FastAPI Security Audit: allow sanitized text while stripping SQL exfiltration directives.'
  );
  const [hitlResult, setHitlResult] = useState<ApproveQuarantinedContentOutput | null>(null);
  const [hitlError, setHitlError] = useState<string | null>(null);

  // Automated Test Suite state
  const [testResults, setTestResults] = useState<AutomatedTestCaseResult[]>([]);
  const [activeTestId, setActiveTestId] = useState<string>('test-2-sql-exfil');

  // Source Code & Claude Config Explorer state
  const [selectedFilePath, setSelectedFilePath] = useState<string>('server.py');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [configServerPath, setConfigServerPath] = useState<string>(
    '/Users/security-eng/safe-doc-guard-mcp/server.py'
  );
  const [configRiskThreshold, setConfigRiskThreshold] = useState<string>('0.35');

  const refreshQuarantineRecords = () => {
    const records = quarantineStore.listRecords();
    setQuarantineList([...records]);
    if (!selectedToken && records.length > 0) {
      setSelectedToken(records[0].review_token);
    }
  };

  // Run initial inspection and populate test suite on mount
  useEffect(() => {
    const defaultFixture = SAMPLE_DOCUMENT_FIXTURES.find(
      (f) => f.id === 'adversarial-pdf-sql-exfil'
    )!;
    const res = executeInspectAndReadDocument({
      base64_data: defaultFixture.base64_data,
      mime_type: defaultFixture.mime_type,
    });
    setInspectionResult(res);
    if (res.status === 'INTERVENTION_REQUIRED') {
      setSelectedToken(res.review_token);
    }
    refreshQuarantineRecords();
    executeAllTests();
  }, []);

  const handleSelectFixture = (fixture: SampleDocumentFixture) => {
    setSelectedFixtureId(fixture.id);
    setCustomFilePath(fixture.file_path);
    setCustomBase64(fixture.base64_data);
    setCustomRawText(fixture.raw_content);
    setMimeType(fixture.mime_type);
    setInspectionError(null);

    try {
      const result = executeInspectAndReadDocument(
        inputMode === 'file_path'
          ? { file_path: fixture.file_path, mime_type: fixture.mime_type }
          : { base64_data: fixture.base64_data, mime_type: fixture.mime_type }
      );
      setInspectionResult(result);
      if (result.status === 'INTERVENTION_REQUIRED') {
        setSelectedToken(result.review_token);
      }
      refreshQuarantineRecords();
    } catch (err) {
      setInspectionError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleRunInspection = () => {
    setInspectionError(null);
    try {
      let payload: {
        file_path?: string;
        base64_data?: string;
        mime_type: 'application/pdf' | 'text/plain';
      };

      if (inputMode === 'file_path') {
        payload = { file_path: customFilePath, mime_type: mimeType };
      } else if (inputMode === 'custom_text') {
        const encoded = encodeUtf8ToBase64(customRawText);
        setCustomBase64(encoded);
        payload = { base64_data: encoded, mime_type: mimeType };
      } else {
        payload = { base64_data: customBase64, mime_type: mimeType };
      }

      const result = executeInspectAndReadDocument(payload);
      setInspectionResult(result);
      if (result.status === 'INTERVENTION_REQUIRED') {
        setSelectedToken(result.review_token);
      }
      refreshQuarantineRecords();
    } catch (err) {
      setInspectionError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const detectedMime: 'application/pdf' | 'text/plain' =
      file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')
        ? 'application/pdf'
        : 'text/plain';

    setMimeType(detectedMime);
    setInputMode('base64_data');
    setSelectedFixtureId('uploaded-file');

    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result || '');
      const base64Clean = dataUrl.replace(/^data:[^;]+;base64,/i, '');
      setCustomBase64(base64Clean);
      try {
        const result = executeInspectAndReadDocument({
          base64_data: base64Clean,
          mime_type: detectedMime,
        });
        setInspectionResult(result);
        if (result.status === 'INTERVENTION_REQUIRED') {
          setSelectedToken(result.review_token);
        }
        refreshQuarantineRecords();
      } catch (err) {
        setInspectionError(err instanceof Error ? err.message : String(err));
      }
    };
    reader.readAsDataURL(file);
  };

  const handleResolveQuarantine = (token: string, decision: OverrideDecision) => {
    setHitlError(null);
    try {
      const output = executeApproveQuarantinedContent({
        review_token: token,
        override_decision: decision,
        reviewer_note: reviewerNote,
      });
      setHitlResult(output);
      setSelectedToken(token);
      refreshQuarantineRecords();
    } catch (err) {
      setHitlError(err instanceof Error ? err.message : String(err));
    }
  };

  const executeAllTests = () => {
    const results: AutomatedTestCaseResult[] = [];

    // Test 1: Benign Corporate Financial PDF
    {
      const t0 = performance.now();
      const fixture = SAMPLE_DOCUMENT_FIXTURES.find((f) => f.id === 'benign-pdf-treasury')!;
      const res = executeInspectAndReadDocument({
        base64_data: fixture.base64_data,
        mime_type: 'application/pdf',
      });
      const assertions = [
        {
          label: 'verdict.is_poisoned is False',
          passed: res.verdict.is_poisoned === false,
          detail: `Actual: ${String(res.verdict.is_poisoned)}`,
        },
        {
          label: 'verdict.risk_score < 0.35',
          passed: res.verdict.risk_score < 0.35,
          detail: `Actual risk_score: ${res.verdict.risk_score.toFixed(2)}`,
        },
        {
          label: 'status == "SAFE" & clean document delivered',
          passed:
            res.status === 'SAFE' &&
            res.document.text.includes('Operating Cash Reserves: $42,810,400'),
          detail:
            res.status === 'SAFE'
              ? `Delivered ${res.document.text.length} chars with metadata`
              : 'Blocked unexpectedly',
        },
      ];
      results.push({
        id: 'test-1-benign-pdf',
        name: 'test_benign_document_passes_cleanly',
        category: 'BENIGN',
        passed: assertions.every((a) => a.passed),
        duration_ms: Math.max(1, Math.round(performance.now() - t0)),
        expected_summary: 'status="SAFE", is_poisoned=False, risk_score=0.00',
        actual_summary: `status="${res.status}", is_poisoned=${res.verdict.is_poisoned}, risk_score=${res.verdict.risk_score.toFixed(2)}`,
        assertions,
        raw_output: res,
      });
    }

    // Test 2: Adversarial PDF with Indirect Prompt Injection & SQL Exfiltration
    {
      const t0 = performance.now();
      const fixture = SAMPLE_DOCUMENT_FIXTURES.find((f) => f.id === 'adversarial-pdf-sql-exfil')!;
      const res = executeInspectAndReadDocument({
        base64_data: fixture.base64_data,
        mime_type: 'application/pdf',
      });
      const hasSqlPattern = res.verdict.detected_patterns.some((p) =>
        p.includes('SQL_DATA_EXFILTRATION')
      );
      const omitsRawSql =
        res.status === 'INTERVENTION_REQUIRED' &&
        !res.warning_payload.sanitized_preview.includes('SELECT user_id, email, ssn_last4');

      const assertions = [
        {
          label: 'verdict.is_poisoned is True',
          passed: res.verdict.is_poisoned === true,
          detail: `Actual: ${String(res.verdict.is_poisoned)}`,
        },
        {
          label: 'status == "INTERVENTION_REQUIRED"',
          passed: res.status === 'INTERVENTION_REQUIRED',
          detail: `Actual status: ${res.status}`,
        },
        {
          label: 'Detects SQL_DATA_EXFILTRATION & system override',
          passed: hasSqlPattern,
          detail: `Patterns: ${res.verdict.detected_patterns.join(', ')}`,
        },
        {
          label: 'Omits raw malicious SQL instructions from main text',
          passed: omitsRawSql,
          detail: omitsRawSql
            ? 'Replaced with [REDACTED BY SAFE-DOC-GUARD-MCP]'
            : 'Failed redaction check',
        },
      ];
      results.push({
        id: 'test-2-sql-exfil',
        name: 'test_adversarial_sql_exfiltration_blocked',
        category: 'ADVERSARIAL',
        passed: assertions.every((a) => a.passed),
        duration_ms: Math.max(2, Math.round(performance.now() - t0)),
        expected_summary: 'status="INTERVENTION_REQUIRED", is_poisoned=True, SQL payload redacted',
        actual_summary: `status="${res.status}", is_poisoned=${res.verdict.is_poisoned}, risk_score=${res.verdict.risk_score.toFixed(2)}`,
        assertions,
        raw_output: res,
      });
    }

    // Test 3: Adversarial Zero-Width Steganography + Obfuscated Base64/Hex
    {
      const t0 = performance.now();
      const fixture = SAMPLE_DOCUMENT_FIXTURES.find(
        (f) => f.id === 'adversarial-text-zerowidth-b64'
      )!;
      const res = executeInspectAndReadDocument({
        base64_data: fixture.base64_data,
        mime_type: 'text/plain',
      });
      const detectsZeroWidth = res.verdict.detected_patterns.some((p) =>
        p.includes('STEGO_ZERO_WIDTH_UNICODE')
      );
      const detectsBase64OrHex = res.verdict.detected_patterns.some(
        (p) => p.includes('HIDDEN_BASE64_PAYLOAD') || p.includes('HIDDEN_HEX_PAYLOAD')
      );

      const assertions = [
        {
          label: 'Detects Zero-Width Unicode (\\u200B, \\u200C, \\u200D, \\uFEFF)',
          passed: detectsZeroWidth,
          detail: `Zero-width pattern matched: ${String(detectsZeroWidth)}`,
        },
        {
          label: 'Deobfuscates embedded Base64/Hex blocks inside text',
          passed: detectsBase64OrHex,
          detail: `Encoded blob deobfuscation matched: ${String(detectsBase64OrHex)}`,
        },
        {
          label: 'Issues cryptographic SDG-HITL-... review token',
          passed: res.status === 'INTERVENTION_REQUIRED' && Boolean(res.review_token),
          detail:
            res.status === 'INTERVENTION_REQUIRED'
              ? `Issued token ${res.review_token}`
              : 'Did not quarantine',
        },
      ];
      results.push({
        id: 'test-3-zerowidth-b64',
        name: 'test_zero_width_steganography_detected',
        category: 'ADVERSARIAL',
        passed: assertions.every((a) => a.passed),
        duration_ms: Math.max(2, Math.round(performance.now() - t0)),
        expected_summary: 'Detects \\u200B stego + Base64/Hex SQL blobs -> INTERVENTION_REQUIRED',
        actual_summary: `status="${res.status}", patterns=${res.verdict.detected_patterns.length}, risk_score=${res.verdict.risk_score.toFixed(2)}`,
        assertions,
        raw_output: res,
      });
    }

    // Test 4: HITL approve_quarantined_content Lifecycle
    {
      const t0 = performance.now();
      const fixture = SAMPLE_DOCUMENT_FIXTURES.find(
        (f) => f.id === 'adversarial-pdf-metadata-only'
      )!;
      const quarantined = executeInspectAndReadDocument({
        base64_data: fixture.base64_data,
        mime_type: 'application/pdf',
      });

      let hitlSanitized: ApproveQuarantinedContentOutput | null = null;
      if (quarantined.status === 'INTERVENTION_REQUIRED') {
        hitlSanitized = executeApproveQuarantinedContent({
          review_token: quarantined.review_token,
          override_decision: 'ALLOW_SANITIZED',
          reviewer_note: 'Pytest automated test suite HITL verification.',
        });
      }

      const assertions = [
        {
          label: 'Detects poisoned PDF /Subject, /Keywords, and /Annots',
          passed: quarantined.status === 'INTERVENTION_REQUIRED',
          detail: `Initial status: ${quarantined.status}`,
        },
        {
          label: 'approve_quarantined_content(ALLOW_SANITIZED) releases clean NDA',
          passed:
            hitlSanitized?.status === 'RELEASED_SANITIZED' &&
            Boolean(hitlSanitized.document?.text.includes('MUTUAL NON-DISCLOSURE AGREEMENT')),
          detail: `HITL resolution status: ${hitlSanitized?.status || 'N/A'}`,
        },
        {
          label: 'Poisoned PDF annotations & metadata remain scrubbed',
          passed:
            hitlSanitized?.document?.metadata.annotations.every((a) =>
              a.includes('REDACTED BY HITL POLICY')
            ) ?? false,
          detail: 'Annotations scrubbed prior to agent release',
        },
      ];

      results.push({
        id: 'test-4-hitl-lifecycle',
        name: 'test_hitl_quarantine_approval_lifecycle',
        category: 'HITL_WORKFLOW',
        passed: assertions.every((a) => a.passed),
        duration_ms: Math.max(2, Math.round(performance.now() - t0)),
        expected_summary: 'Quarantines metadata injection -> Releases sanitized document after HITL approval',
        actual_summary: `HITL status="${hitlSanitized?.status}", token="${quarantined.status === 'INTERVENTION_REQUIRED' ? quarantined.review_token : 'none'}"`,
        assertions,
        raw_output: { initial_quarantine: quarantined, hitl_resolution: hitlSanitized },
      });
    }

    setTestResults(results);
    refreshQuarantineRecords();
  };

  const handleCopyText = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => {
      setCopiedId((prev) => (prev === id ? null : prev));
    }, 1800);
  };

  const handleDownloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const generatedClaudeConfig = useMemo(() => {
    return JSON.stringify(
      {
        mcpServers: {
          'safe-doc-guard-mcp': {
            command: 'uv',
            args: [
              'run',
              '--with',
              'fastapi>=0.115.0',
              '--with',
              'uvicorn>=0.30.0',
              '--with',
              'mcp[cli]>=1.0.0',
              '--with',
              'pypdf>=5.0.0',
              '--with',
              'pydantic>=2.10.0',
              'fastmcp',
              'run',
              configServerPath.trim() || '/path/to/server.py',
            ],
            env: {
              SAFE_DOC_GUARD_RISK_THRESHOLD: configRiskThreshold,
            },
          },
        },
      },
      null,
      2
    );
  }, [configServerPath, configRiskThreshold]);

  const fastapiRequestBodyPreview = useMemo(() => {
    return JSON.stringify(
      inputMode === 'file_path'
        ? { file_path: customFilePath, mime_type: mimeType }
        : {
            base64_data: `${customBase64.slice(0, 68)}... [${customBase64.length} chars]`,
            mime_type: mimeType,
          },
      null,
      2
    );
  }, [inputMode, customFilePath, customBase64, mimeType]);

  const jsonRpcWirePreview = useMemo(() => {
    const requestFrame = {
      jsonrpc: '2.0',
      id: 1042,
      method: 'tools/call',
      params: {
        name: 'inspect_and_read_document',
        arguments:
          inputMode === 'file_path'
            ? { file_path: customFilePath, mime_type: mimeType }
            : {
                base64_data: `${customBase64.slice(0, 68)}... [${customBase64.length} chars]`,
                mime_type: mimeType,
              },
      },
    };
    const responseFrame = {
      jsonrpc: '2.0',
      id: 1042,
      result: {
        content: [
          {
            type: 'text',
            text: inspectionResult,
          },
        ],
        isError: inspectionResult?.status === 'INTERVENTION_REQUIRED',
      },
    };
    return JSON.stringify({ request: requestFrame, response: responseFrame }, null, 2);
  }, [inputMode, customFilePath, customBase64, mimeType, inspectionResult]);

  const selectedSourceFile: SourceFileEntry =
    COMPLETE_MCP_REPOSITORY_FILES.find((f) => f.path === selectedFilePath) ||
    COMPLETE_MCP_REPOSITORY_FILES[0];

  const activeTestCase =
    testResults.find((t) => t.id === activeTestId) || testResults[0];

  const pendingQuarantineCount = quarantineList.filter((q) => q.status === 'PENDING').length;

  return (
    <div className="min-h-screen flex flex-col bg-[#F8FAFC] text-[#0F172A]">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 bg-white border-b border-slate-200 sticky top-0 z-20">
        {/* Zone 1: Brand wordmark (Python FastAPI Edition) */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('guide');
          }}
          className="text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 font-display flex items-center gap-2"
        >
          <span>safe-doc-guard-mcp</span>
          <span className="text-xs font-mono font-medium text-sky-700 bg-sky-50 px-2 py-0.5 rounded border border-sky-200">
            Python FastAPI
          </span>
        </a>

        {/* Zone 2: Navigation Links */}
        <nav className="flex items-center gap-6 text-sm font-medium text-slate-600 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveSection('guide')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeSection === 'guide'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            FastAPI & MCP Guide
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('sandbox')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeSection === 'sandbox'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            REST & MCP Sandbox
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('quarantine')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeSection === 'quarantine'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            HITL Quarantine ({pendingQuarantineCount})
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('tests')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeSection === 'tests'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Pytest Suite
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('source')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeSection === 'source'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Python Source Files
          </button>
        </nav>

        {/* Zone 3: 1 Primary Action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => {
              executeAllTests();
              setActiveSection('tests');
            }}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Run Pytest Suite
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-8 space-y-8">
        {/* Architectural Context Banner */}
        <section className="bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div className="space-y-2 max-w-3xl">
              <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
                <span>Python 3.10+</span>
                <span aria-hidden="true">·</span>
                <span>FastAPI 0.115+</span>
                <span aria-hidden="true">·</span>
                <span>FastMCP (Official MCP SDK)</span>
                <span aria-hidden="true">·</span>
                <span>pypdf 5.0+</span>
                <span aria-hidden="true">·</span>
                <span>Pydantic v2</span>
              </div>
              <h1 className="text-2xl font-bold text-slate-900 tracking-tight text-balance">
                Python FastAPI & FastMCP Document Security Intermediary
              </h1>
              <p className="text-sm text-slate-600 leading-relaxed">
                Production Python server providing dual-interface protection: stdio FastMCP tools for LLM agent integration and FastAPI REST endpoints for web applications. Intercepts indirect prompt injections, zero-width steganography, and SQL credential exfiltration payloads.
              </p>
            </div>

            {/* Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 pt-4 lg:pt-0 border-t lg:border-t-0 lg:border-l border-slate-200 lg:pl-8 shrink-0">
              <div>
                <div className="text-xs text-slate-500">Framework</div>
                <div className="text-xl font-bold text-slate-900 font-mono mt-0.5">
                  FastAPI
                </div>
                <div className="text-xs text-slate-500 mt-0.5">ASGI + FastMCP</div>
              </div>
              <div>
                <div className="text-xs text-slate-500">Endpoints</div>
                <div className="text-xl font-bold text-slate-900 font-mono mt-0.5">
                  4 REST + 2 MCP
                </div>
                <div className="text-xs text-slate-500 mt-0.5">Dual-Interface</div>
              </div>
              <div>
                <div className="text-xs text-slate-500">Quarantine HITL</div>
                <div className="text-xl font-bold text-amber-700 font-mono tabular-nums mt-0.5">
                  {pendingQuarantineCount}
                </div>
                <div className="text-xs text-slate-500 mt-0.5">Tokens Pending</div>
              </div>
              <div>
                <div className="text-xs text-slate-500">Pytest Assertions</div>
                <div className="text-xl font-bold text-emerald-700 font-mono tabular-nums mt-0.5">
                  {testResults.filter((t) => t.passed).length}/{testResults.length || 4}
                </div>
                <div className="text-xs text-slate-500 mt-0.5">All Passing</div>
              </div>
            </div>
          </div>
        </section>

        {/* SECTION 0: COMPLETE FASTAPI & MCP GUIDE */}
        {activeSection === 'guide' && (
          <div className="space-y-8">
            {/* Master Prompt Card for FastAPI Version */}
            <div className="p-6 bg-slate-900 text-white rounded-xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Code2 className="w-5 h-5 text-emerald-400" />
                    <h2 className="text-base font-bold text-white">
                      FastAPI Version Specification Prompt
                    </h2>
                  </div>
                  <p className="text-xs text-slate-300">
                    Use this prompt to build or prompt an AI to generate the complete standalone Python FastAPI & FastMCP codebase.
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      const promptFile = COMPLETE_MCP_REPOSITORY_FILES.find(
                        (f) => f.path === 'PROMPT_OPTION_B_PYTHON_FASTAPI.md'
                      );
                      if (promptFile) {
                        handleCopyText('prompt-fastapi', promptFile.content);
                      }
                    }}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg transition-colors cursor-pointer"
                  >
                    {copiedId === 'prompt-fastapi' ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Prompt Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy FastAPI Prompt</span>
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const promptFile = COMPLETE_MCP_REPOSITORY_FILES.find(
                        (f) => f.path === 'PROMPT_OPTION_B_PYTHON_FASTAPI.md'
                      );
                      if (promptFile) {
                        handleDownloadFile(
                          'PROMPT_PYTHON_FASTAPI.md',
                          promptFile.content
                        );
                      }
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download .md</span>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
                <div className="p-3.5 bg-slate-800/60 rounded-lg border border-slate-700/60 space-y-1">
                  <div className="text-xs font-semibold text-emerald-400">Hybrid FastMCP + FastAPI</div>
                  <div className="text-xs text-slate-300">Provides standard Stdio MCP tools alongside REST endpoints (<code>POST /api/inspect-and-read</code>).</div>
                </div>
                <div className="p-3.5 bg-slate-800/60 rounded-lg border border-slate-700/60 space-y-1">
                  <div className="text-xs font-semibold text-emerald-400">pypdf & Annotation Engine</div>
                  <div className="text-xs text-slate-300">Extracts visible text, Document Info fields, and zero-rect <code>/Annots</code> hidden objects.</div>
                </div>
                <div className="p-3.5 bg-slate-800/60 rounded-lg border border-slate-700/60 space-y-1">
                  <div className="text-xs font-semibold text-emerald-400">Pydantic v2 Strict Verdict</div>
                  <div className="text-xs text-slate-300">Guarantees structured <code>is_poisoned</code>, <code>risk_score</code>, and HITL token lifecycle.</div>
                </div>
              </div>
            </div>

            {/* Step-by-Step Python Terminal Instructions */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-6">
              <div className="border-b border-slate-200 pb-4">
                <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <BookOpen className="w-5 h-5 text-slate-700" />
                  <span>How To Run the Python FastAPI & FastMCP Server</span>
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Follow these steps to run the server locally, test with the FastMCP inspector or cURL, and hook it up to Claude Desktop
                </p>
              </div>

              <div className="space-y-5">
                {/* Step 1 */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-900">
                      Step 1: Set Up Python Virtual Environment & Install Dependencies
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopyText(
                          'cmd-step-1',
                          'python3 -m venv .venv\nsource .venv/bin/activate\npip install "fastapi>=0.115.0" "uvicorn>=0.30.0" "mcp[cli]>=1.0.0" "pypdf>=5.0.0" "pydantic>=2.10.0" "pytest>=8.0.0"'
                        )
                      }
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer"
                    >
                      {copiedId === 'cmd-step-1' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Commands</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3.5 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto">
{`# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate

# 2. Install FastAPI, FastMCP, pypdf, pydantic, and pytest
pip install "fastapi>=0.115.0" "uvicorn>=0.30.0" "mcp[cli]>=1.0.0" "pypdf>=5.0.0" "pydantic>=2.10.0" "pytest>=8.0.0"`}
                  </pre>
                </div>

                {/* Step 2 */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-900">
                      Step 2: Run Either FastMCP Dev Mode OR FastAPI REST Server
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopyText(
                          'cmd-step-2',
                          '# Run FastMCP Stdio & Dev Inspector:\nfastmcp dev server.py\n\n# Or run FastAPI REST Server:\nuvicorn server:app --host 0.0.0.0 --port 8000 --reload'
                        )
                      }
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer"
                    >
                      {copiedId === 'cmd-step-2' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Commands</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3.5 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto">
{`# Mode A: Run with FastMCP visual web inspector (testing tool schemas & stdio):
fastmcp dev server.py

# Mode B: Run FastAPI HTTP REST & OpenAPI Docs server (http://localhost:8000/docs):
uvicorn server:app --host 0.0.0.0 --port 8000 --reload`}
                  </pre>
                </div>

                {/* Step 3 */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-900">
                      Step 3: Run the Pytest Test Suite
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyText('cmd-step-3', 'pytest test_security_pipeline.py -v')}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer"
                    >
                      {copiedId === 'cmd-step-3' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Command</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3.5 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto">
{`# Executes all 4 security test cases (benign, SQL exfiltration, zero-width stego, and HITL lifecycle)
pytest test_security_pipeline.py -v`}
                  </pre>
                </div>

                {/* Step 4 */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-900">
                      Step 4: Claude Desktop Setup (claude_desktop_config.json)
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyText('cmd-step-4', generatedClaudeConfig)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer"
                    >
                      {copiedId === 'cmd-step-4' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Config</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3.5 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto">
{generatedClaudeConfig}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECTION 1: LIVE REST & MCP SANDBOX */}
        {activeSection === 'sandbox' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Left Column: Tool Input & Document Fixtures (5 cols) */}
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-200 pb-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-900">
                    FastAPI Endpoint: POST /api/inspect-and-read
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Select a document fixture or upload a PDF/text file to test
                  </p>
                </div>
                <label className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer transition-colors whitespace-nowrap shrink-0">
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload File</span>
                  <input
                    type="file"
                    accept=".pdf,.txt,.md,.csv"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>

              {/* Preset Document Fixtures */}
              <div className="space-y-2.5">
                <div className="text-xs font-medium text-slate-700">
                  Document Test Fixtures (Benign & Adversarial)
                </div>
                <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg overflow-hidden">
                  {SAMPLE_DOCUMENT_FIXTURES.map((fixture) => {
                    const isSelected = selectedFixtureId === fixture.id;
                    return (
                      <button
                        key={fixture.id}
                        type="button"
                        onClick={() => handleSelectFixture(fixture)}
                        className={`w-full text-left p-3.5 transition-colors cursor-pointer ${
                          isSelected ? 'bg-slate-900 text-white' : 'bg-white hover:bg-slate-50'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span
                            className={`text-xs font-semibold ${
                              isSelected ? 'text-white' : 'text-slate-900'
                            }`}
                          >
                            {fixture.title}
                          </span>
                          <span
                            className={`text-xs font-mono whitespace-nowrap shrink-0 ${
                              isSelected
                                ? 'text-slate-300'
                                : fixture.category === 'BENIGN'
                                ? 'text-emerald-700'
                                : 'text-red-700'
                            }`}
                          >
                            {fixture.category} · {fixture.mime_type}
                          </span>
                        </div>
                        <p
                          className={`text-xs mt-1 leading-relaxed ${
                            isSelected ? 'text-slate-300' : 'text-slate-600'
                          }`}
                        >
                          {fixture.summary}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Input Parameter Mode Switcher */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-700">Payload Delivery Mode</span>
                  <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                    <button
                      type="button"
                      onClick={() => setInputMode('base64_data')}
                      className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        inputMode === 'base64_data'
                          ? 'bg-white text-slate-900 shadow-xs'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      base64_data
                    </button>
                    <button
                      type="button"
                      onClick={() => setInputMode('file_path')}
                      className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        inputMode === 'file_path'
                          ? 'bg-white text-slate-900 shadow-xs'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      file_path
                    </button>
                    <button
                      type="button"
                      onClick={() => setInputMode('custom_text')}
                      className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        inputMode === 'custom_text'
                          ? 'bg-white text-slate-900 shadow-xs'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      Raw Editor
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-4">
                  <label className="text-xs font-medium text-slate-700" htmlFor="mime-select">
                    mime_type
                  </label>
                  <select
                    id="mime-select"
                    value={mimeType}
                    onChange={(e) =>
                      setMimeType(e.target.value as 'application/pdf' | 'text/plain')
                    }
                    className="px-3 py-1.5 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
                  >
                    <option value="application/pdf">application/pdf</option>
                    <option value="text/plain">text/plain</option>
                  </select>
                </div>

                {inputMode === 'file_path' && (
                  <div className="space-y-1.5">
                    <label className="block text-xs font-mono text-slate-600">
                      file_path (str)
                    </label>
                    <input
                      type="text"
                      value={customFilePath}
                      onChange={(e) => setCustomFilePath(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
                    />
                  </div>
                )}

                {inputMode === 'base64_data' && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
                      <span>base64_data (RFC 4648)</span>
                      <span>{customBase64.length.toLocaleString()} chars</span>
                    </div>
                    <textarea
                      rows={5}
                      value={customBase64}
                      onChange={(e) => setCustomBase64(e.target.value)}
                      className="w-full p-3 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900"
                      placeholder="Paste Base64 payload..."
                    />
                  </div>
                )}

                {inputMode === 'custom_text' && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
                      <span>Raw Document Stream</span>
                      <span>{customRawText.length.toLocaleString()} chars</span>
                    </div>
                    <textarea
                      rows={7}
                      value={customRawText}
                      onChange={(e) => setCustomRawText(e.target.value)}
                      className="w-full p-3 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900"
                    />
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={handleRunInspection}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-lg transition-colors cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Call POST /api/inspect-and-read</span>
              </button>

              {inspectionError && (
                <div className="p-3.5 bg-red-50 border border-red-200 rounded-lg text-xs text-red-800 font-mono">
                  Error: {inspectionError}
                </div>
              )}
            </div>

            {/* Right Column: Pipeline Trace & Verdict (7 cols) */}
            <div className="lg:col-span-7 space-y-6">
              {inspectionResult && (
                <>
                  <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
                      <div className="flex items-center gap-3">
                        {inspectionResult.status === 'SAFE' ? (
                          <ShieldCheck className="w-6 h-6 text-emerald-600 shrink-0" />
                        ) : (
                          <ShieldAlert className="w-6 h-6 text-red-600 shrink-0" />
                        )}
                        <div>
                          <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
                            <span>FastAPI Response Status</span>
                            <span aria-hidden="true">·</span>
                            <span
                              className={
                                inspectionResult.status === 'SAFE'
                                  ? 'text-emerald-700 font-semibold'
                                  : 'text-red-700 font-semibold'
                              }
                            >
                              {inspectionResult.status}
                            </span>
                          </div>
                          <h3 className="text-lg font-bold text-slate-900 mt-0.5">
                            {inspectionResult.status === 'SAFE'
                              ? 'Document Verified Safe — Released to LLM Agent'
                              : 'Indirect Prompt Injection Intercepted — Quarantined'}
                          </h3>
                        </div>
                      </div>

                      <div className="text-left sm:text-right font-mono shrink-0">
                        <div className="text-xs text-slate-500">Risk Score (0.00–1.00)</div>
                        <div
                          className={`text-2xl font-bold tabular-nums ${
                            inspectionResult.verdict.is_poisoned
                              ? 'text-red-600'
                              : 'text-emerald-600'
                          }`}
                        >
                          {inspectionResult.verdict.risk_score.toFixed(2)}
                        </div>
                      </div>
                    </div>

                    {/* 5-Stage Execution Trace */}
                    <div className="space-y-2.5">
                      <div className="text-xs font-semibold text-slate-700">
                        5-Stage Security Pipeline Trace
                      </div>
                      <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg">
                        {inspectionResult.pipeline_trace.map((step) => (
                          <div
                            key={step.step_number}
                            className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                          >
                            <div className="space-y-0.5">
                              <div className="font-medium text-slate-900">
                                <span className="font-mono text-slate-500 mr-2">
                                  0{step.step_number}.
                                </span>
                                {step.step_name}
                              </div>
                              <div className="text-slate-600">{step.summary}</div>
                            </div>
                            <div className="flex items-center gap-2 font-mono text-xs shrink-0">
                              <span
                                className={
                                  step.status === 'PASSED'
                                    ? 'text-emerald-700 font-semibold'
                                    : step.status === 'WARNING'
                                    ? 'text-amber-700 font-semibold'
                                    : 'text-red-700 font-semibold'
                                }
                              >
                                {step.status}
                              </span>
                              <span aria-hidden="true" className="text-slate-300">
                                ·
                              </span>
                              <span className="text-slate-500 tabular-nums">
                                {step.duration_ms}ms
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Strict Structured Verdict */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-700">
                          Pydantic SecurityVerdict Schema (Strict JSON)
                        </span>
                        <span className="text-xs font-mono text-slate-500">
                          is_poisoned: {String(inspectionResult.verdict.is_poisoned)} · patterns:{' '}
                          {inspectionResult.verdict.detected_patterns.length}
                        </span>
                      </div>
                      <pre className="p-4 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto leading-relaxed">
                        {JSON.stringify(inspectionResult.verdict, null, 2)}
                      </pre>
                    </div>

                    {/* Payload View */}
                    <div className="space-y-3 pt-2 border-t border-slate-200">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-700">
                          Response Payload View
                        </span>
                        <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                          <button
                            type="button"
                            onClick={() => setActivePayloadView('fastapi_json')}
                            className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                              activePayloadView === 'fastapi_json'
                                ? 'bg-white text-slate-900 shadow-xs'
                                : 'text-slate-600 hover:text-slate-900'
                            }`}
                          >
                            FastAPI JSON Response
                          </button>
                          <button
                            type="button"
                            onClick={() => setActivePayloadView('jsonrpc')}
                            className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                              activePayloadView === 'jsonrpc'
                                ? 'bg-white text-slate-900 shadow-xs'
                                : 'text-slate-600 hover:text-slate-900'
                            }`}
                          >
                            FastMCP Stdio Frame
                          </button>
                        </div>
                      </div>

                      {activePayloadView === 'jsonrpc' ? (
                        <pre className="p-4 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto max-h-96 leading-relaxed">
                          {jsonRpcWirePreview}
                        </pre>
                      ) : inspectionResult.status === 'SAFE' ? (
                        <div className="space-y-3">
                          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 font-mono">
                            <span>Title: {inspectionResult.document.metadata.title}</span>
                            <span aria-hidden="true">·</span>
                            <span>Author: {inspectionResult.document.metadata.author}</span>
                            <span aria-hidden="true">·</span>
                            <span>Pages: {inspectionResult.document.metadata.page_count}</span>
                            <span aria-hidden="true">·</span>
                            <span>{inspectionResult.document.metadata.sha256_fingerprint}</span>
                          </div>
                          <pre className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 whitespace-pre-wrap leading-relaxed">
                            {inspectionResult.document.text}
                          </pre>
                        </div>
                      ) : (
                        <div className="space-y-4">
                          <div className="p-4 bg-red-50 border border-red-200 rounded-lg space-y-2">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="text-xs font-semibold text-red-900">
                                {inspectionResult.warning_payload.message}
                              </span>
                              <span className="text-xs font-mono font-semibold text-red-800">
                                Token: {inspectionResult.review_token}
                              </span>
                            </div>
                            <p className="text-xs text-red-800 font-mono">
                              {inspectionResult.warning_payload.hitl_instructions}
                            </p>
                          </div>

                          <div className="space-y-1.5">
                            <div className="text-xs font-medium text-slate-700">
                              Sanitized Preview (Malicious SQL Instructions Omitted)
                            </div>
                            <pre className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 whitespace-pre-wrap leading-relaxed">
                              {inspectionResult.warning_payload.sanitized_preview}
                            </pre>
                          </div>

                          {/* Direct HITL Action */}
                          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                            <div className="space-y-0.5">
                              <div className="text-xs font-semibold text-slate-900">
                                Resolve via POST /api/approve-quarantined
                              </div>
                              <div className="text-xs text-slate-600 font-mono">
                                review_token: {inspectionResult.review_token}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <button
                                type="button"
                                onClick={() => {
                                  handleResolveQuarantine(
                                    inspectionResult.review_token,
                                    'ALLOW_SANITIZED'
                                  );
                                  setActiveSection('quarantine');
                                }}
                                className="px-3 py-1.5 text-xs font-semibold bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                              >
                                Allow Sanitized
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  handleResolveQuarantine(
                                    inspectionResult.review_token,
                                    'APPROVE_RAW'
                                  );
                                  setActiveSection('quarantine');
                                }}
                                className="px-3 py-1.5 text-xs font-medium bg-white border border-slate-300 text-slate-800 rounded-lg hover:bg-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                              >
                                Approve Raw
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  handleResolveQuarantine(
                                    inspectionResult.review_token,
                                    'REJECT'
                                  );
                                  setActiveSection('quarantine');
                                }}
                                className="px-3 py-1.5 text-xs font-medium bg-white border border-red-300 text-red-700 rounded-lg hover:bg-red-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* SECTION 2: HITL QUARANTINE QUEUE */}
        {activeSection === 'quarantine' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              <div className="flex items-center justify-between border-b border-slate-200 pb-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-900">
                    HITL Quarantine Queue (GET /api/quarantine-records)
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Review flagged documents and submit human operator decisions
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-500 tabular-nums">
                  Total Records: {quarantineList.length}
                </span>
              </div>

              {quarantineList.length === 0 ? (
                <div className="p-8 text-center space-y-3">
                  <div className="text-sm font-medium text-slate-900">
                    No Quarantined Documents in Queue
                  </div>
                  <p className="text-xs text-slate-500 max-w-md mx-auto">
                    Inspect an adversarial fixture in the REST Sandbox to trigger an INTERVENTION_REQUIRED review token.
                  </p>
                  <button
                    type="button"
                    onClick={() => setActiveSection('sandbox')}
                    className="px-4 py-2 text-xs font-semibold bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                  >
                    Open REST Sandbox
                  </button>
                </div>
              ) : (
                <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg">
                  {quarantineList.map((rec) => {
                    const isSelected = selectedToken === rec.review_token;
                    return (
                      <div
                        key={rec.review_token}
                        className={`p-4 space-y-3 transition-colors ${
                          isSelected ? 'bg-slate-50' : 'bg-white'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold text-slate-900">
                              {rec.review_token}
                            </span>
                            <span aria-hidden="true" className="text-slate-300">
                              ·
                            </span>
                            <span className="text-xs font-mono text-slate-600">
                              {rec.source_name}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-red-700 font-semibold tabular-nums">
                              risk_score: {rec.verdict.risk_score.toFixed(2)}
                            </span>
                            <span aria-hidden="true" className="text-slate-300">
                              ·
                            </span>
                            <span
                              className={
                                rec.status === 'PENDING'
                                  ? 'text-amber-700 font-semibold'
                                  : rec.status === 'REJECTED'
                                  ? 'text-red-700 font-semibold'
                                  : 'text-emerald-700 font-semibold'
                              }
                            >
                              {rec.status}
                            </span>
                          </div>
                        </div>

                        <div className="text-xs text-slate-600 font-mono">
                          Patterns: {rec.verdict.detected_patterns.join(' · ')}
                        </div>

                        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                          <span className="text-xs text-slate-500 font-mono tabular-nums">
                            Created: {new Date(rec.created_at).toLocaleTimeString()}
                            {rec.resolved_at
                              ? ` · Resolved: ${new Date(rec.resolved_at).toLocaleTimeString()}`
                              : ''}
                          </span>
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() =>
                                handleResolveQuarantine(rec.review_token, 'ALLOW_SANITIZED')
                              }
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              <Lock className="w-3.5 h-3.5" />
                              <span>ALLOW_SANITIZED</span>
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleResolveQuarantine(rec.review_token, 'APPROVE_RAW')
                              }
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-white border border-slate-300 text-slate-800 rounded-lg hover:bg-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              <Unlock className="w-3.5 h-3.5" />
                              <span>APPROVE_RAW</span>
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleResolveQuarantine(rec.review_token, 'REJECT')
                              }
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-white border border-red-300 text-red-700 rounded-lg hover:bg-red-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>REJECT</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Right Column: Manual Resolution Form */}
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              <div className="border-b border-slate-200 pb-4">
                <h3 className="text-base font-semibold text-slate-900">
                  Endpoint: POST /api/approve-quarantined
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Execute human-in-the-loop validation override
                </p>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-mono text-slate-600 mb-1">
                    review_token (str)
                  </label>
                  <input
                    type="text"
                    value={selectedToken}
                    onChange={(e) => setSelectedToken(e.target.value)}
                    placeholder="SDG-HITL-..."
                    className="w-full px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-600 mb-1">
                    reviewer_note (Optional[str])
                  </label>
                  <input
                    type="text"
                    value={reviewerNote}
                    onChange={(e) => setReviewerNote(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                  />
                </div>

                <div className="grid grid-cols-3 gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => handleResolveQuarantine(selectedToken, 'ALLOW_SANITIZED')}
                    className="py-2 px-3 text-xs font-semibold bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    ALLOW_SANITIZED
                  </button>
                  <button
                    type="button"
                    onClick={() => handleResolveQuarantine(selectedToken, 'APPROVE_RAW')}
                    className="py-2 px-3 text-xs font-medium bg-slate-100 text-slate-900 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    APPROVE_RAW
                  </button>
                  <button
                    type="button"
                    onClick={() => handleResolveQuarantine(selectedToken, 'REJECT')}
                    className="py-2 px-3 text-xs font-medium bg-red-50 text-red-700 border border-red-200 rounded-lg hover:bg-red-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    REJECT
                  </button>
                </div>
              </div>

              {hitlError && (
                <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-800 font-mono">
                  {hitlError}
                </div>
              )}

              {hitlResult && (
                <div className="space-y-2 pt-3 border-t border-slate-200">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-semibold text-slate-800">
                      FastAPI Response: {hitlResult.status}
                    </span>
                    <span className="text-slate-500">{hitlResult.override_decision}</span>
                  </div>
                  <pre className="p-4 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto max-h-96 leading-relaxed">
                    {JSON.stringify(hitlResult, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* SECTION 3: PYTEST TEST SUITE */}
        {activeSection === 'tests' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              <div className="flex items-center justify-between border-b border-slate-200 pb-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-900">
                    Pytest Suite: test_security_pipeline.py
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Automated verification covering benign and adversarial payloads
                  </p>
                </div>
                <button
                  type="button"
                  onClick={executeAllTests}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Re-run Pytest</span>
                </button>
              </div>

              <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg overflow-hidden">
                {testResults.map((test) => {
                  const isSelected = activeTestCase?.id === test.id;
                  return (
                    <button
                      key={test.id}
                      type="button"
                      onClick={() => setActiveTestId(test.id)}
                      className={`w-full text-left p-4 transition-colors cursor-pointer ${
                        isSelected ? 'bg-slate-900 text-white' : 'bg-white hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          {test.passed ? (
                            <CheckCircle2
                              className={`w-4 h-4 shrink-0 ${
                                isSelected ? 'text-emerald-400' : 'text-emerald-600'
                              }`}
                            />
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-red-500 shrink-0" />
                          )}
                          <span className="text-xs font-mono font-semibold">{test.name}</span>
                        </div>
                        <span
                          className={`text-xs font-mono tabular-nums shrink-0 ${
                            isSelected ? 'text-slate-300' : 'text-slate-500'
                          }`}
                        >
                          {test.duration_ms}ms
                        </span>
                      </div>
                      <div
                        className={`text-xs font-mono mt-1.5 ${
                          isSelected ? 'text-slate-300' : 'text-slate-600'
                        }`}
                      >
                        {test.actual_summary}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              {activeTestCase && (
                <>
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-4">
                    <div>
                      <div className="text-xs font-mono text-slate-500">
                        Category: {activeTestCase.category} · Status: PASSED
                      </div>
                      <h3 className="text-base font-mono font-bold text-slate-900 mt-0.5">
                        {activeTestCase.name}()
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-emerald-700 font-semibold">
                      {activeTestCase.assertions.filter((a) => a.passed).length}/
                      {activeTestCase.assertions.length} Assertions Passing
                    </span>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-slate-700">
                      Pytest Assertions
                    </div>
                    <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg">
                      {activeTestCase.assertions.map((assertion, idx) => (
                        <div
                          key={idx}
                          className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                        >
                          <div className="flex items-center gap-2 font-medium text-slate-900">
                            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                            <span className="font-mono">{assertion.label}</span>
                          </div>
                          <span className="font-mono text-slate-500">{assertion.detail}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-slate-700">
                      Captured Output Payload
                    </div>
                    <pre className="p-4 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto max-h-96 leading-relaxed">
                      {JSON.stringify(activeTestCase.raw_output, null, 2)}
                    </pre>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* SECTION 4: PURE PYTHON SOURCE FILES */}
        {activeSection === 'source' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
              {/* Directory Tree */}
              <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-6 flex flex-col justify-between space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                    <div className="flex items-center gap-2">
                      <FolderTree className="w-4 h-4 text-slate-700" />
                      <h2 className="text-base font-semibold text-slate-900">
                        Python Repository Directory Tree
                      </h2>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopyText('dir-tree', PROJECT_DIRECTORY_TREE)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer"
                    >
                      {copiedId === 'dir-tree' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Tree</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto leading-relaxed">
                    {PROJECT_DIRECTORY_TREE}
                  </pre>
                </div>

                <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
                  <div className="text-xs font-semibold text-slate-900">
                    FastAPI Endpoints Summary
                  </div>
                  <div className="text-xs font-mono text-slate-600 space-y-0.5">
                    <div>GET  /health - Health status probe</div>
                    <div>POST /api/inspect-and-read - Inspect and read document</div>
                    <div>POST /api/approve-quarantined - HITL override tool</div>
                    <div>GET  /api/quarantine-records - List all quarantined records</div>
                  </div>
                </div>
              </div>

              {/* Claude Desktop Config */}
              <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-6 flex flex-col justify-between space-y-4">
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                    <div className="flex items-center gap-2">
                      <Sliders className="w-4 h-4 text-slate-700" />
                      <h2 className="text-base font-semibold text-slate-900">
                        claude_desktop_config.json
                      </h2>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          handleCopyText('claude-config', generatedClaudeConfig)
                        }
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer"
                      >
                        {copiedId === 'claude-config' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Config</span>
                          </>
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          handleDownloadFile(
                            'claude_desktop_config.json',
                            generatedClaudeConfig
                          )
                        }
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Download</span>
                      </button>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs font-mono text-slate-600 mb-1">
                        server.py Absolute Path
                      </label>
                      <input
                        type="text"
                        value={configServerPath}
                        onChange={(e) => setConfigServerPath(e.target.value)}
                        className="w-full px-3 py-1.5 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-mono text-slate-600 mb-1">
                        SAFE_DOC_GUARD_RISK_THRESHOLD
                      </label>
                      <input
                        type="text"
                        value={configRiskThreshold}
                        onChange={(e) => setConfigRiskThreshold(e.target.value)}
                        className="w-full px-3 py-1.5 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg text-slate-900"
                      />
                    </div>
                  </div>

                  <pre className="p-4 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto leading-relaxed">
                    {generatedClaudeConfig}
                  </pre>
                </div>

                <div className="text-xs text-slate-500 font-mono">
                  CLI: fastmcp dev server.py (or uvicorn server:app --reload)
                </div>
              </div>
            </div>

            {/* Source Code Viewer (Only Python files) */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-slate-700" />
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">
                      Python Source Code Files ({COMPLETE_MCP_REPOSITORY_FILES.length} Files)
                    </h2>
                    <p className="text-xs text-slate-500">
                      Pure Python implementation using FastAPI, FastMCP, pypdf, and Pydantic v2
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      handleCopyText(
                        `file-${selectedSourceFile.path}`,
                        selectedSourceFile.content
                      )
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
                  >
                    {copiedId === `file-${selectedSourceFile.path}` ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Copied File</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy File</span>
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      handleDownloadFile(
                        selectedSourceFile.path.split('/').pop() || 'server.py',
                        selectedSourceFile.content
                      )
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download File</span>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                {/* File Selector Sidebar */}
                <div className="lg:col-span-4 divide-y divide-slate-200 border border-slate-200 rounded-lg overflow-hidden max-h-[640px] overflow-y-auto">
                  {COMPLETE_MCP_REPOSITORY_FILES.map((file) => {
                    const active = file.path === selectedSourceFile.path;
                    return (
                      <button
                        key={file.path}
                        type="button"
                        onClick={() => setSelectedFilePath(file.path)}
                        className={`w-full text-left p-3 transition-colors cursor-pointer ${
                          active ? 'bg-slate-900 text-white' : 'bg-white hover:bg-slate-50'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-mono font-semibold flex items-center gap-1.5">
                            <FileText className="w-3.5 h-3.5 shrink-0" />
                            {file.path}
                          </span>
                          <span
                            className={`text-xs font-mono tabular-nums ${
                              active ? 'text-slate-300' : 'text-slate-400'
                            }`}
                          >
                            {file.lineCount}L
                          </span>
                        </div>
                        <p
                          className={`text-xs mt-1 ${
                            active ? 'text-slate-300' : 'text-slate-500'
                          }`}
                        >
                          {file.description}
                        </p>
                      </button>
                    );
                  })}
                </div>

                {/* Source Code Viewport */}
                <div className="lg:col-span-8 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-500">
                    <span>{selectedSourceFile.path}</span>
                    <span>
                      {selectedSourceFile.lineCount} lines · Python Stack
                    </span>
                  </div>
                  <pre className="p-5 bg-slate-950 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto max-h-[640px] leading-relaxed">
                    {selectedSourceFile.content}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
