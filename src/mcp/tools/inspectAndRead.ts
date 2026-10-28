import {
  InspectAndReadDocumentInput,
  InspectAndReadDocumentInputSchema,
  InspectAndReadDocumentOutput,
  PipelineStepTrace,
} from '../types/schema';
import {
  extractDocumentContents,
  validateAndDecodeBase64,
} from '../extractors/documentExtractor';
import { runHeuristicPreFilter } from '../security/heuristicScanner';
import { runIsolatedSecurityClassifier } from '../security/isolatedClassifier';
import { quarantineStore } from '../security/quarantineStore';

/**
 * MCP Tool 1: inspect_and_read_document
 * Executes the 5-step security pipeline:
 * 1. Base64 validation & decoding / File resolution
 * 2. Text & metadata extraction (visible text, PDF /Annot, and info dictionary properties)
 * 3. Heuristic Pre-filter (classic overrides, zero-width chars, Base64/Hex blobs, SQL exfiltration)
 * 4. Isolated Security Classification (strict JSON verdict: is_poisoned, risk_score, detected_patterns, suspicious_excerpts)
 * 5. Response Delivery (SAFE document text OR INTERVENTION_REQUIRED with HITL review_token)
 */
export function executeInspectAndReadDocument(
  rawInput: InspectAndReadDocumentInput
): InspectAndReadDocumentOutput {
  const parsedInput = InspectAndReadDocumentInputSchema.parse(rawInput);
  const pipelineTrace: PipelineStepTrace[] = [];

  // Step 1: Input & Base64 Validation
  const t1 = performance.now();
  if (parsedInput.base64_data) {
    const b64Check = validateAndDecodeBase64(parsedInput.base64_data);
    if (!b64Check.isValid) {
      throw new Error(b64Check.error || 'Base64 validation failed');
    }
    pipelineTrace.push({
      step_number: 1,
      step_name: 'Base64 Validation & Decoding',
      status: 'PASSED',
      duration_ms: Math.max(1, Math.round(performance.now() - t1)),
      summary: `Validated RFC 4648 Base64 stream (${b64Check.byteLength.toLocaleString()} bytes decoded).`,
      details: {
        input_mode: 'base64_data',
        decoded_bytes: b64Check.byteLength,
        mime_type: parsedInput.mime_type,
      },
    });
  } else {
    pipelineTrace.push({
      step_number: 1,
      step_name: 'Local File Path Resolution & Buffer Load',
      status: 'PASSED',
      duration_ms: Math.max(1, Math.round(performance.now() - t1)),
      summary: `Resolved local file path "${parsedInput.file_path}" (${parsedInput.mime_type}).`,
      details: {
        input_mode: 'file_path',
        file_path: parsedInput.file_path,
        mime_type: parsedInput.mime_type,
      },
    });
  }

  // Step 2: Text & Metadata Extraction
  const t2 = performance.now();
  const extracted = extractDocumentContents({
    file_path: parsedInput.file_path,
    base64_data: parsedInput.base64_data,
    mime_type: parsedInput.mime_type,
  });
  pipelineTrace.push({
    step_number: 2,
    step_name: 'Text, Annotation & Metadata Extraction',
    status: extracted.annotations.length > 0 ? 'WARNING' : 'PASSED',
    duration_ms: Math.max(1, Math.round(performance.now() - t2)),
    summary: `Extracted ${extracted.visible_text.length.toLocaleString()} chars across ${extracted.metadata.page_count} page(s) and ${extracted.annotations.length} PDF annotation(s).`,
    details: {
      visible_char_count: extracted.visible_text.length,
      annotation_count: extracted.annotations.length,
      title: extracted.metadata.title,
      author: extracted.metadata.author,
      subject: extracted.metadata.subject || 'None',
      sha256: extracted.metadata.sha256_fingerprint,
    },
  });

  // Step 3: Heuristic Pre-Filter
  const t3 = performance.now();
  const heuristics = runHeuristicPreFilter(extracted.combined_inspection_surface);
  pipelineTrace.push({
    step_number: 3,
    step_name: 'Heuristic Pre-Filter Scan',
    status: heuristics.flagged ? 'BLOCKED' : 'PASSED',
    duration_ms: Math.max(1, Math.round(performance.now() - t3)),
    summary: heuristics.flagged
      ? `Flagged ${heuristics.matches.length} heuristic pattern(s) (score: ${heuristics.heuristic_score.toFixed(2)}, zero-width chars: ${heuristics.zero_width_count}, decoded blobs: ${heuristics.decoded_blobs.length}).`
      : 'Zero prompt overrides, zero-width steganography, or encoded blobs detected.',
    details: {
      flagged: heuristics.flagged,
      heuristic_score: heuristics.heuristic_score,
      match_count: heuristics.matches.length,
      zero_width_count: heuristics.zero_width_count,
      control_char_count: heuristics.control_char_count,
      decoded_blobs_count: heuristics.decoded_blobs.length,
      matched_pattern_ids: heuristics.matches.map((m) => m.pattern_id),
    },
  });

  // Step 4: Security Classification
  const t4 = performance.now();
  const classification = runIsolatedSecurityClassifier(extracted, heuristics);
  const { verdict, sanitized_text, omitted_segment_count } = classification;
  pipelineTrace.push({
    step_number: 4,
    step_name: 'Isolated Security Classification Verdict',
    status: verdict.is_poisoned ? 'BLOCKED' : 'PASSED',
    duration_ms: Math.max(2, Math.round(performance.now() - t4)),
    summary: verdict.is_poisoned
      ? `Classified as POISONED (risk_score: ${verdict.risk_score.toFixed(2)}). Imperative agent/SQL hijacking instructions verified.`
      : `Classified as SAFE (risk_score: ${verdict.risk_score.toFixed(2)}). No imperative instructions aimed at host LLM agent.`,
    details: {
      verdict,
    },
  });

  // Step 5: Response Delivery
  const t5 = performance.now();
  if (!verdict.is_poisoned) {
    pipelineTrace.push({
      step_number: 5,
      step_name: 'Response Delivery',
      status: 'PASSED',
      duration_ms: Math.max(1, Math.round(performance.now() - t5)),
      summary: 'Delivered verified clean document text and metadata to host LLM agent.',
      details: {
        delivery_status: 'SAFE',
      },
    });

    return {
      status: 'SAFE',
      verdict,
      document: {
        text: extracted.visible_text,
        metadata: extracted.metadata,
      },
      pipeline_trace: pipelineTrace,
    };
  }

  // Document is poisoned -> Quarantine and issue HITL review token
  const quarantineRecord = quarantineStore.createQuarantineRecord({
    source_name: extracted.metadata.source_name,
    mime_type: extracted.metadata.mime_type,
    raw_text: extracted.visible_text,
    sanitized_text,
    metadata: extracted.metadata,
    verdict,
    heuristic_matches: heuristics.matches,
  });

  pipelineTrace.push({
    step_number: 5,
    step_name: 'Quarantine & HITL Token Issuance',
    status: 'BLOCKED',
    duration_ms: Math.max(1, Math.round(performance.now() - t5)),
    summary: `Withheld raw malicious payload from LLM context. Issued HITL review token ${quarantineRecord.review_token}.`,
    details: {
      delivery_status: 'INTERVENTION_REQUIRED',
      review_token: quarantineRecord.review_token,
      omitted_segment_count,
    },
  });

  return {
    status: 'INTERVENTION_REQUIRED',
    review_token: quarantineRecord.review_token,
    verdict,
    warning_payload: {
      message:
        'SECURITY INTERVENTION REQUIRED: Indirect prompt injection or data exfiltration payload detected inside document. Raw instructions have been omitted to protect downstream database tools.',
      omitted_segment_count,
      sanitized_preview: sanitized_text,
      flagged_snippets: verdict.suspicious_excerpts,
      metadata_summary: {
        source_name: extracted.metadata.source_name,
        mime_type: extracted.metadata.mime_type,
        byte_length: extracted.metadata.byte_length,
        page_count: extracted.metadata.page_count,
        sha256_fingerprint: extracted.metadata.sha256_fingerprint,
      },
      hitl_instructions: `Invoke tool "approve_quarantined_content" with review_token="${quarantineRecord.review_token}" and override_decision set to "ALLOW_SANITIZED", "APPROVE_RAW", or "REJECT" after human operator review.`,
    },
    pipeline_trace: pipelineTrace,
  };
}
