import { z } from 'zod';

/**
 * Input schema for Tool 1: inspect_and_read_document
 */
export const InspectAndReadDocumentInputSchema = z
  .object({
    file_path: z
      .string()
      .min(1)
      .optional()
      .describe('Path to local PDF or text document (e.g. /docs/q3_financial_audit.pdf)'),
    base64_data: z
      .string()
      .min(1)
      .optional()
      .describe('Base64-encoded PDF or plain text document payload'),
    mime_type: z
      .enum(['application/pdf', 'text/plain', 'text/markdown', 'text/csv'])
      .default('application/pdf')
      .describe('Document MIME type (e.g. application/pdf, text/plain)'),
  })
  .refine((data) => Boolean(data.file_path || data.base64_data), {
    message: 'Either file_path or base64_data must be provided.',
  });

export type InspectAndReadDocumentInput = z.infer<typeof InspectAndReadDocumentInputSchema>;

/**
 * Input schema for Tool 2: approve_quarantined_content
 */
export const OverrideDecisionEnum = z.enum(['APPROVE_RAW', 'ALLOW_SANITIZED', 'REJECT']);
export type OverrideDecision = z.infer<typeof OverrideDecisionEnum>;

export const ApproveQuarantinedContentInputSchema = z.object({
  review_token: z
    .string()
    .min(8)
    .describe('Human-in-the-loop review token issued during INTERVENTION_REQUIRED quarantine'),
  override_decision: OverrideDecisionEnum.describe(
    'Human operator resolution: APPROVE_RAW, ALLOW_SANITIZED, or REJECT'
  ),
  reviewer_note: z
    .string()
    .optional()
    .describe('Optional audit justification recorded in the HITL security log'),
});

export type ApproveQuarantinedContentInput = z.infer<typeof ApproveQuarantinedContentInputSchema>;

/**
 * Strict structured security classification verdict required by specification
 */
export const SecurityVerdictSchema = z.object({
  is_poisoned: z.boolean(),
  risk_score: z.number().min(0.0).max(1.0),
  detected_patterns: z.array(z.string()),
  suspicious_excerpts: z.array(z.string()),
});

export type SecurityVerdict = z.infer<typeof SecurityVerdictSchema>;

export interface DocumentMetadata {
  source_name: string;
  mime_type: string;
  byte_length: number;
  page_count: number;
  title?: string;
  author?: string;
  subject?: string;
  keywords?: string;
  creator?: string;
  producer?: string;
  creation_date?: string;
  annotations: string[];
  custom_properties: Record<string, string>;
  sha256_fingerprint: string;
}

export interface ExtractedDocument {
  visible_text: string;
  annotations: string[];
  metadata: DocumentMetadata;
  combined_inspection_surface: string;
}

export interface HeuristicMatch {
  category:
    | 'CLASSIC_OVERRIDE'
    | 'ZERO_WIDTH_CHAR'
    | 'ASCII_CONTROL_ANOMALY'
    | 'OBFUSCATED_BASE64'
    | 'OBFUSCATED_HEX'
    | 'SQL_EXFILTRATION'
    | 'METADATA_INJECTION';
  pattern_id: string;
  description: string;
  severity_weight: number;
  matched_excerpt: string;
  decoded_payload?: string;
  offset?: number;
}

export interface HeuristicScanResult {
  flagged: boolean;
  heuristic_score: number;
  matches: HeuristicMatch[];
  zero_width_count: number;
  control_char_count: number;
  decoded_blobs: Array<{ encoding: 'base64' | 'hex'; raw: string; decoded: string }>;
}

export interface PipelineStepTrace {
  step_number: number;
  step_name: string;
  status: 'PASSED' | 'WARNING' | 'BLOCKED';
  duration_ms: number;
  summary: string;
  details: Record<string, unknown>;
}

export interface SafeDocumentResponse {
  status: 'SAFE';
  verdict: SecurityVerdict;
  document: {
    text: string;
    metadata: DocumentMetadata;
  };
  pipeline_trace: PipelineStepTrace[];
}

export interface InterventionRequiredResponse {
  status: 'INTERVENTION_REQUIRED';
  review_token: string;
  verdict: SecurityVerdict;
  warning_payload: {
    message: string;
    omitted_segment_count: number;
    sanitized_preview: string;
    flagged_snippets: string[];
    metadata_summary: Pick<
      DocumentMetadata,
      'source_name' | 'mime_type' | 'byte_length' | 'page_count' | 'sha256_fingerprint'
    >;
    hitl_instructions: string;
  };
  pipeline_trace: PipelineStepTrace[];
}

export type InspectAndReadDocumentOutput = SafeDocumentResponse | InterventionRequiredResponse;

export interface QuarantinedRecord {
  review_token: string;
  created_at: string;
  source_name: string;
  mime_type: string;
  raw_text: string;
  sanitized_text: string;
  metadata: DocumentMetadata;
  verdict: SecurityVerdict;
  heuristic_matches: HeuristicMatch[];
  status: 'PENDING' | 'APPROVED_RAW' | 'ALLOWED_SANITIZED' | 'REJECTED';
  resolved_at?: string;
  override_decision?: OverrideDecision;
  reviewer_note?: string;
}

export interface ApproveQuarantinedContentOutput {
  status: 'RELEASED_RAW' | 'RELEASED_SANITIZED' | 'REJECTED';
  review_token: string;
  override_decision: OverrideDecision;
  resolved_at: string;
  verdict: SecurityVerdict;
  document?: {
    text: string;
    metadata: DocumentMetadata;
    redacted_segments?: number;
  };
  message: string;
}
