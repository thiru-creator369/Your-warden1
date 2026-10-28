import {
  ApproveQuarantinedContentInput,
  ApproveQuarantinedContentInputSchema,
  ApproveQuarantinedContentOutput,
} from '../types/schema';
import { quarantineStore } from '../security/quarantineStore';

/**
 * MCP Tool 2: approve_quarantined_content
 * Human-in-the-loop (HITL) resolution tool.
 * Accepts review_token and override_decision (APPROVE_RAW | ALLOW_SANITIZED | REJECT)
 * and releases document text only after human validation.
 */
export function executeApproveQuarantinedContent(
  rawInput: ApproveQuarantinedContentInput
): ApproveQuarantinedContentOutput {
  const parsed = ApproveQuarantinedContentInputSchema.parse(rawInput);

  const record = quarantineStore.resolveRecord(
    parsed.review_token,
    parsed.override_decision,
    parsed.reviewer_note
  );

  if (parsed.override_decision === 'REJECT') {
    return {
      status: 'REJECTED',
      review_token: record.review_token,
      override_decision: 'REJECT',
      resolved_at: record.resolved_at!,
      verdict: record.verdict,
      message: `Document "${record.source_name}" permanently rejected by human operator. Zero document contents returned to host LLM agent.`,
    };
  }

  if (parsed.override_decision === 'ALLOW_SANITIZED') {
    // Strip suspicious annotations from metadata when releasing sanitized version
    const sanitizedMetadata = {
      ...record.metadata,
      annotations: record.metadata.annotations.map(() => '[ANNOTATION REDACTED BY HITL POLICY]'),
      subject: record.metadata.subject ? '[METADATA VERIFIED/REDACTED]' : undefined,
      keywords: record.metadata.keywords ? '[METADATA VERIFIED/REDACTED]' : undefined,
    };

    return {
      status: 'RELEASED_SANITIZED',
      review_token: record.review_token,
      override_decision: 'ALLOW_SANITIZED',
      resolved_at: record.resolved_at!,
      verdict: record.verdict,
      document: {
        text: record.sanitized_text,
        metadata: sanitizedMetadata,
        redacted_segments: record.heuristic_matches.length,
      },
      message: `Sanitized document released via HITL token ${record.review_token}. All flagged prompt overrides, hidden annotations, and SQL exfiltration payloads remain redacted.`,
    };
  }

  // APPROVE_RAW
  return {
    status: 'RELEASED_RAW',
    review_token: record.review_token,
    override_decision: 'APPROVE_RAW',
    resolved_at: record.resolved_at!,
    verdict: record.verdict,
    document: {
      text: record.raw_text,
      metadata: record.metadata,
      redacted_segments: 0,
    },
    message: `WARNING: Raw unredacted document text released by explicit human override (token: ${record.review_token}). Downstream database tool access should remain read-restricted.`,
  };
}
