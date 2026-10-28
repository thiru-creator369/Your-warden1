import {
  DocumentMetadata,
  HeuristicMatch,
  OverrideDecision,
  QuarantinedRecord,
  SecurityVerdict,
} from '../types/schema';

class QuarantineManager {
  private records: Map<string, QuarantinedRecord> = new Map();

  public createQuarantineRecord(params: {
    source_name: string;
    mime_type: string;
    raw_text: string;
    sanitized_text: string;
    metadata: DocumentMetadata;
    verdict: SecurityVerdict;
    heuristic_matches: HeuristicMatch[];
  }): QuarantinedRecord {
    const randomPart = Math.random().toString(36).substring(2, 8).toUpperCase();
    const timePart = Date.now().toString(36).toUpperCase().slice(-5);
    const reviewToken = `SDG-HITL-${timePart}-${randomPart}`;

    const record: QuarantinedRecord = {
      review_token: reviewToken,
      created_at: new Date().toISOString(),
      source_name: params.source_name,
      mime_type: params.mime_type,
      raw_text: params.raw_text,
      sanitized_text: params.sanitized_text,
      metadata: params.metadata,
      verdict: params.verdict,
      heuristic_matches: params.heuristic_matches,
      status: 'PENDING',
    };

    this.records.set(reviewToken, record);
    return record;
  }

  public getRecord(reviewToken: string): QuarantinedRecord | undefined {
    return this.records.get(reviewToken.trim());
  }

  public resolveRecord(
    reviewToken: string,
    decision: OverrideDecision,
    reviewerNote?: string
  ): QuarantinedRecord {
    const record = this.records.get(reviewToken.trim());
    if (!record) {
      throw new Error(
        `Quarantine review_token "${reviewToken}" not found or has expired. Trigger inspect_and_read_document on an adversarial document first to generate a token.`
      );
    }

    const statusMap: Record<OverrideDecision, QuarantinedRecord['status']> = {
      APPROVE_RAW: 'APPROVED_RAW',
      ALLOW_SANITIZED: 'ALLOWED_SANITIZED',
      REJECT: 'REJECTED',
    };

    record.status = statusMap[decision];
    record.override_decision = decision;
    record.resolved_at = new Date().toISOString();
    record.reviewer_note = reviewerNote;

    this.records.set(record.review_token, record);
    return record;
  }

  public listRecords(): QuarantinedRecord[] {
    return Array.from(this.records.values()).sort((a, b) =>
      b.created_at.localeCompare(a.created_at)
    );
  }
}

export const quarantineStore = new QuarantineManager();
