import { DocumentMetadata, ExtractedDocument } from '../types/schema';
import { findFixtureByPath } from '../fixtures/sampleDocuments';

export interface Base64ValidationResult {
  isValid: boolean;
  decodedText: string;
  byteLength: number;
  error?: string;
}

/**
 * Validates and decodes a Base64 string (supporting optional data URI prefix).
 */
export function validateAndDecodeBase64(input: string): Base64ValidationResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return {
      isValid: false,
      decodedText: '',
      byteLength: 0,
      error: 'Empty base64_data payload provided.',
    };
  }

  // Strip optional data:...;base64, prefix
  const cleanBase64 = trimmed.replace(/^data:[^;]+;base64,/i, '').replace(/\s+/g, '');

  // Strict RFC 4648 base64 character validation
  if (cleanBase64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(cleanBase64)) {
    return {
      isValid: false,
      decodedText: '',
      byteLength: 0,
      error: 'Malformed Base64 encoding: invalid length or non-alphabet characters detected.',
    };
  }

  try {
    if (typeof Buffer !== 'undefined') {
      const buf = Buffer.from(cleanBase64, 'base64');
      return {
        isValid: true,
        decodedText: buf.toString('utf-8'),
        byteLength: buf.byteLength,
      };
    } else {
      const binary = atob(cleanBase64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const decodedText = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      return {
        isValid: true,
        decodedText,
        byteLength: bytes.byteLength,
      };
    }
  } catch (err) {
    return {
      isValid: false,
      decodedText: '',
      byteLength: 0,
      error: err instanceof Error ? err.message : 'Base64 decode failure.',
    };
  }
}

/**
 * Deterministic fast hash for document fingerprinting across Node and Browser runtimes.
 */
export function computeDocumentFingerprint(raw: string): string {
  let h1 = 0xdeadbeef ^ raw.length;
  let h2 = 0x41c6ce57 ^ raw.length;
  for (let i = 0, ch; i < raw.length; i++) {
    ch = raw.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const hex1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const hex2 = (h2 >>> 0).toString(16).padStart(8, '0');
  const hex3 = ((h1 ^ h2) >>> 0).toString(16).padStart(8, '0');
  const hex4 = (Math.imul(h1, 31) >>> 0).toString(16).padStart(8, '0');
  return `sha256:${hex1}${hex2}${hex3}${hex4}`;
}

function unescapePdfLiteral(str: string): string {
  return str
    .replace(/\\\(/g, '(')
    .replace(/\\\)/g, ')')
    .replace(/\\\\/g, '\\')
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t');
}

function extractPdfInfoField(rawPdf: string, fieldName: string): string | undefined {
  const regex = new RegExp(`\\/${fieldName}\\s*\\(((?:\\\\.|[^\\\\)])*)\\)`, 'i');
  const match = rawPdf.match(regex);
  return match ? unescapePdfLiteral(match[1].trim()) : undefined;
}

/**
 * Extracts visible text streams, /Annot objects, and document info dictionary properties
 * from a PDF buffer or text payload.
 */
export function extractDocumentContents(params: {
  file_path?: string;
  base64_data?: string;
  mime_type: string;
}): ExtractedDocument {
  let rawContent = '';
  let sourceName = params.file_path || 'inline_base64_document';
  let effectiveMimeType = params.mime_type;
  let byteLength = 0;

  if (params.base64_data) {
    const validation = validateAndDecodeBase64(params.base64_data);
    if (!validation.isValid) {
      throw new Error(validation.error || 'Invalid base64_data input.');
    }
    rawContent = validation.decodedText;
    byteLength = validation.byteLength;
  } else if (params.file_path) {
    const fixture = findFixtureByPath(params.file_path);
    if (!fixture) {
      throw new Error(
        `Document not found at path "${params.file_path}". Available local paths include: /workspace/docs/q3_2026_treasury_reconciliation.pdf, /workspace/docs/inc_2026_089_postmortem.txt, /workspace/quarantine/vendor_soc2_questionnaire_poisoned.pdf`
      );
    }
    rawContent = fixture.raw_content;
    sourceName = fixture.file_path;
    effectiveMimeType = fixture.mime_type;
    byteLength = new TextEncoder().encode(rawContent).byteLength;
  }

  const isPdfStructure =
    effectiveMimeType === 'application/pdf' || rawContent.trimStart().startsWith('%PDF-');

  if (isPdfStructure) {
    const visibleLines: string[] = [];
    // Extract text inside BT ... (text) Tj ... ET blocks
    const tjRegex = /\(((?:\\.|[^\\)])*)\)\s*Tj/g;
    let match: RegExpExecArray | null;
    while ((match = tjRegex.exec(rawContent)) !== null) {
      visibleLines.push(unescapePdfLiteral(match[1]));
    }

    // Extract PDF /Annot /Contents (...) blocks
    const annotations: string[] = [];
    const annotRegex = /\/Type\s*\/Annot[\s\S]*?\/Contents\s*\(((?:\\.|[^\\)])*)\)/g;
    let annotMatch: RegExpExecArray | null;
    while ((annotMatch = annotRegex.exec(rawContent)) !== null) {
      annotations.push(unescapePdfLiteral(annotMatch[1]));
    }

    const title = extractPdfInfoField(rawContent, 'Title');
    const author = extractPdfInfoField(rawContent, 'Author');
    const subject = extractPdfInfoField(rawContent, 'Subject');
    const keywords = extractPdfInfoField(rawContent, 'Keywords');
    const creator = extractPdfInfoField(rawContent, 'Creator');
    const producer = extractPdfInfoField(rawContent, 'Producer');
    const creationDate = extractPdfInfoField(rawContent, 'CreationDate');

    const countMatch = rawContent.match(/\/Count\s+(\d+)/);
    const pageCount = countMatch ? Math.max(1, parseInt(countMatch[1], 10)) : 1;

    // Fallback if a user passed plain text with mime_type application/pdf
    const visibleText =
      visibleLines.length > 0 ? visibleLines.join('\n') : rawContent;

    const customProperties: Record<string, string> = {};
    if (subject) customProperties.Subject = subject;
    if (keywords) customProperties.Keywords = keywords;
    if (creator) customProperties.Creator = creator;

    const metadata: DocumentMetadata = {
      source_name: sourceName,
      mime_type: 'application/pdf',
      byte_length: byteLength,
      page_count: pageCount,
      title: title || sourceName.split('/').pop() || 'Untitled PDF',
      author: author || 'Unknown Author',
      subject,
      keywords,
      creator,
      producer,
      creation_date: creationDate,
      annotations,
      custom_properties: customProperties,
      sha256_fingerprint: computeDocumentFingerprint(rawContent),
    };

    // Combine visible text, annotations, and metadata fields for security scanning
    const combinedParts = [
      visibleText,
      ...annotations.map((a) => `[PDF_ANNOTATION] ${a}`),
      title ? `[PDF_META_TITLE] ${title}` : '',
      author ? `[PDF_META_AUTHOR] ${author}` : '',
      subject ? `[PDF_META_SUBJECT] ${subject}` : '',
      keywords ? `[PDF_META_KEYWORDS] ${keywords}` : '',
    ].filter(Boolean);

    return {
      visible_text: visibleText,
      annotations,
      metadata,
      combined_inspection_surface: combinedParts.join('\n'),
    };
  }

  // Plain text / Markdown / CSV document extraction
  const lines = rawContent.split('\n');
  const firstLineTitle = lines[0]?.trim().slice(0, 90) || sourceName;

  const metadata: DocumentMetadata = {
    source_name: sourceName,
    mime_type: effectiveMimeType,
    byte_length: byteLength,
    page_count: Math.max(1, Math.ceil(rawContent.length / 2800)),
    title: firstLineTitle,
    author: 'Plaintext Document Stream',
    annotations: [],
    custom_properties: {
      line_count: String(lines.length),
      encoding: 'UTF-8',
    },
    sha256_fingerprint: computeDocumentFingerprint(rawContent),
  };

  return {
    visible_text: rawContent,
    annotations: [],
    metadata,
    combined_inspection_surface: rawContent,
  };
}
