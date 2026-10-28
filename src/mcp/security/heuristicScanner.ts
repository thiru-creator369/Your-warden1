import { HeuristicMatch, HeuristicScanResult } from '../types/schema';

interface PatternRule {
  id: string;
  category: HeuristicMatch['category'];
  description: string;
  regex: RegExp;
  weight: number;
}

const HEURISTIC_RULES: PatternRule[] = [
  {
    id: 'OVR_IGNORE_PREVIOUS',
    category: 'CLASSIC_OVERRIDE',
    description: 'Classic instruction override ("ignore previous/all instructions" or "disregard safety")',
    regex: /\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|directives|rules|prompts|boundaries|constraints)\b/gi,
    weight: 0.45,
  },
  {
    id: 'OVR_SYSTEM_PROMPT',
    category: 'CLASSIC_OVERRIDE',
    description: 'Explicit system prompt override or developer mode escalation marker',
    regex: /\b(?:system\s+prompt\s+override|developer\s+mode|jailbreak\s+mode|unrestricted\s+developer\s+mode|adopt\s+developer\s+mode|you\s+are\s+now\s+operating\s+in)\b/gi,
    weight: 0.42,
  },
  {
    id: 'OVR_DELIMITER_TAGS',
    category: 'CLASSIC_OVERRIDE',
    description: 'Injected LLM chat template or system boundary tags (<system>, </system>, [INST], [/INST], <|im_start|>)',
    regex: /(?:<\/?system>|\[\/?INST\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>|<\/SYS>>)/gi,
    weight: 0.4,
  },
  {
    id: 'SQL_DATA_EXFILTRATION',
    category: 'SQL_EXFILTRATION',
    description: 'Embedded SQL query targeting sensitive tables, credentials, or schema enumeration',
    regex: /\b(?:SELECT\s+[\w*,\s]+\s+FROM\s+(?:users|accounts|customer_api_keys|payroll_compensation|executive_payroll|credentials|information_schema\.columns)|UNION\s+SELECT\s+[\w*,\s']+\s+FROM)\b[^;\n]*;?/gi,
    weight: 0.55,
  },
  {
    id: 'EXFIL_EXTERNAL_WEBHOOK',
    category: 'SQL_EXFILTRATION',
    description: 'Directive to transmit or append sensitive query outputs to an external collector URL',
    regex: /(?:transmit|append|send|exfiltrate|post)[\s\S]{0,80}https?:\/\/[^\s)"'>]+/gi,
    weight: 0.45,
  },
  {
    id: 'META_HIDDEN_DIRECTIVE',
    category: 'METADATA_INJECTION',
    description: 'Imperative agent command embedded inside PDF annotation or document metadata field',
    regex: /\[(?:PDF_ANNOTATION|PDF_META_SUBJECT|PDF_META_KEYWORDS)\][^\n]*(?:ignore\s+previous|disregard|SELECT\s+.*FROM|override|<system>|\[INST\])[^\n]*/gi,
    weight: 0.5,
  },
];

// Zero-width and invisible formatting characters:
// U+200B Zero-Width Space, U+200C Zero-Width Non-Joiner, U+200D Zero-Width Joiner,
// U+FEFF Zero-Width No-Break Space, U+2060 Word Joiner, U+202A..U+202E BiDi overrides
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]/g;

// Anomalous ASCII control characters (excluding \t 0x09, \n 0x0A, \r 0x0D)
const ASCII_CONTROL_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

// Candidate obfuscated Base64 blocks inside text (at least 32 chars of Base64 alphabet)
const CANDIDATE_BASE64_REGEX = /\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b/g;

// Candidate obfuscated Hex strings (at least 32 hex chars)
const CANDIDATE_HEX_REGEX = /\b(?:[0-9a-fA-F]{2}){16,}\b/g;

function tryDecodeBase64Ascii(candidate: string): string | null {
  try {
    let decoded = '';
    if (typeof Buffer !== 'undefined') {
      decoded = Buffer.from(candidate, 'base64').toString('utf-8');
    } else {
      decoded = atob(candidate);
    }
    // Check if at least 85% of characters are printable ASCII
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
        printable++;
      }
    }
    if (decoded.length >= 16 && printable / decoded.length >= 0.85) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

function tryDecodeHexAscii(candidate: string): string | null {
  try {
    let out = '';
    let printable = 0;
    for (let i = 0; i < candidate.length; i += 2) {
      const byte = parseInt(candidate.slice(i, i + 2), 16);
      if (Number.isNaN(byte)) return null;
      if ((byte >= 32 && byte <= 126) || byte === 10 || byte === 13 || byte === 9) {
        printable++;
      }
      out += String.fromCharCode(byte);
    }
    if (out.length >= 12 && printable / out.length >= 0.85) {
      return out;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Step 3: Heuristic Pre-Filter
 * Scans for classic overrides, zero-width characters, anomalous ASCII control chars,
 * and obfuscated Base64 or Hex blocks hidden inside plain text.
 */
export function runHeuristicPreFilter(inspectionSurface: string): HeuristicScanResult {
  const matches: HeuristicMatch[] = [];
  const decodedBlobs: Array<{ encoding: 'base64' | 'hex'; raw: string; decoded: string }> = [];

  // Normalize away zero-width chars so split words like "ig\u200Bnore" are also caught by regex rules
  const deobfuscatedSurface = inspectionSurface.replace(ZERO_WIDTH_REGEX, '');

  // 1. Scan for Zero-Width / Invisible Unicode characters
  const zwMatches = Array.from(inspectionSurface.matchAll(ZERO_WIDTH_REGEX));
  const zeroWidthCount = zwMatches.length;
  if (zeroWidthCount > 0) {
    const firstIdx = zwMatches[0].index ?? 0;
    const contextSnippet = inspectionSurface
      .slice(Math.max(0, firstIdx - 20), Math.min(inspectionSurface.length, firstIdx + 90))
      .replace(/[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]/g, (ch) => {
        const hex = ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
        return `[\\u${hex}]`;
      });

    matches.push({
      category: 'ZERO_WIDTH_CHAR',
      pattern_id: 'STEGO_ZERO_WIDTH_UNICODE',
      description: `Detected ${zeroWidthCount} invisible/zero-width Unicode character(s) (e.g. \\u200B, \\u200C, \\uFEFF)`,
      severity_weight: Math.min(0.45, 0.2 + zeroWidthCount * 0.04),
      matched_excerpt: contextSnippet.trim(),
      offset: firstIdx,
    });
  }

  // 2. Scan for Anomalous ASCII Control Characters
  const ctrlMatches = Array.from(inspectionSurface.matchAll(ASCII_CONTROL_REGEX));
  const controlCharCount = ctrlMatches.length;
  if (controlCharCount > 0) {
    const firstIdx = ctrlMatches[0].index ?? 0;
    matches.push({
      category: 'ASCII_CONTROL_ANOMALY',
      pattern_id: 'ANOMALOUS_ASCII_CTRL',
      description: `Detected ${controlCharCount} anomalous ASCII control character(s) outside standard whitespace`,
      severity_weight: 0.3,
      matched_excerpt: `Control char 0x${inspectionSurface
        .charCodeAt(firstIdx)
        .toString(16)
        .padStart(2, '0')} at offset ${firstIdx}`,
      offset: firstIdx,
    });
  }

  // 3. Scan for Obfuscated Base64 blocks inside text and inspect decoded content
  const b64Candidates = Array.from(deobfuscatedSurface.matchAll(CANDIDATE_BASE64_REGEX));
  for (const cand of b64Candidates) {
    const rawBlob = cand[0];
    const decoded = tryDecodeBase64Ascii(rawBlob);
    if (decoded) {
      decodedBlobs.push({ encoding: 'base64', raw: rawBlob, decoded });
      matches.push({
        category: 'OBFUSCATED_BASE64',
        pattern_id: 'HIDDEN_BASE64_PAYLOAD',
        description: 'Embedded Base64-encoded text block discovered inside document content',
        severity_weight: 0.4,
        matched_excerpt: `${rawBlob.slice(0, 44)}... -> Decoded: "${decoded.slice(0, 120)}"`,
        decoded_payload: decoded,
        offset: cand.index,
      });
    }
  }

  // 4. Scan for Obfuscated Hex blocks inside text and inspect decoded content
  const hexCandidates = Array.from(deobfuscatedSurface.matchAll(CANDIDATE_HEX_REGEX));
  for (const cand of hexCandidates) {
    const rawHex = cand[0];
    // Ignore sha256 fingerprint strings
    const prefix = deobfuscatedSurface.slice(Math.max(0, (cand.index ?? 0) - 7), cand.index ?? 0);
    if (prefix.toLowerCase() === 'sha256:') continue;

    const decoded = tryDecodeHexAscii(rawHex);
    if (decoded) {
      decodedBlobs.push({ encoding: 'hex', raw: rawHex, decoded });
      matches.push({
        category: 'OBFUSCATED_HEX',
        pattern_id: 'HIDDEN_HEX_PAYLOAD',
        description: 'Embedded Hex-encoded ASCII instruction sequence discovered inside document',
        severity_weight: 0.38,
        matched_excerpt: `${rawHex.slice(0, 40)}... -> Decoded: "${decoded.slice(0, 120)}"`,
        decoded_payload: decoded,
        offset: cand.index,
      });
    }
  }

  // 5. Run pattern rules across both raw deobfuscated text and any decoded Base64/Hex blobs
  const combinedWithDecoded = [
    deobfuscatedSurface,
    ...decodedBlobs.map((b) => `[DECODED_${b.encoding.toUpperCase()}] ${b.decoded}`),
  ].join('\n');

  for (const rule of HEURISTIC_RULES) {
    rule.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.regex.exec(combinedWithDecoded)) !== null) {
      const start = Math.max(0, m.index - 24);
      const end = Math.min(combinedWithDecoded.length, m.index + m[0].length + 48);
      const snippet = combinedWithDecoded.slice(start, end).replace(/\s+/g, ' ').trim();

      // Avoid duplicate snippet entries for the same pattern_id
      const alreadyRecorded = matches.some(
        (existing) => existing.pattern_id === rule.id && existing.matched_excerpt === snippet
      );
      if (!alreadyRecorded) {
        matches.push({
          category: rule.category,
          pattern_id: rule.id,
          description: rule.description,
          severity_weight: rule.weight,
          matched_excerpt: snippet,
          offset: m.index,
        });
      }
    }
  }

  const rawScore = matches.reduce((acc, item) => acc + item.severity_weight, 0);
  const heuristicScore = Number(Math.min(1.0, rawScore).toFixed(2));

  return {
    flagged: matches.length > 0,
    heuristic_score: heuristicScore,
    matches,
    zero_width_count: zeroWidthCount,
    control_char_count: controlCharCount,
    decoded_blobs: decodedBlobs,
  };
}
