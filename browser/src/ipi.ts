/**
 * Indirect prompt injection (IPI) detection.
 *
 * Patterns cover documented in-the-wild attacks as of May 2026:
 *   - Forcepoint X-Labs telemetry (April 2026): "ignore previous instructions",
 *     "if you are an LLM", denial-of-service via false copyright claims
 *   - Google CommonCrawl analysis (April 2026): 32% increase in IPI Nov 2025 → Feb 2026
 *   - Lakera Gandalf: Agent Breaker red-team patterns (travel blog phishing,
 *     compromised MCP tool descriptions, poisoned PDFs, poisoned code rules)
 *   - Brave / Perplexity Comet OTP exfiltration via hidden text in Reddit (2025)
 *   - EchoLeak CVE-2025-32711 (Microsoft 365 Copilot zero-click)
 *   - Palo Alto Unit 42: AI ad-review bypass (March 2026)
 *   - Atlan ad moderation bypass + financial-fraud-via-IPI cases (Dec 2025)
 *
 * The scanner does NOT use an LLM to detect IPI (that would be vulnerable to
 * the same attack class). It's pure regex + HTML structure inspection. Fast,
 * deterministic, and itself unattackable by the content it's inspecting.
 */

import type { IpiThreat, IpiThreatType, IpiScanResult } from './types.js';

// ============================================================================
// Pattern definitions
// ============================================================================

/**
 * High-confidence trigger phrases that almost never appear in benign content.
 *
 * Word boundaries (\b) on both sides prevent matches inside larger words.
 * Case-insensitive. Multiple variations of each canonical pattern.
 */
const TRIGGER_PHRASES: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\bignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|directives?|rules?|commands?)\b/i,
    description: 'classic "ignore previous instructions" pattern',
  },
  {
    pattern: /\bdisregard\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|content)\b/i,
    description: '"disregard previous" variant of the canonical jailbreak',
  },
  {
    pattern: /\bforget\s+(?:all\s+|everything\s+|what\s+you\s+(?:were|are)\s+told|the\s+(?:rules|instructions))\b/i,
    description: '"forget everything" memory-wipe directive',
  },
  {
    pattern: /\b(?:you\s+are\s+now|act\s+as\s+if\s+you\s+are|pretend\s+to\s+be|new\s+role\s*:?\s*you\s+are)\s+(?:a\s+|an\s+)?[a-z]/i,
    description: 'role-hijack attempt ("you are now...")',
  },
  {
    pattern: /\bif\s+you\s+are\s+(?:an?\s+)?(?:llm|ai|assistant|chatbot|language\s+model|gpt|claude|gemini|copilot)\b/i,
    description: 'LLM-targeted directive (Forcepoint observed in the wild)',
  },
  {
    pattern: /\byour\s+new\s+(?:task|instructions?|mission|objective|directive)s?\s+(?:is|are)\b/i,
    description: '"your new task is" instruction-replacement pattern',
  },
  {
    pattern: /\b(?:system\s*:|<\s*system\s*>|\[\s*system\s*\]|\[\s*INST\s*\]|<\s*\|im_start\|\s*>)/i,
    description: 'chat-template role token (system:, [INST], etc.)',
  },
  {
    pattern: /\boverride\s+(?:your|the|all|previous)\s+(?:instructions?|safety|guidelines?|rules?|directives?)\b/i,
    description: 'explicit override directive',
  },
  {
    pattern: /\b(?:do\s+not|don['']?t)\s+(?:tell|reveal|mention|inform|let)\s+(?:the\s+)?(?:user|human|operator)\b/i,
    description: 'concealment directive (hide action from user)',
  },
];

/**
 * Action-oriented payloads. These are more dangerous than trigger phrases
 * because they specify a target action. Forcepoint and Atlan both flagged
 * "send to: [email]" and "transfer X to Y" patterns.
 */
const ACTION_DIRECTIVES: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\bsend\s+(?:an?\s+)?(?:email|message|payment)\s+to\s+[^\s<>"]+@[^\s<>"]+/i,
    description: 'directive to send communication to specific recipient',
  },
  {
    pattern: /\b(?:transfer|send|pay|wire)\s+(?:\$|usd|eur|gbp|btc|eth)?\s*[\d,.]+\s*(?:dollars?|usd|eur|btc|eth)?\s+to\s+/i,
    description: 'payment transfer directive (Atlan flagged this in Dec 2025)',
  },
  {
    pattern: /\b(?:exec|execute|run|invoke|call)\s+(?:the\s+|this\s+)?(?:command|tool|function|shell)\s*:\s*/i,
    description: 'tool/command execution directive',
  },
  {
    pattern: /\bfetch\s+(?:the\s+url\s+|content\s+from\s+|data\s+from\s+)?https?:\/\//i,
    description: 'fetch-directive (potential exfil channel)',
  },
];

/**
 * Payment specifications: recipient + amount + currency in close proximity.
 * Per Atlan, this pattern in IPI was used for autonomous fraud — agents with
 * payment integrations executing transfers without user confirmation.
 */
const PAYMENT_PATTERN =
  /\b(?:to|recipient|account|address)\s*:?\s*[a-z0-9_.@\-]{4,}[\s\S]{0,200}?\b(?:amount|sum|total|usd|eur|gbp|btc|eth)\s*:?\s*\$?\s*[\d,.]+|\b(?:to|recipient|account|address)\s*:?\s*[a-z0-9_.@\-]{4,}[\s\S]{0,200}?\$\s*[\d,.]+/i;

/**
 * Denial-of-service / content-suppression patterns. Less dangerous than action
 * directives but commonly observed (Forcepoint April 2026).
 */
const DOS_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\b(?:copyright|owner|publisher)\s+(?:has\s+)?(?:expressly\s+)?(?:forbid|forbidden|prohibit|prohibited|denied|disallow|disallowed)\s+(?:any\s+)?ai\s+(?:agents?\s+|systems?\s+|to\s+|from\s+)/i,
    description: 'false copyright claim to suppress AI summarization (Forcepoint observed)',
  },
  {
    pattern: /\bdo\s+not\s+(?:summari[sz]e|analy[sz]e|process|read|describe)\s+(?:this\s+(?:page|content|document)|the\s+(?:above|below))\b/i,
    description: 'explicit "do not process" directive',
  },
];

/**
 * Tool-call mimicry: content that looks like an LLM tool call output.
 * Agents may misinterpret these as legitimate function calls.
 */
const TOOL_CALL_MIMICRY: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\{\s*"(?:function|tool|action|name)"\s*:\s*"[a-z_]+"\s*,\s*"(?:arguments|args|parameters|input)"\s*:/i,
    description: 'JSON object that mimics LLM tool-call schema',
  },
  {
    pattern: /<\s*(?:function_calls?|tool_use|invoke|antml:function_calls?)\s*>/i,
    description: 'XML/tag mimicking tool-call markup',
  },
];

/**
 * Suspicious base64 strings: long base64 sequences near LLM-relevant keywords.
 * Heuristic — base64 alone is not suspicious (it's everywhere on the web),
 * but base64 + nearby words like "decode", "execute", "ignore" is suspicious.
 */
const SUSPICIOUS_BASE64 =
  /\b(?:decode|decrypt|execute|eval)\b[\s\S]{0,80}?[a-zA-Z0-9+/=]{60,}/i;

/**
 * Unicode obfuscation markers. Zero-width spaces and RTL/LTR overrides are
 * sometimes used to hide instructions in plain text content.
 */
const UNICODE_OBFUSCATION = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069]{2,}/;

// ============================================================================
// HTML hidden-content detection
// ============================================================================

const HIDDEN_CSS_PATTERNS: Array<{ pattern: RegExp; type: IpiThreatType; description: string }> = [
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_css',
    description: 'substantive text inside display:none element',
  },
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_css',
    description: 'substantive text inside visibility:hidden element',
  },
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*opacity\s*:\s*0(?:\.0+)?[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_css',
    description: 'substantive text inside opacity:0 element',
  },
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*font-size\s*:\s*0(?:\.\d+)?(?:px|pt|em)?[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_size',
    description: 'substantive text rendered at zero font-size',
  },
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*(?:left|top)\s*:\s*-\d{4,}px[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_position',
    description: 'substantive text positioned far off-screen',
  },
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))[^"']*background[^"']*(?:white|#fff(?:fff)?)[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_color',
    description: 'white-on-white text (the Brave/Comet pattern)',
  },
];

const HTML_COMMENT_PATTERN = /<!--([\s\S]*?)-->/g;
const NOSCRIPT_PATTERN = /<noscript[^>]*>([\s\S]*?)<\/noscript>/gi;
const ARIA_HIDDEN_PATTERN = /<[^>]*aria-hidden\s*=\s*["']true["'][^>]*>([^<]{30,})/gi;
const META_INJECTION_PATTERN =
  /<meta\s+[^>]*?(?:name|property)\s*=\s*["'](?:description|keywords?|abstract)["'][^>]*?content\s*=\s*["']([^"']{30,})["']/gi;
const ALT_INSTRUCTIONAL_PATTERN = /<img\s+[^>]*?alt\s*=\s*["']([^"']{80,})["']/gi;
const DATA_URI_HTML_PATTERN = /data:text\/(?:html|plain)[;,][^"'\s<>)]+/gi;
const SVG_SCRIPT_PATTERN = /<svg[^>]*>[\s\S]*?<script[^>]*>([\s\S]*?)<\/script>[\s\S]*?<\/svg>/gi;

// ============================================================================
// Scanner
// ============================================================================

export interface ScanOptions {
  /** Treat content as HTML (apply hidden-text checks). Default: auto-detect. */
  isHtml?: boolean;
  /** Maximum length to scan (DoS guard). Default: 1,000,000 chars. */
  maxLength?: number;
}

/**
 * Scan a string of content (HTML or plain text) for indirect prompt injection.
 *
 * Returns a structured result. Does not throw — caller decides what to do
 * with threats based on their sensitivity level.
 */
export function scanForIpi(content: string, opts: ScanOptions = {}): IpiScanResult {
  const maxLength = opts.maxLength ?? 1_000_000;
  if (content.length > maxLength) {
    // DoS guard — scan only the start of huge documents.
    content = content.slice(0, maxLength);
  }

  const isHtml = opts.isHtml ?? detectHtml(content);
  const threats: IpiThreat[] = [];

  // ─── Trigger phrases (apply to both HTML and plain text) ────────────
  for (const { pattern, description } of TRIGGER_PHRASES) {
    const m = pattern.exec(content);
    if (m) {
      threats.push({
        type: 'trigger_phrase',
        severity: 'high',
        description,
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.9,
      });
    }
  }

  // ─── Action directives (high severity — agentic abuse) ──────────────
  for (const { pattern, description } of ACTION_DIRECTIVES) {
    const m = pattern.exec(content);
    if (m) {
      threats.push({
        type: 'action_directive',
        severity: 'critical',
        description,
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.85,
      });
    }
  }

  // ─── Payment specification (autonomous-fraud pattern) ───────────────
  {
    const m = PAYMENT_PATTERN.exec(content);
    if (m) {
      threats.push({
        type: 'payment_specification',
        severity: 'critical',
        description:
          'recipient + amount in close proximity (Atlan-documented autonomous-fraud IPI pattern)',
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.7,
      });
    }
  }

  // ─── DoS / content suppression ──────────────────────────────────────
  for (const { pattern, description } of DOS_PATTERNS) {
    const m = pattern.exec(content);
    if (m) {
      threats.push({
        type: 'denial_of_service',
        severity: 'low',
        description,
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.8,
      });
    }
  }

  // ─── Tool-call mimicry ──────────────────────────────────────────────
  for (const { pattern, description } of TOOL_CALL_MIMICRY) {
    const m = pattern.exec(content);
    if (m) {
      threats.push({
        type: 'tool_call_mimicry',
        severity: 'high',
        description,
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.85,
      });
    }
  }

  // ─── Suspicious base64 ──────────────────────────────────────────────
  {
    const m = SUSPICIOUS_BASE64.exec(content);
    if (m) {
      threats.push({
        type: 'base64_payload',
        severity: 'medium',
        description: 'long base64 sequence near decode/execute keyword',
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.6,
      });
    }
  }

  // ─── Unicode obfuscation ────────────────────────────────────────────
  {
    const m = UNICODE_OBFUSCATION.exec(content);
    if (m) {
      threats.push({
        type: 'unicode_obfuscation',
        severity: 'medium',
        description: 'cluster of zero-width or directional override characters',
        evidence: '(unicode markers — invisible)',
        offset: m.index,
        confidence: 0.7,
      });
    }
  }

  // ─── HTML-specific checks ───────────────────────────────────────────
  if (isHtml) {
    // Hidden CSS content
    for (const { pattern, type, description } of HIDDEN_CSS_PATTERNS) {
      let m: RegExpExecArray | null;
      const re = new RegExp(pattern.source, pattern.flags);
      while ((m = re.exec(content)) !== null) {
        const hiddenText = m[1] || '';
        if (hiddenText.trim().length >= 20 && looksInstructional(hiddenText)) {
          threats.push({
            type,
            severity: 'high',
            description,
            evidence: truncate(hiddenText, 200),
            offset: m.index,
            confidence: 0.85,
          });
          if (re.lastIndex === m.index) re.lastIndex++; // avoid zero-width infinite loop
        }
      }
    }

    // HTML comments containing instructions
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(HTML_COMMENT_PATTERN.source, HTML_COMMENT_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (body.length >= 30 && looksInstructional(body)) {
          threats.push({
            type: 'html_comment_injection',
            severity: 'medium',
            description: 'HTML comment contains LLM-directed instructions',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.75,
          });
        }
      }
    }

    // <noscript> with instructions
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(NOSCRIPT_PATTERN.source, NOSCRIPT_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (body.length >= 30 && looksInstructional(body)) {
          threats.push({
            type: 'noscript_payload',
            severity: 'high',
            description: '<noscript> tag contains LLM-directed content',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.8,
          });
        }
      }
    }

    // aria-hidden=true with substantive text (Brave/Comet pattern)
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(ARIA_HIDDEN_PATTERN.source, ARIA_HIDDEN_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (looksInstructional(body)) {
          threats.push({
            type: 'aria_hidden_payload',
            severity: 'high',
            description: 'aria-hidden=true element contains instructional content',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.85,
          });
        }
      }
    }

    // Meta tags with long content
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(META_INJECTION_PATTERN.source, META_INJECTION_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (looksInstructional(body)) {
          threats.push({
            type: 'meta_tag_injection',
            severity: 'medium',
            description: 'meta tag content contains LLM-directed instructions',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.7,
          });
        }
      }
    }

    // Excessively long alt text on images (uncommon legitimately)
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(ALT_INSTRUCTIONAL_PATTERN.source, ALT_INSTRUCTIONAL_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (looksInstructional(body)) {
          threats.push({
            type: 'alt_attribute_payload',
            severity: 'medium',
            description: 'image alt text contains LLM-directed instructions',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.7,
          });
        }
      }
    }

    // data:text/html URIs (potential nested document with payload)
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(DATA_URI_HTML_PATTERN.source, DATA_URI_HTML_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        threats.push({
          type: 'data_uri_payload',
          severity: 'medium',
          description: 'data:text/html or data:text/plain URI (nested document)',
          evidence: truncate(m[0], 200),
          offset: m.index,
          confidence: 0.65,
        });
      }
    }

    // SVG with embedded script
    {
      let m: RegExpExecArray | null;
      const re = new RegExp(SVG_SCRIPT_PATTERN.source, SVG_SCRIPT_PATTERN.flags);
      while ((m = re.exec(content)) !== null) {
        threats.push({
          type: 'svg_script_payload',
          severity: 'high',
          description: 'SVG with embedded <script> — XSS + potential LLM injection vector',
          evidence: truncate(m[1] || '', 200),
          offset: m.index,
          confidence: 0.9,
        });
      }
    }
  }

  // ─── Compute risk level ─────────────────────────────────────────────
  const riskLevel = computeRiskLevel(threats);
  const safe = riskLevel === 'none' || riskLevel === 'low';

  return {
    safe,
    threats,
    riskLevel,
    contentLength: content.length,
    isHtml,
  };
}

// ============================================================================
// Helpers
// ============================================================================

function detectHtml(content: string): boolean {
  const sample = content.slice(0, 2000);
  return /<\/?(?:html|body|head|div|p|span|a|img|script|style|meta|link|head|title)\b/i.test(sample);
}

/**
 * Heuristic: does a chunk of text look like instructions to an LLM (vs.
 * normal prose)? Used to suppress false positives on benign hidden content
 * (e.g. a screen-reader-only menu label) while catching IPI.
 */
function looksInstructional(text: string): boolean {
  const t = text.toLowerCase();
  // Strong signals
  if (/\b(?:llm|ai|assistant|chatbot|gpt|claude|gemini|copilot|agent)\b/.test(t)) return true;
  if (/\b(?:ignore|disregard|forget|override|pretend|act\s+as)\b/.test(t)) return true;
  if (/\b(?:you\s+(?:are|must|should|will)|your\s+(?:task|role|instructions?))\b/.test(t)) return true;
  if (/\b(?:do\s+not|don['']?t)\s+(?:tell|reveal|summari[sz]e|mention)\b/.test(t)) return true;
  if (/\b(?:system|user|assistant)\s*:\s/.test(t)) return true;
  if (/\b(?:send|transfer|email|execute|run|call|fetch)\s+\w+\s+to\b/.test(t)) return true;
  return false;
}

function truncate(s: string, n: number): string {
  s = s.replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function computeRiskLevel(threats: IpiThreat[]): IpiScanResult['riskLevel'] {
  if (threats.length === 0) return 'none';
  if (threats.some((t) => t.severity === 'critical')) return 'critical';
  if (threats.some((t) => t.severity === 'high')) return 'high';
  if (threats.some((t) => t.severity === 'medium')) return 'medium';
  return 'low';
}

/**
 * Pattern catalog — exposed for tests and for the CLI's `status` command
 * (so we can show "scanner has N patterns loaded").
 */
export function getPatternCatalog(): {
  triggerPhrases: number;
  actionDirectives: number;
  dosPatterns: number;
  toolCallMimicry: number;
  hiddenCssPatterns: number;
  totalPatterns: number;
} {
  const counts = {
    triggerPhrases: TRIGGER_PHRASES.length,
    actionDirectives: ACTION_DIRECTIVES.length,
    dosPatterns: DOS_PATTERNS.length,
    toolCallMimicry: TOOL_CALL_MIMICRY.length,
    hiddenCssPatterns: HIDDEN_CSS_PATTERNS.length,
    // +5 standalone patterns: payment, base64, unicode, comments, noscript, aria, meta, alt, data-uri, svg-script
    totalPatterns: 0,
  };
  counts.totalPatterns =
    counts.triggerPhrases +
    counts.actionDirectives +
    counts.dosPatterns +
    counts.toolCallMimicry +
    counts.hiddenCssPatterns +
    10; // standalone patterns counted above
  return counts;
}
