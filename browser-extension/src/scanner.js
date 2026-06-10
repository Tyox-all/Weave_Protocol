/**
 * Weave Browser Guard — IPI scanner.
 *
 * Adapted from @weave_protocol/browser's ipi.ts. Same 33 patterns,
 * browser-compatible (no Node APIs). Self-contained, no imports.
 *
 * Patterns are kept in sync manually with the npm package. When the npm
 * scanner adds patterns, update this file too.
 */

// ============================================================================
// Pattern definitions
// ============================================================================

const TRIGGER_PHRASES = [
  {
    pattern: /\bignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|directives?|rules?|commands?)\b/i,
    description: 'classic "ignore previous instructions" pattern',
  },
  {
    pattern: /\bdisregard\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|content)\b/i,
    description: '"disregard previous" variant',
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
    description: 'LLM-targeted directive (Forcepoint-observed)',
  },
  {
    pattern: /\byour\s+new\s+(?:task|instructions?|mission|objective|directive)s?\s+(?:is|are)\b/i,
    description: '"your new task is" instruction-replacement',
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

const ACTION_DIRECTIVES = [
  {
    pattern: /\bsend\s+(?:an?\s+)?(?:email|message|payment)\s+to\s+[^\s<>"]+@[^\s<>"]+/i,
    description: 'directive to send communication to specific recipient',
  },
  {
    pattern: /\b(?:transfer|send|pay|wire)\s+(?:\$|usd|eur|gbp|btc|eth)?\s*[\d,.]+\s*(?:dollars?|usd|eur|btc|eth)?\s+to\s+/i,
    description: 'payment transfer directive',
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

const PAYMENT_PATTERN =
  /\b(?:to|recipient|account|address)\s*:?\s*[a-z0-9_.@\-]{4,}[\s\S]{0,200}?\b(?:amount|sum|total|usd|eur|gbp|btc|eth)\s*:?\s*\$?\s*[\d,.]+|\b(?:to|recipient|account|address)\s*:?\s*[a-z0-9_.@\-]{4,}[\s\S]{0,200}?\$\s*[\d,.]+/i;

const DOS_PATTERNS = [
  {
    pattern: /\b(?:copyright|owner|publisher)\s+(?:has\s+)?(?:expressly\s+)?(?:forbid|forbidden|prohibit|prohibited|denied|disallow|disallowed)\s+(?:any\s+)?ai\s+(?:agents?\s+|systems?\s+|to\s+|from\s+)/i,
    description: 'false copyright claim to suppress AI summarization',
  },
  {
    pattern: /\bdo\s+not\s+(?:summari[sz]e|analy[sz]e|process|read|describe)\s+(?:this\s+(?:page|content|document)|the\s+(?:above|below))\b/i,
    description: 'explicit "do not process" directive',
  },
];

const TOOL_CALL_MIMICRY = [
  {
    pattern: /\{\s*"(?:function|tool|action|name)"\s*:\s*"[a-z_]+"\s*,\s*"(?:arguments|args|parameters|input)"\s*:/i,
    description: 'JSON object that mimics LLM tool-call schema',
  },
  {
    pattern: /<\s*(?:function_calls?|tool_use|invoke|antml:function_calls?)\s*>/i,
    description: 'XML/tag mimicking tool-call markup',
  },
];

const SUSPICIOUS_BASE64 = /\b(?:decode|decrypt|execute|eval)\b[\s\S]{0,80}?[a-zA-Z0-9+/=]{60,}/i;
const UNICODE_OBFUSCATION = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069]{2,}/;

const HIDDEN_CSS_PATTERNS = [
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
    description: 'substantive text positioned off-screen',
  },
  {
    pattern: /<[^>]*style\s*=\s*["'][^"']*color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))[^"']*background[^"']*(?:white|#fff(?:fff)?)[^"']*["'][^>]*>([^<]{20,})/gi,
    type: 'hidden_text_color',
    description: 'white-on-white text (Brave/Comet pattern)',
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

function detectHtml(content) {
  const sample = content.slice(0, 2000);
  return /<\/?(?:html|body|head|div|p|span|a|img|script|style|meta|link|title)\b/i.test(sample);
}

function looksInstructional(text) {
  const t = text.toLowerCase();
  if (/\b(?:llm|ai|assistant|chatbot|gpt|claude|gemini|copilot|agent)\b/.test(t)) return true;
  if (/\b(?:ignore|disregard|forget|override|pretend|act\s+as)\b/.test(t)) return true;
  if (/\b(?:you\s+(?:are|must|should|will)|your\s+(?:task|role|instructions?))\b/.test(t)) return true;
  if (/\b(?:do\s+not|don['']?t)\s+(?:tell|reveal|summari[sz]e|mention)\b/.test(t)) return true;
  if (/\b(?:system|user|assistant)\s*:\s/.test(t)) return true;
  if (/\b(?:send|transfer|email|execute|run|call|fetch)\s+\w+\s+to\b/.test(t)) return true;
  return false;
}

function truncate(s, n) {
  s = s.replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function computeRiskLevel(threats) {
  if (threats.length === 0) return 'none';
  if (threats.some((t) => t.severity === 'critical')) return 'critical';
  if (threats.some((t) => t.severity === 'high')) return 'high';
  if (threats.some((t) => t.severity === 'medium')) return 'medium';
  return 'low';
}

/**
 * Scan a string of content for indirect prompt injection.
 * @param {string} content
 * @param {{ isHtml?: boolean, maxLength?: number }} opts
 * @returns {{ safe: boolean, threats: Array, riskLevel: string, contentLength: number, isHtml: boolean }}
 */
export function scanForIpi(content, opts = {}) {
  const maxLength = opts.maxLength ?? 1_000_000;
  if (content.length > maxLength) content = content.slice(0, maxLength);
  const isHtml = opts.isHtml ?? detectHtml(content);
  const threats = [];

  // Trigger phrases
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

  // Action directives
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

  // Payment specification
  {
    const m = PAYMENT_PATTERN.exec(content);
    if (m) {
      threats.push({
        type: 'payment_specification',
        severity: 'critical',
        description: 'recipient + amount in proximity (autonomous-fraud pattern)',
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.7,
      });
    }
  }

  // DoS
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

  // Tool-call mimicry
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

  // Base64 + Unicode obfuscation
  {
    const m = SUSPICIOUS_BASE64.exec(content);
    if (m) {
      threats.push({
        type: 'base64_payload',
        severity: 'medium',
        description: 'long base64 near decode/execute keyword',
        evidence: truncate(m[0], 200),
        offset: m.index,
        confidence: 0.6,
      });
    }
  }
  {
    const m = UNICODE_OBFUSCATION.exec(content);
    if (m) {
      threats.push({
        type: 'unicode_obfuscation',
        severity: 'medium',
        description: 'zero-width or directional override characters cluster',
        evidence: '(unicode markers — invisible)',
        offset: m.index,
        confidence: 0.7,
      });
    }
  }

  if (isHtml) {
    // Hidden CSS
    for (const { pattern, type, description } of HIDDEN_CSS_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let m;
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
          if (re.lastIndex === m.index) re.lastIndex++;
        }
      }
    }

    // HTML comments
    {
      const re = new RegExp(HTML_COMMENT_PATTERN.source, HTML_COMMENT_PATTERN.flags);
      let m;
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

    // noscript
    {
      const re = new RegExp(NOSCRIPT_PATTERN.source, NOSCRIPT_PATTERN.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (body.length >= 30 && looksInstructional(body)) {
          threats.push({
            type: 'noscript_payload',
            severity: 'high',
            description: '<noscript> tag contains instructional content',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.8,
          });
        }
      }
    }

    // aria-hidden
    {
      const re = new RegExp(ARIA_HIDDEN_PATTERN.source, ARIA_HIDDEN_PATTERN.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (looksInstructional(body)) {
          threats.push({
            type: 'aria_hidden_payload',
            severity: 'high',
            description: 'aria-hidden=true contains instructional content',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.85,
          });
        }
      }
    }

    // meta
    {
      const re = new RegExp(META_INJECTION_PATTERN.source, META_INJECTION_PATTERN.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (looksInstructional(body)) {
          threats.push({
            type: 'meta_tag_injection',
            severity: 'medium',
            description: 'meta tag contains LLM-directed content',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.7,
          });
        }
      }
    }

    // alt
    {
      const re = new RegExp(ALT_INSTRUCTIONAL_PATTERN.source, ALT_INSTRUCTIONAL_PATTERN.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        const body = m[1] || '';
        if (looksInstructional(body)) {
          threats.push({
            type: 'alt_attribute_payload',
            severity: 'medium',
            description: 'image alt text contains LLM-directed content',
            evidence: truncate(body, 200),
            offset: m.index,
            confidence: 0.7,
          });
        }
      }
    }

    // data URIs
    {
      const re = new RegExp(DATA_URI_HTML_PATTERN.source, DATA_URI_HTML_PATTERN.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        threats.push({
          type: 'data_uri_payload',
          severity: 'medium',
          description: 'data:text/html or text/plain URI',
          evidence: truncate(m[0], 200),
          offset: m.index,
          confidence: 0.65,
        });
      }
    }

    // SVG + script
    {
      const re = new RegExp(SVG_SCRIPT_PATTERN.source, SVG_SCRIPT_PATTERN.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        threats.push({
          type: 'svg_script_payload',
          severity: 'high',
          description: 'SVG with embedded <script>',
          evidence: truncate(m[1] || '', 200),
          offset: m.index,
          confidence: 0.9,
        });
      }
    }
  }

  const riskLevel = computeRiskLevel(threats);
  return {
    safe: riskLevel === 'none' || riskLevel === 'low',
    threats,
    riskLevel,
    contentLength: content.length,
    isHtml,
  };
}

export const PATTERN_COUNT = 33;
