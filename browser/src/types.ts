/**
 * Types for @weave_protocol/browser.
 *
 * Threat model:
 *   1. Navigation to malicious URLs — checked against WARD ## Network rules
 *   2. Indirect prompt injection (IPI) in page content — scanned before agent ingestion
 *   3. Tool/action calls in sessions with tainted (untrusted) content — gated
 *      against WARD ## Capabilities + ## Network rules
 *   4. Downloads of malicious files — checked against MIME / extension policy
 */

// ============================================================================
// Decisions
// ============================================================================

export type Decision = 'allow' | 'deny' | 'require_approval';

export interface DecisionResult {
  decision: Decision;
  reasons: string[];
  policySource?: string;
}

// ============================================================================
// IPI (Indirect Prompt Injection) detection
// ============================================================================

/**
 * Categories of IPI threats. These map to documented in-the-wild patterns
 * (Forcepoint, Google CommonCrawl analysis, Lakera Gandalf, Brave/Comet OTP exfil,
 * EchoLeak CVE-2025-32711, Palo Alto Unit 42 telemetry).
 */
export type IpiThreatType =
  | 'trigger_phrase'         // "ignore previous instructions", "you are now", etc.
  | 'hidden_text_css'        // display:none / visibility:hidden / opacity:0 with text
  | 'hidden_text_color'      // text color matches background (white-on-white)
  | 'hidden_text_size'       // 1px / 0px font-size text
  | 'hidden_text_position'   // text positioned offscreen (left:-9999px)
  | 'html_comment_injection' // instructions inside HTML comments
  | 'aria_hidden_payload'    // aria-hidden=true with substantive content
  | 'meta_tag_injection'     // instructions in meta description/keywords
  | 'alt_attribute_payload'  // long instructional alt text on images
  | 'unicode_obfuscation'    // zero-width spaces, RTL marks, homoglyphs
  | 'base64_payload'         // suspiciously long base64 strings near LLM keywords
  | 'role_hijack'            // "system:", "[INST]", chat-template tokens
  | 'denial_of_service'      // "copyright forbids AI", "do not summarize"
  | 'action_directive'       // explicit "send email to X", "transfer Y to Z"
  | 'payment_specification'  // recipient + amount + currency in close proximity
  | 'exfiltration_url'       // URL templating with placeholders for user data
  | 'tool_call_mimicry'      // {"function": ...} or <tool> tags in content
  | 'data_uri_payload'       // data:text/html with embedded instructions
  | 'noscript_payload'       // <noscript> with substantive instructions
  | 'svg_script_payload';    // <svg><script> with instructions

export interface IpiThreat {
  type: IpiThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Short human-readable description of the finding. */
  description: string;
  /** Snippet of the offending content (truncated to 200 chars). */
  evidence: string;
  /** Approximate character offset in source, when available. */
  offset?: number;
  /** Confidence: 0-1. High = clear pattern, low = heuristic. */
  confidence: number;
}

export interface IpiScanResult {
  /** False if any high or critical threats were found. */
  safe: boolean;
  threats: IpiThreat[];
  /** Overall risk level: max severity across all threats. */
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** Length of content scanned. */
  contentLength: number;
  /** Was the content treated as HTML (true) or plain text (false). */
  isHtml: boolean;
}

// ============================================================================
// Navigation, downloads
// ============================================================================

export interface NavigationCheck {
  url: string;
  /** Optional: where the navigation request came from. */
  source?: 'user' | 'page-link' | 'redirect' | 'agent-directed';
}

export interface DownloadCheck {
  url: string;
  filename: string;
  /** MIME type from Content-Type header, if known. */
  mimeType?: string;
  /** Size in bytes, if known. */
  size?: number;
}

// ============================================================================
// Provenance tracking
// ============================================================================

/**
 * Tracks which content sources the agent has ingested in this session. Used to
 * gate later actions: if a tool call (e.g. send_email, http_request) was
 * decided after ingesting content from an external/untrusted source, WARD can
 * be configured to deny or require approval.
 *
 * The 2026 SOTA defense pattern (per Zylos research): "flag tool calls
 * originating from sessions that processed untrusted external content."
 */
export interface SessionProvenance {
  sessionId: string;
  /** URLs the agent has fetched (and their trust level). */
  ingestedSources: Array<{
    url: string;
    trustLevel: 'trusted' | 'untrusted' | 'unknown';
    ingestedAt: number;
    /** Was IPI detected when this source was scanned? */
    hadIpi: boolean;
  }>;
  /** True if any untrusted source has been ingested in this session. */
  tainted: boolean;
}

// ============================================================================
// Errors
// ============================================================================

export class WardBrowserDeniedError extends Error {
  public readonly decision: 'deny' | 'require_approval';
  public readonly reasons: string[];
  public readonly subject: string;
  public readonly policySource: string | undefined;

  constructor(
    decision: 'deny' | 'require_approval',
    reasons: string[],
    subject: string,
    policySource?: string,
  ) {
    super(
      `WARD ${decision === 'deny' ? 'denied' : 'requires approval for'} '${subject}': ${reasons.join(' | ')}`,
    );
    this.name = 'WardBrowserDeniedError';
    this.decision = decision;
    this.reasons = reasons;
    this.subject = subject;
    this.policySource = policySource;
  }
}

export class IpiDetectedError extends Error {
  public readonly scan: IpiScanResult;
  public readonly url: string | undefined;

  constructor(scan: IpiScanResult, url?: string) {
    const topThreat = scan.threats[0];
    const where = url ? ` in ${url}` : '';
    super(
      `Indirect prompt injection detected${where} ` +
        `(risk=${scan.riskLevel}, ${scan.threats.length} threat${scan.threats.length === 1 ? '' : 's'}). ` +
        (topThreat ? `Top finding: ${topThreat.type} — ${topThreat.description}` : ''),
    );
    this.name = 'IpiDetectedError';
    this.scan = scan;
    this.url = url;
  }
}

// ============================================================================
// Options
// ============================================================================

export interface GuardOptions {
  /** Explicit path to WARD.md. Auto-resolves if omitted. */
  wardPath?: string;
  /** Inline WARD.md content (for tests). */
  wardSource?: string;
  /** Behavior when no WARD.md is found. Default: 'open' (warn + allow). */
  failMode?: 'open' | 'closed';
  /**
   * IPI scanning strictness:
   *   - 'strict':   any threat (incl. low/medium) blocks
   *   - 'standard': high + critical block, medium requires approval, low logs
   *   - 'lenient':  only critical blocks
   * Default: 'standard'
   */
  ipiSensitivity?: 'strict' | 'standard' | 'lenient';
  /** Custom dangerous file extensions for download checks. */
  blockedExtensions?: string[];
  /** Custom dangerous MIME types for download checks. */
  blockedMimeTypes?: string[];
  /** Optional logger for allow/deny/scan events. */
  onAllow?: (subject: string, details: Record<string, unknown>) => void | Promise<void>;
  onDeny?: (
    subject: string,
    details: Record<string, unknown>,
  ) => boolean | void | Promise<boolean | void>;
  onIpiDetected?: (scan: IpiScanResult, url?: string) => void | Promise<void>;
}
