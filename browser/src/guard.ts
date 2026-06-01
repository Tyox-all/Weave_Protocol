/**
 * WardBrowserGuard — the primary public API for @weave_protocol/browser.
 *
 * Provides four primary methods:
 *   - checkNavigation(url) — gate a URL against WARD ## Network rules
 *   - scanForInjection(html) — detect IPI in fetched content
 *   - checkDownload(opts) — gate file downloads
 *   - checkAction(capability, sessionId) — gate tool calls in tainted sessions
 *
 * Plus a convenience wrapper for Playwright:
 *   - wrapPlaywrightPage(page) — auto-gates navigation/content/downloads
 *
 * Construction is synchronous (WARD is loaded once at construction time —
 * not per-call — to keep hot paths fast).
 */

import type { WardPolicy } from '@weave_protocol/ward';
import {
  resolveWardForCwd,
  loadWardFromPath,
  loadWardFromSource,
  evaluateNavigation,
  evaluateDownload,
  evaluateTaintedAction,
  type ResolvedWard,
} from './policy.js';
import { scanForIpi } from './ipi.js';
import {
  recordIngestion,
  isTainted,
  classifyTrust,
  getSession,
} from './provenance.js';
import {
  type GuardOptions,
  type IpiScanResult,
  type NavigationCheck,
  type DownloadCheck,
  type DecisionResult,
  type SessionProvenance,
  WardBrowserDeniedError,
  IpiDetectedError,
} from './types.js';

// Defaults for blocked file extensions / MIME types. Conservative — covers
// common executable / scripting formats. Users can override via opts.
const DEFAULT_BLOCKED_EXTENSIONS = [
  '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.msi', '.msix',
  '.app', '.dmg', '.pkg',
  '.sh', '.bash', '.zsh', '.ps1',
  '.jar', '.deb', '.rpm', '.apk',
  '.iso', '.img',
];

const DEFAULT_BLOCKED_MIME = [
  'application/x-msdownload',
  'application/x-executable',
  'application/x-msdos-program',
  'application/x-sh',
  'application/x-shellscript',
];

// ============================================================================
// WardBrowserGuard class
// ============================================================================

export class WardBrowserGuard {
  private resolved: ResolvedWard | null;
  private readonly failClosed: boolean;
  private readonly sensitivity: 'strict' | 'standard' | 'lenient';
  private readonly blockedExtensions: string[];
  private readonly blockedMimeTypes: string[];
  private readonly onAllow?: GuardOptions['onAllow'];
  private readonly onDeny?: GuardOptions['onDeny'];
  private readonly onIpiDetected?: GuardOptions['onIpiDetected'];

  /** Extracted from WARD ## Network for fast trust classification. */
  private readonly allowedOrigins: string[];

  constructor(opts: GuardOptions = {}) {
    this.failClosed = opts.failMode === 'closed';
    this.sensitivity = opts.ipiSensitivity ?? 'standard';
    this.blockedExtensions = opts.blockedExtensions ?? DEFAULT_BLOCKED_EXTENSIONS;
    this.blockedMimeTypes = opts.blockedMimeTypes ?? DEFAULT_BLOCKED_MIME;
    this.onAllow = opts.onAllow;
    this.onDeny = opts.onDeny;
    this.onIpiDetected = opts.onIpiDetected;

    try {
      if (opts.wardSource) {
        this.resolved = loadWardFromSource(opts.wardSource);
      } else if (opts.wardPath) {
        this.resolved = loadWardFromPath(opts.wardPath);
      } else {
        this.resolved = resolveWardForCwd();
      }
    } catch (err) {
      if (this.failClosed) throw err;
      // eslint-disable-next-line no-console
      console.warn(
        `[weave-browser] WARD.md could not be loaded (${err instanceof Error ? err.message : String(err)}). Running in fail-open mode — no enforcement.`,
      );
      this.resolved = null;
    }

    this.allowedOrigins = extractAllowedOrigins(this.resolved?.policy);
  }

  // ──────────────────────────────────────────────────────────────────
  // Inspection
  // ──────────────────────────────────────────────────────────────────

  isLoaded(): boolean {
    return this.resolved !== null;
  }

  getPolicySource(): string | null {
    return this.resolved?.source ?? null;
  }

  getPolicy(): WardPolicy | null {
    return this.resolved?.policy ?? null;
  }

  getSensitivity(): 'strict' | 'standard' | 'lenient' {
    return this.sensitivity;
  }

  // ──────────────────────────────────────────────────────────────────
  // Navigation
  // ──────────────────────────────────────────────────────────────────

  /**
   * Check whether a URL navigation should be allowed. Throws
   * WardBrowserDeniedError if denied; returns the decision result otherwise.
   *
   * Pass `sessionId` to record this fetch in the session's provenance log
   * (used by checkAction() to decide whether to elevate scrutiny).
   */
  async checkNavigation(
    urlOrCheck: string | NavigationCheck,
    sessionId?: string,
  ): Promise<DecisionResult> {
    const check: NavigationCheck =
      typeof urlOrCheck === 'string' ? { url: urlOrCheck } : urlOrCheck;

    if (!this.resolved) {
      // Fail-open: no policy loaded.
      return { decision: 'allow', reasons: ['No WARD.md loaded'] };
    }

    const result = evaluateNavigation(this.resolved.policy, check.url);
    const detail = { url: check.url, source: check.source, sessionId };

    if (result.decision === 'allow') {
      if (this.onAllow) await this.onAllow(`navigation:${check.url}`, detail);
      return { ...result, policySource: this.resolved.source };
    }

    // Denied or requires approval
    if (this.onDeny) {
      const override = await this.onDeny(`navigation:${check.url}`, detail);
      if (override === true) {
        return { decision: 'allow', reasons: ['Overridden by onDeny callback'] };
      }
    }
    throw new WardBrowserDeniedError(
      result.decision === 'deny' ? 'deny' : 'require_approval',
      result.reasons,
      `navigation to ${check.url}`,
      this.resolved.source,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // IPI scanning
  // ──────────────────────────────────────────────────────────────────

  /**
   * Scan fetched page content for indirect prompt injection.
   *
   * Returns an IpiScanResult. Whether it throws depends on guard sensitivity:
   *   - strict:   throws IpiDetectedError on ANY threat (low/medium/high/critical)
   *   - standard: throws on high or critical, records medium as taint
   *   - lenient:  throws only on critical
   *
   * Either way, the result is also reported to onIpiDetected if configured,
   * and the session (if provided) is recorded as tainted.
   */
  async scanForInjection(
    content: string,
    opts: { url?: string; sessionId?: string; isHtml?: boolean } = {},
  ): Promise<IpiScanResult> {
    const result = scanForIpi(content, { isHtml: opts.isHtml });

    // Record provenance
    if (opts.sessionId && opts.url) {
      const trustLevel = classifyTrust(opts.url, this.allowedOrigins);
      recordIngestion(
        opts.sessionId,
        opts.url,
        trustLevel,
        !result.safe,
      );
    }

    if (!result.safe && this.onIpiDetected) {
      await this.onIpiDetected(result, opts.url);
    }

    // Decide whether to throw based on sensitivity
    const shouldThrow = this.shouldThrowForRisk(result.riskLevel);
    if (shouldThrow) {
      throw new IpiDetectedError(result, opts.url);
    }
    return result;
  }

  private shouldThrowForRisk(risk: IpiScanResult['riskLevel']): boolean {
    if (this.sensitivity === 'strict') return risk !== 'none';
    if (this.sensitivity === 'standard') return risk === 'high' || risk === 'critical';
    return risk === 'critical'; // lenient
  }

  // ──────────────────────────────────────────────────────────────────
  // Downloads
  // ──────────────────────────────────────────────────────────────────

  async checkDownload(check: DownloadCheck): Promise<DecisionResult> {
    if (!this.resolved) {
      // Fail-open: still apply MIME/extension blocklists even without WARD
      const fallback = evaluateDownload(
        { name: '', agent: '', version: '1.0' } as WardPolicy,
        check,
        this.blockedExtensions,
        this.blockedMimeTypes,
      );
      if (fallback.decision === 'deny') {
        if (this.onDeny) await this.onDeny(`download:${check.filename}`, { check });
        throw new WardBrowserDeniedError('deny', fallback.reasons, `download ${check.filename}`);
      }
      return { decision: 'allow', reasons: ['No WARD.md loaded'] };
    }

    const result = evaluateDownload(
      this.resolved.policy,
      check,
      this.blockedExtensions,
      this.blockedMimeTypes,
    );
    const detail = { ...check };

    if (result.decision === 'allow') {
      if (this.onAllow) await this.onAllow(`download:${check.filename}`, detail);
      return { ...result, policySource: this.resolved.source };
    }

    if (this.onDeny) {
      const override = await this.onDeny(`download:${check.filename}`, detail);
      if (override === true) return { decision: 'allow', reasons: ['Overridden by onDeny'] };
    }
    throw new WardBrowserDeniedError(
      result.decision === 'deny' ? 'deny' : 'require_approval',
      result.reasons,
      `download ${check.filename}`,
      this.resolved.source,
    );
  }

  // ──────────────────────────────────────────────────────────────────
  // Tainted-session action gating
  // ──────────────────────────────────────────────────────────────────

  /**
   * Check whether a tool call / capability invocation should be allowed,
   * given the session's provenance.
   *
   * If the session has ingested untrusted content (especially with IPI),
   * this elevates normally-allowed capabilities to require_approval. WARD's
   * own deny rules always win.
   *
   * Pass capabilities like "send_email", "http_request", "shell_exec", etc.
   */
  async checkAction(capability: string, sessionId: string): Promise<DecisionResult> {
    if (!this.resolved) {
      return { decision: 'allow', reasons: ['No WARD.md loaded'] };
    }

    const tainted = isTainted(sessionId);
    if (!tainted) {
      // Clean session — use normal WARD capability check via evaluator
      const result = evaluateTaintedAction(this.resolved.policy, capability);
      // For untainted sessions, demote require_approval back to allow if the
      // only reason was the taint elevation
      if (result.decision === 'require_approval' && result.reasons.some((r) => r.includes('session has ingested'))) {
        return { decision: 'allow', reasons: ['Session is untainted'] };
      }
      return { ...result, policySource: this.resolved.source };
    }

    // Tainted session: elevate scrutiny
    const result = evaluateTaintedAction(this.resolved.policy, capability);
    if (result.decision === 'deny') {
      if (this.onDeny) {
        const override = await this.onDeny(`action:${capability}`, { sessionId, tainted });
        if (override === true) return { decision: 'allow', reasons: ['Overridden by onDeny'] };
      }
      throw new WardBrowserDeniedError(
        'deny',
        result.reasons,
        `tainted-session action ${capability}`,
        this.resolved.source,
      );
    }
    // For require_approval in tainted sessions, return the result — the
    // caller is expected to surface to a human, not throw automatically.
    return { ...result, policySource: this.resolved.source };
  }

  // ──────────────────────────────────────────────────────────────────
  // Convenience
  // ──────────────────────────────────────────────────────────────────

  /**
   * Inspect a session's full provenance record. Useful for logging and
   * human-in-the-loop approval flows.
   */
  getSessionProvenance(sessionId: string): SessionProvenance | undefined {
    return getSession(sessionId);
  }

  /**
   * Wrap a Playwright Page so navigation, content reads, and downloads
   * are auto-gated. Returns the same page; modifications are via event
   * hooks (not method replacement) so all existing code keeps working.
   *
   * The Page type is intentionally typed as `unknown` here so this package
   * does not have a hard dependency on `playwright` — the helper duck-types
   * the methods it needs. If Playwright isn't installed, the import won't
   * fail; only calling wrapPlaywrightPage() with a wrong shape will throw.
   *
   * For full Playwright type-safety, use this with @playwright/test as a
   * peer dep in the consuming project.
   */
  wrapPlaywrightPage(page: unknown, sessionId?: string): unknown {
    // Minimal duck typing — Playwright Page has on(), goto(), etc.
    const p = page as {
      on: (event: string, handler: (...args: unknown[]) => unknown) => unknown;
      goto?: (url: string, opts?: unknown) => Promise<unknown>;
    };
    if (!p || typeof p.on !== 'function') {
      throw new TypeError('wrapPlaywrightPage: expected a Playwright Page object');
    }

    const sid = sessionId ?? `pw-${Math.random().toString(36).slice(2, 10)}`;

    // 1. Gate navigation: 'request' event fires on every navigation/subresource.
    //    We hook on 'framenavigated' for top-level navigations specifically.
    p.on('framenavigated', async (frame: unknown) => {
      const f = frame as { url: () => string; parentFrame?: () => unknown };
      if (f.parentFrame && f.parentFrame()) return; // only top-level
      const url = f.url();
      if (!url || url === 'about:blank') return;
      try {
        await this.checkNavigation({ url, source: 'page-link' }, sid);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[weave-browser] post-navigation denial for ${url}: ${err}`);
      }
    });

    // 2. Scan content on each response (only HTML).
    p.on('response', async (response: unknown) => {
      const r = response as {
        url: () => string;
        headers: () => Record<string, string>;
        text: () => Promise<string>;
        status: () => number;
      };
      const ct = r.headers()['content-type'] || '';
      if (!ct.includes('text/html') || r.status() >= 400) return;
      try {
        const body = await r.text();
        await this.scanForInjection(body, { url: r.url(), sessionId: sid, isHtml: true });
      } catch (err) {
        if (err instanceof IpiDetectedError) {
          // eslint-disable-next-line no-console
          console.warn(`[weave-browser] IPI detected at ${r.url()}: risk=${err.scan.riskLevel}`);
        }
      }
    });

    // 3. Gate downloads.
    p.on('download', async (download: unknown) => {
      const d = download as {
        url: () => string;
        suggestedFilename: () => string;
      };
      try {
        await this.checkDownload({ url: d.url(), filename: d.suggestedFilename() });
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[weave-browser] download blocked: ${err}`);
      }
    });

    return page;
  }
}

// ============================================================================
// Helpers
// ============================================================================

function extractAllowedOrigins(policy: WardPolicy | undefined): string[] {
  if (!policy || !policy.network?.allow) return [];
  // URL patterns in WARD ## Network can be globs like "https://api.github.com/**"
  // Extract just the origin portion for fast trust classification.
  const origins = new Set<string>();
  for (const rule of policy.network.allow) {
    const url = rule.url;
    try {
      const u = new URL(url.replace(/\*+.*$/, ''));
      origins.add(u.origin);
    } catch {
      // Non-URL-pattern rule, skip
    }
  }
  return Array.from(origins);
}
