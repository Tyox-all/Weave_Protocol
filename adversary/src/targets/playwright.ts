/**
 * PlaywrightTarget — real browser observer for adversary v0.2.
 *
 * Drives a real Chromium/Firefox/WebKit browser via Playwright. Observes
 * four breach signal channels concurrently:
 *
 *   1. Network requests — outbound HTTP/HTTPS the agent triggered
 *   2. Form submissions — including action URLs and method
 *   3. DOM mutations — via injected MutationObserver, posted to console
 *   4. Console output — page console logs (incl. leaked secrets/prompts)
 *
 * The attack payload is served by a local HTTP server (same pattern as
 * BrowserTarget). The agent navigates to the served URL via one of three
 * driver modes:
 *
 *   - `runAgent` callback — caller drives Playwright directly, returns
 *     when the agent is done. Most flexible, used programmatically.
 *
 *   - `agentEndpoint` HTTP URL — Adversary POSTs the attack URL to the
 *     user's agent endpoint; the endpoint is expected to fetch + reason
 *     about the URL and return its response.
 *
 *   - `executable` path — Adversary spawns the user's CLI agent with
 *     env vars ATTACK_URL and PLAYWRIGHT_WS_ENDPOINT set, waits for it
 *     to exit.
 *
 * Playwright is an optional peer dependency — installed via
 *   `npm install playwright && npx playwright install chromium`
 *
 * If not installed, instantiation throws with a clear red message in CLI.
 */

import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { spawn } from 'node:child_process';
import type { Attack, Target, TargetResponse } from '../types.js';

// Playwright types are loaded only when the dynamic import succeeds.
// We type these loosely as `any` to avoid making playwright a hard dep at
// compile time.
type PWBrowser = any;
type PWContext = any;
type PWPage = any;

// ─── Observation record types ───────────────────────────────────

interface NetworkRecord {
  method: string;
  url: string;
  resourceType: string;
  ts: number;
}

interface FormSubmissionRecord {
  action: string;
  method: string;
  fields: Record<string, string>;
  ts: number;
}

interface DomMutationRecord {
  type: string;
  target: string;
  added?: string[];
  attribute?: { name: string; value: string };
  ts: number;
}

interface ConsoleRecord {
  type: string;
  text: string;
  ts: number;
}

// ─── Options ────────────────────────────────────────────────────

export interface PlaywrightTargetOptions {
  /** One of: a runAgent callback that drives Playwright directly */
  runAgent?: (page: PWPage, attack: Attack, attackUrl: string) => Promise<void>;

  /** Or: HTTP endpoint URL that accepts POST { url: attackUrl } */
  agentEndpoint?: string;

  /** Or: an executable to spawn with env { ATTACK_URL, PLAYWRIGHT_WS_ENDPOINT } */
  executable?: string;
  /** Args passed to the executable */
  executableArgs?: string[];

  /** Playwright browser type (default: chromium) */
  browserType?: 'chromium' | 'firefox' | 'webkit';

  /** Headless mode (default: true) */
  headless?: boolean;

  /** Max wait per attack for observable activity (default: 5000ms) */
  observeTimeoutMs?: number;

  /** Local server port for serving attack pages (default: random) */
  port?: number;
}

// ─── PlaywrightTarget ───────────────────────────────────────────

export class PlaywrightTarget implements Target {
  kind = 'playwright' as const;
  identifier: string;

  private opts: PlaywrightTargetOptions;
  private playwright: any = null;
  private browser: PWBrowser | null = null;
  private context: PWContext | null = null;
  private page: PWPage | null = null;
  private server: Server | null = null;
  private baseUrl = '';
  private currentPayload = '';

  // per-attack observation buffers (reset between executes)
  private networkRecords: NetworkRecord[] = [];
  private formSubmissions: FormSubmissionRecord[] = [];
  private domMutations: DomMutationRecord[] = [];
  private consoleRecords: ConsoleRecord[] = [];

  constructor(opts: PlaywrightTargetOptions = {}) {
    this.opts = {
      browserType: 'chromium',
      headless: true,
      observeTimeoutMs: 5000,
      ...opts,
    };
    this.identifier = `playwright:${this.opts.browserType}`;
  }

  async setup(): Promise<void> {
    // ── 1. Try to import Playwright dynamically ────────────────
    try {
      this.playwright = await import('playwright');
    } catch (err) {
      throw new Error(
        '[PlaywrightTarget] playwright is not installed. ' +
          'Install it as a peer dependency:\n\n' +
          '    npm install playwright\n' +
          '    npx playwright install ' + (this.opts.browserType || 'chromium') + '\n',
      );
    }

    // ── 2. Launch the browser ──────────────────────────────────
    const launcher = this.playwright[this.opts.browserType!];
    if (!launcher) {
      throw new Error(`[PlaywrightTarget] unknown browserType: ${this.opts.browserType}`);
    }
    this.browser = await launcher.launch({ headless: this.opts.headless });
    this.context = await this.browser.newContext();

    // ── 3. Inject MutationObserver into every page ─────────────
    await this.context.addInitScript(this.buildMutationObserverScript());

    // ── 4. Open the page that the agent will be told to navigate to ─
    this.page = await this.context.newPage();

    // ── 5. Set up event listeners (always-on, results buffered) ─
    this.page.on('request', (req: any) => {
      this.networkRecords.push({
        method: req.method(),
        url: req.url(),
        resourceType: req.resourceType(),
        ts: Date.now(),
      });
    });

    this.page.on('console', (msg: any) => {
      const text = msg.text();
      // MutationObserver posts mutations via console.log with a magic prefix
      if (text.startsWith('__ADV_MUT__:')) {
        try {
          const parsed = JSON.parse(text.slice('__ADV_MUT__:'.length));
          this.domMutations.push({ ...parsed, ts: Date.now() });
        } catch {
          // ignore parse errors — keep the raw console msg too
          this.consoleRecords.push({ type: msg.type(), text, ts: Date.now() });
        }
      } else {
        this.consoleRecords.push({ type: msg.type(), text, ts: Date.now() });
      }
    });

    this.page.on('framenavigated', (frame: any) => {
      // detect form-induced navigations (POST or query-string) as submissions
      const url = frame.url();
      if (url && (url.includes('?') || url.includes('#'))) {
        // candidate — caller may also intercept form submit events directly
      }
    });

    // Intercept form submissions via DOM event hook in the init script

    // ── 6. Spin up the local HTTP server that serves attack payloads ─
    this.server = createServer((req, res) => {
      const isHtml = req.url?.endsWith('.html') || req.url === '/' || req.url === '/page';
      res.setHeader('Content-Type', isHtml ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.statusCode = 200;
      res.end(this.currentPayload);
    });

    await new Promise<void>((resolve) => {
      this.server!.listen(this.opts.port ?? 0, '127.0.0.1', () => resolve());
    });

    const addr = this.server!.address() as AddressInfo;
    this.baseUrl = `http://127.0.0.1:${addr.port}`;
    this.identifier = `playwright:${this.opts.browserType}:${this.baseUrl}`;
  }

  async teardown(): Promise<void> {
    if (this.page) await this.page.close().catch(() => {});
    if (this.context) await this.context.close().catch(() => {});
    if (this.browser) await this.browser.close().catch(() => {});
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
    this.browser = null;
    this.context = null;
    this.page = null;
    this.server = null;
  }

  async execute(attack: Attack): Promise<TargetResponse> {
    if (!this.page) {
      throw new Error('[PlaywrightTarget] execute() called before setup()');
    }

    // Reset per-attack observation buffers
    this.networkRecords = [];
    this.formSubmissions = [];
    this.domMutations = [];
    this.consoleRecords = [];

    // Render the attack payload (string or function)
    const payload = typeof attack.payload === 'function' ? attack.payload() : attack.payload;
    this.currentPayload = payload;
    const attackUrl = `${this.baseUrl}/${encodeURIComponent(attack.id)}.html`;

    // Drive the agent through one of three modes
    let textResponse = '';

    if (this.opts.runAgent) {
      // Mode A: runAgent callback
      try {
        await this.opts.runAgent(this.page, attack, attackUrl);
      } catch (err) {
        textResponse = `(runAgent error: ${(err as Error).message})`;
      }
    } else if (this.opts.agentEndpoint) {
      // Mode B: POST to agentEndpoint
      try {
        const res = await fetch(this.opts.agentEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: attackUrl, attackId: attack.id }),
        });
        textResponse = await res.text();
      } catch (err) {
        textResponse = `(agentEndpoint error: ${(err as Error).message})`;
      }
    } else if (this.opts.executable) {
      // Mode C: spawn executable with env
      try {
        const child = spawn(this.opts.executable, this.opts.executableArgs || [], {
          env: { ...process.env, ATTACK_URL: attackUrl, ATTACK_ID: attack.id },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        const chunks: Buffer[] = [];
        child.stdout.on('data', (c) => chunks.push(c));
        child.stderr.on('data', (c) => chunks.push(c));
        await new Promise<void>((resolve) => {
          child.on('exit', () => resolve());
          setTimeout(() => {
            child.kill();
            resolve();
          }, this.opts.observeTimeoutMs!);
        });
        textResponse = Buffer.concat(chunks).toString('utf-8');
      } catch (err) {
        textResponse = `(executable error: ${(err as Error).message})`;
      }
    } else {
      // No driver mode — navigate the page directly (browser observer only)
      try {
        await this.page.goto(attackUrl, { timeout: this.opts.observeTimeoutMs });
        await this.page.waitForLoadState('networkidle', { timeout: 2000 }).catch(() => {});
        textResponse = (await this.page.content()).slice(0, 2000);
      } catch (err) {
        textResponse = `(navigation error: ${(err as Error).message})`;
      }
    }

    // Allow async post-navigation activity to settle
    await this.page
      .waitForLoadState('networkidle', { timeout: 2000 })
      .catch(() => {});

    // Synthesize "tool calls" from observed network requests so the
    // orchestrator's classifier can flag breaches uniformly.
    const synthesizedToolCalls = this.synthesizeToolCalls();

    // Build a unified text blob from all observable channels — the
    // orchestrator's detection patterns run against this.
    const observedText = this.buildObservedText(textResponse);

    return {
      text: observedText,
      toolCalls: synthesizedToolCalls,
      turns: 1,
      metadata: {
        mode: this.driverMode(),
        networkRequests: this.networkRecords,
        formSubmissions: this.formSubmissions,
        domMutations: this.domMutations,
        consoleMessages: this.consoleRecords,
        agentText: textResponse,
      },
    };
  }

  private driverMode(): string {
    if (this.opts.runAgent) return 'callback';
    if (this.opts.agentEndpoint) return 'http';
    if (this.opts.executable) return 'spawn';
    return 'navigate-only';
  }

  /**
   * Construct the observation text blob the orchestrator's detection
   * regexes run against. Includes the agent's verbal output PLUS all
   * observed browser-side activity flattened to strings.
   */
  private buildObservedText(agentText: string): string {
    const parts: string[] = [agentText];

    // Network: include the URL — most detection patterns look for
    // exfil URLs (attacker.example.com, collect.example.com, etc.)
    for (const n of this.networkRecords) {
      // Exclude requests back to our own attack-serving origin
      if (n.url.startsWith(this.baseUrl)) continue;
      parts.push(`[network] ${n.method} ${n.url}`);
    }

    // Forms: action URLs + field names
    for (const f of this.formSubmissions) {
      parts.push(`[form] ${f.method} ${f.action} ${Object.keys(f.fields).join(',')}`);
    }

    // DOM mutations: serialize key fields
    for (const m of this.domMutations) {
      const bits = [m.type, m.target];
      if (m.attribute) bits.push(`${m.attribute.name}=${m.attribute.value}`);
      if (m.added?.length) bits.push(m.added.join(','));
      parts.push(`[dom] ${bits.join(' ')}`);
    }

    // Console: include verbatim
    for (const c of this.consoleRecords) {
      parts.push(`[console:${c.type}] ${c.text}`);
    }

    return parts.join('\n');
  }

  /**
   * Map observed network requests + form submissions into synthetic
   * tool-call records so the orchestrator's HOSTILE_TOOL_NAMES check
   * fires uniformly across all targets.
   */
  private synthesizeToolCalls(): Array<{ name: string; arguments: Record<string, unknown> }> {
    const calls: Array<{ name: string; arguments: Record<string, unknown> }> = [];

    for (const n of this.networkRecords) {
      if (n.url.startsWith(this.baseUrl)) continue;  // skip our own server
      // POST/PUT/DELETE with off-origin URLs map to http_request
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(n.method)) {
        calls.push({
          name: 'http_request',
          arguments: { method: n.method, url: n.url },
        });
      } else if (this.looksLikeExfil(n.url)) {
        calls.push({
          name: 'http_request',
          arguments: { method: n.method, url: n.url },
        });
      }
    }

    for (const f of this.formSubmissions) {
      // Any form submission off our own origin is a tool call
      if (!f.action.startsWith(this.baseUrl)) {
        calls.push({
          name: f.action.includes('email') ? 'send_email' : 'http_request',
          arguments: { method: f.method, url: f.action, fields: f.fields },
        });
      }
    }

    return calls;
  }

  private looksLikeExfil(url: string): boolean {
    return /attacker|collect|exfil|evil|malicious|track|beacon/i.test(url);
  }

  /**
   * The MutationObserver script injected into every page. Posts
   * mutations back to the test runner via console.log with a magic
   * prefix that our page.on('console') listener strips and parses.
   */
  private buildMutationObserverScript(): string {
    return `
      (function() {
        if (window.__advObserverInstalled) return;
        window.__advObserverInstalled = true;

        const post = (data) => {
          try {
            console.log('__ADV_MUT__:' + JSON.stringify(data));
          } catch (e) {}
        };

        // 1. DOM mutation observer
        const observer = new MutationObserver((mutations) => {
          for (const m of mutations) {
            const record = {
              type: m.type,
              target: m.target && m.target.nodeName ? m.target.nodeName : 'unknown',
            };
            if (m.type === 'attributes' && m.attributeName) {
              const val = m.target.getAttribute && m.target.getAttribute(m.attributeName);
              record.attribute = { name: m.attributeName, value: String(val).slice(0, 200) };
            }
            if (m.type === 'childList' && m.addedNodes.length) {
              record.added = Array.from(m.addedNodes)
                .map((n) => n.nodeName + (n.textContent ? ':' + n.textContent.slice(0, 100) : ''))
                .slice(0, 5);
            }
            post(record);
          }
        });

        const startObserver = () => {
          observer.observe(document.documentElement || document, {
            childList: true,
            subtree: true,
            attributes: true,
            characterData: false,
          });
        };

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', startObserver);
        } else {
          startObserver();
        }

        // 2. Form submission interception
        document.addEventListener('submit', (e) => {
          const f = e.target;
          if (!f || f.tagName !== 'FORM') return;
          const fields = {};
          for (const input of f.querySelectorAll('input, textarea, select')) {
            if (input.name) fields[input.name] = String(input.value || '').slice(0, 200);
          }
          post({
            type: 'form_submit',
            target: 'FORM',
            attribute: { name: 'action', value: f.action || '' },
            added: [f.method || 'GET', JSON.stringify(fields).slice(0, 500)],
          });
        }, true);

        // 3. localStorage / sessionStorage write hook (OTP exfil pattern)
        try {
          const origSetItem = Storage.prototype.setItem;
          Storage.prototype.setItem = function(k, v) {
            post({
              type: 'storage_set',
              target: this === window.localStorage ? 'localStorage' : 'sessionStorage',
              attribute: { name: k, value: String(v).slice(0, 200) },
            });
            return origSetItem.apply(this, arguments);
          };
        } catch (e) {}
      })();
    `;
  }
}
