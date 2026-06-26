/**
 * Browser target adapter.
 *
 * Uses Playwright to drive a browser agent against attack payloads served
 * by a local HTTP server. The browser agent is expected to navigate to
 * the URL we provide; we observe what tools it calls and what it returns.
 *
 * For v0.1.0 this target is built around a wrapper: the user provides a
 * `runAgent: (url: string) => Promise<TargetResponse>` callback that drives
 * their actual browser agent (Playwright/Puppeteer/Stagehand-based) against
 * the URL we generate. This keeps Adversary agnostic to which browser
 * framework the agent uses.
 */

import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import type { Attack, Target, TargetResponse } from '../types.js';

export interface BrowserTargetOptions {
  /**
   * Driver callback. Given a URL serving the attack page, invoke the user's
   * browser agent against it and return what the agent did/said.
   */
  runAgent: (url: string, attack: Attack) => Promise<TargetResponse>;
  /** Port to bind the local server on. Default: 0 (random). */
  port?: number;
  /** Host to bind on. Default: 127.0.0.1. */
  host?: string;
}

export class BrowserTarget implements Target {
  kind = 'browser' as const;
  identifier: string;
  private opts: BrowserTargetOptions;
  private server: Server | null = null;
  private baseUrl = '';
  private currentPayload = '';

  constructor(opts: BrowserTargetOptions) {
    this.opts = opts;
    this.identifier = `browser:http://${opts.host || '127.0.0.1'}:${opts.port || '?'}`;
  }

  async setup(): Promise<void> {
    this.server = createServer((req, res) => {
      // Default content-type based on path
      const isHtml = req.url?.endsWith('.html') || req.url === '/' || req.url === '/page';
      res.setHeader('Content-Type', isHtml ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.statusCode = 200;
      res.end(this.currentPayload);
    });

    await new Promise<void>((resolve) => {
      this.server!.listen(this.opts.port ?? 0, this.opts.host ?? '127.0.0.1', () => resolve());
    });

    const addr = this.server!.address() as AddressInfo;
    this.baseUrl = `http://${this.opts.host ?? '127.0.0.1'}:${addr.port}`;
    this.identifier = `browser:${this.baseUrl}`;
  }

  async teardown(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }

  async execute(attack: Attack): Promise<TargetResponse> {
    if (!this.server) {
      throw new Error('BrowserTarget.execute called before setup()');
    }

    // Render the payload (string or function)
    const payload = typeof attack.payload === 'function' ? attack.payload() : attack.payload;
    this.currentPayload = payload;

    // Build URL — include the attack ID in the path for log correlation
    const url = `${this.baseUrl}/${encodeURIComponent(attack.id)}.html`;

    return this.opts.runAgent(url, attack);
  }
}
