/**
 * Shared test fixtures for Mund.
 */

import { DEFAULT_CONFIG } from '../src/constants.js';
import type { MundConfig, SecurityEvent } from '../src/types.js';

export function makeConfig(overrides: Partial<MundConfig> = {}): MundConfig {
  return { ...DEFAULT_CONFIG, notifications: {}, ...overrides };
}

export function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'evt-1',
    timestamp: new Date('2026-01-01T00:00:00Z'),
    rule_id: 'test_rule',
    rule_name: 'Test Rule',
    severity: 'high',
    type: 'secret',
    action_taken: 'alert',
    content_snippet: 'AKIA****',
    full_content_hash: 'deadbeef',
    context: {},
    acknowledged: false,
    ...overrides,
  };
}

type Handler = (params: any) => Promise<any>;

/**
 * Minimal stand-in for McpServer that captures tool handlers so they can be
 * invoked directly, without a transport.
 */
export class FakeMcpServer {
  handlers = new Map<string, Handler>();

  registerTool(name: string, _def: unknown, handler: Handler): void {
    this.handlers.set(name, handler);
  }

  tool(name: string, ...rest: unknown[]): void {
    this.handlers.set(name, rest[rest.length - 1] as Handler);
  }

  async call(name: string, params: Record<string, unknown>): Promise<any> {
    const handler = this.handlers.get(name);
    if (!handler) throw new Error(`Tool not registered: ${name}`);
    return handler(params);
  }
}
