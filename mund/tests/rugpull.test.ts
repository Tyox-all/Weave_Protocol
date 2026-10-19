import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BaselineStore, changesToIssues, checkRugPull, diffManifest, fingerprintManifest } from '../src/rugpull.js';
import type { IAnalyzer } from '../src/types.js';

const manifest = (desc: string, extra: object[] = []) => ({
  name: 'notes', version: '1.0.0',
  tools: [{ name: 'read_note', description: desc, inputSchema: { type: 'object', properties: { title: { type: 'string' } } } }, ...extra],
});

describe('checkRugPull with a baseline store', () => {
  let dir: string;
  let store: BaselineStore;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mund-rugpull-'));
    store = new BaselineStore(join(dir, 'baselines.json'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('records a baseline on first check, then reports unchanged', async () => {
    expect((await checkRugPull('srv', manifest('Read a note.'), { store })).status).toBe('baseline_created');
    expect((await checkRugPull('srv', manifest('Read a note.'), { store })).status).toBe('unchanged');
  });

  it('keeps reporting a change until it is accepted', async () => {
    await checkRugPull('srv', manifest('Read a note.'), { store });
    const changed = manifest('Read a note, newest first.');
    expect((await checkRugPull('srv', changed, { store })).status).toBe('changed');
    expect((await checkRugPull('srv', changed, { store })).status).toBe('changed');
    await checkRugPull('srv', changed, { store, acceptChanges: true });
    expect((await checkRugPull('srv', changed, { store })).status).toBe('unchanged');
  });

  it('keeps separate baselines per server', async () => {
    await checkRugPull('a', manifest('Read a note.'), { store });
    expect((await checkRugPull('b', manifest('Something else.'), { store })).status).toBe('baseline_created');
    expect((await checkRugPull('a', manifest('Read a note.'), { store })).status).toBe('unchanged');
  });
});

describe('escalation', () => {
  it('escalates a changed tool to critical when the analyzer flags it', async () => {
    // Stub analyzer: stands in for Mund's MCP analyzer so no attack text is needed here.
    const analyzer: IAnalyzer = {
      name: 'stub', type: 'mcp',
      analyze: async (content) => content.includes('FLAGGED')
        ? [{ rule_id: 'x', rule_name: 'Tool Description Injection', type: 'mcp', severity: 'critical', action: 'block', match: '' }]
        : [],
    };
    const baseline = fingerprintManifest('srv', manifest('Read a note.'));
    const [change] = await diffManifest(baseline, manifest('Read a note. FLAGGED'), analyzer);
    expect(change).toMatchObject({ kind: 'description_changed', severity: 'critical' });
    expect(change.escalated).toContain('Tool Description Injection');
  });

  it('does not escalate a benign rewording', async () => {
    const baseline = fingerprintManifest('srv', manifest('Read a note.'));
    const [change] = await diffManifest(baseline, manifest('Read a saved note by title.'));
    expect(change).toMatchObject({ severity: 'high' });
    expect(change.escalated).toBeUndefined();
  });
});

describe('changesToIssues', () => {
  it('maps changes to blocking/alerting SecurityIssues', () => {
    const issues = changesToIssues({
      serverId: 'srv', status: 'changed',
      changes: [
        { kind: 'description_changed', tool: 'read_note', severity: 'high', detail: 'd' },
        { kind: 'tool_removed', tool: 'old', severity: 'low', detail: 'r' },
      ],
    });
    expect(issues.map(i => [i.rule_id, i.action, i.match])).toEqual([
      ['mcp_rugpull_description_changed', 'block', 'srv:read_note'],
      ['mcp_rugpull_tool_removed', 'alert', 'srv:old'],
    ]);
  });
});
