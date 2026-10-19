import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerCanaryRugPullTools } from '../../src/tools/canary-rugpull.js';
import { canaries } from '../../src/canary.js';
import { FakeMcpServer } from '../helpers.js';

const parse = (r: any) => JSON.parse(r.content[0].text);

describe('canary + rug-pull MCP tools', () => {
  let server: FakeMcpServer;
  let dir: string;
  beforeEach(() => {
    server = new FakeMcpServer();
    registerCanaryRugPullTools(server as any);
    dir = mkdtempSync(join(tmpdir(), 'mund-tools-'));
    vi.stubEnv('MUND_BASELINE_PATH', join(dir, 'baselines.json'));
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
    for (const c of canaries.list()) canaries.remove(c.token);
  });

  it('creates, lists and removes canaries', async () => {
    const created = parse(await server.call('mund_create_canary', { label: 'bot' }));
    expect(created.how_to_use).toContain(created.token);
    expect(parse(await server.call('mund_list_canaries', {})).canaries).toHaveLength(1);
    expect(parse(await server.call('mund_remove_canary', { token: created.token })).removed).toBe(true);
  });

  it('returns an error for a too-short custom token', async () => {
    expect(parse(await server.call('mund_create_canary', { token: 'short' })).error).toMatch(/at least 12/);
  });

  it('walks baseline -> change -> accept for an MCP server', async () => {
    const m = (d: string) => JSON.stringify({ name: 's', version: '1', tools: [{ name: 't', description: d }] });
    expect(parse(await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: m('Read a note.') })).recommendation).toBe('BASELINE_RECORDED');
    const changed = parse(await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: m('Read a note, newest first.') }));
    expect(changed).toMatchObject({ status: 'changed', recommendation: 'REVIEW_CHANGES', risk_label: 'high' });
    expect(parse(await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: m('Read a note, newest first.'), accept_changes: true })).recommendation).toBe('CHANGES_ACCEPTED');
    expect(parse(await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: m('Read a note, newest first.') })).recommendation).toBe('UNCHANGED');
  });

  it('says DO_NOT_USE when a changed tool gains command execution', async () => {
    const m = (d: string) => JSON.stringify({ name: 's', version: '1', tools: [{ name: 't', description: d }] });
    await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: m('Read a note.') });
    const r = parse(await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: m('Run a shell command on the host.') }));
    expect(r.recommendation).toBe('DO_NOT_USE');
    expect(r.risk_label).toBe('critical');
  });

  it('rejects invalid manifests', async () => {
    expect(parse(await server.call('mund_check_mcp_rugpull', { server_id: 's', manifest: 'not json' })).error).toMatch(/Invalid manifest/);
  });
});
