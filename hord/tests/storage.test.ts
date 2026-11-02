/**
 * Storage: MemoryStorage and SqliteStorage satisfy the same contract, and a
 * SQLite-backed vault survives a restart only with the same master key.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { MemoryStorage } from '../src/storage/memory.js';
import { SqliteStorage } from '../src/storage/sqlite.js';
import type { Attestation, CapabilityToken, IHordStorage, Vault } from '../src/types.js';
import { keyStore } from '../src/vault/encryption.js';

if (!keyStore.isInitialized()) keyStore.initialize('storage-contract-test-passphrase');

const vault = (id: string, agent = 'a'): Vault =>
  ({
    id, agent_id: agent, name: id, sealed: true, version: 1,
    created_at: new Date('2026-01-01T00:00:00.000Z'), updated_at: new Date('2026-01-01T00:00:00.000Z'),
    access_policy: {}, encryption: { algorithm: 'aes-256-gcm', key_id: keyStore.generateKey('encryption').id },
  }) as unknown as Vault;

const backends: Array<[string, () => IHordStorage]> = [
  ['memory', () => new MemoryStorage()],
  ['sqlite', () => new SqliteStorage(':memory:')],
];

describe.each(backends)('%s storage contract', (_name, make) => {
  it('vaults: save, get, list by agent, update, delete', async () => {
    const s = make();
    await s.saveVault(vault('v1'));
    await s.saveVault(vault('v2', 'b'));
    const got = await s.getVault('v1');
    expect(got?.name).toBe('v1');
    expect(got?.created_at).toBeInstanceOf(Date);
    expect((await s.getVaultsByAgent('a')).map((v) => v.id)).toEqual(['v1']);
    await expect(s.updateVault(vault('missing'))).rejects.toThrow(/not found/);
    await s.saveVaultContents('v1', 'ciphertext');
    expect(await s.getVaultContents('v1')).toBe('ciphertext');
    await s.deleteVault('v1');
    expect(await s.getVault('v1')).toBeNull();
    expect(await s.getVaultContents('v1')).toBeNull();
  });

  it('capability tokens: revoke and count uses', async () => {
    const s = make();
    const token = { id: 't1', agent_id: 'a', uses: 0, revoked: false } as unknown as CapabilityToken;
    await s.saveCapabilityToken(token);
    await s.incrementTokenUse('t1');
    await s.incrementTokenUse('t1');
    await s.revokeCapabilityToken('t1');
    const got = await s.getCapabilityToken('t1');
    expect(got?.uses).toBe(2);
    expect(got?.revoked).toBe(true);
    expect((await s.getCapabilityTokensByAgent('a')).length).toBe(1);
  });

  it('attestations: newest first, limit, and chains', async () => {
    const s = make();
    const att = (id: string, t: string, prev?: string) =>
      ({ id, agent_id: 'a', timestamp: new Date(t), previous_attestation_id: prev }) as unknown as Attestation;
    await s.saveAttestation(att('x1', '2026-01-01T00:00:00.000Z'));
    await s.saveAttestation(att('x2', '2026-01-02T00:00:00.000Z', 'x1'));
    await s.saveAttestation(att('x3', '2026-01-03T00:00:00.000Z', 'x2'));
    expect((await s.getAttestationsByAgent('a')).map((a) => a.id)).toEqual(['x3', 'x2', 'x1']);
    expect((await s.getAttestationsByAgent('a', 2)).map((a) => a.id)).toEqual(['x3', 'x2']);
    expect((await s.getAttestationChain('x3')).map((a) => a.id)).toEqual(['x3', 'x2', 'x1']);
  });

  it('token mappings keep original values exactly', async () => {
    const s = make();
    const mapping = { original: '2026-01-01T00:00:00.000Z', type: 'date' } as never;
    await s.saveTokenMapping('tok', mapping);
    expect(await s.getTokenMapping('tok')).toEqual(mapping);
  });

  it('access log: filters, newest first, pagination', async () => {
    const s = make();
    for (let i = 0; i < 5; i++) {
      await s.logAccess({ id: `l${i}`, timestamp: new Date(Date.UTC(2026, 0, i + 1)), agent_id: i % 2 ? 'a' : 'b', action: 'read', resource: `vault:v${i}`, success: true } as never);
    }
    expect((await s.getAccessLog({ agent_id: 'a' })).map((e) => e.id)).toEqual(['l3', 'l1']);
    expect((await s.getAccessLog({ limit: 2 })).map((e) => e.id)).toEqual(['l4', 'l3']);
    expect((await s.getAccessLog({ offset: 4 })).map((e) => e.id)).toEqual(['l0']);
  });
});

// ─── persistence across processes ────────────────────────────

const dir = mkdtempSync(join(tmpdir(), 'hord-sqlite-'));
const dbPath = join(dir, 'hord.sqlite');
const dist = resolve('dist/index.js');
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const runStep = (masterKey: string, code: string) =>
  execFileSync(process.execPath, ['--no-warnings', '--input-type=module', '-e', `
    const h = await import(${JSON.stringify(dist)});
    h.keyStore.initialize(${JSON.stringify(masterKey)});
    const vm = new h.VaultManager(h.createStorage('sqlite', { path: ${JSON.stringify(dbPath)} }));
    ${code}
  `], { encoding: 'utf8' }).trim();

describe('sqlite persistence', () => {
  it('a vault and its secret survive a restart with the same master key', () => {
    const id = runStep('master-one', `
      const v = await vm.createVault({ agent_id: 'a', name: 'kept', access_policy: {} });
      await vm.openVault(v.id, 'a');
      await vm.storeCredential(v.id, 'a', { name: 'db', type: 'password', value: 's3cret' });
      await vm.sealVault(v.id, 'a');
      console.log(v.id);`);
    expect(id).toMatch(/^vault_/);

    expect(runStep('master-one', `
      await vm.openVault('${id}', 'a');
      console.log(await vm.retrieveCredential('${id}', 'a', 'db'));`)).toBe('s3cret');

    expect(() => runStep('master-two', `await vm.openVault('${id}', 'a');`)).toThrow();
  });

  it('the database file is private to the user', () => {
    expect(statSync(dbPath).mode & 0o777).toBe(0o600);
  });

  it('postgres fails loudly instead of silently using memory', async () => {
    const { createStorage } = await import('../src/storage/index.js');
    expect(() => createStorage('postgres')).toThrow(/not implemented/);
  });
});
