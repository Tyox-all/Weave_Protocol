/**
 * The README's code examples, run as written (imports adjusted to src). If a
 * signature changes, this fails and the README gets fixed with it.
 */
import { describe, expect, it } from 'vitest';
import {
  createStorage,
  keyStore,
  VaultManager,
  RedactionEngine,
  CapabilityManager,
  AttestationService,
  ActionType,
} from '../src/index.js';

if (!keyStore.isInitialized()) keyStore.initialize('readme-examples-test-passphrase');

describe('README examples', () => {
  it('quick start: vault', async () => {
    const storage = createStorage('memory');
    const vaults = new VaultManager(storage);

    const vault = await vaults.createVault({ agent_id: 'billing-agent', name: 'api-keys', access_policy: {} });
    await vaults.openVault(vault.id, 'billing-agent');
    await vaults.storeCredential(vault.id, 'billing-agent', { name: 'stripe', type: 'api_key', value: 'sk_test_example' });
    const key = await vaults.retrieveCredential(vault.id, 'billing-agent', 'stripe');
    await vaults.sealVault(vault.id, 'billing-agent');

    expect(key).toBe('sk_test_example');
  });

  it('redaction: tokenize PII', async () => {
    const redactor = new RedactionEngine(createStorage('memory'));
    const { tokenized } = await redactor.tokenizePII('Email jane@example.com about the invoice');
    expect(tokenized).not.toContain('jane@example.com');
    expect(await redactor.deTokenize(tokenized)).toContain('jane@example.com');
  });

  it('capability tokens', async () => {
    const caps = new CapabilityManager(createStorage('memory'));
    const token = await caps.createCapabilityToken({
      agent_id: 'agent-1',
      resource: { type: 'vault', id: 'api-keys' },
      actions: [ActionType.READ],
      delegatable: true,
    });
    const ok = await caps.verifyCapabilityToken(token.id, 'agent-1', { type: 'vault', id: 'api-keys' }, ActionType.READ);
    const denied = await caps.verifyCapabilityToken(token.id, 'agent-1', { type: 'vault', id: 'api-keys' }, ActionType.WRITE);
    const child = await caps.delegateCapability({ parent_token_id: token.id, delegate_to_agent: 'agent-2', justification: 'read-only helper' });

    expect(ok.valid).toBe(true);
    expect(denied.valid).toBe(false);
    expect(child.agent_id).toBe('agent-2');
  });

  it('attestation', async () => {
    const attest = new AttestationService(createStorage('memory'));
    const proof = await attest.attestAction('agent-1', 'api_call', 'Charged invoice 1042', ['stripe:invoices'], { result: 'success' });
    const check = await attest.verify(proof.id);
    expect(check.valid).toBe(true);
  });
});
