/**
 * Vault lifecycle. Before 0.2.0, sealVault() zeroed the key store's own copy
 * of the vault key, so a vault could never be reopened after its first seal.
 */
import { describe, expect, it } from 'vitest';
import { createStorage } from '../src/storage/index.js';
import { VaultManager, keyStore } from '../src/vault/index.js';

describe('VaultManager', () => {
  it('reopens a sealed vault and returns what was stored', async () => {
    if (!keyStore.isInitialized()) keyStore.initialize('vault-lifecycle-test-passphrase');
    const vm = new VaultManager(createStorage('memory'));
    const v = await vm.createVault({ agent_id: 'a', name: 'v', access_policy: {} });

    await vm.openVault(v.id, 'a');
    await vm.storeCredential(v.id, 'a', { name: 'db', type: 'password', value: 's3cret' });
    await vm.sealVault(v.id, 'a');

    for (let i = 0; i < 3; i++) {
      await vm.openVault(v.id, 'a');
      expect(await vm.retrieveCredential(v.id, 'a', 'db')).toBe('s3cret');
      await vm.sealVault(v.id, 'a');
    }
  });
});
