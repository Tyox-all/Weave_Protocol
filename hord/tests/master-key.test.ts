/**
 * Master key handling. Before 0.2.0, any non-hex master key (including the
 * built-in default) hex-decoded to an empty buffer, so every such install
 * derived the same master key.
 */
import { describe, expect, it } from 'vitest';
import { KeyStore, wrapKey, unwrapKey, generateKey } from '../src/vault/encryption.js';

const masterOf = (k: string | Buffer) => {
  const ks = new KeyStore();
  ks.initialize(k);
  return (ks as unknown as { masterKey: Buffer }).masterKey;
};

describe('KeyStore.initialize', () => {
  it('derives different keys from different passphrases', () => {
    const a = masterOf('my-secure-key');
    const b = masterOf('a-totally-different-secret');
    const c = masterOf('hord-default-master-key-change-in-production-1730000000000');
    expect(a.equals(b)).toBe(false);
    expect(a.equals(c)).toBe(false);
    expect(b.equals(c)).toBe(false);
    expect(a.length).toBe(32);
  });

  it('is deterministic for the same passphrase', () => {
    expect(masterOf('same').equals(masterOf('same'))).toBe(true);
  });

  it('uses 64-hex-char strings and 32-byte buffers as raw keys', () => {
    expect(masterOf('ab'.repeat(32)).toString('hex')).toBe('ab'.repeat(32));
    expect(masterOf(Buffer.alloc(32, 7)).equals(Buffer.alloc(32, 7))).toBe(true);
  });

  it('treats short hex-looking strings as passphrases, not truncated keys', () => {
    expect(masterOf('abcd').equals(masterOf('abce'))).toBe(false);
  });

  it('rejects an empty key', () => {
    expect(() => masterOf('')).toThrow(/empty/);
  });

  it('a key wrapped under one passphrase cannot be unwrapped under another', () => {
    const vaultKey = generateKey();
    const wrapped = wrapKey(vaultKey, masterOf('passphrase-one'));
    expect(unwrapKey(wrapped, masterOf('passphrase-one')).equals(vaultKey)).toBe(true);
    expect(() => unwrapKey(wrapped, masterOf('passphrase-two'))).toThrow();
  });
});
