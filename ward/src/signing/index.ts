/**
 * @weave_protocol/ward/signing: signed WARD.md policies (Ward 0.3.8, Node only).
 *
 * A security team signs WARD.md once; every machine that enforces it can
 * then refuse a copy that was edited or signed by someone else. The
 * signature is one HTML comment at the end of the file (invisible when the
 * markdown renders):
 *
 *   <!-- ward-signature v1 keyId=… publicKey=… signedAt=… sig=… -->
 *
 * It signs the SHA-256 of the rest of the file, with line endings
 * normalized to \n and trailing whitespace removed, using Ed25519.
 *
 * What a host trusts can't come from the file itself (whoever edits the file
 * could edit that too), so it comes from outside:
 *
 *   WEAVE_POLICY_TRUSTED_KEYS        comma-separated base64 public keys, or
 *   WEAVE_POLICY_TRUSTED_KEYS_FILE   a file of them, one per line
 *                                    (default ~/.weave/trusted-policy-keys)
 *
 * With trusted keys configured, a policy must carry a valid signature from
 * one of them. Without, unsigned policies are accepted as before, but a
 * signed policy that no longer matches its signature is still refused:
 * someone changed it after it was signed.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { WardPolicy } from "../types.js";

const SIG_LINE = /\n?[ \t]*<!--\s*ward-signature\s+v1\s+([^>]*?)\s*-->\s*$/;

export interface PolicySignature {
  keyId: string;
  publicKey: string;
  signedAt: string;
  sig: string;
}

export interface PolicyCheck {
  ok: boolean;
  /** "unsigned" | "valid" | "tampered" | "untrusted" | "invalid" */
  status: "unsigned" | "valid" | "tampered" | "untrusted" | "invalid";
  reason: string;
  signature?: PolicySignature;
}

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

/** The text a signature covers: the file without its signature line, normalized. */
export function signedContent(source: string): string {
  return source.replace(SIG_LINE, "").replace(/\r\n?/g, "\n").replace(/\s+$/, "") + "\n";
}

/** The signature at the end of a WARD.md, if there is one. */
export function readSignature(source: string): PolicySignature | undefined {
  const m = SIG_LINE.exec(source.replace(/\r\n?/g, "\n"));
  if (!m) return undefined;
  const fields = Object.fromEntries([...m[1].matchAll(/(\w+)=(\S+)/g)].map((f) => [f[1], f[2]]));
  if (!fields.keyId || !fields.publicKey || !fields.sig) return undefined;
  return { keyId: fields.keyId, publicKey: fields.publicKey, signedAt: fields.signedAt ?? "", sig: fields.sig };
}

const keyIdOf = (publicKeyB64: string) => sha256(Buffer.from(publicKeyB64, "base64")).slice(0, 16);

// ─────────────────────────────────────────────────────────
// Keys
// ─────────────────────────────────────────────────────────

export function policyKeyPath(): string {
  return process.env.WEAVE_POLICY_KEY_FILE ?? join(homedir(), ".weave", "keys", "ward-policy.pem");
}

/** Load a policy-signing key, creating one (0600) if none exists. */
export function loadPolicySigningKey(path = policyKeyPath()): { privateKey: KeyObject; publicKeyB64: string; keyId: string } {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
  }
  const privateKey = createPrivateKey(readFileSync(path));
  const publicKeyB64 = createPublicKey(privateKey).export({ type: "spki", format: "der" }).toString("base64");
  return { privateKey, publicKeyB64, keyId: keyIdOf(publicKeyB64) };
}

/** Sign a WARD.md text: returns it with (a fresh) signature line at the end. */
export function signPolicySource(source: string, key = loadPolicySigningKey()): string {
  const content = signedContent(source);
  const digest = sha256(content);
  const sig = sign(null, Buffer.from(`ward-policy/v1:${digest}`), key.privateKey).toString("base64");
  const signedAt = new Date().toISOString();
  return `${content}\n<!-- ward-signature v1 keyId=${key.keyId} publicKey=${key.publicKeyB64} signedAt=${signedAt} sig=${sig} -->\n`;
}

// ─────────────────────────────────────────────────────────
// Trust
// ─────────────────────────────────────────────────────────

export function trustedKeysPath(): string {
  return process.env.WEAVE_POLICY_TRUSTED_KEYS_FILE ?? join(homedir(), ".weave", "trusted-policy-keys");
}

/** Public keys this host trusts to sign policies (base64 SPKI). Empty: no trust list. */
export function trustedPolicyKeys(): string[] {
  const keys: string[] = [];
  for (const k of (process.env.WEAVE_POLICY_TRUSTED_KEYS ?? "").split(",")) if (k.trim()) keys.push(k.trim());
  try {
    for (const line of readFileSync(trustedKeysPath(), "utf8").split("\n")) {
      const k = line.replace(/#.*/, "").trim();
      if (k) keys.push(k);
    }
  } catch {
    // No trust file
  }
  return keys;
}

/**
 * Check a WARD.md text's signature against this host's trust list (or the
 * given keys). `ok: false` means the policy must not be enforced as written.
 */
export function checkPolicySignature(source: string, trusted = trustedPolicyKeys()): PolicyCheck {
  const signature = readSignature(source);
  if (!signature) {
    return trusted.length
      ? { ok: false, status: "unsigned", reason: "WARD.md is not signed, and this machine only accepts policies signed by a trusted key" }
      : { ok: true, status: "unsigned", reason: "WARD.md is not signed (no trusted keys configured)" };
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: Buffer.from(signature.publicKey, "base64"), format: "der", type: "spki" });
    if (keyIdOf(signature.publicKey) !== signature.keyId) throw new Error("keyId mismatch");
  } catch {
    return { ok: false, status: "invalid", reason: "WARD.md's signature line is malformed", signature };
  }
  const digest = sha256(signedContent(source));
  let valid = false;
  try { valid = verify(null, Buffer.from(`ward-policy/v1:${digest}`), key, Buffer.from(signature.sig, "base64")); } catch { /* invalid */ }
  if (!valid) return { ok: false, status: "tampered", reason: `WARD.md was changed after it was signed (key ${signature.keyId})`, signature };
  if (trusted.length && !trusted.includes(signature.publicKey)) {
    return { ok: false, status: "untrusted", reason: `WARD.md is signed by key ${signature.keyId}, which this machine doesn't trust`, signature };
  }
  return { ok: true, status: "valid", reason: `WARD.md signed by key ${signature.keyId}${trusted.length ? " (trusted)" : ""}`, signature };
}

const cache = new Map<string, PolicyCheck>();

/** checkPolicySignature for a parsed policy, cached per text and trust list. */
export function checkPolicy(policy: WardPolicy): PolicyCheck {
  const source = policy.source;
  if (source === undefined) return { ok: true, status: "unsigned", reason: "Policy has no source text (built in code)" };
  const trusted = trustedPolicyKeys();
  const key = sha256(`${trusted.join(",")}\0${source}`);
  let result = cache.get(key);
  if (!result) {
    result = checkPolicySignature(source, trusted);
    if (cache.size > 64) cache.clear();
    cache.set(key, result);
  }
  return result;
}
