/**
 * @weave_protocol/ward/receipts: signed, hash-chained decision receipts
 * (Ward 0.3.7, Node only).
 *
 * Every allow, deny and approval decision becomes one line in an append-only
 * log. Each receipt carries the previous receipt's hash and its own SHA-256
 * hash, signed with Ed25519, so editing, deleting or reordering any receipt
 * breaks verification, and anyone with the public key can check the log
 * offline. Receipts hold the decision and its context, never the call's
 * arguments: those appear only as a keyed digest (HMAC-SHA256 under a key
 * derived from the signing key), so the log can't be used to guess short
 * secrets, while the key holder can still prove which arguments were decided.
 *
 * A chain can't show that its newest receipts were cut off, so the head can
 * be committed elsewhere as a signed checkpoint (Ward 0.3.9): keep checkpoints
 * off the machine, or anchor them on-chain with Dōmere, and verification then
 * catches a log that was truncated or rewritten before the checkpoint.
 *
 *   log:  $WEAVE_RECEIPT_DIR (default ~/.weave/receipts)/<agent>.jsonl   0600
 *   key:  $WEAVE_RECEIPT_KEY_FILE (default ~/.weave/keys/ward-receipts.pem)  0600
 *
 * On when WARD.md's Verification section says `required: true` (frequency
 * every_action, or unset), or WEAVE_RECEIPTS=1; WEAVE_RECEIPTS=0 turns it off.
 */

import {
  createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify,
  type KeyObject,
} from "node:crypto";
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, rmSync, statSync, writeFileSync, appendFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { WardPolicy } from "../types.js";
import type { Decision } from "../enforcer/index.js";

const SLEEP = new Int32Array(new SharedArrayBuffer(4));

// ─────────────────────────────────────────────────────────
// Canonical JSON and hashing
// ─────────────────────────────────────────────────────────

/** JSON with object keys sorted at every level, so equal values hash equally. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

/** Digest of a parsed policy (its rules, not its formatting). */
export function policyDigest(policy: WardPolicy): string {
  const { raw: _raw, ...rules } = policy;
  return `sha256:${sha256(canonicalJson(rules))}`;
}

// ─────────────────────────────────────────────────────────
// Keys
// ─────────────────────────────────────────────────────────

export interface ReceiptKeys {
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** Base64 SPKI DER of the public key */
  publicKeyB64: string;
  /** First 16 hex chars of the public key's SHA-256 */
  keyId: string;
  /** HMAC key for argument digests, derived from the private key */
  argsKey: Buffer;
}

export function receiptKeyPath(): string {
  return process.env.WEAVE_RECEIPT_KEY_FILE ?? join(homedir(), ".weave", "keys", "ward-receipts.pem");
}

/** Load the signing key, creating one (0600) on first use. */
export function loadReceiptKeys(path = receiptKeyPath()): ReceiptKeys {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync("ed25519");
    try {
      writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
    } catch {
      // Another process created it first; use theirs
    }
  }
  const privateKey = createPrivateKey(readFileSync(path));
  return keysFrom(privateKey);
}

function keysFrom(privateKey: KeyObject): ReceiptKeys {
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ type: "spki", format: "der" });
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    privateKey,
    publicKey,
    publicKeyB64: spki.toString("base64"),
    keyId: sha256(spki).slice(0, 16),
    argsKey: createHash("sha256").update("ward-receipts/args/v1").update(pkcs8).digest(),
  };
}

/** HMAC digest of a call's arguments; only the key holder can recompute it. */
export function argsDigest(args: unknown, keys: ReceiptKeys): string {
  return `hmac-sha256:${createHmac("sha256", keys.argsKey).update(canonicalJson(args ?? {})).digest("hex")}`;
}

// ─────────────────────────────────────────────────────────
// Log
// ─────────────────────────────────────────────────────────

export interface ReceiptHeader {
  type: "header";
  v: 1;
  agent: string;
  publicKey: string;
  keyId: string;
  created: string;
  /** Hash of the last receipt before this header (a key change mid-log) */
  prev?: string;
}

export interface Receipt {
  type: "receipt";
  v: 1;
  seq: number;
  at: string;
  agent: string;
  session?: string;
  surface?: string;
  tool: string;
  capability: string;
  decision: Decision;
  reasons: string[];
  argsDigest: string;
  policyDigest: string;
  keyId: string;
  prev: string;
  hash: string;
  sig: string;
}

export interface DecisionToRecord {
  agent: string;
  session?: string;
  surface?: string;
  tool: string;
  capability: string;
  decision: Decision;
  reasons: string[];
  args: unknown;
  policy: WardPolicy;
}

export function receiptDir(): string {
  return process.env.WEAVE_RECEIPT_DIR ?? join(homedir(), ".weave", "receipts");
}

const fileName = (agent: string) => `${(agent || "default").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "default"}.jsonl`;

/** Where an agent's receipts are written. */
export function receiptLogPath(agent: string, dir = receiptDir()): string {
  return join(dir, fileName(agent));
}

/** Are receipts on for this policy? */
export function receiptsEnabled(policy: WardPolicy): boolean {
  const env = process.env.WEAVE_RECEIPTS;
  if (env === "0" || env === "false") return false;
  if (env === "1" || env === "true") return true;
  const v = policy.verification;
  return !!v?.required && (!v.frequency || v.frequency === "every_action");
}

// A reason ends with "(subject)" naming the argument it checked; that can hold
// an argument's value, so receipts keep only the reason itself.
const stripSubject = (reason: string) => reason.replace(/\s*\((?:[^()]|\([^()]*\))*\)\s*$/, "").slice(0, 300);

const ZERO = "sha256:" + "0".repeat(64);

function lastLine(path: string): string | undefined {
  if (!existsSync(path)) return undefined;
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (!size) return undefined;
    const chunk = Math.min(size, 65_536);
    const buf = Buffer.alloc(chunk);
    readSync(fd, buf, 0, chunk, size - chunk);
    const lines = buf.toString("utf8").split("\n").filter((l) => l.trim());
    return lines[lines.length - 1];
  } finally {
    closeSync(fd);
  }
}

function withLock<T>(path: string, fn: () => T): T {
  const lock = `${path}.lock`;
  const deadline = Date.now() + 2_000;
  let locked = false;
  for (;;) {
    try { closeSync(openSync(lock, "wx", 0o600)); locked = true; break; } catch {
      try { if (Date.now() - statSync(lock).mtimeMs > 5_000) { rmSync(lock, { force: true }); continue; } } catch { continue; }
      if (Date.now() > deadline) break;
      Atomics.wait(SLEEP, 0, 0, 10);
    }
  }
  try { return fn(); } finally { if (locked) rmSync(lock, { force: true }); }
}

/** Hash input: every receipt field except hash and sig, canonically ordered. */
const receiptBody = (r: Omit<Receipt, "hash" | "sig"> | Receipt) => {
  const { hash: _h, sig: _s, ...body } = r as Receipt;
  return canonicalJson(body);
};

/**
 * Append a signed receipt for one decision. Returns it, or undefined if it
 * couldn't be written (a receipt never blocks or changes a decision).
 */
export function appendReceipt(d: DecisionToRecord, opts: { dir?: string; keys?: ReceiptKeys } = {}): Receipt | undefined {
  try {
    const keys = opts.keys ?? loadReceiptKeys();
    const dir = opts.dir ?? receiptDir();
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = receiptLogPath(d.agent, dir);
    return withLock(path, () => {
      const last = lastLine(path);
      let prev = ZERO;
      let seq = 0;
      let headerKeyId: string | undefined;
      if (last) {
        const parsed = JSON.parse(last) as Receipt | ReceiptHeader;
        if (parsed.type === "receipt") { prev = parsed.hash; seq = parsed.seq; headerKeyId = parsed.keyId; }
        else { prev = parsed.prev ?? ZERO; headerKeyId = parsed.keyId; seq = lastSeq(path); }
      }
      // A new log, or a new signing key: a header names the key that signs what follows
      if (!last || headerKeyId !== keys.keyId) {
        const header: ReceiptHeader = { type: "header", v: 1, agent: d.agent, publicKey: keys.publicKeyB64, keyId: keys.keyId, created: new Date().toISOString(), ...(last ? { prev } : {}) };
        appendFileSync(path, JSON.stringify(header) + "\n", { mode: 0o600 });
      }
      const body: Omit<Receipt, "hash" | "sig"> = {
        type: "receipt", v: 1, seq: seq + 1, at: new Date().toISOString(), agent: d.agent,
        ...(d.session ? { session: d.session } : {}), ...(d.surface ? { surface: d.surface } : {}),
        tool: d.tool, capability: d.capability, decision: d.decision,
        reasons: d.reasons.map(stripSubject), argsDigest: argsDigest(d.args, keys),
        policyDigest: policyDigest(d.policy), keyId: keys.keyId, prev,
      };
      const hash = `sha256:${sha256(receiptBody(body))}`;
      const receipt: Receipt = { ...body, hash, sig: sign(null, Buffer.from(hash), keys.privateKey).toString("base64") };
      appendFileSync(path, JSON.stringify(receipt) + "\n", { mode: 0o600 });
      try { chmodSync(path, 0o600); } catch { /* best effort */ }
      return receipt;
    });
  } catch (err) {
    if (process.env.WEAVE_RECEIPTS_DEBUG) process.stderr.write(`[ward] receipt not written: ${err instanceof Error ? err.message : String(err)}\n`);
    return undefined;
  }
}

function lastSeq(path: string): number {
  const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.trim());
  for (let i = lines.length - 1; i >= 0; i--) {
    const r = JSON.parse(lines[i]);
    if (r.type === "receipt") return r.seq;
  }
  return 0;
}

// ─────────────────────────────────────────────────────────
// Verification
// ─────────────────────────────────────────────────────────

export interface VerifyResult {
  ok: boolean;
  receipts: number;
  /** Key ids that signed the log, in order */
  keys: string[];
  decisions: Record<string, number>;
  /** Hash of the last receipt. Record it elsewhere (or anchor it with Dōmere): a
   *  chain can't show that receipts after it were removed. */
  head: string;
  /** Checkpoints for this log that matched it */
  checkpoints: number;
  /** Highest receipt a matching checkpoint commits to (0: none) */
  checkpointedSeq: number;
  problems: Array<{ line: number; problem: string }>;
}

/**
 * Verify a receipt log: every hash recomputes, every receipt links to the
 * one before, sequence numbers have no gaps, times never go backwards, and
 * every signature is valid for the key its header names. With `publicKey`
 * (base64 SPKI), every signing key must be that key.
 */
export function verifyReceiptLog(path: string, opts: { publicKey?: string; checkpoints?: ReceiptCheckpoint[] } = {}): VerifyResult {
  const result: VerifyResult = { ok: true, receipts: 0, keys: [], decisions: {}, head: ZERO, checkpoints: 0, checkpointedSeq: 0, problems: [] };
  const fail = (line: number, problem: string) => { result.ok = false; result.problems.push({ line, problem }); };
  let text: string;
  try { text = readFileSync(path, "utf8"); } catch (e) { fail(0, `cannot read: ${(e as Error).message}`); return result; }

  const lines = text.split("\n");
  let key: KeyObject | undefined;
  let keyId: string | undefined;
  let prev = ZERO;
  let seq = 0;
  let lastAt = "";
  let agent: string | undefined;
  const hashBySeq = new Map<number, string>();
  lines.forEach((raw, i) => {
    const n = i + 1;
    if (!raw.trim()) return;
    let r: Receipt | ReceiptHeader;
    try { r = JSON.parse(raw); } catch { fail(n, "not valid JSON"); return; }
    if (r.type === "header") {
      agent ??= r.agent;
      if ((r.prev ?? ZERO) !== prev) fail(n, "header does not continue the chain");
      if (opts.publicKey && r.publicKey !== opts.publicKey) fail(n, `signed by key ${r.keyId}, not the expected key`);
      try {
        key = createPublicKey({ key: Buffer.from(r.publicKey, "base64"), format: "der", type: "spki" });
        keyId = sha256(Buffer.from(r.publicKey, "base64")).slice(0, 16);
        if (keyId !== r.keyId) fail(n, "header keyId does not match its public key");
        result.keys.push(keyId);
      } catch { fail(n, "header public key is invalid"); key = undefined; }
      return;
    }
    if (r.type !== "receipt") { fail(n, `unknown record type ${String((r as { type?: unknown }).type)}`); return; }
    result.receipts++;
    result.decisions[r.decision] = (result.decisions[r.decision] ?? 0) + 1;
    if (!key) fail(n, "receipt before any header");
    if (r.seq !== seq + 1) fail(n, `sequence ${r.seq} after ${seq} (a receipt is missing or out of order)`);
    if (r.prev !== prev) fail(n, "does not link to the previous receipt");
    if (r.at < lastAt) fail(n, "time goes backwards");
    if (r.keyId !== keyId) fail(n, "signed with a key its header doesn't name");
    const expected = `sha256:${sha256(receiptBody(r))}`;
    if (r.hash !== expected) fail(n, "contents don't match its hash (edited)");
    else if (key) {
      let valid = false;
      try { valid = verify(null, Buffer.from(r.hash), key, Buffer.from(r.sig, "base64")); } catch { /* invalid */ }
      if (!valid) fail(n, "signature is invalid");
    }
    prev = r.hash;
    seq = r.seq;
    lastAt = r.at;
    hashBySeq.set(r.seq, r.hash);
  });
  result.head = prev;

  // Checkpoints recorded elsewhere: the log must still contain each one's
  // receipt, unchanged. This is what catches a log cut short.
  for (const cp of opts.checkpoints ?? []) {
    if (cp.agent !== agent) continue;
    const at = `checkpoint of receipt #${cp.seq} (${cp.at})`;
    if (!verifyCheckpoint(cp)) { fail(0, `${at} has an invalid signature`); continue; }
    if (opts.publicKey && cp.publicKey !== opts.publicKey) { fail(0, `${at} is signed by key ${cp.keyId}, not the expected key`); continue; }
    if (!result.keys.includes(cp.keyId)) { fail(0, `${at} is signed by key ${cp.keyId}, which never signed this log`); continue; }
    if (cp.seq > seq) { fail(0, `receipts after #${seq} were removed: the ${at} records #${cp.seq}`); continue; }
    if (hashBySeq.get(cp.seq) !== cp.head) { fail(0, `receipt #${cp.seq} doesn't match the ${at}: the log was rewritten`); continue; }
    result.checkpoints++;
    result.checkpointedSeq = Math.max(result.checkpointedSeq, cp.seq);
  }
  return result;
}

// ─────────────────────────────────────────────────────────
// Checkpoints (0.3.9)
// ─────────────────────────────────────────────────────────

/**
 * A signed statement that an agent's receipt log had reached receipt `seq`
 * with hash `head`. Store it somewhere the log's machine can't rewrite, or
 * anchor it with Dōmere (domere_anchor_receipts), and verifyReceiptLog
 * catches receipts removed or changed up to that point.
 */
export interface ReceiptCheckpoint {
  type: "checkpoint";
  v: 1;
  agent: string;
  seq: number;
  head: string;
  at: string;
  keyId: string;
  publicKey: string;
  sig: string;
}

const checkpointMessage = (cp: Omit<ReceiptCheckpoint, "sig"> | ReceiptCheckpoint) => {
  const { sig: _s, ...body } = cp as ReceiptCheckpoint;
  return Buffer.from(`ward-checkpoint/v1:${sha256(canonicalJson(body))}`);
};

/**
 * Checkpoint the head of a receipt log. Throws if the log doesn't verify or
 * has no receipts: a checkpoint vouches for everything before it.
 */
export function createCheckpoint(path: string, keys = loadReceiptKeys()): ReceiptCheckpoint {
  const v = verifyReceiptLog(path);
  if (!v.ok) throw new Error(`the log doesn't verify (${v.problems[0]?.problem ?? "unknown problem"}), so it can't be checkpointed`);
  if (!v.receipts) throw new Error("the log has no receipts yet");
  if (!v.keys.includes(keys.keyId)) throw new Error(`key ${keys.keyId} never signed this log; checkpoint it with the key that did`);
  let agent = "";
  let seq = 0;
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const r = JSON.parse(line) as Receipt | ReceiptHeader;
    if (r.type === "header" && !agent) agent = r.agent;
    if (r.type === "receipt") seq = r.seq;
  }
  const body: Omit<ReceiptCheckpoint, "sig"> = {
    type: "checkpoint", v: 1, agent, seq, head: v.head, at: new Date().toISOString(), keyId: keys.keyId, publicKey: keys.publicKeyB64,
  };
  return { ...body, sig: sign(null, checkpointMessage(body), keys.privateKey).toString("base64") };
}

/** Is a checkpoint signed by the key it names? (Not whether that key is trusted.) */
export function verifyCheckpoint(cp: ReceiptCheckpoint): boolean {
  try {
    if (cp?.type !== "checkpoint" || cp.v !== 1 || !Number.isInteger(cp.seq) || cp.seq < 1) return false;
    const spki = Buffer.from(cp.publicKey, "base64");
    if (sha256(spki).slice(0, 16) !== cp.keyId) return false;
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    return verify(null, checkpointMessage(cp), key, Buffer.from(cp.sig, "base64"));
  } catch {
    return false;
  }
}

/**
 * Checkpoints from text: JSON lines, a JSON array, or a Dōmere anchor bundle
 * (an object with a `checkpoints` array).
 */
export function readCheckpoints(text: string): ReceiptCheckpoint[] {
  const pick = (v: unknown): ReceiptCheckpoint[] =>
    (Array.isArray(v) ? v : [v]).filter((c): c is ReceiptCheckpoint => !!c && typeof c === "object" && (c as { type?: unknown }).type === "checkpoint");
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && Array.isArray(parsed.checkpoints)) return pick(parsed.checkpoints);
    return pick(parsed);
  } catch {
    const out: ReceiptCheckpoint[] = [];
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try { out.push(...pick(JSON.parse(line))); } catch { /* not a checkpoint */ }
    }
    return out;
  }
}
