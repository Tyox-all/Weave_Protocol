// Ward 0.3.6: the payment guard, Behavioral Limits and spending_limits caps,
// with history kept by @weave_protocol/ward/ledger across hook processes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { parseWard, evaluateToolCall, detectPayment, checkSessionLimits } from '../dist/index.js';
import { evaluateWithLedger, FileLedger } from '../dist/ledger/index.js';

const policy = (extra = '', caps = 'allow:\n  - shell_exec\n  - http_request\ndefault: allow') => parseWard(`---
ward: "1.0"
agent: limits-test
---

## Network

default: allow

## Capabilities

${caps}
${extra}`);

const M = { Bash: { capability: 'shell_exec', commandField: 'command' } };

describe('payment guard', () => {
  const p = policy();
  test('payment tools need approval under a default allow', () => {
    for (const [tool, args] of [['send_payment', { to: 'acct', amount: 50 }], ['stripe_create_payout', {}], ['wallet_send_transaction', { value: '0.1', asset: 'ETH' }], ['transfer', { amount: 10 }], ['purchase_item', { sku: 'x' }]]) {
      const r = evaluateToolCall(p, tool, args);
      assert.equal(r.decision, 'require_approval', tool);
      assert.match(r.reasons[0], /payment guard/);
    }
  });

  test('wallet and payment CLIs in shell commands need approval', () => {
    for (const command of ['cast send 0xabc --value 1ether', 'solana transfer 7xKX 2', 'stripe payouts create --amount 5000']) {
      assert.equal(evaluateToolCall(p, 'Bash', { command }, { mappings: M }).decision, 'require_approval', command);
    }
  });

  test('allowing the capability by name lifts it; default allow and wildcards do not', () => {
    assert.equal(evaluateToolCall(policy('', 'allow:\n  - send_payment\ndefault: deny'), 'send_payment', { amount: 5 }).decision, 'allow');
    assert.equal(evaluateToolCall(policy('', 'allow:\n  - send_*\ndefault: allow'), 'send_payment', { amount: 5 }).decision, 'require_approval');
    assert.equal(evaluateToolCall(policy('', 'allow:\n  - shell_exec\n  - payments\ndefault: deny'), 'Bash', { command: 'cast send 0xabc --value 1ether' }, { mappings: M }).decision, 'allow', "'payments' lifts command payments");
  });

  test('look-alikes are not payments', () => {
    for (const [tool, args] of [['transfer_file', { path: '/tmp/a', dest: '/tmp/b' }], ['send_message', { text: 'hi' }], ['order_by', { field: 'date' }], ['display_price', { sku: 'x' }]]) {
      assert.equal(detectPayment(tool, tool, args), null, tool);
    }
    assert.equal(evaluateToolCall(p, 'Bash', { command: 'git push && npm publish' }, { mappings: M }).decision, 'allow');
  });

  test('amounts: USD known, other currencies stated but not converted', () => {
    assert.deepEqual(detectPayment('send_payment', 'send_payment', { amount_cents: 1250 }), { amountUSD: 12.5, stated: '1250 cents' });
    assert.deepEqual(detectPayment('Bash', 'shell_exec', { command: 'solana transfer x 2' }, 'solana transfer x 2'), { viaCommand: true });
    assert.deepEqual(detectPayment('send_payment', 'send_payment', { amount: '$1,000', currency: 'usd' }), { amountUSD: 1000, stated: '$1,000 USD' });
    assert.equal(detectPayment('send_payment', 'send_payment', { amount: 2, currency: 'ETH' }).amountUSD, undefined);
  });
});

describe('spending_limits parsing', () => {
  test('reads the Witan format', () => {
    const p = policy(`
## Spending Limits

spending_limits:
  - window: day
    budget:
      tool_calls: 100
      tools:
        send_payment:
          max_amount_usd: 500
          max_calls: 3
    on_exceeded: require_approval
  - window: run
    budget:
      tool_calls: 40
    on_exceeded: block
    label: per session
`);
    assert.deepEqual(p.spending, [
      { window: 'day', budget: { tool_calls: 100, tools: { send_payment: { max_amount_usd: 500, max_calls: 3 } } }, onExceeded: 'require_approval' },
      { window: 'run', budget: { tool_calls: 40 }, onExceeded: 'block', label: 'per session' },
    ]);
  });
});

describe('checkSessionLimits', () => {
  const now = Date.parse('2026-11-08T12:00:00Z');
  const ev = (minsAgo, extra = {}) => ({ at: now - minsAgo * 60_000, session: 's1', tool: 'Bash', capability: 'shell_exec', ...extra });
  const call = (extra = {}) => ({ session: 's1', tool: 'Bash', capability: 'shell_exec', ...extra });

  test('Behavioral Limits: tool calls, runtime, external services', () => {
    const p = policy('\n## Behavioral Limits\n\nmaxToolCalls: 3\nmaxRuntimeSeconds: 600\nmaxExternalServices: 2\n');
    assert.deepEqual(checkSessionLimits(p, { events: [ev(1), ev(1)] }, call(), now), []);
    assert.match(checkSessionLimits(p, { events: [ev(1), ev(1), ev(1)] }, call(), now)[0].reason, /Max tool calls/);
    assert.match(checkSessionLimits(p, { events: [], sessionStartedAt: now - 11 * 60_000 }, call(), now)[0].reason, /Max runtime/);
    const hosts = [ev(1, { hosts: ['a.example'] }), ev(1, { hosts: ['b.example'] })];
    assert.equal(checkSessionLimits(p, { events: hosts }, call({ hosts: ['a.example'] }), now).length, 0, 'a known host is fine');
    assert.match(checkSessionLimits(p, { events: hosts }, call({ hosts: ['c.example'] }), now)[0].reason, /external services/);
    assert.equal(checkSessionLimits(p, { events: [ev(1), ev(1), ev(1, { session: 's2' })] }, call(), now).length, 0, 'other sessions do not count');
  });

  test('spending caps: cumulative amounts per window, unknown amounts, actions', () => {
    const p = policy(`
spending_limits:
  - window: day
    budget:
      tools:
        send_payment:
          max_amount_usd: 500
    on_exceeded: block
  - window: hour
    budget:
      tool_calls: 2
    on_exceeded: notify
`);
    const paid = [ev(60, { tool: 'send_payment', capability: 'send_payment', amountUSD: 300, session: 'other' })];
    const pay = (amountUSD) => call({ tool: 'send_payment', capability: 'send_payment', payment: { amountUSD } });
    assert.deepEqual(checkSessionLimits(p, { events: paid }, pay(150), now), []);
    const over = checkSessionLimits(p, { events: paid }, pay(250), now);
    assert.equal(over[0].decision, 'deny');
    assert.match(over[0].reason, /\$550\.00 this day, over the \$500 cap \(\$300\.00 already\)/);
    assert.deepEqual(checkSessionLimits(p, { events: [ev(25 * 60, { tool: 'send_payment', capability: 'send_payment', amountUSD: 499 })] }, pay(450), now), [], 'yesterday is outside the day window');
    assert.equal(checkSessionLimits(p, { events: [] }, call({ tool: 'send_payment', capability: 'send_payment', payment: {} }), now)[0].decision, 'require_approval');
    assert.deepEqual(checkSessionLimits(p, { events: [ev(1), ev(2), ev(3)] }, call(), now), [], 'notify never blocks');
  });
});

describe('ledger across hook processes', () => {
  const p = policy('\n## Behavioral Limits\n\nmaxToolCalls: 3\n');

  test('counts persist between separate ledger instances, per session', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-ledger-'));
    const run = (session) => evaluateWithLedger(p, 'Bash', { command: 'ls' }, { mappings: M, session, dir }).decision;
    assert.deepEqual([run('a'), run('a'), run('a'), run('a'), run('b')], ['allow', 'allow', 'allow', 'deny', 'allow']);
    const file = new FileLedger('limits-test', { dir }).path;
    assert.equal(statSync(file).mode & 0o777, 0o600);
    const data = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(data.events.length, 4, 'denied calls are not recorded');
    assert.ok(!JSON.stringify(data).includes('"ls"'), 'no arguments are stored');
  });

  test('without limits that need history, nothing is written', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-ledger-'));
    evaluateWithLedger(policy(), 'Bash', { command: 'ls' }, { mappings: M, session: 'a', dir });
    assert.throws(() => statSync(new FileLedger('limits-test', { dir }).path));
  });

  test('parallel hook processes do not lose updates', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-ledger-'));
    const script = `
      import { parseWard } from ${JSON.stringify(new URL('../dist/index.js', import.meta.url).href)};
      import { evaluateWithLedger } from ${JSON.stringify(new URL('../dist/ledger/index.js', import.meta.url).href)};
      const p = parseWard('---\\nward: "1.0"\\nagent: race\\n---\\n\\n## Behavioral Limits\\n\\nmaxToolCalls: 1000\\n');
      for (let i = 0; i < 10; i++) evaluateWithLedger(p, 'x', {}, { session: 's', dir: ${JSON.stringify(dir)} });`;
    await Promise.all(Array.from({ length: 6 }, () => new Promise((res, rej) => {
      const c = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: 'inherit' });
      c.on('exit', (code) => (code === 0 ? res() : rej(new Error(`exit ${code}`))));
    })));
    const data = JSON.parse(readFileSync(new FileLedger('race', { dir }).path, 'utf8'));
    assert.equal(data.events.length, 60);
  });
});

// Ward 0.3.12: the ledger lock no longer retries forever when its folder isn't
// writable; it gives up straight away instead of timing the hook out.
describe('unwritable ledger folder', () => {
  test('the lock gives up at once', { skip: process.getuid?.() === 0 && 'root ignores permissions' }, async () => {
    const { mkdirSync, chmodSync } = await import('node:fs');
    const ro = join(mkdtempSync(join(tmpdir(), 'ward-ledger-ro-')), 'ledger');
    mkdirSync(ro, { recursive: true });
    chmodSync(ro, 0o500);
    const script = `
      import { FileLedger } from ${JSON.stringify(new URL('../dist/ledger/index.js', import.meta.url).pathname)};
      const t = Date.now();
      let err = '';
      try { new FileLedger('ro', { dir: ${JSON.stringify(ro)} }).transact(() => ({ result: 1 })); } catch (e) { err = e.code || 'error'; }
      process.stdout.write(JSON.stringify({ ms: Date.now() - t, err }));`;
    try {
      const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 8000 });
      assert.equal(r.signal, null, 'the ledger must not hang');
      const out = JSON.parse(r.stdout);
      assert.ok(out.ms < 1500, `took ${out.ms}ms`);
    } finally {
      chmodSync(ro, 0o700);
    }
  });
});
