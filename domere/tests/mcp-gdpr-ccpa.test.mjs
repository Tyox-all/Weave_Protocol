// The domere MCP server serves the GDPR and CCPA tools (before 1.5.0 it only
// served the 12 core tools), driven here through a real MCP client.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

let client;
before(async () => {
  client = new Client({ name: 'test', version: '1' });
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: ['dist/server.js'],
    env: { PATH: process.env.PATH, DOMERE_ORG_NAME: 'Acme Test Co', DOMERE_ORG_EMAIL: 'privacy@acme.test' },
    stderr: 'ignore',
  }));
});
after(() => client?.close());

async function call(name, args = {}) {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content?.[0]?.text ?? '';
  return { isError: !!r.isError, body: JSON.parse(text) };
}
async function ok(name, args) {
  const { isError, body } = await call(name, args);
  assert.equal(isError, false, `${name}: ${JSON.stringify(body)}`);
  assert.notEqual(body.success, false, `${name}: ${JSON.stringify(body)}`);
  return body;
}

test('lists the 14 core tools plus 12 GDPR and 19 CCPA tools, all uniquely named', async () => {
  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.equal(names.length, 45);
  assert.equal(new Set(names).size, 45);
  for (const n of ['domere_create_thread', 'domere_gdpr_record_consent', 'domere_gdpr_verify_chain', 'ccpa_verify_chain']) assert.ok(names.includes(n), n);
});

describe('GDPR', () => {
  test('consent: record, check, withdraw', async () => {
    const c = await ok('domere_gdpr_record_consent', { subject_id: 's1', email: 'ann@example.com', purpose: 'marketing', legal_basis: 'consent', granted: true, source: 'web_form', version: '1' });
    assert.equal((await ok('domere_gdpr_check_consent', { subject_id: 's1', purpose: 'marketing' })).has_valid_consent, true);
    await ok('domere_gdpr_withdraw_consent', { consent_id: c.consent_id, reason: 'user request' });
    assert.equal((await ok('domere_gdpr_check_consent', { subject_id: 's1', purpose: 'marketing' })).has_valid_consent, false);
  });

  test('a DSAR cannot be processed or completed before identity is verified', async () => {
    const d = await ok('domere_gdpr_handle_dsar', { action: 'create', subject_id: 's2', type: 'access' });
    const early = await call('domere_gdpr_handle_dsar', { action: 'complete', dsar_id: d.dsar_id });
    assert.equal(early.isError, true);
    assert.match(JSON.stringify(early.body), /verif/);
    assert.equal((await call('domere_gdpr_handle_dsar', { action: 'process', dsar_id: d.dsar_id, assigned_to: 'dpo' })).isError, true);
    await ok('domere_gdpr_handle_dsar', { action: 'verify', dsar_id: d.dsar_id, verification_method: 'email', assigned_to: 'dpo' });
    await ok('domere_gdpr_handle_dsar', { action: 'process', dsar_id: d.dsar_id, assigned_to: 'dpo' });
    assert.equal((await ok('domere_gdpr_handle_dsar', { action: 'complete', dsar_id: d.dsar_id })).status, 'completed');
    assert.equal((await call('domere_gdpr_handle_dsar', { action: 'complete', dsar_id: d.dsar_id })).isError, true, 'only once');
  });

  test('automated decisions can be looked up by id', async () => {
    const d = await ok('domere_gdpr_automated_decision', { action: 'record', subject_id: 's3', decision_type: 'credit', algorithm: 'v1', input_data: ['income'], outcome: 'denied', significance: 'legal_effect', legal_basis: 'contract' });
    const got = await ok('domere_gdpr_automated_decision', { action: 'get_decision', decision_id: d.decision_id });
    assert.equal(got.decision.id, d.decision_id);
    assert.equal((await ok('domere_gdpr_automated_decision', { action: 'get_decision', decision_id: 'nope' }).catch((e) => e)) instanceof Error, true);
  });

  test('breach, retention, erasure and report', async () => {
    const b = await ok('domere_gdpr_breach_notify', { action: 'report', description: 'Laptop lost', severity: 'high', affected_subjects: 10, affected_categories: ['contact'], cause: 'human_error' });
    await ok('domere_gdpr_breach_notify', { action: 'notify_authority', breach_id: b.breach_id, authority: 'ICO' });
    const p = await ok('domere_gdpr_retention_check', { action: 'create_policy', name: 'Logs', description: 'Delete logs', data_categories: ['contact'], retention_days: 30, legal_basis: 'legitimate_interests', deletion_method: 'hard_delete' });
    await ok('domere_gdpr_retention_check', { action: 'execute_check', policy_id: p.policy_id });
    await ok('domere_gdpr_right_to_erasure', { subject_id: 's1', reason: 'withdrawn', verify_no_legal_hold: true });
    const now = Date.now();
    await ok('domere_gdpr_report', { report_type: 'consent_summary', start_date: new Date(now - 864e5).toISOString(), end_date: new Date(now + 864e5).toISOString() });
  });
});

describe('CCPA', () => {
  test('consumer, opt-outs and requests, with an intact checkpoint chain', async () => {
    const { consumer } = await ok('ccpa_register_consumer', { email: 'bob@example.com', californiaResident: true });
    await ok('ccpa_record_opt_out', { consumerId: consumer.id, optOutType: 'sale', source: 'web_form' });
    assert.equal((await ok('ccpa_check_opt_out', { consumerId: consumer.id, optOutType: 'sale' })).hasOptOut, true);
    const { request } = await ok('ccpa_submit_request', { consumerId: consumer.id, type: 'know_categories', source: 'web_form' });
    await ok('ccpa_verify_request', { requestId: request.id, method: 'email_verification' });
    assert.equal((await ok('ccpa_complete_request', { requestId: request.id, actions: ['provided categories'], format: 'json' })).request.status, 'completed');
    assert.equal((await ok('ccpa_verify_chain')).valid, true);
  });
});
