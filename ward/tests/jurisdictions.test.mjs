// Ward 0.3.10: model endpoints by jurisdiction, and the Chinese providers Ward now knows.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseWard, evaluateToolCall, parseAndValidate as validateWard } from '../dist/index.js';
import { modelEndpointJurisdiction, isModelEndpoint } from '../dist/enforcer/egress.js';
import { parseYAML } from '../dist/parser/yaml.js';

const policy = (network) => parseWard(`---
ward: "1.0"
agent: jurisdictions-test
---

## Network

${network}

## Capabilities

default: allow
`);

const M = { WebFetch: { capability: 'http_request', urlField: 'url' }, Bash: { capability: 'shell_exec', commandField: 'command' } };
const fetchUrl = (p, url) => evaluateToolCall(p, 'WebFetch', { url }, { mappings: M });

describe('known model endpoints', () => {
  test('Chinese providers, by host and by pattern', () => {
    for (const h of ['api.deepseek.com', 'api.moonshot.ai', 'api.moonshot.cn', 'dashscope.aliyuncs.com', 'dashscope-intl.aliyuncs.com', 'open.bigmodel.cn', 'api.z.ai',
      'api.hunyuan.cloud.tencent.com', 'api.minimaxi.com', 'api.minimax.io', 'api.stepfun.com', 'qianfan.baidubce.com', 'api.siliconflow.cn', 'api.siliconflow.com',
      'ark.cn-beijing.volces.com', 'ark.ap-southeast.volces.com']) {
      assert.equal(modelEndpointJurisdiction(h), 'cn', h);
    }
    assert.equal(modelEndpointJurisdiction('api.openai.com'), 'us');
    assert.equal(modelEndpointJurisdiction('my-co.openai.azure.com'), 'us');
    assert.equal(modelEndpointJurisdiction('bedrock-runtime.eu-west-1.amazonaws.com'), 'us');
    assert.equal(modelEndpointJurisdiction('api.mistral.ai'), 'eu');
    assert.equal(modelEndpointJurisdiction('api.cohere.com'), 'ca');
    assert.equal(isModelEndpoint('www.volces.com'), false, 'Volcengine site, not the Ark API');
    assert.equal(isModelEndpoint('example.com'), false);
  });
});

describe('model_jurisdictions', () => {
  const allowAll = 'allow:\n  - url: "https://**"';

  test('deny: [cn] blocks Chinese model endpoints, in URL arguments and in commands', () => {
    const p = policy(`${allowAll}\nmodel_jurisdictions:\n  deny: [cn]`);
    assert.deepEqual(p.network.model_jurisdictions, { allow: undefined, deny: ['cn'] });
    for (const url of ['https://api.deepseek.com/v1/chat/completions', 'https://ark.cn-beijing.volces.com/api/v3/chat/completions', 'https://api.minimax.io/v1/text']) {
      const r = fetchUrl(p, url);
      assert.equal(r.decision, 'deny', url);
      assert.match(r.reasons[0], /CN jurisdiction/);
    }
    assert.equal(fetchUrl(p, 'https://api.openai.com/v1/chat/completions').decision, 'allow');
    assert.equal(fetchUrl(p, 'https://example.com/page').decision, 'allow', 'not a model endpoint');
    assert.equal(evaluateToolCall(p, 'Bash', { command: 'curl https://api.stepfun.com/v1/chat -d @notes.json' }, { mappings: M }).decision, 'deny');
  });

  test('allow: [us, eu] admits only those', () => {
    const p = policy(`${allowAll}\nmodel_jurisdictions:\n  allow:\n    - us\n    - eu`);
    assert.equal(fetchUrl(p, 'https://api.anthropic.com/v1/messages').decision, 'allow');
    assert.equal(fetchUrl(p, 'https://api.mistral.ai/v1/chat').decision, 'allow');
    assert.equal(fetchUrl(p, 'https://api.cohere.com/v2/chat').decision, 'deny');
    assert.equal(fetchUrl(p, 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat').decision, 'deny');
  });

  test('an allow rule naming the host exactly still wins; a wildcard host does not', () => {
    const p = policy('allow:\n  - url: "https://api.deepseek.com/**"\n  - url: "https://**"\nmodel_jurisdictions:\n  deny: [cn]');
    assert.equal(fetchUrl(p, 'https://api.deepseek.com/v1/chat/completions').decision, 'allow');
    assert.equal(fetchUrl(p, 'https://api.moonshot.ai/v1/chat/completions').decision, 'deny');
  });

  test('without model_jurisdictions nothing changes', () => {
    const p = policy(allowAll);
    assert.equal(fetchUrl(p, 'https://api.deepseek.com/v1/chat/completions').decision, 'allow');
  });

  test('the validator warns about unknown codes', () => {
    const v = validateWard(`---\nward: "1.0"\nagent: t\n---\n\n## Network\n\n${allowAll}\nmodel_jurisdictions:\n  allow: [usa]\n\n## Capabilities\n\ndefault: allow\n`);
    assert.ok(v.warnings.some((w) => /Unknown jurisdiction "usa"/.test(w.message)));
  });
});

test('YAML: one level of nested mapping, without changing lists or scalars', () => {
  assert.deepEqual(parseYAML('model_jurisdictions:\n  deny: [cn]\ndefault: deny\n'), { model_jurisdictions: { deny: ['cn'] }, default: 'deny' });
  assert.deepEqual(parseYAML('m:\n  allow:\n    - us\n    - eu\n  deny: [cn]\nx: 1\n'), { m: { allow: ['us', 'eu'], deny: ['cn'] }, x: 1 });
  assert.deepEqual(parseYAML('a:\n  - 1\n  - 2\nb: yes\n'), { a: [1, 2], b: 'yes' });
  assert.deepEqual(parseYAML('empty:\nnext: 2\n'), { empty: [], next: 2 });
});
