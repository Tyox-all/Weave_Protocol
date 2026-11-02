// Ward parser and enforcer. The bypass cases are regressions: before 0.2.0,
// paths and URLs were matched as raw strings.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseWard, parseAndValidate,
  checkFilesystem, checkNetwork, checkCapability, checkDataEgress, checkBehavioral,
  matchGlob, normalizePath, canonicalUrl,
} from '../dist/index.js';

const HOME = process.env.HOME;

const policy = parseWard(`---
ward: "1.0"
agent: test-agent
---

# WARD.md

## Filesystem

allow:
  - read: /workspace/**
  - write: /workspace/out/**
deny:
  - read: /workspace/secrets/**
  - read: ~/.ssh/**
default: deny

## Network

allow:
  - url: "https://*.github.com/**"
  - url: "https://API.Example.com/v1/*"
deny:
  - url: "https://evil.example/**"
default: allow

## Capabilities

allow:
  - file_read
  - mcp__notes__*
requireApproval:
  - shell_exec
deny:
  - generate_image
default: deny

## Data Boundaries

egressDeny:
  - credentials

## Behavioral Limits

maxIterations: 10
maxCostUSD: 2.50
`);

const fs = (op, path) => checkFilesystem(policy, op, path).decision;
const net = (url, method) => checkNetwork(policy, url, method).decision;

describe('parser', () => {
  test('reads frontmatter and every section', () => {
    assert.equal(policy.agent, 'test-agent');
    assert.equal(policy.filesystem.default, 'deny');
    assert.equal(policy.filesystem.deny.length, 2);
    assert.equal(policy.network.allow.length, 2);
    assert.deepEqual(policy.capabilities.requireApproval, ['shell_exec']);
    assert.deepEqual(policy.dataBoundaries.egressDeny, ['credentials']);
    assert.equal(policy.behavioral.maxCostUSD, 2.5);
  });

  test('validation reports a missing ward version', () => {
    const r = parseAndValidate('---\nagent: x\n---\n# WARD.md\n');
    assert.equal(r.valid, false);
  });
});

describe('filesystem', () => {
  test('allow, deny precedence and default', () => {
    assert.equal(fs('read', '/workspace/src/a.ts'), 'allow');
    assert.equal(fs('read', '/workspace/secrets/token'), 'deny');
    assert.equal(fs('write', '/workspace/src/a.ts'), 'deny', 'write only allowed under out/');
    assert.equal(fs('write', '/workspace/out/report.md'), 'allow');
    assert.equal(fs('read', '/etc/passwd'), 'deny');
  });

  test('".." and "//" cannot escape an allowed directory or dodge a deny rule', () => {
    assert.equal(fs('read', '/workspace/x/../secrets/token'), 'deny');
    assert.equal(fs('read', '/workspace/./secrets/token'), 'deny');
    assert.equal(fs('read', '/workspace//secrets/token'), 'deny');
    assert.equal(fs('read', '/workspace/../etc/passwd'), 'deny');
    assert.equal(fs('read', '/workspace/a/b/../../../etc/passwd'), 'deny');
  });

  test('"~" in rules matches the home directory, however the path is written', { skip: !HOME }, () => {
    const open = parseWard('---\nward: "1.0"\nagent: t\n---\n## Filesystem\ndeny:\n  - read: ~/.ssh/**\ndefault: allow\n');
    assert.equal(checkFilesystem(open, 'read', `${HOME}/.ssh/id_rsa`).decision, 'deny');
    assert.equal(checkFilesystem(open, 'read', '~/.ssh/id_rsa').decision, 'deny');
    assert.equal(checkFilesystem(open, 'read', `${HOME}/projects/../.ssh/id_rsa`).decision, 'deny');
    assert.equal(checkFilesystem(open, 'read', `${HOME}/notes.txt`).decision, 'allow');
  });

  test('normalizePath', () => {
    assert.equal(normalizePath('/a/./b//c/../d'), '/a/b/d');
    assert.equal(normalizePath('/../../etc'), '/etc');
    assert.equal(normalizePath('a/../../b'), '../b');
  });
});

describe('network', () => {
  test('allow, deny and default', () => {
    assert.equal(net('https://api.github.com/repos/x'), 'allow');
    assert.equal(net('https://evil.example/x'), 'deny');
    assert.equal(net('https://anything.else/x'), 'allow', 'default allow');
  });

  test('case, ports, userinfo and fragments cannot dodge a deny rule', () => {
    assert.equal(net('HTTPS://EVIL.EXAMPLE/x'), 'deny');
    assert.equal(net('https://evil.example:443/x'), 'deny');
    assert.equal(net('https://user:pw@evil.example/x'), 'deny');
    assert.equal(net('https://evil.example/a/../x'), 'deny');
  });

  test('a host wildcard only matches that host', () => {
    const strict = parseWard('---\nward: "1.0"\nagent: t\n---\n## Network\nallow:\n  - url: "https://*.github.com/**"\ndefault: deny\n');
    const n = (u) => checkNetwork(strict, u).decision;
    assert.equal(n('https://api.github.com/x'), 'allow');
    assert.equal(n('https://evil.example#.github.com/x'), 'deny');
    assert.equal(n('https://evil.example?.github.com/x'), 'deny');
    assert.equal(n('https://api.github.com@evil.example/x'), 'deny');
    assert.equal(n('https://api.github.com.evil.example/x'), 'deny');
  });

  test('rule hosts are case-insensitive; unparseable URLs are denied', () => {
    assert.equal(net('https://api.example.com/v1/users'), 'allow');
    assert.equal(net('not a url'), 'deny');
  });

  test('canonicalUrl', () => {
    assert.equal(canonicalUrl('HTTPS://User@Evil.Example:443/a/../b?q=1#frag'), 'https://evil.example/b?q=1');
    assert.equal(canonicalUrl('nope'), null);
  });
});

describe('capabilities', () => {
  test('deny, approval, allow list, globs and default', () => {
    assert.equal(checkCapability(policy, 'file_read').decision, 'allow');
    assert.equal(checkCapability(policy, 'shell_exec').decision, 'require_approval');
    assert.equal(checkCapability(policy, 'generate_image').decision, 'deny');
    assert.equal(checkCapability(policy, 'mcp__notes__read').decision, 'allow');
    assert.equal(checkCapability(policy, 'mcp__other__read').decision, 'deny');
  });
});

describe('data egress and behavioral limits', () => {
  test('egress deny list', () => {
    assert.equal(checkDataEgress(policy, 'credentials').decision, 'deny');
    assert.equal(checkDataEgress(policy, 'public').decision, 'allow');
  });

  test('limits are enforced at the boundary', () => {
    const state = { iterations: 9, runtimeSeconds: 0, costUSD: 2.49, tokens: 0, toolCalls: 0, externalServices: new Set() };
    assert.equal(checkBehavioral(policy, state).decision, 'allow');
    assert.equal(checkBehavioral(policy, { ...state, iterations: 10 }).decision, 'deny');
    assert.equal(checkBehavioral(policy, { ...state, costUSD: 2.5 }).decision, 'deny');
  });
});

describe('matchGlob', () => {
  test('* stays within a segment; ** crosses segments', () => {
    assert.equal(matchGlob('/a/b.txt', '/a/*.txt'), true);
    assert.equal(matchGlob('/a/b/c.txt', '/a/*.txt'), false);
    assert.equal(matchGlob('/a/b/c.txt', '/a/**'), true);
    assert.equal(matchGlob('/a.b', '/a?b'), true);
  });
});
