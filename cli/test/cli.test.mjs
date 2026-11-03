// @weave_protocol/cli: framework and package-manager detection, and the code
// `weave init` generates. Generated imports are checked against the real
// packages' source in this repo, generated JavaScript must parse, and every
// npx hint must name a @weave_protocol package (before 0.2.0 the hints ran
// the unrelated npm package "weave", and scaffolds imported names that
// Hord and Dōmere don't export).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  detectFramework, frameworkLabel, detectPackageManager, installCommand, devInstallCommand, runCommand, getScaffold,
} from '../dist/index.js';

const REPO = resolve('..');
const project = (files) => {
  const dir = mkdtempSync(join(tmpdir(), 'weave-cli-'));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), typeof content === 'string' ? content : JSON.stringify(content));
  }
  return dir;
};

describe('detectFramework', () => {
  test('from package.json dependencies, with a priority order', () => {
    const dir = project({ 'package.json': { dependencies: { openai: '1', '@langchain/core': '1' } }, 'tsconfig.json': '{}' });
    const d = detectFramework(dir);
    assert.equal(d.primary, 'langchain-js');
    assert.deepEqual(new Set(d.detected), new Set(['openai-sdk', 'langchain-js']));
    assert.equal(d.language, 'typescript');
  });

  test('from source imports when package.json lists nothing', () => {
    const dir = project({ 'package.json': {}, 'src/server.js': 'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n' });
    assert.equal(detectFramework(dir).primary, 'mcp-server');
  });

  test('node_modules and dot-directories are skipped', () => {
    const dir = project({ 'package.json': {}, 'node_modules/x/index.js': 'import OpenAI from "openai";', '.cache/a.js': 'import OpenAI from "openai";' });
    assert.equal(detectFramework(dir).primary, 'raw');
  });

  test('Python projects and empty directories', () => {
    assert.equal(detectFramework(project({ 'requirements.txt': 'llama-index' })).isPython, true);
    const empty = detectFramework(project({}));
    assert.equal(empty.hasPackageJson, false);
    assert.equal(empty.language, 'unknown');
    assert.equal(frameworkLabel('raw'), 'No framework detected');
  });
});

describe('package managers', () => {
  test('lockfiles win', () => {
    assert.equal(detectPackageManager(project({ 'pnpm-lock.yaml': '' })), 'pnpm');
    assert.equal(detectPackageManager(project({ 'yarn.lock': '' })), 'yarn');
    assert.equal(detectPackageManager(project({ 'bun.lock': '' })), 'bun');
    assert.equal(detectPackageManager(project({ 'package-lock.json': '{}' })), 'npm');
  });

  test('commands per manager', () => {
    assert.equal(installCommand(['a', 'b'], 'pnpm'), 'pnpm add a b');
    assert.equal(devInstallCommand(['a'], 'yarn'), 'yarn add --dev a');
    assert.equal(runCommand('build', 'bun'), 'bun run build');
  });
});

// ─── generated code ─────────────────────────────────────────

/** Names a package exports, read from its src/index.ts and followed through re-exports. */
function exportedNames(pkg) {
  const names = new Set();
  const seen = new Set();
  const visit = (file) => {
    if (seen.has(file) || !existsSync(file)) return;
    seen.add(file);
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/export\s+(?:declare\s+)?(?:abstract\s+)?(?:class|function|const|let|async function)\s+(\w+)/g)) names.add(m[1]);
    for (const m of src.matchAll(/export\s*\{([^}]*)\}/g)) {
      for (const part of m[1].split(',')) {
        const name = part.trim().replace(/^type\s+/, '').split(/\s+as\s+/).pop()?.trim();
        if (name) names.add(name);
      }
    }
    for (const m of src.matchAll(/export\s*\*\s*from\s*["']([^"']+)["']/g)) {
      const base = resolve(dirname(file), m[1].replace(/\.js$/, ''));
      visit(`${base}.ts`);
      visit(join(base, 'index.ts'));
    }
  };
  visit(join(REPO, pkg, 'src', 'index.ts'));
  return names;
}

const ALL = ['tollere', 'mund', 'hord', 'domere', 'witan', 'hundredmen', 'langchain', 'api'];
const FRAMEWORKS = ['langchain-js', 'openai-sdk', 'anthropic-sdk', 'mcp-server', 'raw'];

for (const framework of FRAMEWORKS) {
  for (const language of ['javascript', 'typescript']) {
    describe(`scaffold: ${framework} (${language})`, () => {
      const out = getScaffold(framework, { language, selectedPackages: ALL, framework });

      test('every imported name exists in the package', () => {
        for (const file of out.files) {
          for (const m of file.content.matchAll(/import\s*\{([^}]+)\}\s*from\s*"@weave_protocol\/([\w-]+)"/g)) {
            const exported = exportedNames(m[2]);
            for (const name of m[1].split(',').map((s) => s.trim()).filter(Boolean)) {
              assert.ok(exported.has(name), `${file.path} imports ${name} from @weave_protocol/${m[2]}, which doesn't export it`);
            }
          }
        }
      });

      test('generated JavaScript parses', { skip: language !== 'javascript' }, () => {
        for (const file of out.files) {
          const dir = mkdtempSync(join(tmpdir(), 'weave-scaffold-'));
          const path = join(dir, file.path.replace(/\.js$/, '.mjs'));
          writeFileSync(path, file.content);
          const r = spawnSync(process.execPath, ['--check', path], { encoding: 'utf8' });
          assert.equal(r.status, 0, `${file.path}:\n${r.stderr}`);
        }
      });

      test('Mund results are read through the fields scan() returns', () => {
        for (const file of out.files) {
          assert.doesNotMatch(file.content, /\.safe\b/, 'scan() has no "safe" field');
          assert.doesNotMatch(file.content, /\.description\b/, 'SecurityIssue has no "description" field');
        }
      });

      test('npx hints only name @weave_protocol packages', () => {
        for (const step of out.nextSteps) {
          for (const m of step.matchAll(/npx\s+(-p\s+)?(\S+)/g)) {
            assert.match(m[2], /^@weave_protocol\//, `unscoped npx target in: ${step}`);
          }
        }
      });
    });
  }
}

test('the CLI prints its version and help without a project', () => {
  const r = spawnSync(process.execPath, [resolve('dist/cli.js'), 'version'], { encoding: 'utf8', cwd: project({}) });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /\d+\.\d+\.\d+/);
});

test('weave audit fails cleanly when there is no package.json', () => {
  const r = spawnSync(process.execPath, [resolve('dist/cli.js'), 'audit'], { encoding: 'utf8', cwd: project({}) });
  assert.equal(r.status, 2);
  assert.match(r.stdout + r.stderr, /package\.json not found/);
});
