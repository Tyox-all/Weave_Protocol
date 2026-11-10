#!/usr/bin/env node
/**
 * Test every package that depends on a changed package, against the changed
 * package's local build instead of the version on npm.
 *
 * Each package's own CI job resolves its @weave_protocol dependencies from
 * the registry, so a change that breaks a dependent only shows up after it
 * is published. (Mund 0.6.0 shipped a finding that echoed unmasked secrets;
 * api's tests would have caught it, but only ran against it after release.)
 *
 *   node scripts/test-dependents.mjs --base=origin/main     # packages changed since base
 *   node scripts/test-dependents.mjs --changed=mund,ward    # these packages
 *
 * For each changed package: build it and `npm pack` it. For each package
 * that depends on it, directly or through another Weave package: point the
 * dependency and an npm override at the tarball, install, build, run its
 * tests, then restore its package.json and package-lock.json.
 *
 * It edits package.json and package-lock.json in place while a dependent
 * is tested, and restores both when done. It also reinstalls that
 * dependent's node_modules; run `npm ci` there afterwards to get back to the
 * lockfile.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const flags = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')).map(([k, v]) => [k, v ?? true]));
const gha = !!process.env.GITHUB_ACTIONS;
const log = (s) => console.log(s);

// ── The internal dependency graph ─────────────────────────
const pkgs = {}; // dir -> { name, deps: [dir], hasTest }
const dirOfName = {};
for (const dir of readdirSync(root)) {
  const file = join(root, dir, 'package.json');
  if (!existsSync(file)) continue;
  const p = JSON.parse(readFileSync(file, 'utf8'));
  if (!p.name?.startsWith('@weave_protocol/')) continue;
  dirOfName[p.name] = dir;
  pkgs[dir] = { name: p.name, depNames: Object.keys({ ...p.dependencies, ...p.optionalDependencies, ...p.peerDependencies }).filter((n) => n.startsWith('@weave_protocol/')), hasTest: !!p.scripts?.test };
}
for (const p of Object.values(pkgs)) p.deps = p.depNames.map((n) => dirOfName[n]).filter(Boolean);

/** Packages that depend on `dir`, directly or through other Weave packages. */
function dependentsOf(dir) {
  const out = new Set();
  const visit = (d) => { for (const [k, p] of Object.entries(pkgs)) if (p.deps.includes(d) && !out.has(k)) { out.add(k); visit(k); } };
  visit(dir);
  return [...out];
}

// ── Which packages changed ────────────────────────────────
let changed;
if (flags.changed) changed = String(flags.changed).split(',').map((s) => s.trim()).filter(Boolean);
else {
  const base = flags.base ?? 'origin/main';
  const files = execFileSync('git', ['diff', '--name-only', `${base}...HEAD`], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean);
  const byDir = {};
  for (const f of files) { const d = f.split('/')[0]; if (pkgs[d]) (byDir[d] ??= []).push(f); }
  // A change to docs alone can't break a dependent
  changed = Object.entries(byDir).filter(([, fs]) => fs.some((f) => !f.endsWith('.md'))).map(([d]) => d);
}
for (const d of changed) if (!pkgs[d]) { console.error(`Not a Weave package: ${d}`); process.exit(2); }

const affected = [...new Set(changed.flatMap(dependentsOf))].filter((d) => !changed.includes(d));
if (!changed.length || !affected.length) {
  log(changed.length ? `No package depends on ${changed.join(', ')}.` : 'No package changed (or only its docs).');
  process.exit(0);
}
log(`Changed: ${changed.join(', ')}`);
log(`Testing against the local build: ${affected.join(', ')}\n`);

// ── Build and pack each changed package ───────────────────
const run = (cmd, args, cwd) => {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', env: { ...process.env, YOXALL_SILENCE_BETA_WARNING: '1' } });
  return { ok: r.status === 0, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
};
const packDir = mkdtempSync(join(tmpdir(), 'weave-dependents-'));
const tarball = {};
for (const d of changed) {
  const dir = join(root, d);
  for (const [cmd, args] of [['npm', ['ci', '--no-audit', '--no-fund']], ['npm', ['run', 'build', '--if-present']]]) {
    const r = run(cmd, args, dir);
    if (!r.ok) { console.error(`Building ${d} failed:\n${r.out.slice(-3000)}`); process.exit(1); }
  }
  const r = run('npm', ['pack', '--pack-destination', packDir, '--json'], dir);
  if (!r.ok) { console.error(`Packing ${d} failed:\n${r.out.slice(-3000)}`); process.exit(1); }
  const file = JSON.parse(r.out.slice(r.out.indexOf('['))).at(0).filename;
  tarball[pkgs[d].name] = `file:${join(packDir, file)}`;
  log(`built ${pkgs[d].name} -> ${file}`);
}

/** Copies of these packages installed under `dir` that aren't the local tarball. */
function registryCopies(dir, names) {
  const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8'));
  const stray = [];
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    if (path && names.includes(name) && !String(entry.resolved ?? '').startsWith('file:')) stray.push(`${path} from ${entry.resolved ?? 'unknown'}`);
  }
  return stray;
}

// ── Test each dependent ───────────────────────────────────
const results = [];
for (const d of affected) {
  const dir = join(root, d);
  const using = changed.filter((c) => dependentsOf(c).includes(d)).map((c) => pkgs[c].name);
  if (!pkgs[d].hasTest) { results.push({ d, using, status: 'skip', why: 'no test script' }); continue; }
  const pjPath = join(dir, 'package.json');
  const lockPath = join(dir, 'package-lock.json');
  const pjText = readFileSync(pjPath, 'utf8');
  const lockText = existsSync(lockPath) ? readFileSync(lockPath, 'utf8') : undefined;
  try {
    const pj = JSON.parse(pjText);
    pj.overrides ??= {};
    for (const name of using) {
      // npm only allows overriding a direct dependency with the same spec, so set both
      for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) if (pj[field]?.[name]) pj[field][name] = tarball[name];
      pj.overrides[name] = tarball[name];
    }
    writeFileSync(pjPath, JSON.stringify(pj, null, 2) + '\n');
    let step = 'install';
    let r = run('npm', ['install', '--no-audit', '--no-fund'], dir);
    // Every copy of the changed package in the tree must be the local build;
    // a copy from the registry would make a pass meaningless
    if (r.ok) {
      step = 'check that the local build is used';
      const stray = registryCopies(dir, using);
      if (stray.length) r = { ok: false, out: `Not using the local build: ${stray.join('; ')}` };
    }
    if (r.ok) { step = 'build'; r = run('npm', ['run', 'build', '--if-present'], dir); }
    if (r.ok) { step = 'test'; r = run('npm', ['test'], dir); }
    results.push({ d, using, status: r.ok ? 'pass' : 'fail', step, out: r.out });
  } finally {
    writeFileSync(pjPath, pjText);
    if (lockText !== undefined) writeFileSync(lockPath, lockText);
  }
}

// ── Report ────────────────────────────────────────────────
const failed = results.filter((r) => r.status === 'fail');
const lines = ['## Dependents tested against the local build', '', `Changed: ${changed.map((c) => `\`${c}\``).join(', ')}`, '', '| Package | Uses | Result |', '|---|---|---|'];
for (const r of results) lines.push(`| \`${r.d}\` | ${r.using.map((u) => `\`${u.replace('@weave_protocol/', '')}\``).join(', ')} | ${r.status === 'pass' ? 'pass' : r.status === 'skip' ? `skipped (${r.why})` : `**failed at ${r.step}**`} |`);
log('\n' + lines.join('\n'));
for (const r of failed) {
  // The lines of a failing test, from node:test and vitest output
  const detail = r.out.split('\n').filter((l) => /not ok|✗|×|FAIL|AssertionError|Error:|error:/.test(l)).slice(0, 15).join('\n');
  log(`\n── ${r.d} failed at ${r.step} (using local ${r.using.join(', ')}) ──\n${detail || r.out.slice(-2000)}`);
  if (gha) log(`::error title=${r.d} breaks against local ${r.using.join(', ')}::${r.step} failed. ${(detail.split('\n')[0] ?? '').replace(/[\r\n]/g, ' ').slice(0, 200)}`);
}
if (gha && process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');
process.exit(failed.length ? 1 : 0);
