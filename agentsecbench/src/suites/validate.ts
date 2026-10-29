/**
 * Suite validation, hashing and registration.
 *
 * A suite is only comparable over time if its inputs never change, so:
 *   - every suite is validated against the installed Adversary corpus
 *     BEFORE a run (unknown IDs mean the corpus drifted — refuse to run);
 *   - built-in suites are hash-locked: their manifest hash is pinned in
 *     LOCKED_SUITE_HASHES and checked by tests, so an accidental edit to
 *     a v1 suite fails CI instead of silently changing the benchmark;
 *   - additional suites can be registered at runtime or loaded from a
 *     JSON manifest file, and go through the same validation.
 */

import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { getAttackById } from '@weave_protocol/adversary';
import type { SuiteManifest } from '../types.js';

export interface SuiteValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

const SUITE_ID = /^ASB-[A-Za-z0-9]+-v\d+$/;

/**
 * SHA-256 over the parts of a manifest that define what is measured:
 * id, version, attack set (order-insensitive), trophies and thresholds.
 */
export function suiteManifestHash(suite: SuiteManifest): string {
  const material = JSON.stringify({
    id: suite.id,
    version: suite.version,
    attackIds: [...suite.attackIds].sort(),
    trophies: suite.trophyAttacks.map((t) => t.attackId).sort(),
    tiers: [suite.tierThresholds.A, suite.tierThresholds.B, suite.tierThresholds.C, suite.tierThresholds.D],
  });
  return createHash('sha256').update(material).digest('hex');
}

export function validateSuite(
  suite: SuiteManifest,
  attackExists: (id: string) => boolean = (id) => getAttackById(id) !== undefined,
): SuiteValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!SUITE_ID.test(suite.id ?? '')) errors.push(`id "${suite.id}" must look like ASB-<Name>-v<N>`);
  if (suite.version !== '1.0') errors.push(`version must be "1.0" (got "${suite.version}"); changes ship as a new suite id`);
  if (!Array.isArray(suite.attackIds) || suite.attackIds.length === 0) errors.push('attackIds must be a non-empty list');

  const ids = suite.attackIds ?? [];
  const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (dupes.length) errors.push(`duplicate attack ids: ${[...new Set(dupes)].join(', ')}`);

  const missing = ids.filter((id) => !attackExists(id));
  if (missing.length) {
    errors.push(
      `${missing.length} attack id(s) not in the installed Adversary corpus: ${missing.slice(0, 5).join(', ')}` +
        (missing.length > 5 ? ', …' : '') +
        `. Install @weave_protocol/adversary@${suite.adversaryCompatVersion} or newer.`,
    );
  }

  for (const t of suite.trophyAttacks ?? []) {
    if (!ids.includes(t.attackId)) errors.push(`trophy "${t.name}" (${t.attackId}) is not in attackIds`);
  }

  const { A, B, C, D } = suite.tierThresholds ?? ({} as SuiteManifest['tierThresholds']);
  if (![A, B, C, D].every((n) => typeof n === 'number' && n >= 0 && n <= 100) || !(A > B && B > C && C > D)) {
    errors.push('tierThresholds must be numbers in 0-100 with A > B > C > D');
  }

  if (!suite.methodologyDoc) warnings.push('no methodologyDoc set');
  if ((suite.trophyAttacks ?? []).length === 0) warnings.push('no trophy attacks defined');

  return { ok: errors.length === 0, errors, warnings };
}

/** Throw with all errors if the suite is invalid. */
export function assertValidSuite(suite: SuiteManifest): void {
  const v = validateSuite(suite);
  if (!v.ok) throw new Error(`Suite ${suite.id} is invalid:\n  - ${v.errors.join('\n  - ')}`);
}

/** Load and validate a suite manifest from a JSON file. */
export function loadSuiteFile(path: string): SuiteManifest {
  let suite: SuiteManifest;
  try {
    suite = JSON.parse(readFileSync(path, 'utf8')) as SuiteManifest;
  } catch (err) {
    throw new Error(`Cannot read suite manifest ${path}: ${(err as Error).message}`);
  }
  assertValidSuite(suite);
  return suite;
}
