import type { SuiteManifest } from '../types.js';
import { ASB_BROWSER_V1 } from './browser-v1/manifest.js';
import { assertValidSuite } from './validate.js';

export const SUITES: Record<string, SuiteManifest> = {
  'ASB-Browser-v1': ASB_BROWSER_V1,
};

/**
 * Pinned manifest hashes for built-in suites. A locked suite never
 * changes; if one of these stops matching, the edit belongs in a new
 * suite id (e.g. ASB-Browser-v2), not in the existing manifest.
 */
export const LOCKED_SUITE_HASHES: Record<string, string> = {
  'ASB-Browser-v1': 'a9867e09171c1493d300e6f0ecb357e27cd44391b34a46f81dc640ae7d4a71e6',
};

export { ASB_BROWSER_V1 };
export { validateSuite, assertValidSuite, suiteManifestHash, loadSuiteFile, type SuiteValidation } from './validate.js';

export function getSuite(id: string): SuiteManifest | undefined {
  return SUITES[id];
}

export function listSuites(): SuiteManifest[] {
  return Object.values(SUITES);
}

/**
 * Register an additional suite (e.g. loaded with loadSuiteFile). Built-in
 * suite ids can't be replaced.
 */
export function registerSuite(suite: SuiteManifest): void {
  if (LOCKED_SUITE_HASHES[suite.id]) throw new Error(`${suite.id} is a locked built-in suite and can't be replaced`);
  assertValidSuite(suite);
  SUITES[suite.id] = suite;
}
