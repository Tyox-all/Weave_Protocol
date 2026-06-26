import type { SuiteManifest } from '../types.js';
import { ASB_BROWSER_V1 } from './browser-v1/manifest.js';

export const SUITES: Record<string, SuiteManifest> = {
  'ASB-Browser-v1': ASB_BROWSER_V1,
};

export { ASB_BROWSER_V1 };

export function getSuite(id: string): SuiteManifest | undefined {
  return SUITES[id];
}

export function listSuites(): SuiteManifest[] {
  return Object.values(SUITES);
}
