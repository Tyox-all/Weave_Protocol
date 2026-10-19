/**
 * Mund - The Guardian Protocol
 * Package version, read from package.json at runtime (dist/version.js -> ../package.json)
 */

import { readFileSync } from 'fs';

let cached: string | undefined;

export function getVersion(): string {
  if (!cached) {
    try {
      const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string };
      cached = pkg.version ?? '0.0.0';
    } catch {
      cached = '0.0.0';
    }
  }
  return cached;
}
