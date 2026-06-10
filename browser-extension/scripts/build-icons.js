#!/usr/bin/env node
/**
 * Renders icons/icon.svg into icons/icon-{16,32,48,128}.png
 *
 * Requires `sharp` to be installed in the local node_modules or globally:
 *   npm install sharp
 *
 * Run from the browser-extension/ directory:
 *   node scripts/build-icons.js
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

let sharp;
try {
  sharp = (await import('sharp')).default;
} catch {
  console.error('sharp not installed. Run: npm install sharp');
  process.exit(1);
}

const svg = readFileSync(join(root, 'icons', 'icon.svg'));
const sizes = [16, 32, 48, 128];

for (const size of sizes) {
  await sharp(svg, { density: 600 })
    .resize(size, size)
    .png()
    .toFile(join(root, 'icons', `icon-${size}.png`));
  console.log(`  ✓ icon-${size}.png`);
}

console.log(`\nGenerated ${sizes.length} icons.`);
