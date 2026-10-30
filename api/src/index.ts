/**
 * @weave_protocol/api: library entry point (the Express app, not listening).
 * The server lives in server.ts (bin `weave-api`).
 */

export { default } from './app.js';
export { trackScan, trackIntercept, trackCheckpoint, trackVaultOp } from './app.js';

// Importing this module has no side effects. Run directly (`node dist/index.js`,
// as older MCP configs do), it still starts the server; the bin points at server.js.
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const invokedDirectly = (() => {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (invokedDirectly) void import('./server.js');
