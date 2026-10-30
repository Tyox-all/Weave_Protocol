/**
 * @weave_protocol/hord: library entry point.
 * The MCP server lives in server.ts (bin).
 */

export * from './yoxallismus.js';

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
