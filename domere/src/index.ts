/**
 * @weave_protocol/domere: library entry point.
 * The MCP server lives in server.ts (bin).
 */

export { DomereToolHandler, DOMERE_TOOLS } from './tools/index.js';
export * from './types.js';
export * from './thread/index.js';
export * from './language/index.js';
export * from './anchoring/index.js';
export * from './storage/index.js';

// Enterprise Modules
export * from "./audit/index.js";
export * from "./handoff/index.js";
export * from "./compliance/index.js";
export * from "./orchestration/index.js";
export * from './gdpr-index.js';
export * from './ccpa-index.js';

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
