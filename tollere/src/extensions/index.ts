/**
 * Unified IDE extension scanner
 *
 * Routes to the appropriate registry based on the requested ecosystem.
 */

import type { ExtensionScanResult } from "../types.js";

export { scanVSCodeExtension } from "./vscode.js";
export { scanOpenVSXExtension } from "./openvsx.js";
export { scanJetBrainsExtension } from "./jetbrains.js";

import { scanVSCodeExtension } from "./vscode.js";
import { scanOpenVSXExtension } from "./openvsx.js";
import { scanJetBrainsExtension } from "./jetbrains.js";

export type IDEEcosystem = "vscode" | "cursor" | "windsurf" | "openvsx" | "jetbrains";

/**
 * Scan an IDE extension by ecosystem
 *
 * Note: Cursor and Windsurf both use the VS Code Marketplace, so they
 * are routed to scanVSCodeExtension transparently.
 */
export async function scanExtension(
  fullId: string,
  ecosystem: IDEEcosystem,
): Promise<ExtensionScanResult> {
  switch (ecosystem) {
    case "vscode":
    case "cursor":
    case "windsurf":
      return scanVSCodeExtension(fullId);
    case "openvsx":
      return scanOpenVSXExtension(fullId);
    case "jetbrains":
      return scanJetBrainsExtension(fullId);
    default:
      throw new Error(`Unsupported IDE ecosystem: ${ecosystem}`);
  }
}
