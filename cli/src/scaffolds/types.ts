/**
 * Common interfaces for framework scaffolds.
 *
 * Each framework scaffold knows how to produce:
 *   1. Required Weave Protocol packages
 *   2. A middleware/security file written into the user's project
 *   3. An optional config file
 *   4. A "what to do next" hint
 */

import type { Framework } from "../detect/framework.js";

export interface ScaffoldOutput {
  packages: string[];                       // packages to install
  files: ScaffoldFile[];                    // files to create
  configEntries: ConfigEntry[];             // entries for .weaverc
  nextSteps: string[];                      // human-readable instructions
  mcpEntries?: McpEntry[];                  // optional Claude Desktop MCP additions
}

export interface ScaffoldFile {
  path: string;                             // relative to project root
  content: string;
  description: string;
  overwrite?: boolean;                      // ask before overwriting
}

export interface ConfigEntry {
  key: string;
  value: string | number | boolean | object;
  comment?: string;
}

export interface McpEntry {
  name: string;
  command: string;
  args: string[];
}

export interface ScaffoldOptions {
  language: "typescript" | "javascript";
  selectedPackages: WeavePackage[];
  framework: Framework;
}

export type WeavePackage =
  | "mund"
  | "hord"
  | "domere"
  | "witan"
  | "hundredmen"
  | "tollere"
  | "langchain"
  | "api";
