/**
 * Detect which AI framework(s) the project uses by inspecting package.json
 * and (as a fallback) scanning source files for known import patterns.
 */

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

export type Framework =
  | "langchain-js"
  | "llamaindex-js"
  | "openai-sdk"
  | "anthropic-sdk"
  | "mcp-server"
  | "vercel-ai"
  | "ai-sdk"
  | "google-genai"
  | "raw";

export interface FrameworkDetection {
  primary: Framework;
  detected: Framework[];
  evidence: Record<Framework, string[]>;
  hasPackageJson: boolean;
  isPython: boolean;
  language: "typescript" | "javascript" | "python" | "unknown";
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  type?: string;
}

const DEPENDENCY_SIGNATURES: Record<Framework, string[]> = {
  "langchain-js": ["langchain", "@langchain/core", "@langchain/openai", "@langchain/anthropic"],
  "llamaindex-js": ["llamaindex", "@llamaindex/core"],
  "openai-sdk": ["openai"],
  "anthropic-sdk": ["@anthropic-ai/sdk"],
  "mcp-server": ["@modelcontextprotocol/sdk"],
  "vercel-ai": ["ai"],
  "ai-sdk": ["@ai-sdk/openai", "@ai-sdk/anthropic"],
  "google-genai": ["@google/generative-ai", "@google/genai"],
  raw: [],
};

function readJSON<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

function gatherDependencies(pkg: PackageJson): Set<string> {
  return new Set([
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {}),
    ...Object.keys(pkg.peerDependencies || {}),
  ]);
}

/**
 * Walk source files (limited depth) looking for known imports.
 */
function scanSourceImports(cwd: string, maxDepth = 3): Set<string> {
  const found = new Set<string>();
  const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", ".turbo", "coverage"]);

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP.has(entry) || entry.startsWith(".")) continue;
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        walk(full, depth + 1);
        continue;
      }
      const ext = extname(entry);
      if (![".ts", ".tsx", ".js", ".jsx", ".mjs", ".py"].includes(ext)) continue;
      let content: string;
      try {
        content = readFileSync(full, "utf8");
      } catch {
        continue;
      }
      // Only need to scan first ~100 lines for imports
      const head = content.split("\n").slice(0, 100).join("\n");
      for (const [framework, sigs] of Object.entries(DEPENDENCY_SIGNATURES)) {
        for (const sig of sigs) {
          // Match: import ... from 'sig' or require('sig') or import 'sig'
          const re = new RegExp(`(from|require\\(|import)\\s*['"\`]${sig.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i");
          if (re.test(head)) {
            found.add(framework);
          }
        }
      }
    }
  }

  walk(cwd, 0);
  return found;
}

function detectLanguage(cwd: string, pkg: PackageJson | null): FrameworkDetection["language"] {
  if (existsSync(join(cwd, "tsconfig.json"))) return "typescript";
  if (existsSync(join(cwd, "pyproject.toml")) || existsSync(join(cwd, "requirements.txt"))) return "python";
  if (pkg) return "javascript";
  return "unknown";
}

export function detectFramework(cwd: string = process.cwd()): FrameworkDetection {
  const evidence: Record<string, string[]> = {};
  const detected = new Set<Framework>();

  const pkgPath = join(cwd, "package.json");
  const hasPackageJson = existsSync(pkgPath);
  const pkg = hasPackageJson ? readJSON<PackageJson>(pkgPath) : null;

  // 1. Check package.json dependencies
  if (pkg) {
    const deps = gatherDependencies(pkg);
    for (const [framework, sigs] of Object.entries(DEPENDENCY_SIGNATURES) as Array<[Framework, string[]]>) {
      for (const sig of sigs) {
        if (deps.has(sig)) {
          detected.add(framework);
          evidence[framework] = evidence[framework] || [];
          evidence[framework].push(`dep: ${sig}`);
        }
      }
    }
  }

  // 2. Scan source imports (catches projects without proper package.json or using global pkgs)
  if (detected.size < 2 && hasPackageJson) {
    const fromImports = scanSourceImports(cwd);
    for (const framework of fromImports) {
      const f = framework as Framework;
      detected.add(f);
      evidence[f] = evidence[f] || [];
      evidence[f].push("import found in source");
    }
  }

  // Determine primary framework using priority order
  const priority: Framework[] = [
    "langchain-js",
    "llamaindex-js",
    "mcp-server",
    "vercel-ai",
    "ai-sdk",
    "anthropic-sdk",
    "openai-sdk",
    "google-genai",
  ];
  let primary: Framework = "raw";
  for (const f of priority) {
    if (detected.has(f)) {
      primary = f;
      break;
    }
  }

  // Initialize empty evidence keys
  for (const f of Object.keys(DEPENDENCY_SIGNATURES) as Framework[]) {
    if (!evidence[f]) evidence[f] = [];
  }

  const isPython =
    existsSync(join(cwd, "pyproject.toml")) ||
    existsSync(join(cwd, "requirements.txt")) ||
    existsSync(join(cwd, "setup.py"));

  return {
    primary,
    detected: [...detected],
    evidence: evidence as Record<Framework, string[]>,
    hasPackageJson,
    isPython,
    language: detectLanguage(cwd, pkg),
  };
}

export function frameworkLabel(f: Framework): string {
  const labels: Record<Framework, string> = {
    "langchain-js": "LangChain.js",
    "llamaindex-js": "LlamaIndex (JS)",
    "openai-sdk": "OpenAI SDK",
    "anthropic-sdk": "Anthropic SDK",
    "mcp-server": "MCP Server",
    "vercel-ai": "Vercel AI SDK",
    "ai-sdk": "AI SDK",
    "google-genai": "Google Generative AI",
    raw: "No framework detected",
  };
  return labels[f];
}
