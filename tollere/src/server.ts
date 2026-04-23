#!/usr/bin/env node
/**
 * @weave_protocol/tollere - MCP server (v0.2)
 *
 * Exposes supply chain security tools via Model Context Protocol so AI agents
 * (Claude Desktop, Claude Code, etc.) can audit dependencies, Docker images,
 * and IDE extensions before installing.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { detectTyposquat } from "./typosquat.js";
import { getMaintainerReputation } from "./reputation.js";
import { queryCVEs } from "./cve.js";
import { diffVersions } from "./diff.js";
import { scanPackage, scanPackageJson } from "./scanner.js";
import { detectSandwichPattern } from "./sandwich.js";
import { scanDockerImage } from "./docker.js";
import { scanExtension, type IDEEcosystem } from "./extensions/index.js";
import { DEFAULT_CONFIG } from "./types.js";

const server = new Server(
  { name: "@weave_protocol/tollere", version: "0.2.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "tollere_scan_package",
      description: "Scan a single package for supply chain risks (typosquats, CVEs, low reputation, suspicious patterns). Use BEFORE `npm install <name>`.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "Package name" },
          version: { type: "string", description: "Version to check", default: "latest" },
          ecosystem: { type: "string", enum: ["npm", "pypi", "cargo", "go", "maven"], default: "npm" },
        },
        required: ["name"],
      },
    },
    {
      name: "tollere_scan_dependencies",
      description: "Scan an entire package.json for supply chain risks. Returns a full report.",
      inputSchema: {
        type: "object",
        properties: {
          package_json: { type: "string", description: "The contents of package.json as a JSON string" },
        },
        required: ["package_json"],
      },
    },
    {
      name: "tollere_check_typosquat",
      description: "Check if a package name is suspiciously similar to a popular package.",
      inputSchema: {
        type: "object",
        properties: { name: { type: "string", description: "Package name to check" } },
        required: ["name"],
      },
    },
    {
      name: "tollere_check_maintainer",
      description: "Get maintainer reputation score for a package (0-100, higher = more trustworthy).",
      inputSchema: {
        type: "object",
        properties: { name: { type: "string", description: "Package name" } },
        required: ["name"],
      },
    },
    {
      name: "tollere_check_cves",
      description: "Query OSV.dev for known vulnerabilities affecting a specific package version.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "Package name" },
          version: { type: "string", description: "Specific version to check" },
          ecosystem: { type: "string", enum: ["npm", "pypi", "cargo", "go", "maven"], default: "npm" },
        },
        required: ["name", "version"],
      },
    },
    {
      name: "tollere_diff_versions",
      description: "Compare two versions of a package to detect suspicious changes (new install scripts, injected dependencies, obfuscated code). The Axios case detector.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "Package name" },
          from_version: { type: "string", description: "Older version" },
          to_version: { type: "string", description: "Newer version" },
        },
        required: ["name", "from_version", "to_version"],
      },
    },
    {
      name: "tollere_detect_sandwich",
      description: "Detect sandwich-pattern attacks across the version history of a package - where malicious code is removed in a clean version then reappears later. The Checkmarx case detector.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "Package name (npm)" },
          last_n: { type: "number", description: "Number of recent versions to analyze", default: 15 },
        },
        required: ["name"],
      },
    },
    {
      name: "tollere_scan_docker",
      description: "Scan a Docker image for supply chain risks - tag overwriting, phantom tags, suspicious manifest patterns. Use BEFORE `docker pull`.",
      inputSchema: {
        type: "object",
        properties: {
          image: {
            type: "string",
            description: "Docker image reference (e.g., 'nginx:alpine', 'checkmarx/kics:v2.1.20')",
          },
        },
        required: ["image"],
      },
    },
    {
      name: "tollere_scan_extension",
      description: "Scan an IDE extension for supply chain risks. Covers VS Code (and Cursor/Windsurf), Open VSX (VSCodium/Gitpod), and JetBrains IDEs (IntelliJ/PyCharm/WebStorm/etc).",
      inputSchema: {
        type: "object",
        properties: {
          full_id: {
            type: "string",
            description: "Extension ID (publisher.name for VS Code/Open VSX, plugin ID or name for JetBrains)",
          },
          ecosystem: {
            type: "string",
            enum: ["vscode", "cursor", "windsurf", "openvsx", "jetbrains"],
            description: "Which IDE marketplace to query",
            default: "vscode",
          },
        },
        required: ["full_id"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "tollere_scan_package": {
        const pkg = args as { name: string; version?: string; ecosystem?: string };
        const result = await scanPackage(
          pkg.name,
          pkg.version || "latest",
          (pkg.ecosystem as never) || "npm",
          DEFAULT_CONFIG,
        );
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "tollere_scan_dependencies": {
        const { package_json } = args as { package_json: string };
        const report = await scanPackageJson(package_json, DEFAULT_CONFIG);
        return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
      }

      case "tollere_check_typosquat": {
        const { name: pkgName } = args as { name: string };
        const matches = detectTyposquat(pkgName);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              package: pkgName,
              isPossibleTyposquat: matches.length > 0,
              matches,
            }, null, 2),
          }],
        };
      }

      case "tollere_check_maintainer": {
        const { name: pkgName } = args as { name: string };
        const reputation = await getMaintainerReputation(pkgName);
        return { content: [{ type: "text", text: JSON.stringify(reputation || { error: "Package not found" }, null, 2) }] };
      }

      case "tollere_check_cves": {
        const params = args as { name: string; version: string; ecosystem?: string };
        const cves = await queryCVEs(params.name, params.version, (params.ecosystem as never) || "npm");
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              package: `${params.name}@${params.version}`,
              vulnerabilityCount: cves.length,
              vulnerabilities: cves,
            }, null, 2),
          }],
        };
      }

      case "tollere_diff_versions": {
        const params = args as { name: string; from_version: string; to_version: string };
        const diff = await diffVersions(params.name, params.from_version, params.to_version);
        return { content: [{ type: "text", text: JSON.stringify(diff || { error: "Could not compute diff" }, null, 2) }] };
      }

      case "tollere_detect_sandwich": {
        const params = args as { name: string; last_n?: number };
        const result = await detectSandwichPattern(params.name, { lastN: params.last_n });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "tollere_scan_docker": {
        const { image } = args as { image: string };
        const result = await scanDockerImage(image);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "tollere_scan_extension": {
        const params = args as { full_id: string; ecosystem?: IDEEcosystem };
        const result = await scanExtension(params.full_id, params.ecosystem || "vscode");
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : String(error)}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Tollere MCP server (v0.2) running on stdio");
