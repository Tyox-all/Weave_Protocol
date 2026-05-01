/**
 * Generic scaffold for projects with no detected framework, or where the
 * user wants only the bundle + a config file with no code generation.
 */

import type { ScaffoldOutput, ScaffoldOptions } from "./types.js";

export function scaffoldRaw(opts: ScaffoldOptions): ScaffoldOutput {
  const has = (p: string) => opts.selectedPackages.includes(p as never);

  return {
    packages: opts.selectedPackages.map((p) => `@weave_protocol/${p}`),
    files: [],
    configEntries: [
      { key: "framework", value: "raw" },
      { key: "language", value: opts.language },
    ],
    nextSteps: [
      `Packages installed. Import them as needed.`,
      ...(has("tollere") ? [`Run \`npx weave audit\` to scan your dependencies`] : []),
      ...(has("api") ? [`Run \`npx weave dashboard\` to launch the monitoring UI`] : []),
    ],
  };
}

import { scaffoldLangChainJS } from "./langchain-js.js";
import { scaffoldSDK } from "./sdk.js";
import { scaffoldMcpServer } from "./mcp-server.js";
import type { Framework } from "../detect/framework.js";

export function getScaffold(framework: Framework, opts: ScaffoldOptions): ScaffoldOutput {
  switch (framework) {
    case "langchain-js":
      return scaffoldLangChainJS(opts);
    case "openai-sdk":
    case "vercel-ai":
    case "ai-sdk":
      return scaffoldSDK(opts, "openai");
    case "anthropic-sdk":
      return scaffoldSDK(opts, "anthropic");
    case "mcp-server":
      return scaffoldMcpServer(opts);
    case "llamaindex-js":
    case "google-genai":
    case "raw":
    default:
      return scaffoldRaw(opts);
  }
}

export { scaffoldLangChainJS, scaffoldSDK, scaffoldMcpServer };
