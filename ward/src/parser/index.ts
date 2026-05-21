/**
 * Main WARD.md parser.
 *
 * Reads a WARD.md file (frontmatter + sections), interprets each known
 * section into the typed sub-policy, and returns a fully-typed WardPolicy.
 */

import { splitFrontmatter, parseYAML } from "./yaml.js";
import { splitSections, extractStructuredBlock, type MarkdownSection } from "./markdown.js";
import type {
  WardPolicy,
  FilesystemPolicy,
  FilesystemRule,
  NetworkPolicy,
  CapabilitiesPolicy,
  DataBoundariesPolicy,
  BehavioralPolicy,
  MultiAgentPolicy,
  CompliancePolicy,
  VerificationPolicy,
  ThreatModelPolicy,
  IncidentResponsePolicy,
  ViolationAction,
  ValidationResult,
  ValidationIssue,
} from "../types.js";

// ─────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────

/**
 * Parse a WARD.md source string into a typed policy object.
 * Throws if the document is fundamentally malformed (not just invalid policy).
 */
export function parseWard(source: string): WardPolicy {
  const { frontmatter, body } = splitFrontmatter(source);
  const fm = frontmatter ? parseYAML(frontmatter) : {};
  const sections = splitSections(body);

  const policy: WardPolicy = {
    version: (fm.ward as never) || "1.0",
    agent: fm.agent as string | undefined,
    name: fm.name as string | undefined,
    description: fm.description as string | undefined,
    raw: {},
  };

  for (const section of sections) {
    applySection(policy, section);
  }

  return policy;
}

/**
 * Parse + validate. Returns a structured result with errors and warnings.
 */
export function parseAndValidate(source: string): ValidationResult {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  let policy: WardPolicy;
  try {
    policy = parseWard(source);
  } catch (err) {
    return {
      valid: false,
      errors: [
        {
          level: "error",
          message: `Failed to parse WARD.md: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
      warnings: [],
    };
  }

  // Validation rules
  if (policy.version !== "1.0") {
    errors.push({
      level: "error",
      section: "frontmatter",
      message: `Unsupported WARD version: ${policy.version}`,
      suggestion: "Use 'ward: 1.0' in the frontmatter.",
    });
  }

  if (!policy.filesystem && !policy.network && !policy.capabilities) {
    warnings.push({
      level: "warning",
      message:
        "Policy declares no filesystem, network, or capability constraints — this agent will be unrestricted on those dimensions.",
      suggestion:
        "Add at least one of `## Filesystem`, `## Network`, or `## Capabilities` to define what the agent is allowed to do.",
    });
  }

  if (
    policy.verification?.required &&
    !policy.verification.backend &&
    !policy.verification.blockchain
  ) {
    warnings.push({
      level: "warning",
      section: "verification",
      message: "Verification is required but no backend or blockchain is specified.",
      suggestion: "Set `backend: domere` and `blockchain: solana` (or similar).",
    });
  }

  if (policy.behavioral?.maxCostUSD === undefined && policy.behavioral?.maxRuntimeSeconds === undefined) {
    warnings.push({
      level: "warning",
      section: "behavioral",
      message: "No cost or runtime limits — runaway agents can incur unbounded charges.",
      suggestion: "Set `maxCostUSD` or `maxRuntimeSeconds` in the Behavioral Limits section.",
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    policy,
  };
}

// ─────────────────────────────────────────────────────────
// Section dispatch
// ─────────────────────────────────────────────────────────

function applySection(policy: WardPolicy, section: MarkdownSection): void {
  const yaml = parseYAML(extractStructuredBlock(section.body));

  switch (section.key) {
    case "filesystem":
      policy.filesystem = parseFilesystem(yaml);
      break;
    case "network":
      policy.network = parseNetwork(yaml);
      break;
    case "capabilities":
    case "tools":
      policy.capabilities = parseCapabilities(yaml);
      break;
    case "databoundaries":
    case "egress":
      policy.dataBoundaries = parseDataBoundaries(yaml);
      break;
    case "behavioral":
    case "behaviorallimits":
    case "limits":
      policy.behavioral = parseBehavioral(yaml);
      break;
    case "multiagent":
      policy.multiAgent = parseMultiAgent(yaml);
      break;
    case "compliance":
      policy.compliance = parseCompliance(yaml);
      break;
    case "verification":
    case "attestation":
      policy.verification = parseVerification(yaml);
      break;
    case "threatmodel":
      policy.threatModel = parseThreatModel(yaml);
      break;
    case "incidentresponse":
    case "onviolation":
      policy.incidentResponse = parseIncidentResponse(yaml);
      break;
    default:
      // Preserve unknown sections so callers don't lose data
      if (policy.raw) policy.raw[section.key] = section.body;
  }
}

// ─────────────────────────────────────────────────────────
// Section parsers
// ─────────────────────────────────────────────────────────

function parseFilesystem(y: Record<string, unknown>): FilesystemPolicy {
  return {
    allow: parseFilesystemRules(y.allow),
    deny: parseFilesystemRules(y.deny),
    default: y.default as "allow" | "deny" | undefined,
  };
}

function parseFilesystemRules(raw: unknown): FilesystemRule[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const rules: FilesystemRule[] = [];
  for (const entry of raw) {
    // Supports both "read: /path/**" string form and {op, path} object form
    if (typeof entry === "string") {
      const colon = entry.indexOf(":");
      if (colon === -1) continue;
      const op = entry.slice(0, colon).trim().toLowerCase();
      const path = entry.slice(colon + 1).trim();
      if (isFilesystemOp(op)) rules.push({ op, path });
    } else if (entry && typeof entry === "object") {
      const obj = entry as Record<string, unknown>;
      if (isFilesystemOp(obj.op as string)) {
        rules.push({ op: obj.op as never, path: String(obj.path || "") });
      }
    }
  }
  return rules.length > 0 ? rules : undefined;
}

function isFilesystemOp(op: string): op is "read" | "write" | "execute" | "delete" | "list" {
  return ["read", "write", "execute", "delete", "list"].includes(op);
}

function parseNetwork(y: Record<string, unknown>): NetworkPolicy {
  const toRules = (raw: unknown) => {
    if (!Array.isArray(raw)) return undefined;
    return raw
      .map((entry) => {
        if (typeof entry === "string") {
          // Handle "url: https://..." form (string with leading url: key)
          if (entry.startsWith("url:") || entry.startsWith("url ")) {
            const colon = entry.indexOf(":");
            const url = entry.slice(colon + 1).trim().replace(/^["']|["']$/g, "");
            return { url };
          }
          // Plain URL string
          return { url: entry };
        }
        if (entry && typeof entry === "object") {
          const obj = entry as Record<string, unknown>;
          return { url: String(obj.url || ""), methods: obj.methods as never };
        }
        return null;
      })
      .filter((r): r is { url: string } => r !== null && !!r.url);
  };

  return {
    allow: toRules(y.allow),
    deny: toRules(y.deny),
    default: y.default as "allow" | "deny" | undefined,
  };
}

function parseCapabilities(y: Record<string, unknown>): CapabilitiesPolicy {
  const toStringList = (raw: unknown): string[] | undefined => {
    if (!Array.isArray(raw)) return undefined;
    return raw.map(String).filter(Boolean);
  };

  return {
    allow: toStringList(y.allow),
    deny: toStringList(y.deny),
    requireApproval: toStringList(y.requireApproval ?? y.require_approval),
    default: y.default as "allow" | "deny" | undefined,
  };
}

function parseDataBoundaries(y: Record<string, unknown>): DataBoundariesPolicy {
  const toClassList = (raw: unknown) => {
    if (!Array.isArray(raw)) return undefined;
    return raw.map((v) => String(v).toLowerCase()) as never;
  };

  return {
    egressAllow: toClassList(y.egressAllow ?? y.egress_allow ?? y.allow),
    egressDeny: toClassList(y.egressDeny ?? y.egress_deny ?? y.deny),
    redact: Array.isArray(y.redact)
      ? y.redact.map((r) =>
          typeof r === "string"
            ? { type: r }
            : { type: String((r as Record<string, unknown>).type), replacement: String((r as Record<string, unknown>).replacement || "[REDACTED]") },
        )
      : undefined,
  };
}

function parseBehavioral(y: Record<string, unknown>): BehavioralPolicy {
  const num = (k: string, alt?: string) => {
    const v = y[k] ?? (alt ? y[alt] : undefined);
    return typeof v === "number" ? v : undefined;
  };
  return {
    maxIterations: num("maxIterations", "max_iterations"),
    maxRuntimeSeconds: num("maxRuntimeSeconds", "max_runtime_seconds"),
    maxCostUSD: num("maxCostUSD", "max_cost_usd"),
    maxTokens: num("maxTokens", "max_tokens"),
    maxToolCalls: num("maxToolCalls", "max_tool_calls"),
    maxExternalServices: num("maxExternalServices", "max_external_services"),
  };
}

function parseMultiAgent(y: Record<string, unknown>): MultiAgentPolicy {
  const tc = y.trustChain ?? y.trust_chain;
  const trustChain =
    tc && typeof tc === "object"
      ? {
          upstream: Array.isArray((tc as Record<string, unknown>).upstream)
            ? ((tc as Record<string, unknown>).upstream as string[])
            : undefined,
          downstream: Array.isArray((tc as Record<string, unknown>).downstream)
            ? ((tc as Record<string, unknown>).downstream as string[])
            : undefined,
        }
      : undefined;

  return {
    trustChain,
    isolation: y.isolation as never,
    maxSemanticDrift: typeof y.maxSemanticDrift === "number" ? (y.maxSemanticDrift as number) : undefined,
  };
}

function parseCompliance(y: Record<string, unknown>): CompliancePolicy {
  return {
    frameworks: Array.isArray(y.frameworks)
      ? (y.frameworks.map((f) => String(f).toLowerCase()) as never)
      : undefined,
    backend: y.backend as never,
  };
}

function parseVerification(y: Record<string, unknown>): VerificationPolicy {
  return {
    required: y.required === true,
    backend: y.backend as never,
    blockchain: y.blockchain as never,
    frequency: (y.frequency as string)?.replace(/-/g, "_") as never,
    attestor: y.attestor as string | undefined,
  };
}

function parseThreatModel(y: Record<string, unknown>): ThreatModelPolicy {
  return {
    inScope: Array.isArray(y.inScope ?? y.in_scope)
      ? ((y.inScope ?? y.in_scope) as string[])
      : undefined,
    outOfScope: Array.isArray(y.outOfScope ?? y.out_of_scope)
      ? ((y.outOfScope ?? y.out_of_scope) as string[])
      : undefined,
  };
}

function parseIncidentResponse(y: Record<string, unknown>): IncidentResponsePolicy {
  const onViolation = y.onViolation ?? y.on_violation;
  let actions: ViolationAction[] | undefined;
  if (Array.isArray(onViolation)) {
    const collected: ViolationAction[] = [];
    for (const a of onViolation) {
      if (typeof a === "string") {
        collected.push({ type: a as ViolationAction["type"] });
      } else if (a && typeof a === "object") {
        const obj = a as Record<string, unknown>;
        if (obj.type) {
          collected.push({
            type: obj.type as ViolationAction["type"],
            minSeverity: obj.minSeverity as ViolationAction["minSeverity"],
            target: obj.target as string | undefined,
          });
        }
      }
    }
    if (collected.length > 0) actions = collected;
  }

  return {
    onViolation: actions,
    severityThreshold: y.severityThreshold as never,
  };
}
