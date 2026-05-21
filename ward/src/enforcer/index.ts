/**
 * Runtime policy checks.
 *
 * The enforcer doesn't execute anything itself — it answers questions like
 * "is this proposed file write allowed?" given a parsed WardPolicy. Hosts
 * (Mund, Hundredmen, custom harnesses) plug this in at the right points in
 * their agent loop.
 *
 * Decisions are explicit: ALLOW, DENY, REQUIRE_APPROVAL. Hosts decide what
 * to do with a REQUIRE_APPROVAL result (human-in-the-loop, etc.).
 */

import type {
  WardPolicy,
  FilesystemOp,
  FilesystemRule,
  NetworkRule,
  HttpMethod,
  DataClassification,
  ViolationSeverity,
} from "../types.js";

export type Decision = "allow" | "deny" | "require_approval";

export interface CheckResult {
  decision: Decision;
  reason: string;
  matchedRule?: string;
  severity?: ViolationSeverity;
}

// ─────────────────────────────────────────────────────────
// Filesystem
// ─────────────────────────────────────────────────────────

export function checkFilesystem(
  policy: WardPolicy,
  op: FilesystemOp,
  path: string,
): CheckResult {
  const fs = policy.filesystem;
  if (!fs) return { decision: "allow", reason: "No filesystem policy declared (default allow)." };

  // Deny rules take precedence
  for (const rule of fs.deny || []) {
    if (rule.op === op && matchGlob(path, rule.path)) {
      return {
        decision: "deny",
        reason: `Denied by filesystem rule: ${rule.op} ${rule.path}`,
        matchedRule: `${rule.op}: ${rule.path}`,
        severity: "high",
      };
    }
  }

  // Allow rules
  for (const rule of fs.allow || []) {
    if (rule.op === op && matchGlob(path, rule.path)) {
      return {
        decision: "allow",
        reason: `Allowed by filesystem rule: ${rule.op} ${rule.path}`,
        matchedRule: `${rule.op}: ${rule.path}`,
      };
    }
  }

  const def = fs.default ?? "deny";
  return {
    decision: def,
    reason: `No matching rule; default action is ${def}.`,
    severity: def === "deny" ? "medium" : undefined,
  };
}

// ─────────────────────────────────────────────────────────
// Network
// ─────────────────────────────────────────────────────────

export function checkNetwork(
  policy: WardPolicy,
  url: string,
  method: HttpMethod = "GET",
): CheckResult {
  const net = policy.network;
  if (!net) return { decision: "allow", reason: "No network policy declared (default allow)." };

  const matchesRule = (rule: NetworkRule) => {
    if (!matchGlob(url, rule.url)) return false;
    if (rule.methods && rule.methods.length > 0 && !rule.methods.includes(method)) return false;
    return true;
  };

  for (const rule of net.deny || []) {
    if (matchesRule(rule)) {
      return {
        decision: "deny",
        reason: `Denied by network rule: ${rule.url}`,
        matchedRule: rule.url,
        severity: "high",
      };
    }
  }

  for (const rule of net.allow || []) {
    if (matchesRule(rule)) {
      return {
        decision: "allow",
        reason: `Allowed by network rule: ${rule.url}`,
        matchedRule: rule.url,
      };
    }
  }

  const def = net.default ?? "deny";
  return {
    decision: def,
    reason: `No matching network rule; default action is ${def}.`,
    severity: def === "deny" ? "medium" : undefined,
  };
}

// ─────────────────────────────────────────────────────────
// Capabilities (tools)
// ─────────────────────────────────────────────────────────

export function checkCapability(policy: WardPolicy, toolName: string): CheckResult {
  const caps = policy.capabilities;
  if (!caps) return { decision: "allow", reason: "No capabilities policy declared (default allow)." };

  if (caps.deny?.some((t) => t === toolName || matchGlob(toolName, t))) {
    return {
      decision: "deny",
      reason: `Tool '${toolName}' is in the deny list.`,
      matchedRule: toolName,
      severity: "high",
    };
  }

  if (caps.requireApproval?.some((t) => t === toolName || matchGlob(toolName, t))) {
    return {
      decision: "require_approval",
      reason: `Tool '${toolName}' requires human approval before execution.`,
      matchedRule: toolName,
      severity: "medium",
    };
  }

  if (caps.allow && caps.allow.length > 0) {
    if (caps.allow.some((t) => t === toolName || matchGlob(toolName, t))) {
      return {
        decision: "allow",
        reason: `Tool '${toolName}' is in the allow list.`,
      };
    }
    const def = caps.default ?? "deny";
    return {
      decision: def,
      reason: `Tool '${toolName}' is not in the allow list; default is ${def}.`,
      severity: def === "deny" ? "medium" : undefined,
    };
  }

  return { decision: caps.default ?? "allow", reason: "No allow/deny list; default action applied." };
}

// ─────────────────────────────────────────────────────────
// Data egress
// ─────────────────────────────────────────────────────────

export function checkDataEgress(
  policy: WardPolicy,
  classification: DataClassification,
): CheckResult {
  const db = policy.dataBoundaries;
  if (!db) return { decision: "allow", reason: "No data boundary policy declared." };

  if (db.egressDeny?.includes(classification)) {
    return {
      decision: "deny",
      reason: `Data classification '${classification}' is denied egress.`,
      matchedRule: classification,
      severity: classification === "credentials" || classification === "secret" ? "critical" : "high",
    };
  }

  if (db.egressAllow && db.egressAllow.length > 0) {
    if (db.egressAllow.includes(classification)) {
      return { decision: "allow", reason: `Egress allowed for '${classification}'.` };
    }
    return {
      decision: "deny",
      reason: `Data classification '${classification}' is not in the egress allow list.`,
      matchedRule: classification,
      severity: "medium",
    };
  }

  return { decision: "allow", reason: "No egress rules matched (default allow)." };
}

// ─────────────────────────────────────────────────────────
// Behavioral checks
// ─────────────────────────────────────────────────────────

export interface RuntimeState {
  iterations: number;
  runtimeSeconds: number;
  costUSD: number;
  tokens: number;
  toolCalls: number;
  externalServices: Set<string>;
}

export function checkBehavioral(policy: WardPolicy, state: RuntimeState): CheckResult {
  const b = policy.behavioral;
  if (!b) return { decision: "allow", reason: "No behavioral limits declared." };

  if (b.maxIterations !== undefined && state.iterations >= b.maxIterations) {
    return {
      decision: "deny",
      reason: `Max iterations exceeded (${state.iterations} >= ${b.maxIterations}).`,
      severity: "high",
    };
  }
  if (b.maxRuntimeSeconds !== undefined && state.runtimeSeconds >= b.maxRuntimeSeconds) {
    return {
      decision: "deny",
      reason: `Max runtime exceeded (${state.runtimeSeconds}s >= ${b.maxRuntimeSeconds}s).`,
      severity: "high",
    };
  }
  if (b.maxCostUSD !== undefined && state.costUSD >= b.maxCostUSD) {
    return {
      decision: "deny",
      reason: `Max cost exceeded ($${state.costUSD.toFixed(2)} >= $${b.maxCostUSD.toFixed(2)}).`,
      severity: "critical",
    };
  }
  if (b.maxTokens !== undefined && state.tokens >= b.maxTokens) {
    return {
      decision: "deny",
      reason: `Max tokens exceeded (${state.tokens} >= ${b.maxTokens}).`,
      severity: "medium",
    };
  }
  if (b.maxToolCalls !== undefined && state.toolCalls >= b.maxToolCalls) {
    return {
      decision: "deny",
      reason: `Max tool calls exceeded (${state.toolCalls} >= ${b.maxToolCalls}).`,
      severity: "medium",
    };
  }
  if (
    b.maxExternalServices !== undefined &&
    state.externalServices.size >= b.maxExternalServices
  ) {
    return {
      decision: "deny",
      reason: `Max external services exceeded (${state.externalServices.size} >= ${b.maxExternalServices}).`,
      severity: "high",
    };
  }

  return { decision: "allow", reason: "Within all behavioral limits." };
}

// ─────────────────────────────────────────────────────────
// Glob matcher (minimal, no deps)
// ─────────────────────────────────────────────────────────

/**
 * Match a string against a glob pattern.
 *   *   matches anything except "/"
 *   **  matches anything including "/"
 *   ?   matches a single char
 *   any other char matches literally
 */
export function matchGlob(input: string, pattern: string): boolean {
  // Escape regex special chars except our glob ones
  const regexSource =
    "^" +
    pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, "::DOUBLESTAR::")
      .replace(/\*/g, "[^/]*")
      .replace(/::DOUBLESTAR::/g, ".*")
      .replace(/\?/g, ".") +
    "$";
  return new RegExp(regexSource).test(input);
}
