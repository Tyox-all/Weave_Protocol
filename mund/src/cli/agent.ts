/**
 * Mund - The Guardian Protocol
 * `mund-mcp agent-audit` and `mund-mcp check-skill`: pre-install checks
 * used by the Weave Protocol harness adapters.
 */

import { readFileSync, statSync } from 'fs';
import { resolve } from 'path';
import { runAgentAudit, scanSkillContent, scanSkillDir, verdictFor, type Verdict } from '../agent-audit.js';
import { computeRiskScore } from '../scoring.js';

const flag = (args: string[], name: string) => {
  const hit = args.find((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (!hit) return undefined;
  return hit.includes('=') ? hit.slice(hit.indexOf('=') + 1) : true;
};
const RANK: Record<Verdict, number> = { allow: 0, warn: 1, block: 2 };

export const AGENT_USAGE = `Usage:
  mund-mcp agent-audit [--cwd=DIR] [--live] [--json] [--fail-on=block|warn|none] [--timeout=MS]
                      [--accept-changes=NAME[,NAME…]|all] [--harness=claude|antigravity]
      Audit installed skills and configured MCP servers (Claude Code layout).
      --live connects to approved servers, scans their tool descriptions and
      checks them against the rug-pull baseline. Writes a verdict cache used
      by the harness hooks. --accept-changes re-baselines servers whose tool
      changes you have reviewed.

  mund-mcp check-skill <SKILL.md | skill-dir | -> [--json]
      Scan one skill before installing it. "-" reads content from stdin.
      Exit code 1 means "block".
`;

export async function runAgentAuditCli(args: string[]): Promise<number> {
  if (flag(args, 'help')) { process.stdout.write(AGENT_USAGE); return 0; }
  const timeout = Number(flag(args, 'timeout') ?? 8000);
  const accept = typeof flag(args, 'accept-changes') === 'string' ? String(flag(args, 'accept-changes')).split(',') : undefined;
  const harness = flag(args, 'harness') === 'antigravity' ? 'antigravity' : 'claude';
  const report = await runAgentAudit({ cwd: (flag(args, 'cwd') as string) || process.cwd(), live: !!flag(args, 'live') || !!accept, timeoutMs: timeout, accept, harness });
  if (flag(args, 'json')) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    const icon = { allow: '✓', warn: '!', block: '✗' };
    for (const s of report.servers) {
      const live = s.live.status === 'ok' ? `${s.live.tools} tools, baseline ${s.live.rugpull}` : `live ${s.live.status}${s.live.reason ? `: ${s.live.reason}` : ''}`;
      console.log(`${icon[s.verdict]} MCP  ${s.name} (${s.scope}) ${s.verdict.toUpperCase()} · ${live}`);
      for (const i of s.issues.filter((x) => x.severity !== 'info')) console.log(`      ${i.severity.padEnd(8)} ${i.rule_name}`);
    }
    for (const k of report.skills) {
      console.log(`${icon[k.verdict]} SKILL ${k.name} (${k.scope}) ${k.verdict.toUpperCase()} · risk ${k.risk.score}/100`);
      for (const i of k.issues.filter((x) => x.severity !== 'info' && x.severity !== 'low')) console.log(`      ${i.severity.padEnd(8)} ${i.rule_name}`);
    }
    console.log(`\n${report.servers.length} MCP server(s), ${report.skills.length} skill(s): ${report.summary.block} block, ${report.summary.warn} warn, ${report.summary.allow} allow`);
  }
  const failOn = (flag(args, 'fail-on') as string) || 'block';
  if (failOn === 'none') return 0;
  const worst = [...report.servers, ...report.skills].reduce((w, x) => Math.max(w, RANK[x.verdict]), 0);
  return worst >= RANK[failOn as Verdict] ? 1 : 0;
}

export async function runCheckSkillCli(args: string[]): Promise<number> {
  const target = args.find((a) => !a.startsWith('--'));
  if (!target || flag(args, 'help')) { process.stdout.write(AGENT_USAGE); return target ? 0 : 2; }
  let result: { verdict: Verdict; risk: ReturnType<typeof computeRiskScore>; issues: Awaited<ReturnType<typeof scanSkillContent>> };
  if (target === '-') {
    const issues = await scanSkillContent(readFileSync(0, 'utf8'));
    result = { verdict: verdictFor(issues), risk: computeRiskScore(issues), issues };
  } else if (statSync(resolve(target)).isDirectory()) {
    const r = await scanSkillDir(resolve(target));
    result = { verdict: r.verdict, risk: r.risk, issues: r.issues };
  } else {
    const issues = await scanSkillContent(readFileSync(resolve(target), 'utf8'));
    result = { verdict: verdictFor(issues), risk: computeRiskScore(issues), issues };
  }
  if (flag(args, 'json')) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  else {
    console.log(`${result.verdict.toUpperCase()} · risk ${result.risk.score}/100 (${result.risk.label})`);
    for (const i of result.issues) console.log(`  ${i.severity.padEnd(8)} ${i.rule_name}`);
  }
  return result.verdict === 'block' ? 1 : 0;
}
