/**
 * GET /api/dashboard/snapshot
 *
 * Returns a single JSON snapshot containing everything the v2 dashboard
 * needs in one round-trip:
 *   - status:    overall system health
 *   - surfaces:  five enforcement-surface summaries
 *   - events:    recent enforcement events (allow/deny/ipi/scan)
 *   - ward:      currently-loaded WARD.md summary
 *   - stats:     24-hour aggregates
 *
 * v1.1.0 reads WARD.md from cwd for real, and returns realistic but
 * synthetic data for surface counts and events. Real telemetry integration
 * (collecting events from Hundredmen, adapters, and the browser package)
 * is the v1.2.0 work.
 */

import { Router } from 'express';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const router = Router();

// ─── WARD.md reading ────────────────────────────────────────
interface WardSummary {
  loaded: boolean;
  source?: string;
  name?: string;
  agent?: string;
  version?: string;
  network: { allow: number; deny: number };
  capabilities: { allow: number; deny: number };
  behavioralLimits?: {
    maxIterations?: number;
    maxRuntimeSeconds?: number;
    maxCostUSD?: number;
  };
}

function readWardSummary(): WardSummary {
  const empty: WardSummary = {
    loaded: false,
    network: { allow: 0, deny: 0 },
    capabilities: { allow: 0, deny: 0 },
  };

  const candidates: string[] = [];
  if (process.env.WEAVE_WARD_PATH) candidates.push(process.env.WEAVE_WARD_PATH);
  candidates.push(join(process.cwd(), 'WARD.md'));
  candidates.push(join(process.cwd(), '.weave', 'WARD.md'));

  let path: string | null = null;
  for (const c of candidates) {
    if (existsSync(c)) {
      path = c;
      break;
    }
  }
  if (!path) return empty;

  try {
    const src = readFileSync(path, 'utf8');

    // Parse frontmatter
    const fm = src.match(/^---\s*\n([\s\S]*?)\n---/);
    const fmText = fm ? fm[1] : '';
    const wardMatch = fmText.match(/^ward:\s*["']?([^"'\n]+)["']?/m);
    const nameMatch = fmText.match(/^name:\s*["']?([^"'\n]+)["']?/m);
    const agentMatch = fmText.match(/^agent:\s*["']?([^"'\n]+)["']?/m);

    // Count rules — coarse approximation by counting "- url:" / "- read:" / capability bullets in allow/deny lists.
    const netAllow = countListItemsInSection(src, /## Network/i, /allow:/i, /deny:/i);
    const netDeny = countListItemsInSection(src, /## Network/i, /deny:/i, /default:|^##/im);
    const capAllow = countListItemsInSection(src, /## Capabilities/i, /allow:/i, /deny:|requireApproval:/i);
    const capDeny = countListItemsInSection(src, /## Capabilities/i, /deny:/i, /default:|^##/im);

    // Parse behavioral limits (also coarse)
    const maxIter = parseInt((src.match(/maxIterations:\s*(\d+)/) || [])[1] || '');
    const maxRuntime = parseInt((src.match(/maxRuntimeSeconds:\s*(\d+)/) || [])[1] || '');
    const maxCost = parseFloat((src.match(/maxCostUSD:\s*([\d.]+)/) || [])[1] || '');

    const result: WardSummary = {
      loaded: true,
      source: path,
      name: nameMatch ? nameMatch[1].trim() : undefined,
      agent: agentMatch ? agentMatch[1].trim() : undefined,
      version: wardMatch ? wardMatch[1].trim() : '1.0',
      network: { allow: netAllow, deny: netDeny },
      capabilities: { allow: capAllow, deny: capDeny },
    };

    const limits: WardSummary['behavioralLimits'] = {};
    if (maxIter) limits.maxIterations = maxIter;
    if (maxRuntime) limits.maxRuntimeSeconds = maxRuntime;
    if (maxCost) limits.maxCostUSD = maxCost;
    if (Object.keys(limits).length) result.behavioralLimits = limits;

    return result;
  } catch {
    return empty;
  }
}

/**
 * Counts list-item lines ("  - foo:") between a section header and the next
 * section/default boundary. Coarse but adequate for a dashboard summary.
 */
function countListItemsInSection(
  src: string,
  sectionHeader: RegExp,
  listMarker: RegExp,
  endMarker: RegExp,
): number {
  const sectionStart = src.search(sectionHeader);
  if (sectionStart === -1) return 0;
  const section = src.slice(sectionStart);

  const listStart = section.search(listMarker);
  if (listStart === -1) return 0;
  const tail = section.slice(listStart);

  const endIdx = tail.slice(20).search(endMarker);
  const block = endIdx === -1 ? tail : tail.slice(0, 20 + endIdx);

  return (block.match(/^\s+-\s+\w/gm) || []).length;
}

// ─── Synthetic data (replaced with real telemetry in v1.2.0) ─
function buildSurfaces() {
  // Realistic-looking counts, jittered per-poll so the UI feels alive
  // without requiring real telemetry plumbing yet.
  const jitter = (n: number, pct = 0.05) =>
    Math.round(n * (1 + (Math.random() * 2 - 1) * pct));

  return [
    {
      id: 'mcp',
      name: 'Hundredmen',
      vendor: 'MCP layer',
      icon: '🔍',
      status: 'live',
      eventsToday: jitter(247),
      delta: 12,
    },
    {
      id: 'claude-code',
      name: 'adapter-claudecode',
      vendor: 'Anthropic',
      icon: '🛡️',
      status: 'live',
      eventsToday: jitter(89),
      delta: 23,
    },
    {
      id: 'antigravity',
      name: 'adapter-antigravity',
      vendor: 'Google',
      icon: '🛡️',
      status: 'live',
      eventsToday: jitter(34),
      delta: 8,
    },
    {
      id: 'msaf',
      name: 'adapter-msaf',
      vendor: 'Microsoft',
      icon: '🛡️',
      status: 'idle',
      eventsToday: jitter(12),
      delta: -4,
    },
    {
      id: 'browser',
      name: 'browser',
      vendor: 'Playwright + IPI',
      icon: '🌐',
      status: 'live',
      eventsToday: jitter(156),
      delta: 41,
    },
  ];
}

function buildRecentEvents() {
  // Rotating sample events that look like real enforcement activity.
  // In v1.2.0, this will be replaced with reads from an actual event log.
  const now = Date.now();
  const templates = [
    { kind: 'allow', surface: 'claude-code', subject: 'Bash: ls /tmp', reason: 'allowed by capability rule' },
    { kind: 'allow', surface: 'mcp', subject: 'Read: /Users/me/projects/foo/index.ts', reason: 'matches filesystem allow' },
    { kind: 'deny', surface: 'antigravity', subject: 'Bash: cat ~/.config/gcloud/credentials.db', reason: 'GCP credential path denied' },
    { kind: 'ipi_detected', surface: 'browser', subject: 'https://blog.example.com/post-1234', reason: 'hidden_text_color + trigger_phrase' },
    { kind: 'allow', surface: 'browser', subject: 'navigation: https://api.github.com/repos/foo', reason: 'network allow rule matched' },
    { kind: 'require_approval', surface: 'mcp', subject: 'http_request: api.openai.com', reason: 'capability requires approval' },
    { kind: 'deny', surface: 'msaf', subject: 'ShellExec: cat ~/.azure/credentials', reason: 'Azure credential path denied' },
    { kind: 'scan', surface: 'browser', subject: 'https://docs.python.org/3/library/asyncio.html', reason: 'clean' },
    { kind: 'allow', surface: 'claude-code', subject: 'Write: ./src/new-feature.ts', reason: 'filesystem write allowed in project root' },
    { kind: 'ipi_detected', surface: 'browser', subject: 'https://recipes.example.com/lasagna', reason: 'aria_hidden_payload + html_comment_injection' },
    { kind: 'deny', surface: 'mcp', subject: 'file_delete: /etc/hosts', reason: 'capability in deny list' },
    { kind: 'allow', surface: 'antigravity', subject: 'Edit: ./README.md', reason: 'filesystem allow' },
  ];

  // Pick 12 events with realistic timestamps spread over the last ~30 min
  return templates.slice(0, 12).map((t, i) => ({
    id: `evt-${now}-${i}`,
    timestamp: now - i * 60_000 - Math.floor(Math.random() * 30_000),
    ...t,
  }));
}

function buildStats(surfaces: ReturnType<typeof buildSurfaces>) {
  // Derive from surface counts so the numbers stay self-consistent
  const total = surfaces.reduce((sum, s) => sum + s.eventsToday, 0);
  return {
    decisions: total,
    allows: Math.round(total * 0.84),
    denies: Math.round(total * 0.11),
    approvalsRequested: Math.round(total * 0.05),
    ipiDetected: surfaces.find((s) => s.id === 'browser')?.eventsToday
      ? Math.round((surfaces.find((s) => s.id === 'browser')!.eventsToday) * 0.06)
      : 0,
    urlsScanned: surfaces.find((s) => s.id === 'browser')?.eventsToday || 0,
  };
}

// ─── Route ──────────────────────────────────────────────────
router.get('/snapshot', (_req, res) => {
  const surfaces = buildSurfaces();
  res.json({
    status: 'ok',
    timestamp: Date.now(),
    surfaces,
    events: buildRecentEvents(),
    ward: readWardSummary(),
    stats: buildStats(surfaces),
    notes: {
      dataSource:
        'Surface counts and events are synthetic in v1.1.0. WARD.md is read from cwd. Real telemetry integration coming in v1.2.0.',
    },
  });
});

export default router;
