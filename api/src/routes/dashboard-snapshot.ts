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
 * Everything comes from real sources: surface counts, events and stats from
 * the events surfaces report (POST /api/v1/events, sent by Ward's
 * reportEvent when WEAVE_DASHBOARD_URL is set), and the WARD summary from
 * WARD.md in cwd. A surface that hasn't reported shows as "off"; nothing is
 * invented. (Before 1.4.0 the counts and events here were synthetic.)
 */

import { Router } from 'express';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { events, SURFACES, type StoredEvent, type Surface } from '../services/events.js';

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

// ─── Built from reported events ─────────────────────────────
const SURFACE_INFO: Record<Surface, { name: string; vendor: string; icon: string }> = {
  mcp: { name: 'Hundredmen', vendor: 'MCP layer', icon: '🔍' },
  'claude-code': { name: 'adapter-claudecode', vendor: 'Anthropic', icon: '🛡️' },
  antigravity: { name: 'adapter-antigravity', vendor: 'Google', icon: '🛡️' },
  msaf: { name: 'adapter-msaf', vendor: 'Microsoft', icon: '🛡️' },
  browser: { name: 'browser', vendor: 'Playwright + IPI', icon: '🌐' },
  'gemini-cli': { name: 'adapter-geminicli', vendor: 'Google', icon: '🛡️' },
  codex: { name: 'adapter-codex', vendor: 'OpenAI', icon: '🛡️' },
  opencode: { name: 'adapter-opencode', vendor: 'OpenCode', icon: '🛡️' },
  cursor: { name: 'adapter-cursor', vendor: 'Cursor', icon: '🛡️' },
  'qwen-code': { name: 'adapter-qwencode', vendor: 'Alibaba Qwen', icon: '🛡️' },
};

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function buildSurfaces(day: StoredEvent[], now = Date.now()) {
  return SURFACES.map((id) => {
    const mine = day.filter((e) => e.surface === id);
    const last = mine.reduce((t, e) => Math.max(t, e.timestamp), 0);
    return {
      id,
      ...SURFACE_INFO[id],
      // live: reported in the last 5 minutes; idle: in the last day; off: not reporting
      status: last && now - last < 5 * MINUTE ? 'live' : last ? 'idle' : 'off',
      eventsToday: mine.length,
      lastHour: mine.filter((e) => now - e.timestamp < HOUR).length,
      lastEventAt: last || null,
    };
  });
}

export function buildStats(day: StoredEvent[]) {
  const count = (d: string) => day.filter((e) => e.decision === d).length;
  return {
    decisions: day.length,
    allows: count('allow'),
    denies: count('deny'),
    approvalsRequested: count('require_approval'),
    ipiDetected: count('ipi_detected'),
    urlsScanned: day.filter((e) => e.surface === 'browser' && (e.decision === 'scan' || e.decision === 'ipi_detected')).length,
  };
}

// ─── Route ──────────────────────────────────────────────────
router.get('/snapshot', (_req, res) => {
  const now = Date.now();
  const day = events.since(now - DAY);
  res.json({
    status: 'ok',
    timestamp: now,
    surfaces: buildSurfaces(day, now),
    events: events.recent(12).map(({ id, surface, decision, subject, reason, timestamp }) => ({
      id, surface, kind: decision, subject, reason: reason ?? '', timestamp,
    })),
    ward: readWardSummary(),
    stats: buildStats(day),
    notes: {
      dataSource: day.length
        ? 'Live: events reported by Weave surfaces in the last 24 hours (in memory since the API started).'
        : 'No surface has reported yet. Set WEAVE_DASHBOARD_URL and WEAVE_API_KEY where your agents run to see their decisions here.',
    },
  });
});

export default router;
