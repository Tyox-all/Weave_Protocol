/**
 * Weave Browser Guard — popup script.
 *
 * Queries the active tab, fetches the latest scan result from the
 * background service worker, and renders the appropriate state.
 */

const RISK_LABELS = {
  none: 'Clean',
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
  critical: 'Critical risk',
};

const RISK_ICONS = {
  none: '✓',
  low: '!',
  medium: '!',
  high: '✗',
  critical: '☠',
};

const RISK_DETAIL = {
  none: 'This page appears safe for AI agents to ingest.',
  low: 'Low-confidence patterns detected. Likely benign but worth a glance.',
  medium: 'Medium-risk content detected. Review the findings before relying on this page in an AI workflow.',
  high: 'High-risk content. An AI agent reading this page could be manipulated. Treat with caution.',
  critical: 'CRITICAL: Hostile instructions explicitly target AI agents on this page. Do not let an AI agent process this.',
};

// ─── State management ───────────────────────────────────────────
function showState(id) {
  for (const el of document.querySelectorAll('.state')) {
    el.classList.add('hidden');
  }
  document.getElementById(id)?.classList.remove('hidden');
}

// ─── Render ─────────────────────────────────────────────────────
function renderClean(scan) {
  document.getElementById('clean-url').textContent = truncateMid(scan.url, 50);
  showState('state-clean');
}

function renderThreats(scan) {
  const result = scan.result;
  const risk = result.riskLevel;

  // Top card
  const card = document.getElementById('risk-card');
  card.className = `risk-card risk-${risk}`;
  document.getElementById('risk-icon').textContent = RISK_ICONS[risk] || '?';
  document.getElementById('risk-label').textContent = `${RISK_LABELS[risk]} — ${result.threats.length} finding${result.threats.length === 1 ? '' : 's'}`;
  document.getElementById('risk-detail').textContent = RISK_DETAIL[risk] || '';

  // Threats list
  const list = document.getElementById('threats-list');
  list.innerHTML = '';
  for (const threat of result.threats) {
    const el = document.createElement('div');
    el.className = `threat sev-${threat.severity}`;
    el.innerHTML = `
      <div class="threat-header">
        <span class="threat-type">${escapeHtml(threat.type)}</span>
        <span class="threat-sev sev-${threat.severity}">${threat.severity}</span>
      </div>
      <div class="threat-description">${escapeHtml(threat.description)}</div>
      <div class="threat-evidence">${escapeHtml(threat.evidence)}</div>
      <div class="threat-confidence">Confidence: ${Math.round(threat.confidence * 100)}%</div>
    `;
    list.appendChild(el);
  }

  // Page meta
  document.getElementById('threat-url').textContent = truncateMid(scan.url, 45);
  document.getElementById('threat-title').textContent = scan.title || '(untitled)';

  showState('state-threats');
}

// ─── Utilities ──────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function truncateMid(s, n) {
  if (!s || s.length <= n) return s;
  const half = Math.floor((n - 1) / 2);
  return s.slice(0, half) + '…' + s.slice(-half);
}

// ─── Wire up ────────────────────────────────────────────────────
async function init() {
  // Get current sensitivity setting
  const { sensitivity = 'standard' } = await chrome.storage.local.get('sensitivity');
  document.getElementById('sensitivity-display').textContent = `sensitivity: ${sensitivity}`;

  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    showState('state-no-data');
    return;
  }

  // Ask background for the scan result for this tab
  const scan = await chrome.runtime.sendMessage({ type: 'GET_TAB_SCAN', tabId: tab.id });

  if (!scan) {
    showState('state-no-data');
    return;
  }

  if (scan.result.threats.length === 0) {
    renderClean(scan);
  } else {
    renderThreats(scan);
  }
}

// Button handlers
document.getElementById('btn-rescan').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    await chrome.runtime.sendMessage({ type: 'CLEAR_TAB_SCAN', tabId: tab.id });
    chrome.tabs.reload(tab.id);
    window.close();
  }
});

document.getElementById('btn-options').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

init();
