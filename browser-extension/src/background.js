/**
 * Weave Browser Guard — background service worker.
 *
 * Listens for scan results from content scripts, updates the tab's badge,
 * and stores results so the popup can display them.
 *
 * Storage strategy: keep the last result per tab keyed by tabId. When the tab
 * navigates or closes, results are pruned.
 */

const BADGE_COLORS = {
  none: '#10b981',     // green
  low: '#10b981',      // green (still safe-ish)
  medium: '#f59e0b',   // amber
  high: '#ef4444',     // red
  critical: '#a855f7', // purple (skull-tier)
};

const BADGE_TEXT = {
  none: '',
  low: '!',
  medium: '!',
  high: '✗',
  critical: '☠',
};

// In-memory cache of last scan per tab
const lastScans = new Map();

// ─── Message handling ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_COMPLETE') {
    const tabId = sender.tab?.id;
    if (tabId == null) return;
    handleScanComplete(tabId, message.payload);
    return;
  }

  if (message.type === 'GET_TAB_SCAN') {
    const tabId = message.tabId;
    sendResponse(lastScans.get(tabId) ?? null);
    return true; // async response
  }

  if (message.type === 'CLEAR_TAB_SCAN') {
    lastScans.delete(message.tabId);
    chrome.action.setBadgeText({ tabId: message.tabId, text: '' });
    return;
  }
});

// ─── Scan handling ────────────────────────────────────────────────
async function handleScanComplete(tabId, payload) {
  lastScans.set(tabId, payload);

  const risk = payload.result.riskLevel;
  const text = BADGE_TEXT[risk] || '';
  const color = BADGE_COLORS[risk] || '#6b7280';

  // Always update color
  chrome.action.setBadgeBackgroundColor({ tabId, color });

  // Only show badge text if there's something to alert on
  if (payload.shouldAlert && text) {
    chrome.action.setBadgeText({ tabId, text });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }

  // Optional: update tooltip
  const summary =
    risk === 'none'
      ? 'Weave Guard: page clean'
      : `Weave Guard: ${payload.result.threats.length} threat${payload.result.threats.length === 1 ? '' : 's'} detected (${risk.toUpperCase()})`;
  chrome.action.setTitle({ tabId, title: summary });
}

// ─── Tab lifecycle — clear on navigation away ─────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  lastScans.delete(tabId);
});

chrome.webNavigation?.onBeforeNavigate?.addListener?.((details) => {
  // Top-frame navigation only — clear stale data
  if (details.frameId === 0) {
    lastScans.delete(details.tabId);
    chrome.action.setBadgeText({ tabId: details.tabId, text: '' });
  }
});

// ─── First-install onboarding ─────────────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    // Set default sensitivity if not yet configured
    const existing = await chrome.storage.local.get('sensitivity');
    if (!existing.sensitivity) {
      await chrome.storage.local.set({ sensitivity: 'standard' });
    }
  }
});
