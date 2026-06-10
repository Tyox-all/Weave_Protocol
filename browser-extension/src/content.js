/**
 * Weave Browser Guard — content script.
 *
 * Runs on every page (excluding sensitive sites per manifest exclusion list).
 * Scans the rendered HTML for IPI patterns and reports results to the
 * background service worker, which updates the icon badge and stores
 * results for the popup to display.
 *
 * Read-only: we don't modify the DOM, don't intercept requests, don't
 * inject anything visible to the user. Just inspect and report.
 */

(async () => {
  // Bail on sensitive contexts — never scan in iframes
  if (window.self !== window.top) return;

  // Bail on non-HTTP(S) schemes
  if (!/^https?:/.test(location.protocol)) return;

  // Dynamically import the scanner (allowed via web_accessible_resources)
  const scannerUrl = chrome.runtime.getURL('src/scanner.js');
  const { scanForIpi } = await import(scannerUrl);

  // Capture the rendered HTML — outerHTML of <html> gives the full document
  // including any DOM modifications by JS that ran before document_idle.
  const html = document.documentElement.outerHTML;

  // Get user-configured sensitivity
  const { sensitivity = 'standard' } = await chrome.storage.local.get('sensitivity');

  const result = scanForIpi(html, { isHtml: true });

  // Determine display state based on sensitivity
  const shouldAlert = displayThreshold(result.riskLevel, sensitivity);

  // Send to background to update badge + store for popup
  chrome.runtime.sendMessage({
    type: 'SCAN_COMPLETE',
    payload: {
      url: location.href,
      title: document.title,
      timestamp: Date.now(),
      result,
      shouldAlert,
    },
  });
})();

function displayThreshold(risk, sensitivity) {
  if (sensitivity === 'strict') return risk !== 'none';
  if (sensitivity === 'standard') return risk === 'high' || risk === 'critical';
  return risk === 'critical'; // lenient
}
