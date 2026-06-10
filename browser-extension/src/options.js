/**
 * Weave Browser Guard — options page.
 * Persists sensitivity choice to chrome.storage.local.
 */

async function init() {
  const { sensitivity = 'standard' } = await chrome.storage.local.get('sensitivity');
  const input = document.querySelector(`input[name="sensitivity"][value="${sensitivity}"]`);
  if (input) input.checked = true;

  // Persist on change
  for (const radio of document.querySelectorAll('input[name="sensitivity"]')) {
    radio.addEventListener('change', async () => {
      if (radio.checked) {
        await chrome.storage.local.set({ sensitivity: radio.value });
      }
    });
  }
}

init();
