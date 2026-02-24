/* ============================================
   Hybrid AI Defense — Background Service Worker
   ============================================ */

// Extension install/update handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[Hybrid AI Defense] Extension installed successfully.');
  } else if (details.reason === 'update') {
    console.log(`[Hybrid AI Defense] Extension updated to v${chrome.runtime.getManifest().version}`);
  }
});
