const PRODUCTION_URL = "https://phishpipeline-backend.up.railway.app";
const LOCAL_URL = "http://localhost:8000";

// Cache the resolved URL so popup doesn't need to re-discover it
let resolvedBase = null;

async function getApiBase() {
  if (resolvedBase) return resolvedBase;

  for (const base of [PRODUCTION_URL, LOCAL_URL]) {
    try {
      const r = await fetch(`${base}/api/health`, {
        signal: AbortSignal.timeout(4000),
      });
      if (r.ok) {
        resolvedBase = base;
        return base;
      }
    } catch {
      continue;
    }
  }
  return null;
}

// Resolve on extension startup so popup gets it instantly
getApiBase().then((base) => {
  if (base) {
    chrome.storage.session.set({ pp_api_base: base });
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_API_BASE") {
    getApiBase().then((base) => sendResponse({ base }));
    return true; // async response
  }
  if (msg.type === "PING") {
    sendResponse({ alive: true });
  }
  return true;
});
