// Try production backend first, fall back to localhost for dev.
// The PRODUCTION_URL must match what's in manifest.json host_permissions.
const PRODUCTION_URL = "https://phishpipeline-production-2212.up.railway.app";
const LOCAL_URL = "http://localhost:8000";

let API_BASE = LOCAL_URL; // default until resolveApiBase() completes

const LAST_RESULT_KEY = "pp_last_result";

// Ask background.js for the resolved backend (it health-checks production
// then localhost and caches the winner). Falls back to direct probing if
// the service worker is unavailable.
async function resolveApiBase() {
  const viaBackground = await new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "GET_API_BASE" }, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response?.base || null);
      });
    } catch {
      resolve(null);
    }
  });

  if (viaBackground) {
    API_BASE = viaBackground;
    return viaBackground;
  }

  // Fallback: probe directly (production first, then localhost)
  for (const [base, timeout] of [
    [PRODUCTION_URL, 4000],
    [LOCAL_URL, 2000],
  ]) {
    try {
      const r = await fetch(`${base}/api/health`, {
        signal: AbortSignal.timeout(timeout),
      });
      if (r.ok) {
        API_BASE = base;
        return base;
      }
    } catch {
      // try next
    }
  }
  return null; // both offline
}

const resultEl = document.getElementById("result");
const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const tabBtn = document.getElementById("tabBtn");
const connDot = document.getElementById("connDot");
const modelInfoEl = document.getElementById("modelInfo");

// Populated from GET /api/model-info at popup open; every verdict shown in
// this popup comes exclusively from the PhishPipeline backend's ML model.
let modelInfo = null;

const STAGE_LABELS = {
  URL_ONLY: "Stage 1 — URL model",
  URL_ONLY_FALLBACK: "Stage 1 — URL model (fallback)",
  HYBRID: "Stage 2 — URL + HTML models",
};

function modelBadge(data) {
  const stage = STAGE_LABELS[data.stage] || "ML model";
  const version =
    modelInfo && modelInfo.current_version != null
      ? `model v${modelInfo.current_version}`
      : "base model";
  return `<div class="pp-model-badge">🧠 ${escHtml(stage)} · ${escHtml(version)}</div>`;
}

// ── State renderer ────────────────────────────────────────────────

function render(state, data = {}) {
  resultEl.style.display = "block";

  if (state === "classifying") {
    resultEl.innerHTML = `
      <div class="pp-result-card classifying">
        <div class="pp-classifying-row">
          <div class="pp-pulse-dot"></div>
          <span>Classifying with PhishPipeline ML model…</span>
        </div>
        <div class="pp-shimmer"></div>
        <div class="pp-result-url">${escHtml(data.url || "")}</div>
      </div>`;
  }

  else if (state === "phishing") {
    const pct = Math.round((data.confidence || 0) * 100);
    resultEl.innerHTML = `
      <div class="pp-result-card phishing">
        <div class="pp-result-label" style="color:#FF6B6B">⚠ Phishing Detected</div>
        <div class="pp-conf-bar-track">
          <div class="pp-conf-bar-fill"
               style="width:${pct}%;background:#C00000"></div>
        </div>
        <div class="pp-conf-text">${pct}% confidence</div>
        ${data.attack_category ?
          `<div class="pp-result-sub">Attack type: ${escHtml(data.attack_category)}</div>`
          : ""}
        <div class="pp-result-url">${escHtml(data.url || "")}</div>
        ${(data.adversarial_flags || []).length > 0 ?
          `<div style="margin-top:10px;font-size:11px;color:#F0A93B">
            ${data.adversarial_flags.map((f) => `⚠ ${escHtml(f)}`).join("<br>")}
          </div>` : ""}
        ${modelBadge(data)}
      </div>`;
  }

  else if (state === "clean") {
    const pct = Math.round((data.confidence || 0) * 100);
    resultEl.innerHTML = `
      <div class="pp-result-card clean">
        <div class="pp-result-label" style="color:#3FDC7F">✓ Clean</div>
        <div class="pp-conf-bar-track">
          <div class="pp-conf-bar-fill"
               style="width:${pct}%;background:#1F9D4F"></div>
        </div>
        <div class="pp-conf-text">${pct}% confidence</div>
        <div class="pp-result-sub">No threats detected · safe to proceed</div>
        <div class="pp-result-url">${escHtml(data.url || "")}</div>
        ${modelBadge(data)}
      </div>`;
  }

  else if (state === "offline") {
    resultEl.innerHTML = `
      <div class="pp-result-card offline">
        <div class="pp-result-label" style="color:#F0A93B">⚡ Backend Offline</div>
        <div class="pp-result-sub">Could not reach PhishPipeline server.<br>
          Make sure the backend is running on port 8000.</div>
      </div>`;
  }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── Scan logic ────────────────────────────────────────────────────

async function scan(rawUrl) {
  let url = rawUrl.trim();
  if (!url) return;
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  scanBtn.disabled = true;
  tabBtn.disabled = true;
  render("classifying", { url });

  try {
    const res = await fetch(`${API_BASE}/api/submit-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const resultData = { ...data, url };

    // Persist for popup reopen
    chrome.storage.session.set({
      [LAST_RESULT_KEY]: { state: data.label, data: resultData },
    });

    render(data.label === "phishing" ? "phishing" : "clean", resultData);
  } catch (e) {
    render("offline");
  } finally {
    scanBtn.disabled = false;
    tabBtn.disabled = false;
  }
}

// ── Event listeners ───────────────────────────────────────────────

scanBtn.addEventListener("click", () => scan(urlInput.value));

urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") scan(urlInput.value);
});

tabBtn.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.url) {
      urlInput.value = tabs[0].url;
      scan(tabs[0].url);
    }
  });
});

// ── Init ──────────────────────────────────────────────────────────

async function init() {
  const resolved = await resolveApiBase();

  if (resolved) {
    connDot.className = "pp-conn-dot online";
    connDot.title = `Connected: ${resolved}`;
  } else {
    connDot.className = "pp-conn-dot offline";
    connDot.title = "No backend reachable";
  }

  // Load which ML model is serving classifications, so every verdict in
  // the popup is attributed to the exact deployed PhishPipeline model.
  try {
    const r = await fetch(`${API_BASE}/api/model-info`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      modelInfo = await r.json();
      if (modelInfoEl) {
        const version =
          modelInfo.current_version != null
            ? `v${modelInfo.current_version} (retrained)`
            : "base";
        const shortName = String(modelInfo.stage1_model || "").split("/").pop();
        modelInfoEl.textContent = `Model: ${shortName} · ${version}`;
      }
    }
  } catch {
    if (modelInfoEl) modelInfoEl.textContent = "Model info unavailable";
  }

  // Restore last result if popup was reopened
  chrome.storage.session.get([LAST_RESULT_KEY], (result) => {
    const saved = result[LAST_RESULT_KEY];
    if (saved) {
      urlInput.value = saved.data?.url || "";
      render(saved.state, saved.data);
    }
  });
}

init();
