import { useEffect, useRef, useState } from "react";
import { api } from "../api/client.js";
import ResultCard from "./ResultCard.jsx";
import { useToast } from "../context/ToastContext.jsx";

const POLL_INTERVAL_MS = 2000;
const MAX_ROWS_IN_STATE = 50;
const MAX_VISIBLE_ROWS = 11;
const FLASH_DURATION_MS = 950;
const STREAMING_WINDOW_MS = 5000;

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function formatTime(timestamp) {
  if (!timestamp) return "--:--:--";
  const date = new Date(timestamp.endsWith("Z") ? timestamp : `${timestamp}Z`);
  if (Number.isNaN(date.getTime())) {
    return "--:--:--";
  }
  return date.toLocaleTimeString("en-GB", { hour12: false });
}

// Suspicion boundary: scores above 35 indicate phishing-level suspicion,
// 35 and below do not.
const SUSPICION_PHISHING_THRESHOLD = 35;

function suspicionTier(score) {
  return score > SUSPICION_PHISHING_THRESHOLD ? "high" : "low";
}

function SuspicionPill({ score }) {
  if (score == null) {
    // User-submitted URLs have no CT-feed suspicion score.
    return <span className="pp-pill pp-pill-none">—</span>;
  }
  const tier = suspicionTier(score);
  const className =
    tier === "high" ? "pp-pill pp-pill-high" : "pp-pill pp-pill-low";
  const label = tier === "high" ? "HIGH" : "LOW";
  return (
    <span className={className}>
      {score} · {label}
    </span>
  );
}

function StatusBadge({ row }) {
  if (row.status === "pending") {
    return (
      <span className="pp-badge pp-badge-pending">
        Classifying
        <span className="pp-badge-dots">
          <span className="pp-badge-dot" />
          <span className="pp-badge-dot" />
          <span className="pp-badge-dot" />
        </span>
      </span>
    );
  }

  if (row.label === "phishing") {
    return <span className="pp-badge pp-badge-phishing">Phishing</span>;
  }

  return <span className="pp-badge pp-badge-clean">Clean</span>;
}

function Toggle({ on, onToggle }) {
  return (
    <button
      type="button"
      className={`pp-toggle-switch ${on ? "pp-on" : "pp-off"}`}
      onClick={onToggle}
      aria-pressed={on}
    >
      <span className="pp-toggle-knob" />
    </button>
  );
}

function modalStateForRow(row) {
  if (row.status === "pending") return "classifying";
  if (row.label === "phishing") return "phishing";
  return "clean";
}

function Dashboard() {
  const showToast = useToast();

  const [rows, setRows] = useState([]);
  const [flashIds, setFlashIds] = useState(new Set());
  const [lastPollOkAt, setLastPollOkAt] = useState(null);
  const [, forceTick] = useState(0);
  const knownIdsRef = useRef(new Set());
  const flashTimersRef = useRef(new Map());

  const [phishingOnly, setPhishingOnly] = useState(false);
  const [highScoreOnly, setHighScoreOnly] = useState(false);
  const [hideWildcards, setHideWildcards] = useState(false);
  const [threshold, setThreshold] = useState(30);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const res = await api.get("/api/queue", {
          phishing_only: phishingOnly || undefined,
          high_score_only: highScoreOnly || undefined,
          hide_wildcards: hideWildcards || undefined,
          min_score: threshold > 0 ? threshold : undefined,
          limit: MAX_ROWS_IN_STATE,
        });
        if (!res.ok) return;
        const data = await res.json();
        const fetched = Array.isArray(data) ? data : data.rows || [];
        if (cancelled) return;

        setLastPollOkAt(Date.now());

        const newlyAdded = [];
        for (const row of fetched) {
          if (!knownIdsRef.current.has(row.id)) {
            knownIdsRef.current.add(row.id);
            newlyAdded.push(row.id);
          }
        }

        setRows((prev) => {
          const byId = new Map(prev.map((r) => [r.id, r]));
          for (const row of fetched) {
            byId.set(row.id, row);
          }
          const merged = Array.from(byId.values()).sort(
            (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
          );
          return merged.slice(0, MAX_ROWS_IN_STATE);
        });

        if (newlyAdded.length > 0) {
          setFlashIds((prevFlash) => {
            const nextFlash = new Set(prevFlash);
            newlyAdded.forEach((id) => nextFlash.add(id));
            return nextFlash;
          });

          newlyAdded.forEach((id) => {
            const existingTimer = flashTimersRef.current.get(id);
            if (existingTimer) clearTimeout(existingTimer);
            const timer = setTimeout(() => {
              setFlashIds((prevFlash) => {
                const nextFlash = new Set(prevFlash);
                nextFlash.delete(id);
                return nextFlash;
              });
              flashTimersRef.current.delete(id);
            }, FLASH_DURATION_MS);
            flashTimersRef.current.set(id, timer);
          });
        }
      } catch {
        // backend unreachable — badge falls back to Offline via lastPollOkAt age
      } finally {
        if (!cancelled) forceTick((t) => t + 1);
      }
    }

    poll();
    const interval = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(interval);
      flashTimersRef.current.forEach((timer) => clearTimeout(timer));
      flashTimersRef.current.clear();
    };
  }, [phishingOnly, highScoreOnly, hideWildcards, threshold]);

  const isStreaming =
    lastPollOkAt !== null && Date.now() - lastPollOkAt < STREAMING_WINDOW_MS;

  const [checkInput, setCheckInput] = useState("");
  const [checkState, setCheckState] = useState("idle");
  const [checkUrl, setCheckUrl] = useState("");
  const [checkConfidence, setCheckConfidence] = useState(0);
  const [checkStage, setCheckStage] = useState("URL_ONLY");
  const [checkFlags, setCheckFlags] = useState([]);
  const [checkClassifiedIn, setCheckClassifiedIn] = useState("0.3s");

  const [modalRow, setModalRow] = useState(null);

  const filteredRows = rows.filter((row) => {
    const score = row.suspicion_score;

    if (phishingOnly && row.label !== "phishing") return false;
    if (highScoreOnly && (score ?? 0) < 70) return false;
    if (hideWildcards && row.url.includes("*")) return false;
    if (threshold > 0 && score != null && score < threshold) return false;

    return true;
  });

  const visibleRows = filteredRows.slice(0, MAX_VISIBLE_ROWS);

  function runCheck(rawUrl) {
    const trimmed = rawUrl.trim();
    if (!trimmed) return;

    const normalizedUrl =
      trimmed.startsWith("http://") || trimmed.startsWith("https://")
        ? trimmed
        : `https://${trimmed}`;

    setCheckUrl(normalizedUrl);
    setCheckState("classifying");
    const startedAt = performance.now();

    api
      .post("/api/submit-url", { url: normalizedUrl })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        const elapsedSeconds = ((performance.now() - startedAt) / 1000).toFixed(1);
        setCheckConfidence(data.confidence || 0);
        setCheckStage(data.stage || "URL_ONLY");
        setCheckFlags(data.adversarial_flags || []);
        setCheckClassifiedIn(`${elapsedSeconds}s`);
        setCheckState(data.label === "phishing" ? "phishing" : "clean");
        if (data.label === "phishing") {
          showToast(`Phishing detected: ${normalizedUrl}`, "error");
        }
      })
      .catch(() => {
        setCheckState("idle");
        showToast("Backend offline or invalid URL", "error");
      });
  }

  function handleCheckNow() {
    runCheck(checkInput);
  }

  function handleViewRow(row) {
    setModalRow(row);
  }

  function closeModal() {
    setModalRow(null);
  }

  function handleExportCsv() {
    const header =
      "id,url,source,timestamp,label,confidence,suspicion_score,attack_category,status";
    const escape = (value) => {
      const s = value == null ? "" : String(value);
      return s.includes(",") || s.includes('"')
        ? `"${s.replace(/"/g, '""')}"`
        : s;
    };
    const lines = filteredRows.map((row) =>
      [
        row.id,
        row.url,
        row.source,
        row.timestamp,
        row.label,
        row.confidence,
        row.suspicion_score,
        row.attack_category,
        row.status,
      ]
        .map(escape)
        .join(",")
    );
    const csv = [header, ...lines].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const link = document.createElement("a");
    const date = new Date().toISOString().slice(0, 10);
    link.href = URL.createObjectURL(blob);
    link.download = `phishpipeline-export-${date}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast("CSV exported", "success");
  }

  return (
    <>
      <div className="pp-main">
        <div className="pp-left-panel">
          <div className="pp-feed-header">
            <span className="pp-feed-title">Live Certstream Feed</span>
            {isStreaming ? (
              <div className="pp-streaming-badge">
                <span className="pp-streaming-dot" />
                <span>Streaming</span>
              </div>
            ) : (
              <div className="pp-offline-badge">
                <span className="pp-offline-dot" />
                <span>Offline</span>
              </div>
            )}
          </div>

          <div className="pp-row-grid pp-col-headers">
            <div>Time</div>
            <div>Domain</div>
            <div>Suspicion</div>
            <div>Status</div>
            <div>Action</div>
          </div>

          <div className="pp-feed-body">
            {visibleRows.length === 0 && (
              <div className="pp-empty-state">Waiting for domains to arrive…</div>
            )}
            {visibleRows.map((row) => (
              <div
                key={row.id}
                className={`pp-row-grid pp-feed-row ${
                  flashIds.has(row.id) ? "pp-row-flash" : ""
                }`}
              >
                <div className="pp-cell-time">{formatTime(row.timestamp)}</div>
                <div className="pp-cell-domain" title={extractDomain(row.url)}>
                  {extractDomain(row.url)}
                </div>
                <div>
                  <SuspicionPill score={row.suspicion_score} />
                </div>
                <div>
                  <StatusBadge row={row} />
                </div>
                <div>
                  <button
                    type="button"
                    className="pp-view-btn"
                    onClick={() => handleViewRow(row)}
                  >
                    View
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="pp-right-column">
          <div className="pp-panel">
            <div className="pp-panel-title">Check a URL</div>
            <div className="pp-check-row">
              <input
                type="text"
                className="pp-check-input"
                placeholder="Enter a URL or domain"
                value={checkInput}
                onChange={(e) => setCheckInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCheckNow();
                }}
              />
              <button type="button" className="pp-check-btn" onClick={handleCheckNow}>
                Check Now
              </button>
            </div>
            <button
              type="button"
              className="pp-check-tab-btn"
              disabled
              title="Only available in the browser extension"
            >
              Check Current Tab
            </button>
            {checkState !== "idle" && (
              <div className="pp-result-wrap">
                <ResultCard
                  state={checkState}
                  url={checkUrl}
                  confidence={checkConfidence}
                  stage={checkStage}
                  adversarialFlags={checkFlags}
                  classifiedIn={checkClassifiedIn}
                />
              </div>
            )}
          </div>

          <div className="pp-panel pp-filter-panel">
            <div className="pp-panel-title">Filter Controls</div>

            <div className="pp-toggle-row">
              <span>Show Phishing Only</span>
              <Toggle on={phishingOnly} onToggle={() => setPhishingOnly((v) => !v)} />
            </div>
            <div className="pp-toggle-row">
              <span>High Score Only (&ge;70)</span>
              <Toggle on={highScoreOnly} onToggle={() => setHighScoreOnly((v) => !v)} />
            </div>
            <div className="pp-toggle-row">
              <span>Hide Wildcards</span>
              <Toggle on={hideWildcards} onToggle={() => setHideWildcards((v) => !v)} />
            </div>

            <div className="pp-threshold-row">
              <span>Score threshold</span>
              <span className="pp-threshold-value">&ge; {threshold}</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="pp-threshold-slider"
            />

            <div className="pp-filter-footer">
              <span className="pp-shown-count">
                {filteredRows.length} of {rows.length} shown
              </span>
              <button type="button" className="pp-export-btn" onClick={handleExportCsv}>
                Export CSV
              </button>
            </div>
          </div>
        </div>
      </div>

      {modalRow && (
        <div className="pp-modal-overlay rc-modal-backdrop" onClick={closeModal}>
          <div
            className="pp-modal-box rc-modal-content"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              className="rc-modal-close"
              onClick={closeModal}
              aria-label="Close"
            >
              ✕
            </button>
            <ResultCard
              state={modalStateForRow(modalRow)}
              url={modalRow.url}
              confidence={modalRow.confidence || 0}
              stage={modalRow.stage || "URL_ONLY"}
              adversarialFlags={modalRow.adversarial_flags || []}
              classifiedIn="—"
            />
          </div>
        </div>
      )}
    </>
  );
}

export default Dashboard;
