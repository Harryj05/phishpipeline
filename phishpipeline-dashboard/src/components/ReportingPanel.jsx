import { useEffect, useState } from "react";
import { api } from "../api/client.js";

const POLL_INTERVAL_MS = 5000;
const PAGE_SIZE = 10;

const STATUSES = ["ALL", "SUBMITTED", "FAILED", "PENDING"];
const CHANNELS = ["ALL", "GSB", "PHISHTANK", "OPENPHISH", "REGISTRAR"];
const CH_KEYS = {
  GSB: "gsb",
  PHISHTANK: "phishtank",
  OPENPHISH: "openphish",
  REGISTRAR: "registrar",
};
const STATUS_FILTER_CODE = { SUBMITTED: "submitted", FAILED: "failed", PENDING: "pending" };

const ICON_META = {
  submitted: { icon: "✓", bg: "rgba(0,100,0,.25)", fg: "#3FDC7F", title: "Submitted" },
  failed: { icon: "✗", bg: "rgba(192,0,0,.22)", fg: "#FF6B6B", title: "Failed" },
  pending: { icon: "⏳", bg: "rgba(180,83,9,.22)", fg: "#F0A93B", title: "Pending" },
  skipped: { icon: "—", bg: "rgba(148,163,184,.12)", fg: "#6B7C8D", title: "Skipped — no API key" },
};

function relativeTime(timestamp) {
  if (!timestamp) return "—";
  const date = new Date(timestamp.endsWith("Z") ? timestamp : `${timestamp}Z`);
  if (Number.isNaN(date.getTime())) return "—";
  const diffMs = Date.now() - date.getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function truncateUrl(url, max = 35) {
  if (!url) return "";
  return url.length > max ? `${url.slice(0, max - 1)}…` : url;
}

function StatusPills({ options, current, onSelect }) {
  return (
    <div className="rp-pill-group">
      {options.map((label) => (
        <button
          key={label}
          type="button"
          className={`rp-pill ${current === label ? "rp-pill-active" : ""}`}
          onClick={() => onSelect(label)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

function ChannelIcon({ code }) {
  const meta = ICON_META[code] || ICON_META.skipped;
  return (
    <span
      className="rp-icon-dot"
      title={meta.title}
      style={{ background: meta.bg, color: meta.fg }}
    >
      {meta.icon}
    </span>
  );
}

function ReportingPanel() {
  const [reports, setReports] = useState([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState({ submitted: 0, failed: 0, pending: 0 });
  const [status, setStatus] = useState("ALL");
  const [channel, setChannel] = useState("ALL");
  const [page, setPage] = useState(1);
  const [drawerId, setDrawerId] = useState(null);
  const [drawerData, setDrawerData] = useState(null);
  const [infoOpen, setInfoOpen] = useState(true);
  const [showJson, setShowJson] = useState(false);
  const [retryingRowIds, setRetryingRowIds] = useState(new Set());
  const [toast, setToast] = useState(null);

  async function fetchReports() {
    try {
      const res = await api.get("/api/reports", {
        page,
        limit: PAGE_SIZE,
        status: status !== "ALL" ? STATUS_FILTER_CODE[status] : undefined,
        channel: channel !== "ALL" ? CH_KEYS[channel] : undefined,
      });
      if (!res.ok) return;
      const data = await res.json();
      setReports(Array.isArray(data.rows) ? data.rows : []);
      setTotal(data.total ?? 0);
      if (data.summary) setSummary(data.summary);
    } catch {
      // backend unreachable — silently skip this poll cycle
    }
  }

  useEffect(() => {
    fetchReports();
    const interval = setInterval(fetchReports, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, status, channel]);

  async function fetchDrawerData(urlId) {
    try {
      const res = await api.get(`/api/reports/${urlId}`);
      if (!res.ok) return;
      const data = await res.json();
      setDrawerData(data);
    } catch {
      // backend unreachable — leave drawer stale
    }
  }

  useEffect(() => {
    if (drawerId != null) fetchDrawerData(drawerId);
  }, [drawerId]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2500);
    return () => clearTimeout(t);
  }, [toast]);

  const channelStatus = (entry, key) => entry.channels?.[key]?.status;
  const rowStatuses = (entry) =>
    Object.values(entry.channels || {}).map((c) => c?.status);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageRows = reports;

  const submittedCount = summary.submitted;
  const failedCount = summary.failed;
  const pendingCount = summary.pending;

  function handleFilterChange(setter, value) {
    setter(value);
    setPage(1);
  }

  function handleRetryRow(urlId) {
    setRetryingRowIds((prev) => new Set(prev).add(urlId));
    api.post(`/api/reports/retry/${urlId}`)
      .then(() => {
        setTimeout(async () => {
          await fetchReports();
          if (drawerId === urlId) await fetchDrawerData(urlId);
          setRetryingRowIds((prev) => {
            const next = new Set(prev);
            next.delete(urlId);
            return next;
          });
          setToast("Retry submitted");
        }, 1200);
      })
      .catch(() => {
        setRetryingRowIds((prev) => {
          const next = new Set(prev);
          next.delete(urlId);
          return next;
        });
      });
  }

  const activeEntry = reports.find((e) => e.url_queue_id === drawerId);

  // Full report detail as a plain object, suitable for JSON export/copy.
  const reportJson =
    activeEntry &&
    JSON.stringify(
      {
        url_queue_id: activeEntry.url_queue_id,
        url: activeEntry.url,
        reported_at: activeEntry.reported_at,
        detection: {
          confidence: drawerData?.confidence ?? null,
          attack_category: drawerData?.attack_category ?? null,
          first_seen: drawerData?.first_seen ?? null,
        },
        channels: activeEntry.channels,
        reports: drawerData?.reports ?? [],
      },
      null,
      2
    );

  function copyJson() {
    if (!reportJson) return;
    navigator.clipboard
      ?.writeText(reportJson)
      .then(() => setToast("JSON copied to clipboard"))
      .catch(() => setToast("Copy failed"));
  }

  function downloadJson() {
    if (!reportJson || !activeEntry) return;
    const blob = new Blob([reportJson], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `report-${activeEntry.url_queue_id}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    setToast("JSON downloaded");
  }

  return (
    <div className="rp-wrap">
      <div className="rp-panel">
        <div className="rp-header">
          <div className="rp-title">Automated Reports</div>
          <div className="rp-summary-badges">
            <span className="rp-badge rp-badge-submitted">{submittedCount} submitted</span>
            <span className="rp-badge rp-badge-failed">{failedCount} failed</span>
            <span className="rp-badge rp-badge-pending">{pendingCount} pending</span>
          </div>
        </div>

        <div className="rp-filter-bar">
          <div className="rp-filter-group">
            <span className="rp-filter-label">Status</span>
            <StatusPills
              options={STATUSES}
              current={status}
              onSelect={(v) => handleFilterChange(setStatus, v)}
            />
          </div>
          <div className="rp-filter-group">
            <span className="rp-filter-label">Channel</span>
            <StatusPills
              options={CHANNELS}
              current={channel}
              onSelect={(v) => handleFilterChange(setChannel, v)}
            />
          </div>
        </div>

        <div className="rp-row rp-row-header">
          <div>URL</div>
          <div className="rp-col-center">GSB</div>
          <div className="rp-col-center">PhishTank</div>
          <div className="rp-col-center">OpenPhish</div>
          <div className="rp-col-center">Registrar</div>
          <div>Reported</div>
          <div className="rp-col-right">Actions</div>
        </div>

        <div>
          {pageRows.length === 0 && (
            <div className="rp-empty-state">No reports match the current filters</div>
          )}
          {pageRows.map((entry, i) => {
            const hasFailed = rowStatuses(entry).includes("failed");
            return (
              <div
                key={entry.url_queue_id}
                className="rp-row"
                style={{ background: i % 2 === 0 ? "#162233" : "#1A2940" }}
              >
                <div className="rp-cell-url" title={entry.url}>
                  {truncateUrl(entry.url)}
                </div>
                <div className="rp-col-center">
                  <ChannelIcon code={channelStatus(entry, "gsb")} />
                </div>
                <div className="rp-col-center">
                  <ChannelIcon code={channelStatus(entry, "phishtank")} />
                </div>
                <div className="rp-col-center">
                  <ChannelIcon code={channelStatus(entry, "openphish")} />
                </div>
                <div className="rp-col-center">
                  <ChannelIcon code={channelStatus(entry, "registrar")} />
                </div>
                <div className="rp-cell-reported">{relativeTime(entry.reported_at)}</div>
                <div className="rp-cell-actions">
                  {hasFailed && (
                    <button
                      type="button"
                      className="rp-action-retry"
                      onClick={() => handleRetryRow(entry.url_queue_id)}
                      disabled={retryingRowIds.has(entry.url_queue_id)}
                    >
                      {retryingRowIds.has(entry.url_queue_id)
                        ? "Retrying…"
                        : "Retry Failed"}
                    </button>
                  )}
                  <button
                    type="button"
                    className="rp-action-details"
                    onClick={() => {
                      setDrawerId(entry.url_queue_id);
                      setInfoOpen(true);
                    }}
                  >
                    Details ↗
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        <div className="rp-pagination">
          <span>
            Showing {total === 0 ? 0 : (safePage - 1) * PAGE_SIZE + 1}–
            {Math.min((safePage - 1) * PAGE_SIZE + pageRows.length, total)} of{" "}
            {total}
          </span>
          <div className="rp-pagination-btns">
            <button
              type="button"
              className="rp-page-btn"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Prev
            </button>
            <button
              type="button"
              className="rp-page-btn"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {activeEntry && (
        <>
          <div className="rp-drawer-backdrop" onClick={() => setDrawerId(null)} />
          <div className="rp-drawer">
            <div className="rp-drawer-header">
              <div className="rp-drawer-header-text">
                <div className="rp-drawer-eyebrow">Report Detail</div>
                <div className="rp-drawer-url">{activeEntry.url}</div>
                <div className="rp-drawer-subtitle">
                  Reported {relativeTime(activeEntry.reported_at)}
                </div>
              </div>
              <button
                type="button"
                className="rp-drawer-close"
                onClick={() => setDrawerId(null)}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <div className="rp-drawer-actions">
              <button
                type="button"
                className={`rp-json-toggle ${showJson ? "active" : ""}`}
                onClick={() => setShowJson((v) => !v)}
              >
                {showJson ? "Hide JSON" : "View JSON"}
              </button>
              <button type="button" className="rp-json-btn" onClick={copyJson}>
                Copy
              </button>
              <button type="button" className="rp-json-btn" onClick={downloadJson}>
                Download
              </button>
            </div>

            <div className="rp-drawer-body">
              {showJson && (
                <pre className="rp-json-view">{reportJson}</pre>
              )}

              <div className="rp-info-section">
                <div
                  className="rp-info-header"
                  onClick={() => setInfoOpen((v) => !v)}
                >
                  <span>Detection Info</span>
                  <span
                    className="rp-info-chevron"
                    style={{ transform: infoOpen ? "rotate(0deg)" : "rotate(-90deg)" }}
                  >
                    ▾
                  </span>
                </div>
                {infoOpen && (
                  <div className="rp-info-body">
                    <div className="rp-info-row">
                      <span>Confidence score</span>
                      <b className="rp-info-confidence">
                        {drawerData?.confidence != null
                          ? drawerData.confidence.toFixed(2)
                          : "—"}
                      </b>
                    </div>
                    <div className="rp-info-row">
                      <span>Attack category</span>
                      <span className="rp-info-value">
                        {drawerData?.attack_category || "—"}
                      </span>
                    </div>
                    <div className="rp-info-row">
                      <span>Time first seen</span>
                      <span className="rp-info-value">
                        {relativeTime(drawerData?.first_seen)}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {toast && <div className="rp-toast">{toast}</div>}
    </div>
  );
}

export default ReportingPanel;
