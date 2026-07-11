import { useEffect, useState } from "react";
import { api } from "../api/client.js";
import { useToast } from "../context/ToastContext.jsx";

const POLL_INTERVAL_MS = 5000;
const FADE_DURATION_MS = 300;

function formatTimestamp(timestamp) {
  const date = new Date(timestamp.endsWith("Z") ? timestamp : `${timestamp}Z`);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleString("en-GB", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function confidenceTier(confidence, label) {
  if (label === "phishing") return "red";
  if (confidence < 0.7) return "amber";
  return "green";
}

function ConfidenceBar({ confidence, label }) {
  const percent = Math.round((confidence ?? 0) * 100);
  const tier = confidenceTier(confidence ?? 0, label);

  return (
    <div>
      <div className="admin-confidence-track">
        <div
          className={`admin-confidence-fill admin-confidence-${tier}`}
          style={{ width: `${percent}%` }}
        />
      </div>
      <div className="admin-confidence-value">{percent}%</div>
    </div>
  );
}

function SourceBadge({ source }) {
  const className =
    source === "certstream" ? "admin-source-certstream" : "admin-source-user";
  return <span className={`admin-source-badge ${className}`}>{source}</span>;
}

function FlaggedRow({ row, onLabel, isRemoving }) {
  return (
    <div className={`admin-row ${isRemoving ? "admin-row-fade-out" : ""}`}>
      <div className="admin-row-url" title={row.url}>
        {row.url}
      </div>
      <div className="admin-row-label">{row.label ?? "—"}</div>
      <ConfidenceBar confidence={row.confidence} label={row.label} />
      <SourceBadge source={row.source} />
      <div className="admin-row-time">{formatTimestamp(row.timestamp)}</div>
      <div className="admin-row-actions">
        <button
          type="button"
          className="admin-btn-tp"
          onClick={() => onLabel(row.id, "phishing")}
          disabled={isRemoving}
        >
          ✓ True Positive
        </button>
        <button
          type="button"
          className="admin-btn-fp"
          onClick={() => onLabel(row.id, "clean")}
          disabled={isRemoving}
        >
          ✗ False Positive
        </button>
      </div>
    </div>
  );
}

function AdminPanel() {
  const showToast = useToast();
  const [rows, setRows] = useState([]);
  const [removingIds, setRemovingIds] = useState(new Set());
  const [stats, setStats] = useState(null);

  const [sourceFilter, setSourceFilter] = useState("all");
  const [minConfidence, setMinConfidence] = useState(0);
  const [maxConfidence, setMaxConfidence] = useState(1);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  async function fetchFlagged() {
    try {
      const res = await api.get("/api/admin/flagged", {
        min_confidence: String(minConfidence),
        max_confidence: String(maxConfidence),
        source: sourceFilter,
        limit: "50",
      });
      if (!res.ok) return;
      const data = await res.json();
      setRows(data);
    } catch {
      // backend unreachable — silently skip this poll cycle
    }
  }

  async function fetchStats() {
    try {
      const res = await api.get("/api/admin/stats");
      if (!res.ok) return;
      setStats(await res.json());
    } catch {
      // backend unreachable — silently skip this poll cycle
    }
  }

  useEffect(() => {
    fetchFlagged();
    fetchStats();

    const interval = setInterval(() => {
      fetchFlagged();
      fetchStats();
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceFilter, minConfidence, maxConfidence]);

  function handleLabel(id, trueLabel) {
    setRemovingIds((prev) => new Set(prev).add(id));

    api
      .post("/api/admin/label", { id, true_label: trueLabel, labeled_by: "admin" })
      .then(() => {
        setTimeout(() => {
          setRows((prev) => prev.filter((row) => row.id !== id));
          setRemovingIds((prev) => {
            const next = new Set(prev);
            next.delete(id);
            return next;
          });
          fetchStats();
          showToast(
            trueLabel === "phishing" ? "Marked as true positive" : "Marked as false positive",
            "success"
          );
        }, FADE_DURATION_MS);
      })
      .catch(() => {
        setRemovingIds((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
        showToast("Backend unreachable — label not saved", "error");
      });
  }

  const visibleRows = rows.filter((row) => {
    if (dateFrom && new Date(row.timestamp) < new Date(dateFrom)) return false;
    if (dateTo && new Date(row.timestamp) > new Date(`${dateTo}T23:59:59`)) {
      return false;
    }
    return true;
  });

  return (
    <div className="admin-main">
      <div className="admin-left-panel">
        <div className="admin-panel-header">
          <span className="admin-panel-title">Flagged URLs for Review</span>
          <span className="admin-count-badge">
            {visibleRows.length} pending
          </span>
        </div>

        <div className="admin-filters">
          <div className="admin-filter-group">
            <label>Source</label>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <option value="all">All</option>
              <option value="user">User</option>
              <option value="certstream">Certstream</option>
            </select>
          </div>

          <div className="admin-filter-group">
            <label>
              Confidence: {minConfidence.toFixed(2)} – {maxConfidence.toFixed(2)}
            </label>
            <div className="admin-range-row">
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={minConfidence}
                onChange={(e) =>
                  setMinConfidence(
                    Math.min(Number(e.target.value), maxConfidence)
                  )
                }
              />
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={maxConfidence}
                onChange={(e) =>
                  setMaxConfidence(
                    Math.max(Number(e.target.value), minConfidence)
                  )
                }
              />
            </div>
          </div>

          <div className="admin-filter-group">
            <label>Date range</label>
            <div className="admin-date-row">
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
              />
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="admin-row-list">
          {visibleRows.length === 0 && (
            <div className="admin-empty-state">No URLs pending review</div>
          )}
          {visibleRows.map((row) => (
            <FlaggedRow
              key={row.id}
              row={row}
              onLabel={handleLabel}
              isRemoving={removingIds.has(row.id)}
            />
          ))}
        </div>
      </div>

      <div className="admin-right-column">
        <div className="admin-stats-card">
          <div className="admin-panel-title">Review Stats</div>

          <div className="admin-stat-row">
            <span className="admin-stat-label">True Positives</span>
            <span className="admin-stat-value admin-stat-tp">
              {stats?.true_positives ?? 0}
            </span>
          </div>
          <div className="admin-stat-row">
            <span className="admin-stat-label">False Positives</span>
            <span className="admin-stat-value admin-stat-fp">
              {stats?.false_positives ?? 0}
            </span>
          </div>
          <div className="admin-stat-row">
            <span className="admin-stat-label">FP Rate</span>
            <span className="admin-stat-value">
              {stats ? stats.fp_rate : 0}%
            </span>
          </div>
          <div className="admin-stat-row">
            <span className="admin-stat-label">Total Reviewed</span>
            <span className="admin-stat-value">
              {stats?.total_reviewed ?? 0}
            </span>
          </div>
          <div className="admin-stat-row">
            <span className="admin-stat-label">Pending Review</span>
            <span className="admin-stat-value">
              {stats?.pending_review ?? 0}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AdminPanel;
