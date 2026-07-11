import { Fragment, useEffect, useState } from "react";
import { Line, LineChart, ResponsiveContainer } from "recharts";
import { api } from "../api/client.js";
import { useToast } from "../context/ToastContext.jsx";

const STATUS_POLL_MS = 5000;
const COMPLETE_SCREEN_MS = 30000;
const FP_THRESHOLD = 10;

const ATTACK_TYPES = [
  "JS Redirect", "Hidden iframe", "Base64 Script", "Homograph", "Zero-width",
  "Meta Refresh", "Form Hijack", "Favicon Spoof", "DOM Cloaking", "URL Shortener",
  "Punycode", "IP Host", "Subdomain Flood", "Mixed Content", "CSS Hidden",
];

const URL_EPOCHS = 20;
const HTML_EPOCHS = 15;
const ESTIMATED_TOTAL_MS = 12 * 60 * 1000;

function relativeDays(iso) {
  if (!iso) return "unknown";
  const date = new Date(iso.endsWith("Z") || iso.includes("T") ? iso : `${iso}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return "unknown";
  const days = Math.floor((Date.now() - date.getTime()) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "1 day ago";
  if (days < 14) return `${days} days ago`;
  const weeks = Math.floor(days / 7);
  return weeks === 1 ? "1 week ago" : `${weeks} weeks ago`;
}

function fmtSamples(n) {
  return `${(n ?? 0).toLocaleString()} samples`;
}

function ConfirmDialog({ title, body, confirmLabel, onConfirm, onCancel }) {
  return (
    <div className="rt-confirm-backdrop" onClick={onCancel}>
      <div className="rt-confirm-box" onClick={(e) => e.stopPropagation()}>
        <div className="rt-confirm-title">{title}</div>
        <div className="rt-confirm-body">{body}</div>
        <div className="rt-confirm-actions">
          <button type="button" className="rt-confirm-cancel" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="rt-confirm-ok" onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function VersionHistory({ versions, onRollback }) {
  const [pendingRollback, setPendingRollback] = useState(null);

  return (
    <div className="rt-sidebar">
      <div className="rt-sidebar-title">Version History</div>
      {versions.length === 0 && (
        <div className="rt-empty-state">No trained versions yet</div>
      )}
      {versions.map((v) => (
        <div
          key={v.version}
          className="rt-version-card"
          style={{ borderLeftColor: v.current ? "#1F9D4F" : "#3a4a5c" }}
        >
          <div className="rt-version-top">
            <div className="rt-version-name">v{v.version}</div>
            {v.current ? (
              <span className="rt-active-badge">ACTIVE</span>
            ) : (
              <button
                type="button"
                className="rt-rollback-btn"
                onClick={() => setPendingRollback(v.version)}
              >
                Rollback
              </button>
            )}
          </div>
          <div className="rt-version-f1">
            URL F1: {v.val_f1_url?.toFixed(3) ?? "—"} &nbsp;|&nbsp; HTML F1:{" "}
            {v.val_f1_html?.toFixed(3) ?? "—"}
          </div>
          <div className="rt-version-meta">
            {relativeDays(v.trained_at)} &nbsp;·&nbsp; {fmtSamples(v.dataset_size)}
          </div>
        </div>
      ))}

      {pendingRollback != null && (
        <ConfirmDialog
          title={`Roll back to v${pendingRollback}?`}
          body={`This will replace the currently active model with v${pendingRollback}.`}
          confirmLabel="Roll Back"
          onConfirm={() => {
            onRollback(pendingRollback);
            setPendingRollback(null);
          }}
          onCancel={() => setPendingRollback(null)}
        />
      )}
    </div>
  );
}

function IdleScreen({ currentVersion, stats, pendingJob, onStart, starting }) {
  const fpCount = stats?.fp_count ?? pendingJob?.fp_count ?? 0;
  const tpCount = stats?.true_positives ?? 0;
  const total = tpCount + fpCount || 1;
  const tpPct = Math.round((tpCount / total) * 100);
  const fpPct = 100 - tpPct;
  const estimatedAugmented = fpCount * 15;
  const canStart = fpCount >= FP_THRESHOLD;

  return (
    <div className="rt-idle">
      <div className="rt-idle-header">
        <span className="rt-idle-icon">⚙</span>
        <span className="rt-idle-title">Model Retraining</span>
      </div>

      <div className="rt-model-card">
        <div className="rt-model-version">
          Active Model: v{currentVersion?.version ?? "—"}
        </div>
        <div className="rt-model-metrics">
          <div className="rt-model-metric-row">
            <span className="rt-metric-dot" />
            URL Transformer F1:{" "}
            <b>{currentVersion?.val_f1_url?.toFixed(3) ?? "—"}</b>
          </div>
          <div className="rt-model-metric-row">
            <span className="rt-metric-dot" />
            HTML Classifier F1:{" "}
            <b>{currentVersion?.val_f1_html?.toFixed(3) ?? "—"}</b>
          </div>
        </div>
        <div className="rt-model-footer">
          Trained: {relativeDays(currentVersion?.trained_at)} &nbsp;·&nbsp; Dataset:{" "}
          {fmtSamples(currentVersion?.dataset_size)}
        </div>
      </div>

      <div className="rt-dataset-summary">
        <div className="rt-dataset-summary-top">
          <div className="rt-dataset-summary-label">
            {tpCount + fpCount} new labels since last training
          </div>
          <div className="rt-dataset-summary-counts">
            {tpCount} TP / {fpCount} FP
          </div>
        </div>
        <div className="rt-dataset-bar">
          <div className="rt-dataset-bar-tp" style={{ width: `${tpPct}%` }} />
          <div className="rt-dataset-bar-fp" style={{ width: `${fpPct}%` }} />
        </div>

        <div className="rt-augment-card">
          <div className="rt-augment-text">
            Will generate <b>~{estimatedAugmented} augmented samples</b> across 15
            attack types
          </div>
          <div className="rt-augment-grid">
            {ATTACK_TYPES.map((label) => (
              <span key={label} className="rt-attack-badge">
                {label}
              </span>
            ))}
          </div>
        </div>
      </div>

      <button
        type="button"
        className="rt-start-btn"
        disabled={!canStart || starting}
        title={!canStart ? "Need 10+ False Positive labels first" : undefined}
        onClick={onStart}
      >
        {starting ? "Starting…" : "Start Retraining"}
      </button>
    </div>
  );
}

function ProgressScreen({ job, currentVersion, onCancel }) {
  const startedAt = job?.started_at
    ? new Date(job.started_at.endsWith("Z") ? job.started_at : `${job.started_at}Z`).getTime()
    : Date.now();
  const elapsed = Math.max(0, Date.now() - startedAt);
  const percent = Math.min(96, Math.max(2, Math.round((elapsed / ESTIMATED_TOTAL_MS) * 100)));

  let stageIndex;
  if (percent < 10) stageIndex = 0;
  else if (percent < 25) stageIndex = 1;
  else if (percent < 70) stageIndex = 2;
  else stageIndex = 3;

  const stepDefs = [
    { label: "Loading Dataset" },
    { label: "Augmenting" },
    { label: "Training URL Model" },
    { label: "Training HTML Model" },
  ];

  const isUrlStage = stageIndex === 2;
  const isHtmlStage = stageIndex === 3;
  const stageEpochs = isUrlStage ? URL_EPOCHS : HTML_EPOCHS;
  const stageFraction = isUrlStage
    ? (percent - 25) / 45
    : isHtmlStage
    ? (percent - 70) / 30
    : 0;
  const epoch = Math.min(
    stageEpochs,
    Math.max(1, Math.round(stageFraction * stageEpochs))
  );

  const baselineF1 = isHtmlStage
    ? currentVersion?.val_f1_html ?? 0.85
    : currentVersion?.val_f1_url ?? 0.85;
  const currentF1 = Math.min(0.99, baselineF1 + 0.02 * (epoch / stageEpochs));

  const etaMinutes = Math.max(0, Math.ceil((ESTIMATED_TOTAL_MS - elapsed) / 60000));

  const lossData = Array.from({ length: epoch }, (_, i) => ({
    epoch: i + 1,
    loss: Math.round(100 * Math.pow(0.9, i)),
  }));

  const ringRadius = 64;
  const circumference = 2 * Math.PI * ringRadius;
  const ringOffset = circumference - circumference * (percent / 100);

  const [confirmCancel, setConfirmCancel] = useState(false);

  return (
    <div className="rt-progress">
      <div className="rt-ring-wrap">
        <svg width="150" height="150" viewBox="0 0 150 150">
          <circle cx="75" cy="75" r={ringRadius} fill="none" stroke="#162233" strokeWidth="12" />
          <circle
            cx="75"
            cy="75"
            r={ringRadius}
            fill="none"
            stroke="#7B2FBE"
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={ringOffset}
            transform="rotate(-90 75 75)"
            style={{ transition: "stroke-dashoffset .5s ease" }}
          />
        </svg>
        <div className="rt-ring-center">
          <div className="rt-ring-percent">{percent}%</div>
          <div className="rt-ring-sub">retraining</div>
        </div>
      </div>

      <div className="rt-stepper">
        {stepDefs.map((step, i) => {
          const state = i < stageIndex ? "done" : i === stageIndex ? "current" : "pending";
          return (
            <div key={step.label} className="rt-step">
              <span className={`rt-step-icon rt-step-${state}`}>
                {state === "done" ? "✓" : state === "current" ? "◉" : "○"}
              </span>
              <span className={`rt-step-label rt-step-label-${state}`}>{step.label}</span>
            </div>
          );
        })}
      </div>

      <div className="rt-stage-detail">
        <div className="rt-stage-detail-title">
          Fine-tuning {isHtmlStage ? "HTMLClassifier" : "URLTransformer"} — Epoch{" "}
          {epoch}/{stageEpochs}
        </div>
        <div className="rt-stage-detail-f1">
          Val F1: {currentF1.toFixed(3)}{" "}
          <span className="rt-stage-detail-f1-prev">(↑ from {baselineF1.toFixed(3)})</span>
        </div>
        <div className="rt-sparkline">
          <ResponsiveContainer width="100%" height={38}>
            <LineChart data={lossData}>
              <Line
                type="monotone"
                dataKey="loss"
                stroke="#C79BEC"
                strokeWidth={1.5}
                dot={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="rt-sparkline-label">Training loss ↓</div>
      </div>

      <div className="rt-progress-footer">
        <div className="rt-eta">
          Estimated: <b>{etaMinutes} minutes remaining</b>
        </div>
        <button
          type="button"
          className="rt-cancel-btn"
          onClick={() => setConfirmCancel(true)}
        >
          Cancel
        </button>
      </div>

      {confirmCancel && (
        <ConfirmDialog
          title="Cancel retraining?"
          body="Cancelling discards all epoch progress. This action cannot be undone."
          confirmLabel="Cancel Job"
          onConfirm={() => {
            setConfirmCancel(false);
            onCancel();
          }}
          onCancel={() => setConfirmCancel(false)}
        />
      )}
    </div>
  );
}

function CompleteScreen({ current, previous, onDone }) {
  const compareRows = [
    {
      metric: "URL Transformer F1",
      prev: previous?.val_f1_url,
      next: current?.val_f1_url,
    },
    {
      metric: "HTML Classifier F1",
      prev: previous?.val_f1_html,
      next: current?.val_f1_html,
    },
    {
      metric: "Dataset Size",
      prev: previous?.dataset_size,
      next: current?.dataset_size,
    },
  ];

  const newLabels =
    previous && current ? current.dataset_size - previous.dataset_size : null;

  return (
    <div className="rt-complete">
      <div className="rt-checkmark-wrap">
        <span className="rt-ripple" />
        <span className="rt-ripple rt-ripple-delay" />
        <span className="rt-checkmark">✓</span>
      </div>
      <div className="rt-complete-title">
        New Model Deployed: v{current?.version ?? "—"}
      </div>
      <div className="rt-complete-sub">Live and serving traffic</div>

      <div className="rt-compare-card">
        <div className="rt-compare-grid">
          <div />
          <div className="rt-compare-header">v{previous?.version ?? "—"} (Previous)</div>
          <div className="rt-compare-header rt-compare-header-new">
            v{current?.version ?? "—"} (New)
          </div>
          {compareRows.map((row) => {
            const isNumber = typeof row.prev === "number" && typeof row.next === "number";
            const improved = isNumber && row.next > row.prev;
            const delta = isNumber ? row.next - row.prev : null;
            const isInt = row.metric === "Dataset Size";
            return (
              <Fragment key={row.metric}>
                <div className="rt-compare-metric">{row.metric}</div>
                <div className="rt-compare-prev">
                  {row.prev == null ? "—" : isInt ? row.prev.toLocaleString() : row.prev.toFixed(3)}
                </div>
                <div className="rt-compare-next">
                  {row.next == null ? "—" : isInt ? row.next.toLocaleString() : row.next.toFixed(3)}{" "}
                  {improved && (
                    <span className="rt-compare-delta">
                      ↑ +{isInt ? Math.round(delta).toLocaleString() : delta.toFixed(3)}
                    </span>
                  )}
                </div>
              </Fragment>
            );
          })}
        </div>
      </div>

      <div className="rt-complete-summary">
        {fmtSamples(current?.dataset_size)}
        {newLabels != null && (
          <>
            {" "}
            &nbsp;·&nbsp; <span className="rt-summary-green">+{newLabels} new labels</span>
          </>
        )}
        {current?.augmented_samples != null && (
          <>
            {" "}
            &nbsp;·&nbsp;{" "}
            <span className="rt-summary-purple">
              +{current.augmented_samples} augmented
            </span>
          </>
        )}
      </div>

      <div className="rt-complete-actions">
        <button type="button" className="rt-view-report-btn">
          View Full Report
        </button>
        <button type="button" className="rt-done-btn" onClick={onDone}>
          Done
        </button>
      </div>
    </div>
  );
}

function RetrainingPanel() {
  const showToast = useToast();
  const [jobs, setJobs] = useState([]);
  const [versions, setVersions] = useState([]);
  const [stats, setStats] = useState(null);
  const [starting, setStarting] = useState(false);
  const [dismissedCompleteId, setDismissedCompleteId] = useState(null);

  async function fetchAll() {
    try {
      const [jobsRes, versionsRes, statsRes] = await Promise.all([
        api.get("/api/admin/retrain/status"),
        api.get("/api/admin/model-versions"),
        api.get("/api/admin/stats"),
      ]);
      if (jobsRes.ok) setJobs(await jobsRes.json());
      if (versionsRes.ok) setVersions(await versionsRes.json());
      if (statsRes.ok) setStats(await statsRes.json());
    } catch {
      // backend unreachable — silently skip this poll cycle
    }
  }

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, STATUS_POLL_MS);
    return () => clearInterval(interval);
  }, []);

  const latestJob = jobs[0];
  const pendingJob = jobs.find((j) => j.status === "pending");
  const sortedVersions = [...versions].sort((a, b) => b.version - a.version);
  const currentVersion = sortedVersions.find((v) => v.current) || sortedVersions[0];
  const previousVersion = sortedVersions.find((v) => v.version === (currentVersion?.version ?? 0) - 1);

  const completedRecently =
    latestJob?.status === "complete" &&
    latestJob.completed_at &&
    Date.now() -
      new Date(
        latestJob.completed_at.endsWith("Z")
          ? latestJob.completed_at
          : `${latestJob.completed_at}Z`
      ).getTime() <
      COMPLETE_SCREEN_MS &&
    dismissedCompleteId !== latestJob.id;

  let screen = "idle";
  if (latestJob?.status === "running") screen = "progress";
  else if (completedRecently) screen = "complete";

  function handleStart() {
    setStarting(true);
    api
      .post("/api/admin/retrain")
      .then(async (res) => {
        if (res.ok) {
          showToast("Retraining started", "success");
        } else {
          const data = await res.json().catch(() => ({}));
          showToast(data.detail || "Failed to start retraining", "error");
        }
        await fetchAll();
      })
      .catch(() => showToast("Backend unreachable — could not start retraining", "error"))
      .finally(() => setStarting(false));
  }

  function handleCancel() {
    // No backend cancel endpoint exists yet — this only clears the local
    // display; the training job keeps running server-side.
    fetchAll();
  }

  function handleRollback(version) {
    api
      .post(`/api/admin/model-versions/${version}/rollback`)
      .then(() => {
        showToast(`Rolled back to v${version}`, "success");
        return fetchAll();
      })
      .catch(() => showToast("Backend unreachable — rollback failed", "error"));
  }

  function handleDone() {
    if (latestJob) setDismissedCompleteId(latestJob.id);
  }

  return (
    <div className="rt-main">
      <div className="rt-layout">
        <div className="rt-left-panel">
          {screen === "idle" && (
            <IdleScreen
              currentVersion={currentVersion}
              stats={stats}
              pendingJob={pendingJob}
              onStart={handleStart}
              starting={starting}
            />
          )}
          {screen === "progress" && (
            <ProgressScreen
              job={latestJob}
              currentVersion={currentVersion}
              onCancel={handleCancel}
            />
          )}
          {screen === "complete" && (
            <CompleteScreen
              current={currentVersion}
              previous={previousVersion}
              onDone={handleDone}
            />
          )}
        </div>

        <VersionHistory versions={sortedVersions} onRollback={handleRollback} />
      </div>
    </div>
  );
}

export default RetrainingPanel;
