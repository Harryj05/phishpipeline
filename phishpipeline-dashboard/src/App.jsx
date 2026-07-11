import { useEffect, useState } from "react";
import {
  HashRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import "./App.css";
import { api } from "./api/client.js";
import { ToastProvider } from "./context/ToastContext.jsx";
import ErrorBoundary from "./components/ErrorBoundary.jsx";
import Dashboard from "./components/Dashboard.jsx";
import AdminPanel from "./components/AdminPanel.jsx";
import RetrainingPanel from "./components/RetrainingPanel.jsx";
import ReportingPanel from "./components/ReportingPanel.jsx";
import AnalyticsPanel from "./components/AnalyticsPanel.jsx";

const NAV_STORAGE_KEY = "phishpipeline_active_tab";
const STATS_POLL_MS = 5000;

const TABS = [
  { key: "dashboard", label: "Live Feed" },
  { key: "admin", label: "Admin Review" },
  { key: "reports", label: "Reports" },
  { key: "analytics", label: "Analytics" },
];

function AdminSection() {
  const [subTab, setSubTab] = useState("review");

  return (
    <div>
      <div className="pp-subtabs">
        <button
          type="button"
          className={`pp-subtab ${subTab === "review" ? "active" : ""}`}
          onClick={() => setSubTab("review")}
        >
          Review
        </button>
        <button
          type="button"
          className={`pp-subtab ${subTab === "retraining" ? "active" : ""}`}
          onClick={() => setSubTab("retraining")}
        >
          Retraining
        </button>
      </div>
      {subTab === "review" ? <AdminPanel /> : <RetrainingPanel />}
    </div>
  );
}

function NavBar({ stats, backendOnline }) {
  const location = useLocation();
  const navigate = useNavigate();
  const activeKey = location.pathname.replace("/", "") || "dashboard";

  return (
    <nav className="pp-nav">
      <div className="pp-nav-logo-group">
        <div className="pp-nav-logo">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 2L4 5V11C4 16.5 7.4 21.2 12 22C16.6 21.2 20 16.5 20 11V5L12 2Z"
              fill="#FFFFFF"
            />
            <path
              d="M9.5 12L11 13.5L14.5 10"
              stroke="#1F4E79"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <span className="pp-nav-title">PhishPipeline</span>
        <div
          className="pp-backend-dot"
          title={
            backendOnline === null
              ? "Connecting..."
              : backendOnline
              ? "Backend connected"
              : "Backend offline"
          }
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            marginLeft: 8,
            background:
              backendOnline === null
                ? "#6B7C8D"
                : backendOnline
                ? "#3FDC7F"
                : "#FF6B6B",
            flexShrink: 0,
          }}
        />
      </div>

      <div className="pp-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className={`pp-tab ${activeKey === tab.key ? "active" : ""}`}
            onClick={() => navigate(`/${tab.key}`)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="pp-stat-tiles">
        <div className="pp-stat-tile">
          <span className="pp-stat-number" style={{ color: "#FFFFFF" }}>
            {stats.domainsScanned}
          </span>
          <span className="pp-stat-sub">last 10 min</span>
          <span className="pp-stat-label">Domains Scanned</span>
        </div>
        <div className="pp-stat-tile">
          <span className="pp-stat-number" style={{ color: "#FF5A5A" }}>
            {stats.phishingCount}
          </span>
          <span className="pp-stat-label">Phishing Detected</span>
        </div>
        <div className="pp-stat-tile">
          <span className="pp-stat-number" style={{ color: "#F0A93B" }}>
            {stats.queuedCount}
          </span>
          <span className="pp-stat-label">Queued for Review</span>
        </div>
        <div className="pp-stat-tile">
          <span className="pp-stat-number" style={{ color: "#34C77B" }}>
            {stats.cleanCount}
          </span>
          <span className="pp-stat-label">Clean</span>
        </div>
      </div>
    </nav>
  );
}

function RouteRedirect() {
  const navigate = useNavigate();

  useEffect(() => {
    const saved = localStorage.getItem(NAV_STORAGE_KEY);
    const target = TABS.some((t) => t.key === saved) ? saved : "dashboard";
    navigate(`/${target}`, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return null;
}

function PersistTab() {
  const location = useLocation();

  useEffect(() => {
    const key = location.pathname.replace("/", "");
    if (TABS.some((t) => t.key === key)) {
      localStorage.setItem(NAV_STORAGE_KEY, key);
    }
  }, [location.pathname]);

  return null;
}

function AppShell() {
  const [stats, setStats] = useState({
    domainsScanned: 0,
    phishingCount: 0,
    queuedCount: 0,
    cleanCount: 0,
  });
  const location = useLocation();
  const [backendOnline, setBackendOnline] = useState(null); // null=checking

  useEffect(() => {
    async function checkHealth() {
      try {
        const r = await api.get("/api/health");
        setBackendOnline(r.ok);
      } catch {
        setBackendOnline(false);
      }
    }
    checkHealth();
    const interval = setInterval(checkHealth, 30000); // check every 30s
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const res = await api.get("/api/queue");
        if (!res.ok) return;
        const data = await res.json();
        const rows = Array.isArray(data) ? data : data.rows || [];
        if (cancelled) return;

        setStats({
          domainsScanned: rows.length,
          phishingCount: rows.filter((r) => r.label === "phishing").length,
          queuedCount: rows.filter((r) => r.status === "pending").length,
          cleanCount: rows.filter(
            (r) => r.status === "classified" && r.label !== "phishing"
          ).length,
        });
      } catch {
        // backend unreachable — silently skip this poll cycle
      }
    }

    poll();
    const interval = setInterval(poll, STATS_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="pp-app">
      <PersistTab />
      <NavBar stats={stats} backendOnline={backendOnline} />

      {backendOnline === false && (
        <div
          style={{
            background: "rgba(192,0,0,0.15)",
            borderBottom: "1px solid #C00000",
            padding: "8px 22px",
            fontSize: 13,
            color: "#FF6B6B",
          }}
        >
          ⚠ Backend unreachable — data may be stale. Check that the server is
          running.
        </div>
      )}

      <ErrorBoundary key={location.pathname}>
        <Routes>
          <Route path="/" element={<RouteRedirect />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/admin" element={<AdminSection />} />
          <Route path="/reports" element={<ReportingPanel />} />
          <Route path="/analytics" element={<AnalyticsPanel />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </ErrorBoundary>
    </div>
  );
}

function App() {
  return (
    <HashRouter>
      <ToastProvider>
        <AppShell />
      </ToastProvider>
    </HashRouter>
  );
}

export default App;
