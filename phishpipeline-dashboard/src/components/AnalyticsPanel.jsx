import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client.js";

const ANALYTICS_POLL_MS = 60000;
const LIVE_POLL_MS = 60000;
const TIMELINE_DAYS_SHOWN = 14;

const CATEGORY_LABELS = {
  regular: "Regular",
  js_evasion: "JS Evasion",
  clickjacking: "Clickjacking",
  dom_cloaking: "DOM Cloaking",
  text_encoding: "Text Encoding",
};

const CATEGORY_COLORS = {
  Regular: "#1F9D4F",
  "JS Evasion": "#B45309",
  Clickjacking: "#B45309",
  "DOM Cloaking": "#C00000",
  "Text Encoding": "#C00000",
};

const CATEGORY_ORDER = [
  "regular",
  "js_evasion",
  "clickjacking",
  "dom_cloaking",
  "text_encoding",
];

function formatMinsAsHm(mins) {
  const total = Math.round(mins || 0);
  const h = Math.floor(total / 60);
  const m = total % 60;
  return `${h}h ${m}m`;
}

function formatRelative(timestamp) {
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

function formatShortDate(dateStr) {
  const date = new Date(`${dateStr}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return dateStr;
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function truncateUrl(url, max = 40) {
  if (!url) return "";
  return url.length > max ? `${url.slice(0, max - 1)}…` : url;
}

function percentDelta(current, previous) {
  if (!previous) return null;
  return Math.round(((current - previous) / previous) * 100);
}

function TrendBadge({ delta, invert = false }) {
  if (delta === null || delta === undefined || Number.isNaN(delta) || delta === 0) {
    return null;
  }
  const up = delta > 0;
  const good = invert ? !up : up;
  const color = good ? "#3FDC7F" : "#FF6B6B";
  const arrow = up ? "↑" : "↓";
  return (
    <span className="an-kpi-trend" style={{ color }}>
      {arrow} {Math.abs(delta)}% this week
    </span>
  );
}

function KpiCard({ icon, iconBg, iconFg, value, label, delta, invert }) {
  return (
    <div className="an-kpi-card">
      <div className="an-kpi-top">
        <span className="an-kpi-icon" style={{ background: iconBg, color: iconFg }}>
          {icon}
        </span>
        <TrendBadge delta={delta} invert={invert} />
      </div>
      <div>
        <div className="an-kpi-value">{value}</div>
        <div className="an-kpi-label">{label}</div>
      </div>
    </div>
  );
}

function CategoryTooltip({ active, payload }) {
  if (!active || !payload || payload.length === 0) return null;
  const entry = payload[0];
  return (
    <div className="an-tooltip">
      <div className="an-tooltip-label">{entry.payload.category}</div>
      <div style={{ color: entry.payload.color }}>{entry.value.toFixed(1)}h avg</div>
    </div>
  );
}

function TimelineTooltip({ active, payload, label }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="an-tooltip">
      <div className="an-tooltip-label">{label}</div>
      {payload.map((entry) => (
        <div key={entry.dataKey} style={{ color: entry.color }}>
          {entry.name}: {entry.value}
        </div>
      ))}
    </div>
  );
}

function CategoryBarLabel(props) {
  const { x, y, width, height, value } = props;
  return (
    <text
      x={x + width - 6}
      y={y + height / 2}
      dy={4}
      textAnchor="end"
      fill="#fff"
      fontSize={10.5}
      fontWeight={700}
    >
      {value.toFixed(1)}h
    </text>
  );
}

function StatusBadge({ status }) {
  const map = {
    taken_down: { label: "TAKEN DOWN", bg: "#006400", fg: "#fff" },
    error: { label: "ERROR", bg: "#C00000", fg: "#fff" },
  };
  const view = map[status] || { label: "ACTIVE", bg: "#2E75B6", fg: "#fff" };
  return (
    <span
      className="an-status-badge"
      style={{ background: view.bg, color: view.fg }}
    >
      {view.label}
    </span>
  );
}

function TtdCell({ row }) {
  const isPolling =
    row.last_polled_at &&
    Date.now() - new Date(
      row.last_polled_at.endsWith("Z") ? row.last_polled_at : `${row.last_polled_at}Z`
    ).getTime() <
      60000;

  if (isPolling) {
    return (
      <span className="an-ttd-polling">
        <span className="an-ttd-spinner" />
        Polling
      </span>
    );
  }

  if (row.polling_status === "taken_down" && row.time_to_takedown_mins != null) {
    return <span className="an-ttd-value">{formatMinsAsHm(row.time_to_takedown_mins)}</span>;
  }

  return <span className="an-ttd-dash">—</span>;
}

function AnalyticsPanel() {
  const [analytics, setAnalytics] = useState(null);
  const [liveRows, setLiveRows] = useState([]);

  async function fetchAnalytics() {
    try {
      const res = await api.get("/api/analytics/takedown");
      if (res.ok) setAnalytics(await res.json());
    } catch {
      // backend unreachable — silently skip this poll cycle
    }
  }

  async function fetchLive() {
    try {
      const res = await api.get("/api/analytics/takedown/live");
      if (res.ok) setLiveRows(await res.json());
    } catch {
      // backend unreachable — silently skip this poll cycle
    }
  }

  useEffect(() => {
    fetchAnalytics();
    fetchLive();
    const analyticsInterval = setInterval(fetchAnalytics, ANALYTICS_POLL_MS);
    const liveInterval = setInterval(fetchLive, LIVE_POLL_MS);
    return () => {
      clearInterval(analyticsInterval);
      clearInterval(liveInterval);
    };
  }, []);

  const overall = analytics?.overall;
  const timeline = analytics?.timeline || [];

  const categoryChartData = CATEGORY_ORDER.map((key) => {
    const entry = analytics?.by_category?.[key];
    const label = CATEGORY_LABELS[key];
    return {
      category: label,
      hours: (entry?.avg_mins || 0) / 60,
      color: CATEGORY_COLORS[label],
    };
  });
  const maxHours = Math.max(1, ...categoryChartData.map((d) => d.hours));
  const xDomainMax = maxHours * 1.2;

  // Trim leading empty days so the curve starts where activity begins
  // instead of dragging a flat zero line across the chart.
  const windowed = timeline.slice(-TIMELINE_DAYS_SHOWN);
  const firstActive = windowed.findIndex(
    (e) => (e.reported || 0) > 0 || (e.taken_down || 0) > 0
  );
  const activeWindow = firstActive > 0 ? windowed.slice(firstActive) : windowed;
  const timelineChartData = activeWindow.map((entry) => ({
    date: formatShortDate(entry.date),
    Reported: entry.reported,
    "Taken Down": entry.taken_down,
  }));

  const lastWeek = timeline.slice(-7);
  const prevWeek = timeline.slice(-14, -7);
  const sum = (arr, key) => arr.reduce((acc, e) => acc + (e[key] || 0), 0);
  const reportedThisWeek = sum(lastWeek, "reported");
  const reportedPrevWeek = sum(prevWeek, "reported");
  const takenDownThisWeek = sum(lastWeek, "taken_down");
  const takenDownPrevWeek = sum(prevWeek, "taken_down");
  const rateThisWeek = reportedThisWeek ? (takenDownThisWeek / reportedThisWeek) * 100 : 0;
  const ratePrevWeek = reportedPrevWeek ? (takenDownPrevWeek / reportedPrevWeek) * 100 : 0;
  const avgMinsThisWeek =
    sum(lastWeek.filter((e) => e.taken_down > 0), "avg_mins") /
      (lastWeek.filter((e) => e.taken_down > 0).length || 1) || 0;
  const avgMinsPrevWeek =
    sum(prevWeek.filter((e) => e.taken_down > 0), "avg_mins") /
      (prevWeek.filter((e) => e.taken_down > 0).length || 1) || 0;

  return (
    <div className="an-main">
      <div className="an-kpi-row">
        <KpiCard
          icon="⚑"
          iconBg="rgba(46,117,182,.2)"
          iconFg="#8FC0EC"
          value={overall?.total_reported ?? 0}
          label="Total Reported"
          delta={percentDelta(reportedThisWeek, reportedPrevWeek)}
        />
        <KpiCard
          icon="🛡"
          iconBg="rgba(0,100,0,.22)"
          iconFg="#3FDC7F"
          value={overall?.total_taken_down ?? 0}
          label="Sites Taken Down"
          delta={percentDelta(takenDownThisWeek, takenDownPrevWeek)}
        />
        <KpiCard
          icon="%"
          iconBg="rgba(180,83,9,.2)"
          iconFg="#F0A93B"
          value={`${overall?.takedown_rate_percent ?? 0}%`}
          label="Takedown Rate"
          delta={percentDelta(rateThisWeek, ratePrevWeek)}
        />
        <KpiCard
          icon="◷"
          iconBg="rgba(123,47,190,.24)"
          iconFg="#C79BEC"
          value={formatMinsAsHm(overall?.avg_time_to_takedown_mins ?? 0)}
          label="Avg Time to Takedown"
          delta={percentDelta(avgMinsThisWeek, avgMinsPrevWeek)}
          invert
        />
      </div>

      <div className="an-charts-row">
        <div className="an-chart-card an-chart-card-left">
          <div className="an-chart-title">Time to Takedown by Attack Category</div>
          <div className="an-chart-inner">
            <ResponsiveContainer width="100%" height={230}>
              <BarChart
                data={categoryChartData}
                layout="vertical"
                margin={{ top: 4, right: 20, left: 4, bottom: 4 }}
              >
                <CartesianGrid stroke="#1F4E79" horizontal={false} />
                <XAxis
                  type="number"
                  domain={[0, xDomainMax]}
                  tick={{ fill: "#6B7C8D", fontSize: 9.5 }}
                  axisLine={{ stroke: "#1F4E79" }}
                  tickLine={false}
                  unit="h"
                />
                <YAxis
                  type="category"
                  dataKey="category"
                  width={110}
                  tick={{ fill: "#CBD5E1", fontSize: 11.5 }}
                  axisLine={{ stroke: "#1F4E79" }}
                  tickLine={false}
                />
                <Tooltip content={<CategoryTooltip />} cursor={{ fill: "rgba(158,199,232,0.06)" }} />
                <Bar
                  dataKey="hours"
                  radius={[4, 4, 4, 4]}
                  label={CategoryBarLabel}
                  isAnimationActive={false}
                >
                  {categoryChartData.map((entry) => (
                    <Cell key={entry.category} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="an-chart-card an-chart-card-right">
          <div className="an-chart-title">Daily Reported vs Taken Down — Last 14 Days</div>
          <div className="an-chart-inner">
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={timelineChartData} margin={{ top: 4, right: 12, left: 4, bottom: 4 }}>
                <CartesianGrid stroke="#1F4E79" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fill: "#6B7C8D", fontSize: 9.5 }}
                  axisLine={{ stroke: "#1F4E79" }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#6B7C8D", fontSize: 9.5 }}
                  axisLine={{ stroke: "#1F4E79" }}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip content={<TimelineTooltip />} cursor={{ stroke: "rgba(158,199,232,0.2)" }} />
                <Legend
                  verticalAlign="bottom"
                  height={28}
                  formatter={(value) => (
                    <span style={{ color: "#CBD5E1", fontSize: 11 }}>{value}</span>
                  )}
                />
                <Area
                  type="monotone"
                  dataKey="Reported"
                  stroke="#2E75B6"
                  strokeWidth={2}
                  fill="#2E75B6"
                  fillOpacity={0.2}
                  dot={{ r: 3, fill: "#2E75B6" }}
                />
                <Area
                  type="monotone"
                  dataKey="Taken Down"
                  stroke="#3FDC7F"
                  strokeWidth={2}
                  fill="#3FDC7F"
                  fillOpacity={0.2}
                  dot={{ r: 3, fill: "#3FDC7F" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="an-table-card">
        <div className="an-table-header">
          <span className="an-table-title">Active Tracking</span>
          <span className="an-count-badge">{liveRows.length}</span>
        </div>
        <div className="an-row an-row-header">
          <div>URL</div>
          <div>Category</div>
          <div>Reported At</div>
          <div>Last Checked</div>
          <div>Status</div>
          <div className="an-col-right">TTD</div>
        </div>
        <div>
          {liveRows.length === 0 && (
            <div className="an-empty-state">No URLs currently being tracked</div>
          )}
          {liveRows.map((row, i) => {
            const isDown = row.polling_status === "taken_down";
            return (
              <div
                key={row.id}
                className={`an-row ${isDown ? "an-row-down" : ""}`}
                style={{ background: isDown ? "#1A3A2A" : i % 2 === 0 ? "#162233" : "#1A2940" }}
              >
                <div className="an-cell-url" title={row.url}>
                  {truncateUrl(row.url)}
                </div>
                <div className="an-cell-category">
                  {CATEGORY_LABELS[row.attack_category] || row.attack_category}
                </div>
                <div className="an-cell-time">{formatRelative(row.reported_at)}</div>
                <div className="an-cell-time">{formatRelative(row.last_polled_at)}</div>
                <div>
                  <StatusBadge status={row.polling_status} />
                </div>
                <div className="an-col-right">
                  <TtdCell row={row} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default AnalyticsPanel;
