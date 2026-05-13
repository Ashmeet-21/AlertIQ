/**
 * Dashboard (main page)
 *
 * Layout:
 *   1. Page header — title + live clock
 *   2. Stats bar   — 8 summary numbers
 *   3. Filter bar  — priority + status filters
 *   4. Alert table — one row per alert, click to open detail
 */
import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { api, createAlertSocket } from "../api.js";
import Navbar    from "../components/Navbar.jsx";
import StatsBar  from "../components/StatsBar.jsx";
import PriorityBadge from "../components/PriorityBadge.jsx";
import { VerdictBadge, StatusBadge } from "../components/VerdictBadge.jsx";
import { timeAgo, getSourceLabel, normaliseStatus } from "../utils.js";

// Left-side colour strip per priority
const PRIORITY_COLORS = {
  P1: "var(--red)",
  P2: "var(--orange)",
  P3: "var(--yellow)",
  P4: "var(--green)",
};

const QUEUE_OPTIONS   = ["", "P1", "P2", "P3", "P4"];
const STATUS_OPTIONS  = ["", "triage", "escalated", "suppressed", "queued"];

// ── Sub-components ─────────────────────────────────────────

function AlertRow({ alert, flash, onClick }) {
  const ip      = alert.normalized_payload?.["source.ip"] ?? "—";
  const verdict = alert.triage_result?.verdict;
  const status  = normaliseStatus(alert.status);
  const color   = PRIORITY_COLORS[alert.priority_queue];

  // Suppressed alerts have no meaningful priority — don't show a badge
  const showPriority = status !== "suppressed";

  return (
    <div
      className="alert-row"
      onClick={onClick}
      style={{
        borderLeftColor: showPriority ? (color ?? "transparent") : "var(--border)",
        background: flash ? "rgba(34,211,238,0.06)" : undefined,
      }}
    >
      {/* Priority badge — suppressed alerts show "—" instead */}
      <span style={{ paddingLeft: 21 }}>
        {showPriority
          ? <PriorityBadge queue={alert.priority_queue} score={alert.priority_score} />
          : <span className="text-dim mono" style={{ fontSize: 11 }}>—</span>
        }
      </span>

      {/* Event name + friendly source type */}
      <div>
        <div className="alert-event-name">{alert.event_type}</div>
        <div className="alert-source-type">{getSourceLabel(alert.source_type)}</div>
      </div>

      <span className="mono text-muted" style={{ fontSize: 12 }}>{ip}</span>

      {/* StatusBadge handles normalisation of "escalate" → "escalated" internally */}
      <span><StatusBadge status={status} /></span>

      <span>
        {verdict
          ? <VerdictBadge verdict={verdict} />
          : <span className="text-dim mono" style={{ fontSize: 11 }}>—</span>}
      </span>

      <span className="mono text-dim" style={{ fontSize: 11 }}>{timeAgo(alert.created_at)}</span>

      <span>
        <button
          className="btn-ghost btn"
          style={{ fontSize: 11, padding: "4px 10px", color: "var(--cyan)", borderColor: "var(--cyan-border)" }}
          onClick={e => { e.stopPropagation(); onClick(); }}
        >
          View →
        </button>
      </span>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate();

  const [alerts,       setAlerts]       = useState([]);
  const [stats,        setStats]        = useState(null);
  const [filterQueue,  setFilterQueue]  = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [loading,      setLoading]      = useState(true);
  const [wsStatus,     setWsStatus]     = useState("connecting");
  const [flashId,      setFlashId]      = useState(null);
  const [clock,        setClock]        = useState(new Date());

  // Tick the clock every second
  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  // Fetch alerts + stats from the API
  const loadAlerts = useCallback(async () => {
    try {
      const [alertsData, statsData] = await Promise.all([
        api.alerts({
          queue:  filterQueue  || undefined,
          status: filterStatus || undefined,
          limit: 100,
        }),
        api.stats(),
      ]);
      setAlerts(alertsData);
      setStats(statsData);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
    }
  }, [filterQueue, filterStatus]);

  // Re-fetch whenever filters change
  useEffect(() => {
    setLoading(true);
    loadAlerts();
  }, [loadAlerts]);

  // WebSocket — flash new/updated rows
  useEffect(() => {
    let ws, reconnectTimer;

    function connect() {
      ws = createAlertSocket();
      ws.onopen  = () => setWsStatus("connected");
      ws.onclose = () => {
        setWsStatus("disconnected");
        reconnectTimer = setTimeout(connect, 5000); // retry after 5 s
      };
      ws.onerror = () => setWsStatus("disconnected");
      ws.onmessage = ({ data }) => {
        const msg = JSON.parse(data);
        if (msg.type === "alert_updated" || msg.type === "verdict_submitted") {
          loadAlerts();
          setFlashId(msg.alert_id);
          setTimeout(() => setFlashId(null), 2000);
        }
      };
    }

    connect();
    return () => { clearTimeout(reconnectTimer); ws?.close(); };
  }, [loadAlerts]);

  const timeStr = clock.toLocaleTimeString("en-US", { hour12: false });

  return (
    <div className="page">
      <Navbar wsStatus={wsStatus} />

      <div className="container" style={{ paddingTop: 28, paddingBottom: 28 }}>

        {/* ── Page header ──────────────────────────────── */}
        <div className="row" style={{ marginBottom: 22, gap: 16 }}>
          <div className="stack gap-4">
            <span className="mono text-cyan" style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.14em" }}>
              SECURITY OPERATIONS CENTER
            </span>
            <h1 style={{ fontSize: 22, fontWeight: 800, letterSpacing: "-0.03em" }}>Alert Queue</h1>
            <p className="text-muted" style={{ fontSize: 12 }}>
              Real-time view of all ingested security events
            </p>
          </div>

          {/* Live clock — top right */}
          <div className="stack" style={{ marginLeft: "auto", textAlign: "right" }}>
            <span className="mono text-dim" style={{ fontSize: 10, letterSpacing: "0.1em", marginBottom: 2 }}>SYSTEM TIME</span>
            <span className="mono text-cyan" style={{ fontSize: 14, fontWeight: 600 }}>{timeStr}</span>
          </div>
        </div>

        {/* ── Stats bar ────────────────────────────────── */}
        <div style={{ marginBottom: 20 }}>
          <StatsBar stats={stats} />
        </div>

        {/* ── Filter bar ───────────────────────────────── */}
        <div className="filter-bar" style={{ marginBottom: 14 }}>
          <span className="filter-label">FILTER</span>
          <div className="filter-divider" />

          {/* Priority buttons */}
          <div className="row gap-4">
            {QUEUE_OPTIONS.map(q => (
              <button
                key={q}
                className={`filter-btn${filterQueue === q ? " active" : ""}${q === "P1" ? " danger" : ""}`}
                onClick={() => setFilterQueue(q)}
              >
                {q || "ALL"}
              </button>
            ))}
          </div>

          <div className="filter-divider" />

          {/* Status dropdown */}
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
          >
            {STATUS_OPTIONS.map(s => (
              <option key={s} value={s}>{s ? s.toUpperCase() : "ALL STATUSES"}</option>
            ))}
          </select>

          <span className="flex-1" />

          <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={loadAlerts}>
            ↻ Refresh
          </button>
        </div>

        {/* ── Alert table ──────────────────────────────── */}
        <div className="alert-table">

          {/* Column headers */}
          <div className="table-head">
            <span style={{ paddingLeft: 21 }}>PRIORITY</span>
            <span>EVENT</span>
            <span>SOURCE IP</span>
            <span>STATUS</span>
            <span>AI VERDICT</span>
            <span>TIME</span>
            <span></span>
          </div>

          {/* Rows */}
          {loading ? (
            <div style={{ padding: "60px 0", textAlign: "center" }} className="text-muted mono" >
              Fetching alerts…
            </div>
          ) : alerts.length === 0 ? (
            <div style={{ padding: "60px 0", textAlign: "center" }}>
              <div style={{ fontSize: 28, opacity: 0.2, marginBottom: 10 }}>◎</div>
              <p className="text-muted">No alerts match the current filters.</p>
            </div>
          ) : (
            alerts.map(alert => (
              <AlertRow
                key={alert.id}
                alert={alert}
                flash={alert.id === flashId}
                onClick={() => navigate(`/alerts/${alert.id}`)}
              />
            ))
          )}
        </div>

        {/* ── Footer status bar ────────────────────────── */}
        <div className="row gap-12" style={{ marginTop: 10, fontSize: 11 }}>
          <span className="mono text-dim">
            {alerts.length} alert{alerts.length !== 1 ? "s" : ""}
          </span>
          {wsStatus === "connected" && (
            <span className="row gap-4" style={{ color: "var(--green)" }}>
              <span
                className="live-dot pulse"
                style={{ background: "var(--green)", boxShadow: "0 0 6px var(--green)" }}
              />
              <span className="mono" style={{ fontSize: 11 }}>live updates active</span>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
