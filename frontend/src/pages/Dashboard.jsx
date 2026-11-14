import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { api, createAlertSocket } from "../api.js";
import Navbar from "../components/Navbar.jsx";
import PriorityBadge from "../components/PriorityBadge.jsx";
import { VerdictBadge } from "../components/VerdictBadge.jsx";
import { timeAgo, getSourceLabel, normaliseStatus, humanize, STATUS_LABELS } from "../utils.js";

const QUEUES = ["", "P1", "P2", "P3", "P4"];
const STATUSES = ["", "triage", "escalated", "suppressed", "queued", "error"];

function AlertRow({ alert, isNew }) {
  const p = alert.normalized_payload ?? {};
  const triage = alert.triage_result;
  const status = normaliseStatus(alert.status);
  return (
    <li className={isNew ? "row-new" : undefined}>
      <Link to={`/alerts/${alert.id}`} className="row-link">
        <PriorityBadge queue={alert.priority_queue} score={alert.priority_score} />
        <div className="row-main">
          <div className="row-title">{humanize(alert.event_type)}</div>
          <div className="row-sub">{p["event.message"] || getSourceLabel(alert.source_type)}</div>
        </div>
        <div className="row-ip">
          <div className="mono">{p["source.ip"] ?? "–"}</div>
          <div className="row-sub">{getSourceLabel(alert.source_type)}</div>
        </div>
        <div className="row-verdict">
          {alert.analyst_verdict ? (
            <><VerdictBadge verdict={alert.analyst_verdict} /> <span className="muted">(analyst)</span></>
          ) : triage?.verdict ? (
            <><VerdictBadge verdict={triage.verdict} /> <span className="muted">{Math.round((triage.confidence ?? 0) * 100)}%</span></>
          ) : (
            <span className="muted">{STATUS_LABELS[status] ?? status}</span>
          )}
        </div>
        <div className="row-when">{timeAgo(alert.created_at)}</div>
      </Link>
    </li>
  );
}

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [queue, setQueue] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [wsStatus, setWsStatus] = useState("connecting");
  const [newId, setNewId] = useState(null);

  const loadAlerts = useCallback(async () => {
    try {
      const [alertsData, statsData] = await Promise.all([
        api.alerts({ queue: queue || undefined, status: status || undefined, limit: 100 }),
        api.stats(),
      ]);
      setAlerts(alertsData);
      setStats(statsData);
      setLoadError("");
    } catch (err) {
      setLoadError(`Couldn't load alerts: ${err.message}. Check that the backend is running on port 8000.`);
    } finally {
      setLoading(false);
    }
  }, [queue, status]);

  useEffect(() => {
    setLoading(true);
    loadAlerts();
  }, [loadAlerts]);

  useEffect(() => {
    let ws, reconnectTimer;
    let stopped = false;   // set on cleanup so a closed socket doesn't schedule a new one

    function connect() {
      ws = createAlertSocket();
      ws.onopen = () => setWsStatus("connected");
      ws.onclose = () => {
        setWsStatus("disconnected");
        if (!stopped) reconnectTimer = setTimeout(connect, 5000);
      };
      ws.onerror = () => setWsStatus("disconnected");
      ws.onmessage = ({ data }) => {
        const msg = JSON.parse(data);
        if (msg.type === "alert_updated" || msg.type === "verdict_submitted") {
          loadAlerts();
          setNewId(msg.alert_id);
        }
      };
    }

    connect();
    return () => { stopped = true; clearTimeout(reconnectTimer); ws?.close(); };
  }, [loadAlerts]);

  const counts = stats ? { "": stats.total, P1: stats.p1, P2: stats.p2, P3: stats.p3, P4: stats.p4 } : {};
  const summary = stats && [
    stats.escalated && `${stats.escalated} escalated by rule`,
    stats.triage && `${stats.triage} reviewed by AI`,
    stats.suppressed && `${stats.suppressed} suppressed as noise`,
    stats.queued && `${stats.queued} waiting for AI`,
    stats.error && `${stats.error} failed in the pipeline`,
  ].filter(Boolean).join(", ");

  return (
    <>
      <Navbar wsStatus={wsStatus} />
      <main className="page">
        <h1>Alert queue</h1>

        <div className="queue-head">
          <div className="tabs" role="group" aria-label="Filter by priority">
            {QUEUES.map(q => (
              <button key={q} className="tab" aria-pressed={queue === q} onClick={() => setQueue(q)}>
                {q || "All"} <b>{counts[q] ?? "–"}</b>
              </button>
            ))}
          </div>
          <label className="status-filter">
            Status
            <select value={status} onChange={e => setStatus(e.target.value)}>
              {STATUSES.map(s => <option key={s} value={s}>{s ? STATUS_LABELS[s] : "Any"}</option>)}
            </select>
          </label>
        </div>
        {summary && <p className="summary">{summary}.</p>}

        {loadError && <p className="notice notice-error">{loadError}</p>}

        {loading ? (
          <p className="empty">Loading alerts…</p>
        ) : alerts.length === 0 ? (
          <p className="empty">
            {queue || status
              ? "No alerts match these filters."
              : "No alerts yet. Send some with: python scripts/send_sample_alerts.py"}
          </p>
        ) : (
          <ul className="queue">
            {alerts.map(a => <AlertRow key={a.id} alert={a} isNew={a.id === newId} />)}
          </ul>
        )}
      </main>
    </>
  );
}
