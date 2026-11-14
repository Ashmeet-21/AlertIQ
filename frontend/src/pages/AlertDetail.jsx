import { Fragment, useState, useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import Navbar from "../components/Navbar.jsx";
import PriorityBadge from "../components/PriorityBadge.jsx";
import { VerdictBadge } from "../components/VerdictBadge.jsx";
import {
  getMitre, getSourceLabel, normaliseStatus, humanize, timeAgo,
  STATUS_LABELS, PROVIDER_LABELS, VERDICT_LABELS,
} from "../utils.js";

// Standard first steps for alerts that skip AI triage because a rule escalated them
const PLAYBOOKS = {
  data_exfiltration: "Isolate the source system. Capture memory and a disk image. Notify the DLP and legal teams before contacting the user.",
  login_failure:     "Check whether any attempt succeeded. Lock the targeted account if it's brute force, and block the source IP at the perimeter.",
  port_scan:         "Find out whether the source is an approved vulnerability scanner. If not, block it at the firewall and look for follow-up access attempts.",
  malware_detected:  "Quarantine the endpoint. Collect forensic artifacts and check for lateral movement from this host in the last 24 hours.",
};
const DEFAULT_PLAYBOOK = "Review the alert data, confirm how far the impact reaches, and hand it to incident response if the threat is confirmed.";

const DECISIONS = [
  { value: "true_positive",  label: "Confirm threat", className: "btn btn-threat" },
  { value: "needs_review",   label: "Needs review",   className: "btn btn-quiet" },
  { value: "false_positive", label: "Not a threat",   className: "btn btn-safe" },
];

function Facts({ payload }) {
  const yes = v => (v ? "Yes" : "No");
  const rows = [
    ["Source IP",   payload["source.ip"] && <span className="mono">{payload["source.ip"]}</span>],
    ...(payload["enrichment.source_ip.is_internal"]
      ? [["Network", "Internal"]]
      : [["Location", payload["enrichment.source_ip.country"] !== "unknown" && payload["enrichment.source_ip.country"]],
         ["Network",  payload["enrichment.source_ip.org"] !== "unknown" && payload["enrichment.source_ip.org"]]]),
    ["Proxy or VPN", payload["enrichment.source_ip.is_proxy"] != null &&
      <span className={payload["enrichment.source_ip.is_proxy"] ? "flag" : undefined}>{yes(payload["enrichment.source_ip.is_proxy"])}</span>],
    ["Hosting provider", payload["enrichment.source_ip.is_hosting"] != null &&
      <span className={payload["enrichment.source_ip.is_hosting"] ? "flag" : undefined}>{yes(payload["enrichment.source_ip.is_hosting"])}</span>],
    ["Destination", payload["destination.ip"] && <span className="mono">{payload["destination.ip"]}</span>],
    ["Host",        payload["host.name"]],
    ["User",        payload["user.name"]],
    ["Attempts",    payload["event.count"]],
    ["Target asset", payload["enrichment.asset.name"] !== "unknown" && payload["enrichment.asset.name"] &&
      `${payload["enrichment.asset.name"]} (${payload["enrichment.asset.criticality"]})`],
  ].filter(([, v]) => v !== undefined && v !== null && v !== false && v !== "");

  return (
    <dl className="facts">
      {rows.map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}
    </dl>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState(null);
  const canDecide = (() => {
    try { return JSON.parse(localStorage.getItem("alertiq_user") || "{}").role !== "read_only"; }
    catch { return true; }
  })();

  useEffect(() => {
    api.alert(id)
      .then(data => { setAlert(data); setNotes(data.analyst_notes ?? ""); })
      .catch(err => setLoadError(`Couldn't load this alert: ${err.message}`));
  }, [id]);

  async function decide(verdict) {
    setSaving(true);
    setSaveMsg(null);
    try {
      setAlert(await api.submitVerdict(id, verdict, notes));
      setSaveMsg({ ok: true, text: `Saved as "${VERDICT_LABELS[verdict]}". Future AI reviews will use it as an example.` });
    } catch (err) {
      setSaveMsg({ ok: false, text: `Not saved: ${err.message}` });
    } finally {
      setSaving(false);
    }
  }

  if (!alert) {
    return (
      <>
        <Navbar />
        <main className="page">
          {loadError ? <p className="notice notice-error">{loadError}</p> : <p className="empty">Loading alert…</p>}
        </main>
      </>
    );
  }

  const triage = alert.triage_result;
  const p = alert.normalized_payload ?? {};
  const status = normaliseStatus(alert.status);
  const mitre = getMitre(alert.event_type);
  const q = alert.priority_queue ?? "";

  return (
    <>
      <Navbar />
      <main className="page">
        <Link to="/" className="back">← Alert queue</Link>

        <div className="detail-head">
          <PriorityBadge queue={alert.priority_queue} score={alert.priority_score} />
          <div>
            <h1>{humanize(alert.event_type)}</h1>
            {p["event.message"] && <p>{p["event.message"]}</p>}
            <p className="muted">
              {getSourceLabel(alert.source_type)}, {timeAgo(alert.created_at)}. {STATUS_LABELS[status] ?? status}.
              {mitre && <> MITRE {mitre.technique}: {mitre.name}.</>}
            </p>
          </div>
        </div>

        <div className="detail-cols">
          <div>
            {status === "escalated" ? (
              <section className="panel">
                <h2>Escalated by rule: {alert.filter_reason ?? "matched an escalation rule"}</h2>
                <p>This alert skipped AI review and went straight to the top of the queue.</p>
                <h3>First steps</h3>
                <p className="action" data-q={q}>{PLAYBOOKS[alert.event_type] ?? DEFAULT_PLAYBOOK}</p>
              </section>
            ) : triage ? (
              <section className="panel">
                <h2>
                  <VerdictBadge verdict={triage.verdict} />, {Math.round((triage.confidence ?? 0) * 100)}% confident
                </h2>
                <p>{triage.summary}</p>
                <h3>What to do</h3>
                <p className="action" data-q={q}>{triage.recommended_action}</p>
                <h3>Why</h3>
                <p className="reasoning">{triage.reasoning}</p>
                {triage.provider && (
                  <p className="reasoning">Reviewed by {PROVIDER_LABELS[triage.provider] ?? triage.provider}.</p>
                )}
              </section>
            ) : (
              <section className="panel">
                <h2>{STATUS_LABELS[status] ?? status}</h2>
                <p className="muted">
                  {status === "suppressed" ? `Matched a noise rule (${alert.filter_reason}). No action needed.`
                    : status === "error" ? "The pipeline failed on this alert. Review the details by hand."
                    : "The AI review hasn't finished yet. Reload in a few seconds."}
                </p>
              </section>
            )}

            <section className="panel decision">
              <h2>Your decision</h2>
              {alert.analyst_verdict && (
                <p>Recorded: <VerdictBadge verdict={alert.analyst_verdict} />{alert.analyst_notes && <>. “{alert.analyst_notes}”</>}</p>
              )}
              <label htmlFor="notes" className="muted">Notes (optional, shown to the AI as context on similar alerts)</label>
              <textarea id="notes" value={notes} onChange={e => setNotes(e.target.value)} disabled={!canDecide}
                placeholder="Same actor as incident #1042. Block the /24." />
              <div className="decision-actions">
                {DECISIONS.map(d => (
                  <button key={d.value} className={d.className} disabled={saving || !canDecide} onClick={() => decide(d.value)}>
                    {d.label}
                  </button>
                ))}
              </div>
              {!canDecide && <p className="muted" style={{ marginTop: 10 }}>Your account is read-only, so you can view alerts but not record decisions.</p>}
              {saveMsg && <p className={`notice ${saveMsg.ok ? "notice-ok" : "notice-error"}`} style={{ marginTop: 14 }}>{saveMsg.text}</p>}
            </section>
          </div>

          <aside className="panel">
            <h2>Details</h2>
            <Facts payload={p} />
            <details>
              <summary>All fields</summary>
              <pre>{JSON.stringify(p, null, 2)}</pre>
            </details>
            <p className="muted mono" style={{ marginTop: 14, fontSize: 12 }}>{alert.id}</p>
          </aside>
        </div>
      </main>
    </>
  );
}
