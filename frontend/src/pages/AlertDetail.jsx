/**
 * AlertDetail page
 *
 * A security analyst lands here after clicking an alert.
 * The page is structured in priority order — most critical information first:
 *
 *  1. Header         — priority, status, event type, when it happened
 *  2. Action banner  — for ESCALATED/P1: "what to do RIGHT NOW" is top of page
 *  3. Threat context — MITRE ATT&CK tactic, source type, time in queue
 *  4. Two columns    — normalised data (left) | Claude AI verdict (right)
 *  5. Enrichment     — IP reputation, asset info (only non-"unknown" values)
 *  6. Analyst panel  — analyst notes + TP / NR / FP verdict buttons
 */
import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import Navbar    from "../components/Navbar.jsx";
import PriorityBadge from "../components/PriorityBadge.jsx";
import { VerdictBadge, StatusBadge } from "../components/VerdictBadge.jsx";
import {
  getMitre,
  getSourceLabel,
  normaliseStatus,
  timeAgo,
  timeSince,
  fixEncoding,
} from "../utils.js";

// ── Priority border colours (left stripe on header card) ──────────────────────
const PRIORITY_BORDER = {
  P1: "var(--red)",
  P2: "var(--orange)",
  P3: "var(--yellow)",
  P4: "var(--green)",
};

// ── Analyst verdict buttons ───────────────────────────────────────────────────
const VERDICT_BTNS = [
  { value: "true_positive",  label: "✓ Confirm Threat",   color: "var(--red)",    bg: "var(--red-bg)",    border: "var(--red-border)"    },
  { value: "needs_review",   label: "? Needs Review",     color: "var(--yellow)", bg: "var(--yellow-bg)", border: "var(--yellow-border)"  },
  { value: "false_positive", label: "✗ False Positive",   color: "var(--green)",  bg: "var(--green-bg)",  border: "var(--green-border)"   },
];

// ── Small reusable card section ───────────────────────────────────────────────
function Card({ title, icon, titleColor = "var(--muted)", children, style }) {
  return (
    <div className="card" style={style}>
      <div className="card-head">
        {icon && <span>{icon}</span>}
        <span className="card-head-title" style={{ color: titleColor }}>{title}</span>
      </div>
      <div className="card-body">{children}</div>
    </div>
  );
}

// ── Key/value row in the normalised data table ────────────────────────────────
function DataRow({ label, value }) {
  return (
    <div className="data-row">
      <span className="data-key">{label}</span>
      <span className="data-val">{JSON.stringify(value)}</span>
    </div>
  );
}

// ── Immediate action banner shown for ESCALATED alerts ───────────────────────
// This is the most important element on the page for escalated alerts.
// A real SOC analyst needs to know WHAT HAPPENED and WHAT TO DO in < 5 seconds.
function EscalatedBanner({ filterReason, eventType }) {
  // Look up a standard playbook action based on event type
  const playbooks = {
    data_exfiltration: "Isolate the source system immediately. Capture memory and disk image. Notify DLP and legal teams. Do not alert the user until investigation is scoped.",
    login_failure:     "Verify whether any attempt succeeded. Lock the targeted account if brute-force is confirmed. Block the source IP at the perimeter. Notify the account owner.",
    port_scan:         "Identify the scanning source. Check whether it is an authorised vulnerability scanner. If not, block at firewall and investigate for follow-on exploitation attempts.",
    malware_detected:  "Quarantine the affected endpoint immediately. Collect forensic artifacts. Check for lateral movement from this host in the last 24 hours.",
  };
  const playbook = playbooks[eventType] ?? "Review alert data, confirm scope of impact, and escalate to senior analyst or incident response team if threat is confirmed.";

  return (
    <div style={{
      background: "rgba(244,63,94,0.08)",
      border: "1px solid var(--red-border)",
      borderLeft: "4px solid var(--red)",
      borderRadius: "0 var(--radius-lg) var(--radius-lg) 0",
      padding: "16px 20px",
      marginBottom: 16,
    }}>
      {/* Banner title */}
      <div className="row gap-8" style={{ marginBottom: 10 }}>
        <span style={{ fontSize: 16 }}>⚠</span>
        <span style={{ fontWeight: 700, fontSize: 14, color: "var(--red)", letterSpacing: "-0.01em" }}>
          Immediate Action Required — This Alert Was Auto-Escalated
        </span>
      </div>

      {/* Escalation reason */}
      <div style={{ marginBottom: 10 }}>
        <span className="mono text-dim" style={{ fontSize: 10, letterSpacing: "0.1em" }}>ESCALATION REASON</span>
        <p style={{ fontSize: 13, color: "var(--text)", marginTop: 4 }}>{filterReason ?? "Matched escalation rule."}</p>
      </div>

      {/* Standard playbook */}
      <div>
        <span className="mono text-dim" style={{ fontSize: 10, letterSpacing: "0.1em" }}>STANDARD PLAYBOOK</span>
        <p style={{ fontSize: 13, color: "#fca5a5", marginTop: 4, lineHeight: 1.65 }}>{playbook}</p>
      </div>
    </div>
  );
}

// ── Threat context strip ──────────────────────────────────────────────────────
// Shows MITRE ATT&CK tactic, source system, and time in queue.
// Helps an analyst orient quickly without reading the full detail.
function ThreatContext({ alert, status }) {
  const mitre     = getMitre(alert.event_type);
  const sourceLabel = getSourceLabel(alert.source_type);
  const queueTime = timeSince(alert.created_at);

  return (
    <div style={{
      display: "flex",
      gap: 10,
      flexWrap: "wrap",
      marginBottom: 16,
    }}>
      {/* MITRE ATT&CK tile */}
      {mitre && (
        <div style={{
          background: "var(--surface)",
          border: "1px solid var(--border2)",
          borderRadius: var_radius,
          padding: "10px 16px",
          flex: 1,
          minWidth: 180,
        }}>
          <div className="mono text-dim" style={{ fontSize: 9, letterSpacing: "0.12em", marginBottom: 4 }}>MITRE ATT&CK</div>
          <div style={{ fontWeight: 700, fontSize: 13, color: "var(--text)" }}>{mitre.tactic}</div>
          <div className="mono" style={{ fontSize: 11, color: "var(--muted)", marginTop: 2 }}>
            {mitre.technique} · {mitre.name}
          </div>
        </div>
      )}

      {/* Source system tile */}
      <div style={{
        background: "var(--surface)",
        border: "1px solid var(--border2)",
        borderRadius: var_radius,
        padding: "10px 16px",
        flex: 1,
        minWidth: 150,
      }}>
        <div className="mono text-dim" style={{ fontSize: 9, letterSpacing: "0.12em", marginBottom: 4 }}>SOURCE SYSTEM</div>
        <div style={{ fontWeight: 700, fontSize: 13, color: "var(--text)" }}>{sourceLabel}</div>
        <div className="mono" style={{ fontSize: 11, color: "var(--muted)", marginTop: 2 }}>
          {alert.event_type}
        </div>
      </div>

      {/* Time in queue tile */}
      <div style={{
        background: "var(--surface)",
        border: "1px solid var(--border2)",
        borderRadius: var_radius,
        padding: "10px 16px",
        flex: 1,
        minWidth: 150,
      }}>
        <div className="mono text-dim" style={{ fontSize: 9, letterSpacing: "0.12em", marginBottom: 4 }}>TIME IN QUEUE</div>
        <div style={{ fontWeight: 700, fontSize: 13, color: status === "escalated" ? "var(--red)" : "var(--text)" }}>
          {queueTime}
        </div>
        <div className="mono" style={{ fontSize: 11, color: "var(--muted)", marginTop: 2 }}>
          since {new Date(alert.created_at).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit" })}
        </div>
      </div>

      {/* Alert ID tile */}
      <div style={{
        background: "var(--surface)",
        border: "1px solid var(--border2)",
        borderRadius: var_radius,
        padding: "10px 16px",
        flex: 1,
        minWidth: 220,
      }}>
        <div className="mono text-dim" style={{ fontSize: 9, letterSpacing: "0.12em", marginBottom: 4 }}>ALERT ID</div>
        <div className="mono" style={{ fontSize: 11, color: "var(--muted)", wordBreak: "break-all" }}>{alert.id}</div>
      </div>
    </div>
  );
}

// workaround for template literal in style — CSS var
const var_radius = "var(--radius)";

// ── Main component ────────────────────────────────────────────────────────────
export default function AlertDetail() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [alert,      setAlert]      = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [notes,      setNotes]      = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg,  setSubmitMsg]  = useState("");

  useEffect(() => {
    api.alert(id)
      .then(data => { setAlert(data); setNotes(data.analyst_notes ?? ""); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  async function submitVerdict(verdict) {
    setSubmitting(true);
    setSubmitMsg("");
    try {
      const updated = await api.submitVerdict(id, verdict, notes);
      setAlert(updated);
      setSubmitMsg("Verdict saved — will be used as training context for future Claude prompts.");
    } catch (err) {
      setSubmitMsg(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div className="page">
        <Navbar wsStatus="disconnected" />
        <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
          <p className="text-muted mono">Loading alert…</p>
        </div>
      </div>
    );
  }

  if (!alert) return null;

  // ── Derived data ──────────────────────────────────────────────────────────
  const triage  = alert.triage_result ?? {};
  const payload = alert.normalized_payload ?? {};
  const status  = normaliseStatus(alert.status);

  // Split enrichment fields from data fields
  const dataRows      = Object.entries(payload).filter(([k]) => !k.startsWith("enrichment."));
  const enrichEntries = Object.entries(payload)
    .filter(([k]) => k.startsWith("enrichment."))
    // Hide tiles where value is "unknown" — they add noise, not signal
    .filter(([, v]) => v !== "unknown" && v !== null && v !== undefined);

  const confidencePct = Math.round((triage.confidence ?? 0) * 100);
  const borderColor   = PRIORITY_BORDER[alert.priority_queue] ?? "var(--border)";
  const isEscalated   = status === "escalated";
  const isSuppressed  = status === "suppressed";

  // Confidence bar colour
  const confColor =
    confidencePct >= 90 ? "var(--green)"  :
    confidencePct >= 70 ? "var(--yellow)" : "var(--orange)";

  return (
    <div className="page">
      <Navbar wsStatus="connected" />

      <div className="container fade-in" style={{ paddingTop: 24, paddingBottom: 36 }}>

        {/* ── Back button ────────────────────────────────────────────────── */}
        <button
          className="btn btn-ghost"
          style={{ marginBottom: 18, fontSize: 12 }}
          onClick={() => navigate("/")}
        >
          ← Back to queue
        </button>

        {/* ── Alert header card ──────────────────────────────────────────── */}
        <div className="detail-header" style={{ borderLeftColor: borderColor, marginBottom: 16 }}>
          <div>
            <div className="detail-badges">
              <PriorityBadge queue={alert.priority_queue} score={alert.priority_score} />
              <StatusBadge status={status} />
              {triage.verdict && <VerdictBadge verdict={triage.verdict} />}
            </div>
            <h1 className="detail-title">{alert.event_type}</h1>
            <p className="detail-meta text-muted">
              <span className="mono">{getSourceLabel(alert.source_type)}</span>
              <span style={{ margin: "0 8px", color: "var(--border2)" }}>·</span>
              {timeAgo(alert.created_at)}
            </p>
          </div>

          {/* Show filter reason as a subtle note, not the main content */}
          {alert.filter_reason && !isEscalated && (
            <div className="detail-filter-note">
              <small>PIPELINE DECISION</small>
              {alert.filter_reason}
            </div>
          )}
        </div>

        {/* ── ESCALATED: show action banner BEFORE anything else ─────────── */}
        {isEscalated && (
          <EscalatedBanner
            filterReason={alert.filter_reason}
            eventType={alert.event_type}
          />
        )}

        {/* ── Threat context strip ───────────────────────────────────────── */}
        {!isSuppressed && (
          <ThreatContext alert={alert} status={status} />
        )}

        {/* ── Two-column: data + verdict ─────────────────────────────────── */}
        <div className="detail-grid" style={{ marginBottom: 16 }}>

          {/* Left: Normalised alert data */}
          <Card title="NORMALISED ALERT DATA" icon="◈" titleColor="var(--cyan)">
            {dataRows.length > 0
              ? dataRows.map(([k, v]) => <DataRow key={k} label={k} value={v} />)
              : <p className="text-muted" style={{ fontSize: 13 }}>No normalised data available.</p>
            }
          </Card>

          {/* Right: Claude AI verdict */}
          <Card title="CLAUDE AI VERDICT" icon="⬡" titleColor="var(--purple)">
            {triage.verdict ? (
              <div className="stack gap-16">

                {/* Verdict + confidence + severity in one row */}
                <div className="row gap-8" style={{ flexWrap: "wrap" }}>
                  <VerdictBadge verdict={triage.verdict} />
                  <span
                    className="badge mono"
                    style={{ color: confColor, background: "var(--surface2)", borderColor: "var(--border)" }}
                  >
                    {confidencePct}% confidence
                  </span>
                  {triage.severity && (
                    <span
                      className="badge mono"
                      style={{ color: "var(--text)", background: "var(--surface2)", borderColor: "var(--border)" }}
                    >
                      {triage.severity}
                    </span>
                  )}
                </div>

                {/* Confidence bar */}
                <div className="confidence-bar-track">
                  <div className="confidence-bar-fill" style={{ width: `${confidencePct}%`, background: confColor }} />
                </div>

                {/* What happened — plain English */}
                <p style={{ fontSize: 13, lineHeight: 1.65 }}>{fixEncoding(triage.summary)}</p>

                {/* Recommended action — most important block visually */}
                {triage.verdict === "true_positive" ? (
                  /* For confirmed threats: bold red-bordered action block */
                  <div>
                    <div className="section-label">Recommended Action</div>
                    <div style={{
                      background: "rgba(244,63,94,0.07)",
                      border: "1px solid var(--red-border)",
                      borderLeft: "3px solid var(--red)",
                      borderRadius: "0 var(--radius) var(--radius) 0",
                      padding: "12px 16px",
                      fontSize: 13,
                      color: "#fca5a5",
                      lineHeight: 1.65,
                      fontWeight: 500,
                    }}>
                      {fixEncoding(triage.recommended_action)}
                    </div>
                  </div>
                ) : (
                  /* For needs_review / false_positive: standard blue block */
                  <div>
                    <div className="section-label">Recommended Action</div>
                    <div className="action-block">{fixEncoding(triage.recommended_action)}</div>
                  </div>
                )}

                {/* Claude's reasoning — secondary detail */}
                <div>
                  <div className="section-label">Why Claude Reached This Verdict</div>
                  <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
                    {fixEncoding(triage.reasoning)}
                  </p>
                </div>
              </div>
            ) : (
              /* No AI verdict — explain clearly why */
              <div style={{ textAlign: "center", padding: "28px 0" }}>
                <div style={{ fontSize: 28, opacity: 0.2, marginBottom: 12 }}>⬡</div>
                <p style={{ fontSize: 14, fontWeight: 600, color: "var(--text)", marginBottom: 8 }}>
                  {isEscalated  ? "Not AI-Triaged"       :
                   isSuppressed ? "Alert Suppressed"      :
                                  "Pending AI Analysis"   }
                </p>
                <p className="text-muted" style={{ fontSize: 13, maxWidth: 280, margin: "0 auto", lineHeight: 1.6 }}>
                  {isEscalated  ? "This alert was escalated directly to the analyst queue without AI triage. See the action banner above." :
                   isSuppressed ? "This event matched a suppression rule and was not sent for AI analysis. No action is needed." :
                                  "The AI pipeline is still processing this alert. Refresh in a moment." }
                </p>
              </div>
            )}
          </Card>
        </div>

        {/* ── Enrichment — only show tiles that have real data ──────────── */}
        {enrichEntries.length > 0 && (
          <Card
            title="IP REPUTATION & ASSET DATA"
            icon="🌐"
            titleColor="var(--blue)"
            style={{ marginBottom: 16 }}
          >
            <div className="enrichment-grid">
              {enrichEntries.map(([k, v]) => {
                // Build a friendly label from the field name
                const label = k
                  .replace("enrichment.", "")
                  .replace(/_/g, " ")
                  .toUpperCase();

                // Highlight dangerous enrichment values in red
                const isDangerous = v === true && (k.includes("proxy") || k.includes("hosting"));

                return (
                  <div
                    key={k}
                    className="enrichment-tile"
                    style={isDangerous ? { borderColor: "var(--red-border)", background: "var(--red-bg)" } : {}}
                  >
                    <div className="enrichment-key">{label}</div>
                    <div
                      className="enrichment-val"
                      style={isDangerous ? { color: "var(--red)", fontWeight: 700 } : {}}
                    >
                      {/* Show boolean as Yes / No rather than true / false */}
                      {typeof v === "boolean" ? (v ? "Yes" : "No") : String(v)}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Warn analyst if IP is a known proxy/Tor */}
            {payload["enrichment.source_ip.is_proxy"] === true && (
              <div style={{
                marginTop: 12,
                background: "rgba(244,63,94,0.07)",
                border: "1px solid var(--red-border)",
                borderRadius: "var(--radius)",
                padding: "8px 14px",
                fontSize: 12,
                color: "var(--red)",
              }}>
                ⚠ Source IP is a known anonymising proxy or Tor exit node — attacker is concealing their real location.
              </div>
            )}
          </Card>
        )}

        {/* ── Analyst verdict panel ──────────────────────────────────────── */}
        <Card title="ANALYST VERDICT" icon="🔍" titleColor="var(--cyan)">

          {/* Show existing verdict if already recorded */}
          {alert.analyst_verdict && (
            <div className="analyst-current">
              <span className="mono text-muted" style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em" }}>
                RECORDED:
              </span>
              <VerdictBadge verdict={alert.analyst_verdict} />
              {alert.analyst_notes && (
                <span className="text-muted" style={{ fontSize: 12, fontStyle: "italic" }}>
                  "{alert.analyst_notes}"
                </span>
              )}
            </div>
          )}

          {/* Notes field — optional context that Claude will use for future prompts */}
          <div className="field" style={{ marginBottom: 16 }}>
            <label className="field-label">
              Analyst notes
              <span className="text-dim" style={{ fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
                {" "}— optional · used as few-shot context to improve future Claude triage
              </span>
            </label>
            <textarea
              value={notes}
              onChange={e => setNotes(e.target.value)}
              rows={2}
              placeholder="e.g. Confirmed — same actor as incident #1042. Block entire /24 subnet."
              style={{ resize: "vertical", fontFamily: "var(--mono)", fontSize: 12, lineHeight: 1.6 }}
            />
          </div>

          {/* Verdict buttons */}
          <div className="verdict-actions">
            {VERDICT_BTNS.map(btn => (
              <button
                key={btn.value}
                className="verdict-btn"
                disabled={submitting}
                onClick={() => submitVerdict(btn.value)}
                style={{ color: btn.color, background: btn.bg, borderColor: btn.border }}
              >
                {btn.label}
              </button>
            ))}
          </div>

          {/* Submission result message */}
          {submitMsg && (
            <div
              className={`alert-msg ${submitMsg.startsWith("Error") ? "error" : "success"}`}
              style={{ marginTop: 14 }}
            >
              {submitMsg}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
