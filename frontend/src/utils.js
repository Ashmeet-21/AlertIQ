/**
 * utils.js — shared helper data and functions
 *
 * Centralised here so the same logic works across Dashboard and AlertDetail.
 * Any security analyst can update these mappings without touching component logic.
 */

// ── MITRE ATT&CK mappings ─────────────────────────────────────────────────────
// Maps event_type strings to MITRE tactic, technique ID, and technique name.
// Security analysts think in ATT&CK — showing this immediately communicates context.

export const MITRE_MAP = {
  login_failure:          { tactic: "Credential Access",    technique: "T1110", name: "Brute Force"                           },
  failed_login:           { tactic: "Credential Access",    technique: "T1110", name: "Brute Force"                           },
  auth_failure:           { tactic: "Credential Access",    technique: "T1110", name: "Brute Force"                           },
  data_exfiltration:      { tactic: "Exfiltration",         technique: "T1048", name: "Exfiltration Over Alternative Protocol" },
  port_scan:              { tactic: "Reconnaissance",       technique: "T1046", name: "Network Service Discovery"             },
  malware_detected:       { tactic: "Execution",            technique: "T1204", name: "User Execution"                        },
  privilege_escalation:   { tactic: "Privilege Escalation", technique: "T1068", name: "Exploitation for Privilege Escalation" },
  lateral_movement:       { tactic: "Lateral Movement",     technique: "T1021", name: "Remote Services"                       },
  suspicious_process:     { tactic: "Execution",            technique: "T1059", name: "Command and Scripting Interpreter"     },
  account_created:        { tactic: "Persistence",          technique: "T1136", name: "Create Account"                        },
  config_change:          { tactic: "Defense Evasion",      technique: "T1562", name: "Impair Defenses"                       },
  heartbeat:              null, // suppressed — no ATT&CK mapping
  health_check:           null,
};

/** Returns MITRE info for an event type, or null if unknown. */
export function getMitre(eventType) {
  return MITRE_MAP[eventType?.toLowerCase()] ?? null;
}

// ── Source type friendly labels ───────────────────────────────────────────────
// Converts developer-facing identifiers to human-readable names.
// "identity_system" → "Identity Provider" is immediately clear to any analyst.

const SOURCE_LABELS = {
  identity_system:  "Identity Provider",
  dlp_system:       "DLP System",
  dlp:              "DLP",
  monitoring:       "Monitoring System",
  firewall:         "Firewall / NGFW",
  ids:              "IDS / IPS",
  ips:              "IDS / IPS",
  edr:              "Endpoint (EDR)",
  siem:             "SIEM",
  cloud:            "Cloud Provider",
  waf:              "Web Application Firewall",
};

/** Returns a readable source label, falling back to the raw value. */
export function getSourceLabel(sourceType) {
  return SOURCE_LABELS[sourceType?.toLowerCase()] ?? sourceType ?? "Unknown Source";
}

// ── Status normalisation ──────────────────────────────────────────────────────
// Some older DB records have "escalate" (action name) instead of "escalated"
// (status name). Normalise on the way into the UI so badges are consistent.

const STATUS_NORM = { escalate: "escalated", suppress: "suppressed" };

export function normaliseStatus(status) {
  return STATUS_NORM[status] ?? status;
}

// ── Status descriptions ───────────────────────────────────────────────────────
// Plain-English tooltip / subtitle for each status value.
// Especially important for "triage" which is commonly misunderstood.

export const STATUS_DESCRIPTIONS = {
  triage:     "AI has reviewed this alert and produced a verdict.",
  escalated:  "Automatically escalated — requires immediate analyst review.",
  suppressed: "Filtered out as known noise — no action needed.",
  queued:     "Waiting for the AI pipeline to process.",
  duplicate:  "Identical event received within the dedup window.",
};

// ── Time formatting ───────────────────────────────────────────────────────────

export function timeAgo(dateStr) {
  const mins = Math.floor((Date.now() - new Date(dateStr)) / 60000);
  if (mins < 1)   return "just now";
  if (mins < 60)  return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)   return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/** Returns how long in human words since the date, with a label. */
export function timeSince(dateStr) {
  const diff = Date.now() - new Date(dateStr);
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return "less than a minute";
  if (mins < 60) return `${mins} minute${mins !== 1 ? "s" : ""}`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs} hour${hrs !== 1 ? "s" : ""}`;
  return `${Math.floor(hrs / 24)} day${Math.floor(hrs / 24) !== 1 ? "s" : ""}`;
}

// ── Text sanitisation ─────────────────────────────────────────────────────────
// Fixes UTF-8 double-encoding artifacts from Claude CLI output.
// e.g. "â€"" (double-encoded em dash) → "—"

export function fixEncoding(text) {
  if (!text) return text;
  try {
    // Decode as if it were latin-1 bytes re-interpreted from UTF-8
    return decodeURIComponent(escape(text));
  } catch {
    return text;
  }
}
