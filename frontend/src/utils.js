// event_type -> MITRE ATT&CK technique, shown on the alert page
export const MITRE_MAP = {
  login_failure:        { technique: "T1110", name: "Brute Force" },
  failed_login:         { technique: "T1110", name: "Brute Force" },
  auth_failure:         { technique: "T1110", name: "Brute Force" },
  data_exfiltration:    { technique: "T1048", name: "Exfiltration Over Alternative Protocol" },
  port_scan:            { technique: "T1046", name: "Network Service Discovery" },
  malware_detected:     { technique: "T1204", name: "User Execution" },
  privilege_escalation: { technique: "T1068", name: "Exploitation for Privilege Escalation" },
  lateral_movement:     { technique: "T1021", name: "Remote Services" },
  suspicious_process:   { technique: "T1059", name: "Command and Scripting Interpreter" },
  account_created:      { technique: "T1136", name: "Create Account" },
  config_change:        { technique: "T1562", name: "Impair Defenses" },
  c2_beacon:            { technique: "T1071", name: "Application Layer Protocol" },
  suspicious_email:     { technique: "T1566", name: "Phishing" },
};

export function getMitre(eventType) {
  return MITRE_MAP[eventType?.toLowerCase()] ?? null;
}

const SOURCE_LABELS = {
  identity_system: "Identity provider",
  email_gateway:   "Email gateway",
  network_ids:     "Network IDS",
  firewall:        "Firewall",
  edr:             "Endpoint (EDR)",
  agent:           "Host agent",
  dlp:             "DLP",
  waf:             "Web application firewall",
  cloud:           "Cloud provider",
};

export function getSourceLabel(sourceType) {
  return SOURCE_LABELS[sourceType?.toLowerCase()] ?? sourceType ?? "Unknown source";
}

// "privilege_escalation" -> "Privilege escalation"
export function humanize(id) {
  if (!id) return "";
  const s = String(id).replace(/[_.]+/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export const VERDICT_LABELS = {
  true_positive:  "Threat",
  false_positive: "Not a threat",
  needs_review:   "Needs review",
};

// Older rows stored the action name ("escalate") instead of the status
const STATUS_NORM = { escalate: "escalated", suppress: "suppressed" };

export function normaliseStatus(status) {
  return STATUS_NORM[status] ?? status;
}

export const STATUS_LABELS = {
  triage:     "Reviewed by AI",
  escalated:  "Escalated by rule",
  suppressed: "Suppressed as noise",
  queued:     "Waiting for AI",
  duplicate:  "Duplicate",
  error:      "Pipeline error",
};

export const PROVIDER_LABELS = {
  anthropic:  "Claude API",
  claude_cli: "Claude (CLI)",
  ollama:     "local model",
  rules:      "built-in rules",
};

export function timeAgo(dateStr) {
  const mins = Math.floor((Date.now() - new Date(dateStr)) / 60000);
  if (mins < 1)  return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs} h ago`;
  return `${Math.floor(hrs / 24)} d ago`;
}
