/**
 * VerdictBadge — AI / analyst verdict (TRUE POSITIVE, NEEDS REVIEW, etc.)
 * StatusBadge  — pipeline status (TRIAGE, ESCALATED, SUPPRESSED, etc.)
 *
 * StatusBadge also normalises old "escalate" DB values → "escalated" so
 * both old and new records display consistently.
 */
import { normaliseStatus, STATUS_DESCRIPTIONS } from "../utils.js";

const VERDICT_COLORS = {
  true_positive:  { color: "var(--red)",    bg: "var(--red-bg)",    border: "var(--red-border)",    label: "TRUE POSITIVE"  },
  false_positive: { color: "var(--green)",  bg: "var(--green-bg)",  border: "var(--green-border)",  label: "FALSE POSITIVE" },
  needs_review:   { color: "var(--yellow)", bg: "var(--yellow-bg)", border: "var(--yellow-border)", label: "NEEDS REVIEW"   },
};

const STATUS_COLORS = {
  triage:     { color: "var(--purple)", bg: "var(--purple-bg)", border: "var(--purple-border)", label: "AI REVIEWED"  },
  escalated:  { color: "var(--red)",    bg: "var(--red-bg)",    border: "var(--red-border)",    label: "ESCALATED"    },
  suppressed: { color: "var(--gray)",   bg: "var(--gray-bg)",   border: "var(--gray-border)",   label: "SUPPRESSED"   },
  queued:     { color: "var(--cyan)",   bg: "var(--cyan-bg)",   border: "var(--cyan-border)",   label: "PENDING"      },
  duplicate:  { color: "var(--gray)",   bg: "var(--gray-bg)",   border: "var(--gray-border)",   label: "DUPLICATE"    },
};

const FALLBACK = { color: "var(--gray)", bg: "var(--gray-bg)", border: "var(--gray-border)" };

export function VerdictBadge({ verdict }) {
  const s = VERDICT_COLORS[verdict] ?? { ...FALLBACK, label: verdict ?? "—" };
  return (
    <span className="badge" style={{ color: s.color, background: s.bg, borderColor: s.border }}>
      {s.label}
    </span>
  );
}

export function StatusBadge({ status }) {
  // Normalise old "escalate" action values before looking up colours
  const norm = normaliseStatus(status);
  const s    = STATUS_COLORS[norm] ?? { ...FALLBACK, label: norm ?? "—" };
  const desc = STATUS_DESCRIPTIONS[norm];

  return (
    <span
      className="badge"
      style={{ color: s.color, background: s.bg, borderColor: s.border }}
      title={desc} // tooltip explains what the status means
    >
      {s.label}
    </span>
  );
}
