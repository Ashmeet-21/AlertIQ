/**
 * PriorityBadge
 * Shows the alert priority (P1–P4) with a colour-coded badge.
 * P1 CRITICAL gets a pulsing dot to draw attention.
 */

// Colour definitions per priority level
const STYLES = {
  P1: { color: "var(--red)",    bg: "var(--red-bg)",    border: "var(--red-border)",    label: "P1 CRITICAL" },
  P2: { color: "var(--orange)", bg: "var(--orange-bg)", border: "var(--orange-border)", label: "P2 HIGH"     },
  P3: { color: "var(--yellow)", bg: "var(--yellow-bg)", border: "var(--yellow-border)", label: "P3 MEDIUM"   },
  P4: { color: "var(--green)",  bg: "var(--green-bg)",  border: "var(--green-border)",  label: "P4 LOW"      },
};

export default function PriorityBadge({ queue, score }) {
  const s = STYLES[queue] ?? {
    color: "var(--gray)",
    bg: "var(--gray-bg)",
    border: "var(--gray-border)",
    label: queue ?? "—",
  };

  return (
    <span
      className="badge"
      style={{ color: s.color, background: s.bg, borderColor: s.border }}
    >
      {/* Animated dot only for critical alerts */}
      {queue === "P1" && (
        <span
          className="pulse"
          style={{
            width: 5, height: 5, borderRadius: "50%",
            background: s.color,
            display: "inline-block",
            flexShrink: 0,
          }}
        />
      )}
      {s.label}{score != null ? ` (${score})` : ""}
    </span>
  );
}
