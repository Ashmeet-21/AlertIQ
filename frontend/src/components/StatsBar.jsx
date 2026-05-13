/**
 * StatsBar
 * Shows 8 summary numbers across the top of the dashboard.
 * Each card has a coloured top border so it's scannable at a glance.
 */

// One card — label, big number, accent colour
function StatCard({ label, value, color, icon }) {
  return (
    <div
      className="stat-card"
      style={{ borderTopColor: color }}
    >
      {/* Subtle radial tint matching the accent colour */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        background: `radial-gradient(ellipse at top, ${color}0d 0%, transparent 60%)`,
      }} />

      <div className="stat-label">{icon} {label}</div>
      <div className="stat-value" style={{ color }}>{value ?? "—"}</div>
    </div>
  );
}

export default function StatsBar({ stats }) {
  // Show skeleton placeholders while data is loading
  if (!stats) {
    return (
      <div className="stats-grid">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="stat-card" style={{ borderTopColor: "var(--border)", height: 72 }} />
        ))}
      </div>
    );
  }

  return (
    <div className="stats-grid">
      <StatCard label="TOTAL"      value={stats.total}      color="var(--cyan)"   icon="◈" />
      <StatCard label="P1 CRIT"    value={stats.p1}         color="var(--red)"    icon="▲" />
      <StatCard label="P2 HIGH"    value={stats.p2}         color="var(--orange)" icon="▲" />
      <StatCard label="P3 MED"     value={stats.p3}         color="var(--yellow)" icon="◆" />
      <StatCard label="P4 LOW"     value={stats.p4}         color="var(--green)"  icon="◆" />
      <StatCard label="ESCALATED"  value={stats.escalated}  color="var(--red)"    icon="⚡" />
      <StatCard label="TRIAGE"     value={stats.triage}     color="var(--purple)" icon="⬡" />
      <StatCard label="SUPPRESSED" value={stats.suppressed} color="var(--gray)"   icon="◎" />
    </div>
  );
}
