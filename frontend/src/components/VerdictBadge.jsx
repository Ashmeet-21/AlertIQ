import { VERDICT_LABELS } from "../utils.js";

export function VerdictBadge({ verdict }) {
  if (!verdict) return null;
  return <span className="verdict" data-v={verdict}>{VERDICT_LABELS[verdict] ?? verdict}</span>;
}
