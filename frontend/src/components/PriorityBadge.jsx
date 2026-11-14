// Solid priority block: the queue is read top-down by this column
export default function PriorityBadge({ queue, score }) {
  return (
    <div className="prio" data-q={queue ?? ""} aria-label={queue ? `Priority ${queue}, score ${score}` : "No priority"}>
      <strong>{queue ?? "–"}</strong>
      {score != null && <span>{score}</span>}
    </div>
  );
}
