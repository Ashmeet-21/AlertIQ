import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg import Connection
from backend.database import get_db, update_analyst_verdict
from backend.core.auth import require_analyst
from backend.core.ws_manager import ws_manager
from backend.schemas import AlertOut, AlertStats, VerdictUpdate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])

ALERT_COLUMNS = (
    "id, event_type, source_type, normalized_payload, severity, status, "
    "filter_reason, triage_result, priority_score, priority_queue, "
    "analyst_verdict, analyst_notes, created_at"
)


def _row_to_alert(r) -> AlertOut:
    return AlertOut(
        id=r[0],
        event_type=r[1],
        source_type=r[2],
        normalized_payload=r[3],
        severity=r[4],
        status=r[5],
        filter_reason=r[6],
        triage_result=r[7],
        priority_score=r[8],
        priority_queue=r[9],
        analyst_verdict=r[10],
        analyst_notes=r[11],
        created_at=r[12],
    )


# ── GET /alerts/stats ──────────────────────────────────────────────────────────

@router.get("/stats", response_model=AlertStats)
def get_stats(
    conn: Connection = Depends(get_db),
    _: dict = Depends(require_analyst),
):
    """Dashboard summary: total count and breakdown by queue/status."""
    row = conn.execute(
        """
        SELECT
            COUNT(*)                                             AS total,
            COUNT(*) FILTER (WHERE priority_queue = 'P1')       AS p1,
            COUNT(*) FILTER (WHERE priority_queue = 'P2')       AS p2,
            COUNT(*) FILTER (WHERE priority_queue = 'P3')       AS p3,
            COUNT(*) FILTER (WHERE priority_queue = 'P4')       AS p4,
            COUNT(*) FILTER (WHERE status = 'queued')           AS queued,
            COUNT(*) FILTER (WHERE status = 'triage')           AS triage,
            COUNT(*) FILTER (WHERE status = 'escalated')        AS escalated,
            COUNT(*) FILTER (WHERE status = 'suppressed')       AS suppressed
        FROM alerts
        """
    ).fetchone()
    return AlertStats(
        total=row[0],
        p1=row[1],
        p2=row[2],
        p3=row[3],
        p4=row[4],
        queued=row[5],
        triage=row[6],
        escalated=row[7],
        suppressed=row[8],
    )


# ── GET /alerts ────────────────────────────────────────────────────────────────

@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: str | None = Query(None, description="Filter by status"),
    queue: str | None = Query(None, description="Filter by priority queue: P1–P4"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    conn: Connection = Depends(get_db),
    _: dict = Depends(require_analyst),
):
    conditions: list[str] = []
    params: list = []

    if status:
        conditions.append("status = %s")
        params.append(status)
    if queue:
        conditions.append("priority_queue = %s")
        params.append(queue)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    rows = conn.execute(
        f"SELECT {ALERT_COLUMNS} FROM alerts {where} ORDER BY created_at DESC LIMIT %s OFFSET %s",
        params,
    ).fetchall()

    return [_row_to_alert(r) for r in rows]


# ── GET /alerts/{alert_id} ─────────────────────────────────────────────────────

@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: str,
    conn: Connection = Depends(get_db),
    _: dict = Depends(require_analyst),
):
    row = conn.execute(
        f"SELECT {ALERT_COLUMNS} FROM alerts WHERE id = %s",
        (alert_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _row_to_alert(row)


# ── PATCH /alerts/{alert_id}/verdict ──────────────────────────────────────────

VALID_VERDICTS = {"true_positive", "false_positive", "needs_review"}


@router.patch("/{alert_id}/verdict", response_model=AlertOut)
def submit_verdict(
    alert_id: str,
    body: VerdictUpdate,
    conn: Connection = Depends(get_db),
    user: dict = Depends(require_analyst),
):
    """
    Analyst submits a TP / FP / NR verdict.
    - Stored on the alert row for the feedback loop (few-shot prompting).
    - Broadcasts an alert_updated event via WebSocket so the dashboard
      reflects the change instantly without a page refresh.
    """
    if body.analyst_verdict not in VALID_VERDICTS:
        raise HTTPException(
            status_code=422,
            detail=f"analyst_verdict must be one of: {sorted(VALID_VERDICTS)}",
        )

    row = conn.execute("SELECT id FROM alerts WHERE id = %s", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    update_analyst_verdict(conn, alert_id, body.analyst_verdict, body.analyst_notes, user["id"])
    logger.info(
        f"[verdict] alert={alert_id} analyst={user['email']} "
        f"verdict={body.analyst_verdict}"
    )

    # Broadcast so the dashboard updates without a refresh
    ws_manager.broadcast_from_thread({
        "type": "verdict_submitted",
        "alert_id": alert_id,
        "analyst_verdict": body.analyst_verdict,
    })

    # Return the updated alert
    updated = conn.execute(
        f"SELECT {ALERT_COLUMNS} FROM alerts WHERE id = %s", (alert_id,)
    ).fetchone()
    return _row_to_alert(updated)
