import psycopg
from backend.config import settings


def get_db():
    conn = psycopg.connect(settings.database_url)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def open_db() -> psycopg.Connection:
    return psycopg.connect(settings.database_url)


def update_alert_status(conn: psycopg.Connection, alert_id: str, status: str, filter_reason: str | None = None) -> None:
    conn.execute(
        "UPDATE alerts SET status = %s, filter_reason = %s WHERE id = %s",
        (status, filter_reason, alert_id),
    )
    conn.commit()


def update_normalized_payload(conn: psycopg.Connection, alert_id: str, payload: dict) -> None:
    from psycopg.types.json import Jsonb
    conn.execute(
        "UPDATE alerts SET normalized_payload = %s WHERE id = %s",
        (Jsonb(payload), alert_id),
    )


def update_triage_result(conn: psycopg.Connection, alert_id: str, result: dict) -> None:
    from psycopg.types.json import Jsonb
    conn.execute(
        "UPDATE alerts SET triage_result = %s WHERE id = %s",
        (Jsonb(result), alert_id),
    )


def update_priority(conn: psycopg.Connection, alert_id: str, score: int, queue: str) -> None:
    conn.execute(
        "UPDATE alerts SET priority_score = %s, priority_queue = %s WHERE id = %s",
        (score, queue, alert_id),
    )


def update_analyst_verdict(
    conn: psycopg.Connection,
    alert_id: str,
    analyst_verdict: str,
    analyst_notes: str | None,
    analyst_id: str,
) -> None:
    """Record an analyst's TP/FP/NR verdict on an alert."""
    conn.execute(
        """UPDATE alerts
              SET analyst_verdict = %s,
                  analyst_notes   = %s,
                  analyst_id      = %s
            WHERE id = %s""",
        (analyst_verdict, analyst_notes, analyst_id, alert_id),
    )
    conn.commit()


def get_feedback_examples(conn: psycopg.Connection, limit: int = 5) -> list[dict]:
    """
    Return recent alerts where an analyst confirmed a verdict.
    Used as few-shot examples in the Claude prompt (feedback loop).
    Only returns alerts with a definitive TP or FP verdict.
    """
    rows = conn.execute(
        """SELECT normalized_payload, triage_result, analyst_verdict, analyst_notes
             FROM alerts
            WHERE analyst_verdict IN ('true_positive', 'false_positive')
            ORDER BY created_at DESC
            LIMIT %s""",
        (limit,),
    ).fetchall()

    examples = []
    for row in rows:
        examples.append({
            "alert": row[0],
            "ai_verdict": (row[1] or {}).get("verdict", "unknown"),
            "analyst_verdict": row[2],
            "analyst_notes": row[3] or "",
        })
    return examples
