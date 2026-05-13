import uuid
import logging
from fastapi import APIRouter, Depends, BackgroundTasks
from psycopg import Connection
from psycopg.types.json import Jsonb
from backend.database import get_db
from backend.schemas import RawEventIn, IngestResponse
from backend.core.normalizer import normalize, extract_severity
from backend.core.deduplicator import make_hash, is_duplicate
from backend.core.ws_manager import ws_manager
from backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["ingest"])


def _queue_for_processing(alert_id: str, normalized: dict):
    from backend.core.prefilter import apply_prefilter
    from backend.core.throttle import is_throttled
    from backend.core.scrubber import scrub
    from backend.core.enricher import enrich
    from backend.core.claude_engine import triage_alert
    from backend.core.scorer import score_alert
    from backend.core.notifier import notify
    from backend.database import (
        open_db,
        update_alert_status,
        update_normalized_payload,
        update_triage_result,
        update_priority,
        get_feedback_examples,
    )

    source_ip   = normalized.get("source.ip", "")
    source_type = normalized.get("source.type", "")
    try:
        with open_db() as conn:
            throttled  = is_throttled(conn, source_ip)
            result     = apply_prefilter(normalized, throttled=throttled)
            scrubbed   = scrub(normalized)
            enrichment = enrich(scrubbed)
            enriched   = {**scrubbed, **enrichment}
            update_normalized_payload(conn, alert_id, enriched)

            triage = None
            if result.action == "triage":
                # Feedback loop: fetch analyst-verified examples to improve Claude's accuracy
                few_shots = get_feedback_examples(conn, limit=5)
                triage = triage_alert(enriched, source_type=source_type, few_shots=few_shots)
                update_triage_result(conn, alert_id, triage)
                score, queue = score_alert(triage, enriched)
            elif result.action == "escalate":
                score, queue = 100, "P1"
            else:
                score, queue = 0, "P4"

            update_priority(conn, alert_id, score, queue)

            # Normalise status to past-tense strings matching the API contract
            STATUS_MAP = {"triage": "triage", "escalate": "escalated", "suppress": "suppressed"}
            final_status = STATUS_MAP.get(result.action, result.action)
            update_alert_status(conn, alert_id, final_status, result.reason)

            if queue in ("P1", "P2"):
                notify(alert_id, enriched, triage, queue)

            logger.info(f"[pipeline] alert {alert_id} → {result.action} | {queue} score={score}")

            # ── Live update: push to all connected dashboard clients ──────────
            ws_manager.broadcast_from_thread({
                "type": "alert_updated",
                "alert_id": alert_id,
                "status": final_status,
                "queue": queue,
                "score": score,
            })

    except Exception as exc:
        logger.error(f"[pipeline] pipeline failed for {alert_id}: {exc}")


@router.post("/ingest", response_model=IngestResponse, status_code=202)
def ingest_alert(
    event: RawEventIn,
    background_tasks: BackgroundTasks,
    conn: Connection = Depends(get_db),
):
    normalized = normalize(event.event_type, event.payload)
    normalized["source.type"] = event.source_type
    event_hash = make_hash(event.event_type, normalized)

    dupe, existing_id = is_duplicate(conn, event_hash, settings.dedup_window_seconds)
    if dupe:
        return IngestResponse(
            alert_id=existing_id,
            status="duplicate",
            message="Alert already ingested within dedup window",
        )

    alert_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO alerts
            (id, event_type, source_type, raw_payload, normalized_payload, event_hash, severity, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            alert_id,
            event.event_type,
            event.source_type,
            Jsonb(event.payload),
            Jsonb(normalized),
            event_hash,
            extract_severity(event.payload),
            "queued",
        ),
    )
    conn.commit()

    background_tasks.add_task(_queue_for_processing, alert_id, normalized)

    return IngestResponse(
        alert_id=alert_id,
        status="queued",
        message="Alert ingested and queued for triage",
    )
