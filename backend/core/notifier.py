import httpx
import logging
from datetime import datetime, timezone
from backend.config import settings

logger = logging.getLogger(__name__)

_QUEUE_EMOJI  = {"P1": "🚨", "P2": "⚠️"}
_QUEUE_COLOR  = {"P1": "#FF0000", "P2": "#FF8C00"}
_QUEUE_LABEL  = {"P1": "CRITICAL — Immediate Response", "P2": "HIGH — Urgent Review"}


def _build_payload(alert_id: str, enriched: dict, triage: dict | None, queue: str) -> dict:
    event_type  = enriched.get("event.type", "unknown")
    source_ip   = enriched.get("source.ip", "unknown")
    country     = enriched.get("enrichment.source_ip.country", "unknown")
    asset       = enriched.get("enrichment.asset.name", "unknown")
    criticality = enriched.get("enrichment.asset.criticality", "unknown")
    timestamp   = enriched.get("@timestamp", datetime.now(timezone.utc).isoformat())

    emoji = _QUEUE_EMOJI.get(queue, "🔔")
    color = _QUEUE_COLOR.get(queue, "#888888")
    label = _QUEUE_LABEL.get(queue, queue)

    fields = [
        {"title": "Alert ID",    "value": alert_id,                          "short": True},
        {"title": "Event Type",  "value": event_type,                        "short": True},
        {"title": "Source IP",   "value": f"{source_ip} ({country})",        "short": True},
        {"title": "Asset",       "value": f"{asset} [{criticality}]",        "short": True},
    ]

    if triage:
        verdict    = triage.get("verdict", "unknown")
        confidence = triage.get("confidence", 0.0)
        action     = triage.get("recommended_action", "Review manually.")
        fields += [
            {"title": "Verdict",    "value": f"{verdict} ({confidence:.0%})", "short": True},
            {"title": "Action",     "value": action,                          "short": False},
        ]
    else:
        fields.append({"title": "Reason", "value": "Auto-escalated — CRITICAL severity or high attempt count", "short": False})

    return {
        "attachments": [{
            "color":      color,
            "title":      f"{emoji} AlertIQ {label}",
            "text":       triage.get("summary", "") if triage else f"Alert requires immediate analyst attention.",
            "fields":     fields,
            "footer":     "AlertIQ SIEM",
            "ts":         timestamp,
        }]
    }


def notify(alert_id: str, enriched: dict, triage: dict | None, queue: str) -> None:
    event_type = enriched.get("event.type", "unknown")
    verdict    = triage.get("verdict") if triage else "auto-escalated"

    logger.warning(f"[notifier] {queue} alert fired | id={alert_id} type={event_type} verdict={verdict}")

    if not settings.slack_webhook_url:
        logger.info("[notifier] SLACK_WEBHOOK_URL not set — logged only")
        return

    payload = _build_payload(alert_id, enriched, triage, queue)
    try:
        resp = httpx.post(settings.slack_webhook_url, json=payload, timeout=5.0)
        resp.raise_for_status()
        logger.info(f"[notifier] Slack notification sent for {alert_id}")
    except Exception as exc:
        logger.error(f"[notifier] Slack notification failed: {exc}")
