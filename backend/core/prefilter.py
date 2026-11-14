from dataclasses import dataclass


@dataclass
class FilterResult:
    action: str  # "suppress" | "escalate" | "triage"
    reason: str


# Routine noise: dropped, no further processing
NOISE_EVENT_TYPES = {"heartbeat", "health_check", "ping", "keepalive", "noop"}
# At or above this attempt count the alert skips the AI and goes straight to an analyst
ESCALATE_MIN_COUNT = 50


def apply_prefilter(normalized: dict, throttled: bool = False) -> FilterResult:
    if throttled:
        return FilterResult(action="suppress", reason="source IP throttled — alert storm detected")

    event_type = str(normalized.get("event.type", "")).lower()
    if event_type in NOISE_EVENT_TYPES:
        return FilterResult(action="suppress", reason="routine noise event type")

    severity = normalized.get("event.severity")
    if severity is not None and str(severity).upper() == "CRITICAL":
        return FilterResult(action="escalate", reason="explicit CRITICAL severity")

    count = normalized.get("event.count")
    if count is not None:
        try:
            if int(count) >= ESCALATE_MIN_COUNT:
                return FilterResult(action="escalate", reason="very high attempt count (>=50)")
        except (ValueError, TypeError):
            pass

    return FilterResult(action="triage", reason="passed pre-filter — queued for AI triage")
