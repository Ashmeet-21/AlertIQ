from dataclasses import dataclass


@dataclass
class FilterResult:
    action: str  # "suppress" | "escalate" | "triage"
    reason: str


# Suppress group: checked first — matching alert is dropped, no further processing.
SUPPRESS_RULES = [
    {
        "field": "event.type",
        "values": ["heartbeat", "health_check", "ping", "keepalive", "noop"],
        "reason": "routine noise event type",
    },
]

# Escalate group: matching alert bypasses Claude and goes straight to analyst queue.
ESCALATE_RULES = [
    {
        "field": "event.severity",
        "values": ["CRITICAL"],
        "reason": "explicit CRITICAL severity",
    },
    {
        "field": "event.count",
        "min": 50,
        "reason": "very high attempt count (>=50)",
    },
]


def apply_prefilter(normalized: dict, throttled: bool = False) -> FilterResult:
    if throttled:
        return FilterResult(action="suppress", reason="source IP throttled — alert storm detected")

    event_type = str(normalized.get("event.type", "")).lower()
    for rule in SUPPRESS_RULES:
        if rule["field"] == "event.type":
            if event_type in [v.lower() for v in rule["values"]]:
                return FilterResult(action="suppress", reason=rule["reason"])

    for rule in ESCALATE_RULES:
        field_val = normalized.get(rule["field"])
        if field_val is None:
            continue
        if "values" in rule:
            if str(field_val).upper() in [v.upper() for v in rule["values"]]:
                return FilterResult(action="escalate", reason=rule["reason"])
        if "min" in rule:
            try:
                if int(field_val) >= rule["min"]:
                    return FilterResult(action="escalate", reason=rule["reason"])
            except (ValueError, TypeError):
                pass

    return FilterResult(action="triage", reason="passed pre-filter — queued for AI triage")
