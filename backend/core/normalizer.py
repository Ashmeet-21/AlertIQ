from datetime import datetime, timezone


# Maps common raw field names → unified schema keys (ECS-inspired)
FIELD_MAP = {
    "src_ip":        "source.ip",
    "source_ip":     "source.ip",
    "dest_ip":       "destination.ip",
    "destination_ip":"destination.ip",
    "user":          "user.name",
    "username":      "user.name",
    "host":          "host.name",
    "hostname":      "host.name",
    "message":       "event.message",
    "msg":           "event.message",
    "severity":      "event.severity",
    "attempts":      "event.count",
    "count":         "event.count",
    "timespan_sec":  "event.duration_sec",
}


def normalize(event_type: str, raw: dict) -> dict:
    normalized = {
        "event.type": event_type,
        "@timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
    }
    for raw_key, value in raw.items():
        mapped = FIELD_MAP.get(raw_key)
        if mapped:
            normalized[mapped] = value
    return normalized


def extract_severity(raw: dict) -> str | None:
    sev = raw.get("severity") or raw.get("priority") or raw.get("level")
    if sev:
        return str(sev).upper()
    # Infer from attempt count if no explicit severity
    count = raw.get("attempts") or raw.get("count") or 0
    if int(count) >= 20:
        return "HIGH"
    if int(count) >= 5:
        return "MEDIUM"
    return "LOW"
