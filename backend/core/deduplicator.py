import hashlib
from datetime import datetime, timedelta, timezone
from psycopg import Connection


def make_hash(event_type: str, normalized: dict) -> str:
    key = "|".join([
        event_type,
        str(normalized.get("source.ip", "")),
        str(normalized.get("destination.ip", "")),
        str(normalized.get("user.name", "")),
        str(normalized.get("host.name", "")),
    ])
    return hashlib.md5(key.encode()).hexdigest()


def is_duplicate(conn: Connection, event_hash: str, window_seconds: int) -> tuple[bool, str | None]:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    row = conn.execute(
        "SELECT id FROM alerts WHERE event_hash = %s AND created_at >= %s LIMIT 1",
        (event_hash, cutoff),
    ).fetchone()
    if row:
        return True, str(row[0])
    return False, None
