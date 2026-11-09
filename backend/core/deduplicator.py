import hashlib
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
    # Window computed by Postgres: created_at is a naive NOW() timestamp, so comparing it
    # with a Python UTC datetime breaks whenever the DB timezone isn't UTC.
    row = conn.execute(
        "SELECT id FROM alerts WHERE event_hash = %s AND created_at >= NOW() - make_interval(secs => %s) LIMIT 1",
        (event_hash, window_seconds),
    ).fetchone()
    if row:
        return True, str(row[0])
    return False, None
