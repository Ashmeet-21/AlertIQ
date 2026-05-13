from datetime import datetime, timedelta, timezone
from psycopg import Connection

THROTTLE_WINDOW_SECONDS = 60
THROTTLE_MAX_COUNT = 10


def is_throttled(conn: Connection, source_ip: str) -> bool:
    if not source_ip:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=THROTTLE_WINDOW_SECONDS)
    row = conn.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE normalized_payload->>'source.ip' = %s
          AND created_at >= %s
        """,
        (source_ip, cutoff),
    ).fetchone()
    return int(row[0]) >= THROTTLE_MAX_COUNT
