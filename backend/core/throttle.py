from psycopg import Connection

THROTTLE_WINDOW_SECONDS = 60
THROTTLE_MAX_COUNT = 10


def is_throttled(conn: Connection, source_ip: str) -> bool:
    if not source_ip:
        return False
    # Same reason as deduplicator: let Postgres compute the window
    row = conn.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE normalized_payload->>'source.ip' = %s
          AND created_at >= NOW() - make_interval(secs => %s)
        """,
        (source_ip, THROTTLE_WINDOW_SECONDS),
    ).fetchone()
    return int(row[0]) >= THROTTLE_MAX_COUNT
