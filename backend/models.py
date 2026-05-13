CREATE_ALERTS_TABLE = """
    CREATE TABLE IF NOT EXISTS alerts (
        id                 VARCHAR(36) PRIMARY KEY,
        event_type         VARCHAR(100) NOT NULL,
        source_type        VARCHAR(100) NOT NULL,
        raw_payload        JSONB NOT NULL,
        normalized_payload JSONB NOT NULL,
        event_hash         VARCHAR(64) NOT NULL,
        severity           VARCHAR(20),
        status             VARCHAR(20) DEFAULT 'queued',
        filter_reason      VARCHAR(255),
        created_at         TIMESTAMP DEFAULT NOW()
    )
"""

CREATE_HASH_INDEX = """
    CREATE INDEX IF NOT EXISTS idx_alerts_event_hash ON alerts(event_hash)
"""

# Migration for existing tables created before Step 2
ADD_FILTER_REASON_COLUMN = """
    ALTER TABLE alerts ADD COLUMN IF NOT EXISTS filter_reason VARCHAR(255)
"""

# Migration for existing tables created before Step 5
ADD_TRIAGE_RESULT_COLUMN = """
    ALTER TABLE alerts ADD COLUMN IF NOT EXISTS triage_result JSONB
"""

# Migration for existing tables created before Step 6
ADD_PRIORITY_COLUMNS = """
    ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS priority_score INTEGER,
        ADD COLUMN IF NOT EXISTS priority_queue VARCHAR(10)
"""

CREATE_USERS_TABLE = """
    CREATE TABLE IF NOT EXISTS users (
        id              VARCHAR(36) PRIMARY KEY,
        email           VARCHAR(255) UNIQUE NOT NULL,
        hashed_password VARCHAR(255) NOT NULL,
        role            VARCHAR(20) NOT NULL DEFAULT 'analyst',
        created_at      TIMESTAMP DEFAULT NOW()
    )
"""

# Step 8 (Feedback Loop) — analyst verdict stored directly on the alert row
ADD_ANALYST_VERDICT_COLUMNS = """
    ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS analyst_verdict VARCHAR(50),
        ADD COLUMN IF NOT EXISTS analyst_notes   TEXT,
        ADD COLUMN IF NOT EXISTS analyst_id      VARCHAR(36)
"""

DDL_STATEMENTS = [
    CREATE_ALERTS_TABLE,
    CREATE_HASH_INDEX,
    ADD_FILTER_REASON_COLUMN,
    ADD_TRIAGE_RESULT_COLUMN,
    ADD_PRIORITY_COLUMNS,
    CREATE_USERS_TABLE,
    ADD_ANALYST_VERDICT_COLUMNS,
]
