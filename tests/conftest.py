"""
Tests run against a separate Postgres database (alertiq_test) so they never touch real alerts.
Create it once:  docker exec alertiq-postgres psql -U alertiq -c "CREATE DATABASE alertiq_test"
"""
import os

# Must be set before backend.config is imported (env vars win over .env)
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://alertiq:alertiq123@localhost:5432/alertiq_test"
)
os.environ["AI_PROVIDER"] = "rules"          # deterministic, free, no network
os.environ["INGEST_API_KEY"] = "test-ingest-key"
os.environ["ALLOW_REGISTRATION"] = "false"
os.environ["SLACK_WEBHOOK_URL"] = ""

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import enricher


@pytest.fixture(scope="module")
def client(monkeypatch_module):
    # No real ip-api.com calls: every public IP looks like a hosting provider abroad
    monkeypatch_module.setattr(
        enricher, "_geo_lookup",
        lambda ip: {"country": "Testland", "org": "TestHost", "is_proxy": False, "is_hosting": True},
    )
    with TestClient(app) as c:   # runs lifespan: creates tables
        with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
            conn.execute("TRUNCATE alerts, users")
        yield c


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def db():
    return psycopg.connect(os.environ["DATABASE_URL"])
