"""End-to-end flow against a real Postgres: auth -> ingest -> pipeline -> dashboard APIs -> feedback."""
import pytest
from tests.conftest import db

KEY = {"X-API-Key": "test-ingest-key"}


def _login(client, email, password):
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def users(client):
    r = client.post("/auth/register", json={"email": "admin@test.local", "password": "admin-pass-1"})
    assert r.status_code == 201 and r.json()["role"] == "admin"
    admin = _login(client, "admin@test.local", "admin-pass-1")
    for email, role in (("analyst@test.local", "analyst"), ("viewer@test.local", "read_only")):
        r = client.post("/auth/users", json={"email": email, "password": "user-pass-1", "role": role}, headers=admin)
        assert r.status_code == 201, r.text
    return {
        "admin": admin,
        "analyst": _login(client, "analyst@test.local", "user-pass-1"),
        "viewer": _login(client, "viewer@test.local", "user-pass-1"),
    }


def _ingest(client, event_type, **payload):
    r = client.post("/alerts/ingest", json={"event_type": event_type, "source_type": "test", "payload": payload}, headers=KEY)
    assert r.status_code == 202, r.text
    return r.json()


def _get(client, users, alert_id):
    r = client.get(f"/alerts/{alert_id}", headers=users["viewer"])
    assert r.status_code == 200
    return r.json()


# ── auth & access control ──────────────────────────────────────────────────────

def test_strangers_cannot_self_register_after_admin(client, users):
    # Open sign-up would give anyone an analyst account that can read every alert
    r = client.post("/auth/register", json={"email": "stranger@x.com", "password": "whatever-123"})
    assert r.status_code == 403


def test_admin_cannot_create_unknown_role(client, users):
    r = client.post("/auth/users", json={"email": "x@test.local", "password": "user-pass-1", "role": "superuser"}, headers=users["admin"])
    assert r.status_code == 422


def test_wrong_password_is_401(client, users):
    assert client.post("/auth/login", json={"email": "admin@test.local", "password": "nope-nope"}).status_code == 401


def test_ingest_requires_api_key(client):
    r = client.post("/alerts/ingest", json={"event_type": "x", "source_type": "y", "payload": {}})
    assert r.status_code == 401


def test_alerts_require_login(client):
    assert client.get("/alerts").status_code == 401


# ── pipeline ───────────────────────────────────────────────────────────────────

def test_brute_force_runs_full_pipeline_and_raw_pii_is_scrubbed(client, users):
    res = _ingest(client, "login_failure", src_ip="45.33.32.156", dest_ip="10.0.0.1", user="bob",
                  attempts=30, message="failed for bob@corp.com password=hunter2")
    a = _get(client, users, res["alert_id"])
    assert a["status"] == "triage"
    assert a["triage_result"]["verdict"] == "true_positive"
    assert a["triage_result"]["provider"] == "rules"
    assert a["normalized_payload"]["enrichment.asset.name"] == "core-router-01"
    assert a["priority_queue"] in ("P1", "P2")
    # The raw payload in the DB must not keep the email or password either
    with db() as conn:
        raw = conn.execute("SELECT raw_payload::text FROM alerts WHERE id = %s", (res["alert_id"],)).fetchone()[0]
    assert "bob@corp.com" not in raw and "hunter2" not in raw


def test_same_event_twice_is_deduplicated(client):
    first = _ingest(client, "port_scan", src_ip="198.51.100.7", dest_ip="10.0.0.2")
    second = _ingest(client, "port_scan", src_ip="198.51.100.7", dest_ip="10.0.0.2")
    assert second["status"] == "duplicate" and second["alert_id"] == first["alert_id"]


def test_noise_is_suppressed_and_critical_is_escalated(client, users):
    noise = _get(client, users, _ingest(client, "heartbeat", src_ip="10.9.9.9")["alert_id"])
    assert noise["status"] == "suppressed" and noise["priority_queue"] == "P4"
    crit = _get(client, users, _ingest(client, "malware_detected", src_ip="10.9.9.8", severity="CRITICAL")["alert_id"])
    assert crit["status"] == "escalated" and crit["priority_queue"] == "P1"


def test_garbage_attempt_count_is_accepted(client):
    assert _ingest(client, "login_failure", src_ip="10.7.7.7", attempts="many")["status"] == "queued"


# ── dashboard APIs, roles, feedback loop ───────────────────────────────────────

def test_read_only_can_view_but_not_change(client, users):
    alert_id = client.get("/alerts", headers=users["viewer"]).json()[0]["id"]
    assert client.get("/alerts/stats", headers=users["viewer"]).status_code == 200
    r = client.patch(f"/alerts/{alert_id}/verdict", json={"analyst_verdict": "false_positive"}, headers=users["viewer"])
    assert r.status_code == 403


def test_analyst_verdict_feeds_the_next_triage(client, users):
    from backend.database import get_feedback_examples
    alert_id = client.get("/alerts", params={"status": "triage"}, headers=users["analyst"]).json()[0]["id"]
    r = client.patch(f"/alerts/{alert_id}/verdict",
                     json={"analyst_verdict": "true_positive", "analyst_notes": "known scanner"}, headers=users["analyst"])
    assert r.status_code == 200 and r.json()["analyst_verdict"] == "true_positive"
    with db() as conn:
        examples = get_feedback_examples(conn)
    assert any(e["analyst_notes"] == "known scanner" for e in examples)


def test_stats_match_the_alerts(client, users):
    s = client.get("/alerts/stats", headers=users["viewer"]).json()
    assert s["total"] == s["queued"] + s["triage"] + s["escalated"] + s["suppressed"] + s["error"]
    assert s["queued"] == 0   # every alert made it through the pipeline


# ── live updates ───────────────────────────────────────────────────────────────

def test_websocket_rejects_missing_token(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/alerts") as ws:
            ws.receive_text()


def test_websocket_pushes_pipeline_updates(client, users):
    token = users["viewer"]["Authorization"].split()[1]
    with client.websocket_connect(f"/ws/alerts?token={token}") as ws:
        res = _ingest(client, "login_failure", src_ip="203.0.113.50", attempts=12)
        msg = ws.receive_json()
    assert msg["type"] == "alert_updated" and msg["alert_id"] == res["alert_id"]
