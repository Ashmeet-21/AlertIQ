"""Pure-logic tests: no database, no network."""
from backend.core.claude_engine import _validate, _extract_json
from backend.core.normalizer import extract_severity
from backend.core.prefilter import apply_prefilter
from backend.core.rules_triage import rules_triage
from backend.core.scorer import score_alert
from backend.core.scrubber import scrub
from backend.core.enricher import get_asset_info


def test_scrub_reaches_nested_lists():
    # PII hidden inside a list must not reach the DB or the AI prompt
    out = scrub({"recipients": ["ceo@corp.com", {"note": "pwd=hunter2"}], "attempts": 3})
    assert out["recipients"][0] == "[REDACTED-EMAIL]"
    assert "hunter2" not in str(out)
    assert out["attempts"] == 3   # numbers untouched


def test_bad_attempt_count_does_not_crash_ingest():
    # A log source sending "attempts": "many" used to raise ValueError -> HTTP 500
    assert extract_severity({"attempts": "many"}) == "LOW"
    assert extract_severity({"severity": "x" * 50}) == "X" * 20   # fits VARCHAR(20)


def test_prefilter_order_suppress_then_escalate():
    assert apply_prefilter({"event.type": "heartbeat", "event.severity": "CRITICAL"}).action == "suppress"
    assert apply_prefilter({"event.type": "login_failure", "event.count": 50}).action == "escalate"
    assert apply_prefilter({"event.type": "login_failure", "event.count": 3}).action == "triage"


def test_false_positive_lands_lower_than_true_positive():
    enriched = {"enrichment.asset.criticality": "critical", "enrichment.source_ip.is_internal": False}
    tp, _ = score_alert({"verdict": "true_positive", "severity": "HIGH", "confidence": 0.9}, enriched)
    fp, fp_queue = score_alert({"verdict": "false_positive", "severity": "HIGH", "confidence": 0.9}, enriched)
    assert tp > fp
    assert fp_queue in ("P3", "P4")


def test_ai_outage_does_not_bury_alerts():
    # Fallback verdict has confidence 0: the alert must stay visible for a human, not drop to P4
    from backend.core.claude_engine import FALLBACK
    _, queue = score_alert(dict(FALLBACK), {"enrichment.source_ip.is_internal": False})
    assert queue in ("P2", "P3")


def test_scorer_survives_missing_or_garbage_fields():
    # The AI fallback has severity UNKNOWN; a null severity or text confidence must not crash scoring
    score, queue = score_alert({"severity": None, "confidence": "high"}, {"enrichment.asset.criticality": None})
    assert 0 <= score <= 100 and queue in ("P1", "P2", "P3", "P4")


def test_rules_triage_flags_external_brute_force_on_critical_asset():
    v = rules_triage({
        "event.type": "login_failure", "event.count": 30, "source.ip": "45.33.32.156",
        "enrichment.source_ip.is_internal": False, "enrichment.source_ip.is_hosting": True,
        "enrichment.asset.criticality": "critical",
    })
    assert v["verdict"] == "true_positive" and v["severity"] == "HIGH"


def test_rules_triage_calls_internal_typo_benign():
    v = rules_triage({"event.type": "login_failure", "event.count": 2, "source.ip": "10.1.2.3",
                      "enrichment.source_ip.is_internal": True})
    assert v["verdict"] == "false_positive"


def test_model_output_is_validated():
    # A prompt-injected or sloppy model reply can't push invalid values into scoring/DB
    v = _validate(_extract_json('Sure! {"verdict": "IGNORE_ALL", "confidence": 7, "severity": "apocalyptic", "summary": "x"}'))
    assert v["verdict"] == "needs_review"
    assert v["confidence"] == 1.0
    assert v["severity"] == "UNKNOWN"


def test_asset_lookup_uses_target_not_attacker():
    # Attack from an unknown IP against the core router: the router's criticality should count
    assert get_asset_info("", "10.0.0.1", "203.0.113.9")["criticality"] == "critical"
