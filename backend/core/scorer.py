SEVERITY_BASE = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "UNKNOWN": 40}
VERDICT_MOD   = {"true_positive": 20, "needs_review": 0, "false_positive": -40}
ASSET_MOD     = {"critical": 15, "high": 10, "medium": 5, "low": 0, "unknown": 0}


def compute_score(triage_result: dict, enriched: dict) -> int:
    severity   = triage_result.get("severity", "UNKNOWN").upper()
    verdict    = triage_result.get("verdict", "needs_review")
    confidence = float(triage_result.get("confidence", 0.5))

    base  = SEVERITY_BASE.get(severity, 40)
    v_mod = VERDICT_MOD.get(verdict, 0)

    asset_crit = enriched.get("enrichment.asset.criticality", "unknown").lower()
    a_mod = ASSET_MOD.get(asset_crit, 0)

    ip_mod = 0
    if enriched.get("enrichment.source_ip.is_proxy"):                      ip_mod += 10
    if enriched.get("enrichment.source_ip.is_hosting"):                    ip_mod += 5
    if not enriched.get("enrichment.source_ip.is_internal", True):        ip_mod += 5

    raw = (base + v_mod + a_mod + ip_mod) * confidence
    return max(0, min(100, round(raw)))


def assign_queue(score: int) -> str:
    if score >= 80: return "P1"
    if score >= 60: return "P2"
    if score >= 40: return "P3"
    return "P4"


def score_alert(triage_result: dict, enriched: dict) -> tuple[int, str]:
    score = compute_score(triage_result, enriched)
    return score, assign_queue(score)
