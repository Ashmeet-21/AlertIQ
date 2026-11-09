"""
Deterministic triage used when no AI backend is available (free, offline).
Same output shape as the AI engine, so scoring, the dashboard and Slack work unchanged.
"""

# event types that are usually attacks when they show up at all
HIGH_RISK_TYPES = {
    "malware_detected", "ransomware", "privilege_escalation", "data_exfiltration",
    "c2_beacon", "command_and_control", "lateral_movement", "credential_dumping",
}
AUTH_FAILURE_TYPES = {"login_failure", "auth_failure", "failed_login", "brute_force", "password_spray"}


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def rules_triage(alert: dict) -> dict:
    event_type = str(alert.get("event.type", "")).lower()
    count = _to_int(alert.get("event.count"))
    external = alert.get("enrichment.source_ip.is_internal") is False
    proxy = bool(alert.get("enrichment.source_ip.is_proxy"))
    hosting = bool(alert.get("enrichment.source_ip.is_hosting"))
    critical_asset = str(alert.get("enrichment.asset.criticality", "")).lower() in ("critical", "high")

    reasons = []
    risk = 0
    if event_type in HIGH_RISK_TYPES:
        risk += 3; reasons.append(f"'{event_type}' is a high-risk event type")
    if event_type in AUTH_FAILURE_TYPES and count >= 10:
        risk += 2; reasons.append(f"{count} failed attempts suggests brute force")
    elif event_type in AUTH_FAILURE_TYPES and count >= 5:
        risk += 1; reasons.append(f"{count} failed attempts")
    if external:
        risk += 1; reasons.append("source IP is external")
    if proxy or hosting:
        risk += 1; reasons.append("source IP is a proxy/VPN or hosting provider")
    if critical_asset:
        risk += 1; reasons.append("target is a critical/high-value asset")

    if risk >= 4:
        verdict, severity, confidence = "true_positive", "HIGH", 0.8
        action = "Block the source IP, review the affected account/asset, and open an incident."
    elif risk >= 2:
        verdict, severity, confidence = "needs_review", "MEDIUM", 0.6
        action = "Review recent activity for this source IP and user before deciding."
    elif risk == 0 and event_type in AUTH_FAILURE_TYPES:
        verdict, severity, confidence = "false_positive", "LOW", 0.6
        action = "Likely a user mistyping a password from an internal host. No action needed."
    else:
        verdict, severity, confidence = "needs_review", "LOW", 0.5
        action = "Low-signal event. Spot-check if it repeats."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity,
        "summary": f"{event_type or 'event'} from {alert.get('source.ip', 'unknown source')}"
                   + (f" ({count} attempts)" if count else "") + ".",
        "recommended_action": action,
        "reasoning": "Rule-based triage (no AI backend): " + ("; ".join(reasons) if reasons else "no risk signals found") + ".",
    }
