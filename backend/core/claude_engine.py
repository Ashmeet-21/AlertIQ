import subprocess
import json
import re
import logging

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert security analyst AI embedded in a SIEM triage pipeline.

Your job: analyze a security alert and determine if it is a real threat.

Rules:
- Respond with a JSON object only — no markdown, no explanation, no wrapping text.
- Base your verdict on the alert data provided: event type, source IP enrichment, asset criticality, user activity, and attempt counts.
- Be specific in your recommended action.

Response format:
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": <float 0.0-1.0>,
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "summary": "<1-2 sentence plain-English summary of what happened>",
  "recommended_action": "<specific action for the analyst>",
  "reasoning": "<brief explanation of your verdict>"
}"""

FALLBACK = {
    "verdict": "needs_review",
    "confidence": 0.0,
    "severity": "UNKNOWN",
    "summary": "AI triage unavailable — manual review required.",
    "recommended_action": "Review alert manually.",
    "reasoning": "Claude CLI unavailable or returned an error.",
}


def _extract_json(text: str) -> dict:
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise json.JSONDecodeError("no JSON object found", text, 0)


def _build_prompt(alert_data: dict, few_shots: list[dict]) -> str:
    """
    Build the full prompt for Claude.
    If few_shots are available, include them so Claude learns from
    past analyst corrections (feedback loop).
    """
    parts = [SYSTEM_PROMPT]

    if few_shots:
        parts.append("\n\nPast analyst-verified examples (use these to calibrate your verdict):\n")
        for i, ex in enumerate(few_shots, 1):
            parts.append(
                f"EXAMPLE {i}:\n"
                f"Alert: {json.dumps(ex['alert'], indent=2)}\n"
                f"AI initial verdict: {ex['ai_verdict']}\n"
                f"Analyst confirmed: {ex['analyst_verdict']}\n"
                f"Analyst notes: {ex['analyst_notes'] or 'none'}\n"
            )

    parts.append(
        f"\n\nNow triage this new security alert:\n\n"
        f"{json.dumps(alert_data, indent=2)}"
    )
    return "\n".join(parts)


def triage_alert(normalized: dict, source_type: str = "", few_shots: list[dict] | None = None) -> dict:
    alert_data = {"source_type": source_type, "alert": normalized}
    prompt = _build_prompt(alert_data, few_shots or [])

    try:
        result = subprocess.run(
            ["claude", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise RuntimeError(f"claude CLI exited {result.returncode}: {result.stderr.strip()}")
        verdict = _extract_json(result.stdout.strip())
        logger.info(
            f"[claude_engine] verdict={verdict.get('verdict')} "
            f"confidence={verdict.get('confidence')} "
            f"few_shots_used={len(few_shots or [])}"
        )
        return verdict
    except json.JSONDecodeError as exc:
        logger.error(f"[claude_engine] response was not valid JSON: {exc}")
        return dict(FALLBACK)
    except Exception as exc:
        logger.error(f"[claude_engine] triage failed: {exc}")
        return dict(FALLBACK)
