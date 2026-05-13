import re
from copy import deepcopy

# Order matters: more specific patterns first to avoid partial matches
PATTERNS = [
    # SSN before phone — SSN is \d{3}-\d{2}-\d{4}, phone is \d{3}-\d{3}-\d{4}
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "[REDACTED-SSN]"),
    (re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.\-]+'), "[REDACTED-EMAIL]"),
    (re.compile(r'\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b'), "[REDACTED-PHONE]"),
    (re.compile(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'), "[REDACTED-CC]"),
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+\/]+=*'), "bearer [REDACTED-TOKEN]"),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+'), r"\1=[REDACTED-CREDENTIAL]"),
    (re.compile(r'(?i)(token|secret|api[_\-]?key)\s*[:=]\s*\S+'), r"\1=[REDACTED-CREDENTIAL]"),
]


def _scrub_string(value: str) -> str:
    for pattern, replacement in PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def scrub(payload: dict) -> dict:
    result = deepcopy(payload)
    for key, value in result.items():
        if isinstance(value, str):
            result[key] = _scrub_string(value)
        elif isinstance(value, dict):
            result[key] = scrub(value)
    return result
