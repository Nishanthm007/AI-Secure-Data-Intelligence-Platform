import re
from typing import List, Tuple, Optional
from ..models.schemas import Finding, RiskLevel


# ── Pattern definitions ────────────────────────────────────────────────────────
# Each entry: name, compiled regex, risk level, capture group index (1-based or 0 for full match)
_PATTERNS: List[Tuple] = [
    (
        "password",
        re.compile(
            r"(?i)(?:password|passwd|pwd|pass)\s*[=:\"'\s]+\s*(\S{3,})",
            re.IGNORECASE,
        ),
        RiskLevel.critical,
        1,
    ),
    (
        "api_key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey|api[_\-]?token)\s*[=:\"'\s]+\s*([\w\-\.]{8,})",
            re.IGNORECASE,
        ),
        RiskLevel.high,
        1,
    ),
    (
        "secret",
        re.compile(
            r"(?i)(?:secret|client[_\-]?secret|app[_\-]?secret)\s*[=:\"'\s]+\s*([\w\-\.]{8,})",
            re.IGNORECASE,
        ),
        RiskLevel.critical,
        1,
    ),
    (
        "token",
        re.compile(
            r"(?i)(?:(?:auth|access|refresh|bearer)[_\-]?token|token)\s*[=:\"'\s]+\s*([\w\-\.]{8,})",
            re.IGNORECASE,
        ),
        RiskLevel.high,
        1,
    ),
    (
        "aws_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        RiskLevel.critical,
        0,
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\b"),
        RiskLevel.high,
        0,
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        RiskLevel.critical,
        0,
    ),
    (
        "connection_string",
        re.compile(
            r"(?:mongodb(?:\+srv)?|postgresql|mysql|redis|amqp|jdbc:[^:]+)://[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        RiskLevel.critical,
        0,
    ),
    (
        "url_with_credentials",
        re.compile(r"https?://[\w\-\.%]+:[\w\-\.%@!#$&*]+@[\w\-\.]+", re.IGNORECASE),
        RiskLevel.critical,
        0,
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),
        RiskLevel.critical,
        0,
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        RiskLevel.critical,
        0,
    ),
    (
        "email",
        re.compile(r"\b[\w\.\+\-]+@[\w\-]+\.[\w\.\-]{2,}\b"),
        RiskLevel.low,
        0,
    ),
    (
        "phone",
        re.compile(
            r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s])?\d{3}[-.\s]\d{4}(?!\d)"
        ),
        RiskLevel.low,
        0,
    ),
    (
        "ip_address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        RiskLevel.low,
        0,
    ),
    (
        "stack_trace",
        re.compile(
            r"(?:Traceback \(most recent call last\)|"
            r"at\s+[\w\.\$<>]+\([\w\.]+:\d+\)|"
            r"NullPointerException|"
            r"java\.[\w\.]+Exception|"
            r"Exception in thread|"
            r"\w+Error:\s+.+)",
            re.IGNORECASE,
        ),
        RiskLevel.medium,
        0,
    ),
    (
        "debug_leak",
        re.compile(
            r"(?i)(?:DEBUG|VERBOSE)\s*[:\|]\s*.{10,}(?:key|token|pass|secret|auth)",
            re.IGNORECASE,
        ),
        RiskLevel.medium,
        0,
    ),
]

# Mask functions per finding type
_MASK_RULES = {
    "password": lambda v: "***REDACTED***",
    "secret": lambda v: "***REDACTED***",
    "api_key": lambda v: v[:4] + "***REDACTED***" if len(v) > 4 else "***REDACTED***",
    "token": lambda v: v[:4] + "***REDACTED***" if len(v) > 4 else "***REDACTED***",
    "aws_key": lambda v: "AKIA***REDACTED***",
    "jwt": lambda v: "eyJ***REDACTED***",
    "private_key": lambda v: "-----BEGIN PRIVATE KEY [REDACTED]-----",
    "connection_string": lambda v: re.sub(r"(://)[^@\s]+@", r"\1***:***@", v),
    "url_with_credentials": lambda v: re.sub(r"(://)[^:@\s]+:[^@\s]+@", r"\1***:***@", v),
    "credit_card": lambda v: "****-****-****-" + v.replace("-", "").replace(" ", "")[-4:],
    "ssn": lambda v: "***-**-****",
    "email": lambda v: v[0] + "***@***." + v.split(".")[-1] if "@" in v else "***",
    "phone": lambda v: "***-***-" + v.replace("-", "").replace(" ", "").replace(".", "")[-4:],
    "ip_address": lambda v: "X.X.X.X",
    "stack_trace": lambda v: "[STACK TRACE REDACTED]",
    "debug_leak": lambda v: "[DEBUG INFO REDACTED]",
}


def detect(text: str, line_offset: int = 0) -> List[Finding]:
    """Run all detection patterns against the given text. line_offset shifts line numbers."""
    findings: List[Finding] = []
    seen: set = set()  # deduplicate (type, value) pairs

    lines = text.splitlines()

    for pattern_name, regex, risk, group in _PATTERNS:
        for match in regex.finditer(text):
            raw_value = match.group(group) if group else match.group(0)
            dedup_key = (pattern_name, raw_value)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Calculate line number
            line_num = text[: match.start()].count("\n") + 1 + line_offset

            # Get surrounding context (truncated for safety)
            line_text = lines[line_num - 1 - line_offset] if (line_num - 1 - line_offset) < len(lines) else ""
            context = (line_text[:120] + "...") if len(line_text) > 120 else line_text

            # Mask value for display
            mask_fn = _MASK_RULES.get(pattern_name, lambda v: v[:4] + "***" if len(v) > 4 else "***")
            masked_value = mask_fn(raw_value)

            findings.append(
                Finding(
                    type=pattern_name,
                    risk=risk,
                    value=masked_value,
                    line=line_num,
                    context=context,
                )
            )

    return findings


def mask_content(text: str) -> str:
    """Return a copy of text with all sensitive values masked."""
    masked = text
    for pattern_name, regex, risk, group in _PATTERNS:
        mask_fn = _MASK_RULES.get(pattern_name, lambda v: "***REDACTED***")

        def _replace(m, _name=pattern_name, _group=group, _fn=mask_fn):
            full = m.group(0)
            val = m.group(_group) if _group and _group <= len(m.groups()) else full
            replacement = _fn(val)
            if _group and _group <= len(m.groups()):
                return full.replace(val, replacement, 1)
            return replacement

        masked = regex.sub(_replace, masked)
    return masked
