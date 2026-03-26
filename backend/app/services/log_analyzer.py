import re
from collections import Counter
from typing import List, Dict, Tuple, Optional
from ..models.schemas import Finding, RiskLevel
from .detector import detect, mask_content


# ── Brute-force / anomaly patterns ────────────────────────────────────────────
_FAILED_LOGIN_RE = re.compile(
    r"(?i)(?:failed\s+login|login\s+fail(?:ed|ure)|authentication\s+fail(?:ed|ure)|"
    r"invalid\s+(?:password|credentials)|unauthorized|403|401)",
)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DEBUG_MODE_RE = re.compile(r"(?i)\bDEBUG\b")
_ERROR_RE = re.compile(r"(?i)\b(?:ERROR|FATAL|CRITICAL|EXCEPTION|TRACEBACK)\b")
_STACK_TRACE_RE = re.compile(
    r"(?:Traceback \(most recent call last\)|"
    r"at\s+[\w\.\$<>]+\([\w\.]+:\d+\)|"
    r"NullPointerException|java\.[\w\.]+Exception)"
)

# Risk level for anomaly findings
_ANOMALY_RISK = {
    "brute_force_attempt": RiskLevel.high,
    "suspicious_ip_activity": RiskLevel.medium,
    "debug_mode_leak": RiskLevel.medium,
    "repeated_errors": RiskLevel.medium,
    "stack_trace_leak": RiskLevel.medium,
}


def analyze_log(content: str, max_lines: int = 10000) -> Dict:
    """
    Perform full log analysis:
      - Line-by-line sensitive data detection
      - Anomaly detection (brute-force, suspicious IPs, debug leaks)
      - Per-line risk map for frontend highlighting
    Returns dict with findings, anomalies, line_risks, and masked_content.
    """
    lines = content.splitlines()[:max_lines]

    all_findings: List[Finding] = []
    line_risks: Dict[str, str] = {}  # "line_number" -> highest risk on that line
    failed_login_lines: List[int] = []
    ip_counter: Counter = Counter()
    debug_line_count = 0
    error_count = 0

    for idx, line in enumerate(lines, start=1):
        line_findings = detect(line, line_offset=idx - 1)

        if line_findings:
            # Determine highest risk for this line
            severity_order = ["critical", "high", "medium", "low"]
            highest = min(
                line_findings, key=lambda f: severity_order.index(f.risk)
            )
            line_risks[str(idx)] = highest.risk
            all_findings.extend(line_findings)

        # Anomaly tracking
        if _FAILED_LOGIN_RE.search(line):
            failed_login_lines.append(idx)

        for ip in _IP_RE.findall(line):
            if not ip.startswith(("10.", "172.", "192.168.", "127.")):
                ip_counter[ip] += 1

        if _DEBUG_MODE_RE.search(line):
            debug_line_count += 1

        if _ERROR_RE.search(line):
            error_count += 1

    # ── Anomaly findings ──────────────────────────────────────────────────────
    anomaly_findings: List[Finding] = []

    # Brute-force: ≥5 failed logins
    if len(failed_login_lines) >= 5:
        anomaly_findings.append(
            Finding(
                type="brute_force_attempt",
                risk=RiskLevel.high,
                value=f"{len(failed_login_lines)} failed login attempts detected",
                line=failed_login_lines[0],
                context=f"Failed login events on lines: {failed_login_lines[:10]}",
            )
        )
        for ln in failed_login_lines:
            existing = line_risks.get(str(ln))
            if existing not in ("critical", "high"):
                line_risks[str(ln)] = "high"

    # Suspicious IPs: single IP appearing ≥10 times
    for ip, count in ip_counter.most_common(5):
        if count >= 10:
            anomaly_findings.append(
                Finding(
                    type="suspicious_ip_activity",
                    risk=RiskLevel.medium,
                    value=f"{ip} appeared {count} times",
                    context=f"External IP {ip} made {count} requests — possible scanning/attack",
                )
            )

    # Debug mode leaks
    if debug_line_count >= 3:
        anomaly_findings.append(
            Finding(
                type="debug_mode_leak",
                risk=RiskLevel.medium,
                value=f"Debug mode active ({debug_line_count} DEBUG lines)",
                context="Application running in DEBUG mode — may expose sensitive internals",
            )
        )

    # High error rate
    if error_count >= 10:
        anomaly_findings.append(
            Finding(
                type="repeated_errors",
                risk=RiskLevel.medium,
                value=f"{error_count} error events detected",
                context="High error rate may indicate application instability or attack",
            )
        )

    masked = mask_content("\n".join(lines))

    return {
        "findings": all_findings + anomaly_findings,
        "line_risks": line_risks,
        "masked_content": masked,
        "stats": {
            "total_lines": len(lines),
            "failed_logins": len(failed_login_lines),
            "error_count": error_count,
            "debug_lines": debug_line_count,
        },
    }
