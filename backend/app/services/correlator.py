import re
from collections import defaultdict
from typing import List, Dict
from ..services.detector import detect
from ..services.log_analyzer import analyze_log
from ..services.risk_engine import calculate_score, classify_level

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_EMAIL_RE = re.compile(r"\b[\w\.\+\-]+@[\w\-]+\.[\w\.\-]{2,}\b")
_FAILED_RE = re.compile(
    r"(?i)(?:failed\s+login|login\s+fail|auth.*fail|invalid\s+(?:password|credentials)|401|403)"
)


def correlate_logs(log_contents: List[str]) -> Dict:
    """
    Cross-log anomaly detection:
    - Shared IPs across multiple logs
    - Shared emails/credentials across logs
    - Coordinated brute-force (failed logins on same IP across logs)
    - Aggregate risk aggregation
    """
    per_log = []
    ip_to_logs: Dict[str, set] = defaultdict(set)
    email_to_logs: Dict[str, set] = defaultdict(set)
    ip_fail_to_logs: Dict[str, set] = defaultdict(set)
    all_findings = []

    for idx, content in enumerate(log_contents):
        result = analyze_log(content)
        findings = result["findings"]
        score = calculate_score(findings)
        level = classify_level(score)

        all_findings.extend(findings)

        # Collect IPs and emails for cross-log correlation
        ips_in_log = set(_IP_RE.findall(content))
        emails_in_log = set(e.lower() for e in _EMAIL_RE.findall(content))

        for ip in ips_in_log:
            ip_to_logs[ip].add(idx)

        for email in emails_in_log:
            email_to_logs[email].add(idx)

        # Track IPs involved in failed logins
        for line in content.splitlines():
            if _FAILED_RE.search(line):
                for ip in _IP_RE.findall(line):
                    ip_fail_to_logs[ip].add(idx)

        per_log.append({
            "log_index": idx + 1,
            "risk_score": score,
            "risk_level": level,
            "findings_count": len(findings),
            "stats": result.get("stats", {}),
        })

    # Build correlations
    correlations = []

    # Shared IPs
    for ip, log_set in ip_to_logs.items():
        if len(log_set) > 1:
            logs = sorted(log_set)
            correlations.append({
                "type": "shared_ip",
                "severity": "high",
                "value": ip,
                "log_indices": [i + 1 for i in logs],
                "description": (
                    f"IP {ip} appears across {len(logs)} log files — "
                    f"possible coordinated scanning or lateral movement."
                ),
            })

    # Shared emails
    for email, log_set in email_to_logs.items():
        if len(log_set) > 1:
            logs = sorted(log_set)
            correlations.append({
                "type": "shared_email",
                "severity": "medium",
                "value": email,
                "log_indices": [i + 1 for i in logs],
                "description": (
                    f"Account {email} active in {len(logs)} log files — "
                    f"track this identity across all systems."
                ),
            })

    # Coordinated brute-force
    for ip, log_set in ip_fail_to_logs.items():
        if len(log_set) > 1:
            logs = sorted(log_set)
            correlations.append({
                "type": "coordinated_brute_force",
                "severity": "critical",
                "value": ip,
                "log_indices": [i + 1 for i in logs],
                "description": (
                    f"IP {ip} triggered authentication failures in {len(logs)} separate log files — "
                    f"high confidence coordinated brute-force attack. Block immediately."
                ),
            })

    # Sort by severity
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    correlations.sort(key=lambda c: _sev_order.get(c["severity"], 9))

    aggregate_score = calculate_score(all_findings)
    aggregate_level = classify_level(aggregate_score)

    return {
        "log_count": len(log_contents),
        "per_log": per_log,
        "correlations": correlations,
        "aggregate_risk_score": aggregate_score,
        "aggregate_risk_level": aggregate_level,
        "total_findings": len(all_findings),
    }
