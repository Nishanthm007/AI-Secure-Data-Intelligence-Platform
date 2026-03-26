from typing import List, Tuple
from ..models.schemas import Finding, RiskLevel

# Weight per severity
_WEIGHTS = {
    RiskLevel.critical: 5,
    RiskLevel.high: 3,
    RiskLevel.medium: 2,
    RiskLevel.low: 1,
}


def calculate_score(findings: List[Finding]) -> int:
    return sum(_WEIGHTS.get(f.risk, 0) for f in findings)


def classify_level(score: int) -> RiskLevel:
    if score >= 10:
        return RiskLevel.critical
    if score >= 7:
        return RiskLevel.high
    if score >= 4:
        return RiskLevel.medium
    return RiskLevel.low


def build_summary(findings: List[Finding], content_type: str, stats: dict = None) -> str:
    if not findings:
        return f"No sensitive data or security issues detected in {content_type} input."

    type_counts: dict = {}
    for f in findings:
        type_counts[f.type] = type_counts.get(f.type, 0) + 1

    parts = [f"{count} {ftype.replace('_', ' ')}(s)" for ftype, count in type_counts.items()]
    summary = f"{content_type.capitalize()} input contains: {', '.join(parts)}."

    if stats:
        if stats.get("failed_logins", 0) >= 5:
            summary += f" {stats['failed_logins']} failed login events detected."
        if stats.get("error_count", 0) >= 5:
            summary += f" High error rate ({stats['error_count']} errors)."

    return summary
