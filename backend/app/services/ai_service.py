from typing import List, Optional
from ..models.schemas import Finding, RiskLevel


# ── Rule-based insight templates ──────────────────────────────────────────────
_INSIGHT_RULES = [
    ("password", RiskLevel.critical, "Plaintext password(s) found — never log credentials; use hashed storage and audit log pipelines immediately."),
    ("secret", RiskLevel.critical, "Hardcoded secret detected — rotate this secret immediately and remove it from logs/source code."),
    ("api_key", RiskLevel.high, "API key exposed in logs — rotate the key immediately and restrict API key permissions."),
    ("aws_key", RiskLevel.critical, "AWS access key exposed — revoke via IAM console immediately; check CloudTrail for unauthorized usage."),
    ("jwt", RiskLevel.high, "JWT token found in plaintext — tokens grant authenticated access; rotate and invalidate affected sessions."),
    ("connection_string", RiskLevel.critical, "Database connection string exposed — rotate credentials and restrict DB network access."),
    ("url_with_credentials", RiskLevel.critical, "Credentials embedded in URL — remove credentials from URLs; use environment variables or secret managers."),
    ("credit_card", RiskLevel.critical, "Credit card number detected — this is a PCI-DSS violation; engage your compliance team immediately."),
    ("ssn", RiskLevel.critical, "Social Security Number found — potential HIPAA/PII violation; initiate a data breach assessment."),
    ("private_key", RiskLevel.critical, "Private key material found — revoke and regenerate the key pair immediately."),
    ("brute_force_attempt", RiskLevel.high, "Multiple failed login attempts detected — possible brute-force attack; consider IP blocking and account lockout policies."),
    ("suspicious_ip_activity", RiskLevel.medium, "Suspicious external IP activity detected — review firewall rules and consider rate limiting."),
    ("stack_trace", RiskLevel.medium, "Stack trace leaked — internal code paths exposed to logs; configure production error handlers to suppress stack traces."),
    ("debug_mode_leak", RiskLevel.medium, "Application running in DEBUG mode — disable debug mode in production to prevent sensitive data exposure."),
    ("debug_leak", RiskLevel.medium, "Debug log entries contain sensitive keywords — review logging configuration to filter sensitive fields."),
    ("email", RiskLevel.low, "Email addresses found in logs — ensure logging complies with GDPR/privacy regulations."),
    ("ip_address", RiskLevel.low, "IP addresses logged — ensure compliance with data retention policies for network identifiers."),
    ("repeated_errors", RiskLevel.medium, "High error rate detected — investigate application stability and check for ongoing attacks or misconfigurations."),
]


def generate_rule_based_insights(findings: List[Finding]) -> List[str]:
    """Generate contextual, actionable security insights from findings."""
    finding_types = {f.type for f in findings}
    insights = []

    for ftype, risk, message in _INSIGHT_RULES:
        if ftype in finding_types:
            insights.append(message)

    if not insights:
        insights.append("No significant security issues detected. Continue monitoring for anomalies.")

    return insights[:8]  # cap at 8 insights


async def generate_ai_insights(
    findings: List[Finding],
    content_type: str,
    content_preview: str,
    stats: Optional[dict] = None,
) -> List[str]:
    """
    Attempt OpenAI-powered insights; fall back to rule-based if unavailable.
    """
    from ..core.config import settings

    if not settings.openai_api_key or settings.ai_provider == "none":
        return generate_rule_based_insights(findings)

    try:
        from openai import AsyncOpenAI
        import json

        client = AsyncOpenAI(api_key=settings.openai_api_key)

        findings_text = "\n".join(
            f"- [{f.risk.upper()}] {f.type}"
            + (f" at line {f.line}" if f.line else "")
            + (f": {f.context[:80]}" if f.context else "")
            for f in findings[:30]
        )

        stats_text = ""
        if stats:
            stats_text = f"\nLog stats: {stats.get('total_lines', 0)} lines, {stats.get('failed_logins', 0)} failed logins, {stats.get('error_count', 0)} errors."

        prompt = (
            f"You are a senior security analyst. Analyze these findings from a '{content_type}' input "
            f"and provide 4-6 specific, actionable security insights.{stats_text}\n\n"
            f"Findings:\n{findings_text}\n\n"
            f"Return a JSON object with key 'insights' containing an array of insight strings. "
            f"Each insight must be specific (mention the finding type), actionable, and under 150 characters. "
            f"Do NOT be generic. Focus on the actual risks present."
        )

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=600,
            temperature=0.3,
        )

        raw = response.choices[0].message.content
        data = json.loads(raw)
        insights = data.get("insights", [])
        if isinstance(insights, list) and insights:
            return insights[:8]

        return generate_rule_based_insights(findings)

    except Exception:
        return generate_rule_based_insights(findings)
