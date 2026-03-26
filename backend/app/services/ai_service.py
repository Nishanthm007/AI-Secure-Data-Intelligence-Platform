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
    """Generate dynamic, context-aware insights using actual finding data."""
    insights = []
    by_type: dict = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    # Templates that inject real finding data
    _DYNAMIC_RULES = [
        ("password", RiskLevel.critical,
         lambda fs: f"Plaintext password(s) detected on line {fs[0].line or '?'} — credentials must never appear in logs; rotate immediately and audit your logging pipeline."),
        ("secret", RiskLevel.critical,
         lambda fs: f"Hardcoded secret found on line {fs[0].line or '?'} — rotate this key now and enforce secret scanning in your CI/CD pipeline."),
        ("api_key", RiskLevel.high,
         lambda fs: f"API key exposed on line {fs[0].line or '?'} — revoke and regenerate immediately; restrict key scope to minimum required permissions."),
        ("aws_key", RiskLevel.critical,
         lambda fs: f"AWS access key (AKIA...) found on line {fs[0].line or '?'} — revoke via IAM console now and check CloudTrail for unauthorized usage."),
        ("jwt", RiskLevel.high,
         lambda fs: f"JWT token found on line {fs[0].line or '?'} — this grants authenticated session access; invalidate the token and rotate signing secrets."),
        ("connection_string", RiskLevel.critical,
         lambda fs: f"Database connection string with embedded credentials on line {fs[0].line or '?'} — use a secret manager (e.g. Vault, AWS Secrets Manager) immediately."),
        ("url_with_credentials", RiskLevel.critical,
         lambda fs: f"Credentials embedded in URL on line {fs[0].line or '?'} — move to environment variables; URLs are frequently logged and cached."),
        ("credit_card", RiskLevel.critical,
         lambda fs: f"Credit card number on line {fs[0].line or '?'} — PCI-DSS violation; engage compliance team, scope the breach, and notify your payment processor."),
        ("ssn", RiskLevel.critical,
         lambda fs: f"SSN found on line {fs[0].line or '?'} — HIPAA/PII violation; initiate a data breach assessment and notify your privacy officer."),
        ("private_key", RiskLevel.critical,
         lambda fs: f"Private key material on line {fs[0].line or '?'} — revoke and regenerate the key pair; audit all systems that trusted this key."),
        ("brute_force_attempt", RiskLevel.high,
         lambda fs: f"Brute-force pattern detected: {len(fs)} consecutive failed logins on line {fs[0].line or '?'} — block IP and enforce account lockout policies."),
        ("suspicious_ip_activity", RiskLevel.medium,
         lambda fs: f"Suspicious external IP activity detected ({len(fs)} event(s)) — review firewall rules and add the IP to your threat intelligence watchlist."),
        ("stack_trace", RiskLevel.medium,
         lambda fs: f"Stack trace leaked on line {fs[0].line or '?'} — internal code paths exposed; configure production loggers to suppress stack traces."),
        ("debug_mode_leak", RiskLevel.medium,
         lambda fs: f"Application running in DEBUG mode (line {fs[0].line or '?'}) — disable DEBUG in production; it exposes internal state and config."),
        ("debug_leak", RiskLevel.medium,
         lambda fs: f"Sensitive keyword in DEBUG log on line {fs[0].line or '?'} — add log filters to scrub sensitive field names before writing to log sinks."),
        ("email", RiskLevel.low,
         lambda fs: f"{len(fs)} email address(es) logged — verify GDPR/privacy compliance; consider pseudonymising user identifiers in logs."),
        ("repeated_errors", RiskLevel.medium,
         lambda fs: f"High error rate detected ({len(fs)} error finding(s)) — investigate application stability; may indicate an ongoing attack or misconfiguration."),
    ]

    for ftype, risk, template in _DYNAMIC_RULES:
        if ftype in by_type:
            insights.append(template(by_type[ftype]))

    if not insights:
        total = len(findings)
        insights.append(f"Scanned {total} finding(s) — no critical security issues detected. Continue monitoring for anomalies.")

    return insights[:8]


async def generate_ai_insights(
    findings: List[Finding],
    content_type: str,
    content_preview: str,
    stats: Optional[dict] = None,
) -> List[str]:
    """
    Try Gemini first → Groq second → rule-based fallback last.
    """
    from ..core.config import settings

    if settings.ai_provider == "none":
        return generate_rule_based_insights(findings)

    import httpx
    import json

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

    # ── 1. Try Gemini ─────────────────────────────────────────────────────────
    if settings.gemini_api_key:
        try:
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-2.5-flash:generateContent?key={settings.gemini_api_key}"
            )
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 600,
                    "responseMimeType": "application/json"
                }
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()

            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            insights = json.loads(text).get("insights", [])
            if isinstance(insights, list) and insights:
                return insights[:8]
        except Exception:
            pass  # Gemini failed → try Groq

    # ── 2. Try Groq ───────────────────────────────────────────────────────────
    if settings.groq_api_key:
        try:
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 600,
                "response_format": {"type": "json_object"}
            }
            headers = {
                "Authorization": f"Bearer {settings.groq_api_key}",
                "Content-Type": "application/json"
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    json=payload,
                    headers=headers
                )
                resp.raise_for_status()

            text = resp.json()["choices"][0]["message"]["content"]
            insights = json.loads(text).get("insights", [])
            if isinstance(insights, list) and insights:
                return insights[:8]
        except Exception:
            pass  # Groq failed → rule-based

    # ── 3. Rule-based fallback ─────────────────────────────────────────────────
    return generate_rule_based_insights(findings)

