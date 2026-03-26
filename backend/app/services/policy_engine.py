from typing import List
from ..models.schemas import Finding, RiskLevel, AnalysisOptions
from .detector import mask_content


_HIGH_RISK_LEVELS = {RiskLevel.high, RiskLevel.critical}


def apply_policy(
    content: str,
    findings: List[Finding],
    risk_level: RiskLevel,
    options: AnalysisOptions,
) -> dict:
    """
    Evaluate policy rules and determine action + masked content.

    Returns:
        {
            "action": "blocked" | "masked" | "allowed",
            "masked_content": str | None,
        }
    """
    # Block policy: stop processing if high/critical risk
    if options.block_high_risk and risk_level in _HIGH_RISK_LEVELS:
        return {
            "action": "blocked",
            "masked_content": None,
        }

    # Mask policy: redact sensitive values from content
    if options.mask and findings:
        return {
            "action": "masked",
            "masked_content": mask_content(content),
        }

    return {
        "action": "allowed",
        "masked_content": content,
    }
