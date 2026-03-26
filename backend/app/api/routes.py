from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from typing import Optional, List
from pydantic import BaseModel
import json

from ..models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalysisOptions,
    InputType,
    RiskLevel,
)
from ..services import detector, log_analyzer, risk_engine, policy_engine, ai_service, parser
from ..services.correlator import correlate_logs
from ..core.config import settings
from ..core.limiter import analyze_limit, upload_limit


class CorrelateRequest(BaseModel):
    logs: List[str]
    options: AnalysisOptions = AnalysisOptions()

router = APIRouter()


# ── Shared analysis pipeline ──────────────────────────────────────────────────

async def _run_analysis(
    content: str,
    input_type: str,
    options: AnalysisOptions,
) -> AnalyzeResponse:
    content_type = input_type
    findings = []
    line_risks = {}
    masked_content = None
    stats = {}

    # Route to appropriate analysis path
    if input_type == InputType.log or options.log_analysis and _looks_like_log(content):
        result = log_analyzer.analyze_log(content, max_lines=settings.max_log_lines)
        findings = result["findings"]
        line_risks = result["line_risks"]
        masked_content = result["masked_content"]
        stats = result["stats"]
        content_type = "log"
    else:
        findings = detector.detect(content)
        masked_content = detector.mask_content(content)

    # Risk scoring
    score = risk_engine.calculate_score(findings)
    level = risk_engine.classify_level(score)
    summary = risk_engine.build_summary(findings, content_type, stats)

    # Policy
    policy = policy_engine.apply_policy(content, findings, level, options)
    action = policy["action"]
    if policy["masked_content"] is not None:
        masked_content = policy["masked_content"]

    # AI insights
    insights = await ai_service.generate_ai_insights(
        findings, content_type, content[:500], stats
    )

    return AnalyzeResponse(
        summary=summary,
        content_type=content_type,
        findings=findings,
        risk_score=score,
        risk_level=level,
        action=action,
        insights=insights,
        masked_content=masked_content,
        line_risks=line_risks if line_risks else None,
    )


def _looks_like_log(content: str) -> bool:
    """Heuristic: content looks like a log file if it has timestamp-like prefixes."""
    import re
    timestamp_re = re.compile(r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}")
    first_lines = content.splitlines()[:10]
    matches = sum(1 for ln in first_lines if timestamp_re.search(ln))
    return matches >= 2


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_text(request: AnalyzeRequest, _: None = Depends(analyze_limit)):
    """Analyze text / SQL / chat / log content provided as JSON."""
    if not request.content or not request.content.strip():
        raise HTTPException(status_code=400, detail="Content must not be empty.")

    return await _run_analysis(request.content, request.input_type, request.options)


@router.post("/analyze/upload", response_model=AnalyzeResponse)
async def analyze_file(
    file: UploadFile = File(...),
    options: str = Form(default='{"mask":true,"block_high_risk":true,"log_analysis":true}'),
    _: None = Depends(upload_limit),
):
    """Analyze an uploaded file (PDF, DOCX, TXT, LOG)."""
    # Validate file size
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    file_bytes = await file.read()
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {settings.max_file_size_mb} MB.",
        )
    # Reset position for parser
    import io
    file.file = io.BytesIO(file_bytes)

    # Parse options JSON
    try:
        opts_dict = json.loads(options)
        opts = AnalysisOptions(**opts_dict)
    except Exception:
        opts = AnalysisOptions()

    # Determine input_type from extension
    filename = file.filename or ""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    input_type = InputType.log if ext in ("log",) else InputType.file

    # Extract text
    file.file.seek(0)
    content = await parser.parse_file(file)

    return await _run_analysis(content, input_type, opts)


@router.post("/correlate")
async def correlate(request: CorrelateRequest, _: None = Depends(analyze_limit)):
    """Cross-log anomaly detection across multiple log files."""
    if not request.logs or len(request.logs) < 2:
        raise HTTPException(status_code=400, detail="Provide at least 2 log contents to correlate.")
    if len(request.logs) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 logs per correlation request.")
    for i, log in enumerate(request.logs):
        if not log or not log.strip():
            raise HTTPException(status_code=400, detail=f"Log {i + 1} is empty.")
    return correlate_logs(request.logs)


@router.get("/health")
async def health():
    return {"status": "ok", "ai_enabled": bool(settings.openai_api_key)}
