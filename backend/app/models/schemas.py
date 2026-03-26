from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class InputType(str, Enum):
    text = "text"
    file = "file"
    sql = "sql"
    chat = "chat"
    log = "log"


class AnalysisOptions(BaseModel):
    mask: bool = True
    block_high_risk: bool = True
    log_analysis: bool = True


class AnalyzeRequest(BaseModel):
    input_type: InputType
    content: str
    options: AnalysisOptions = AnalysisOptions()


class Finding(BaseModel):
    type: str
    risk: RiskLevel
    value: Optional[str] = None
    line: Optional[int] = None
    context: Optional[str] = None


class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: List[Finding]
    risk_score: int
    risk_level: RiskLevel
    action: str
    insights: List[str]
    masked_content: Optional[str] = None
    line_risks: Optional[dict] = None  # line_number -> risk_level for log viewer
