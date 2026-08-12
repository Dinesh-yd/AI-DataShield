from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr


class ScanTextRequest(BaseModel):
    user_email: EmailStr
    user_name: str = "Demo User"
    content: str


class PIIFindingOut(BaseModel):
    entity_type: str
    original: str
    redacted: str
    confidence: float
    start: int
    end: int


class ScanResponse(BaseModel):
    scan_id: int
    redacted_text: str
    confidence_avg: float
    findings: list[PIIFindingOut]
    risk_score: float
    risk_level: str


class BreachCheckRequest(BaseModel):
    user_email: EmailStr


class BreachDeleteRequest(BaseModel):
    user_email: EmailStr


class BreachEventOut(BaseModel):
    breach_name: str
    breach_date: str
    data_classes: list[str]
    is_verified: bool
    severity_score: float


class BreachCheckResponse(BaseModel):
    email: EmailStr
    breach_count: int
    exposure_score: float
    events: list[BreachEventOut]


class AlertOut(BaseModel):
    id: int
    alert_type: str
    severity: str
    title: str
    message: str
    remediation: list[str]
    is_read: bool
    created_at: datetime


class DashboardSummary(BaseModel):
    total_files_scanned: int
    total_pii_found: int
    avg_risk_score: float
    breach_exposure_total: int
    compliance_indicator: str
    risk_trend: list[dict[str, Any]]
