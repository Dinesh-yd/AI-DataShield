from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.v1.utils import get_or_create_user
from app.core.database import get_db
from app.models.entities import BreachCheck, PIIFinding, RiskSnapshot, ScanJob, ScanResult

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(email: str, db: Session = Depends(get_db)):
    user = get_or_create_user(db, email)

    total_files_scanned = db.query(func.count(ScanJob.id)).filter(ScanJob.user_id == user.id).scalar() or 0

    total_pii_found = (
        db.query(func.count(PIIFinding.id))
        .join(ScanResult, ScanResult.id == PIIFinding.scan_result_id)
        .join(ScanJob, ScanJob.id == ScanResult.scan_job_id)
        .filter(ScanJob.user_id == user.id)
        .scalar()
        or 0
    )

    avg_risk_score = (
        db.query(func.avg(RiskSnapshot.final_score)).filter(RiskSnapshot.user_id == user.id).scalar() or 0.0
    )

    breach_exposure_total = (
        db.query(func.sum(BreachCheck.breach_count)).filter(BreachCheck.user_id == user.id).scalar() or 0
    )

    if avg_risk_score < 25:
        compliance_indicator = "Compliant"
    elif avg_risk_score < 50:
        compliance_indicator = "Watch"
    else:
        compliance_indicator = "At Risk"

    trend_rows = (
        db.query(func.date(RiskSnapshot.computed_at), func.avg(RiskSnapshot.final_score))
        .filter(RiskSnapshot.user_id == user.id)
        .group_by(func.date(RiskSnapshot.computed_at))
        .order_by(func.date(RiskSnapshot.computed_at).asc())
        .all()
    )
    risk_trend = [{"day": str(day), "score": round(float(score), 2)} for day, score in trend_rows]

    return {
        "total_files_scanned": total_files_scanned,
        "total_pii_found": total_pii_found,
        "avg_risk_score": round(float(avg_risk_score), 2),
        "breach_exposure_total": int(breach_exposure_total),
        "compliance_indicator": compliance_indicator,
        "risk_trend": risk_trend,
    }


@router.get("/compliance")
def compliance(email: str, db: Session = Depends(get_db)):
    user = get_or_create_user(db, email)
    latest = (
        db.query(RiskSnapshot).filter(RiskSnapshot.user_id == user.id).order_by(RiskSnapshot.computed_at.desc()).first()
    )

    score = latest.final_score if latest else 0.0
    controls = {
        "pii_detection": score < 75,
        "breach_monitoring": True,
        "alerting": True,
        "redaction_enabled": True,
    }
    return {
        "user": email,
        "current_risk": score,
        "controls": controls,
        "status": "Pass" if all(controls.values()) else "Review Required",
    }
