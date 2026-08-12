import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.utils import get_or_create_user
from app.core.database import get_db
from app.models.entities import BreachCheck, BreachEvent, PIIFinding, ScanJob, ScanResult
from app.services.remediation import aggregate_breach_data_classes, proactive_controls, recommend_actions

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.get("/recommendations")
def recommendations(email: str, db: Session = Depends(get_db)):
    user = get_or_create_user(db, email)

    pii_rows = (
        db.query(PIIFinding.entity_type)
        .join(ScanResult, PIIFinding.scan_result_id == ScanResult.id)
        .join(ScanJob, ScanResult.scan_job_id == ScanJob.id)
        .filter(ScanJob.user_id == user.id)
        .all()
    )
    pii_types = [entity_type for (entity_type,) in pii_rows]

    latest_check = (
        db.query(BreachCheck)
        .filter(BreachCheck.user_id == user.id)
        .order_by(BreachCheck.checked_at.desc())
        .first()
    )
    breach_count = latest_check.breach_count if latest_check else 0

    breach_class_rows = (
        db.query(BreachEvent.data_classes)
        .join(BreachCheck, BreachEvent.breach_check_id == BreachCheck.id)
        .filter(BreachCheck.user_id == user.id)
        .all()
    )
    data_classes: list[str] = []
    for (raw_classes,) in breach_class_rows:
        try:
            parsed = json.loads(raw_classes or "[]")
            if isinstance(parsed, list):
                data_classes.extend([str(item) for item in parsed])
        except json.JSONDecodeError:
            continue

    aggregated_classes = aggregate_breach_data_classes(data_classes)
    recommendations = recommend_actions(pii_types, aggregated_classes, breach_count)

    return {
        "email": email,
        "pii_types_detected": sorted(set(pii_types)),
        "breach_data_classes": aggregated_classes,
        "latest_breach_count": breach_count,
        "recommendations": recommendations,
    }


@router.get("/proactive-controls")
def proactive(email: str, db: Session = Depends(get_db)):
    user = get_or_create_user(db, email)

    pii_rows = (
        db.query(PIIFinding.entity_type)
        .join(ScanResult, PIIFinding.scan_result_id == ScanResult.id)
        .join(ScanJob, ScanResult.scan_job_id == ScanJob.id)
        .filter(ScanJob.user_id == user.id)
        .all()
    )
    pii_types = [entity_type for (entity_type,) in pii_rows]

    latest_check = (
        db.query(BreachCheck)
        .filter(BreachCheck.user_id == user.id)
        .order_by(BreachCheck.checked_at.desc())
        .first()
    )
    breach_count = latest_check.breach_count if latest_check else 0

    breach_class_rows = (
        db.query(BreachEvent.data_classes)
        .join(BreachCheck, BreachEvent.breach_check_id == BreachCheck.id)
        .filter(BreachCheck.user_id == user.id)
        .all()
    )
    data_classes: list[str] = []
    for (raw_classes,) in breach_class_rows:
        try:
            parsed = json.loads(raw_classes or "[]")
            if isinstance(parsed, list):
                data_classes.extend([str(item) for item in parsed])
        except json.JSONDecodeError:
            continue

    aggregated_classes = aggregate_breach_data_classes(data_classes)
    controls = proactive_controls(pii_types, aggregated_classes, breach_count)

    return {
        "email": email,
        "latest_breach_count": breach_count,
        "controls": controls,
    }
