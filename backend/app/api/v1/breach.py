import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.utils import get_or_create_user
from app.core.database import get_db
from app.models.entities import Alert, BreachCheck, BreachEvent
from app.schemas.dto import BreachCheckRequest, BreachCheckResponse, BreachDeleteRequest, BreachEventOut
from app.services.alerts import broker
from app.services.breach import check_email_breach, remove_email_from_mock_breach_db
from app.services.monitor import breach_monitor
from app.services.notifier import send_email_notification
from app.services.risk import classify_level

router = APIRouter(prefix="/breach", tags=["breach"])


def _existing_breach_names(db: Session, email: str) -> set[str]:
    rows = (
        db.query(BreachEvent.breach_name)
        .join(BreachCheck, BreachEvent.breach_check_id == BreachCheck.id)
        .filter(BreachCheck.email_checked == email)
        .all()
    )
    return {name for (name,) in rows}


@router.post("/check-email", response_model=BreachCheckResponse)
async def breach_check(payload: BreachCheckRequest, db: Session = Depends(get_db)):
    user = get_or_create_user(db, payload.user_email)
    events = await check_email_breach(payload.user_email)
    seen_breaches = _existing_breach_names(db, payload.user_email)
    new_events = [item for item in events if item["breach_name"] not in seen_breaches]

    exposure_score = round(min(100.0, sum(e["severity_score"] for e in events) / max(1, len(events))), 2) if events else 0.0

    check = BreachCheck(
        user_id=user.id,
        email_checked=payload.user_email,
        exposure_score=exposure_score,
        breach_count=len(events),
    )
    db.add(check)
    db.commit()
    db.refresh(check)

    for event in events:
        db.add(
            BreachEvent(
                breach_check_id=check.id,
                breach_name=event["breach_name"],
                breach_date=event["breach_date"],
                data_classes=json.dumps(event["data_classes"]),
                is_verified=event["is_verified"],
                severity_score=event["severity_score"],
            )
        )
    db.commit()

    if new_events:
        severity = classify_level(exposure_score)
        alert = Alert(
            user_id=user.id,
            alert_type="breach",
            severity=severity,
            title="Breach Exposure Detected",
            message=f"{len(new_events)} new breach events found for {payload.user_email}",
            remediation='["Reset reused passwords","Enable MFA","Review exposed accounts and rotate secrets"]',
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        await broker.publish(
            user.id,
            {
                "type": "breach",
                "severity": alert.severity,
                "title": alert.title,
                "message": alert.message,
            },
        )
        send_email_notification(
            payload.user_email,
            "AI DataShield: Breach Exposure Detected",
            f"Detected {len(new_events)} new breach events for {payload.user_email}. Exposure score: {exposure_score}",
        )

    return BreachCheckResponse(
        email=payload.user_email,
        breach_count=len(events),
        exposure_score=exposure_score,
        events=[
            BreachEventOut(
                breach_name=e["breach_name"],
                breach_date=e["breach_date"],
                data_classes=e["data_classes"],
                is_verified=e["is_verified"],
                severity_score=e["severity_score"],
            )
            for e in events
        ],
    )


@router.get("/history")
def breach_history(email: str, db: Session = Depends(get_db)):
    checks = db.query(BreachCheck).filter(BreachCheck.email_checked == email).order_by(BreachCheck.checked_at.desc()).all()
    rows = []
    for check in checks:
        rows.append(
            {
                "id": check.id,
                "email": check.email_checked,
                "checked_at": check.checked_at,
                "breach_count": check.breach_count,
                "exposure_score": check.exposure_score,
                "exposure_level": classify_level(check.exposure_score),
            }
        )
    return rows


@router.get("/monitor/status")
def breach_monitor_status():
    return breach_monitor.status()


@router.post("/monitor/run-once")
async def breach_monitor_run_once():
    return await breach_monitor.run_once()


@router.post("/remove-sensitive-email")
def remove_sensitive_email(payload: BreachDeleteRequest):
    return remove_email_from_mock_breach_db(payload.user_email)
