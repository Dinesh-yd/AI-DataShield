from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import RiskSnapshot, User

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/{entity_id}")
def get_latest_risk(entity_id: int, db: Session = Depends(get_db)):
    snapshot = (
        db.query(RiskSnapshot)
        .filter(RiskSnapshot.user_id == entity_id)
        .order_by(RiskSnapshot.computed_at.desc())
        .first()
    )
    if not snapshot:
        raise HTTPException(status_code=404, detail="Risk data not found")
    return {
        "user_id": entity_id,
        "final_score": snapshot.final_score,
        "level": snapshot.level,
        "components": {
            "pii_score": snapshot.pii_score,
            "sensitivity_score": snapshot.sensitivity_score,
            "breach_score": snapshot.breach_score,
        },
        "computed_at": snapshot.computed_at,
    }


@router.get("/trend/{email}")
def risk_trend(email: str, days: int = 30, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    rows = (
        db.query(func.date(RiskSnapshot.computed_at).label("day"), func.avg(RiskSnapshot.final_score).label("avg_score"))
        .filter(RiskSnapshot.user_id == user.id)
        .group_by(func.date(RiskSnapshot.computed_at))
        .order_by(func.date(RiskSnapshot.computed_at).desc())
        .limit(days)
        .all()
    )

    return [{"day": str(day), "avg_score": round(float(avg_score), 2)} for day, avg_score in rows]
