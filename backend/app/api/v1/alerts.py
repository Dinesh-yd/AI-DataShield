import json

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.api.v1.utils import get_or_create_user
from app.core.database import get_db
from app.models.entities import Alert
from app.services.alerts import broker

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(email: str, db: Session = Depends(get_db)):
    user = get_or_create_user(db, email)
    rows = db.query(Alert).filter(Alert.user_id == user.id).order_by(Alert.created_at.desc()).all()
    return [
        {
            "id": row.id,
            "alert_type": row.alert_type,
            "severity": row.severity,
            "title": row.title,
            "message": row.message,
            "remediation": json.loads(row.remediation or "[]"),
            "is_read": row.is_read,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.post("/ack/{alert_id}")
def ack_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"ok": False, "message": "Alert not found"}
    alert.is_read = True
    db.commit()
    return {"ok": True}


@router.websocket("/ws/{user_id}")
async def alerts_ws(websocket: WebSocket, user_id: int):
    await broker.connect(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        broker.disconnect(user_id, websocket)
