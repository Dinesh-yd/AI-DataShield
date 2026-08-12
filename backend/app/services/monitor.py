import asyncio
import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.entities import Alert, BreachCheck, BreachEvent, User
from app.services.alerts import broker
from app.services.breach import check_email_breach
from app.services.notifier import send_email_notification
from app.services.risk import classify_level


def _existing_breach_names(db: Session, email: str) -> set[str]:
    rows = (
        db.query(BreachEvent.breach_name)
        .join(BreachCheck, BreachEvent.breach_check_id == BreachCheck.id)
        .filter(BreachCheck.email_checked == email)
        .all()
    )
    return {name for (name,) in rows}


class BreachMonitor:
    def __init__(self):
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._last_run_at: str | None = None
        self._last_error: str | None = None

    async def start(self):
        if not settings.breach_monitor_enabled or self._task:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        if not self._task:
            return
        self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except BaseException:
            pass
        self._task = None

    def status(self) -> dict[str, str | bool | int | None]:
        return {
            "enabled": settings.breach_monitor_enabled,
            "running": self._task is not None and not self._task.done(),
            "interval_seconds": settings.breach_monitor_interval_seconds,
            "last_run_at": self._last_run_at,
            "last_error": self._last_error,
        }

    async def run_once(self) -> dict[str, int | str]:
        users_processed, alerts_created = await self._run_cycle()
        return {
            "users_processed": users_processed,
            "alerts_created": alerts_created,
            "executed_at": datetime.utcnow().isoformat(),
        }

    async def _run(self):
        while not self._stop_event.is_set():
            try:
                await self._run_cycle()
                self._last_error = None
            except Exception as exc:
                self._last_error = str(exc)
            self._last_run_at = datetime.utcnow().isoformat()
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=max(30, settings.breach_monitor_interval_seconds))
            except asyncio.TimeoutError:
                continue

    async def _run_cycle(self) -> tuple[int, int]:
        db = SessionLocal()
        users_processed = 0
        alerts_created = 0
        try:
            users = db.query(User).all()
            for user in users:
                users_processed += 1
                events = await check_email_breach(user.email)
                exposure_score = round(min(100.0, sum(e["severity_score"] for e in events) / max(1, len(events))), 2) if events else 0.0
                seen_breaches = _existing_breach_names(db, user.email)
                new_events = [item for item in events if item["breach_name"] not in seen_breaches]

                check = BreachCheck(
                    user_id=user.id,
                    email_checked=user.email,
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

                if not new_events:
                    continue

                alerts_created += 1
                severity = classify_level(exposure_score)
                alert = Alert(
                    user_id=user.id,
                    alert_type="breach_monitor",
                    severity=severity,
                    title="New Breach Event Detected",
                    message=f"{len(new_events)} new breach events found for {user.email}",
                    remediation='["Reset reused passwords","Enable MFA","Audit exposed accounts and rotate secrets"]',
                )
                db.add(alert)
                db.commit()
                db.refresh(alert)

                await broker.publish(
                    user.id,
                    {
                        "type": "breach_monitor",
                        "severity": alert.severity,
                        "title": alert.title,
                        "message": alert.message,
                    },
                )
                send_email_notification(
                    user.email,
                    "AI DataShield: New Breach Event Detected",
                    f"Detected {len(new_events)} new breach events for {user.email}. Exposure score: {exposure_score}",
                )
            return users_processed, alerts_created
        finally:
            db.close()


breach_monitor = BreachMonitor()
