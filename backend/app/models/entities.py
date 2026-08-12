from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    file_type: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="completed")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    scan_result = relationship("ScanResult", back_populates="scan_job", uselist=False)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), unique=True)
    source_text_hash: Mapped[str] = mapped_column(String(128))
    total_entities: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(50), default="Low")
    redacted_text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_job = relationship("ScanJob", back_populates="scan_result")
    findings = relationship("PIIFinding", back_populates="scan_result")


class PIIFinding(Base):
    __tablename__ = "pii_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(50))
    original_snippet: Mapped[str] = mapped_column(String(255))
    redacted_snippet: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float)
    position_start: Mapped[int] = mapped_column(Integer)
    position_end: Mapped[int] = mapped_column(Integer)

    scan_result = relationship("ScanResult", back_populates="findings")


class BreachCheck(Base):
    __tablename__ = "breach_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    email_checked: Mapped[str] = mapped_column(String(255), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    exposure_score: Mapped[float] = mapped_column(Float, default=0.0)
    breach_count: Mapped[int] = mapped_column(Integer, default=0)

    breach_events = relationship("BreachEvent", back_populates="breach_check")


class BreachEvent(Base):
    __tablename__ = "breach_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    breach_check_id: Mapped[int] = mapped_column(ForeignKey("breach_checks.id"), index=True)
    breach_name: Mapped[str] = mapped_column(String(255))
    breach_date: Mapped[str] = mapped_column(String(50), default="")
    data_classes: Mapped[str] = mapped_column(Text, default="[]")
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    severity_score: Mapped[float] = mapped_column(Float, default=0.0)

    breach_check = relationship("BreachCheck", back_populates="breach_events")


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scan_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"), index=True)
    pii_score: Mapped[float] = mapped_column(Float)
    breach_score: Mapped[float] = mapped_column(Float)
    sensitivity_score: Mapped[float] = mapped_column(Float)
    final_score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String(50))
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    alert_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default="[]")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
