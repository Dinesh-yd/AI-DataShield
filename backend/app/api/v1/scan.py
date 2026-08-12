import hashlib

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.v1.utils import get_or_create_user
from app.core.database import get_db
from app.models.entities import Alert, PIIFinding, RiskSnapshot, ScanJob, ScanResult
from app.schemas.dto import PIIFindingOut, ScanResponse, ScanTextRequest
from app.services.ocr import extract_text_from_image
from app.services.pii import detect_pii
from app.services.redaction import mask_value, redact_with_mask
from app.services.alerts import broker
from app.services.risk import calculate_risk

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/text", response_model=ScanResponse)
async def scan_text(payload: ScanTextRequest, db: Session = Depends(get_db)):
    user = get_or_create_user(db, payload.user_email, payload.user_name)

    findings = detect_pii(payload.content)
    redacted = redact_with_mask(payload.content, findings)
    risk = calculate_risk(findings)

    scan_job = ScanJob(user_id=user.id, file_name="inline_text.txt", file_type="text")
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    scan_result = ScanResult(
        scan_job_id=scan_job.id,
        source_text_hash=hashlib.sha256(payload.content.encode("utf-8")).hexdigest(),
        total_entities=len(findings),
        risk_score=risk["final_score"],
        risk_level=risk["level"],
        redacted_text=redacted,
    )
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    for f in findings:
        db.add(
            PIIFinding(
                scan_result_id=scan_result.id,
                entity_type=f.entity_type,
                original_snippet=f.value,
                redacted_snippet=mask_value(f.value, f.entity_type),
                confidence=f.confidence,
                position_start=f.start,
                position_end=f.end,
            )
        )

    db.add(
        RiskSnapshot(
            user_id=user.id,
            scan_result_id=scan_result.id,
            pii_score=float(risk["pii_score"]),
            breach_score=float(risk["breach_score"]),
            sensitivity_score=float(risk["sensitivity_score"]),
            final_score=float(risk["final_score"]),
            level=str(risk["level"]),
        )
    )
    db.commit()

    if float(risk["final_score"]) >= 50:
        alert = Alert(
            user_id=user.id,
            alert_type="risk",
            severity=str(risk["level"]),
            title="High Privacy Risk Detected",
            message=f"Scan {scan_result.id} risk is {risk['final_score']} ({risk['level']})",
            remediation='["Rotate exposed credentials","Mask sensitive IDs before sharing","Enable ongoing breach monitoring"]',
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        await broker.publish(
            user.id,
            {
                "type": "risk",
                "severity": alert.severity,
                "title": alert.title,
                "message": alert.message,
            },
        )

    confidence_avg = round(sum(x.confidence for x in findings) / len(findings), 2) if findings else 0.0

    return ScanResponse(
        scan_id=scan_result.id,
        redacted_text=redacted,
        confidence_avg=confidence_avg,
        findings=[
            PIIFindingOut(
                entity_type=f.entity_type,
                original=f.value,
                redacted=mask_value(f.value, f.entity_type),
                confidence=f.confidence,
                start=f.start,
                end=f.end,
            )
            for f in findings
        ],
        risk_score=float(risk["final_score"]),
        risk_level=str(risk["level"]),
    )


@router.post("/image", response_model=ScanResponse)
async def scan_image(
    user_email: str = Form(...),
    user_name: str = Form("Demo User"),
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    content = await image.read()
    text = extract_text_from_image(content)
    if not text.strip():
        raise HTTPException(status_code=400, detail="No readable text extracted from image")

    payload = ScanTextRequest(user_email=user_email, user_name=user_name, content=text)
    return await scan_text(payload, db)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    result = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(PIIFinding).filter(PIIFinding.scan_result_id == result.id).all()
    avg_conf = round(sum(x.confidence for x in findings) / len(findings), 2) if findings else 0.0

    return ScanResponse(
        scan_id=result.id,
        redacted_text=result.redacted_text,
        confidence_avg=avg_conf,
        findings=[
            PIIFindingOut(
                entity_type=f.entity_type,
                original=f.original_snippet,
                redacted=f.redacted_snippet,
                confidence=f.confidence,
                start=f.position_start,
                end=f.position_end,
            )
            for f in findings
        ],
        risk_score=result.risk_score,
        risk_level=result.risk_level,
    )


@router.get("/{scan_id}/download-redacted")
def download_redacted(scan_id: int, db: Session = Depends(get_db)):
    result = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return PlainTextResponse(
        content=result.redacted_text,
        headers={"Content-Disposition": f"attachment; filename=redacted-{scan_id}.txt"},
    )
