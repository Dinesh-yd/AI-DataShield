# Privacy Compliance Documentation (Hackathon MVP)

## Scope
This document describes privacy controls implemented in AI DataShield for text/image scanning, redaction, breach monitoring, and alerting.

## Data Flow
1. User submits text or image input.
2. OCR extracts text from images (if applicable).
3. PII detection identifies sensitive entities.
4. Redaction service masks entities before downstream processing.
5. Risk and breach checks produce scores and alerts.
6. Findings and risk snapshots are stored for auditability.

## Data Classification and Handling
| Data Type | Example | Control |
| --- | --- | --- |
| Email | `user@corp.com` | Detect + mask token in outputs |
| Phone | `555-123-4567` | Detect + mask token in outputs |
| National IDs | SSN/AADHAAR/PAN | High-priority detection and redaction |
| Payment Data | Card numbers | High-priority detection and redaction |
| IP Address | `192.168.1.1` | Detection + redaction |

## Security Controls
1. PII masking tokens for all exposed values before output.
2. Risk scoring and severity classification.
3. Alert generation for high-risk scans and breach events.
4. Optional SMTP notifications for breach detections.
5. WebSocket-based real-time alert delivery.

## Data Minimization
1. Redacted output is used for downstream LLM-safe processing.
2. Hashing is used for source text fingerprinting (`source_text_hash`).
3. Only required identity fields are kept for user session tracking.

## Retention and Deletion Policy (MVP)
1. Retain findings for trend analytics and incident review.
2. Recommend periodic cleanup job for old scans/checks in production.
3. For regulated deployments, add user-initiated deletion endpoint.

## Incident Response (MVP Procedure)
1. Detect exposure via scan/breach monitor.
2. Create alert and notify user.
3. Provide remediation and proactive controls.
4. Track closure in an operational ticket/worklog.

## Compliance Mapping (High-Level)
| Requirement Theme | Current Support |
| --- | --- |
| Data minimization | Redaction + tokenization |
| Security of processing | Risk scoring + alerts |
| Breach awareness | Breach check + monitor |
| User notification | UI alerts + optional SMTP |
| Auditability | Persistent scan/risk/breach records |

## Known Gaps for Production
1. Formal DPIA template automation.
2. Policy enforcement engine (retention expiry job).
3. Role-based access control and full audit log export.
