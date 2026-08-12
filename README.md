# AI DataShield

End-to-End Privacy & Breach Intelligence Platform (Hackathon MVP).

## Features
- AI-based PII detection and redaction for text
- OCR-based PII detection for images
- Local mock dark-web breach lookup and exposure history (HIBP-like structure)
- Privacy risk score (0-100) with classification
- Real-time UI alerts over WebSocket
- Dashboard summary with compliance indicator
- Python-only Streamlit 4-phase presentation dashboard

## Quick Start (Local)
1. Open terminal in `ai-datashield/backend`
2. Create env file:
   - Copy `.env.example` to `.env`
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Run server:
   - `python -m streamlit run app.py`
5. Open:
   - `http://localhost:8000`

## Python-only UI (Streamlit)
1. Keep backend running on `http://localhost:8000`
2. In a new terminal at `ai-datashield/backend` install dependencies:
   - `pip install -r requirements.txt`
3. Run Streamlit from `ai-datashield` root:
   - `streamlit run streamlit_app.py`
4. Open the Streamlit URL shown in terminal (usually `http://localhost:8501`)

## Docker
1. Copy `backend/.env.example` to `backend/.env`
2. Run from `ai-datashield/infra`:
   - `docker compose up --build`
3. Open `http://localhost:8000`

## API Surface
- `POST /api/v1/auth/register`
- `POST /api/v1/scan/text`
- `POST /api/v1/scan/image`
- `GET /api/v1/scan/{scan_id}`
- `GET /api/v1/scan/{scan_id}/download-redacted`
- `POST /api/v1/breach/check-email`
- `GET /api/v1/breach/history?email=`
- `GET /api/v1/breach/monitor/status`
- `POST /api/v1/breach/monitor/run-once`
- `POST /api/v1/breach/remove-sensitive-email`
- `GET /api/v1/risk/{entity_id}`
- `GET /api/v1/risk/trend/{email}`
- `GET /api/v1/alerts?email=`
- `POST /api/v1/alerts/ack/{alert_id}`
- `GET /api/v1/dashboard/summary?email=`
- `GET /api/v1/dashboard/compliance?email=`
- `GET /api/v1/remediation/recommendations?email=`
- `GET /api/v1/remediation/proactive-controls?email=`

## Notes
- Breach checks use OpenAI-generated synthetic breach events when `OPENAI_API_KEY` is set; otherwise fallback is `backend/app/data/mock_breach_db.json`.
- For real breach lookup, set `MOCK_BREACH_MODE=false` and provide `HIBP_API_KEY` in `backend/.env`.
- Continuous breach monitoring can be enabled with `BREACH_MONITOR_ENABLED=true` and interval via `BREACH_MONITOR_INTERVAL_SECONDS`.
- OCR uses local Tesseract. If unavailable, image scan may return no text.

## Judge Evidence Artifacts
- Privacy compliance documentation: `docs/privacy-compliance.md`
- API integration documentation: `docs/api-integration.md`
- Redaction benchmark dataset: `evaluation/redaction_test_data.json`
- Redaction benchmark output: `evaluation/benchmark_results.json`
- Redaction accuracy report: `evaluation/redaction_accuracy_report.md`
