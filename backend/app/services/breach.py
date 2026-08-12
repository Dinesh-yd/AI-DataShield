from typing import Any
import json
from pathlib import Path
import re

import httpx

from app.core.config import settings


def severity_from_data_classes(data_classes: list[str], verified: bool) -> float:
    class_weight = {
        "Passwords": 30,
        "Credit cards": 35,
        "Phone numbers": 10,
        "Email addresses": 8,
        "Government issued IDs": 20,
    }
    severity = 10.0
    for key, weight in class_weight.items():
        if key in data_classes:
            severity += weight
    if verified:
        severity += 10
    return min(100.0, severity)


async def check_email_breach(email: str) -> list[dict[str, Any]]:
    # Real breach-source mode: query HIBP when API key is provided and mock mode is disabled.
    if settings.hibp_api_key and not settings.mock_breach_mode:
        return await _load_hibp_breach_events(email)

    # Demo mode fallback uses local deterministic mock breaches.
    if settings.mock_breach_mode:
        return _load_mock_breach_events(email)

    # If real mode is requested but not configured, return no events.
    return []


async def _load_hibp_breach_events(email: str) -> list[dict[str, Any]]:
    url = f"{settings.hibp_base_url}/breachedaccount/{email}"
    headers = {
        "hibp-api-key": settings.hibp_api_key,
        "user-agent": "ai-datashield/1.0",
    }
    params = {"truncateResponse": "false"}

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.get(url, headers=headers, params=params)
    except Exception:
        return []

    if response.status_code == 404:
        return []
    if response.status_code != 200:
        return []

    raw = response.json()
    if not isinstance(raw, list):
        return []

    events: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        data_classes = item.get("DataClasses", [])
        if not isinstance(data_classes, list):
            data_classes = []
        is_verified = bool(item.get("IsVerified", False))
        events.append(
            {
                "breach_name": str(item.get("Name", "Unknown")),
                "breach_date": str(item.get("BreachDate", "")),
                "data_classes": [str(x) for x in data_classes],
                "is_verified": is_verified,
                "severity_score": severity_from_data_classes([str(x) for x in data_classes], is_verified),
            }
        )
    return events


def _load_mock_breach_events(email: str) -> list[dict[str, Any]]:
    db_path = Path(settings.mock_breach_db_path)
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parents[2] / settings.mock_breach_db_path

    if not db_path.exists():
        return []

    raw_catalog = json.loads(db_path.read_text(encoding="utf-8"))
    catalog = raw_catalog if isinstance(raw_catalog, dict) else {}

    key = email.strip().lower()
    records = catalog.get("emails", {}).get(key, [])

    events: list[dict[str, Any]] = []
    for item in records:
        data_classes = item.get("data_classes", [])
        is_verified = bool(item.get("is_verified", True))
        events.append(
            {
                "breach_name": item.get("breach_name", "Unknown"),
                "breach_date": item.get("breach_date", ""),
                "data_classes": data_classes,
                "is_verified": is_verified,
                "severity_score": severity_from_data_classes(data_classes, is_verified),
            }
        )
    return events


def remove_email_from_mock_breach_db(email: str) -> dict[str, Any]:
    db_path = Path(settings.mock_breach_db_path)
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parents[2] / settings.mock_breach_db_path

    if not db_path.exists():
        return {"ok": False, "deleted": False, "deleted_events": 0, "message": "Mock breach database file not found"}

    raw_catalog = json.loads(db_path.read_text(encoding="utf-8"))
    if not isinstance(raw_catalog, dict):
        raw_catalog = {"emails": {}}

    emails = raw_catalog.get("emails")
    if not isinstance(emails, dict):
        emails = {}
        raw_catalog["emails"] = emails

    key = email.strip().lower()
    existing = emails.get(key, [])
    deleted_events = len(existing) if isinstance(existing, list) else 0
    deleted = key in emails
    if deleted:
        del emails[key]
        db_path.write_text(json.dumps(raw_catalog, indent=2), encoding="utf-8")
        return {
            "ok": True,
            "deleted": True,
            "deleted_events": deleted_events,
            "message": f"Removed {key} from mock breach dataset",
        }

    return {
        "ok": True,
        "deleted": False,
        "deleted_events": 0,
        "message": f"{key} not found in mock breach dataset",
    }


async def _generate_breach_events_with_openai(email: str) -> list[dict[str, Any]]:
    prompt = (
        "You generate synthetic breach intelligence for security demos. "
        "Return ONLY JSON with this shape: "
        '{"events":[{"breach_name":"string","breach_date":"YYYY-MM-DD or empty","data_classes":["Email addresses"],"is_verified":true}]}. '
        "No markdown, no explanation. "
        f"Input email: {email}"
    )

    payload = {
        "model": settings.openai_model,
        "messages": [
            {"role": "system", "content": "You are a strict JSON API."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "breach_events",
                "schema": {
                    "type": "object",
                    "properties": {
                        "events": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "breach_name": {"type": "string"},
                                    "breach_date": {"type": "string"},
                                    "data_classes": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                    "is_verified": {"type": "boolean"},
                                },
                                "required": ["breach_name", "breach_date", "data_classes", "is_verified"],
                                "additionalProperties": False,
                            },
                        }
                    },
                    "required": ["events"],
                    "additionalProperties": False,
                },
            },
        },
    }

    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.post(f"{settings.openai_base_url}/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        raw = response.json()
    except Exception:
        return []

    content = _extract_openai_content(raw)
    if not content:
        return []

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return []

    events_raw = parsed.get("events", []) if isinstance(parsed, dict) else []
    if not isinstance(events_raw, list):
        return []

    events: list[dict[str, Any]] = []
    for item in events_raw:
        if not isinstance(item, dict):
            continue
        data_classes = item.get("data_classes", [])
        if not isinstance(data_classes, list):
            data_classes = ["Email addresses"]
        is_verified = bool(item.get("is_verified", True))
        events.append(
            {
                "breach_name": str(item.get("breach_name", "SyntheticBreach")),
                "breach_date": str(item.get("breach_date", "")),
                "data_classes": [str(x) for x in data_classes],
                "is_verified": is_verified,
                "severity_score": severity_from_data_classes([str(x) for x in data_classes], is_verified),
            }
        )

    return events


def _extract_openai_content(raw: dict[str, Any]) -> str:
    choices = raw.get("choices", []) if isinstance(raw, dict) else []
    if not choices:
        return ""

    message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text", "")))
        joined = "\n".join(text_parts).strip()
        if joined:
            return joined

    fallback_text = json.dumps(message)
    match = re.search(r"\{[\s\S]*\}", fallback_text)
    return match.group(0) if match else ""
