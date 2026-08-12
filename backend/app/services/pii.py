import re
from dataclasses import dataclass


@dataclass
class PIIMatch:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float


PII_PATTERNS: dict[str, tuple[str, float]] = {
    "EMAIL": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.99),
    "PHONE": (
        r"(?<!\w)(?:(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}|\d{3}[\s.-]\d{4})\b",
        0.95,
    ),
    "SSN": (r"\b\d{3}-\d{2}-\d{4}\b", 0.99),
    "AADHAAR": (r"\b[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}\b", 0.97),
    "PAN": (r"\b[A-Z]{5}\d{4}[A-Z]\b", 0.96),
    "CREDIT_CARD": (r"\b(?:\d[ -]*?){13,16}\b", 0.93),
    "IP_ADDRESS": (r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b", 0.94),
    "ADDRESS": (r"\b\d{1,5}\s+[A-Za-z][A-Za-z0-9.\-]*(?:\s+[A-Za-z0-9.\-]+){0,4}\s(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd|Drive|Dr|Way|Court|Ct)\b", 0.76),
}

ENTITY_PRIORITY = {
    "SSN": 100,
    "CREDIT_CARD": 95,
    "AADHAAR": 90,
    "PAN": 85,
    "EMAIL": 80,
    "PHONE": 75,
    "IP_ADDRESS": 70,
    "ADDRESS": 65,
}

SENSITIVITY_WEIGHTS = {
    "EMAIL": 2,
    "PHONE": 3,
    "SSN": 10,
    "PAN": 6,
    "AADHAAR": 8,
    "CREDIT_CARD": 10,
    "IP_ADDRESS": 4,
    "ADDRESS": 5,
}


def detect_pii(text: str) -> list[PIIMatch]:
    matches: list[PIIMatch] = []
    for entity_type, (pattern, conf) in PII_PATTERNS.items():
        for found in re.finditer(pattern, text):
            matches.append(
                PIIMatch(
                    entity_type=entity_type,
                    value=found.group(0),
                    start=found.start(),
                    end=found.end(),
                    confidence=conf,
                )
            )

    matches.sort(
        key=lambda item: (
            item.start,
            -ENTITY_PRIORITY.get(item.entity_type, 0),
            -(item.end - item.start),
        )
    )

    filtered: list[PIIMatch] = []
    last_end = -1
    for item in matches:
        if item.start < last_end:
            continue
        filtered.append(item)
        last_end = item.end

    return filtered


def pii_token_label(entity_type: str) -> str:
    return entity_type.lower()
