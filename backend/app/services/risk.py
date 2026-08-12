from math import log2

from app.services.pii import SENSITIVITY_WEIGHTS, PIIMatch


def calculate_risk(matches: list[PIIMatch], breach_count: int = 0, verified_breaches: int = 0) -> dict[str, float | str]:
    if not matches and breach_count == 0:
        return {
            "pii_score": 0.0,
            "sensitivity_score": 0.0,
            "breach_score": 0.0,
            "final_score": 0.0,
            "level": "Low",
        }

    pii_score = min(100.0, len(matches) * 8.0)

    weighted_sum = 0.0
    max_possible = max(1, len(matches) * 10)
    for item in matches:
        weight = SENSITIVITY_WEIGHTS.get(item.entity_type, 2)
        weighted_sum += weight * item.confidence
    sensitivity_score = min(100.0, (weighted_sum / max_possible) * 100)

    breach_score = min(100.0, 20.0 * log2(1 + breach_count) + 0.6 * (verified_breaches * 10))

    final_score = round((0.45 * pii_score) + (0.30 * sensitivity_score) + (0.25 * breach_score), 2)
    level = classify_level(final_score)

    return {
        "pii_score": round(pii_score, 2),
        "sensitivity_score": round(sensitivity_score, 2),
        "breach_score": round(breach_score, 2),
        "final_score": final_score,
        "level": level,
    }


def classify_level(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"
