from collections import defaultdict


def recommend_actions(
    pii_types: list[str],
    breach_data_classes: list[str],
    breach_count: int,
) -> list[dict[str, str | list[str]]]:
    recommendations: list[dict[str, str | list[str]]] = []

    if breach_count <= 0 and not breach_data_classes:
        return [
            {
                "priority": "Medium",
                "title": "Baseline Security Hygiene",
                "reason": "No breach exposure found for this account in the current check.",
                "actions": [
                    "Change your password once every month.",
                    "Keep MFA enabled on all critical accounts.",
                    "Avoid reusing passwords across services.",
                ],
                "eta": "Ongoing",
            }
        ]

    pii_set = {item.upper() for item in pii_types}
    class_set = set(breach_data_classes)

    if "SSN" in pii_set or "AADHAAR" in pii_set:
        recommendations.append(
            {
                "priority": "Critical",
                "title": "Identity Fraud Protection",
                "reason": "Government-issued identifiers were detected.",
                "actions": [
                    "Place fraud alert or credit freeze with bureaus.",
                    "Enable transaction and account-opening notifications.",
                    "Use identity-theft monitoring for 90 days.",
                ],
                "eta": "Within 24 hours",
            }
        )

    if "CREDIT_CARD" in pii_set or "Credit cards" in class_set:
        recommendations.append(
            {
                "priority": "Critical",
                "title": "Card Exposure Containment",
                "reason": "Payment card data may be exposed.",
                "actions": [
                    "Block and reissue exposed cards.",
                    "Enable spend alerts and merchant controls.",
                    "Review transactions from the last 30 days.",
                ],
                "eta": "Immediately",
            }
        )

    if "Passwords" in class_set:
        recommendations.append(
            {
                "priority": "High",
                "title": "Credential Rotation",
                "reason": "Password-class data appears in breach records.",
                "actions": [
                    "Reset passwords for affected accounts.",
                    "Rotate reused credentials across services.",
                    "Enforce unique password policy.",
                ],
                "eta": "Within 12 hours",
            }
        )

    if "EMAIL" in pii_set or "PHONE" in pii_set or "Email addresses" in class_set or "Phone numbers" in class_set:
        recommendations.append(
            {
                "priority": "High",
                "title": "Account Hardening",
                "reason": "Contact identifiers are exposed and prone to phishing/SIM-swap attempts.",
                "actions": [
                    "Enable MFA on all critical accounts.",
                    "Add SIM lock / port-out PIN with telecom provider.",
                    "Turn on sign-in anomaly alerts.",
                ],
                "eta": "Within 24 hours",
            }
        )

    if "PAN" in pii_set:
        recommendations.append(
            {
                "priority": "High",
                "title": "Tax Identifier Safeguards",
                "reason": "PAN-like tax identifier detected in shared content.",
                "actions": [
                    "Remove PAN from shared/public artifacts.",
                    "Mask PAN in logs and exports.",
                    "Review access to tax-related records.",
                ],
                "eta": "Within 24 hours",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "priority": "Medium",
                "title": "Baseline Privacy Hygiene",
                "reason": "No severe exposure signals found, but preventive controls are recommended.",
                "actions": [
                    "Keep MFA enabled.",
                    "Continue periodic breach checks.",
                    "Avoid sharing raw identifiers in prompts/documents.",
                ],
                "eta": "Within 7 days",
            }
        )

    if breach_count >= 3:
        recommendations.append(
            {
                "priority": "High",
                "title": "Incident Response Escalation",
                "reason": "Multiple breach events were detected for the same identity.",
                "actions": [
                    "Trigger incident response workflow.",
                    "Review endpoint logs for credential abuse.",
                    "Notify stakeholders and track mitigation closure.",
                ],
                "eta": "Today",
            }
        )

    priority_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recommendations.sort(key=lambda item: priority_rank.get(str(item["priority"]), 4))
    return recommendations


def aggregate_breach_data_classes(raw_data_classes: list[str]) -> list[str]:
    counts = defaultdict(int)
    for item in raw_data_classes:
        counts[item] += 1
    return sorted(counts.keys(), key=lambda item: (-counts[item], item))


def proactive_controls(
    pii_types: list[str],
    breach_data_classes: list[str],
    breach_count: int,
) -> list[dict[str, str]]:
    pii_set = {item.upper() for item in pii_types}
    class_set = set(breach_data_classes)
    controls: list[dict[str, str]] = []

    controls.append(
        {
            "control": "Mandatory MFA",
            "status": "Required",
            "why": "Baseline account protection against credential stuffing and phishing.",
        }
    )
    controls.append(
        {
            "control": "Password Reuse Block",
            "status": "Required" if breach_count > 0 or "Passwords" in class_set else "Recommended",
            "why": "Prevents reuse of credentials exposed in breach data.",
        }
    )

    if "EMAIL" in pii_set or "PHONE" in pii_set or "Email addresses" in class_set or "Phone numbers" in class_set:
        controls.append(
            {
                "control": "High-Risk Login Alerts",
                "status": "Required",
                "why": "Promptly detects suspicious sign-in attempts on exposed contact identifiers.",
            }
        )
        controls.append(
            {
                "control": "SIM Swap Defense",
                "status": "Recommended",
                "why": "Reduces account takeover risk via telecom number hijacking.",
            }
        )

    if "SSN" in pii_set or "AADHAAR" in pii_set or "PAN" in pii_set:
        controls.append(
            {
                "control": "Identity Verification Step-Up",
                "status": "Required",
                "why": "Adds stronger checks for profile/account changes when national IDs are exposed.",
            }
        )

    if "CREDIT_CARD" in pii_set or "Credit cards" in class_set:
        controls.append(
            {
                "control": "Payment Instrument Rotation",
                "status": "Required",
                "why": "Forces replacement of potentially exposed payment cards.",
            }
        )

    return controls
