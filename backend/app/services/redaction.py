from app.services.pii import PIIMatch


def redact_with_mask(text: str, matches: list[PIIMatch]) -> str:
    if not matches:
        return text
    chunks = []
    last_idx = 0
    for match in matches:
        chunks.append(text[last_idx:match.start])
        chunks.append(mask_value(match.value, match.entity_type))
        last_idx = match.end
    chunks.append(text[last_idx:])
    return "".join(chunks)


def mask_value(value: str, entity_type: str | None = None) -> str:
    if entity_type:
        return f"[REDACTED_PII_{entity_type.lower()}]"
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
