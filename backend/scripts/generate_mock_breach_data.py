import argparse
import json
import random
import time
from datetime import date
from pathlib import Path


BREACH_NAMES = [
    "Adobe2013",
    "LinkedIn2021",
    "Collection1",
    "Canva2019",
    "Dropbox2012",
    "Apollo2021",
    "MyFitnessPal2018",
    "Evite2019",
    "Tumblr2013",
    "Dubsmash2018",
]

DATA_CLASS_PROFILES = [
    ["Email addresses"],
    ["Email addresses", "Passwords"],
    ["Email addresses", "Phone numbers"],
    ["Email addresses", "Passwords", "Usernames"],
    ["Email addresses", "IP addresses"],
]

DOMAIN_POOL = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "proton.me",
    "company.com",
    "corp.com",
]

NAME_POOL = [
    "john.doe",
    "alice.m",
    "rohit.k",
    "nina.s",
    "dev.user",
    "ops.alert",
    "finance.bot",
    "test.mail",
    "demo.user",
]


def _load_catalog(path: Path) -> dict:
    if not path.exists():
        return {"emails": {}}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {"emails": {}}
    emails = raw.get("emails")
    if not isinstance(emails, dict):
        raw["emails"] = {}
    return raw


def _pick_email(emails: dict[str, list], chance_existing: float) -> str:
    existing_keys = list(emails.keys())
    if existing_keys and random.random() < chance_existing:
        return random.choice(existing_keys)
    return f"{random.choice(NAME_POOL)}{random.randint(1, 999)}@{random.choice(DOMAIN_POOL)}".lower()


def _new_event() -> dict:
    return {
        "breach_name": random.choice(BREACH_NAMES),
        "breach_date": date.today().isoformat(),
        "data_classes": random.choice(DATA_CLASS_PROFILES),
        "is_verified": random.random() < 0.85,
    }


def _append_event(catalog: dict, chance_existing: float) -> tuple[str, dict]:
    emails = catalog.setdefault("emails", {})
    email = _pick_email(emails, chance_existing)
    emails.setdefault(email, [])
    event = _new_event()
    emails[email].append(event)
    return email, event


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Continuously generate random mock breach events in the existing JSON schema."
    )
    parser.add_argument(
        "--file",
        default=str(Path(__file__).resolve().parents[1] / "app" / "data" / "mock_breach_db.json"),
        help="Path to mock_breach_db.json",
    )
    parser.add_argument("--interval", type=int, default=10, help="Seconds between generated events")
    parser.add_argument(
        "--existing-chance",
        type=float,
        default=0.75,
        help="Chance [0..1] to append to an existing email instead of creating a new one",
    )
    args = parser.parse_args()

    out_path = Path(args.file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating mock breach events every {args.interval}s -> {out_path}")
    while True:
        catalog = _load_catalog(out_path)
        email, event = _append_event(catalog, args.existing_chance)
        out_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
        print(f"[{time.strftime('%H:%M:%S')}] added event for {email}: {event['breach_name']}")
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    main()
