import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = ROOT / "backend"
if str(BACKEND_APP) not in sys.path:
    sys.path.append(str(BACKEND_APP))

from app.services.pii import detect_pii  # noqa: E402


def _safe_div(num: float, den: float) -> float:
    return round((num / den) if den else 0.0, 4)


def main() -> None:
    dataset_path = ROOT / "evaluation" / "redaction_test_data.json"
    out_path = ROOT / "evaluation" / "benchmark_results.json"

    cases = json.loads(dataset_path.read_text(encoding="utf-8"))

    tp = 0
    fp = 0
    fn = 0
    by_case = []

    for case in cases:
        expected = set(case["expected"])
        detected = {item.entity_type for item in detect_pii(case["text"])}

        case_tp = len(expected & detected)
        case_fp = len(detected - expected)
        case_fn = len(expected - detected)

        tp += case_tp
        fp += case_fp
        fn += case_fn

        by_case.append(
            {
                "id": case["id"],
                "expected": sorted(expected),
                "detected": sorted(detected),
                "tp": case_tp,
                "fp": case_fp,
                "fn": case_fn,
            }
        )

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    result = {
        "total_cases": len(cases),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "by_case": by_case,
    }

    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
