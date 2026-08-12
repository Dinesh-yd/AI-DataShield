# Redaction Accuracy Report

## Benchmark Setup
1. Dataset: `evaluation/redaction_test_data.json`
2. Evaluator: `backend/scripts/evaluate_redaction.py`
3. Metric basis: entity-type detection (`TP/FP/FN`), then precision/recall/F1.

## Results
- Total test cases: `6`
- True positives: `10`
- False positives: `0`
- False negatives: `0`
- Precision: `1.00`
- Recall: `1.00`
- F1 score: `1.00`

Reference output: `evaluation/benchmark_results.json`.

## Coverage Notes
Covered entity categories:
1. Email
2. Phone (including local 7-digit `XXX-XXXX` pattern)
3. SSN
4. PAN
5. Credit card
6. IP address
7. Address

## Limitations
1. Current benchmark size is small and synthetic.
2. Real-world noisy text/OCR errors can reduce scores.
3. Address patterns are rule-based and may vary by region/language.

## Next Benchmark Improvements
1. Expand dataset to 500+ mixed-domain samples.
2. Add adversarial and ambiguous examples.
3. Add per-entity confusion matrix and confidence calibration checks.
