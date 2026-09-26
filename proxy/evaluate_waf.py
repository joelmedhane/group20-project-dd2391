import json
from pathlib import Path

from waf import BLOCKING_REQUESTS_THRESHOLD, inspect_text, normalize_request


CASES_FILE = Path(__file__).with_name("test_queries.json")
THRESHOLDS = sorted({2, BLOCKING_REQUESTS_THRESHOLD, 6})


def score_case(case):
    text = normalize_request(case["body"]) + " " + normalize_request(case["query"])
    return inspect_text(text)[0]


def confusion_counts(cases, threshold):
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for case in cases:
        expected = case["malicious"]
        blocked = score_case(case) >= threshold
        result = "TP" if expected and blocked else "FN" if expected else "FP" if blocked else "TN"
        counts[result] += 1
    return counts


def main():
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    print("WAF threshold comparison")
    print("threshold  TP  FP  TN  FN  precision  recall")
    for threshold in THRESHOLDS:
        counts = confusion_counts(cases, threshold)
        precision_denominator = counts["TP"] + counts["FP"]
        recall_denominator = counts["TP"] + counts["FN"]
        precision = counts["TP"] / precision_denominator if precision_denominator else 0
        recall = counts["TP"] / recall_denominator if recall_denominator else 0
        print(
            f"{threshold:9}  {counts['TP']:2}  {counts['FP']:2}  "
            f"{counts['TN']:2}  {counts['FN']:2}  {precision:9.0%}  {recall:6.0%}"
        )

    print(f"\nPer-query results at configured threshold ({BLOCKING_REQUESTS_THRESHOLD}):")
    for case in cases:
        score = score_case(case)
        blocked = score >= BLOCKING_REQUESTS_THRESHOLD
        outcome = "BLOCK" if blocked else "ALLOW"
        expected = "malicious" if case["malicious"] else "benign"
        print(f"{outcome:5} score={score:2} expected={expected:8} {case['name']}")


if __name__ == "__main__":
    main()