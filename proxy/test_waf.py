import json
import unittest
from types import SimpleNamespace

from evaluate_waf import CASES_FILE
from waf import is_malicious


class WafQueryTests(unittest.TestCase):
    def test_labeled_queries_match_expected_decisions(self):
        cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(query=case["name"]):
                request = SimpleNamespace(
                    url=SimpleNamespace(query=case["query"]),
                    client=SimpleNamespace(host="test", port=0),
                )
                actual = is_malicious(case["body"].encode("utf-8"), request)
                self.assertEqual(actual, case["malicious"])


if __name__ == "__main__":
    unittest.main()