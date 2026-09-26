## WAF test queries and comparison

The labeled request corpus is in `proxy/test_queries.json`. It includes benign
terms that overlap with rule keywords, encoded SQL-injection examples, Unicode
normalization, and a form-body request. The `malicious` value is the expected
label; edit or extend these cases as the rules change.

Run the behavior tests and print the comparison report from the repository root:

```sh
python3 -m unittest discover -s proxy -p 'test_*.py' -v
python3 proxy/evaluate_waf.py
```

The report compares threshold configurations 2, 4, and 6 using the same current
normalization and scoring rules. It reports true/false positives and negatives,
precision, recall, and each query's score at the configured threshold. This is
a threshold comparison, not a comparison of separate WAF algorithms; only one
filter implementation currently exists in this project.
