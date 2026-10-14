# Vulnerable SQLi Demo

A deliberately insecure local Node.js/Express/SQLite application for coursework involving SQL-injection filtering/firewall/WAF experiments.

## Important

This application is **intentionally vulnerable**. It binds only to `127.0.0.1` by default. Do not expose it to the Internet or use it with real credentials/data.

## Features

- Create account
- Log in / log out
- Search users
- Add friends
- View friends
- Local SQLite database (`app.db`)
- Deliberate SQL injection vulnerabilities in:
  - account creation
  - login
  - user search

The project uses the `sqlite3` npm package, **not** `better-sqlite3`.

## Run

```bash
npm install
npm start
```

Then open:

```text
http://127.0.0.1:3000
```

The database file is created automatically on first run.

## Reset database

Stop the server and delete:

```bash
rm app.db
```

Then run `npm start` again.

## Demo accounts

- `alice` / `alice123`
- `bob` / `bob123`
- `charlie` / `charlie123`

## Where the deliberate vulnerabilities are

See `server.js` and search for:

```text
INTENTIONALLY VULNERABLE TO SQL INJECTION
```

The vulnerable routes construct SQL statements by directly concatenating user-controlled strings. The friend-related routes use parameterized queries so the project has a simple contrast between unsafe and safer SQL handling.

## SQL Injection Examples

This project is intentionally vulnerable to SQL injection for educational purposes.

### 1. Login bypass

Enter the following in the username field:

```text
' OR '1'='1' --
```

The password field can contain any value.

This modifies the login query so that the condition becomes true and the password check is commented out, allowing authentication without knowing a valid password.

Example vulnerable query:

```sql
SELECT * FROM users
WHERE username = '' OR '1'='1' -- '
AND password = 'anything'
```

### 2. Display passwords through user search

Enter the following in the user search field:

```text
' UNION SELECT id, password FROM users --
```

This uses `UNION SELECT` to append the `password` column from the `users` table to the normal search results.

Because the search page displays the second selected column as if it were a username, the stored passwords are shown in the results.

Example output:

```text
alice123
bob123
charlie123
```

This demonstrates how SQL injection can expose sensitive database information when user input is inserted directly into SQL queries.


# Docker setup

The vulnerable Express.js/SQLite application has been containerized with Docker.

The application is intentionally vulnerable to SQL injection for educational testing. The Node.js target currently runs on port 3000.

Run the application with the following commands:

Build the Docker image:

```
docker compose build
```

Start the application:

```
docker compose up
```

Or build and start in one command:

```
docker compose up --build
```

Then open:

http://localhost:3000

Stop the application with:

```
docker compose down
```

Current Docker structure

The node_target service runs the vulnerable Express application inside Docker.

During the baseline demonstration, port 3000 is exposed to the host so the SQL injection vulnerability can be tested directly.

In the final setup, the Node target will only be accessible internally through Docker, while the FastAPI proxy/WAF will be exposed on port 80.

The WAF is an additional defense layer and is not a replacement for secure SQL queries such as parameterized queries.

# Running SQLmap Tests

## 1. Run the test

From the project root, navigate to the SQLmap directory:

```bash
cd sql-map
```

Run the test script:

```bash
./run_sqlmap.sh
```

The script starts the vulnerable application and WAF in the foreground, builds and runs the SQLmap container, and prints a summary of the HTTP status codes observed during testing.

## 2. View the results

The results are saved in:

```text
sql-map/sqlmap-results/
```

The traffic log is available at:

```text
sql-map/sqlmap-results/waf.log
```

The script prints counts for:

- **403** — Forbidden.
- **401** — Unauthorized.
- **400** — Bad Request.
- **200** — OK.


## Individual Contributions:

**Author:** Alberto Calcara 

## Responsibility
As part of our collaborative group project implementing a secure "defense-in-depth" architecture, my primary focus was designing, building, and deploying the gateway layer that protects our intentionally vulnerable Node.js/Express backend. Specifically, I was responsible for developing the asynchronous FastAPI reverse proxy (`rev-proxy.py`).

### Asynchronous FastAPI Reverse Proxy 
* **Catch-All Routing:** I implemented a FastAPI endpoint using a wildcard (`/{path:path}`) coupled with support for all standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`). This ensures that any incoming web traffic targeting the application is intercepted by the proxy layer.
* **WAF Inspection Hook:** I integrated the security inspection by invoking the `is_malicious()` function prior to forwarding any payload. If a request is flagged as an attempted SQL injection, the proxy immediately halts execution and returns an HTTP `403 Forbidden` status code.
* **Header Sanitization:** To prevent routing errors and protocol mismatches, I iterated through incoming request headers and explicitly stripped hop-by-hop headers such as `host` and `connection`. This ensures that internal backend communication remains correct.
* **Payload & Query Parameter Forwarding:** I captured the raw request bodies asynchronously and preserved exact query strings (`request.url.query`), ensuring that complex search queries and form submissions reach the backend unaltered.
* **High-Performance Stream Forwarding:** Using Python's `httpx` async client combined with Starlette's `StreamingResponse` and `aiter_raw()`, I ensured that responses from the Node.js backend are streamed back to the client efficiently with minimal overhead and no data corruption.

## Sources 
* **FastAPI & Starlette Documentation:** Consulted for request routing techniques, path converters (`{path:path}`), dependency patterns, and streaming response handling.
* **Python `httpx` Documentation:** Referenced for building async HTTP client requests, handling client connection pooling, and forwarding raw content.
* **Docker Guide:** secure port mapping configurations.
**Morzeux, HttpParamsDataset** I added 92 test queries to the existing 8 in the json file test_queries.json too, here is the main source for them: https://github.com/Morzeux/HttpParamsDataset/. 

## Filter logic 
**Author:** Sonja Shkembi

My task was the development of the blocking filter for malicious inputs. Throughout the development of the detection algorithm, I tried to improve the logic such that we would get the best tradeoff between false positives and false negatives.

First version started with a simple check if the input contained any SQL words (select, delete, update, or). But this obviously caused a lot of false positives.

The second version included a scoring system. 
```
{
  "name": "SELECT",
  "value": "select",
  "score": 2
  }
```
A request was blocked only if the triggered rules were giving an overall score above a certain threshold.

The final version includes a better structure of rules divided in types. 
 ```
{
  "name": "SELECT",
  "type": "word",
  "value": "select",
  "score": 1
  }
```
Multi-word SQL words like SELECT...FROM, UNION...SELECT are detected as keyword patterns and SQL comments and words are handled separately. Word boundaries (\b) are also used so that a rule for select matches the actual word but does not match normal words such as selection or selected. 
The rules were generated by AI, but scores were set by us after deciding on some tradeoffs. 
The inital run of sqlmap reported all parameters as injectable but after adding more rules, the WAF blocked a larger proportion of the malicious requests. For the search parameter there are some inputs which pass through the waf. Most of these requests return an empty result set (HTTP 200 []), indicating that they were not blocked but demonstrate that they were not a successful exploitation.
These findings conclude that unfortunately a signature-based WAF alone is not enough against all SQL injections attacks, therefore parammetrized queries should be the foundation of the application's defense, with WAF as an additional layer of security.

### Main functions of the blocking filter

- **is_malicious()** – The main function that takes the request body and query parameters and gives the final verdict after calling `inspect_text()`. If the score reaches the blocking threshold, the request is classified as malicious. We decided on a threshold of 4 since 5 was considering many malicious cases as valid.
- **normalize_request()** – Normalizes the input by decoding URL-encoded characters, lowercasing, and removing extra whitespace. This makes it easier to detect patterns. Double encoded input was not considered.
- **rule_matches()** – Checks whether the input matches a specific rule based on its type (`word`, `keywords`, or `regex`).
- **inspect_text()** – Goes through all the rules, calculates the total score of the triggered rules, and keeps track of which rules were triggered. It also handles SQL comments separately before calling `rule_matches()`.
- **log_blocking_request()** – Just a simple logging mechanism for blocked requests, including the client's host and port, the score, and the triggered rules.

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf)
- [Anomaly Scoring](https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/)
- [Python re documentation](https://docs.python.org/3/library/re.html)

## WAF testing and evaluation
**Author:** Alexander Pereira Engström

### Responsibility
My contribution was to build a repeatable way to test the WAF and evaluate how changing its blocking threshold affects detection. I created the initial eight labeled queries, added an automated behavior test, and wrote a report script to compare threshold settings.

### Test Queries and Evaluation
* **Labeled test cases:** I created the original eight benign and malicious examples in `proxy/test_queries.json`. Alberto later added 92 cases from the Morzeux HttpParamsDataset, bringing the corpus to 100 cases: 50 labeled benign and 50 labeled as SQL injection.
* **Automated behavior test:** `proxy/test_waf.py` runs each labeled request through the WAF and compares its decision with the expected label.
* **Threshold report:** `proxy/evaluate_waf.py` compares thresholds 2, 5, and 6. It reports true positives, false positives, true negatives, false negatives, precision, recall, and the result for each query.
* **Current findings:** At thresholds 2 and 5, the WAF blocks 45 of the 50 malicious-labeled requests and allows all 50 benign requests. This means five malicious-labeled cases are missed. At threshold 6, 32 malicious cases are blocked and 18 are missed, with no benign cases blocked. These results describe this corpus only and are not a guarantee of real-world performance.
* **Configuration:** I aligned the threshold key in `proxy/waf_rules.json` with the key read by the filter, so the configured threshold is applied.

### Sources
* **Python `unittest` documentation:** https://docs.python.org/3/library/unittest.html
* **OWASP Web Security Testing Guide, Testing for SQL Injection:** https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/ (guidance on testing web applications for SQL injection)
* **Morzeux, HttpParamsDataset:** https://github.com/Morzeux/HttpParamsDataset/ (source for the 92 additional cases added by Alberto)

