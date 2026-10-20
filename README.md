# Vulnerable SQLi Demo

A deliberately insecure local Node.js/Express/SQLite application for coursework involving SQL-injection filtering/firewall/WAF experiments.

## Important

This application is **intentionally vulnerable**.

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


The WAF is an additional defense layer and is not a replacement for secure SQL queries such as parameterized queries.


## Running the Project

### Requirements
Before running the project, make sure the following are installed:
- Docker and Docker Compose
- Git
- Python 3 (for running the WAF evaluation scripts)

### 1. Clone the Repository

```bash
git clone https://github.com/joelmedhane/group20-project-dd2391.git
cd group20-project-dd2391
```

### 2. Build and Start the Application

Run the following command from the project root:

```bash
docker compose up -d --build node_target fastapi_proxy
```

This builds and starts two services:
- `node_target`: The intentionally vulnerable Node.js/Express application running internally on port 3000.
- `fastapi_proxy`: The FastAPI reverse proxy and WAF, exposed on localhost port 8080.

Open the application in your browser:

http://localhost:8080

All incoming requests pass through the WAF before reaching the vulnerable backend.

### 3. Test the Application

Demo accounts:

- `alice` / `alice123`
- `bob` / `bob123`
- `charlie` / `charlie123`

You can use the application to test normal functionality such as logging in, searching for users, and adding friends.

The WAF inspects incoming requests and returns HTTP 403 Forbidden when the request reaches its configured blocking threshold.

### 4. Run Automated SQLmap Tests

From the project root:

```bash
cd sql-map
bash run_sqlmap.sh
```

The script starts the required containers and executes SQLmap against the login and authenticated user search endpoints through the WAF.

Test results are stored in:

- `sql-map/sqlmap-results/waf.log`
- `sql-map/sqlmap-results/waf-search.log`

The script prints a summary of HTTP response codes to the terminal.

### 5. Run WAF Evaluation Tests

From the repository root:

```bash
python3 proxy/test_waf.py
python3 proxy/evaluate_waf.py
```

These tests evaluate the WAF against labeled benign and malicious requests and compare different blocking thresholds.

### 6. Stop the Application

From the repository root:

```bash
docker compose down
```

The backend is intentionally vulnerable and should only be used in a controlled testing environment.


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

## Initial Web Application, Docker Setup and SQLmap Testing
**Author:** Joel Medhane

## Responsibility
My main contribution was setting up the initial vulnerable web application and Docker environment, manually verifying SQL injection vulnerabilities, and developing an automated testing process using SQLmap. My focus was establishing a working environment for demonstrating SQL injection attacks and evaluating the effectiveness of our WAF.

### Initial Web Application
* **Web Application:** I used generative AI to create the initial web application, providing a user interface for registration, login, user search, and friend management. This served as the starting point for our SQL injection testing environment.

### Initial Docker Setup
* **Containerization:** I created the initial `Dockerfile` and `docker-compose.yml` configuration to run the vulnerable application inside a Docker container, providing a reproducible environment for local testing.
* **Baseline Testing Environment:** I initially configured Docker Compose to expose the vulnerable application directly to the host, allowing us to interact with the backend without an intermediary security layer. When the reverse proxy was later introduced, the direct port mapping was removed to prevent requests from bypassing the WAF.
* **Manual SQL Injection Verification:** After setting up Docker, we verified the vulnerabilities through the webpage. Using `' OR '1'='1' --`, we demonstrated authentication bypass by modifying the SQL `WHERE` condition and commenting out the password check. We also used `' UNION SELECT id, password FROM users --` to extract stored passwords through the user search functionality. These tests established a baseline for evaluating the WAF.

### Automated SQLmap Testing
* **SQLmap Automation:** I developed the Bash script `run_sqlmap.sh` to automate SQL injection testing against the WAF. The script uses `--batch` for non-interactive execution, `--level 3` for more extensive testing, and `--flush-session` to avoid reusing results from previous scans.
* **Login Endpoint Testing:** I configured SQLmap to test `/api/login` using JSON-formatted POST requests. The `--data` argument specifies the request body, while `-p username,password` explicitly selects both parameters for injection testing. The `--ignore-code 401` option handles expected authentication failures during the tests.
* **Authenticated Search Testing:** Since `/api/users/search` requires authentication, I implemented a login step using `curl` to obtain the `connect.sid` session cookie. The cookie is extracted from the saved cookie file and passed to SQLmap using `--cookie`, allowing it to test the search parameter `q` within an authenticated session.
* **Docker Integration:** The script starts the backend and FastAPI proxy using `docker compose up -d --build`, then executes SQLmap in a separate container using `docker compose run --build --rm sqlmap`. Requests are directed to `http://fastapi_proxy:8000` over the Docker network, ensuring that the attacks pass through the WAF instead of reaching the vulnerable backend directly.
* **Traffic Logging and Analysis:** I used SQLmap's `-t` option to capture HTTP request and response traffic in `waf.log` and `waf-search.log`. The script uses `grep` to summarize HTTP response codes: `403` (Forbidden), `401` (Unauthorized), `400` (Bad Request), and `200` (OK). This provided a repeatable method for observing the WAF's behavior against automated injection attempts. However, an HTTP 200 response does not necessarily indicate successful SQL injection, since requests may reach the backend without successfully exploiting the vulnerability.

### Sources
* **SQLmap Documentation:** https://github.com/sqlmapproject/sqlmap/wiki/Usage (SQL injection testing, command-line parameters, authentication handling, and HTTP traffic logging)
* **Docker Documentation:** https://docs.docker.com/ (Dockerfile configuration, Docker Compose, container networking, and port mapping)
