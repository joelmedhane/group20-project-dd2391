#!/usr/bin/env bash
# Runs SQLmap against the WAF: login and authenticated search.

set -e

OUT="sqlmap-results"
URL="http://host.docker.internal:8080"
LOGIN_URL="$URL/api/login"
SEARCH_URL="$URL/api/users/search?q=test"

mkdir -p "$OUT"

echo "Starting containers..."
docker compose -f ../docker-compose.yml up -d --build node_target fastapi_proxy

# 1. Test login
echo
echo "1. Testing login with SQLmap"

docker compose -f ../docker-compose.yml run --build --rm sqlmap \
  -u "$LOGIN_URL" \
  --data='{"username":"","password":""}' \
  -H "Content-Type: application/json" \
  -p username,password \
  --ignore-code 401 \
  --batch --level 3 --flush-session \
  --output-dir=/results -t /results/waf.log

# 2. Log in and save the session cookie
echo
echo "2. Logging in as Alice"

curl -sS \
  -c "$OUT/cookies.txt" \
  -o "$OUT/login-response.txt" \
  -H "Content-Type: application/json" \
  --data '{"username":"alice","password":"alice123"}' \
  http://localhost:8080/api/login

COOKIE=$(awk '/^#HttpOnly_/ {sub(/^#HttpOnly_/, ""); print $6 "=" $7}' "$OUT/cookies.txt")
rm -f "$OUT/cookies.txt"

if [ -z "$COOKIE" ]; then
  echo "ERROR: No session cookie found."
  cat "$OUT/login-response.txt"
  exit 1
fi

# 3. Test authenticated search
echo
echo "3. Testing search with SQLmap"

docker compose -f ../docker-compose.yml run --build --rm sqlmap \
  -u "$SEARCH_URL" \
  --cookie="$COOKIE" \
  -p q \
  --batch --level 3 --flush-session \
  --output-dir=/results -t /results/waf-search.log


STATUS_REGEX='\([0-9]{3} [^)]*\)'

echo
echo "Results for $OUT/waf.log"
echo "Blocked (403):      $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '403' || true)"
echo "Unauthorized (401): $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '401' || true)"
echo "Bad Request (400):  $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '400' || true)"
echo "OK (200):           $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '200' || true)"

echo
echo "Results for $OUT/waf-search.log"
echo "Blocked (403):      $(grep -oE "$STATUS_REGEX" "$OUT/waf-search.log" | grep -c '403' || true)"
echo "Unauthorized (401): $(grep -oE "$STATUS_REGEX" "$OUT/waf-search.log" | grep -c '401' || true)"
echo "Bad Request (400):  $(grep -oE "$STATUS_REGEX" "$OUT/waf-search.log" | grep -c '400' || true)"
echo "OK (200):           $(grep -oE "$STATUS_REGEX" "$OUT/waf-search.log" | grep -c '200' || true)"

echo
echo "Login log:  $OUT/waf.log"
echo "Search log: $OUT/waf-search.log"