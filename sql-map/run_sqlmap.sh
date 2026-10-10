#!/usr/bin/env bash
# Runs sqlmap against the WAF
set -e

OUT=sqlmap-results
URL=http://host.docker.internal:8080/api/login

mkdir -p "$OUT"

echo "Starting containers..."
docker compose -f ../docker-compose.yml up -d --build node_target fastapi_proxy

echo "1. Testing login with sqlmap"
docker compose -f ../docker-compose.yml run --build --rm sqlmap \
  -u "$URL" \
  --data='{"username":"","password":""}' \
  -H "Content-Type: application/json" \
  -p username,password \
  --ignore-code 401 \
  --batch --level 3 --flush-session \
  --output-dir=/results -t /results/waf.log

STATUS_REGEX='\([0-9]{3} [^)]*\)'

echo
echo "Blocked (403):      $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '403' || true)"
echo "Unauthorized (401): $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '401' || true)"
echo "Bad Request (Improvement) (400):  $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '400' || true)"
echo "OK (200):           $(grep -oE "$STATUS_REGEX" "$OUT/waf.log" | grep -c '200' || true)"
echo "Full traffic log: $OUT/waf.log"