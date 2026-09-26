from __future__ import annotations

import urllib.parse
import unicodedata
from pathlib import Path
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import Request

RULES_FILE = Path(__file__).with_name("waf_rules.json")

def load_rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)

config = load_rules()
RULES = config["rules"]
BLOCKING_REQUESTS_THRESHOLD = config.get("blocking_threshold", 4)

def normalize_request(text):
    #normalize the input before applying WAF rules
    #decode url encoding
    text=urllib.parse.unquote_plus(text) #turns + into space

    #normalize unicode representations
    text = unicodedata.normalize('NFKC', text)

    text = text.lower()

    return text

def inspect_text(text):
    score = 0
    triggered_rules = []

    for rule in RULES:
        if rule['value'] in text:
            score += rule['score']
            triggered_rules.append(rule['name'])

    return score, triggered_rules

def log_blocking_request(request,score,triggered_rules):
    #why the request was blocked
    print(f"Blocked request from {request.client.host}:{request.client.port}"
          f"- Score: {score}, Triggered Rules: {', '.join(triggered_rules)}")


def is_malicious(raw_body: bytes, request: Request):

    body = raw_body.decode('utf-8')

    normalized_body = normalize_request(body)
    normalized_query = normalize_request(request.url.query)

    text_to_inspect = normalized_body + " " + normalized_query

    score, rules = inspect_text(text_to_inspect)

    if score >= BLOCKING_REQUESTS_THRESHOLD:
        #show a message why it was blocked
        log_blocking_request(request, score, rules)

        return True

    return False