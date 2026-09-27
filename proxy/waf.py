from __future__ import annotations

import urllib.parse
import unicodedata
from pathlib import Path
import json
import re
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
    # SELECT%20*%20FROM%20users -> select * from users

    if text is None:
        return ""
    
    #decode url encoding
    text =str(text)
    text = urllib.parse.unquote_plus(text) #turns + into space also
    text = unicodedata.normalize('NFKC', text)
    # Select select SELECT 
    text = text.lower()

    #remove multiple spaces
    text=re.sub(r'\s+',' ', text)
    text = text.strip()

    return text


def rule_matches(text, rule_value):
    #check if a WAF rule matches the text

    value = rule_value.lower().strip()

    # some SQL statements can have text between the keywords
    #this accounts for SELECT username FROM users, where SELECT and FROM are not next to each other 
    if value == "select from":
        return re.search(r"\bselect\b.+\bfrom\b",text) is not None

    # UPDATE users SET password='asdf'
    if value == "update set":
        return re.search(r"\bupdate\b.+\bset\b",text) is not None

    #for multi-word rules ex. union select, drop table
    if ' ' in value:
        pattern = re.escape(value)
        pattern = pattern.replace(r'\ ', r'\s+')

        return re.search(pattern,text) is not None

    #single word rules
    if value.replace("_","").isalnum():
        #select shouldnt match selected,selection
        pattern=r"\b" +re.escape(value) + r"\b"
        return re.search(pattern, text) is not None

    #symbols like --, /*
    return value in text


def inspect_text(text):
    score = 0
    triggered_rules = []

    for rule in RULES:
        if rule_matches(text, rule["value"]):
            score += rule['score']
            triggered_rules.append(rule['name'])

    return score, triggered_rules

def log_blocking_request(request,score,triggered_rules):
    #why the request was blocked
    print(f"Blocked request from {request.client.host}:{request.client.port}"
          f"- Score: {score}, Triggered Rules: {', '.join(triggered_rules)}")


def is_malicious(raw_body: bytes, request: Request):

    body = raw_body.decode('utf-8', errors="replace")

    normalized_body = normalize_request(body)
    normalized_query = normalize_request(request.url.query)
    normalized_path = normalize_request(request.url.path)

    text_to_inspect = normalized_body + " " + normalized_query + " " + normalized_path

    score, rules = inspect_text(text_to_inspect)

    if score >= BLOCKING_REQUESTS_THRESHOLD:
        #show a message why it was blocked
        log_blocking_request(request, score, rules)

        return True

    return False