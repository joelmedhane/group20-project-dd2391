from __future__ import annotations

import urllib.parse
import unicodedata
from pathlib import Path
import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import Request

#-----------------------rules loading-----------------------

RULES_FILE = Path(__file__).with_name("waf_rules.json")

def load_rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)

config = load_rules()
RULES = config["rules"]
BLOCKING_REQUESTS_THRESHOLD = config.get("blocking_threshold", 4)

#--------------------text normalization--------------------

def normalize_request(text):
    #normalize the input before applying WAF rules
    # SELECT%20*%20FROM%20users -> select * from users

    if text is None:
        return ""
    
    #decode url encoding
    text =str(text)
    text = urllib.parse.unquote_plus(text)
    text = unicodedata.normalize('NFKC', text)

    text = text.lower()

    #remove multiple spaces
    text=re.sub(r'\s+',' ', text)
    text = text.strip()

    return text

#-------------------matching logic-------------------

def rule_matches(text, rule):

    rule_type=rule["type"]
    value=rule["value"]

    if rule_type=="word":
        pattern= r"\b" +value + r"\b"
        return re.search(pattern,text) is not None

    if rule_type=="keywords":
        pattern=""

        for word in value:
            if pattern:
                pattern+= r".+?"
            pattern+= r"\b" +word + r"\b"
            
        return re.search(pattern,text) is not None

    if rule_type == "regex":
        return re.search(value, text) is not None

    return False

#------------------- inspection logic-------------------
def inspect_text(text):
    score = 0
    triggered_rules = []

    original_text = text
    cleaned_text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL) #sel/**/ect becomes sel ect
    print(cleaned_text)

    for rule in RULES:

        if rule["type"]=="comment":
            matched = rule["value"] in original_text

        else:
            matched=rule_matches(cleaned_text,rule)

        if matched:
            score += rule['score']
            triggered_rules.append(rule['name'])

    return score, triggered_rules

#-------------------logging-------------------
def log_blocking_request(request,score,triggered_rules):
    #why the request was blocked
    print(f"Blocked request from {request.client.host}:{request.client.port}"
          f"- Score: {score}, Triggered Rules: {', '.join(triggered_rules)}")

#-------------------main function-------------------
def is_malicious(raw_body, request):

    body = raw_body.decode('utf-8', errors="replace")

    normalized_body = normalize_request(body)
    normalized_query = normalize_request(request.url.query)

    text_to_inspect = normalized_body + " " + normalized_query 

    score, rules = inspect_text(text_to_inspect)

    if score >= BLOCKING_REQUESTS_THRESHOLD:
        #show a message why it was blocked
        log_blocking_request(request, score, rules)

        return True

    return False