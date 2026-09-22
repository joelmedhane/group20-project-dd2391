from fastapi import Request

def is_malicious(raw_body: bytes, request: Request):
    return False