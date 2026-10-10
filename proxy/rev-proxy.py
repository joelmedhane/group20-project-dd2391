import httpx
from fastapi import FastAPI, Request, Response
from starlette.responses import StreamingResponse
from waf import is_malicious

app = FastAPI()
client = httpx.AsyncClient(base_url="http://node_target:3000/")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def reverse_proxy(request: Request, path: str):
    raw_body = await request.body()
    
    if is_malicious(raw_body, request):
        return Response(status_code=403)
        
    safe_headers = {}
    for key, value in request.headers.items():
        if key.lower() not in ('host', 'connection'):
            safe_headers[key] = value
            
    query_string = request.url.query.encode("utf-8")
    url = httpx.URL(path=request.url.path, query=query_string)

    rp_req = client.build_request(
        method=request.method,
        url=url,
        headers=safe_headers,
        content=raw_body
    )
    
    rp_resp = await client.send(rp_req, stream=True)
    client.cookies.clear() 
    
    return StreamingResponse(
        rp_resp.aiter_raw(),
        status_code=rp_resp.status_code,
        headers=rp_resp.headers
    )