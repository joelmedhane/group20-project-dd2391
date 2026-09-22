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
        
    