import hashlib, hmac
from fastapi import Header, HTTPException, Request
from app.config import HMAC_SECRET

async def verify(request: Request, x_signature: str = Header(default="")):
    body = await request.body()
    want = "sha256=" + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, x_signature):
        raise HTTPException(401, "bad signature")
    return body
