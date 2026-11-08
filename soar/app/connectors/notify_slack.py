import httpx
from app.config import SLACK_WEBHOOK
from app.engine.retry import Retryable

async def run(text: str, dry_run: bool = False, **_):
    if dry_run or not SLACK_WEBHOOK:
        return {"sent": False, "simulated": True, "text": text}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(SLACK_WEBHOOK, json={"text": text})
    if r.status_code == 429:
        raise Retryable("slack rate limited")
    r.raise_for_status()
    return {"sent": True}
