import httpx
from app.config import GITHUB_TOKEN, GITHUB_REPO
from app.engine.retry import Retryable

async def run(title: str, body: str, labels: list | None = None,
              dry_run: bool = False, **_):
    if dry_run or not GITHUB_TOKEN:
        return {"created": False, "simulated": True, "title": title}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/issues",
            json={"title": title, "body": body, "labels": labels or ["security"]},
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}",
                     "Accept": "application/vnd.github+json"},
        )
    if r.status_code >= 500:
        raise Retryable("github 5xx")
    r.raise_for_status()
    return {"created": True, "url": r.json()["html_url"], "number": r.json()["number"]}
