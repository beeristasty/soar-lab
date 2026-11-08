import httpx
from app.config import ABUSEIPDB_KEY
from app.engine.retry import Retryable

async def run(ip: str, dry_run: bool = False, **_):
    if dry_run or not ABUSEIPDB_KEY:
        return {"ip": ip, "score": 90 if dry_run else 0, "reports": 0, "simulated": True}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        )
    if r.status_code == 429:
        raise Retryable("abuseipdb rate limited")
    r.raise_for_status()
    d = r.json()["data"]
    return {"ip": ip, "score": d["abuseConfidenceScore"], "reports": d["totalReports"],
            "country": d.get("countryCode")}
