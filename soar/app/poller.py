import asyncio, hashlib, hmac, json, os
from pathlib import Path
import httpx
from app.config import HMAC_SECRET

INDEXER = os.environ.get("WAZUH_INDEXER", "https://wazuh.indexer:9200")
USER = os.environ.get("WAZUH_USER", "admin")
PASS = os.environ.get("WAZUH_PASSWORD", "SecretPassword")
CURSOR = Path("/var/lib/poller/cursor")

async def tick(client):
    since = CURSOR.read_text().strip() if CURSOR.exists() else "now-15m"
    q = {"size": 50, "sort": [{"timestamp": "asc"}],
         "query": {"range": {"timestamp": {"gt": since}}}}
    r = await client.post(f"{INDEXER}/wazuh-alerts-*/_search", json=q,
                          auth=(USER, PASS))
    hits = r.json().get("hits", {}).get("hits", [])
    for h in hits:
        alert = h["_source"]
        body = json.dumps({"alert": alert}).encode()
        sig = "sha256=" + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
        await client.post("http://soar-api:8080/ingest/wazuh", content=body,
                          headers={"X-Signature": sig, "Content-Type": "application/json"})
        CURSOR.write_text(alert["timestamp"])

async def main():
    async with httpx.AsyncClient(timeout=30, verify=False) as c:
        while True:
            try:
                await tick(c)
            except Exception as e:
                print("poller error:", e, flush=True)
            await asyncio.sleep(10)

asyncio.run(main())
