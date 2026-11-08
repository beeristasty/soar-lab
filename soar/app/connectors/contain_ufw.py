import asyncio, ipaddress
from app.engine.retry import Retryable

async def run(ip: str, ttl_hours: int = 24, safe_ips: set | None = None,
              dry_run: bool = False, **_):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"blocked": False, "reason": "bad ip"}
    if safe_ips and ip in safe_ips:
        return {"blocked": False, "reason": "allowlisted", "ip": ip}
    if dry_run:
        return {"blocked": True, "ip": ip, "simulated": True, "ttl_hours": ttl_hours}
    p = await asyncio.create_subprocess_exec(
        "nsenter", "-t", "1", "-n", "-m", "ufw", "insert", "1", "deny", "from", ip,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await p.communicate()
    if p.returncode != 0:
        raise Retryable(err.decode()[:300])
    return {"blocked": True, "ip": ip, "ttl_hours": ttl_hours}
