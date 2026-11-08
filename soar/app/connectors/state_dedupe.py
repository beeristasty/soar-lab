async def run(key: str, ttl: int = 3600, dry_run: bool = False, **_):
    return {"key": key, "ttl": ttl, "deduped": False}
