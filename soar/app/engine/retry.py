import asyncio, random
from app.engine import registry

class Retryable(Exception):
    pass

async def call(uses: str, kwargs: dict, timeout: float, attempts: int = 3):
    mod = registry.get(uses)
    last = None
    for i in range(attempts):
        try:
            return await asyncio.wait_for(mod.run(**kwargs), timeout=timeout)
        except (asyncio.TimeoutError, Retryable) as e:
            last = e
            if i < attempts - 1:
                await asyncio.sleep((2 ** i) + random.uniform(0, 0.4))
        except Exception:
            raise
    raise Retryable(f"{uses} exhausted retries: {last}")
