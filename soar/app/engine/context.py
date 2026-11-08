import re
from simpleeval import simple_eval
from app.engine.dsl import REF

def resolve(value, ctx):
    if isinstance(value, dict):
        return {k: resolve(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, ctx) for v in value]
    if not isinstance(value, str):
        return value
    whole = REF.fullmatch(value)
    if whole:
        return _lookup(whole.group(1), ctx)
    return REF.sub(lambda m: str(_lookup(m.group(1), ctx)), value)

def _lookup(path, ctx):
    cur = ctx
    for part in re.split(r"\.|\[|\]", path):
        if not part:
            continue
        if isinstance(cur, (list, tuple)):
            cur = cur[int(part)]
        else:
            cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part, None)
        if cur is None:
            return None
    return cur

def truthy(expr: str, ctx) -> bool:
    try:
        return bool(simple_eval(resolve(expr, ctx), names=ctx))
    except Exception:
        return False
