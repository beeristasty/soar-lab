import asyncio, json, time
from datetime import datetime, timezone, timedelta
from app.config import PLAYBOOK_DIR, DRY_RUN, SAFE_IPS_FILE
from app.db import connect
from app.audit import log
from app.engine import context, retry
from app.engine.dsl import Playbook

DEDUPE_TTL = 3600

def _open_case(pb, alert, key):
    with connect() as c:
        row = c.execute(
            "INSERT INTO cases(playbook_id,dedupe_key,severity,subject)"
            " VALUES (%s,%s,%s,%s) RETURNING id",
            (pb.id, key, alert.get("rule", {}).get("level"), json.dumps(alert)),
        ).fetchone()
        c.execute("INSERT INTO dedupe(key,expires_at) VALUES (%s,%s)",
                  (key, datetime.now(timezone.utc) + timedelta(seconds=DEDUPE_TTL)))
        return row[0]

def start(pb: Playbook, alert: dict) -> int:
    src = alert.get("data", {}).get("srcip") or alert.get("data", {}).get("src_ip") or "unknown"
    key = f"{pb.id}:{src}"
    with connect() as c:
        hit = c.execute(
            "SELECT key FROM dedupe WHERE key=%s AND expires_at > now()", (key,)
        ).fetchone()
    if hit:
        with connect() as c:
            row = c.execute("SELECT id FROM cases WHERE dedupe_key=%s ORDER BY id DESC LIMIT 1", (key,)).fetchone()
        return row[0] if row else -1
    case_id = _open_case(pb, alert, key)
    asyncio.create_task(run(pb, case_id, alert))
    return case_id

async def run(pb: Playbook, case_id: int, alert: dict):
    with connect() as c:
        run_id = c.execute(
            "INSERT INTO runs(case_id,playbook_id,playbook_version,dry_run) VALUES (%s,%s,%s,%s) RETURNING id",
            (case_id, pb.id, pb.version, DRY_RUN),
        ).fetchone()[0]
    safe = set(SAFE_IPS_FILE.read_text().split()) if SAFE_IPS_FILE.exists() else set()
    ctx = {
        "inputs": {"src_ip": alert.get("data", {}).get("srcip", "0.0.0.0")},
        "case": {"id": case_id, "playbook": pb.id},
        "steps": {},
        "dry_run": DRY_RUN,
        "safe_ips": safe,
    }
    status = "ok"
    for step in pb.steps:
        if step.when and not context.truthy(step.when, ctx):
            log(run_id, step.id, step.uses, "skipped", {"reason": "when false"}, 0)
            continue
        kwargs = context.resolve(step.with_, ctx)
        kwargs.setdefault("dry_run", DRY_RUN)
        t0 = time.monotonic()
        try:
            result = await retry.call(step.uses, kwargs, step.timeout_seconds)
            ctx["steps"][step.id] = result or {}
            log(run_id, step.id, step.uses, "ok", result or {}, int((time.monotonic() - t0) * 1000))
        except Exception as e:
            log(run_id, step.id, step.uses, "error", {"error": str(e)}, int((time.monotonic() - t0) * 1000))
            if step.on_error == "continue":
                continue
            status = "failed"
            break
    with connect() as c:
        c.execute("UPDATE runs SET status=%s, ended_at=now() WHERE id=%s", (status, run_id))
        if status == "ok":
            c.execute("UPDATE cases SET status='auto_closed', closed_at=now() WHERE id=%s", (case_id,))
