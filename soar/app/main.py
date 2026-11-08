from fastapi import FastAPI, Depends, Request
from app import db, security
from app.engine import loader, executor
from app.config import PLAYBOOK_DIR

app = FastAPI(title="soar-lab")

@app.on_event("startup")
def _boot():
    db.init()

@app.get("/healthz")
def healthz():
    return {"ok": True, "playbooks": [p.id for p in loader.load_all(PLAYBOOK_DIR)]}

@app.post("/ingest/wazuh")
async def ingest(request: Request, _=Depends(security.verify)):
    body = await request.json()
    alert = body.get("alert", body)
    rule = alert.get("rule", {})
    rid = int(rule.get("id", 0))
    for pb in loader.load_all(PLAYBOOK_DIR):
        if rid in pb.trigger.rule_ids:
            case_id = executor.start(pb, alert)
            return {"case_id": case_id, "playbook": pb.id}
    return {"case_id": None}
