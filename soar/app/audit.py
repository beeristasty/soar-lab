import json
from app.db import connect

def log(run_id: int, step_id: str, connector: str, outcome: str, detail: dict, ms: int):
    with connect() as c:
        c.execute(
            "INSERT INTO audit(run_id,step_id,connector,outcome,detail,duration_ms)"
            " VALUES (%s,%s,%s,%s,%s,%s)",
            (run_id, step_id, connector, outcome, json.dumps(detail, default=str), ms),
        )
