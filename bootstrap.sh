#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p soar/app/{api,engine,connectors} soar/tests/fixtures soar/playbooks \
         wazuh/rules grafana/provisioning docs/{requirements,runbooks} \
         scripts .github/workflows

# ---------- wazuh upstream ----------
[ -d wazuh-docker ] || git clone --depth 1 https://github.com/wazuh/wazuh-docker.git
cat > wazuh/rules/local_rules.xml <<'RULES'
<group name="local,soc,attack,">
  <rule id="100100" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>SSH brute force: 5+ failed passwords from same source in 60s</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,</group>
  </rule>
  <rule id="100101" level="3">
    <if_sid>100100</if_sid>
    <description>PB-001: brute force routed to SOAR</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>
RULES

# ---------- soar image ----------
cat > soar/Dockerfile <<'DOCKER'
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ufw curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir .
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
DOCKER

cat > soar/pyproject.toml <<'PYPROJ'
[project]
name = "soar-lab"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
  "fastapi==0.115.6", "uvicorn==0.34.0", "pydantic==2.10.4",
  "psycopg[binary]==3.2.3", "redis==5.2.1", "httpx==0.28.1",
  "pyyaml==6.0.2", "simpleeval==1.0.3", "jinja2==3.1.5",
  "pytest==8.3.4", "pytest-asyncio==0.25.0", "respx==0.22.0",
]
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[tool.setuptools]
packages = ["app", "app.api", "app.engine", "app.connectors"]
PYPROJ

cat > soar/app/config.py <<'PY'
import os
from pathlib import Path

DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
PLAYBOOK_DIR = Path(os.environ.get("PLAYBOOK_DIR", "/playbooks"))
HMAC_SECRET = os.environ.get("HMAC_SECRET", "dev-secret")
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
SAFE_IPS_FILE = Path(os.environ.get("SAFE_IPS_FILE", "/etc/soar/safe-ips.txt"))

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")
PY

cat > soar/app/db.py <<'PY'
import psycopg
from app.config import DATABASE_URL

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id BIGSERIAL PRIMARY KEY, playbook_id TEXT NOT NULL, dedupe_key TEXT,
  status TEXT NOT NULL DEFAULT 'open', severity TEXT, subject JSONB,
  created_at TIMESTAMPTZ DEFAULT now(), closed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS runs (
  id BIGSERIAL PRIMARY KEY, case_id BIGINT REFERENCES cases(id) ON DELETE CASCADE,
  playbook_id TEXT, playbook_version TEXT, status TEXT DEFAULT 'running',
  dry_run BOOLEAN, started_at TIMESTAMPTZ DEFAULT now(), ended_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS audit (
  id BIGSERIAL PRIMARY KEY, run_id BIGINT REFERENCES runs(id) ON DELETE CASCADE,
  step_id TEXT, connector TEXT, outcome TEXT, detail JSONB,
  duration_ms INT, at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS dedupe (
  key TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS audit_run ON audit(run_id);
"""

def connect():
    return psycopg.connect(DATABASE_URL, autocommit=True)

def init():
    with connect() as c:
        c.execute(SCHEMA)
PY

cat > soar/app/audit.py <<'PY'
import json
from app.db import connect

def log(run_id: int, step_id: str, connector: str, outcome: str, detail: dict, ms: int):
    with connect() as c:
        c.execute(
            "INSERT INTO audit(run_id,step_id,connector,outcome,detail,duration_ms)"
            " VALUES (%s,%s,%s,%s,%s,%s)",
            (run_id, step_id, connector, outcome, json.dumps(detail, default=str), ms),
        )
PY

cat > soar/app/security.py <<'PY'
import hashlib, hmac
from fastapi import Header, HTTPException, Request
from app.config import HMAC_SECRET

async def verify(request: Request, x_signature: str = Header(default="")):
    body = await request.body()
    want = "sha256=" + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, x_signature):
        raise HTTPException(401, "bad signature")
    return body
PY

cat > soar/app/main.py <<'PY'
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
PY

cat > soar/app/engine/dsl.py <<'PY'
import re
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
PBID = re.compile(r"^pb-\d{3}-[a-z0-9-]+$")
USES = re.compile(r"^[a-z]+(\.[a-z_]+)+$")
REF = re.compile(r"\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}")

class Trigger(BaseModel):
    source: Literal["wazuh"] = "wazuh"
    rule_ids: list[int] = Field(min_length=1)
    threshold: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=60, ge=1)

class Step(BaseModel):
    id: str
    uses: str
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    when: str | None = None
    on_error: Literal["fail", "continue", "escalate"] = "fail"
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    model_config = {"populate_by_name": True}

    @field_validator("uses")
    @classmethod
    def _uses(cls, v):
        if not USES.match(v):
            raise ValueError(f"uses must be namespace.action, got {v!r}")
        return v

class Playbook(BaseModel):
    id: str
    version: str
    title: str
    description: str = ""
    owner: str = ""
    stakeholders: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    trigger: Trigger
    inputs: list[str] = Field(default_factory=list)
    steps: list[Step] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not PBID.match(v):
            raise ValueError("id must look like pb-001-name")
        return v

    @field_validator("version")
    @classmethod
    def _ver(cls, v):
        if not SEMVER.match(v):
            raise ValueError("version must be semver")
        return v

    @model_validator(mode="after")
    def _refs(self):
        ids = [s.id for s in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate step ids")
        known = set(self.inputs)
        for s in self.steps:
            for blob in [s.when or ""] + [str(v) for v in s.with_.values()]:
                for ref in REF.findall(blob):
                    root = ref.split(".")[0].split("[")[0]
                    if root in ("inputs", "case", "steps", "safe_ips", "dry_run"):
                        continue
                    if ref not in known and root not in known:
                        raise ValueError(f"unresolved reference {ref!r} in step {s.id}")
            known.add(s.id)
        return self
PY

cat > soar/app/engine/loader.py <<'PY'
import yaml
from pathlib import Path
from app.engine.dsl import Playbook

def load_all(directory: Path) -> list[Playbook]:
    out = []
    for f in sorted(Path(directory).glob("*.yaml")):
        out.append(Playbook(**yaml.safe_load(f.read_text())))
    return out

def load_one(directory: Path, pb_id: str) -> Playbook:
    for pb in load_all(directory):
        if pb.id == pb_id:
            return pb
    raise KeyError(pb_id)
PY

cat > soar/app/engine/registry.py <<'PY'
import importlib
_CACHE: dict[str, object] = {}

def get(uses: str):
    if uses not in _CACHE:
        mod = importlib.import_module("app.connectors." + uses.replace(".", "_"))
        _CACHE[uses] = mod
    return _CACHE[uses]
PY

cat > soar/app/engine/retry.py <<'PY'
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
PY

cat > soar/app/engine/context.py <<'PY'
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
PY

cat > soar/app/engine/executor.py <<'PY'
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
PY

cat > soar/app/connectors/state_dedupe.py <<'PY'
async def run(key: str, ttl: int = 3600, dry_run: bool = False, **_):
    return {"key": key, "ttl": ttl, "deduped": False}
PY

cat > soar/app/connectors/ti_abuseipdb.py <<'PY'
import httpx
from app.config import ABUSEIPDB_KEY
from app.engine.retry import Retryable

async def run(ip: str, dry_run: bool = False, **_):
    if dry_run or not ABUSEIPDB_KEY:
        return {"ip": ip, "score": 0, "reports": 0, "simulated": True}
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
PY

cat > soar/app/connectors/contain_ufw.py <<'PY'
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
        "nsenter", "-t", "1", "-n", "ufw", "insert", "1", "deny", "from", ip,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await p.communicate()
    if p.returncode != 0:
        raise Retryable(err.decode()[:300])
    return {"blocked": True, "ip": ip, "ttl_hours": ttl_hours}
PY

cat > soar/app/connectors/notify_slack.py <<'PY'
import httpx
from app.config import SLACK_WEBHOOK
from app.engine.retry import Retryable

async def run(text: str, dry_run: bool = False, **_):
    if dry_run or not SLACK_WEBHOOK:
        return {"sent": False, "simulated": True, "text": text}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(SLACK_WEBHOOK, json={"text": text})
    if r.status_code == 429:
        raise Retryable("slack rate limited")
    r.raise_for_status()
    return {"sent": True}
PY

cat > soar/app/connectors/ticket_github.py <<'PY'
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
PY

cat > soar/playbooks/pb-001-ssh-bruteforce.yaml <<'PB'
id: pb-001-ssh-bruteforce
version: 1.0.0
title: SSH brute force triage and containment
description: >
  Enriches a source IP responsible for repeated SSH auth failures, blocks it at
  the host firewall when confidence is high, and opens a case for the SOC.
owner: soc-automation@example.com
stakeholders: [SOC, Threat Intel]
mitre: [T1110]
trigger:
  source: wazuh
  rule_ids: [100100, 100101]
  threshold: 5
  window_seconds: 60
inputs: [src_ip]
steps:
  - id: dedupe
    uses: state.dedupe
    with: {key: "{{ inputs.src_ip }}", ttl: 3600}
  - id: enrich
    uses: ti.abuseipdb
    with: {ip: "{{ inputs.src_ip }}"}
  - id: notify_triage
    uses: notify.slack
    with:
      text: ":rotating_light: *PB-001* brute force from `{{ inputs.src_ip }}` — abuse score {{ steps.enrich.score }} (case #{{ case.id }})"
  - id: contain
    uses: contain.ufw
    when: "steps.enrich.score >= 50"
    on_error: continue
    with: {ip: "{{ inputs.src_ip }}", ttl_hours: 24, safe_ips: "{{ safe_ips }}"}
  - id: ticket
    uses: ticket.github
    when: "steps.enrich.score >= 50"
    on_error: continue
    with:
      title: "[PB-001] Auto-contained brute force from {{ inputs.src_ip }}"
      body: |
        Case #{{ case.id }}
        Source IP: {{ inputs.src_ip }}
        AbuseIPDB score: {{ steps.enrich.score }} ({{ steps.enrich.reports }} reports)
        Containment: {{ steps.contain }}
      labels: [security, auto-triage]
PB

cat > soar/app/poller.py <<'PY'
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
PY

cat > soar/app/worker.py <<'PY'
import asyncio, uvicorn
from app.main import app

# worker hosts the event loop that playbooks run on
uvicorn.run(app, host="0.0.0.0", port=8081)
PY

cat > soar/tests/conftest.py <<'PY'
import os
os.environ.setdefault("DATABASE_URL", "postgresql://soar:soar@localhost:5432/soar")
PY

cat > soar/tests/test_dsl.py <<'PY'
import pytest, yaml
from pathlib import Path
from app.engine.dsl import Playbook

PB = Path(__file__).parents[1] / "playbooks"

def test_shipped_playbooks_parse():
    for f in PB.glob("*.yaml"):
        Playbook(**yaml.safe_load(f.read_text()))

def test_bad_uses_rejected():
    raw = yaml.safe_load((PB / "pb-001-ssh-bruteforce.yaml").read_text())
    raw["steps"][0]["uses"] = "nonsense"
    with pytest.raises(Exception):
        Playbook(**raw)

def test_unresolved_reference_rejected():
    raw = yaml.safe_load((PB / "pb-001-ssh-bruteforce.yaml").read_text())
    raw["steps"][1]["with"]["ip"] = "{{ steps.nope.value }}"
    with pytest.raises(Exception):
        Playbook(**raw)
PY

cat > soar/tests/test_connectors.py <<'PY'
import pytest, httpx, respx
from app.connectors import ti_abuseipdb, contain_ufw, ticket_github

@pytest.mark.asyncio
@respx.mock
async def test_enrich_scores(monkeypatch):
    monkeypatch.setattr(ti_abuseipdb, "ABUSEIPDB_KEY", "k")
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 12, "countryCode": "RU"}}))
    out = await ti_abuseipdb.run(ip="1.2.3.4")
    assert out["score"] == 88

@pytest.mark.asyncio
async def test_contain_skips_allowlisted():
    out = await contain_ufw.run(ip="9.9.9.9", safe_ips={"9.9.9.9"})
    assert out["blocked"] is False

@pytest.mark.asyncio
async def test_contain_rejects_garbage():
    out = await contain_ufw.run(ip="not-an-ip")
    assert out["blocked"] is False

@pytest.mark.asyncio
@respx.mock
async def test_ticket_retries_on_5xx(monkeypatch):
    monkeypatch.setattr(ticket_github, "GITHUB_TOKEN", "t")
    monkeypatch.setattr(ticket_github, "GITHUB_REPO", "me/r")
    route = respx.post("https://api.github.com/repos/me/r/issues")
    route.side_effect = [httpx.Response(502), httpx.Response(201, json={"html_url": "u", "number": 1})]
    out = await ticket_github.run(title="x", body="y")
    assert out["number"] == 1
PY

cat > .env.example <<'ENV'
DATABASE_URL=postgresql://soar:soar@postgres:5432/soar
POSTGRES_PASSWORD=change-me
HMAC_SECRET=change-me-too
DRY_RUN=true
SAFE_IPS_FILE=/etc/soar/safe-ips.txt
ABUSEIPDB_KEY=
SLACK_WEBHOOK=
GITHUB_TOKEN=
GITHUB_REPO=
WAZUH_INDEXER=https://wazuh.indexer:9200
WAZUH_USER=admin
WAZUH_PASSWORD=SecretPassword
ENV
cp -n .env.example .env

echo "# your own admin IP — never auto-blocked" > safe-ips.txt
curl -s https://api.ipify.org >> safe-ips.txt && echo >> safe-ips.txt

cat > docker-compose.yml <<'DC'
include:
  - path: wazuh-docker/single-node/docker-compose.yml

name: soar-lab

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: soar
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-soar}
      POSTGRES_DB: soar
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U soar"]
      interval: 5s
      retries: 30

  redis:
    image: redis:7-alpine
    volumes: [redisdata:/data]

  soar-api:
    build: ./soar
    env_file: .env
    environment:
      PLAYBOOK_DIR: /playbooks
    volumes:
      - ./soar/playbooks:/playbooks:ro
      - ./safe-ips.txt:/etc/soar/safe-ips.txt:ro
    ports: ["8080:8080"]
    depends_on:
      postgres: {condition: service_healthy}
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8080/healthz"]
      interval: 10s
      retries: 10

  soar-worker:
    build: ./soar
    command: ["python", "-m", "app.worker"]
    env_file: .env
    pid: host
    privileged: true
    environment:
      PLAYBOOK_DIR: /playbooks
    volumes:
      - ./soar/playbooks:/playbooks:ro
      - ./safe-ips.txt:/etc/soar/safe-ips.txt:ro
    depends_on:
      postgres: {condition: service_healthy}

  soar-poller:
    build: ./soar
    command: ["python", "-m", "app.poller"]
    env_file: .env
    volumes: [pollercursor:/var/lib/poller]
    depends_on:
      soar-api: {condition: service_healthy}

volumes:
  pgdata:
  redisdata:
  pollercursor:
DC

cat > wazuh/rules/.keep <<'K'
K

cat > docker-compose.override.yml <<'OVR'
services:
  wazuh.manager:
    volumes:
      - ./wazuh/rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
OVR

cat > Makefile <<'MK'
.PHONY: up down certs test lint smoke
certs:
	cd wazuh-docker/single-node && docker compose -f generate-indexer-certs.yml run --rm generator
up: certs
	docker compose up -d --build
down:
	docker compose down
test:
	cd soar && python -m pytest -q
lint:
	cd soar && python -m pytest -q tests/test_dsl.py
smoke:
	./scripts/smoke-test.sh
MK

cat > scripts/smoke-test.sh <<'SM'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
SIG=$(printf '%s' '{"alert":{"rule":{"id":100100,"level":10},"data":{"srcip":"198.51.100.7"}}}' \
  | openssl dgst -sha256 -hmac "$(grep ^HMAC_SECRET .env | cut -d= -f2)" | sed 's/^.* //')
curl -fsS -X POST localhost:8080/ingest/wazuh \
  -H "X-Signature: sha256=$SIG" -H 'Content-Type: application/json' \
  -d '{"alert":{"rule":{"id":100100,"level":10},"data":{"srcip":"198.51.100.7"}}}'
echo
SM
chmod +x scripts/smoke-test.sh

cat > .github/workflows/ci.yml <<'CI'
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install ./soar
      - run: cd soar && python -m pytest -q
CI

cat > .gitignore <<'GI'
.env
wazuh-docker/
__pycache__/
.pytest_cache/
*.pyc
GI

cat > docs/requirements/pb-001.md <<'D'
# PB-001 requirements — SSH brute force triage

## Stakeholder inputs
- **SOC tier 1:** wants the alert to arrive with enrichment already attached; will not
  accept automation that blocks without a human-visible trail.
- **Threat Intel:** AbuseIPDB confidence >= 50 is the agreed action threshold.
- **Host owner (me):** my own admin IP must never be blocked.

## Success criteria
- Median time from alert to containment under 30s.
- Zero duplicate Slack messages for the same IP within an hour.
- Allowlisted IPs are skipped even when confidence is high.

## Explicit non-goals
- No unban automation (manual `ufw delete` for v1).
- No blocking above 24h TTL.
D

cat > docs/threat-model.md <<'D'
# Threat model

| Failure | Blast radius | Mitigation |
|---|---|---|
| Blocks the admin IP | Lose SSH access to the lab | `safe-ips.txt`, verified before first live run |
| Blocks a shared CDN IP | Site unavailable to real users | Confidence threshold 50 + 24h TTL |
| Duplicate flood from replayed alerts | Slack/ticket spam | 1h dedupe key on source IP |
| AbuseIPDB outage | Playbook stalls | 3 attempts, backoff, then `on_error: continue` |
| Bad IP from Wazuh | Garbage `ufw` rule | `ipaddress` validation before execution |
D

cat > docs/runbooks/pb-001.md <<'D'
# Runbook — PB-001

**Disable:** set `DRY_RUN=true` in `.env` and restart `soar-worker`.
**Unblock an IP:** `sudo ufw delete deny from <ip>`
**Check a run:** `psql -c "select * from audit where run_id=<id> order by id"`
**Escalate:** any run with `status=failed` is a manual triage.
D

echo "scaffold complete"
