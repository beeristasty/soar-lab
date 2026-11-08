import psycopg
from app.config import DATABASE_URL

LOCK_ID = 918273645

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
        c.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
        try:
            c.execute(SCHEMA)
        finally:
            c.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
