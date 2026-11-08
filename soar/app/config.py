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
