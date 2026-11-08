# BUILD.md — reproducing the SOAR lab

Scope: a single-host lab that takes real SSH brute-force alerts from a SIEM and runs them
through a versioned Python playbook. Roughly 4–6 hours from a clean host. Everything is Docker
Compose so the whole thing can be torn down and rebuilt.

Target: 8 GB Lightsail. Budget ~$2/day, prorated.

Secrets never go in this file. They live in `.env`, which is gitignored.

---

## Architecture

```
auth.log / auditd / FIM  ──▶  Wazuh agent (host)
                                    │ 127.0.0.1:1514
                                    ▼
                            Wazuh manager + rules + MITRE map
                                    │
                                    ▼
                            Wazuh indexer (OpenSearch)
                                    │
                            soar-poller (signed HMAC POST)
                                    ▼
                    soar-api ──▶ Postgres (cases, dedupe, audit)
                        │
                        ▼
                in-process YAML playbook engine
                        │
        ┌───────────────┼─────────────────────┬────────────────┐
        ▼               ▼                     ▼                ▼
   AbuseIPDB       ufw deny (host)      Slack webhook     GitHub issue
```

`soar-api` runs with `pid: host` and `privileged: true` so `nsenter -t 1 -n -m` reaches the host
network *and* mount namespaces. Containment targets the host firewall, not a container.

`soar-worker` is vestigial — it serves a uvicorn on 8081 that nothing calls. Recreate both
containers on any config change.

---

## Prerequisites

- Lightsail Ubuntu 24.04, 8 GB. Add 2 GB swap before anything else.
- Free accounts: AbuseIPDB, Slack (workspace with a `#soc-alerts` channel), GitHub (throwaway repo).
- A second network to attack from for the live run — phone hotspot. Loopback is allowlisted.

---

## Phase 1 — host prep

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

sudo apt update
sudo apt install -y docker.io docker-compose-v2 make git jq curl hydra python3 python3-venv
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" && newgrp docker

docker compose version   # must be >= 2.20 for `include:`
```

Do not use snap Docker — confinement breaks the bind mounts.

## Phase 2 — scaffold

Run `bootstrap.sh` from the project root. It writes the tree, the compose files, the playbook,
the engine, the tests, and the docs.

## Phase 2b — code patches after scaffold

`bootstrap.sh` writes the initial scaffold. Apply these four corrections before building;
each corresponds to an entry in the failure table.

```bash
# 1. app must exist before pip install resolves the package
python3 - <<'PY'
import pathlib
p = pathlib.Path("soar/Dockerfile")
s = p.read_text()
s = s.replace("COPY pyproject.toml ./\nRUN pip install --no-cache-dir .\nCOPY app ./app",
              "COPY pyproject.toml ./\nCOPY app ./app\nRUN pip install --no-cache-dir .")
p.write_text(s)
PY

# 2. executor-injected globals are valid template roots
sed -i 's/if root in ("inputs", "case", "steps"):/if root in ("inputs", "case", "steps", "safe_ips", "dry_run"):/' soar/app/engine/dsl.py

# 3. connector modules are flat files, not subpackages
sed -i 's|import_module(f"app.connectors.{uses}")|import_module("app.connectors." + uses.replace(".", "_"))|' soar/app/engine/registry.py

# 4. httpx takes verify on the client, not the request
sed -i 's/async with httpx.AsyncClient(timeout=30) as c:/async with httpx.AsyncClient(timeout=30, verify=False) as c:/' soar/app/poller.py
sed -i 's/auth=(USER, PASS), verify=False)/auth=(USER, PASS))/' soar/app/poller.py

```
## Phase 3 — pin the SIEM and generate certs
```

The upstream repo restructured at 5.x. Pin to the last 4.x tag.

```bash
git clone --depth 1 --branch v4.14.10 https://github.com/wazuh/wazuh-docker.git
ls wazuh-docker/single-node/   # expect docker-compose.yml, generate-indexer-certs.yml, config/
```

Generate:

```bash
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

Certs land in `config/wazuh_indexer_ssl_certs/`. The generator leaves them at `400` under a
`dr-x------` directory, which non-root container users cannot read. Relax them:

```bash
cd ~/soar-lab
sudo chmod 755 wazuh-docker/single-node/config/wazuh_indexer_ssl_certs
sudo chmod 644 wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/*
```

## Phase 4 — secrets

```bash
cp .env.example .env
sed -i "s|^HMAC_SECRET=.*|HMAC_SECRET=$(openssl rand -hex 32)|" .env
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 16)|" .env
```

Then set `DATABASE_URL` to match the generated password — **it does not track `POSTGRES_PASSWORD`
automatically**:

```bash
PW=$(grep ^POSTGRES_PASSWORD .env | cut -d= -f2-)
sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://soar:${PW}@postgres:5432/soar|" .env
```

Fill `ABUSEIPDB_KEY`, `SLACK_WEBHOOK`, `GITHUB_TOKEN`, `GITHUB_REPO`. Keep `DRY_RUN=true`.

Verify each credential in isolation with the three curl tests before running anything.

## Phase 5 — allowlist and firewall

```bash
curl -s https://api.ipify.org > safe-ips.txt
echo 127.0.0.1 >> safe-ips.txt
sudo ufw allow 22/tcp
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw enable
```

Install the boot-time allowlist refresher so a restart cannot lock you out:

```bash
sudo tee /usr/local/bin/refresh-safe-ip.sh >/dev/null <<'SH'
#!/usr/bin/env bash
set -eu
IP=$(curl -fsS --max-time 10 https://api.ipify.org) || exit 0
[ -n "$IP" ] || exit 0
printf '# refreshed %s\n%s\n' "$(date -Is)" "$IP" > /home/ubuntu/soar-lab/safe-ips.txt
echo 127.0.0.1 >> /home/ubuntu/soar-lab/safe-ips.txt
chown ubuntu:ubuntu /home/ubuntu/soar-lab/safe-ips.txt
SH
sudo chmod +x /usr/local/bin/refresh-safe-ip.sh

sudo tee /etc/systemd/system/refresh-safe-ip.service >/dev/null <<'UNIT'
[Unit]
Description=Refresh SOAR allowlist with current public IP
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/refresh-safe-ip.sh

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl enable refresh-safe-ip.service
```

Attach a Lightsail static IP if the instance will be stopped and started.

## Phase 6 — detection rules and bring-up

Write the rules, then start the stack.

```bash
cat > wazuh/rules/local_rules.xml <<'RULES'
<group name="local,soc,attack,">
  <rule id="100100" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>SSH brute force: 5+ auth failures from same source in 60s</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,</group>
  </rule>
  <rule id="100102" level="10" frequency="5" timeframe="60">
    <if_matched_sid>2502</if_matched_sid>
    <same_source_ip />
    <description>SSH brute force (journald/PAM path): repeated missed passwords from same source</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,</group>
  </rule>
</group>
RULES
```

`100102` is the journald fallback. Keep it — a decode change should not silently kill detection.

```bash
make up
```

Known snag: 1514/1515 are already published by the upstream compose, so the override must not
duplicate them. `docker-compose.override.yml` is volumes-only for that reason.

Checkpoint:

```bash
curl -s localhost:8080/healthz | jq          # {"ok": true, "playbooks": ["pb-001-..."]}
curl -sk -u admin:"$(grep ^WAZUH_PASSWORD .env | cut -d= -f2-)" \
  https://localhost:9200/_cluster/health | jq .status    # green or yellow
```

## Phase 7 — agent

Three config changes first. Skipping any of them means the rule never fires.

Enable password auth — `sshd_config` is first-value-wins and `Include` sits at line 12, so
drop-ins are read before the main file. Edit the existing drop-in; a later-sorting one loses.

```bash
sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' \
  /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
sudo sshd -t && sudo systemctl restart ssh
sudo sshd -T | grep -i passwordauthentication   # must be yes
```

Revert the rsyslog template — Ubuntu 24.04's `RSYSLOG_FileFormat` emits ISO-8601 stamps the
syslog decoder cannot parse:

```bash
sudo sed -i 's/Template="RSYSLOG_FileFormat"/Template="RSYSLOG_TraditionalFileFormat"/' /etc/rsyslog.conf
sudo systemctl restart rsyslog
```

Install the agent on the host, not in a container. It needs real `/var/log/auth.log` and real
FIM targets.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-agent
sudo apt install -y --allow-downgrades wazuh-agent=4.14.10-1   # match the manager
sudo sed -i 's|<address>.*</address>|<address>127.0.0.1</address>|' /var/ossec/etc/ossec.conf
```

`auth.log` is not monitored by default. Add it:

```bash
sudo python3 - <<'PY'
p = "/var/ossec/etc/ossec.conf"
s = open(p).read()
if "/var/log/auth.log" not in s:
    b = "  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n\n"
    s = s.replace("  <localfile>\n    <log_format>journald</log_format>",
                  b + "  <localfile>\n    <log_format>journald</log_format>", 1)
    open(p, "w").write(s)
    print("added")
PY
sudo grep -n 'auth.log' /var/ossec/etc/ossec.conf
```

Register. Use `manage_agents` on **both** sides and never mix in `agent-auth` — mixing produces
duplicate IDs and `Invalid ID` loops.

```bash
docker compose exec wazuh.manager /var/ossec/bin/manage_agents
#   A -> name -> 127.0.0.1 -> y -> confirm -> E -> <id> -> copy block -> Q

sudo rm -f /var/ossec/etc/client.keys
sudo /var/ossec/bin/manage_agents
#   I -> paste -> y -> Q
```

Verify IDs match on both sides before starting:

```bash
sudo cat /var/ossec/etc/client.keys
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l
```

Then `sudo systemctl enable --now wazuh-agent`. The manager must show the ID **Active**.

Note: remoted logs the source as `172.19.0.1` (the Docker gateway). That is normal.

## Phase 8 — validate in dry run

```bash
make smoke
docker compose exec -T postgres psql -U soar -d soar -c \
  "select r.status, a.step_id, a.outcome, a.detail from runs r join audit a on a.run_id=r.id order by a.id"
```

All five steps must be `ok`. `contain` shows `blocked: true, simulated: true`. Run `make smoke`
again and confirm `select count(*) from cases` stays at `1`.

Confirm the rule fires at all — inject lines rather than waiting on hydra:

```bash
for i in $(seq 1 6); do
  logger -p auth.info -t sshd "Failed password for invalid user testuser from 203.0.113.9 port 4000$i ssh2"
done
```

`203.0.113.9` is not allowlisted. In dry run the block is simulated, so nothing is written; once
`DRY_RUN=false` the same injection writes a real rule — remove it with
`sudo ufw delete deny from 203.0.113.9.
## Phase 9 — live run

```bash
sed -i 's/^DRY_RUN=.*/DRY_RUN=false/' .env
docker compose up -d --force-recreate soar-api soar-worker
sleep 12
docker compose exec -T soar-api printenv DRY_RUN    # must be false
docker compose exec -T postgres psql -U soar -d soar -c 'delete from dedupe'
```

Recreating `soar-api` is mandatory — execution happens in that process, so a worker-only
recreate leaves the old `DRY_RUN` in place and the run reports `simulated: true`.

Run hydra from the **phone hotspot** so the source is not allowlisted:

```bash
hydra -l ubuntu -P ~/words.txt -t 4 ssh://<host-ip>
```

`~/words.txt` can be built with:

```bash
printf '%s\n' password 123456 admin letmein root toor qwerty 12345678 abc123 Password1 > ~/words.txt
```

Expect: Slack block, `ufw` DENY rule at position 1, GitHub issue, run `auto_closed`.

## Phase 10 — capture evidence

In order, one session: alert with T1110 tag → playbook YAML → audit table → `ufw status
numbered` before/after → Slack block → GitHub issue → metrics query. Crop public IPs and
anything showing a token.

Metrics, excluding runs with an errored step — failures inflate the figure roughly 4× through
retry backoff:

```sql
select round(percentile_cont(0.5) within group (order by t.ms)::numeric, 0) median_ms, count(*) n
from (
  select r.id, sum(a.duration_ms) ms
  from runs r join audit a on a.run_id = r.id
  where not exists (select 1 from audit x where x.run_id = r.id and x.outcome = 'error')
  group by r.id
) t;
```

`automation_ms` is machine time only — do not call it MTTR.

---

## Teardown

```bash
sudo ufw status numbered | grep DENY     # delete leftovers
sed -i 's/^DRY_RUN=.*/DRY_RUN=true/' .env
docker compose up -d --force-recreate soar-api soar-worker
docker compose down
```

Snapshot from the console, then terminate. A snapshot preserves volumes, certs and the schema;
the boot service rewrites the allowlist on restore. Let the GitHub token expire or downgrade it
to read-only.

---

## Known failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `generate-indexer-certs.yml: no such file` | Cloned 5.x layout | Pin `v4.14.10` |
| `address already in use` on 1514 | Override duplicates upstream ports | Volumes-only override |
| `package directory 'app' does not exist` | `pip install .` before `COPY app` | Copy app before install |
| `password authentication failed for user "soar"` | `DATABASE_URL` out of sync | Rewrite URL from `POSTGRES_PASSWORD` |
| `duplicate key ... cases_id_seq` | api and worker race on schema init | `pg_advisory_lock` in `init()` |
| `unresolved reference 'safe_ips'` | Validator only allows `inputs`/`case`/`steps` | Allowlist the injected globals |
| `ModuleNotFoundError: app.connectors.state.dedupe` | Dot path vs flat filename | `uses.replace(".", "_")` in registry |
| Agent `Never connected` | Key ID mismatch between host and manager | Wipe `client.keys`, re-register both sides |
| Agent enrolls as a new ID | Mixing `agent-auth` with `manage_agents` | `manage_agents` only |
| `passwordauthentication no` | Drop-in sorts before main config | Edit `60-cloudimg-settings.conf` |
| `nsenter ... Operation not permitted` | Capabilities on the wrong container | `pid: host` + `privileged: true` on `soar-api` |
| `Invalid position '1'` | `-n` without `-m` uses container `ufw` state | `nsenter -t 1 -n -m` |
| `AsyncClient.post() got an unexpected keyword 'verify'` | `verify` is a client arg | Pass to `AsyncClient(...)` |
| Alerts decode as `2502`, never `5710` | Agent reads journald, not `auth.log` | Add `auth.log` localfile + traditional template |
| Live run reports `simulated: true` | `DRY_RUN` cached in the API container | Recreate `soar-api`, not just the worker |
| Blocked own IP | IP changed, allowlist stale | Static IP + boot refresh |
| Rule never fires | Password auth off, or agent disconnected | `agent_control -l`, `sshd -T` |

---

## Design decisions specific to the build

- **`nsenter` needs `-n` and `-m`.** Network namespace alone leaves the container using its own
  `ufw` binary and empty rule state against host iptables. A namespace swap is not a boundary you
  can half-apply.
- **Dry run must walk the full graph**, which is why simulated enrichment returns a score above
  threshold.

Everything else — idempotency placement, TI gating, allowlist handling — is in the README's
design-decisions section.

## Not built

No unban automation, no case UI, single host, no real Splunk/CrowdStrike adapters (interfaces
are mocked), no RBAC on the API, worker does not consume a queue.
