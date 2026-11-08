# Changelog

Conventions: [Keep a Changelog](https://keepachangelog.com/). Playbook versions are
semver; platform changes are grouped separately because they affect every playbook.

## 2026-11-08

### Playbook — pb-001 `1.1.0` → `1.2.0`

Added
- Rule `100102` matching the journald/PAM signature. The agent reads journald, so
  sshd events decoded as generic syslog and `5710`/`5760` never matched.

Changed
- Trigger widened to `[100100, 100102]`.

### Platform

Fixed
- Agent config now monitors `/var/log/auth.log`; it previously was not a
  `<localfile>` at all.
- rsyslog reverted to the traditional template. Ubuntu 24.04 defaults to
  `RSYSLOG_FileFormat`, whose ISO-8601 stamps the syslog decoder cannot parse —
  detection was silently producing zero matches.
- `poller.py` passed `verify=` to `AsyncClient.post()` instead of the client
  constructor. Every poll cycle raised; nine alerts sat undelivered in the index.
- `pid: host` and `privileged: true` moved onto `soar-api`. Execution happens in
  the API process via `asyncio.create_task`, so capabilities on `soar-worker`
  never applied and `nsenter` failed with `Operation not permitted`.
- `contain_ufw` now enters the mount namespace (`nsenter -t 1 -n -m`) as well as
  the network namespace. Without it the container used its own `ufw` binary and
  empty rule state, failing with `Invalid position '1'`.

Known
- `soar-worker` is vestigial. It runs a uvicorn on 8081 that nothing calls.
  Recreate both containers on any config change until it consumes the Redis queue.

## 2026-11-07

### Playbook — pb-001 `1.0.0` → `1.1.0`

Changed
- Removed TI-confidence gates on `contain` and `ticket`. The detection rule
  already encodes volume; score now sets severity instead of gating action.

Fixed
- Dry-run enrichment returns a score above threshold so validation walks the full
  graph rather than skipping the branch it is meant to test.
