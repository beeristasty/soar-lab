
## Entry — 2026-11-08

### Finding 3 — detection path, not detection logic

`100100` never fired during live validation despite hydra producing failures.
Three separate causes, each independently fatal:

1. The agent read journald, so sshd lines decoded as generic syslog (`2502`) and
   `5710`/`5760` never matched.
2. `/var/log/auth.log` was not a configured `<localfile>` at all.
3. Once added, rsyslog's default `RSYSLOG_FileFormat` emitted ISO-8601 stamps
   the syslog decoder cannot parse.

Fix: added rule `100102` on the PAM signature as a second path, enabled
`auth.log` as a source, and reverted the rsyslog template to traditional format.

Lesson: the smoke harness never caught this because it posts a synthetic alert
straight to the API, bypassing the SIEM entirely. A test that skips the decode
layer proves nothing about detection.

### Finding 4 — poller never delivered

`poller.py` passed `verify=False` to `AsyncClient.post()` rather than the client
constructor. httpx raised on every cycle, so alerts accumulated in the index
unread. The cursor only advanced after a successful POST, so nothing was lost.

Fix: `verify=False` on the client. Added a startup assertion that the first poll
returns without exception.

### Action items

| Item | Owner | Due |
|---|---|---|
| Add an end-to-end test that injects via `logger -t sshd` and asserts a case exists | lab owner | next review |
| Assert `syslog` decode format in a health check | lab owner | next review |
