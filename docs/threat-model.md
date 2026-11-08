# Threat model

| Failure | Blast radius | Mitigation |
|---|---|---|
| Blocks the admin IP | Lose SSH access to the lab | `safe-ips.txt`, verified before first live run |
| Blocks a shared CDN IP | Site unavailable to real users | Confidence threshold 50 + 24h TTL |
| Duplicate flood from replayed alerts | Slack/ticket spam | 1h dedupe key on source IP |
| AbuseIPDB outage | Playbook stalls | 3 attempts, backoff, then `on_error: continue` |
| Bad IP from Wazuh | Garbage `ufw` rule | `ipaddress` validation before execution |
