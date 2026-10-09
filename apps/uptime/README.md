# uptime

Monitoring and alerts. https://uptime.agathla.com (DNS alias of the k3s entry), behind
Authelia (group `admins` or `app-uptime`).

- **Uptime Kuma** checks every service once a minute and alerts by push (ntfy.sh topic)
  and email (Proton SMTP, `noreply@agathla.com`) when one stays down, and again when it's
  back. Monitors and notification settings live in Kuma's database on its volume (nightly
  Longhorn backups); Kuma's own login is turned off (Settings → Security), Authelia does it.
- **Heartbeat** (`heartbeat.yaml`): every 2 minutes a job reports to healthchecks.io
  whether Kuma is up. healthchecks.io is outside the homelab, so if the cluster or the
  house internet goes down, the reports stop and it alerts by itself.

## Vault

| Path | Keys |
|---|---|
| `secret/k8s/uptime/healthchecks` | `ping-url` (healthchecks.io check, period 2 min) |
| `secret/k8s/uptime/ntfy` | `topic` (long random ntfy.sh topic; anyone who knows it can read the alerts) |
| `secret/k8s/uptime/smtp` | `password` (Proton SMTP token for `noreply@agathla.com`) |
