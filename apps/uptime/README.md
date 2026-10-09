# uptime

Monitoring and alerts. https://uptime.agathla.com (DNS alias of the k3s entry), behind
Authelia (group `admins` or `app-uptime`).

- **Uptime Kuma** checks every service once a minute and alerts by push (ntfy.sh topic)
  and email (Proton SMTP, `noreply@agathla.com`) when one stays down, and again when it's
  back. Kuma's own login is turned off (Settings → Security), Authelia does it.
- **Monitors and alert channels are in git**: `kuma-config/monitors.json`. After every Argo
  CD sync of this app, the `kuma-config` job (`kuma-config.yaml`) applies it: missing
  monitors are created, existing ones (same name) are overwritten with what's in git.
  Monitors added by hand in the UI are left alone, and removing one from the file doesn't
  delete it in Kuma (delete it in the UI too). History lives in Kuma's database on its
  volume (nightly Longhorn backups).
- **Heartbeat** (`heartbeat.yaml`): every 2 minutes a job reports to healthchecks.io
  whether Kuma is up. healthchecks.io is outside the homelab, so if the cluster or the
  house internet goes down, the reports stop and it alerts by itself.

## Vault

| Path | Keys |
|---|---|
| `secret/k8s/uptime/healthchecks` | `ping-url` (healthchecks.io check, period 2 min) |
| `secret/k8s/uptime/ntfy` | `topic` (long random ntfy.sh topic; anyone who knows it can read the alerts) |
| `secret/k8s/uptime/smtp` | `password` (Proton SMTP token for `noreply@agathla.com`), `to` (where alert emails go) |

Kuma checks the apps behind Authelia directly (their network policies in
`apps/media` and `apps/ente-admin` allow Kuma, on the web UI ports only).
