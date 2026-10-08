# ente-admin

Read-only dashboard for the `ente` and `prvtente` instances: per account the email,
storage used/quota, file count and size, albums, trash, account and plan dates, login
security (2FA / email codes), uploads per day, whether it is uploading right now, and
its devices (phone model, OS, Ente version, desktop or web) with their last activity.

https://ente-admin.agathla.com (DNS alias of the k3s entry). Login is Authelia (password +
2FA, group `admins`) through Traefik's forwardAuth; a NetworkPolicy lets only Traefik reach
the pod, so the login can't be bypassed.

Not visible by design: file types, names, dates, places. Ente encrypts them end to end;
the server only knows sizes and when files were added or changed. Real client IPs aren't
recorded either (museum only sees the proxies).

## Database access

`app.py` connects to each instance's Postgres as `ente_dashboard`, which can only read
these tables/columns (no session tokens, no file keys):

```sql
CREATE ROLE ente_dashboard LOGIN PASSWORD '<from Vault>';
GRANT CONNECT ON DATABASE ente_db TO ente_dashboard;
GRANT USAGE ON SCHEMA public TO ente_dashboard;
GRANT SELECT ON users, subscriptions, usage, trash TO ente_dashboard;
GRANT SELECT (owner_id, is_deleted) ON collections TO ente_dashboard;
GRANT SELECT (owner_id, updation_time, info) ON files TO ente_dashboard;
GRANT SELECT (user_id, app, user_agent, creation_time, last_used_at, is_deleted) ON tokens TO ente_dashboard;
```

## Vault `secret/k8s/ente-admin`

| Key | |
|---|---|
| `ente-db-password`, `prvtente-db-password` | password of `ente_dashboard` on each instance |
| `key-encryption` | museum's `key.encryption` (decrypts account emails) |

The Python libraries are installed at pod start (pinned versions) until the dashboard
gets its own image from Forgejo CI.
