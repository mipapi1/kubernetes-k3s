# prvtente

Second (private) Ente Photos server, migrated from the `prvtente-prod01` VM. Same layout
as [`../ente`](../ente), with two differences:

- **Object storage runs on Silo** (`pgsty/silo`), the maintained MinIO fork Ente now uses,
  instead of MinIO. It reads the existing MinIO data directory in place. This instance is
  the test run for switching `ente` to Silo as well.
- **museum runs Ente's newest official image** (2026-09-15). The VM ran a custom build
  (Ente 2026-01-01 with object deletion after 1 minute instead of 45 days); the database
  migrates forward on first start. A custom build can come back later via CI.

Addresses: `https://prvtente.agathla.com` (API), `https://prvtenteminio.agathla.com`
(photo transfers). Secrets from Vault `secret/k8s/prvtente/*`.

`museum` and `minio` (Silo) start at `replicas: 0`: the VM's MinIO and Silo must never run
on the same data directory at once. Postgres runs from the start with an empty database.

## Cutover

1. Stop the stacks on the VM.
2. `pg_dump` the VM's `ente_db` and restore it into the cluster's Postgres.
3. Set `replicas: 1` on `minio` and `museum`, commit, push.
4. DNS overrides `prvtente`/`prvtenteminio` → `10.0.20.10` (aliases of the k3s entry).
5. Check: Silo health and logs, museum `/ping` and migrations, then the Ente app.

## Rollback

Silo may write objects in a newer format than the VM's MinIO can read, and museum migrates
the database forward, so rolling back means: replicas `0`, DNS back to `10.0.20.69`, and
the VM's own untouched Postgres. Objects uploaded after cutover would not be readable by
the old MinIO.
