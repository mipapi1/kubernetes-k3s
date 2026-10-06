# ente

Ente Photos server (museum), migrated from the `ente-prod01` VM. The phone/desktop apps
keep using `https://ente.agathla.com`.

| File | What |
|---|---|
| `museum.yaml` | The API server (official `ghcr.io/ente/server`, pinned by digest to the build the VM ran) and its non-secret config. |
| `postgres.yaml` | Postgres 15.15 on a Longhorn volume. |
| `minio.yaml` | MinIO serving the photos from the NAS (`/volume1/ente`, ~344 GB, not copied). Image republished to `ghcr.io/mipapi1/minio` (MinIO stopped publishing community images). |
| `external-secret.yaml` | DB password and MinIO credentials from Vault `secret/k8s/ente/*`; museum's `credentials.yaml` is rendered from them. |
| `ingress.yaml` | `ente.agathla.com` (API) and `minio.agathla.com` (photo transfers). |

`museum` and `minio` start at `replicas: 0`: two MinIO servers on the same data
directory corrupt it. Postgres runs from the start with an empty database.

## Cutover

1. Stop the stacks on the VM.
2. `pg_dump` the VM's `ente_db` and restore it into the cluster's Postgres.
3. Set `replicas: 1` on `minio` and `museum`, commit, push.
4. Point the DNS overrides `ente`/`minio` at `10.0.20.10` (aliases of the k3s entry).
5. Check: museum `/ping`, MinIO health, then open the Ente app and view/upload a photo.

## Follow-ups

- museum runs with the image's built-in default `key.encryption`, `key.hash` and
  `jwt.secret` (none are set in its config). Rotate them to secrets in Vault — carefully,
  data in Postgres is encrypted with the current ones.
- Replace the weak MinIO root login, and eventually MinIO itself (e.g. Garage).

## Rollback

Set the replicas back to `0` and push, point DNS back at the VM (`10.0.20.28`), start the
stacks on the VM. The VM's Postgres is untouched by the dump.
