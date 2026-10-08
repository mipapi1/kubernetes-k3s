# kubernetes-k3s

Homelab k3s cluster: three Proxmox VMs that each run the k3s control plane and workloads.

```
kubernetes-k3s/
├── apps/                  GitOps: each folder = one app, deployed by Argo CD
└── ansible/
    ├── requirements.yml   pinned collections, incl. upstream k3s-io/k3s-ansible (k3s.orchestration)
    ├── site.yml           NFS prep → upstream k3s install → NFS CSI, Longhorn, Argo CD, External Secrets, CloudNativePG, Forgejo
    ├── inventory.yml      cluster hosts and k3s settings
    ├── group_vars/        secrets looked up from Vault
    ├── manifests/         applied by k3s itself (Traefik config, CoreDNS override for *.agathla.com)
    ├── roles/             this repo's own roles (nfs, nfs_csi, longhorn, argocd, external_secrets, cloudnative_pg, forgejo, cert_manager)
    └── deploy.sh
```

The k3s install itself comes from the upstream [k3s-io/k3s-ansible](https://github.com/k3s-io/k3s-ansible) collection; this repo only adds its own roles around it.

The VMs themselves are created by the separate [proxmox-infrastructure](https://github.com/mipapi1/proxmox-infrastructure) repo.

## Cluster

| Node | IP | Proxmox host | Size |
|---|---|---|---|
| k3s-prod01 | 10.0.20.11 | proxmox01 | 4 vCPU / 8 GB / 100 GB |
| k3s-prod02 | 10.0.20.12 | proxmox02 | 4 vCPU / 8 GB / 100 GB |
| k3s-prod03 | 10.0.20.13 | proxmox03 | 4 vCPU / 8 GB / 100 GB |

All three are k3s servers (embedded etcd, tolerates one node failure) and also run workloads — there are no dedicated agents.

## Deploying from scratch

Requires `terraform`, `vault`, `kubectl`, `helm` and Ansible (ansible-core 2.18+, with the `hvac`, `kubernetes` and `netaddr` Python packages — with pipx: `pipx install ansible-core && pipx inject ansible-core hvac kubernetes netaddr`), and a Vault login at `https://vault.agathla.com`.

**1. Create the VMs** — in the proxmox-infrastructure repo:

```bash
./tf.sh apply
```

After rebuilding VMs, clear their old SSH host keys: `ssh-keygen -R 10.0.20.11` (and `.12`, `.13`).

**2. Install k3s and add-ons** — installs the pinned collections, then k3s, NFS CSI (`nfs-nas` StorageClass), Longhorn (default StorageClass, backups to the NAS) and Argo CD. Chart versions are pinned in each role's `defaults/main.yml`. It reuses your `vault login` token and only prompts for Vault credentials if that has expired:

```bash
cd ansible
./deploy.sh
```

Extra arguments go to `ansible-playbook`, e.g. `./deploy.sh --check` for a dry run. Upstream's other playbooks run the same way: `ansible-playbook k3s.orchestration.upgrade` / `.reset` / `.reboot`.

## Updating k3s-ansible

Upstream is pinned by tag in `ansible/requirements.yml`. To update, check the [releases](https://github.com/k3s-io/k3s-ansible/tags), bump `version:`, then:

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml --force
ansible-playbook site.yml --syntax-check
```

## Secrets

Nothing secret is committed. Secrets live in Vault (`secret/` KV v2):

| Path | Used by |
|---|---|
| `secret/proxmox/terraform` | proxmox-infrastructure `tf.sh` (Proxmox API token) |
| `secret/k3s/cluster` | Ansible (k3s cluster token) |
| `secret/cloudflare` | Ansible (cert-manager DNS-01 token) |
| `secret/k8s/*` | apps in the cluster, via External Secrets Operator (read-only) |

### Apps: secrets from Vault (External Secrets Operator)

The `vault` ClusterSecretStore logs in to Vault with ESO's Kubernetes service account
(Kubernetes auth — no Vault token stored in the cluster) and may only read `secret/k8s/*`.
An app requests a secret like this:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: myapp, namespace: myapp}
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: ClusterSecretStore, name: vault}
  target: {name: myapp-secrets}            # Kubernetes Secret that gets created
  data:
    - secretKey: DB_PASSWORD
      remoteRef: {key: k8s/myapp, property: db-password}
```

One-time Vault setup (as root; redo `auth/kubernetes/config` if the cluster is rebuilt, since its CA changes):

```bash
vault auth enable kubernetes
kubectl --context homelab config view --raw --minify \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/k3s-ca.crt
vault write auth/kubernetes/config kubernetes_host=https://10.0.20.10:6443 \
  kubernetes_ca_cert=@/tmp/k3s-ca.crt disable_local_ca_jwt=true
vault policy write k8s-external-secrets - <<'POLICY'
path "secret/data/k8s/*"     { capabilities = ["read"] }
path "secret/metadata/k8s/*" { capabilities = ["read", "list"] }
POLICY
vault write auth/kubernetes/role/external-secrets \
  bound_service_account_names=external-secrets bound_service_account_namespaces=external-secrets \
  policies=k8s-external-secrets ttl=1h
```

Re-deploy a single add-on without re-running the k3s install (which restarts every server):
`./deploy.sh --tags external_secrets` (tags: `nfs`, `nfs_csi`, `longhorn`, `argocd`, `external_secrets`, `cloudnative_pg`, `forgejo`, `authelia`).

## Forgejo (git server)

https://git.agathla.com, installed by the `forgejo` role rather than through Argo CD, because
Argo CD reads the apps from it (a broken Forgejo must not be needed to fix Forgejo). Git over
HTTPS only; sign-in is required to see anything and self-registration is off.

- **Database:** PostgreSQL run by the CloudNativePG operator (`cloudnative_pg` role), defined
  in `roles/forgejo/files/postgres.yaml`.
- **Accounts:** `forgejo-admin` is the break-glass admin; its password is re-applied from Vault
  on every start, so change it in Vault, not in the UI. Daily work uses a normal account.
- **Secrets** (all generated, never in git):

| Vault path | Keys |
|---|---|
| `secret/k8s/forgejo/admin` | `username`, `password` |
| `secret/k8s/forgejo/postgres` | `password` (the operator applies a new one by itself) |
| `secret/k8s/forgejo/app` | `secret-key`, `internal-token`, `jwt-secret`, `lfs-jwt-secret` |
| `secret/k8s/argocd/forgejo` | `token`: Argo CD's read-only access (restricted Forgejo user `argocd`, read on this repo) |

The `app` keys encrypt stored credentials (2FA, mirror tokens), so a restore needs them and
the volumes. Don't regenerate them on a running instance.

## Authelia (login portal)

https://auth.agathla.com, installed by the `authelia` role (`./deploy.sh --tags authelia`).
One login (password + 2FA: authenticator app or passkey) in front of web UIs that don't
have a good login of their own. An app is protected by adding Authelia's Traefik
forwardAuth middleware to its Ingress; access rules live in the role's template
(default: deny; group `admins` gets every protected app with 2FA).

Users are defined in Vault, passwords only as argon2id hashes; password change/reset
in the portal is off. Set or change a password:

```bash
ansible/roles/authelia/files/hash-password.sh | vault kv patch secret/k8s/authelia/users papi-password-hash=-
```

| Vault path | Keys |
|---|---|
| `secret/k8s/authelia/main` | `jwt-secret`, `session-secret`, `storage-encryption-key` (generated), `smtp-password` (Proton SMTP token) |
| `secret/k8s/authelia/users` | `papi-email`, `papi-password-hash` |

## Apps (GitOps with Argo CD)

Argo CD (https://argocd.agathla.com, user `admin`) watches `apps/` on the `main` branch of this
repo **in Forgejo** (`argocd_apps_repo` in `inventory.yml`, read over Forgejo's in-cluster Service).
GitHub only holds a push mirror: push to Forgejo, never to GitHub.
**Each folder under `apps/` becomes an Application** named after the folder, deployed into a
namespace of the same name (created automatically). Plain manifests or a `kustomization.yaml`
both work.

- **Add an app:** commit `apps/<name>/…` and push. Argo CD picks it up within ~3 minutes.
- **Change an app:** commit and push. Manual `kubectl` edits are reverted (self-heal).
- **Remove a resource:** delete it from the folder; Argo CD prunes it from the cluster.
- **Remove a whole app:** deleting its folder removes the Application but **keeps** its
  resources and data (`preserveResourcesOnDeletion`). Clean up deliberately with
  `kubectl delete namespace <name>`.
- **Expose it:** an Ingress with `ingressClassName: traefik` and host `<name>.agathla.com`,
  plus a DNS override `<name>.agathla.com → 10.0.20.10` in OPNsense (Unbound).
- **Secrets:** an `ExternalSecret` reading `secret/k8s/<name>` from Vault (see below).

The ApplicationSet is created by the `argocd` role (`./deploy.sh --tags argocd`).

Initial admin password (change it after the first login, then delete the secret):

```bash
kubectl --context homelab -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d; echo
```
