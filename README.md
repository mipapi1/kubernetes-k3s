# kubernetes-k3s

Homelab k3s cluster: three Proxmox VMs that each run the k3s control plane and workloads.

```
kubernetes-k3s/
└── ansible/
    ├── requirements.yml   pinned collections, incl. upstream k3s-io/k3s-ansible (k3s.orchestration)
    ├── site.yml           NFS prep → upstream k3s install → cert-manager, NFS CSI, Longhorn
    ├── inventory.yml      cluster hosts and k3s settings
    ├── group_vars/        secrets looked up from Vault
    ├── roles/             this repo's own roles (cert_manager, nfs, nfs_csi, longhorn)
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

Requires `terraform`, `vault`, `kubectl`, `helm` and Ansible (ansible-core 2.18+, with the `hvac` Python package for the Vault lookups — with pipx: `pipx install ansible-core && pipx inject ansible-core hvac`), and a Vault login at `https://vault.agathla.com`.

**1. Create the VMs** — in the proxmox-infrastructure repo:

```bash
./tf.sh apply
```

After rebuilding VMs, clear their old SSH host keys: `ssh-keygen -R 10.0.20.11` (and `.12`, `.13`).

**2. Install k3s and add-ons** — installs the pinned collections, then k3s, NFS CSI (`nfs-nas` StorageClass) and cert-manager. It reuses your `vault login` token and only prompts for Vault credentials if that has expired:

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
