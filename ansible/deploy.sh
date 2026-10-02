#!/bin/bash
# Runs site.yml. Vault lookups use your `vault login` token, so no credentials
# are passed on the command line.
#
# Usage: ./deploy.sh [ansible-playbook args]   e.g. ./deploy.sh --check
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.agathla.com}"
# macOS: without this, Ansible workers crash ("worker was found in a dead state")
# when the Vault lookups (hvac/requests) run in forked processes.
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

cd "$(dirname "$0")"

# Reuse the existing Vault login if it can still read the k3s secret; otherwise log in.
if ! vault kv get -field=token secret/k3s/cluster >/dev/null 2>&1; then
  read -p "Vault Username: " VAULT_USER
  vault login -method=userpass -no-print username="$VAULT_USER"
fi

# Install/refresh pinned collections (no-op when already present)
ansible-galaxy collection install -r requirements.yml >/dev/null

exec ansible-playbook site.yml "$@"
