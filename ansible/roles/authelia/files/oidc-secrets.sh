#!/bin/bash
# Creates the OpenID Connect secrets in Vault. Nothing is printed or written to disk.
#   secret/k8s/authelia/oidc   hmac-secret, jwks-key (RSA private key that signs the ID
#                              tokens), headlamp-secret-hash (argon2id hash of Headlamp's
#                              client secret)
#   secret/k8s/headlamp/oidc   client-secret (the same secret in plain, for Headlamp)
#
#   ./oidc-secrets.sh            # first time
#   ./oidc-secrets.sh --rotate   # replace them: Headlamp/kubectl sessions end, sign in again
#
# Uses the same private Python venv as hash-password.sh.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.agathla.com}"
AUTHELIA_PATH="secret/k8s/authelia/oidc"
HEADLAMP_PATH="secret/k8s/headlamp/oidc"

die() { echo "error: $*" >&2; exit 1; }

vault token lookup >/dev/null 2>&1 || die "not logged in to Vault (vault login -method=userpass username=papi)"
if [ "${1:-}" != "--rotate" ] && vault kv get "$AUTHELIA_PATH" >/dev/null 2>&1; then
  die "$AUTHELIA_PATH already exists; use --rotate to replace it"
fi

venv="${HOME}/.cache/authelia-hash-venv"
if [ ! -x "${venv}/bin/python" ]; then
  python3 -m venv "${venv}" >&2
  "${venv}/bin/pip" install --quiet argon2-cffi >&2
fi

client_secret="$("${venv}/bin/python" -c 'import secrets, string; a = string.ascii_letters + string.digits; print("".join(secrets.choice(a) for _ in range(64)), end="")')"
jwks_key="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"
[ -n "$client_secret" ] && [ -n "$jwks_key" ] || die "generating the secrets failed"

# One JSON object on stdin -> all keys of the Authelia entry at once
CLIENT_SECRET="$client_secret" JWKS_KEY="$jwks_key" "${venv}/bin/python" -c '
import json, os, secrets, string
from argon2 import PasswordHasher, Type
a = string.ascii_letters + string.digits
print(json.dumps({
    "hmac-secret": "".join(secrets.choice(a) for _ in range(64)),
    "jwks-key": os.environ["JWKS_KEY"],
    # Authelia defaults: argon2id, 3 iterations, 64 MiB, parallelism 4
    "headlamp-secret-hash": PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                                           hash_len=32, salt_len=16, type=Type.ID).hash(os.environ["CLIENT_SECRET"]),
}))
' | vault kv put "$AUTHELIA_PATH" - >/dev/null || die "writing $AUTHELIA_PATH failed"

printf '%s' "$client_secret" | vault kv put "$HEADLAMP_PATH" client-secret=- >/dev/null || die "writing $HEADLAMP_PATH failed"
unset client_secret jwks_key
echo "saved $AUTHELIA_PATH and $HEADLAMP_PATH"
