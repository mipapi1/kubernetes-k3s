#!/bin/bash
# Creates the OpenID Connect secrets in Vault. Nothing is printed or written to disk.
#   secret/k8s/authelia/oidc   hmac-secret, jwks-key (RSA private key that signs the ID
#                              tokens), headlamp-secret-hash (PBKDF2-SHA512 hash of
#                              Headlamp's client secret)
#   secret/k8s/headlamp/oidc   client-secret (the same secret in plain, for Headlamp)
#
#   ./oidc-secrets.sh            # first time
#   ./oidc-secrets.sh --rotate   # replace them: Headlamp/kubectl sessions end, sign in again
#   ./oidc-secrets.sh --rehash   # only re-hash the existing Headlamp secret (no sign-out)
#
# PBKDF2, not argon2id: Authelia checks the client secret on every token request, and
# Headlamp sends a burst of parallel refreshes when its token expires; argon2id's 64 MiB
# per check got Authelia OOM-killed (2026-10-17).
#
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.agathla.com}"
AUTHELIA_PATH="secret/k8s/authelia/oidc"
HEADLAMP_PATH="secret/k8s/headlamp/oidc"

die() { echo "error: $*" >&2; exit 1; }

vault token lookup >/dev/null 2>&1 || die "not logged in to Vault (vault login -method=userpass username=papi)"

# Authelia's PBKDF2 format: $pbkdf2-sha512$<iterations>$<salt>$<key>, adapted base64
# ('.' for '+', no padding); the secret comes from env CLIENT_SECRET
HASH_PY='
import base64, hashlib, os
def ab64(b): return base64.b64encode(b).decode().rstrip("=").replace("+", ".")
def client_hash(secret):
    salt, n = os.urandom(16), 310000
    key = hashlib.pbkdf2_hmac("sha512", secret.encode(), salt, n, 64)
    return f"$pbkdf2-sha512${n}${ab64(salt)}${ab64(key)}"
'

if [ "${1:-}" = "--rehash" ]; then
  CLIENT_SECRET="$(vault kv get -field=client-secret "$HEADLAMP_PATH")" python3 -c "$HASH_PY"'
print(client_hash(os.environ["CLIENT_SECRET"]), end="")' \
    | vault kv patch "$AUTHELIA_PATH" headlamp-secret-hash=- >/dev/null || die "re-hashing failed"
  echo "re-hashed headlamp-secret-hash in $AUTHELIA_PATH"
  exit 0
fi
if [ "${1:-}" != "--rotate" ] && vault kv get "$AUTHELIA_PATH" >/dev/null 2>&1; then
  die "$AUTHELIA_PATH already exists; use --rotate to replace it"
fi

client_secret="$(python3 -c 'import secrets, string; a = string.ascii_letters + string.digits; print("".join(secrets.choice(a) for _ in range(64)), end="")')"
jwks_key="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"
[ -n "$client_secret" ] && [ -n "$jwks_key" ] || die "generating the secrets failed"

# One JSON object on stdin -> all keys of the Authelia entry at once
CLIENT_SECRET="$client_secret" JWKS_KEY="$jwks_key" python3 -c "$HASH_PY"'
import json, secrets, string
a = string.ascii_letters + string.digits
print(json.dumps({
    "hmac-secret": "".join(secrets.choice(a) for _ in range(64)),
    "jwks-key": os.environ["JWKS_KEY"],
    "headlamp-secret-hash": client_hash(os.environ["CLIENT_SECRET"]),
}))
' | vault kv put "$AUTHELIA_PATH" - >/dev/null || die "writing $AUTHELIA_PATH failed"

printf '%s' "$client_secret" | vault kv put "$HEADLAMP_PATH" client-secret=- >/dev/null || die "writing $HEADLAMP_PATH failed"
unset client_secret jwks_key
echo "saved $AUTHELIA_PATH and $HEADLAMP_PATH"
