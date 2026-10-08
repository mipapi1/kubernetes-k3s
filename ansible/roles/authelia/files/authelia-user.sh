#!/bin/bash
# Manage Authelia users. They live in Vault (secret/k8s/authelia/users, key `users`, one
# JSON object); External Secrets syncs them to Authelia within about a minute. Passwords
# are stored only as argon2id hashes (hash-password.sh) and never printed.
#
#   authelia-user.sh list
#   authelia-user.sh add <user> --email <email> [--name "Display Name"] [--groups app-ente-admin,...]
#   authelia-user.sh groups <user> +app-seerr -app-ente-admin     # add/remove groups
#   authelia-user.sh password <user>                              # set a new password
#   authelia-user.sh disable <user> | enable <user> | remove <user>
#   authelia-user.sh migrate                                      # one-time: old papi-* keys -> users
#
# Groups: `admins` = everything; `app-<name>` = that app (see authelia_apps in defaults/main.yml).
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.agathla.com}"
VAULT_PATH="secret/k8s/authelia/users"
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }
valid_user() { [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || die "username must be lowercase letters, digits, . _ - (got '$1')"; }
valid_group() { [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || die "invalid group '$1'"; }

read_users() {  # current JSON; {} only if the secret exists without a `users` key yet
  local raw
  raw="$(vault kv get -format=json "$VAULT_PATH")" || die "can't read $VAULT_PATH from Vault (logged in? vault login -method=userpass username=papi)"
  printf '%s' "$raw" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"].get("users") or "{}")'
}
# Run a small Python edit on the users JSON ($1 = code using dict `u` and sys.argv[1:]) and
# save the result. Nothing is written if the edit fails, and never without an active admin
# (so a typo can't wipe the users or lock everyone out).
edit() {
  local code="$1" current out; shift
  current="$(read_users)"
  out="$(printf '%s' "$current" | python3 -c "
import json, sys
u = json.load(sys.stdin)
$code
if not any('admins' in x.get('groups', []) and not x.get('disabled') for x in u.values()):
    sys.exit('refusing to save: no active user in group admins would be left')
print(json.dumps(u, sort_keys=True))
" "$@")" || die "nothing changed"
  [ -n "$out" ] || die "nothing changed (empty result)"
  printf '%s' "$out" | vault kv patch "$VAULT_PATH" users=- >/dev/null || die "writing to Vault failed"
  echo "saved; Authelia picks it up within about a minute"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  list)
    read_users | python3 -c '
import json, sys
u = json.load(sys.stdin)
print("%-14s %-18s %-30s %-9s %s" % ("USER", "NAME", "EMAIL", "STATUS", "GROUPS"))
for name in sorted(u):
    x = u[name]
    print("%-14s %-18s %-30s %-9s %s" % (name, x.get("displayname", ""), x.get("email", ""),
          "disabled" if x.get("disabled") else "active", ", ".join(x.get("groups", []))))
'
    ;;
  add)
    user="${1:-}"; shift || true; valid_user "$user"
    email=""; name="$user"; groups=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --email) email="$2"; shift 2;; --name) name="$2"; shift 2;; --groups) groups="$2"; shift 2;;
        *) die "unknown option $1";;
      esac
    done
    [[ "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "--email is required (used for 2FA codes and, in ente-admin, to match the user's own Ente account)"
    for g in ${groups//,/ }; do valid_group "$g"; done
    read_users | python3 -c 'import json,sys; sys.exit(1 if sys.argv[1] in json.load(sys.stdin) else 0)' "$user" || die "user '$user' already exists"
    echo "Set a password for $user (min. 12 characters; share it with them securely):"
    hash="$("$HERE/hash-password.sh")"
    HASH="$hash" edit '
import os
user, email, name, groups = sys.argv[1:5]
u[user] = {"displayname": name, "email": email.lower(), "password": os.environ["HASH"],
           "groups": [g for g in groups.replace(",", " ").split() if g], "disabled": False}' \
      "$user" "$email" "$name" "$groups"
    ;;
  groups)
    user="${1:-}"; shift || true; valid_user "$user"; [ $# -gt 0 ] || die "give +group and/or -group"
    for g in "$@"; do [[ "$g" =~ ^[+-] ]] || die "use +group or -group (got '$g')"; valid_group "${g:1}"; done
    edit '
user = sys.argv[1]
if user not in u: sys.exit("no such user: " + user)
gs = u[user].setdefault("groups", [])
for g in sys.argv[2:]:
    if g[0] == "+" and g[1:] not in gs: gs.append(g[1:])
    if g[0] == "-" and g[1:] in gs: gs.remove(g[1:])
print("groups of %s: %s" % (user, ", ".join(gs) or "(none)"), file=sys.stderr)' "$user" "$@"
    ;;
  password)
    user="${1:-}"; valid_user "$user"
    read_users | python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in json.load(sys.stdin) else 1)' "$user" || die "no such user: $user"
    hash="$("$HERE/hash-password.sh")"
    HASH="$hash" edit 'import os; u[sys.argv[1]]["password"] = os.environ["HASH"]' "$user"
    ;;
  disable|enable)
    user="${1:-}"; valid_user "$user"
    edit '
if sys.argv[1] not in u: sys.exit("no such user: " + sys.argv[1])
u[sys.argv[1]]["disabled"] = sys.argv[2] == "disable"' "$user" "$cmd"
    ;;
  remove)
    user="${1:-}"; valid_user "$user"
    read -r -p "Remove user '$user' for good? [y/N] " ok < /dev/tty; [ "$ok" = "y" ] || die "aborted"
    edit '
if sys.argv[1] not in u: sys.exit("no such user: " + sys.argv[1])
del u[sys.argv[1]]' "$user"
    ;;
  migrate)
    read_users | python3 -c 'import json,sys; sys.exit(1 if json.load(sys.stdin) else 0)' || die "users already exists in Vault; nothing to migrate"
    email="$(vault kv get -field=papi-email "$VAULT_PATH")"
    hash="$(vault kv get -field=papi-password-hash "$VAULT_PATH")"
    EMAIL="$email" HASH="$hash" edit '
import os
u["papi"] = {"displayname": "papi", "email": os.environ["EMAIL"].lower(), "password": os.environ["HASH"],
             "groups": ["admins"], "disabled": False}'
    ;;
  *)
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
