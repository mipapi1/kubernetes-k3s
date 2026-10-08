#!/bin/bash
# Prints an argon2id hash (Authelia's default parameters) of a password typed at the
# prompt. The password is never echoed, stored or passed as an argument.
#
#   ./hash-password.sh | vault kv patch secret/k8s/authelia/users papi-password-hash=-
#
# Uses a private Python venv with argon2-cffi in ~/.cache (created on first use).
set -euo pipefail

venv="${HOME}/.cache/authelia-hash-venv"
if [ ! -x "${venv}/bin/python" ]; then
  python3 -m venv "${venv}" >&2
  "${venv}/bin/pip" install --quiet argon2-cffi >&2
fi

read -rs -p "Password: " pw < /dev/tty; echo >&2
read -rs -p "Repeat:   " pw2 < /dev/tty; echo >&2
[ "${pw}" = "${pw2}" ] || { echo "Passwords don't match" >&2; exit 1; }
[ "${#pw}" -ge 12 ] || { echo "Use at least 12 characters" >&2; exit 1; }

# Authelia defaults: argon2id, 3 iterations, 64 MiB, parallelism 4, 32-byte key, 16-byte salt
PW="${pw}" "${venv}/bin/python" -c '
import os
from argon2 import PasswordHasher, Type
print(PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16, type=Type.ID).hash(os.environ["PW"]), end="")
'
