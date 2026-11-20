#!/bin/bash
# Install the lab clock candidate Fabric from a local wheel directory, refusing
# any wheel whose sha256 differs from requirements-clocklab-candidate.lock.
# usage: install-clocklab-candidate.sh <wheel-dir> [python]
set -euo pipefail
WHEEL_DIR=${1:?wheel directory required}
PY=${2:-python3}
HERE=$(cd "$(dirname "$0")" && pwd)
LOCK="$HERE/requirements-clocklab-candidate.lock"
EXPECTED=$(sed -n 's/^ *--hash=sha256:\([0-9a-f]\{64\}\)$/\1/p' "$LOCK")
[[ ${#EXPECTED} -eq 64 ]] || { echo "lab lock carries no single sha256" >&2; exit 2; }
WHEEL="$WHEEL_DIR/azazel_fabric-0.10.1.dev0-py3-none-any.whl"
[[ -f $WHEEL ]] || { echo "candidate wheel absent: $WHEEL" >&2; exit 2; }
ACTUAL=$("$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$WHEEL")
[[ $ACTUAL == "$EXPECTED" ]] || { echo "candidate wheel sha256 $ACTUAL != locked $EXPECTED; refused" >&2; exit 1; }
# pip re-checks the same hash from the lock and installs nothing else.
"$PY" -m pip install --no-index --no-deps --require-hashes --find-links "$WHEEL_DIR" -r "$LOCK"
echo "installed lab candidate Fabric sha256=$ACTUAL"
