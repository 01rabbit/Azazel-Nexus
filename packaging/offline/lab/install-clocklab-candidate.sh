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
# --force-reinstall: a different build of the same version must be replaced, not kept.
"$PY" -m pip install --no-index --no-deps --require-hashes --force-reinstall --find-links "$WHEEL_DIR" -r "$LOCK"
# What is on disk must be what the (hash-checked) wheel carries: every file the
# wheel's RECORD lists is compared with the installed file, and nothing else may
# be missing. A kept older build of the same version fails here.
"$PY" - "$WHEEL" <<'PYCHECK'
import base64, csv, hashlib, importlib.metadata as metadata, io, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as wheel:
    record = next(n for n in wheel.namelist() if n.endswith(".dist-info/RECORD"))
    rows = list(csv.reader(io.TextIOWrapper(wheel.open(record), encoding="utf-8")))
dist = metadata.distribution("azazel-fabric")
if dist.version != "0.10.1.dev0":
    raise SystemExit(f"installed azazel-fabric is {dist.version}, not 0.10.1.dev0")
checked = 0
for name, digest, _size in rows:
    if not digest or name.endswith(".dist-info/RECORD"):
        continue
    algo, _, value = digest.partition("=")
    path = dist.locate_file(name)
    try:
        actual = base64.urlsafe_b64encode(hashlib.new(algo, path.read_bytes()).digest()).rstrip(b"=").decode()
    except OSError:
        raise SystemExit(f"installed file missing: {name}")
    if actual != value:
        raise SystemExit(f"installed file differs from the locked wheel: {name}")
    checked += 1
if not checked:
    raise SystemExit("wheel RECORD lists no files")
print(f"verified {checked} installed files against the locked wheel")
PYCHECK
echo "installed lab candidate Fabric sha256=$ACTUAL"
