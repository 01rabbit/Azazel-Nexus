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
# be missing, and nothing may be extra. A kept older build of the same version fails here.
"$PY" - "$WHEEL" <<'PYCHECK'
import base64, csv, hashlib, importlib.metadata as metadata, io, os, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as wheel:
    record = next(n for n in wheel.namelist() if n.endswith(".dist-info/RECORD"))
    rows = list(csv.reader(io.TextIOWrapper(wheel.open(record), encoding="utf-8")))
dist = metadata.distribution("azazel-fabric")
# The two trees that are scanned must be real directories: a link would make every
# file read below come from somewhere else. Refused before any installed file is read.
dist_info = record.rsplit("/", 1)[0]
root = dist.locate_file("")
for top in ("azazel_fabric", dist_info):
    if os.path.islink(os.path.join(root, top)):
        raise SystemExit(f"{top} is a symbolic link")
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
# Nothing else may sit inside the package or the distribution's own dist-info:
# a file an earlier build left behind (an old .py) is not in this wheel's RECORD.
# Reported, never deleted. Allowed besides RECORD: the INSTALLER and REQUESTED
# markers pip writes, and __pycache__/*.pyc that Python creates on import.
listed = {name for name, _digest, _size in rows}
listed |= {f"{dist_info}/RECORD", f"{dist_info}/INSTALLER", f"{dist_info}/REQUESTED"}
root = dist.locate_file("")
# Residual risk, accepted: a stale __pycache__/*.pyc (unchecked hash-based, or with a
# matching mtime and size) of a module that is listed can still be loaded.
extra, problems = [], []
def rel_of(path):
    return os.path.relpath(path, root).replace(os.sep, "/")
def walk_error(error):
    problems.append(f"cannot scan {rel_of(error.filename) if error.filename else error}: {error.strerror or error}")
for top in ("azazel_fabric", dist_info):
    start = os.path.join(root, top)
    if os.path.islink(start):
        problems.append(f"{top} is a symbolic link")
        continue
    for folder, dirs, files in os.walk(start, onerror=walk_error, followlinks=False):
        for name in dirs:
            if os.path.islink(os.path.join(folder, name)):
                problems.append(f"{rel_of(os.path.join(folder, name))} is a symbolic link to a directory")
        for file in files:
            rel = rel_of(os.path.join(folder, file))
            if rel in listed:
                continue
            if file.endswith(".pyc") and os.path.basename(folder) == "__pycache__":
                continue
            extra.append(rel)
if extra:
    problems.append("installed files not in the locked wheel's RECORD (left in place): " + ", ".join(sorted(extra)))
if problems:
    raise SystemExit("; ".join(problems))
print(f"verified {checked} installed files against the locked wheel")
PYCHECK
echo "installed lab candidate Fabric sha256=$ACTUAL"
