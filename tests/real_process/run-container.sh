#!/usr/bin/env bash
set -euo pipefail
umask 022

python -B - <<'PY'
from pathlib import Path
import hashlib
import re

wheel = Path('/wheel/azazel_mio-0.1.0+git.c31c244-py3-none-any.whl')
locks = [
    Path('/src/packaging/offline/requirements-aarch64-cp313.lock'),
    Path('/src/packaging/offline/requirements-x86_64-cp313.lock'),
]
digests = []
for lock in locks:
    match = re.search(
        r'(?m)^azazel-mio==[^\n]+\n\s+--hash=sha256:([0-9a-f]{64})\s*$',
        lock.read_text(encoding='utf-8'),
    )
    if match is None:
        raise SystemExit(f'MIO wheel digest missing from {lock}')
    digests.append(match.group(1))
if len(set(digests)) != 1:
    raise SystemExit('Debian target locks disagree on the MIO wheel digest')
expected = digests[0]
actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit('MIO wheel digest mismatch')
print(f'verified MIO wheel digest against both Debian locks: {actual}')
PY

SCRATCH_SRC=$(mktemp -d /tmp/nxs-real-process.XXXXXX)
cleanup() {
  rm -rf -- "$SCRATCH_SRC"
}
trap cleanup EXIT

cp -a /src/. "$SCRATCH_SRC/"
chmod 0755 "$SCRATCH_SRC"
rm -rf -- "$SCRATCH_SRC/.venv" "$SCRATCH_SRC/.pytest_cache" "$SCRATCH_SRC/runtime/.pytest_cache"
python -m pip install --no-index --find-links=/wheels -e "${SCRATCH_SRC}[dev]" -e "$SCRATCH_SRC/runtime" \
  /wheel/azazel_mio-0.1.0+git.c31c244-py3-none-any.whl

# The test's Linux SO_PEERCRED run uses these ordinary system identities. They
# exist only in this --rm container; the source tree's principal policy is
# unchanged.
groupadd --gid 20001 azknowledge
groupadd --gid 20002 azmio
groupadd --gid 20003 azmioentry
groupadd --gid 20004 azazel-operator
groupadd --gid 20005 azknowledge-read
groupadd --gid 20006 azmission-read
groupadd --gid 20007 azmio-advise
groupadd --gid 20008 azoperator
groupadd --gid 20009 azexplain
groupadd --gid 20010 azintake
groupadd --gid 20011 azedge
groupadd --gid 20012 azincident-read
groupadd --gid 20013 azaudit
groupadd --gid 20014 azaudit-submit
useradd --uid 20001 --gid azknowledge --no-create-home --shell /usr/sbin/nologin azknowledge
useradd --uid 20002 --gid azmio --no-create-home --shell /usr/sbin/nologin azmio
useradd --uid 20003 --gid azmioentry --no-create-home --shell /usr/sbin/nologin azmioentry
useradd --uid 20004 --gid azoperator --no-create-home --shell /usr/sbin/nologin azoperator
useradd --uid 20009 --gid azexplain --no-create-home --shell /usr/sbin/nologin azexplain
useradd --uid 20010 --gid azintake --no-create-home --shell /usr/sbin/nologin azintake
useradd --uid 20011 --gid azedge --no-create-home --shell /usr/sbin/nologin azedge
useradd --uid 20013 --gid azaudit --no-create-home --shell /usr/sbin/nologin azaudit
usermod --append --groups azknowledge-read,azmission-read azmio
usermod --append --groups azazel-operator azmioentry
usermod --append --groups azazel-operator azoperator
usermod --append --groups azmio-advise azexplain
usermod --append --groups azincident-read azintake

cd "$SCRATCH_SRC"
PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -q -p no:cacheprovider \
  tests/unit/test_mio_fast_assistance.py \
  tests/unit/test_mio_reference.py \
  tests/unit/test_knowledge_lookup.py \
  tests/unit/test_real_knowledge_lite_fixture.py \
  tests/unit/test_incident_explain.py \
  tests/real_process/test_mio_process_integration.py

# Exercise the service's fixed degraded response with the shared package
# absent. The positive adapter unit tests above intentionally need the wheel.
python -m pip uninstall --yes azazel-mio >/dev/null
PYTHONDONTWRITEBYTECODE=1 python -B - <<'PY'
import importlib.util
if importlib.util.find_spec('azazel_mio') is not None:
    raise SystemExit('azazel_mio unexpectedly remains installed')
print('confirmed shared MIO package absent for degraded process phase')
PY
PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -q -p no:cacheprovider \
  tests/real_process/test_mio_process_integration.py
