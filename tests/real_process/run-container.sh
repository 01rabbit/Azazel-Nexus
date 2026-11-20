#!/usr/bin/env bash
set -euo pipefail
umask 022

: "${NEXUS_EXPECTED_HEAD:?fixed Nexus source commit required by run-docker.sh}"
: "${KNOWLEDGE_EXPECTED_HEAD:?fixed Knowledge source commit required by run-docker.sh}"
# Fabric input. Default is the stable v0.10.0 tag wheel (unchanged path). The
# lab candidate is a separate input: FABRIC_PROFILE=candidate with the wheel
# name, its sha256 and the expected version passed in (run-docker.sh).
FABRIC_PROFILE=${FABRIC_PROFILE:-stable}
if [[ "$FABRIC_PROFILE" == candidate ]]; then
  : "${FABRIC_WHEEL_NAME:?candidate profile needs FABRIC_WHEEL_NAME}"
  : "${FABRIC_WHEEL_SHA256:?candidate profile needs FABRIC_WHEEL_SHA256}"
  : "${FABRIC_EXPECTED_VERSION:?candidate profile needs FABRIC_EXPECTED_VERSION}"
else
  FABRIC_WHEEL_NAME=azazel_fabric-0.10.0-py3-none-any.whl
  FABRIC_WHEEL_SHA256=b22356fd672cd60471606d3a7b73ccdba99091e680fedd854381a29d76e21424
  FABRIC_EXPECTED_VERSION=0.10.0
fi
export FABRIC_PROFILE FABRIC_WHEEL_NAME FABRIC_WHEEL_SHA256 FABRIC_EXPECTED_VERSION
printf 'fabric profile=%s wheel=%s\n' "$FABRIC_PROFILE" "$FABRIC_WHEEL_NAME"
printf 'fixed source heads: Nexus=%s Knowledge=%s\n' \
  "$NEXUS_EXPECTED_HEAD" "$KNOWLEDGE_EXPECTED_HEAD"

python -B - <<'PY'
from pathlib import Path
import hashlib
import re

wheel = Path('/wheel/azazel_mio-0.1.0.dev20261108+gitguidance8-py3-none-any.whl')
import os
fabric_wheel = Path('/fabric-wheel') / os.environ['FABRIC_WHEEL_NAME']
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
fabric_expected = os.environ['FABRIC_WHEEL_SHA256']
fabric_actual = hashlib.sha256(fabric_wheel.read_bytes()).hexdigest()
if fabric_actual != fabric_expected:
    raise SystemExit('Fabric Knowledge Context contract wheel digest mismatch')
print(f'verified Fabric {os.environ["FABRIC_EXPECTED_VERSION"]} wheel digest: {fabric_actual}')
if os.environ['FABRIC_PROFILE'] == 'candidate':
    for lock in locks:
        if fabric_expected not in lock.read_text(encoding='utf-8'):
            raise SystemExit(f'candidate Fabric digest absent from {lock}')
    print('candidate Fabric digest matches both Nexus offline locks')
PY

SCRATCH_SRC=$(mktemp -d /tmp/nxs-real-process.XXXXXX)
SCRATCH_KNOWLEDGE=$(mktemp -d /tmp/knowledge-real-process.XXXXXX)
cleanup() {
  if [[ -d /tmp/fabric-load && -d /out ]]; then cp -a /tmp/fabric-load/. /out/ 2>/dev/null || true; fi
  rm -rf -- "$SCRATCH_SRC"
  rm -rf -- "$SCRATCH_KNOWLEDGE"
}
trap cleanup EXIT

cp -a /src/. "$SCRATCH_SRC/"
chmod 0755 "$SCRATCH_SRC"
rm -rf -- "$SCRATCH_SRC/.venv" "$SCRATCH_SRC/.pytest_cache" "$SCRATCH_SRC/runtime/.pytest_cache"
cp -a /knowledge/. "$SCRATCH_KNOWLEDGE/"
chmod 0755 "$SCRATCH_KNOWLEDGE"
rm -rf -- "$SCRATCH_KNOWLEDGE/.venv" "$SCRATCH_KNOWLEDGE/.pytest_cache"
export KNOWLEDGE_TEST_SRC="$SCRATCH_KNOWLEDGE"
python -m pip install --no-index --find-links=/wheels --find-links=/fabric-wheel \
  -e "${SCRATCH_SRC}[dev]" -e "$SCRATCH_SRC/runtime" \
  /wheel/azazel_mio-0.1.0.dev20261108+gitguidance8-py3-none-any.whl \
  "/fabric-wheel/$FABRIC_WHEEL_NAME" \
  fastapi uvicorn pydantic PyYAML idna PyNaCl httpx

if [[ "$FABRIC_PROFILE" == candidate ]]; then
  # Knowledge's `api-context-candidate` extra (never the stable `api` extra).
  # Its Fabric requirement is a git URL, which cannot resolve offline, so the
  # pinned wheel above stands in for it; the other extra members are installed
  # by name and the extra's pin is checked against the Nexus pin.
  python - <<'PYEXTRA'
import re, pathlib, os
k = pathlib.Path(os.environ['KNOWLEDGE_TEST_SRC'], 'pyproject.toml').read_text()
n = pathlib.Path('/src/pyproject.toml').read_text()
extra = re.search(r'(?ms)^api-context-candidate = \[(.*?)^\]', k).group(1)
pin = re.search(r'Azazel-Fabric\.git@([0-9a-f]{40})', extra).group(1)
assert pin in n, 'Knowledge candidate extra and Nexus fabric extra pin different Fabric commits'
print('api-context-candidate Fabric pin', pin, 'equals the Nexus fabric extra pin')
PYEXTRA
  python -m pip install --no-index --no-deps --find-links=/wheels -e "$SCRATCH_KNOWLEDGE"
fi
if [[ "$FABRIC_PROFILE" == candidate || "${FABRIC_LOAD_RECORD:-0}" == 1 ]]; then
  # Test-only hook: every process that imports azazel_fabric records the
  # version, file, RECORD check, direct_url and wheel hash it actually loaded.
  mkdir -p /tmp/fabric-load && chmod 1777 /tmp/fabric-load
  python - <<'PYEXPECT'
import json, os
json.dump({"wheel_path": "/fabric-wheel/" + os.environ["FABRIC_WHEEL_NAME"],
           "wheel_sha256": os.environ["FABRIC_WHEEL_SHA256"],
           "version": os.environ["FABRIC_EXPECTED_VERSION"], "profile": os.environ["FABRIC_PROFILE"]},
          open("/tmp/fabric-load/expect.json", "w"))
PYEXPECT
  SP=$(python -c 'import sysconfig;print(sysconfig.get_path("purelib"))')
  cp "$SCRATCH_SRC/tests/real_process/_fabric_load_hook/_az_fabric_load_hook.py" "$SP/"
  printf 'import _az_fabric_load_hook; _az_fabric_load_hook.install()\n' > "$SP/az_fabric_load_hook.pth"
  chmod 0644 "$SP/_az_fabric_load_hook.py" "$SP/az_fabric_load_hook.pth"
fi

# Verify the installed distribution and import come from this environment's site-packages.
python -I -B - <<'PYVERIFY'
import importlib.metadata as metadata
import os
_fab = metadata.version('azazel-fabric')
assert _fab == os.environ['FABRIC_EXPECTED_VERSION'], _fab
print('installed azazel-fabric', _fab)
import pathlib
import sysconfig
import azazel_mio
from azazel_mio.playbook import PROMPT_TEMPLATE_VERSION

dist = metadata.distribution('azazel-mio')
origin = pathlib.Path(azazel_mio.__file__).resolve()
site = pathlib.Path(sysconfig.get_path('purelib')).resolve()
dist_root = pathlib.Path(dist.locate_file('')).resolve()
assert dist.version == '0.1.0.dev20261108+gitguidance8'
assert PROMPT_TEMPLATE_VERSION == '1.9.0'
assert dist_root == site and origin.is_relative_to(site), (dist_root, origin, site)
print(f'MIO distribution={dist_root} module={origin} version={dist.version} template={PROMPT_TEMPLATE_VERSION}')
PYVERIFY

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
groupadd --gid 20015 azknowledgeegress
groupadd --gid 20016 azknowledge-context-client
groupadd --gid 20017 azmioctx
groupadd --gid 20018 azmio-contextobs
useradd --uid 20001 --gid azknowledge --no-create-home --shell /usr/sbin/nologin azknowledge
useradd --uid 20002 --gid azmio --no-create-home --shell /usr/sbin/nologin azmio
useradd --uid 20003 --gid azmioentry --no-create-home --shell /usr/sbin/nologin azmioentry
useradd --uid 20004 --gid azoperator --no-create-home --shell /usr/sbin/nologin azoperator
useradd --uid 20009 --gid azexplain --no-create-home --shell /usr/sbin/nologin azexplain
useradd --uid 20010 --gid azintake --no-create-home --shell /usr/sbin/nologin azintake
useradd --uid 20011 --gid azedge --no-create-home --shell /usr/sbin/nologin azedge
useradd --uid 20013 --gid azaudit --no-create-home --shell /usr/sbin/nologin azaudit
useradd --uid 20015 --gid azknowledgeegress --no-create-home --shell /usr/sbin/nologin azknowledgeegress
useradd --uid 20017 --gid azmioctx --no-create-home --shell /usr/sbin/nologin azmioctx
usermod --append --groups azknowledge-read,azmission-read azmio
# ADR-0010: the broker's one client is the context observation account, and
# only entryd carries the context observation socket's group. azmio (locald)
# is no client of the broker.
usermod --append --groups azknowledge-context-client azmioctx
usermod --append --groups azazel-operator,azmio-contextobs azmioentry
usermod --append --groups azazel-operator azoperator
usermod --append --groups azmio-advise azexplain
usermod --append --groups azincident-read azintake

cd "$SCRATCH_SRC"
if [[ -n "${TEST_TARGETS:-}" ]]; then
  # Focused run (u70): only the named files, same real-process settings.
  export NEXUS_REQUIRE_REAL_PROCESS=1
  # shellcheck disable=SC2086
  PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -q -p no:cacheprovider $TEST_TARGETS
  exit $?
fi
PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -q -p no:cacheprovider \
  tests/unit/test_knowledge_context_adapter.py \
  tests/unit/test_knowledge_context_transport.py \
  tests/unit/test_knowledge_contextd.py \
  tests/unit/test_runtime_hardening.py \
  tests/unit/test_knowledge_context_systemd_static.py \
  tests/unit/test_activation.py \
  tests/unit/test_activation_policy.py \
  tests/unit/test_activation_approval_v3.py \
  tests/unit/test_bootstrap_tmpfiles_packaging.py \
  tests/unit/test_mio_fast_assistance.py \
  tests/unit/test_mio_reference.py \
  tests/unit/test_knowledge_lookup.py \
  tests/unit/test_real_knowledge_lite_fixture.py \
  tests/unit/test_incident_explain.py \
  tests/real_process/test_mio_process_integration.py

# Keep the full-node listener subprocess separate from the tight 500 ms
# service-path timing cases above. Both run under the same suite lock.
export NEXUS_REQUIRE_REAL_PROCESS=1
PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -q -p no:cacheprovider \
  tests/real_process/test_knowledge_context_process_interop.py \
  tests/real_process/test_knowledge_context_linux_acceptance.py \
  tests/real_process/test_knowledge_context_official_entry.py \
  tests/real_process/test_knowledge_context_shipped_budget.py \
  tests/real_process/test_knowledge_context_clock_rollback.py

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
