"""Shared fixtures, and the path to the runtime distribution.

`azazel_nexus_runtime` is a separate distribution (`runtime/`), because the
library must stay installable -- and importable -- without the privileged
layer. One suite covers both, so its source directory is put on the path here
for a contributor who installed only the library.

CI does not rely on this: it installs `./runtime` as its own distribution, to
prove the packaging works, and runs the CORE-imports job *without* it, to
prove the library does not need it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_RUNTIME_SRC = Path(__file__).resolve().parents[2] / "runtime" / "src"
if _RUNTIME_SRC.is_dir() and str(_RUNTIME_SRC) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_SRC))

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "knowledge-lite"


@pytest.fixture(scope="session")
def fixture_root() -> Path:
    return FIXTURE_ROOT


@pytest.fixture(scope="session")
def negative_index() -> dict:
    return json.loads((FIXTURE_ROOT / "negative.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def negative_cases(negative_index) -> dict[str, dict]:
    return {case["name"]: case for case in negative_index["fixtures"]}


@pytest.fixture
def lab_host(tmp_path, monkeypatch) -> Path:
    """Mark this test's host as a lab host (`lab_host.LAB_HOST_MARKER`).

    The public Knowledge Lite fixture key is refused as a commissioned anchor
    everywhere else (`azazel_nexus.lab_keys`). A test that drives the
    producer's published fixture through a commissioned reader declares
    itself a lab, exactly as the lab tooling marks a rehearsal host.
    """
    from azazel_nexus import lab_host as module

    marker = tmp_path / "etc-azazel-lab" / "LAB-HOST"
    marker.parent.mkdir()
    marker.write_text("lab\n")
    monkeypatch.setattr(module, "LAB_HOST_MARKER", marker)
    return marker


@pytest.fixture
def cache_root(tmp_path) -> Path:
    root = tmp_path / "knowledge-lite-cache"
    root.mkdir()
    return root


class _ModuleOs:
    """A module's own ``os``; delegates to the real one until a test overrides it."""

    def __getattr__(self, name):
        return getattr(os, name)


@pytest.fixture
def private_os(monkeypatch):
    """Give a module its own ``os`` so overrides stay off the process-wide one.

    pytest itself calls ``os.fstat`` (output capture) and ``os.stat``
    (linecache) while a test runs; a fake on the shared module breaks it.
    """
    def isolate(module):
        # A second call in the same test (a fixture and the test, say) keeps
        # the overrides already placed instead of dropping them.
        if not isinstance(module.os, _ModuleOs):
            monkeypatch.setattr(module, "os", _ModuleOs())
        return module.os
    return isolate


@pytest.fixture
def audit_owner_is_this_account():
    """Skip, as root, a test that stands this account in for ``azaudit``.

    These tests own their temporary ledger, so the fake ``azaudit`` account is
    given this process's uid. As root that uid is 0, and the inspector refuses
    an audit account with uid 0 by design (``bootstrap_audit``), so the stand-in
    no longer works. ``tests/unit`` runs as a non-root user; the refusal of uid
    0 is checked as root in ``test_runtime_bootstrap_audit.py``.
    """
    if os.geteuid() == 0:
        pytest.skip("running as root: the stand-in azaudit uid would be 0, which is refused by design")
