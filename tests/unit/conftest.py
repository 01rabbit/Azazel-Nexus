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
