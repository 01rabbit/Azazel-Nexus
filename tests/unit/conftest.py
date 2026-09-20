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
