"""Shared access to the vendored Knowledge Lite fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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
