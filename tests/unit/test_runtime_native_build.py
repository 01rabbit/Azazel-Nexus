"""Inspect the target build recipe without compiling or installing anything."""

from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_native_deadline_build_has_no_portable_backendless_wheel_fallback(monkeypatch, platform):
    extensions, calls = [], []

    def extension(name, *, sources, libraries):
        value = SimpleNamespace(name=name, sources=sources, libraries=libraries)
        extensions.append(value)
        return value

    monkeypatch.setitem(sys.modules, "setuptools", SimpleNamespace(
        Extension=extension, setup=lambda **kwargs: calls.append(kwargs),
    ))
    monkeypatch.setattr(sys, "platform", platform)
    runtime = Path(__file__).resolve().parents[2] / "runtime"
    runpy.run_path(str(runtime / "setup.py"))
    assert len(calls) == 1
    assert calls[0]["ext_modules"] == extensions
    # Both hosts declare the extension: its Linux-only C guard prevents a
    # non-Linux builder silently emitting a backendless py3-none-any wheel.
    assert len(extensions) == 1
    if extensions:
        value, = extensions
        assert value.name == "azazel_nexus_runtime._bootstrap_deadline"
        assert value.libraries == ["rt"]
        assert value.sources == ["src/azazel_nexus_runtime/_bootstrap_deadline.c"]
        assert (runtime / value.sources[0]).is_file()
        assert (runtime / "MANIFEST.in").read_text().strip() == "include " + value.sources[0]
