from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from tools.stage_runtime_entrypoints import declared_daemons, stage


ROOT = Path(__file__).resolve().parents[2]
LIBEXEC = Path("usr/libexec/azazel")


def test_staged_set_is_derived_from_the_installed_units_and_runtime_scripts() -> None:
    daemons = declared_daemons()

    unit_names = set()
    for unit in (ROOT / "packaging" / "systemd").glob("*.service"):
        for line in unit.read_text(encoding="utf-8").splitlines():
            if line.startswith("ExecStart="):
                unit_names.add(Path(line.removeprefix("ExecStart=")).name)

    assert set(daemons) == unit_names
    assert "az-core-reserve-probe" not in daemons


def test_stages_executable_wrappers_under_the_fixed_libexec_path(
    tmp_path: Path,
) -> None:
    destdir = tmp_path / "image-root"
    staged = stage(Path(sys.executable), destdir=destdir)
    directory = destdir / LIBEXEC

    assert {path.name for path in staged} == set(declared_daemons())
    assert {path.name for path in directory.iterdir()} == set(declared_daemons())
    for path in staged:
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        assert not path.is_symlink()
        text = path.read_text(encoding="utf-8")
        assert text.startswith("#!/bin/sh\nexec ")
        assert os.fspath(Path(sys.executable)) in text
        assert " -c 'from azazel_nexus_runtime." in text


def test_non_absolute_or_missing_interpreter_fails_before_writing(
    tmp_path: Path,
) -> None:
    destdir = tmp_path / "image-root"
    with pytest.raises(ValueError, match="absolute executable"):
        stage(Path("python3"), destdir=destdir)
    with pytest.raises(ValueError, match="absolute executable"):
        stage(tmp_path / "missing-python", destdir=destdir)
    assert not destdir.exists()


def test_existing_symlink_entrypoint_is_refused_before_any_replacement(
    tmp_path: Path,
) -> None:
    destdir = tmp_path / "image-root"
    directory = destdir / LIBEXEC
    directory.mkdir(parents=True)
    link = directory / "az-activated"
    link.symlink_to(tmp_path / "outside")

    with pytest.raises(ValueError, match="symlink"):
        stage(Path(sys.executable), destdir=destdir)

    assert link.is_symlink()
    assert list(directory.iterdir()) == [link]


def test_malformed_runtime_module_path_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "runtime").mkdir(parents=True)
    (root / "runtime" / "pyproject.toml").write_text(
        '[project.scripts]\n"az-testd" = "azazel_nexus_runtime..outside:main"\n',
        encoding="utf-8",
    )
    unit_dir = root / "packaging" / "systemd"
    unit_dir.mkdir(parents=True)
    (unit_dir / "az-testd.service").write_text(
        "[Service]\nExecStart=/usr/libexec/azazel/az-testd\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid runtime entrypoint"):
        declared_daemons(root)
