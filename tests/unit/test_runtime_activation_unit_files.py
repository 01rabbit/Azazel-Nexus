"""Scoped unit files and the overrides that would change them (#206 P3b).

Temporary roots only: every search-path directory is resolved below a test
root owned by the test user.
"""

import os

import pytest

from azazel_nexus_runtime import activation_unit_files as unit_files
from azazel_nexus_runtime.activation_unit_files import (
    UnitFilesRefused,
    UnitOverrideRefused,
    drop_in_directory_names,
    measure_scoped_unit_files,
    require_no_unit_overrides,
)

EDGE = "azazel-edge-core.service"
INTAKE = "azazel-edge-intaked.service"
SCOPE = (EDGE, INTAKE)
SEARCH = ("etc/systemd/system", "run/systemd/system", "usr/local/lib/systemd/system",
          "etc/systemd/system.control", "run/systemd/system.control",
          "run/systemd/transient", "run/systemd/generator", "run/systemd/generator.late",
          "run/systemd/generator.early", "etc/systemd/system.attached",
          "run/systemd/system.attached")


@pytest.fixture
def root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    vendor = root / "usr/lib/systemd/system"
    vendor.mkdir(parents=True)
    for unit in SCOPE:
        (vendor / unit).write_text(f"[Unit]\nDescription={unit}\n")
        (vendor / unit).chmod(0o644)
    for path in [root, *root.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)
    monkeypatch.setattr(unit_files, "_ROOT", root)
    monkeypatch.setattr(unit_files, "_OWNER", os.getuid())
    return root


def _dir(root, relative):
    path = root / relative
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != root:
        current.chmod(0o755)
        current = current.parent
    return path


def test_measures_the_vendor_files_when_nothing_overrides_them(root):
    assert measure_scoped_unit_files(SCOPE) == {
        unit: f"[Unit]\nDescription={unit}\n".encode() for unit in SCOPE}


def test_search_path_is_the_reviewed_systemd_profile():
    assert set(unit_files._SEARCH_PATH) == {"/" + d for d in SEARCH} | {
        "/usr/lib/systemd/system"}


def test_drop_in_names_include_prefix_and_global_forms():
    assert drop_in_directory_names(EDGE) == (
        "azazel-edge-core.service.d", "azazel-.service.d", "azazel-edge-.service.d",
        "service.d")


@pytest.mark.parametrize("directory", SEARCH)
def test_a_mask_symlink_is_the_accepted_governed_state(root, directory):
    (_dir(root, directory) / EDGE).symlink_to("/dev/null")
    require_no_unit_overrides(SCOPE)
    assert set(measure_scoped_unit_files(SCOPE)) == set(SCOPE)


@pytest.mark.parametrize("directory", SEARCH)
@pytest.mark.parametrize("entry", ["file", "other-link", "relative-null", "directory"])
def test_any_other_same_name_entry_is_an_override(root, directory, entry):
    target = _dir(root, directory) / EDGE
    if entry == "file":
        target.write_text("[Service]\nEnvironment=AZAZEL_ENFORCE=1\n")
    elif entry == "other-link":
        target.symlink_to(root / "usr/lib/systemd/system" / INTAKE)
    elif entry == "relative-null":
        target.symlink_to("../../../dev/null")
    else:
        target.mkdir()
    with pytest.raises(UnitOverrideRefused):
        require_no_unit_overrides(SCOPE)
    with pytest.raises(UnitOverrideRefused):
        measure_scoped_unit_files(SCOPE)


@pytest.mark.parametrize("directory", (*SEARCH, "usr/lib/systemd/system"))
@pytest.mark.parametrize("name", [
    "azazel-edge-core.service.d", "azazel-.service.d", "azazel-edge-.service.d",
    "service.d", "azazel-edge-intaked.service.d",
])
def test_any_drop_in_file_is_refused_in_every_directory_including_vendor(root, directory, name):
    drop_in = _dir(root, directory) / name
    drop_in.mkdir()
    require_no_unit_overrides(SCOPE)  # an empty drop-in directory changes nothing
    (drop_in / "10-environment.conf").write_text("[Service]\nEnvironment=X=1\n")
    with pytest.raises(UnitOverrideRefused):
        require_no_unit_overrides(SCOPE)


@pytest.mark.parametrize("entry", ["file", "symlink", "mask-inside"])
def test_drop_in_entries_of_any_kind_are_refused(root, entry, tmp_path):
    base = _dir(root, "run/systemd/system")
    if entry == "file":
        (base / "azazel-edge-core.service.d").write_text("not a directory")
    elif entry == "symlink":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (base / "azazel-edge-core.service.d").symlink_to(elsewhere)
    else:
        (base / "service.d").mkdir()
        (base / "service.d/vendor.conf").symlink_to("/dev/null")
    with pytest.raises(UnitOverrideRefused):
        require_no_unit_overrides(SCOPE)


def test_unrelated_units_and_their_drop_ins_are_ignored(root):
    base = _dir(root, "etc/systemd/system")
    (base / "ssh.service").write_text("[Service]\n")
    (base / "ssh.service.d").mkdir()
    (base / "ssh.service.d/x.conf").write_text("[Service]\n")
    (base / "sockets.target.d").mkdir()
    (base / "sockets.target.d/x.conf").write_text("[Unit]\n")
    (base / "multi-user.target.wants").mkdir()
    require_no_unit_overrides(SCOPE)


def test_a_writable_or_linked_search_directory_refuses(root, tmp_path):
    base = _dir(root, "etc/systemd/system")
    base.chmod(0o777)
    with pytest.raises(UnitFilesRefused):
        require_no_unit_overrides(SCOPE)
    base.chmod(0o755)
    base.rename(tmp_path / "moved")
    base.symlink_to(tmp_path / "moved")
    with pytest.raises(UnitFilesRefused):
        require_no_unit_overrides(SCOPE)


@pytest.mark.parametrize("units", [(), ("ssh.service",), (EDGE, EDGE), "azazel-edge-core.service"])
def test_scope_must_be_allowlisted_distinct_units(root, units):
    with pytest.raises(UnitFilesRefused):
        measure_scoped_unit_files(units)


def test_a_missing_vendor_file_or_directory_refuses(root):
    (root / "usr/lib/systemd/system" / INTAKE).unlink()
    with pytest.raises(UnitFilesRefused):
        measure_scoped_unit_files(SCOPE)
    (root / "usr/lib/systemd/system" / EDGE).unlink()
    (root / "usr/lib/systemd/system").rmdir()
    with pytest.raises(UnitFilesRefused):
        require_no_unit_overrides(SCOPE)
