"""Single-validation link resolver and bounded projection cost."""

from hashlib import sha256

import pytest

from azazel_nexus import installed_manifest
from azazel_nexus.installed_manifest import (
    InstalledDirectory,
    InstalledFile,
    InstalledLink,
    InstalledManifest,
    installed_link_resolver,
    resolve_installed_link,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import loaded_modules
from azazel_nexus_runtime.loaded_modules import _project_modules

import test_runtime_loaded_modules as base


def _file(path, mode=0o644):
    return InstalledFile(path, mode, 3, "a" * 64)


def _v3():
    files = (_file("usr/bin/other"), _file("usr/bin/real", 0o755))
    links = (
        InstalledLink("usr/bin/alias", "real"),
        InstalledLink("usr/bin/abs", "/usr/bin/real"),
        InstalledLink("usr/bin/chain", "alias"),
    )
    return InstalledManifest(
        files, (InstalledDirectory("usr/bin"),), 3,
        tuple(sorted(links, key=lambda item: item.path)),
    )


BAD_PATHS = (
    "usr/bin/real", "usr/bin/alias", "usr/bin/abs", "usr/bin/chain",
    "usr/bin", "usr/bin/missing",
    "etc/passwd", "usr/../etc", "usr//bin", "", "/usr/bin/real", "usr/bin/ré",
    None, 3,
)


@pytest.mark.parametrize("path", BAD_PATHS)
def test_resolver_matches_resolve_installed_link(path):
    manifest = _v3()
    resolver = installed_link_resolver(manifest)
    try:
        expected = resolve_installed_link(manifest, path)
    except ApprovalRefused as error:
        with pytest.raises(ApprovalRefused) as raised:
            resolver(path)
        assert str(raised.value) == str(error)
    else:
        assert resolver(path) == expected


def test_resolver_refuses_invalid_manifest_at_creation():
    with pytest.raises(ApprovalRefused, match="link resolution refused"):
        installed_link_resolver(object())


def test_projection_validates_manifest_a_bounded_number_of_times(monkeypatch):
    count = 0
    original = installed_manifest._validate_manifest

    def counted(manifest):
        nonlocal count
        count += 1
        return original(manifest)

    monkeypatch.setattr(installed_manifest, "_validate_manifest", counted)
    extra = {f"opt/env/site/mod{i}.py": (0o644, b"x") for i in range(1500)}
    manifest = base._manifest(extra)
    count = 0
    registry = base._registry()
    for i in range(400):
        name = f"mod{i}"
        registry[name] = base._source_module(
            name=name, origin=f"/opt/env/site/{name}.py")
    assert len(manifest.files) >= 1500
    base._project(registry, manifest, monkeypatch=monkeypatch)
    assert 1 <= count <= 2
