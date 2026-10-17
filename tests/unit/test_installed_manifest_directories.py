"""Versioned selected-file manifests with explicit directory records."""

from hashlib import sha256
import json

import pytest

from azazel_nexus.installed_manifest import (
    InstalledDirectory,
    InstalledFile,
    InstalledManifest,
    decode_installed_manifest,
    encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused


def _file(path="usr/bin/tool"):
    return InstalledFile(path, 0o755, 1, "a" * 64)


def _directory(path, mode=0o755):
    return InstalledDirectory(path, mode)


def _pin(raw):
    return "sha256:" + sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _v2(files=("usr/tool",), directories=()):
    return InstalledManifest(
        tuple(_file(path) for path in files),
        tuple(_directory(path) for path in directories),
        version=2,
    )


def test_v1_bytes_remain_unchanged_and_empty_directories_are_implicit():
    value = InstalledManifest((_file(),))
    raw = encode_installed_manifest(value)

    assert raw == (
        b'{"files":[{"mode":493,"path":"usr/bin/tool","sha256":"'
        + b"a" * 64
        + b'","size":1}],"schema":"azazel-nexus/selected-installed-files/v1"}'
    )
    assert b'"directories"' not in raw
    assert decode_installed_manifest(raw, expected_digest=_pin(raw)) == value


def test_v1_rejects_nonempty_directories():
    with pytest.raises(ApprovalRefused):
        InstalledManifest((_file(),), (_directory("usr/bin"),), version=1)


def test_v2_empty_directory_list_preserves_version_identity():
    value = _v2()
    raw = encode_installed_manifest(value)

    assert json.loads(raw) == {
        "schema": "azazel-nexus/selected-installed-files/v2",
        "files": [{"path": "usr/tool", "mode": 0o755,
                   "size": 1, "sha256": "a" * 64}],
        "directories": [],
    }
    decoded = decode_installed_manifest(raw, expected_digest=_pin(raw))
    assert decoded == value
    assert decoded.version == 2 and decoded.directories == ()


def test_v2_round_trips_declared_nested_and_empty_directories():
    value = _v2(
        files=("usr/libexec/azazel/daemon",),
        directories=(
            "usr/libexec", "usr/libexec/azazel", "usr/share", "usr/share/azazel",
            "usr/share/azazel/empty",
        ),
    )
    raw = encode_installed_manifest(value)

    assert decode_installed_manifest(raw, expected_digest=_pin(raw)) == value
    assert json.loads(raw)["directories"] == [
        {"path": "usr/libexec", "mode": 0o755},
        {"path": "usr/libexec/azazel", "mode": 0o755},
        {"path": "usr/share", "mode": 0o755},
        {"path": "usr/share/azazel", "mode": 0o755},
        {"path": "usr/share/azazel/empty", "mode": 0o755},
    ]


def test_v2_requires_every_intermediate_directory_to_be_declared():
    with pytest.raises(ApprovalRefused):
        _v2(files=("opt/app/lib/x.py",), directories=("opt/app",))


def test_declared_selected_root_needs_no_ancestors_outside_that_root():
    value = _v2(
        files=("opt/app/lib/x.py",), directories=("opt/app/lib",),
    )
    assert decode_installed_manifest(
        encode_installed_manifest(value),
        expected_digest=_pin(encode_installed_manifest(value)),
    ) == value


def test_directory_descendants_use_component_aware_ancestry():
    value = _v2(
        files=("opt/app/file", "opt/application/file"),
        directories=("opt/app",),
    )
    assert encode_installed_manifest(value)


@pytest.mark.parametrize("directories", [
    ("usr/lib", "usr/lib"),
    ("usr/libexec/azazel", "usr/libexec"),
])
def test_v2_rejects_duplicate_or_unsorted_directories(directories):
    with pytest.raises(ApprovalRefused):
        _v2(files=("usr/tool",), directories=directories)


def test_v2_rejects_file_directory_collision():
    with pytest.raises(ApprovalRefused):
        InstalledManifest((_file("usr/bin"),), (_directory("usr/bin"),), version=2)


def test_v2_rejects_file_ancestor_of_any_entry():
    with pytest.raises(ApprovalRefused):
        _v2(files=("usr/cache", "usr/cache/item"))


@pytest.mark.parametrize("path", [
    "etc/passwd", "usr/../opt/escape", "usr//empty", "opt/./child",
])
def test_directory_path_uses_canonical_usr_opt_path_policy(path):
    with pytest.raises(ApprovalRefused):
        _directory(path)


@pytest.mark.parametrize("mode", [0o644, 0o700, True, "0755"])
def test_directory_mode_is_exactly_0755(mode):
    with pytest.raises(ApprovalRefused):
        _directory("usr/data", mode)


def test_v2_directory_count_bound():
    directories = tuple(_directory(f"usr/d{index:04d}") for index in range(1024))
    accepted = InstalledManifest((_file("usr/tool"),), directories, version=2)
    assert len(decode_installed_manifest(
        encode_installed_manifest(accepted),
        expected_digest=_pin(encode_installed_manifest(accepted)),
    ).directories) == 1024

    with pytest.raises(ApprovalRefused):
        InstalledManifest(
            (_file(),), (*directories, _directory("usr/d1024")), version=2,
        )


def test_decoder_requires_exact_v2_top_level_shape_and_pinned_digest():
    raw = encode_installed_manifest(_v2())
    document = json.loads(raw)
    for invalid in (
        {**document, "unexpected": True},
        {key: value for key, value in document.items() if key != "directories"},
    ):
        encoded = _canonical(invalid)
        with pytest.raises(ApprovalRefused):
            decode_installed_manifest(encoded, expected_digest=_pin(encoded))

    with pytest.raises(ApprovalRefused):
        decode_installed_manifest(raw, expected_digest="sha256:" + "0" * 64)


def test_decoder_rejects_noncanonical_or_invalid_v2_directory_records():
    base = json.loads(encode_installed_manifest(_v2()))
    invalid_documents = (
        {**base, "directories": [{"path": "usr/lib", "mode": 0o700}]},
        {**base, "directories": [{"path": "usr/lib", "mode": 0o755, "extra": 0}]},
        {**base, "directories": ["usr/lib"]},
    )
    for document in invalid_documents:
        raw = _canonical(document)
        with pytest.raises(ApprovalRefused):
            decode_installed_manifest(raw, expected_digest=_pin(raw))
