"""Pure v3 installed-manifest link validation and resolution."""

from hashlib import sha256
import json

import pytest

from azazel_nexus.installed_manifest import (
    InstalledDirectory,
    InstalledFile,
    InstalledLink,
    InstalledManifest,
    decode_installed_manifest,
    encode_installed_manifest,
    resolve_installed_link,
)
from azazel_nexus.operator_trust import ApprovalRefused


def _file(path):
    return InstalledFile(path, 0o644, 3, "a" * 64)


def _link(path, target):
    return InstalledLink(path, target)


def _v3(files, links=(), directories=()):
    return InstalledManifest(
        tuple(sorted((_file(path) for path in files), key=lambda item: item.path)),
        tuple(sorted((InstalledDirectory(path) for path in directories),
                     key=lambda item: item.path)),
        3,
        tuple(sorted((_link(path, target) for path, target in links),
                     key=lambda item: item.path)),
    )


def _pin(raw):
    return "sha256:" + sha256(raw).hexdigest()


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_v3_roundtrip_and_empty_links_preserve_version_identity():
    manifest = _v3(("usr/bin/tool",))
    raw = encode_installed_manifest(manifest)
    document = json.loads(raw)

    assert document == {
        "schema": "azazel-nexus/selected-installed-files/v3",
        "files": [{"path": "usr/bin/tool", "mode": 0o644,
                   "size": 3, "sha256": "a" * 64}],
        "directories": [],
        "links": [],
    }
    decoded = decode_installed_manifest(raw, expected_digest=_pin(raw))
    assert decoded == manifest
    assert decoded.version == 3 and decoded.links == ()


def test_absolute_and_sibling_link_chains_resolve_to_listed_regular_files():
    manifest = _v3(
        ("usr/bin/real-tool",),
        (
            ("usr/bin/a-link", "real-tool"),
            ("usr/bin/b-link", "a-link"),
            ("usr/bin/absolute-link", "/usr/bin/real-tool"),
        ),
    )
    assert resolve_installed_link(manifest, "usr/bin/real-tool") == "usr/bin/real-tool"
    assert resolve_installed_link(manifest, "usr/bin/a-link") == "usr/bin/real-tool"
    assert resolve_installed_link(manifest, "usr/bin/b-link") == "usr/bin/real-tool"
    assert resolve_installed_link(manifest, "usr/bin/absolute-link") == "usr/bin/real-tool"


@pytest.mark.parametrize(("link_count", "accepted"), [(8, True), (9, False)])
def test_link_traversal_depth_is_bounded(link_count, accepted):
    links = []
    for index in range(link_count):
        target = f"link-{index + 1}" if index + 1 < link_count else "leaf"
        links.append((f"usr/chain/link-{index}", target))
    if accepted:
        manifest = _v3(("usr/chain/leaf",), links)
        assert resolve_installed_link(manifest, "usr/chain/link-0") == "usr/chain/leaf"
    else:
        with pytest.raises(ApprovalRefused):
            _v3(("usr/chain/leaf",), links)


@pytest.mark.parametrize("links", [
    (("usr/bin/a", "missing"),),
    (("usr/bin/a", "b"), ("usr/bin/b", "a")),
])
def test_dangling_and_cyclic_declared_links_refuse_at_model_validation(links):
    with pytest.raises(ApprovalRefused):
        _v3(("usr/bin/leaf",), links)


def test_directory_is_not_a_valid_link_target():
    with pytest.raises(ApprovalRefused):
        _v3(
            ("usr/leaf",),
            (("usr/directory-link", "/usr/data"),),
            directories=("usr/data",),
        )


@pytest.mark.parametrize("target", [
    "../escape", "./relative", "subdir/name", ".", "..", "/etc/passwd",
    "/usr/../opt/escape", "/opt//bad", "/usr/bad\nname", "/usr/naïve",
    "/usr/" + "x" * 512,
])
def test_link_targets_reject_relative_paths_and_noncanonical_absolute_paths(target):
    with pytest.raises(ApprovalRefused):
        _link("usr/bin/alias", target)


def test_link_collision_with_file_directory_or_other_link_refuses():
    with pytest.raises(ApprovalRefused):
        InstalledManifest((_file("usr/bin/alias"),), (), 3,
                          (_link("usr/bin/alias", "leaf"),))
    with pytest.raises(ApprovalRefused):
        InstalledManifest((_file("usr/leaf"), InstalledFile(
            "usr/bin/alias", 0o644, 3, "b" * 64,
        )), (InstalledDirectory("usr/bin/alias"),), 3, ())
    with pytest.raises(ApprovalRefused):
        InstalledManifest(
            (_file("usr/leaf"),), (InstalledDirectory("usr/bin/alias"),), 3,
            (_link("usr/bin/alias", "leaf"),),
        )
    with pytest.raises(ApprovalRefused):
        _v3(
            ("usr/leaf",),
            (("usr/bin/alias", "leaf"), ("usr/bin/alias", "leaf")),
        )


def test_file_or_link_cannot_be_ancestor_of_any_entry():
    with pytest.raises(ApprovalRefused):
        _v3(("usr/node", "usr/node/child"))
    with pytest.raises(ApprovalRefused):
        _v3(
            ("usr/leaf", "usr/alias/child"),
            (("usr/alias", "leaf"),),
        )


def test_links_obey_declared_directory_intermediate_rules():
    with pytest.raises(ApprovalRefused):
        _v3(
            ("opt/app/real" ,),
            (("opt/app/lib/alias", "/opt/app/real"),),
            directories=("opt/app",),
        )


def test_v1_and_v2_require_empty_links_without_changing_existing_constructors():
    with pytest.raises(ApprovalRefused):
        InstalledManifest((_file("usr/tool"),), (), 1, (_link("usr/alias", "tool"),))
    with pytest.raises(ApprovalRefused):
        InstalledManifest((_file("usr/tool"),), (), 2, (_link("usr/alias", "tool"),))


def test_link_count_bound_and_all_declared_links_must_resolve():
    links = tuple(
        _link(f"usr/link-{index:04d}", "leaf") for index in range(1024)
    )
    accepted = InstalledManifest((_file("usr/leaf"),), (), 3, links)
    assert len(accepted.links) == 1024

    with pytest.raises(ApprovalRefused):
        InstalledManifest(
            (_file("usr/leaf"),), (), 3,
            (*links, _link("usr/link-1024", "missing")),
        )


def test_v3_decoder_requires_exact_fields_and_matching_pin():
    raw = encode_installed_manifest(_v3(("usr/leaf",), (("usr/alias", "leaf"),)))
    document = json.loads(raw)
    for invalid in (
        {**document, "extra": 1},
        {key: value for key, value in document.items() if key != "links"},
        {**document, "links": [{"path": "usr/alias", "target": "leaf", "x": 1}]},
    ):
        changed = _canonical(invalid)
        with pytest.raises(ApprovalRefused):
            decode_installed_manifest(changed, expected_digest=_pin(changed))
    with pytest.raises(ApprovalRefused):
        decode_installed_manifest(raw, expected_digest="sha256:" + "0" * 64)


def test_resolver_refuses_missing_or_directory_inputs():
    manifest = _v3(("usr/leaf",), directories=("usr/data",))
    for path in ("usr/missing", "usr/data"):
        with pytest.raises(ApprovalRefused):
            resolve_installed_link(manifest, path)
