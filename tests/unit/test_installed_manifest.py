"""Canonical selected-installed-file manifest validation; no filesystem access."""

from hashlib import sha256
import json

import pytest

from azazel_nexus.installed_manifest import (
    InstalledFile,
    InstalledManifest,
    decode_installed_manifest,
    encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused

DIGEST = "a" * 64


def entry(path="opt/azazel/bin/az-activated", *, mode=0o755, size=17, digest=DIGEST):
    return InstalledFile(path, mode, size, digest)


def manifest():
    return InstalledManifest((
        entry("opt/azazel/bin/az-activated"),
        entry("usr/lib/python3/site-packages/azazel_nexus.py", mode=0o644, size=0,
              digest="b" * 64),
    ))


def expected_for(raw):
    return "sha256:" + sha256(raw).hexdigest()


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def test_manifest_has_exact_canonical_schema_and_pinned_roundtrip():
    value = manifest()
    raw = encode_installed_manifest(value)
    expected = (
        b'{"files":[{"mode":493,"path":"opt/azazel/bin/az-activated",'
        b'"sha256":"' + b"a" * 64 + b'","size":17},{"mode":420,'
        b'"path":"usr/lib/python3/site-packages/azazel_nexus.py","sha256":"'
        + b"b" * 64 + b'","size":0}],"schema":"azazel-nexus/selected-installed-files/v1"}'
    )

    assert raw == expected
    assert decode_installed_manifest(raw, expected_digest=expected_for(raw)) == value
    assert encode_installed_manifest(decode_installed_manifest(
        raw, expected_digest=expected_for(raw),
    )) == raw


def test_decoder_requires_independently_matching_prefixed_sha256_pin():
    raw = encode_installed_manifest(manifest())
    for expected in ("0" * 64, sha256(raw).hexdigest(), "sha256:" + "A" * 64, True):
        with pytest.raises(ApprovalRefused):
            decode_installed_manifest(raw, expected_digest=expected)


@pytest.mark.parametrize("raw", [
    b"",
    b"{}\n",
    b"null",
    b"[]",
    b"{" + b" " * (1 << 20),
])
def test_decoder_refuses_malformed_noncanonical_or_oversized_raw(raw):
    with pytest.raises(ApprovalRefused):
        decode_installed_manifest(raw, expected_digest=expected_for(raw))


@pytest.mark.parametrize("mutation", [
    "wrong-version", "extra-top", "missing-top", "duplicate-key", "unknown-entry",
    "missing-entry-field", "duplicate-path", "unsorted-paths", "empty-files",
])
def test_decoder_refuses_schema_duplicates_and_noncanonical_file_sets(mutation):
    raw = encode_installed_manifest(manifest())
    document = json.loads(raw)
    if mutation == "wrong-version":
        document["schema"] = "azazel-nexus/selected-installed-files/v2"
    elif mutation == "extra-top":
        document["unexpected"] = True
    elif mutation == "missing-top":
        del document["files"]
    elif mutation == "duplicate-key":
        raw = raw[:-1] + b',"schema":"azazel-nexus/selected-installed-files/v1"}'
    elif mutation == "unknown-entry":
        document["files"][0]["symlink"] = False
    elif mutation == "missing-entry-field":
        del document["files"][0]["mode"]
    elif mutation == "duplicate-path":
        document["files"][1]["path"] = document["files"][0]["path"]
    elif mutation == "unsorted-paths":
        document["files"].reverse()
    else:
        document["files"] = []
    if mutation != "duplicate-key":
        raw = canonical(document)

    with pytest.raises(ApprovalRefused):
        decode_installed_manifest(raw, expected_digest=expected_for(raw))


@pytest.mark.parametrize("path", [
    "/usr/bin/python3",
    "etc/passwd",
    "usr/../etc/passwd",
    "usr/./bin/python",
    "usr//bin/python",
    "usr/bin\\python",
    "usr/bin/naïve",
    "usr/" + "x" * 510,
    "usr/" + "/".join(["x"] * 32),
])
def test_file_path_must_be_bounded_relative_ascii_and_under_allowed_prefixes(path):
    with pytest.raises(ApprovalRefused):
        entry(path)


@pytest.mark.parametrize(("mode", "size", "digest"), [
    (True, 1, DIGEST),
    (0o600, 1, DIGEST),
    (0o100755, 1, DIGEST),
    (0o644, True, DIGEST),
    (0o644, -1, DIGEST),
    (0o644, (64 << 20) + 1, DIGEST),
    (0o644, 1, "sha256:" + DIGEST),
    (0o644, 1, "A" * 64),
])
def test_file_entries_reject_invalid_modes_sizes_and_digests(mode, size, digest):
    with pytest.raises(ApprovalRefused):
        entry(mode=mode, size=size, digest=digest)


def test_manifest_requires_nonempty_exact_tuple_and_sorted_unique_entries():
    with pytest.raises(ApprovalRefused):
        InstalledManifest(())
    with pytest.raises(ApprovalRefused):
        InstalledManifest([entry()])
    with pytest.raises(ApprovalRefused):
        InstalledManifest((entry("usr/a"), entry("opt/a")))
    with pytest.raises(ApprovalRefused):
        InstalledManifest((entry("opt/a"), entry("opt/a")))
    with pytest.raises(ApprovalRefused):
        InstalledManifest((object(),))


def test_file_count_and_aggregate_size_are_bounded():
    too_many = tuple(entry(f"opt/f{index:04d}") for index in range(4097))
    with pytest.raises(ApprovalRefused):
        InstalledManifest(too_many)

    over_total = tuple(entry(f"opt/f{index}", size=64 << 20) for index in range(9))
    with pytest.raises(ApprovalRefused):
        InstalledManifest(over_total)


def test_decoder_checks_file_count_before_constructing_entries(monkeypatch):
    import azazel_nexus.installed_manifest as installed_manifest

    document = {
        "schema": "azazel-nexus/selected-installed-files/v1",
        "files": [{"path": "opt/a", "mode": 0o644, "size": 0, "sha256": DIGEST}]
        * 4097,
    }
    raw = canonical(document)
    monkeypatch.setattr(
        installed_manifest, "InstalledFile",
        lambda **kwargs: pytest.fail("entry construction occurred before count bound"),
    )

    with pytest.raises(ApprovalRefused):
        decode_installed_manifest(raw, expected_digest=expected_for(raw))


def test_inclusive_file_and_total_size_limits_are_accepted():
    files = tuple(entry(f"opt/f{index}", size=64 << 20) for index in range(8))
    value = InstalledManifest(files)
    raw = encode_installed_manifest(value)

    assert decode_installed_manifest(raw, expected_digest=expected_for(raw)) == value


def test_path_depth_32_and_length_512_are_valid_boundaries():
    deep_path = "usr/" + "/".join(["x"] * 31)
    long_path = "usr/" + "x" * 508

    assert len(deep_path.split("/")) == 32
    assert len(long_path) == 512
    assert InstalledFile(deep_path, 0o644, 0, DIGEST).path == deep_path
    assert InstalledFile(long_path, 0o644, 0, DIGEST).path == long_path


def test_encoder_rejects_wrong_manifest_type():
    with pytest.raises(ApprovalRefused):
        encode_installed_manifest(object())
