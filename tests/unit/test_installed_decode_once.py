"""Byte-identical manifest decoding is shared only inside one measurement scope."""

from hashlib import sha256
import os

import pytest

from azazel_nexus import installed_files, installed_manifest
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledManifest,
    decode_installed_manifest, decode_scope, encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused

FILES = {
    "opt/env/bin/python": b"synthetic interpreter bytes\n",
    "opt/env/site/az-activated": b"wrapper bytes\n",
}
DIRS = ("opt/env", "opt/env/bin", "opt/env/site")


def _manifest(files=FILES):
    entries = tuple(sorted((
        InstalledFile(p, 0o755, len(b), sha256(b).hexdigest()) for p, b in files.items()
    ), key=lambda e: e.path))
    raw = encode_installed_manifest(
        InstalledManifest(entries, tuple(InstalledDirectory(p) for p in DIRS), 2))
    return raw, "sha256:" + sha256(raw).hexdigest()


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "installed"
    for relative, payload in FILES.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755)
    for d in (root, root / "opt", *(root / p for p in DIRS)):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o755)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    raw, pin = _manifest()
    try:
        yield root, fd, raw, pin
    finally:
        os.close(fd)


@pytest.fixture
def decodes(monkeypatch):
    calls = []
    real = installed_manifest._decode_installed_manifest

    def counted(raw, expected_digest):
        calls.append(raw)
        return real(raw, expected_digest)

    monkeypatch.setattr(installed_manifest, "_decode_installed_manifest", counted)
    return calls


def _sequence(tree):
    """Mirror measure_bootstrap_installed_files: decode, 2 pinned reads, measure."""
    _root, fd, raw, pin = tree
    owner = os.getuid()
    decode_installed_manifest(raw, expected_digest=pin)
    out = []
    for paths in (("opt/env/bin/python", "opt/env/site/az-activated"),
                  ("opt/env/bin/python",)):
        decode_installed_manifest(raw, expected_digest=pin)
        out.append(installed_files._read_pinned_at(
            fd, raw, expected_digest=pin, paths=paths, owner=owner))
    decode_installed_manifest(raw, expected_digest=pin)
    out.append(installed_files._measure_at(fd, raw, expected_digest=pin, owner=owner))
    return out


def test_scope_reduces_decodes_with_identical_results(tree, decodes):
    plain = _sequence(tree)
    unscoped = len(decodes)
    decodes.clear()
    with decode_scope():
        scoped = _sequence(tree)
    assert scoped == plain
    assert unscoped == 7 and len(decodes) == 1


def test_scope_does_not_outlive_the_call(tree, decodes):
    _root, _fd, raw, pin = tree
    with decode_scope():
        decode_installed_manifest(raw, expected_digest=pin)
    assert len(decodes) == 1
    decode_installed_manifest(raw, expected_digest=pin)
    decode_installed_manifest(raw, expected_digest=pin)
    assert len(decodes) == 3


def test_nested_scope_joins_outer(tree, decodes):
    _root, _fd, raw, pin = tree
    with decode_scope():
        decode_installed_manifest(raw, expected_digest=pin)
        with decode_scope():
            decode_installed_manifest(raw, expected_digest=pin)
        decode_installed_manifest(raw, expected_digest=pin)
    assert len(decodes) == 1


def test_changed_bytes_are_decoded_and_refused_like_unscoped(tree):
    _root, _fd, raw, pin = tree
    bad = raw[:-1] + b" "
    with pytest.raises(ApprovalRefused) as plain:
        decode_installed_manifest(bad, expected_digest=pin)
    with decode_scope():
        decode_installed_manifest(raw, expected_digest=pin)
        with pytest.raises(ApprovalRefused) as scoped:
            decode_installed_manifest(bad, expected_digest=pin)
        # Refusal is never memoized and does not poison the good bytes.
        with pytest.raises(ApprovalRefused):
            decode_installed_manifest(bad, expected_digest=pin)
        assert decode_installed_manifest(raw, expected_digest=pin) == \
            decode_installed_manifest(raw, expected_digest=pin)
    assert str(scoped.value) == str(plain.value)


def test_different_valid_manifest_same_scope_not_confused(tree):
    _root, _fd, raw, pin = tree
    other_raw, other_pin = _manifest({"opt/env/bin/python": b"other\n"})
    with decode_scope():
        first = decode_installed_manifest(raw, expected_digest=pin)
        second = decode_installed_manifest(other_raw, expected_digest=other_pin)
        assert first != second
        with pytest.raises(ApprovalRefused):
            decode_installed_manifest(other_raw, expected_digest=pin)
        assert decode_installed_manifest(raw, expected_digest=pin) == first


def test_wrong_pin_and_bad_types_still_refuse_in_scope(tree):
    _root, _fd, raw, pin = tree
    with decode_scope():
        decode_installed_manifest(raw, expected_digest=pin)
        for bad_raw, bad_pin in ((raw, "sha256:" + "0" * 64), (bytearray(raw), pin),
                                 (raw, None), (b"", pin)):
            with pytest.raises(ApprovalRefused):
                decode_installed_manifest(bad_raw, expected_digest=bad_pin)


def test_files_are_reread_and_rehashed_every_measurement_in_scope(tree):
    root, fd, raw, pin = tree
    owner = os.getuid()
    with decode_scope():
        installed_files._measure_at(fd, raw, expected_digest=pin, owner=owner)
        target = root / "opt/env/bin/python"
        target.write_bytes(b"tampered interpreter bytes!\n"[:len(FILES["opt/env/bin/python"])])
        with pytest.raises(ApprovalRefused):
            installed_files._measure_at(fd, raw, expected_digest=pin, owner=owner)
        with pytest.raises(ApprovalRefused):
            installed_files._read_pinned_at(
                fd, raw, expected_digest=pin, paths=("opt/env/bin/python",), owner=owner)


def test_scope_resets_after_exception_in_block(tree, decodes):
    _root, _fd, raw, pin = tree
    with pytest.raises(RuntimeError):
        with decode_scope():
            decode_installed_manifest(raw, expected_digest=pin)
            raise RuntimeError("boom")
    assert len(decodes) == 1
    decode_installed_manifest(raw, expected_digest=pin)
    decode_installed_manifest(raw, expected_digest=pin)
    assert len(decodes) == 3


def test_copied_context_sees_nothing_after_outer_exit(tree, decodes):
    import contextvars
    _root, _fd, raw, pin = tree
    with decode_scope():
        decode_installed_manifest(raw, expected_digest=pin)
        ctx = contextvars.copy_context()
    assert len(decodes) == 1
    ctx.run(decode_installed_manifest, raw, expected_digest=pin)
    assert len(decodes) == 2
