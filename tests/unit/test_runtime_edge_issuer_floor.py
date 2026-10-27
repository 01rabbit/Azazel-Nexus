"""The Edge rollback floor writer: raise-only, atomic, fail-closed (temporary files only)."""

from __future__ import annotations

from contextlib import contextmanager
import os

import pytest

from azazel_nexus.edge_issuer import (
    FLOOR_FILENAME,
    EdgeFloor,
    IssuerVerification,
    decode_floor,
    encode_floor,
)
from azazel_nexus_runtime import edge_issuer_floor as ef
from azazel_nexus_runtime.edge_issuer_floor import (
    EdgeFloorCommitUncertain,
    EdgeFloorRefused,
    raise_edge_floor,
    raise_floor_after_grant,
    read_edge_floor,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


@pytest.fixture
def state(tmp_path, monkeypatch):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o711)
    directory.chmod(0o711)

    @contextmanager
    def state_directory():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(ef, "_state_directory", state_directory)
    monkeypatch.setattr(ef, "_OWNER", os.getuid())
    return directory


def _authenticated(version="0.1.0", digest=DIGEST_A, **overrides) -> IssuerVerification:
    fields = dict(
        digest_verified=True, issuer_authenticated=True, issuer_status="authenticated",
        issuer="edge-release", revocation_status="none", revoked="none",
        floor_status="absent", version=version, package_digest=digest,
    )
    fields.update(overrides)
    return IssuerVerification(**fields)


def test_the_first_authenticated_grant_creates_a_readable_floor(state):
    assert read_edge_floor() is None
    assert raise_floor_after_grant(_authenticated(), launched_digest=DIGEST_A) == "raised"
    assert read_edge_floor() == EdgeFloor("0.1.0", DIGEST_A, 0)
    leaf = state / "edge-issuer"
    assert oct(leaf.stat().st_mode & 0o777) == "0o755"
    assert oct((leaf / FLOOR_FILENAME).stat().st_mode & 0o777) == "0o644"
    assert decode_floor((leaf / FLOOR_FILENAME).read_bytes()) == read_edge_floor()


def test_an_unauthenticated_grant_never_moves_the_floor(state):
    unauthenticated = IssuerVerification(
        digest_verified=True, issuer_authenticated=False, issuer_status="not_configured")
    assert raise_floor_after_grant(unauthenticated, launched_digest=DIGEST_A) == "not_authenticated"
    assert raise_floor_after_grant(None, launched_digest=DIGEST_A) == "not_authenticated"
    assert read_edge_floor() is None


@pytest.mark.parametrize("overrides,launched", [
    ({"digest_verified": False}, DIGEST_A),
    ({"revoked": "revoked_digest"}, DIGEST_A),
    ({"revoked": "not_evaluated"}, DIGEST_A),
    ({"revocation_status": "refused"}, DIGEST_A),
    ({"floor_status": "below_floor"}, DIGEST_A),
    ({"floor_status": "replayed"}, DIGEST_A),
    ({"floor_status": "refused"}, DIGEST_A),
    ({}, DIGEST_B),   # launched evidence bound to another package
    ({}, None),
])
def test_an_ineligible_grant_never_moves_the_floor(state, overrides, launched):
    assert raise_floor_after_grant(_authenticated(**overrides),
                                   launched_digest=launched) == "not_eligible"
    assert read_edge_floor() is None


def test_the_floor_only_rises(state):
    raise_edge_floor(EdgeFloor("0.2.0", DIGEST_A, 3))
    for lower in (EdgeFloor("0.1.9", DIGEST_A, 3),      # rollback
                  EdgeFloor("0.2.0", DIGEST_B, 3),      # replay at the same version
                  EdgeFloor("0.2.0", DIGEST_A, 2)):     # older revocation sequence
        with pytest.raises(EdgeFloorRefused):
            raise_edge_floor(lower)
    assert read_edge_floor() == EdgeFloor("0.2.0", DIGEST_A, 3)
    assert raise_floor_after_grant(_authenticated("0.2.0", DIGEST_A, revocation_sequence=3,
                                                  revocation_status="in_force",
                                                  floor_status="held"),
                                   launched_digest=DIGEST_A) == "held"
    assert raise_floor_after_grant(_authenticated("0.1.0", DIGEST_B),
                                   launched_digest=DIGEST_B) == "refused"
    raise_edge_floor(EdgeFloor("0.10.0", DIGEST_B, 3))  # numeric, not lexical
    assert read_edge_floor().version == "0.10.0"


def test_a_corrupt_floor_is_refused_and_never_overwritten(state):
    raise_edge_floor(EdgeFloor("0.1.0", DIGEST_A))
    path = state / "edge-issuer" / FLOOR_FILENAME
    path.write_bytes(b"{corrupt")
    with pytest.raises(EdgeFloorRefused):
        read_edge_floor()
    assert raise_floor_after_grant(_authenticated("0.2.0"), launched_digest=DIGEST_A) == "refused"
    assert path.read_bytes() == b"{corrupt"


def test_a_floor_with_unsafe_mode_is_refused(state):
    raise_edge_floor(EdgeFloor("0.1.0", DIGEST_A))
    (state / "edge-issuer" / FLOOR_FILENAME).chmod(0o666)
    with pytest.raises(EdgeFloorRefused):
        read_edge_floor()


def test_a_linked_floor_is_refused(state, tmp_path):
    raise_edge_floor(EdgeFloor("0.1.0", DIGEST_A))
    path = state / "edge-issuer" / FLOOR_FILENAME
    target = tmp_path / "elsewhere.json"
    target.write_bytes(encode_floor(EdgeFloor("9.9.9", DIGEST_A)))
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(EdgeFloorRefused):
        read_edge_floor()


def test_a_crash_before_rename_keeps_the_old_floor(state, monkeypatch):
    raise_edge_floor(EdgeFloor("0.1.0", DIGEST_A))
    original = os.replace

    def crash(*args, **kwargs):
        raise OSError("power lost")

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(EdgeFloorRefused):
        raise_edge_floor(EdgeFloor("0.2.0", DIGEST_A))
    monkeypatch.setattr(os, "replace", original)
    assert read_edge_floor() == EdgeFloor("0.1.0", DIGEST_A)
    # The stale partial file is never read, and the next raise succeeds.
    assert raise_edge_floor(EdgeFloor("0.2.0", DIGEST_A)) == EdgeFloor("0.2.0", DIGEST_A)


def test_an_unconfirmed_commit_is_uncertain_not_success(state, monkeypatch):
    original = os.fsync
    calls = []

    def failing(fd):
        calls.append(fd)
        if len(calls) >= 3:  # leaf creation, file, then the directory after rename
            raise OSError("fsync failed")
        return original(fd)

    monkeypatch.setattr(os, "fsync", failing)
    with pytest.raises(EdgeFloorCommitUncertain):
        raise_edge_floor(EdgeFloor("0.1.0", DIGEST_A))
    calls.clear()
    calls.append(0)  # the leaf exists now: file fsync, then the directory fails
    assert raise_floor_after_grant(_authenticated("0.2.0"),
                                   launched_digest=DIGEST_A) == "uncertain"


def test_a_wrong_owner_is_refused(state, monkeypatch):
    raise_edge_floor(EdgeFloor("0.1.0", DIGEST_A))
    monkeypatch.setattr(ef, "_OWNER", os.getuid() + 1)
    with pytest.raises(EdgeFloorRefused):
        read_edge_floor()
