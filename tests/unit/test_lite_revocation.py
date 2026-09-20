"""Revocation (#6, E1).

The interesting failures here are not "a bad list is refused" -- they are the
ways a refusal could still leave the node *less* protected than before it. A
refused list must leave the list in force untouched; an unreadable list must
not read as an empty one; and a correctly signed older list must not be able
to lift what a newer one said.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from signing_oracle import public_key_for, sign_detached

from azazel_nexus.content_store import ContentRefused, digest_bytes
from azazel_nexus.revocation import (
    EMPTY,
    REVOCATION_FILENAME,
    RevocationList,
    RevocationRefused,
    RevocationStore,
)

TRUSTED_SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))
SECOND_TRUSTED_SEED = bytes(range(64, 96))

TRUSTED_KEY = public_key_for(TRUSTED_SEED)
OTHER_KEY = public_key_for(OTHER_SEED)
SECOND_TRUSTED_KEY = public_key_for(SECOND_TRUSTED_SEED)

BAD_ARTIFACT = digest_bytes(b"the artifact that turned out to be bad")
OTHER_ARTIFACT = digest_bytes(b"an artifact that is fine")


def signed(revocations: RevocationList, *, seed: bytes = TRUSTED_SEED) -> bytes:
    payload = revocations.as_payload()
    return sign_detached(seed=seed, message=payload) + payload


def a_list(sequence: int, **kwargs: object) -> RevocationList:
    fields: dict = {"sequence": sequence, "issued_at": f"2026-09-{sequence:02d}T00:00:00Z"}
    fields.update(kwargs)
    return RevocationList(**fields)  # type: ignore[arg-type]


@pytest.fixture()
def store(tmp_path: Path) -> RevocationStore:
    return RevocationStore(root=tmp_path / "lite", trusted_keys=(TRUSTED_KEY,))


# -- the baseline ----------------------------------------------------------


def test_a_node_that_has_accepted_nothing_revokes_nothing(store: RevocationStore) -> None:
    in_force = store.current()
    assert in_force == EMPTY
    assert in_force.sequence == 0
    assert in_force.revokes_digest(BAD_ARTIFACT) is False


def test_a_signed_list_from_a_trusted_key_takes_effect(store: RevocationStore) -> None:
    store.accept(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))

    in_force = store.current()
    assert in_force.sequence == 1
    assert in_force.revokes_digest(BAD_ARTIFACT) is True
    assert in_force.revokes_digest(OTHER_ARTIFACT) is False


def test_revocation_survives_being_read_by_a_fresh_store(tmp_path: Path) -> None:
    """A restart does not forget. The statement lives on disk, not in memory."""

    root = tmp_path / "lite"
    RevocationStore(root=root, trusted_keys=(TRUSTED_KEY,)).accept(
        signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT})))
    )
    reopened = RevocationStore(root=root, trusted_keys=(TRUSTED_KEY,))
    assert reopened.current().revokes_digest(BAD_ARTIFACT) is True


# -- a refusal must never leave the node less protected --------------------


def test_a_list_signed_by_an_untrusted_key_is_refused_and_changes_nothing(
    store: RevocationStore,
) -> None:
    store.accept(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))

    with pytest.raises(RevocationRefused) as caught:
        store.accept(signed(a_list(2), seed=OTHER_SEED))
    assert "trusted key" in str(caught.value)

    still = store.current()
    assert still.sequence == 1
    assert still.revokes_digest(BAD_ARTIFACT) is True


def test_a_tampered_payload_is_refused(store: RevocationStore) -> None:
    blob = bytearray(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))
    blob[-2] ^= 0x01
    with pytest.raises(RevocationRefused):
        store.accept(bytes(blob))
    assert store.current() == EMPTY


def test_a_correctly_signed_older_list_cannot_un_revoke(store: RevocationStore) -> None:
    """The replay. Both lists verify; only their sequence numbers differ.

    Sequence 1 revoked nothing. Sequence 2 revoked the artifact. Replaying
    sequence 1 afterwards is a valid signature over a statement that was true
    once, and accepting it would bring the artifact back.
    """

    empty_first = signed(a_list(1))
    revoking_second = signed(a_list(2, revoked_digests=frozenset({BAD_ARTIFACT})))

    store.accept(empty_first)
    store.accept(revoking_second)
    assert store.current().revokes_digest(BAD_ARTIFACT) is True

    with pytest.raises(RevocationRefused) as caught:
        store.accept(empty_first)
    assert "replay" in str(caught.value)
    assert store.current().sequence == 2
    assert store.current().revokes_digest(BAD_ARTIFACT) is True


def test_a_list_with_the_same_sequence_is_refused(store: RevocationStore) -> None:
    """Equal is not newer. Otherwise two lists at the same number both apply."""

    store.accept(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))
    with pytest.raises(RevocationRefused) as caught:
        store.accept(signed(a_list(1)))
    assert "does not exceed" in str(caught.value)
    assert store.current().revokes_digest(BAD_ARTIFACT) is True


def test_an_unreadable_stored_list_is_out_of_service_not_unrevoked(
    store: RevocationStore,
) -> None:
    """The move an adversary would actually make.

    Corrupting one file must not be the same as issuing a list that revokes
    nothing. The assertion below first establishes that something *was*
    revoked, so a `raises` that passed for an unrelated reason would be
    visible.
    """

    store.accept(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))
    assert store.current().revokes_digest(BAD_ARTIFACT) is True

    blob = bytearray(store.path.read_bytes())
    blob[0] ^= 0x01
    store.path.write_bytes(bytes(blob))

    with pytest.raises(RevocationRefused) as caught:
        store.current()
    assert "out of service rather than unrevoked" in str(caught.value)


def test_a_revoked_signer_cannot_issue_the_next_list(tmp_path: Path) -> None:
    """The key is revoked by the list in force, and applied before belief."""

    store = RevocationStore(
        root=tmp_path / "lite", trusted_keys=(TRUSTED_KEY, SECOND_TRUSTED_KEY)
    )
    store.accept(
        signed(
            a_list(
                1,
                revoked_digests=frozenset({BAD_ARTIFACT}),
                revoked_keys=frozenset({SECOND_TRUSTED_KEY.hex()}),
            )
        )
    )

    with pytest.raises(RevocationRefused) as caught:
        store.accept(signed(a_list(2), seed=SECOND_TRUSTED_SEED))
    assert "itself revoked" in str(caught.value)
    assert store.current().revokes_digest(BAD_ARTIFACT) is True

    # The still-trusted key can, so the refusal above is about the revocation
    # and not about sequence 2 being unacceptable.
    store.accept(signed(a_list(2), seed=TRUSTED_SEED))
    assert store.current().sequence == 2


def test_a_failed_write_leaves_the_previous_list_in_force(
    store: RevocationStore, monkeypatch
) -> None:
    import os as os_module

    store.accept(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))
    monkeypatch.setattr(os_module, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("full")))

    with pytest.raises(OSError):
        store.accept(signed(a_list(2)))

    assert store.current().sequence == 1
    assert store.current().revokes_digest(BAD_ARTIFACT) is True
    leftovers = sorted(p.name for p in store.root.iterdir())
    assert leftovers == [REVOCATION_FILENAME], f"a failed write left {leftovers}"


# -- malformed input -------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 63, 64])
def test_a_blob_with_no_payload_is_refused(store: RevocationStore, length: int) -> None:
    with pytest.raises(RevocationRefused) as caught:
        store.accept(b"\x00" * length)
    assert "signature followed by a payload" in str(caught.value)


def test_a_payload_that_is_not_json_is_refused(store: RevocationStore) -> None:
    payload = b"not json at all"
    with pytest.raises(RevocationRefused) as caught:
        store.accept(sign_detached(seed=TRUSTED_SEED, message=payload) + payload)
    assert "not JSON" in str(caught.value)


@pytest.mark.parametrize(
    "payload, expected",
    [
        (b'{"issued_at":"2026-09-01T00:00:00Z"}', "sequence"),
        (b'{"sequence":1}', "issued_at"),
        (b'{"sequence":"1","issued_at":"x"}', "an integer"),
        (b'{"sequence":true,"issued_at":"x"}', "an integer"),
        (b'{"sequence":1,"issued_at":"   "}', "when it was issued"),
        (b'{"sequence":1,"issued_at":"x","revoked_generations":["2"]}', "list of integers"),
        (b'{"sequence":1,"issued_at":"x","revoked_keys":[7]}', "list of strings"),
        (b'[]', "an object"),
    ],
)
def test_every_malformed_payload_is_refused_with_its_own_reason(
    store: RevocationStore, payload: bytes, expected: str
) -> None:
    with pytest.raises(RevocationRefused) as caught:
        store.accept(sign_detached(seed=TRUSTED_SEED, message=payload) + payload)
    assert expected in str(caught.value)


def test_a_revoked_digest_that_is_not_a_digest_is_refused(store: RevocationStore) -> None:
    """A revocation list cannot smuggle a path in where a digest belongs."""

    payload = b'{"sequence":1,"issued_at":"x","revoked_digests":["../../etc/passwd"]}'
    with pytest.raises(ContentRefused):
        store.accept(sign_detached(seed=TRUSTED_SEED, message=payload) + payload)


# -- trust store hygiene ---------------------------------------------------


def test_one_unusable_trusted_key_does_not_make_every_list_unverifiable(
    tmp_path: Path,
) -> None:
    """A truncated key in the trust store is an operator fault, not an outage."""

    store = RevocationStore(
        root=tmp_path / "lite", trusted_keys=(b"\x00" * 8, TRUSTED_KEY)
    )
    store.accept(signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))))
    assert store.current().revokes_digest(BAD_ARTIFACT) is True


def test_the_result_does_not_depend_on_the_order_of_trusted_keys(tmp_path: Path) -> None:
    blob = signed(a_list(1, revoked_digests=frozenset({BAD_ARTIFACT})))
    for index, keys in enumerate(
        ((OTHER_KEY, TRUSTED_KEY), (TRUSTED_KEY, OTHER_KEY))
    ):
        store = RevocationStore(root=tmp_path / f"lite{index}", trusted_keys=keys)
        store.accept(blob)
        assert store.current().revokes_digest(BAD_ARTIFACT) is True


# -- what the operator plane is told ---------------------------------------


def test_reason_for_names_the_statement_that_withdrew_the_artifact() -> None:
    revocations = a_list(
        4, revoked_digests=frozenset({BAD_ARTIFACT}), revoked_generations=frozenset({7})
    )
    assert revocations.reason_for(digest=BAD_ARTIFACT) == (
        f"artifact {BAD_ARTIFACT} is revoked by revocation sequence 4"
    )
    assert revocations.reason_for(generation=7) == (
        "generation 7 is revoked by revocation sequence 4"
    )
    assert revocations.reason_for(digest=OTHER_ARTIFACT, generation=8) is None


def test_a_generation_and_a_digest_are_revoked_independently() -> None:
    """Revoking generation 7 does not revoke an artifact, and vice versa."""

    by_generation = a_list(1, revoked_generations=frozenset({7}))
    assert by_generation.revokes_generation(7) is True
    assert by_generation.revokes_digest(BAD_ARTIFACT) is False

    by_digest = a_list(1, revoked_digests=frozenset({BAD_ARTIFACT}))
    assert by_digest.revokes_digest(BAD_ARTIFACT) is True
    assert by_digest.revokes_generation(7) is False
