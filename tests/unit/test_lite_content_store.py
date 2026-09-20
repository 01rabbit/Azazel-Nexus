"""Content addressing (#6, E1).

The store's whole purpose is to notice bytes that changed after admission.
Every test here is written so that it can only pass because the digest was
re-derived -- not because the file was missing, not because an unrelated
parse refused first, and not because the test and the implementation happen
to agree on a constant.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from azazel_nexus.content_store import (
    DIGEST_HEX_LENGTH,
    ContentRefused,
    ContentStore,
    ContentTampered,
    digest_bytes,
    parse_digest,
)


@pytest.fixture()
def store(tmp_path: Path) -> ContentStore:
    return ContentStore(root=tmp_path / "cache")


def test_the_address_is_the_sha256_of_the_bytes_and_nothing_else() -> None:
    """Pinned against hashlib directly, not against the module's own output."""

    data = b"advisory claim"
    assert digest_bytes(data) == "sha256:" + hashlib.sha256(data).hexdigest()


def test_a_round_trip_returns_the_same_bytes(store: ContentStore) -> None:
    digest = store.put(b"advisory claim")
    assert store.get(digest) == b"advisory claim"


def test_storing_the_same_bytes_twice_is_one_blob(store: ContentStore) -> None:
    first = store.put(b"advisory claim")
    second = store.put(b"advisory claim")
    assert first == second
    assert sum(1 for path in store.objects.rglob("*") if path.is_file()) == 1


def test_different_bytes_get_different_addresses(store: ContentStore) -> None:
    assert store.put(b"one") != store.put(b"two")


# -- the property the store exists for -------------------------------------


def test_a_blob_altered_after_admission_is_refused_on_read(store: ContentStore) -> None:
    """The file is present and readable. Only its contents changed.

    A store that trusted the filename would return the altered bytes here.
    """

    digest = store.put(b"advisory claim")
    target = store.path_for(digest)
    assert target.is_file()

    target.write_bytes(b"advisory claiM")
    assert target.is_file(), "the blob is still present; absence is not the failure under test"

    with pytest.raises(ContentTampered) as caught:
        store.get(digest)
    assert caught.value.expected == digest
    assert caught.value.actual == digest_bytes(b"advisory claiM")
    assert caught.value.expected != caught.value.actual


def test_a_single_flipped_bit_is_refused(store: ContentStore) -> None:
    """Same length, same path, one bit. Nothing else can be noticing this."""

    digest = store.put(b"\x00" * 64)
    target = store.path_for(digest)
    altered = bytearray(target.read_bytes())
    altered[17] ^= 0x01
    target.write_bytes(bytes(altered))

    assert len(target.read_bytes()) == 64
    with pytest.raises(ContentTampered):
        store.get(digest)


def test_tampering_is_reported_and_not_repaired(store: ContentStore) -> None:
    """The evidence survives the refusal.

    A store that healed the blob would leave an operator with a clean cache
    and no record that anything happened.
    """

    digest = store.put(b"advisory claim")
    target = store.path_for(digest)
    target.write_bytes(b"tampered")

    with pytest.raises(ContentTampered):
        store.get(digest)
    assert target.read_bytes() == b"tampered", "the altered bytes must still be there to look at"


def test_put_refuses_to_overwrite_a_tampered_blob(store: ContentStore) -> None:
    """Re-admitting the original content must not erase the evidence either."""

    digest = store.put(b"advisory claim")
    store.path_for(digest).write_bytes(b"tampered")

    with pytest.raises(ContentTampered):
        store.put(b"advisory claim")
    assert store.path_for(digest).read_bytes() == b"tampered"


def test_has_reports_presence_and_says_nothing_about_integrity(store: ContentStore) -> None:
    """Two different questions. `has` answers the cheap one, and only it."""

    digest = store.put(b"advisory claim")
    store.path_for(digest).write_bytes(b"tampered")

    assert store.has(digest) is True
    with pytest.raises(ContentTampered):
        store.get(digest)


def test_reading_an_absent_address_is_refused_as_absent_not_as_tampering(
    store: ContentStore,
) -> None:
    """The two failures have different operator responses and different types."""

    absent = digest_bytes(b"never stored")
    with pytest.raises(ContentRefused) as caught:
        store.get(absent)
    assert not isinstance(caught.value, ContentTampered)
    assert "no content addressed" in str(caught.value)


# -- a digest is never a path ---------------------------------------------


@pytest.mark.parametrize(
    "digest, expected",
    [
        ("2cf2" * 16, "algorithm-qualified"),
        ("sha512:" + "a" * 64, "algorithm"),
        ("sha256:" + "a" * (DIGEST_HEX_LENGTH - 1), "hex characters"),
        ("sha256:" + "a" * (DIGEST_HEX_LENGTH + 1), "hex characters"),
        ("sha256:" + "A" * DIGEST_HEX_LENGTH, "lower-case hex"),
        # Exactly 64 characters, so the length check passes and the hex check
        # is the one that refuses it. That is the point of the case.
        ("sha256:" + "../" * 21 + "x", "lower-case hex"),
    ],
)
def test_every_malformed_digest_is_refused_with_its_own_reason(
    digest: str, expected: str
) -> None:
    with pytest.raises(ContentRefused) as caught:
        parse_digest(digest)
    assert expected in str(caught.value)


def test_a_traversal_attempt_never_reaches_the_filesystem(store: ContentStore) -> None:
    """`path_for` parses before it composes, so no path is built at all."""

    traversal = "sha256:" + "../" * 21 + "x"
    with pytest.raises(ContentRefused):
        store.path_for(traversal)
    with pytest.raises(ContentRefused):
        store.has(traversal)
    with pytest.raises(ContentRefused):
        store.get(traversal)


def test_a_stored_blob_lives_under_the_objects_directory(store: ContentStore) -> None:
    """Fan-out is by the digest's own first byte, not by anything else."""

    digest = store.put(b"advisory claim")
    hex_part = digest.split(":", 1)[1]
    assert store.path_for(digest) == store.objects / hex_part[:2] / hex_part[2:]
    assert store.path_for(digest).is_file()


def test_a_failed_write_leaves_no_partial_blob(store: ContentStore, monkeypatch) -> None:
    """The temporary file is removed; the address stays unoccupied."""

    import os as os_module

    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os_module, "replace", refuse)
    with pytest.raises(OSError):
        store.put(b"advisory claim")

    assert store.has(digest_bytes(b"advisory claim")) is False
    leftovers = [path.name for path in store.objects.rglob("*") if path.is_file()]
    assert leftovers == [], f"a failed write left {leftovers} behind"
