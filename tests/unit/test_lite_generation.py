"""Knowledge Lite generations and rollback (#6, E1).

The first test in this file is the one that would have failed before this
change existed: after a promotion, the artifact that was displaced is still
there. `StagedReader._promote` deleted it, so rollback was not an unimplemented
feature -- it was an impossible one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from azazel_nexus.content_store import ContentStore, ContentTampered, digest_bytes
from azazel_nexus.lite_generation import (
    LiteGeneration,
    LiteGenerationRefused,
    LiteGenerationStore,
)

SIGNER = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
OTHER_SIGNER = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"


@pytest.fixture()
def store(tmp_path: Path) -> LiteGenerationStore:
    root = tmp_path / "lite"
    return LiteGenerationStore(root=root, content=ContentStore(root=root))


def admit(store: LiteGenerationStore, payload: bytes, *, at: str, signer: str = SIGNER):
    digest = store.content.put(payload)
    return store.promote(artifact_digest=digest, signer_key=signer, admitted_at=at)


# -- the property that did not exist before --------------------------------


def test_a_promotion_does_not_destroy_what_it_displaced(store: LiteGenerationStore) -> None:
    """Rollback is possible because the displaced artifact is still readable."""

    first = admit(store, b"bundle one", at="2026-09-01T00:00:00Z")
    admit(store, b"bundle two", at="2026-09-02T00:00:00Z")

    assert store.live().number == 2
    assert store.read(first.number).artifact_digest == digest_bytes(b"bundle one")
    assert store.artifact_of(store.read(first.number)) == b"bundle one"


def test_rolling_back_serves_the_older_artifact_again(store: LiteGenerationStore) -> None:
    admit(store, b"bundle one", at="2026-09-01T00:00:00Z")
    admit(store, b"bundle two", at="2026-09-02T00:00:00Z")

    rolled = store.roll_back_to(
        1, admitted_at="2026-09-03T00:00:00Z", reason="bundle two mislabels a CVE", actor="operator"
    )

    assert rolled.number == 3
    assert store.live().number == 3
    assert store.artifact_of(store.live()) == b"bundle one"


def test_a_rollback_moves_the_history_forwards_not_backwards(
    store: LiteGenerationStore,
) -> None:
    """Generation 2 is still on disk and still says what it said."""

    admit(store, b"bundle one", at="2026-09-01T00:00:00Z")
    admit(store, b"bundle two", at="2026-09-02T00:00:00Z")
    rolled = store.roll_back_to(
        1, admitted_at="2026-09-03T00:00:00Z", reason="regression", actor="operator"
    )

    assert store.numbers() == (1, 2, 3)
    assert store.read(2).artifact_digest == digest_bytes(b"bundle two")
    assert rolled.rolled_back_from == 2
    assert rolled.supersedes == 2
    assert rolled.is_rollback is True


def test_a_rollback_records_why_and_who(store: LiteGenerationStore) -> None:
    admit(store, b"one", at="2026-09-01T00:00:00Z")
    admit(store, b"two", at="2026-09-02T00:00:00Z")
    rolled = store.roll_back_to(
        1, admitted_at="2026-09-03T00:00:00Z", reason="bad IOC set", actor="operator@node"
    )

    event = rolled.as_event()
    assert event["event_type"] == "lite.generation.rolled_back"
    assert event["rollback_reason"] == "bad IOC set"
    assert event["actor"] == "operator@node"
    assert event["rolled_back_from"] == 2


@pytest.mark.parametrize("reason, actor", [("", "operator"), ("   ", "operator"), ("why", ""), ("why", "  ")])
def test_a_rollback_without_a_reason_or_an_actor_is_refused(reason: str, actor: str) -> None:
    with pytest.raises(LiteGenerationRefused):
        LiteGeneration(
            number=3,
            artifact_digest=digest_bytes(b"x"),
            signer_key=SIGNER,
            admitted_at="2026-09-03T00:00:00Z",
            supersedes=2,
            rolled_back_from=2,
            rollback_reason=reason,
            actor=actor,
        )


def test_rolling_back_to_an_altered_artifact_is_refused(store: LiteGenerationStore) -> None:
    """The one rollback that must fail.

    The generation record is intact and names a blob that is present. Only the
    bytes changed, and only the digest re-derivation can notice.
    """

    first = admit(store, b"bundle one", at="2026-09-01T00:00:00Z")
    admit(store, b"bundle two", at="2026-09-02T00:00:00Z")
    store.content.path_for(first.artifact_digest).write_bytes(b"bundle onE")

    with pytest.raises(LiteGenerationRefused) as caught:
        store.roll_back_to(1, admitted_at="2026-09-03T00:00:00Z", reason="r", actor="a")
    assert "no longer hashes" in str(caught.value)
    assert store.live().number == 2, "the live generation is unchanged by a failed rollback"


def test_rolling_back_to_the_live_generation_is_refused(store: LiteGenerationStore) -> None:
    admit(store, b"one", at="2026-09-01T00:00:00Z")
    admit(store, b"two", at="2026-09-02T00:00:00Z")
    with pytest.raises(LiteGenerationRefused) as caught:
        store.roll_back_to(2, admitted_at="2026-09-03T00:00:00Z", reason="r", actor="a")
    assert "already live" in str(caught.value)


def test_rolling_back_with_nothing_promoted_is_refused(store: LiteGenerationStore) -> None:
    with pytest.raises(LiteGenerationRefused):
        store.roll_back_to(1, admitted_at="2026-09-03T00:00:00Z", reason="r", actor="a")


# -- promotion rules -------------------------------------------------------


def test_nothing_is_live_before_the_first_promotion(store: LiteGenerationStore) -> None:
    assert store.live() is None
    assert store.numbers() == ()


def test_generation_numbers_only_increase(store: LiteGenerationStore) -> None:
    for index, payload in enumerate([b"a", b"b", b"c"], start=1):
        assert admit(store, payload, at=f"2026-09-0{index}T00:00:00Z").number == index
    assert store.numbers() == (1, 2, 3)


def test_a_generation_names_content_that_is_already_stored(store: LiteGenerationStore) -> None:
    """A live pointer to an address holding nothing would serve nothing."""

    with pytest.raises(LiteGenerationRefused) as caught:
        store.promote(
            artifact_digest=digest_bytes(b"never stored"),
            signer_key=SIGNER,
            admitted_at="2026-09-01T00:00:00Z",
        )
    assert "already stored" in str(caught.value)
    assert store.live() is None


def test_a_generation_names_its_signer(store: LiteGenerationStore) -> None:
    generation = admit(store, b"one", at="2026-09-01T00:00:00Z", signer=OTHER_SIGNER)
    assert generation.signer_key == OTHER_SIGNER
    assert generation.as_event()["signer_key"] == OTHER_SIGNER


@pytest.mark.parametrize("signer", ["", SIGNER[:-1], SIGNER + "aa"])
def test_a_generation_without_a_full_signer_key_is_refused(signer: str) -> None:
    with pytest.raises(LiteGenerationRefused) as caught:
        LiteGeneration(
            number=1,
            artifact_digest=digest_bytes(b"x"),
            signer_key=signer,
            admitted_at="2026-09-01T00:00:00Z",
        )
    assert "signer" in str(caught.value)


def test_a_generation_that_supersedes_a_later_one_is_refused() -> None:
    with pytest.raises(LiteGenerationRefused) as caught:
        LiteGeneration(
            number=2,
            artifact_digest=digest_bytes(b"x"),
            signer_key=SIGNER,
            admitted_at="2026-09-01T00:00:00Z",
            supersedes=3,
        )
    assert "only move forward" in str(caught.value)


def test_serving_the_live_artifact_re_derives_its_digest(store: LiteGenerationStore) -> None:
    """Verification at admission does not cover bytes that change afterwards.

    The live generation record is untouched and names a blob that is present,
    so nothing except the re-derivation can notice. Without this test,
    `artifact_of` could read the file directly and every other test here would
    still pass -- which is how a guard that never runs gets written.
    """

    admit(store, b"bundle one", at="2026-09-01T00:00:00Z")
    live = store.live()
    assert store.artifact_of(live) == b"bundle one"

    store.content.path_for(live.artifact_digest).write_bytes(b"bundle onE")
    with pytest.raises(ContentTampered):
        store.artifact_of(store.live())


def test_the_event_carries_provenance_and_no_content(store: LiteGenerationStore) -> None:
    """Audit records what was admitted, never what it said."""

    generation = admit(store, b"secret-looking bundle body", at="2026-09-01T00:00:00Z")
    event = generation.as_event()
    assert event["event_type"] == "lite.generation.promoted"
    assert event["artifact_digest"] == digest_bytes(b"secret-looking bundle body")
    assert "secret-looking" not in repr(event)


# -- the live pointer ------------------------------------------------------


def test_live_is_read_from_the_pointer_not_from_the_highest_number(
    store: LiteGenerationStore,
) -> None:
    """After a rollback those two agree. The test makes them disagree.

    Generation 1 is the one being served while generation 2 exists on disk, a
    state a promotion never produces but a partially applied one can.
    """

    admit(store, b"one", at="2026-09-01T00:00:00Z")
    admit(store, b"two", at="2026-09-02T00:00:00Z")
    store.live_pointer.write_text("1\n", encoding="utf-8")

    assert store.numbers()[-1] == 2
    assert store.live().number == 1


def test_a_live_pointer_that_is_not_a_number_is_refused(store: LiteGenerationStore) -> None:
    admit(store, b"one", at="2026-09-01T00:00:00Z")
    store.live_pointer.write_text("../../etc\n", encoding="utf-8")
    with pytest.raises(LiteGenerationRefused) as caught:
        store.live()
    assert "not a generation number" in str(caught.value)


def test_a_failed_pointer_write_leaves_no_debris(store: LiteGenerationStore, monkeypatch) -> None:
    import os as os_module

    admit(store, b"one", at="2026-09-01T00:00:00Z")
    store.content.put(b"two")
    monkeypatch.setattr(os_module, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("full")))
    with pytest.raises(OSError):
        store.promote(
            artifact_digest=digest_bytes(b"two"),
            signer_key=SIGNER,
            admitted_at="2026-09-02T00:00:00Z",
        )
    debris = [p.name for p in store.root.iterdir() if p.name.startswith(".live-")]
    assert debris == [], f"a failed pointer write left {debris}"


# -- pruning ---------------------------------------------------------------


def test_pruning_keeps_the_newest_generations(store: LiteGenerationStore) -> None:
    for index, payload in enumerate([b"a", b"b", b"c", b"d"], start=1):
        admit(store, payload, at=f"2026-09-0{index}T00:00:00Z")

    assert store.prune(retain=2) == (1, 2)
    assert store.numbers() == (3, 4)


def test_pruning_never_removes_the_live_generation(store: LiteGenerationStore) -> None:
    """Retention is a disk policy. It must not become an outage."""

    for index, payload in enumerate([b"a", b"b", b"c", b"d"], start=1):
        admit(store, payload, at=f"2026-09-0{index}T00:00:00Z")
    store.live_pointer.write_text("1\n", encoding="utf-8")

    removed = store.prune(retain=2)
    assert 1 not in removed
    assert store.live().number == 1
    assert store.artifact_of(store.live()) == b"a"


def test_pruning_keeps_a_blob_that_a_retained_generation_still_names(
    store: LiteGenerationStore,
) -> None:
    """A rollback makes two generations share one artifact.

    Pruning the older one must not delete the bytes the newer one serves.
    """

    admit(store, b"a", at="2026-09-01T00:00:00Z")
    admit(store, b"b", at="2026-09-02T00:00:00Z")
    store.roll_back_to(1, admitted_at="2026-09-03T00:00:00Z", reason="r", actor="op")

    assert store.prune(retain=2) == (1,)
    assert store.live().number == 3
    assert store.artifact_of(store.live()) == b"a"


def test_pruning_removes_the_blob_nothing_names_any_more(store: LiteGenerationStore) -> None:
    first = admit(store, b"a", at="2026-09-01T00:00:00Z")
    admit(store, b"b", at="2026-09-02T00:00:00Z")

    assert store.content.has(first.artifact_digest) is True
    store.prune(retain=1)
    assert store.content.has(first.artifact_digest) is False


def test_pruning_nothing_when_there_is_nothing_to_prune(store: LiteGenerationStore) -> None:
    admit(store, b"a", at="2026-09-01T00:00:00Z")
    assert store.prune(retain=3) == ()
    assert store.numbers() == (1,)


def test_retaining_nothing_is_refused(store: LiteGenerationStore) -> None:
    admit(store, b"a", at="2026-09-01T00:00:00Z")
    with pytest.raises(LiteGenerationRefused) as caught:
        store.prune(retain=0)
    assert "retention starts at 1" in str(caught.value)
