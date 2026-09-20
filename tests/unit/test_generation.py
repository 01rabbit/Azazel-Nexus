"""Promoted, never edited in place; and a rollback that reads forwards (#27)."""

from __future__ import annotations

import pytest

from azazel_nexus.generation import (
    Generation,
    GenerationRefused,
    GenerationStore,
    tree_digest,
)

T0 = "2026-09-20T00:00:00+00:00"
T1 = "2026-09-20T01:00:00+00:00"
T2 = "2026-09-20T02:00:00+00:00"
CD = "sha256:" + "a" * 64


@pytest.fixture()
def store(tmp_path) -> GenerationStore:
    return GenerationStore(tmp_path / "generations")


def test_the_first_generation_supersedes_nothing(store):
    first = store.create({"node.yaml": b"a: 1\n"}, created_at=T0, commissioning_digest=CD)
    assert (first.number, first.supersedes) == (1, None)


def test_generations_only_move_forward(store):
    store.create({"node.yaml": b"a: 1\n"}, created_at=T0, commissioning_digest=CD)
    second = store.create({"node.yaml": b"a: 2\n"}, created_at=T1, commissioning_digest=CD)
    assert (second.number, second.supersedes) == (2, 1)
    assert store.numbers() == (1, 2)


def test_a_generation_cannot_claim_to_supersede_a_later_one():
    with pytest.raises(GenerationRefused, match="only move forward"):
        Generation(
            number=2, digest=CD, created_at=T0, commissioning_digest=CD, supersedes=3
        )


# -- the digest -------------------------------------------------------------


def test_moving_a_file_between_names_changes_the_digest():
    """A digest over contents alone calls two configurations the same one."""

    body = b"listen: 0.0.0.0\n"
    assert tree_digest({"a.yaml": body}) != tree_digest({"b.yaml": body})


def test_the_digest_does_not_depend_on_iteration_order():
    files = {"b.yaml": b"2\n", "a.yaml": b"1\n"}
    assert tree_digest(files) == tree_digest(dict(reversed(list(files.items()))))


@pytest.mark.parametrize("path", ["/etc/passwd", "../outside", "a/../../outside", ""])
def test_a_path_outside_the_tree_is_refused(path):
    with pytest.raises(GenerationRefused, match="inside the generation tree"):
        tree_digest({path: b""})


def test_verify_rederives_the_digest_from_the_tree(store):
    """Called on every boot (§2.3). Verified once is verified for one tree."""

    store.create({"node.yaml": b"a: 1\n"}, created_at=T0, commissioning_digest=CD)
    assert store.verify(1).number == 1

    (store.root / "1" / "tree" / "node.yaml").write_bytes(b"a: 999\n")
    with pytest.raises(GenerationRefused, match="not the configuration that was verified"):
        store.verify(1)


def test_a_second_creation_does_not_touch_the_first_generation(store):
    """Promoted, never edited in place (§3).

    The store allocates the next number, so two creations never target the
    same directory. The first generation's tree is what it was.
    """

    store.create({"node.yaml": b"a: 1\n"}, created_at=T0, commissioning_digest=CD)
    second = store.create({"node.yaml": b"a: 2\n"}, created_at=T1, commissioning_digest=CD)

    assert second.number == 2
    assert store.read_tree(1) == {"node.yaml": b"a: 1\n"}
    assert store.read_tree(2) == {"node.yaml": b"a: 2\n"}


def test_two_writers_that_allocated_the_same_number_do_not_merge_trees(store, monkeypatch):
    """The refusal ordinary single-threaded use cannot reach.

    `create()` allocates the next free number, so one caller never collides
    with itself. Two callers can: both read the same highest number, both
    compute the same next one, and the second one must not write into the
    first one's directory. That would merge two configurations into one tree
    and give it one digest, which would then verify.

    The race is reproduced by holding the allocation stale rather than by
    threading, so the test is deterministic and the branch is genuinely
    exercised rather than assumed.
    """

    store.create({"node.yaml": b"first\n"}, created_at=T0, commissioning_digest=CD)
    store.create({"node.yaml": b"second\n"}, created_at=T1, commissioning_digest=CD)

    monkeypatch.setattr(store, "numbers", lambda: (1,))
    with pytest.raises(GenerationRefused, match="never edited in place"):
        store.create({"node.yaml": b"third\n"}, created_at=T2, commissioning_digest=CD)

    assert store.read_tree(2) == {"node.yaml": b"second\n"}


# -- rollback ---------------------------------------------------------------


def test_a_rollback_creates_a_new_generation_rather_than_moving_a_pointer(store):
    """What was rolled back stays on disk, with its own number.

    A pointer moved backwards leaves a history that reads as though the bad
    generation never existed. An operator asking "what did we try" then has
    nothing to read.
    """

    first = store.create({"node.yaml": b"good\n"}, created_at=T0, commissioning_digest=CD)
    store.create({"node.yaml": b"bad\n"}, created_at=T1, commissioning_digest=CD)

    third = store.roll_back_to(1, created_at=T2, reason="bad broke the UI", actor="op-1")

    assert store.numbers() == (1, 2, 3)
    assert third.rolled_back_from == 2
    assert third.digest == first.digest
    assert store.read_tree(2) == {"node.yaml": b"bad\n"}


def test_a_rollback_records_reason_actor_digest_and_generations(store):
    store.create({"node.yaml": b"good\n"}, created_at=T0, commissioning_digest=CD)
    store.create({"node.yaml": b"bad\n"}, created_at=T1, commissioning_digest=CD)
    third = store.roll_back_to(1, created_at=T2, reason="bad broke the UI", actor="op-1")

    event = third.as_event()
    assert event["event_type"] == "generation.rolled_back"
    assert event["rolled_back_from"] == 2
    assert event["rollback_reason"] == "bad broke the UI"
    assert event["actor"] == "op-1"
    assert event["digest"] == third.digest
    assert event["generation"] == 3


@pytest.mark.parametrize(
    "reason,actor,match",
    [("", "op-1", "must record why"), ("  ", "op-1", "must record why"),
     ("bad", "", "who performed it"), ("bad", None, "who performed it")],
)
def test_an_unexplained_or_unattributed_rollback_is_refused(reason, actor, match):
    with pytest.raises(GenerationRefused, match=match):
        Generation(
            number=3,
            digest=CD,
            created_at=T0,
            commissioning_digest=CD,
            supersedes=2,
            rolled_back_from=2,
            rollback_reason=reason,
            actor=actor,
        )


def test_rolling_back_to_the_current_generation_is_refused(store):
    store.create({"node.yaml": b"a\n"}, created_at=T0, commissioning_digest=CD)
    with pytest.raises(GenerationRefused, match="already current"):
        store.roll_back_to(1, created_at=T1, reason="none", actor="op-1")


def test_rolling_back_to_a_tampered_generation_is_refused(store):
    """The target is verified first. Rollback restores a checked tree."""

    store.create({"node.yaml": b"good\n"}, created_at=T0, commissioning_digest=CD)
    store.create({"node.yaml": b"bad\n"}, created_at=T1, commissioning_digest=CD)
    (store.root / "1" / "tree" / "node.yaml").write_bytes(b"tampered\n")

    with pytest.raises(GenerationRefused, match="not the configuration"):
        store.roll_back_to(1, created_at=T2, reason="go back", actor="op-1")
