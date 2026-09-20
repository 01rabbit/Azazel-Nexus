"""The keys a Knowledge Lite artifact must be signed by (#6, E1)."""

from __future__ import annotations

from pathlib import Path

import pytest
from signing_oracle import public_key_for

from azazel_nexus.lite_trust import TRUST_FILENAME, TrustRefused, TrustStore

KEY_A = public_key_for(bytes(range(32))).hex()
KEY_B = public_key_for(bytes(range(32, 64))).hex()
COMMISSIONING = "sha256:" + "a" * 64
OTHER_COMMISSIONING = "sha256:" + "b" * 64


@pytest.fixture()
def trust(tmp_path: Path) -> TrustStore:
    return TrustStore(root=tmp_path / "lite")


def test_nothing_is_pinned_on_a_fresh_node(trust: TrustStore) -> None:
    assert trust.is_pinned() is False
    with pytest.raises(TrustRefused) as caught:
        trust.keys(commissioning_digest=COMMISSIONING)
    assert "nothing is admitted until keys are pinned" in str(caught.value)


def test_pinned_keys_come_back(trust: TrustStore) -> None:
    trust.pin(
        [KEY_A, KEY_B],
        commissioning_digest=COMMISSIONING,
        pinned_at="2026-09-01T00:00:00Z",
        actor="operator",
    )
    assert trust.is_pinned() is True
    assert trust.keys(commissioning_digest=COMMISSIONING) == (
        bytes.fromhex(KEY_A),
        bytes.fromhex(KEY_B),
    )


def test_keys_do_not_carry_across_a_re_commissioning(trust: TrustStore) -> None:
    """The binding, stated as a refusal.

    These are the right keys for the node this used to be. That is not an
    argument for trusting them now.
    """

    trust.pin(
        [KEY_A], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
    )
    with pytest.raises(TrustRefused) as caught:
        trust.keys(commissioning_digest=OTHER_COMMISSIONING)
    assert "do not carry across a re-commissioning" in str(caught.value)


def test_pinning_twice_is_refused(trust: TrustStore) -> None:
    trust.pin(
        [KEY_A], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
    )
    with pytest.raises(TrustRefused) as caught:
        trust.pin(
            [KEY_B],
            commissioning_digest=COMMISSIONING,
            pinned_at="2026-09-02T00:00:00Z",
            actor="op",
        )
    assert "already pinned" in str(caught.value)
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(KEY_A),)


def test_repinning_records_why_and_who(trust: TrustStore) -> None:
    trust.pin(
        [KEY_A], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
    )
    trust.repin(
        [KEY_B],
        commissioning_digest=COMMISSIONING,
        pinned_at="2026-09-02T00:00:00Z",
        reason="the previous signer was retired",
        actor="operator@node",
    )
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(KEY_B),)
    assert trust.pinned_at() == "2026-09-02T00:00:00Z"


@pytest.mark.parametrize("reason", ["", "   "])
def test_a_repin_without_a_reason_is_refused(trust: TrustStore, reason: str) -> None:
    trust.pin(
        [KEY_A], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
    )
    with pytest.raises(TrustRefused) as caught:
        trust.repin(
            [KEY_B],
            commissioning_digest=COMMISSIONING,
            pinned_at="2026-09-02T00:00:00Z",
            reason=reason,
            actor="op",
        )
    assert "must record why" in str(caught.value)
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(KEY_A),)


def test_repinning_when_nothing_is_pinned_is_refused(trust: TrustStore) -> None:
    """A first pinning is a commissioning step, not a correction."""

    with pytest.raises(TrustRefused) as caught:
        trust.repin(
            [KEY_A],
            commissioning_digest=COMMISSIONING,
            pinned_at="2026-09-01T00:00:00Z",
            reason="r",
            actor="op",
        )
    assert "first pinning is `pin`" in str(caught.value)
    assert trust.is_pinned() is False


def test_an_empty_trust_set_is_refused_at_pin_time(trust: TrustStore) -> None:
    with pytest.raises(TrustRefused) as caught:
        trust.pin([], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op")
    assert "no keys admits no artifact" in str(caught.value)
    assert trust.is_pinned() is False


def test_a_malformed_key_is_refused_before_anything_is_written(trust: TrustStore) -> None:
    """Otherwise the fault presents as "Lite never works" rather than as one."""

    with pytest.raises(TrustRefused) as caught:
        trust.pin(
            [KEY_A, "not-a-key"],
            commissioning_digest=COMMISSIONING,
            pinned_at="2026-09-01T00:00:00Z",
            actor="op",
        )
    assert "unusable" in str(caught.value)
    assert trust.is_pinned() is False


def test_duplicate_keys_are_pinned_once(trust: TrustStore) -> None:
    trust.pin(
        [KEY_A, KEY_A],
        commissioning_digest=COMMISSIONING,
        pinned_at="2026-09-01T00:00:00Z",
        actor="op",
    )
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(KEY_A),)


def test_the_pinned_order_does_not_depend_on_the_caller(tmp_path: Path) -> None:
    for index, order in enumerate(([KEY_A, KEY_B], [KEY_B, KEY_A])):
        trust = TrustStore(root=tmp_path / f"lite{index}")
        trust.pin(
            order, commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
        )
        assert trust.keys(commissioning_digest=COMMISSIONING) == (
            bytes.fromhex(KEY_A),
            bytes.fromhex(KEY_B),
        )


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({"commissioning_digest": "  "}, "pinned under a commissioning"),
        ({"pinned_at": ""}, "when it was pinned"),
        ({"actor": "   "}, "who pinned it"),
    ],
)
def test_a_pinning_without_its_provenance_is_refused(
    trust: TrustStore, kwargs: dict, expected: str
) -> None:
    fields = {
        "commissioning_digest": COMMISSIONING,
        "pinned_at": "2026-09-01T00:00:00Z",
        "actor": "op",
    }
    fields.update(kwargs)
    with pytest.raises(TrustRefused) as caught:
        trust.pin([KEY_A], **fields)
    assert expected in str(caught.value)
    assert trust.is_pinned() is False


def test_an_unreadable_trust_store_is_refused_not_treated_as_empty(
    trust: TrustStore,
) -> None:
    trust.pin(
        [KEY_A], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
    )
    trust.path.write_text("{not json", encoding="utf-8")
    with pytest.raises(TrustRefused) as caught:
        trust.keys(commissioning_digest=COMMISSIONING)
    assert "unreadable" in str(caught.value)


def test_a_failed_write_leaves_the_previous_pinning_in_place(
    trust: TrustStore, monkeypatch
) -> None:
    import os as os_module

    trust.pin(
        [KEY_A], commissioning_digest=COMMISSIONING, pinned_at="2026-09-01T00:00:00Z", actor="op"
    )
    monkeypatch.setattr(
        os_module, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("full"))
    )
    with pytest.raises(OSError):
        trust.repin(
            [KEY_B],
            commissioning_digest=COMMISSIONING,
            pinned_at="2026-09-02T00:00:00Z",
            reason="r",
            actor="op",
        )
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(KEY_A),)
    assert sorted(p.name for p in trust.root.iterdir()) == [TRUST_FILENAME]
