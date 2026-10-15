"""Generation evidence bindings stay private and prevent bound rollbacks."""

from __future__ import annotations

import json

import pytest

from azazel_nexus.generation import GenerationRefused, GenerationStore

T0 = "2026-09-20T00:00:00+00:00"
T1 = "2026-09-20T01:00:00+00:00"
T2 = "2026-09-20T02:00:00+00:00"
CD = "sha256:" + "a" * 64
BINDING = "hmac-sha256:" + "b" * 64


@pytest.fixture()
def store(tmp_path) -> GenerationStore:
    return GenerationStore(tmp_path / "generations")


def test_evidence_binding_round_trips_in_metadata_but_not_audit_event(store):
    generation = store.create(
        {"node.yaml": b"a: 1\n"},
        created_at=T0,
        commissioning_digest=CD,
        commissioning_evidence_binding=BINDING,
    )

    metadata = json.loads(store._meta(generation.number).read_text(encoding="utf-8"))
    assert metadata["commissioning_evidence_binding"] == BINDING
    assert store.read(generation.number).commissioning_evidence_binding == BINDING
    assert "commissioning_evidence_binding" not in generation.as_event()
    assert generation.as_event()["commissioning_digest"] == CD


@pytest.mark.parametrize(
    "binding",
    [
        123,
        True,
        b"hmac-sha256:" + b"b" * 64,
        "hmac-sha256:" + "B" * 64,
        "hmac-sha256:" + "b" * 63,
        "sha256:" + "b" * 64,
        "hmac-sha256:" + "b" * 64 + "extra",
    ],
)
def test_invalid_evidence_binding_types_and_formats_are_refused(store, binding):
    with pytest.raises(GenerationRefused, match="commissioning evidence binding"):
        store.create(
            {"node.yaml": b"a: 1\n"},
            created_at=T0,
            commissioning_digest=CD,
            commissioning_evidence_binding=binding,
        )


def test_legacy_metadata_without_binding_reads_as_none(store):
    generation = store.create(
        {"node.yaml": b"a: 1\n"}, created_at=T0, commissioning_digest=CD
    )
    metadata_path = store._meta(generation.number)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert "commissioning_evidence_binding" not in metadata
    metadata.pop("commissioning_evidence_binding", None)
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    legacy = store.read(generation.number)
    assert legacy.commissioning_evidence_binding is None
    assert legacy.commissioning_digest == CD


@pytest.mark.parametrize("bound_endpoint", ["target", "latest"])
def test_bound_generation_rollback_refuses_without_mutation(store, bound_endpoint):
    binding_for_first = BINDING if bound_endpoint == "target" else None
    binding_for_second = BINDING if bound_endpoint == "latest" else None
    store.create(
        {"node.yaml": b"good\n"},
        created_at=T0,
        commissioning_digest=CD,
        commissioning_evidence_binding=binding_for_first,
    )
    store.create(
        {"node.yaml": b"bad\n"},
        created_at=T1,
        commissioning_digest=CD,
        commissioning_evidence_binding=binding_for_second,
    )
    before = {
        path.relative_to(store.root): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }

    with pytest.raises(GenerationRefused, match="validated forward render and approval"):
        store.roll_back_to(1, created_at=T2, reason="restore known state", actor="op-1")

    after = {
        path.relative_to(store.root): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }
    assert store.numbers() == (1, 2)
    assert after == before


def test_legacy_generations_can_still_be_rolled_back(store):
    first = store.create(
        {"node.yaml": b"good\n"}, created_at=T0, commissioning_digest=CD
    )
    store.create({"node.yaml": b"bad\n"}, created_at=T1, commissioning_digest=CD)

    rollback = store.roll_back_to(
        first.number, created_at=T2, reason="restore known state", actor="op-1"
    )

    assert rollback.number == 3
    assert rollback.rolled_back_from == 2
    assert rollback.commissioning_evidence_binding is None
