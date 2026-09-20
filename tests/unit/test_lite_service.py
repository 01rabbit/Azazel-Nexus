"""The four states of Knowledge Lite (#6, E1).

The claim under test is not "each state can be produced" -- it is that the
four are **distinguishable**, that no state serves a claim it should withhold,
and that none of them stops the deterministic path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Sequence

import pytest
from signing_oracle import public_key_for, sign_detached

from azazel_nexus.content_store import digest_bytes
from azazel_nexus.lite_service import KnowledgeLite, LiteState, no_claim_reader
from azazel_nexus.lite_trust import TrustStore
from azazel_nexus.revocation import RevocationList, RevocationStore

SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))
KEY = public_key_for(SEED)
OTHER_KEY = public_key_for(OTHER_SEED)

COMMISSIONING = "sha256:" + "a" * 64
NOW = "2026-09-20T00:00:00Z"
LATER = "2027-09-20T00:00:00Z"

CURRENT_CLAIM = {"id": "ioc-1", "expiry": "2026-12-31T00:00:00Z"}
EXPIRED_CLAIM = {"id": "ioc-2", "expiry": "2026-01-01T00:00:00Z"}
UNDATED_CLAIM = {"id": "attack-T1059"}


def claims_reader(payload: bytes) -> Sequence[Mapping]:
    return json.loads(payload.decode("utf-8"))["claims"]


def artifact_of(*claims: Mapping) -> bytes:
    return json.dumps({"claims": list(claims)}, sort_keys=True).encode("utf-8")


def build(root: Path) -> KnowledgeLite:
    TrustStore(root=root).pin(
        [KEY.hex()],
        commissioning_digest=COMMISSIONING,
        pinned_at="2026-09-01T00:00:00Z",
        actor="operator",
    )
    return KnowledgeLite(
        root=root, commissioning_digest=COMMISSIONING, claims_of=claims_reader
    )


@pytest.fixture()
def lite(tmp_path: Path) -> KnowledgeLite:
    return build(tmp_path / "lite")


def admit(lite: KnowledgeLite, payload: bytes, *, seed: bytes = SEED, at: str = NOW):
    return lite.admit(
        artifact=payload, signature=sign_detached(seed=seed, message=payload), admitted_at=at
    )


def revoke(lite: KnowledgeLite, sequence: int, **kwargs: object) -> None:
    revocations = RevocationList(
        sequence=sequence, issued_at="2026-09-20T00:00:00Z", **kwargs  # type: ignore[arg-type]
    )
    payload = revocations.as_payload()
    RevocationStore(root=lite.root, trusted_keys=(KEY,)).accept(
        sign_detached(seed=SEED, message=payload) + payload
    )


# -- the four states -------------------------------------------------------


def test_a_node_with_nothing_admitted_is_unavailable(lite: KnowledgeLite) -> None:
    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.UNAVAILABLE
    assert "has been admitted" in reading.reason
    assert reading.served == ()
    assert reading.generation is None


def test_a_verified_current_artifact_is_available(lite: KnowledgeLite) -> None:
    reading = admit(lite, artifact_of(CURRENT_CLAIM, EXPIRED_CLAIM))

    assert reading.state is LiteState.AVAILABLE
    assert reading.admitted is True
    assert [claim["id"] for claim in reading.served] == ["ioc-1"]
    assert [claim["id"] for claim in reading.withheld] == ["ioc-2"]
    assert reading.signer_key == KEY.hex()
    assert reading.generation == 1


def test_an_artifact_whose_claims_have_all_expired_is_stale(lite: KnowledgeLite) -> None:
    """And it serves nothing. `stale` is not `available` with a label."""

    admit(lite, artifact_of(EXPIRED_CLAIM))
    reading = lite.read(as_of=NOW)

    assert reading.state is LiteState.STALE
    assert reading.served == ()
    assert [claim["id"] for claim in reading.withheld] == ["ioc-2"]
    assert "withheld rather than served with a label" in reading.reason


def test_a_claim_that_expires_between_two_reads_stops_being_served(
    lite: KnowledgeLite,
) -> None:
    """The same artifact, the same bytes, two different `as_of` values."""

    admit(lite, artifact_of(CURRENT_CLAIM))
    assert lite.read(as_of=NOW).state is LiteState.AVAILABLE

    later = lite.read(as_of=LATER)
    assert later.state is LiteState.STALE
    assert later.served == ()


def test_an_undated_claim_is_served_at_any_time(lite: KnowledgeLite) -> None:
    """Static reference material is versioned, not dated."""

    admit(lite, artifact_of(UNDATED_CLAIM))
    for as_of in (NOW, LATER):
        reading = lite.read(as_of=as_of)
        assert reading.state is LiteState.AVAILABLE
        assert [claim["id"] for claim in reading.served] == ["attack-T1059"]


def test_a_tampered_artifact_is_quarantined_not_unavailable(lite: KnowledgeLite) -> None:
    """The distinction the operator acts on.

    "We do not have it" and "we had it and it is not trustworthy" call for
    different responses, and this node had it.
    """

    admit(lite, artifact_of(CURRENT_CLAIM))
    live = lite.generations.live()
    lite.content.path_for(live.artifact_digest).write_bytes(b"replaced")

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert reading.state is not LiteState.UNAVAILABLE
    assert reading.served == ()
    assert reading.generation == 1, "a quarantined cache still reports what it was"


def test_an_unreadable_artifact_is_quarantined(lite: KnowledgeLite) -> None:
    """Present, intact, correctly signed, and not parseable."""

    payload = b"correctly signed bytes that are not the expected format"
    reading = admit(lite, payload)
    assert reading.state is LiteState.QUARANTINED
    assert "present and cannot be read" in reading.reason


def test_the_default_reader_refuses_rather_than_reporting_usable(
    tmp_path: Path,
) -> None:
    """A caller that forgets a reader gets `quarantined`, never `available`."""

    root = tmp_path / "lite"
    TrustStore(root=root).pin(
        [KEY.hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="op"
    )
    lite = KnowledgeLite(root=root, commissioning_digest=COMMISSIONING)
    assert lite.claims_of is no_claim_reader

    reading = admit(lite, artifact_of(CURRENT_CLAIM))
    assert reading.state is LiteState.QUARANTINED
    assert "no claim reader was supplied" in reading.reason


# -- verification happens again on every read ------------------------------


def test_revoking_the_signing_key_quarantines_an_already_live_cache(
    lite: KnowledgeLite,
) -> None:
    """No restart, no new artifact. The next read stops serving."""

    assert admit(lite, artifact_of(CURRENT_CLAIM)).state is LiteState.AVAILABLE

    revoke(lite, 1, revoked_keys=frozenset({KEY.hex()}))

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "is revoked by revocation sequence 1" in reading.reason
    assert reading.served == ()


def test_revoking_the_artifact_digest_quarantines_it(lite: KnowledgeLite) -> None:
    payload = artifact_of(CURRENT_CLAIM)
    admit(lite, payload)

    revoke(lite, 1, revoked_digests=frozenset({digest_bytes(payload)}))

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "artifact" in reading.reason and "revoked" in reading.reason


def test_revoking_the_generation_quarantines_it(lite: KnowledgeLite) -> None:
    admit(lite, artifact_of(CURRENT_CLAIM))

    revoke(lite, 1, revoked_generations=frozenset({1}))

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "generation 1 is revoked" in reading.reason


def test_an_unverifiable_revocation_list_quarantines_rather_than_unrevokes(
    lite: KnowledgeLite,
) -> None:
    """Corrupting one file must not be the same as revoking nothing."""

    admit(lite, artifact_of(CURRENT_CLAIM))
    revoke(lite, 1, revoked_generations=frozenset({1}))
    assert lite.read(as_of=NOW).state is LiteState.QUARANTINED

    path = RevocationStore(root=lite.root, trusted_keys=(KEY,)).path
    blob = bytearray(path.read_bytes())
    blob[0] ^= 0x01
    path.write_bytes(bytes(blob))

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "out of service rather than unrevoked" in reading.reason


def test_a_generation_record_that_names_the_wrong_signer_is_quarantined(
    lite: KnowledgeLite,
) -> None:
    """The record is intact JSON naming a stored artifact. Only it is lying.

    Content addressing binds bytes to a digest. Nothing else binds the digest
    in a record to a key, so `signer_key` is a proven fact only because the
    signature is checked again here.
    """

    admit(lite, artifact_of(CURRENT_CLAIM))
    record = lite.generations.generations / "1" / "generation.json"
    raw = json.loads(record.read_text(encoding="utf-8"))
    raw["signer_key"] = OTHER_KEY.hex()
    record.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "does not describe the artifact it names" in reading.reason


def test_a_generation_pointing_at_another_admitted_artifact_is_quarantined(
    lite: KnowledgeLite,
) -> None:
    """The swap the re-verification exists to catch.

    Both artifacts were admitted and both are intact, so neither the content
    store nor the generation metadata has anything to object to. Only the
    signature, checked against the artifact it now names, does.
    """

    admit(lite, artifact_of(CURRENT_CLAIM))
    other = artifact_of(UNDATED_CLAIM)
    other_digest = lite.content.put(other)

    record = lite.generations.generations / "1" / "generation.json"
    raw = json.loads(record.read_text(encoding="utf-8"))
    raw["artifact_digest"] = other_digest
    record.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "does not verify under any admitted key" in reading.reason


def test_an_unreadable_trust_store_quarantines_a_live_cache(lite: KnowledgeLite) -> None:
    admit(lite, artifact_of(CURRENT_CLAIM))
    lite.trust.path.write_text("{not json", encoding="utf-8")

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "admitted keys cannot be read" in reading.reason


def test_a_corrupt_live_pointer_quarantines_rather_than_reporting_nothing(
    lite: KnowledgeLite,
) -> None:
    admit(lite, artifact_of(CURRENT_CLAIM))
    lite.generations.live_pointer.write_text("../../etc\n", encoding="utf-8")

    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert reading.state is not LiteState.UNAVAILABLE


# -- admission refusals ----------------------------------------------------


def test_an_artifact_signed_by_an_unadmitted_key_is_not_promoted(
    lite: KnowledgeLite,
) -> None:
    reading = admit(lite, artifact_of(CURRENT_CLAIM), seed=OTHER_SEED)

    assert reading.admitted is False
    assert reading.state is LiteState.UNAVAILABLE
    assert "does not verify under any admitted key" in reading.reason
    assert lite.generations.live() is None


def test_a_refused_admission_leaves_the_live_cache_untouched(lite: KnowledgeLite) -> None:
    """A refusal must never be worse than not having tried."""

    admit(lite, artifact_of(CURRENT_CLAIM))
    refused = admit(lite, artifact_of(UNDATED_CLAIM), seed=OTHER_SEED)

    assert refused.admitted is False
    assert refused.state is LiteState.AVAILABLE, "the previous cache is still serving"
    assert refused.generation == 1
    assert lite.generations.numbers() == (1,)
    assert [claim["id"] for claim in lite.read(as_of=NOW).served] == ["ioc-1"]


def test_a_revoked_artifact_is_not_admitted_again(lite: KnowledgeLite) -> None:
    payload = artifact_of(CURRENT_CLAIM)
    revoke(lite, 1, revoked_digests=frozenset({digest_bytes(payload)}))

    reading = admit(lite, payload)
    assert reading.admitted is False
    assert "not admitted again" in reading.reason
    assert lite.generations.live() is None


def test_an_artifact_signed_by_a_revoked_key_is_not_admitted(lite: KnowledgeLite) -> None:
    revoke(lite, 1, revoked_keys=frozenset({KEY.hex()}))

    reading = admit(lite, artifact_of(CURRENT_CLAIM))
    assert reading.admitted is False
    assert "is revoked by revocation sequence 1" in reading.reason
    assert lite.generations.live() is None


def test_nothing_is_admitted_without_a_trust_store(tmp_path: Path) -> None:
    lite = KnowledgeLite(
        root=tmp_path / "lite",
        commissioning_digest=COMMISSIONING,
        claims_of=claims_reader,
    )
    reading = admit(lite, artifact_of(CURRENT_CLAIM))
    assert reading.admitted is False
    assert "no admitted keys" in reading.reason
    assert lite.generations.live() is None


def test_admitting_a_second_artifact_promotes_a_new_generation(
    lite: KnowledgeLite,
) -> None:
    admit(lite, artifact_of(EXPIRED_CLAIM))
    assert lite.read(as_of=NOW).state is LiteState.STALE

    reading = admit(lite, artifact_of(CURRENT_CLAIM), at="2026-09-21T00:00:00Z")
    assert reading.admitted is True
    assert reading.state is LiteState.AVAILABLE
    assert reading.generation == 2


# -- what every state has in common ---------------------------------------


@pytest.mark.parametrize(
    "state", [LiteState.AVAILABLE, LiteState.STALE, LiteState.UNAVAILABLE, LiteState.QUARANTINED]
)
def test_no_state_blocks_the_deterministic_path(tmp_path: Path, state: LiteState) -> None:
    """Asserted in every state, not in the convenient one."""

    produced = _produce(tmp_path, state)
    assert produced.state is state
    assert produced.blocks_core() is False


@pytest.mark.parametrize(
    "state, sources",
    [
        (LiteState.AVAILABLE, True),
        (LiteState.STALE, False),
        (LiteState.UNAVAILABLE, False),
        (LiteState.QUARANTINED, False),
    ],
)
def test_only_available_sources_the_knowledge_lite_capability(
    tmp_path: Path, state: LiteState, sources: bool
) -> None:
    """A capability present in name while serving nothing is a false claim."""

    produced = _produce(tmp_path, state)
    assert produced.state is state
    assert produced.sources_capability is sources


@pytest.mark.parametrize(
    "state", [LiteState.STALE, LiteState.UNAVAILABLE, LiteState.QUARANTINED]
)
def test_no_state_but_available_serves_a_claim(tmp_path: Path, state: LiteState) -> None:
    produced = _produce(tmp_path, state)
    assert produced.served == ()


def test_the_event_carries_provenance_and_counts_never_claim_content(
    lite: KnowledgeLite,
) -> None:
    admit(lite, artifact_of(CURRENT_CLAIM, EXPIRED_CLAIM))
    event = lite.read(as_of=NOW).as_event()

    assert event["state"] == "available"
    assert event["served"] == 1 and event["withheld"] == 1
    assert event["signer_key"] == KEY.hex()
    assert "ioc-1" not in json.dumps(event), "an audit event records provenance, not content"


def test_the_four_states_have_four_distinct_reasons(tmp_path: Path) -> None:
    """Two states that say the same thing are one state with two names.

    Each state is produced on its own store: a shared one would let an earlier
    state leave the service somewhere the next one did not put it.
    """

    reasons = {
        state: _produce(tmp_path, state).reason
        for state in (
            LiteState.AVAILABLE,
            LiteState.STALE,
            LiteState.UNAVAILABLE,
            LiteState.QUARANTINED,
        )
    }
    assert len(set(reasons.values())) == 4, reasons


def _produce(tmp_path: Path, state: LiteState):
    """Drive a fresh service into `state` by the shortest honest route."""

    lite = build(tmp_path / f"lite-{state.value}")
    if state is LiteState.UNAVAILABLE:
        return lite.read(as_of=NOW)
    if state is LiteState.AVAILABLE:
        return admit(lite, artifact_of(CURRENT_CLAIM))
    if state is LiteState.STALE:
        admit(lite, artifact_of(EXPIRED_CLAIM))
        return lite.read(as_of=NOW)
    admit(lite, artifact_of(CURRENT_CLAIM))
    revoke(lite, 1, revoked_generations=frozenset({1}))
    return lite.read(as_of=NOW)
