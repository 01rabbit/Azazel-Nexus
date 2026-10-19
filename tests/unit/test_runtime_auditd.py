"""One writer, typed events, and a chain that runs through the segments (#40).

The failure this daemon exists to prevent: two processes read the same head,
compute the same next sequence, and both write. **Both branches then report
themselves intact**, because each is internally consistent and neither knows
about the other. A forked audit chain is worse than no audit chain, because
it is believed.

The second one: a segment boundary that restarts the chain. A set of short
chains that each verify is exactly the property an attacker deleting a file
would rely on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azazel_nexus.audit import AuditChainBroken, AuditLedger, AuditUnavailable
from azazel_nexus_runtime.auditd import (
    ASSIGNED_BY_THE_DAEMON,
    EVENT_SCHEMAS,
    REGISTRY,
    AuditService,
    Checkpoint,
    SegmentedLedger,
    VERBS,
)
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import RequestRefused
from azazel_nexus_runtime.transport import Request

SERVICE = Principal(uid=900, gid=900, pid=7, classes=frozenset({PrincipalClass.SERVICE}))
ROOT = Principal(uid=0, gid=0, pid=1, classes=frozenset({PrincipalClass.ROOT}))
#: Reading is the operator's; writing is a daemon's. Neither holds both.
OPERATOR = Principal(uid=1000, gid=1000, pid=8, classes=frozenset({PrincipalClass.OPERATOR}))
DIGEST = "sha256:" + "ab" * 32


def _event(day: str = "2026-09-20", unit: str = "auditd") -> dict:
    return {
        "unit": unit,
        "generation": 1,
        "digest": DIGEST,
        "occurred_at": f"{day}T12:00:00Z",
        "actor": "operator@console",
    }


def _request(
    verb_name: str,
    arguments: dict,
    payload: dict | None = None,
    *,
    principal: Principal = SERVICE,
) -> Request:
    verb = REGISTRY.resolve(verb_name, principal)
    return Request(
        verb=verb,
        arguments=verb.bind(arguments),
        principal=principal,
        payload=payload or {},
    )


def _append(service: AuditService, **kwargs) -> dict:
    return service.handle(
        _request(
            "audit.append",
            {"event_type": "activation.unit_granted"},
            _event(**kwargs),
        )
    )


def _service(tmp_path: Path) -> AuditService:
    root = tmp_path / "ledger"
    root.mkdir(parents=True, exist_ok=True)
    service = AuditService(SegmentedLedger(root))
    service.start()
    return service


# -- the daemon assigns the chaining fields ------------------------------


def test_a_caller_cannot_claim_its_position_in_the_chain(tmp_path):
    """A writer choosing its own sequence could choose one already taken.

    The *reason* is asserted, not just the refusal. A claimed chaining field
    is also an undeclared field, so a test that only expected `RequestRefused`
    passed with the dedicated check deleted -- which is how the first version
    of this test behaved. The detail distinguishes them: a claimed field is
    named (it comes from a fixed tuple of ours), a merely undeclared one is
    not (its name is the caller's).
    """

    service = _service(tmp_path)
    for claimed in ASSIGNED_BY_THE_DAEMON:
        payload = {**_event(), claimed: 999}
        with pytest.raises(RequestRefused) as refused:
            service.handle(
                _request(
                    "audit.append", {"event_type": "activation.unit_granted"}, payload
                )
            )
        assert refused.value.detail == claimed, (
            "the claim was refused as an ordinary unknown field, so nothing "
            "distinguishes a writer trying to place itself in the chain"
        )


def test_the_sequence_and_hash_come_back_from_the_daemon(tmp_path):
    service = _service(tmp_path)
    first = _append(service)
    second = _append(service)
    assert first["sequence"] == 1 and second["sequence"] == 2
    assert first["event_hash"] != second["event_hash"]


def test_two_writers_through_one_daemon_do_not_fork_the_chain(tmp_path):
    """Which is the whole reason a daemon owns this.

    Both callers are service principals writing the same event type. They go
    through one appender, so the chain has one order and it verifies.
    """

    service = _service(tmp_path)
    for _ in range(6):
        _append(service)
    service.ledger.verify()
    assert service.ledger.head()[0] == 6


# -- the chain runs through the segments ---------------------------------


def test_a_new_day_starts_a_new_file_and_continues_the_chain(tmp_path):
    """The boundary is where the file changes, not where the chain restarts."""

    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    _append(service, day="2026-09-20")
    third = _append(service, day="2026-09-21")

    segments = service.ledger.segments()
    assert [s.name for s in segments] == ["2026-09-20.jsonl", "2026-09-21.jsonl"]
    assert third["sequence"] == 3, "the second file restarted the sequence"
    service.ledger.verify()


def test_restart_refuses_backward_day_without_mutating_segments_or_head(tmp_path):
    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    _append(service, day="2026-09-21")

    restarted = AuditService(SegmentedLedger(service.ledger.root))
    restarted.start()
    assert restarted.verified
    before_files = {
        segment.name: segment.read_bytes()
        for segment in restarted.ledger.segments()
    }
    before_head = restarted.ledger.head()
    assert (restarted.head_sequence, restarted.head_hash) == before_head

    with pytest.raises(AuditUnavailable, match="precedes the latest audit segment"):
        _append(restarted, day="2026-09-20")

    assert {
        segment.name: segment.read_bytes()
        for segment in restarted.ledger.segments()
    } == before_files
    assert restarted.ledger.head() == before_head
    assert (restarted.head_sequence, restarted.head_hash) == before_head
    restarted.ledger.verify()


def test_older_timestamp_within_current_day_keeps_append_contract(tmp_path):
    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    older = _event(day="2026-09-20")
    older["occurred_at"] = "2026-09-20T01:00:00Z"

    result = service.handle(
        _request(
            "audit.append",
            {"event_type": "activation.unit_granted"},
            older,
        )
    )

    assert result["sequence"] == 2
    assert [segment.name for segment in service.ledger.segments()] == [
        "2026-09-20.jsonl"
    ]
    service.ledger.verify()


def test_the_first_entry_of_a_segment_chains_onto_the_previous_one(tmp_path):
    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    _append(service, day="2026-09-21")

    first_day = list(AuditLedger(service.ledger.root / "2026-09-20.jsonl"))
    second_day = list(AuditLedger(service.ledger.root / "2026-09-21.jsonl"))
    assert second_day[0].previous_hash == first_day[-1].event_hash


def test_the_head_comes_from_the_latest_segment_with_a_record(tmp_path):
    """An append reads one record, not every segment (#175)."""

    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    second = _append(service, day="2026-09-21")
    # An empty later file, as a crash between create and write would leave.
    (service.ledger.root / "2026-09-22.jsonl").write_text("", encoding="utf-8")
    # An earlier segment the head no longer needs to read.
    first = service.ledger.root / "2026-09-20.jsonl"
    first.write_text("not a record\n" + first.read_text(encoding="utf-8"), encoding="utf-8")

    assert service.ledger.head() == (2, second["event_hash"])
    with pytest.raises(AuditChainBroken):
        service.ledger.verify()


def test_a_deleted_segment_is_a_break_rather_than_a_shorter_chain(tmp_path):
    """A set of short chains that each verify is what a deletion would leave."""

    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    _append(service, day="2026-09-21")
    (service.ledger.root / "2026-09-20.jsonl").unlink()

    with pytest.raises(AuditChainBroken):
        service.ledger.verify()


def test_a_reordered_segment_name_is_refused(tmp_path):
    service = _service(tmp_path)
    with pytest.raises(AuditUnavailable):
        service.ledger.append(_event(), day="not-a-day")


def test_segments_are_walked_in_chronological_order(tmp_path):
    """Valid appends leave segments in the order the chain traverses."""

    service = _service(tmp_path)
    for day in ("2026-09-20", "2026-09-21", "2026-09-22"):
        _append(service, day=day)
    assert [s.name for s in service.ledger.segments()] == [
        "2026-09-20.jsonl",
        "2026-09-21.jsonl",
        "2026-09-22.jsonl",
    ]


# -- verification ---------------------------------------------------------


def test_appending_is_refused_until_the_chain_has_been_verified(tmp_path):
    """Appending to a head nobody checked chains onto something maybe broken."""

    root = tmp_path / "ledger"
    root.mkdir()
    service = AuditService(SegmentedLedger(root))
    assert service.verified is False
    with pytest.raises(RequestRefused):
        _append(service)


def test_a_broken_chain_is_reported_and_never_repaired(tmp_path):
    """A ledger that healed itself could not report the one thing it is for."""

    service = _service(tmp_path)
    _append(service)
    _append(service)

    segment = service.ledger.root / "2026-09-20.jsonl"
    lines = segment.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["event"]["actor"] = "someone.else"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    segment.write_text("\n".join(lines) + "\n", encoding="utf-8")

    after = AuditService(SegmentedLedger(service.ledger.root))
    after.start()
    assert after.verified is False
    assert after.break_reason

    before = segment.read_text(encoding="utf-8")
    after.handle(_request("audit.verify", {}, principal=OPERATOR))
    assert segment.read_text(encoding="utf-8") == before, "the daemon rewrote the chain"


def test_a_skipped_sequence_is_a_break(tmp_path):
    service = _service(tmp_path)
    _append(service)
    segment = service.ledger.root / "2026-09-20.jsonl"
    record = json.loads(segment.read_text(encoding="utf-8").splitlines()[0])
    record["sequence"] = 5
    segment.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AuditChainBroken):
        SegmentedLedger(service.ledger.root).verify()


def test_a_correctly_rehashed_entry_spliced_into_the_wrong_place_is_caught(tmp_path):
    """The one break the other two checks cannot see.

    Changing an entry's contents breaks its own hash; changing its number
    breaks the sequence. This is neither: the entry is internally consistent
    and correctly hashed **for a different predecessor**. Only comparing its
    `previous_hash` against where the chain actually is catches it, and
    without that comparison the whole file still verifies.
    """

    import hashlib

    from azazel_nexus.audit import canonical_event_bytes

    service = _service(tmp_path)
    _append(service)
    _append(service)

    segment = service.ledger.root / "2026-09-20.jsonl"
    lines = segment.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])

    forged_previous = "f" * 64
    record["previous_hash"] = forged_previous
    record["event_hash"] = hashlib.sha256(
        forged_previous.encode("ascii") + canonical_event_bytes(record["event"])
    ).hexdigest()
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    segment.write_text("\n".join(lines) + "\n", encoding="utf-8")

    spliced = list(AuditLedger(segment))
    assert spliced[1].recomputed() == spliced[1].event_hash, (
        "the fixture must be internally consistent, or it tests the hash "
        "check instead of the link check"
    )
    assert spliced[1].sequence == 2

    with pytest.raises(AuditChainBroken) as broken:
        SegmentedLedger(service.ledger.root).verify()
    assert "chains onto" in str(broken.value)


def test_verify_reports_the_checkpoints_and_says_they_are_unsigned(tmp_path):
    """The specification asks for signed checkpoints and this node has no key.

    Writing an unsigned file and calling it a checkpoint would be the weaker
    artifact wearing the stronger name.
    """

    service = _service(tmp_path)
    _append(service, day="2026-09-20")
    _append(service, day="2026-09-21")

    answer = service.handle(_request("audit.verify", {}, principal=OPERATOR))
    assert answer["verified"] is True
    assert len(answer["checkpoints"]) == 2
    assert all(mark["signed"] is False for mark in answer["checkpoints"])


def test_bootstrap_observation_returns_only_auditd_verified_head(tmp_path):
    service = _service(tmp_path)
    first = _append(service)
    assert service.handle(_request(
        "audit.bootstrap.observe", {}, principal=ROOT
    )) == {
        "verified": True,
        "head_sequence": first["sequence"],
        "head_hash": first["event_hash"],
    }

    second = _append(service)
    observed = service.handle(_request(
        "audit.bootstrap.observe", {}, principal=ROOT
    ))
    assert (observed["head_sequence"], observed["head_hash"]) == (
        second["sequence"], second["event_hash"]
    )


def test_bootstrap_observation_is_root_only_and_refuses_unverified_chain(tmp_path):
    with pytest.raises(RequestRefused):
        _request("audit.bootstrap.observe", {}, principal=OPERATOR)
    with pytest.raises(RequestRefused):
        _request("audit.bootstrap.observe", {}, principal=SERVICE)

    service = _service(tmp_path)
    _append(service)
    segment = service.ledger.root / "2026-09-20.jsonl"
    record = json.loads(segment.read_text(encoding="utf-8"))
    record["event_hash"] = "f" * 64
    segment.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    service = AuditService(SegmentedLedger(service.ledger.root))
    service.start()
    with pytest.raises(RequestRefused):
        service.handle(_request("audit.bootstrap.observe", {}, principal=ROOT))


def test_a_checkpoint_is_not_a_trust_anchor():
    assert Checkpoint("2026-09-20.jsonl", 3, "a" * 64, 3).signed is False


# -- events are typed ----------------------------------------------------


def test_an_undeclared_event_type_is_refused(tmp_path):
    """Refused during argument binding, before the handler sees it."""

    service = _service(tmp_path)
    with pytest.raises(RequestRefused):
        service.handle(
            _request("audit.append", {"event_type": "something.invented"}, _event())
        )


def test_the_append_verbs_event_types_are_exactly_the_declared_schemas():
    """This is what makes the refusal above structural.

    `_bind_event` has no branch for an undeclared type, because the enum makes
    one unreachable. If these two ever drifted apart, that absent branch would
    become a `KeyError` -- so the agreement is pinned here rather than assumed.
    """

    append = next(verb for verb in VERBS if verb.name == "audit.append")
    bootstrap = next(verb for verb in VERBS if verb.name == "audit.bootstrap.append")
    (regular_type,) = append.arguments
    (bootstrap_type,) = bootstrap.arguments
    assert set(regular_type.choices) == {
        name for name in EVENT_SCHEMAS if not name.startswith("bootstrap.")
    }
    assert set(bootstrap_type.choices) == {
        name for name in EVENT_SCHEMAS if name.startswith("bootstrap.")
    }


def test_bootstrap_lifecycle_schemas_match_emitted_event_shapes():
    lifecycle = {
        "bootstrap.controller_ready_intent": None,
        "bootstrap.grant_intent": None,
        "bootstrap.start_intent": ("auditd", "commissiond"),
        "bootstrap.ready": ("auditd", "commissiond"),
        "bootstrap.stopping": None,
        "bootstrap.stopped": None,
    }
    base_fields = {"approval_digest", "generation", "occurred_at"}
    for event_type, unit_keys in lifecycle.items():
        schema = EVENT_SCHEMAS[event_type]
        names = {argument.name for argument in schema}
        assert names == base_fields | ({"unit_key"} if unit_keys else set())
        if unit_keys:
            unit_key = next(arg for arg in schema if arg.name == "unit_key")
            assert unit_key.kind.value == "enum"
            assert set(unit_key.choices) == set(unit_keys)


def test_bootstrap_lifecycle_events_append_with_top_level_and_unit_keys(tmp_path):
    service = _service(tmp_path)
    lifecycle = (
        ("bootstrap.controller_ready_intent", None),
        ("bootstrap.grant_intent", None),
        ("bootstrap.start_intent", "auditd"),
        ("bootstrap.ready", "auditd"),
        ("bootstrap.start_intent", "commissiond"),
        ("bootstrap.ready", "commissiond"),
        ("bootstrap.stopping", None),
        ("bootstrap.stopped", None),
    )
    for event_type, unit_key in lifecycle:
        payload = {
            "approval_digest": DIGEST,
            "generation": 1,
            "occurred_at": "2026-09-20T12:00:00Z",
        }
        if event_type in {"bootstrap.start_intent", "bootstrap.ready"}:
            payload["unit_key"] = unit_key
        answer = service.handle(
            _request("audit.bootstrap.append", {"event_type": event_type}, payload,
                     principal=ROOT)
        )
        assert answer["sequence"] >= 1
        assert len(answer["event_hash"]) == 64


def test_undeclared_bootstrap_lifecycle_event_is_refused_before_append(tmp_path):
    service = _service(tmp_path)
    with pytest.raises(RequestRefused):
        service.handle(
            _request(
                "audit.bootstrap.append",
                {"event_type": "bootstrap.not_a_lifecycle_event"},
                {
                    "approval_digest": DIGEST,
                    "generation": 1,
                    "occurred_at": "2026-09-20T12:00:00Z",
                },
                principal=ROOT,
            )
        )


def test_service_cannot_write_bootstrap_events_via_either_verb(tmp_path):
    service = _service(tmp_path)
    payload = {
        "approval_digest": DIGEST,
        "generation": 1,
        "occurred_at": "2026-09-20T12:00:00Z",
    }
    with pytest.raises(RequestRefused):
        service.handle(
            _request("audit.append", {"event_type": "bootstrap.grant_intent"}, payload)
        )
    with pytest.raises(RequestRefused):
        service.handle(
            _request("audit.bootstrap.append", {"event_type": "bootstrap.grant_intent"},
                     payload)
        )


def test_an_undeclared_field_is_refused_rather_than_stored(tmp_path):
    """A chain whose entries are arbitrary is one nobody can write a reader for."""

    service = _service(tmp_path)
    with pytest.raises(RequestRefused):
        service.handle(
            _request(
                "audit.append",
                {"event_type": "activation.unit_granted"},
                {**_event(), "note": "x" * 5000},
            )
        )


def test_a_missing_field_is_refused(tmp_path):
    service = _service(tmp_path)
    payload = _event()
    del payload["actor"]
    with pytest.raises(RequestRefused):
        service.handle(
            _request("audit.append", {"event_type": "activation.unit_granted"}, payload)
        )


def test_a_field_outside_its_declared_range_is_refused(tmp_path):
    service = _service(tmp_path)
    for bad in (
        {"unit": "sshd"},
        {"digest": "../../etc/passwd"},
        {"occurred_at": "yesterday"},
        {"actor": "a" * 200},
        {"generation": -1},
    ):
        with pytest.raises(RequestRefused):
            service.handle(
                _request(
                    "audit.append",
                    {"event_type": "activation.unit_granted"},
                    {**_event(), **bad},
                )
            )


def test_every_declared_event_carries_when_it_happened():
    """The segment a record lands in is the day it happened, not the day it arrived."""

    for event_type, schema in EVENT_SCHEMAS.items():
        names = {argument.name for argument in schema}
        assert "occurred_at" in names, f"{event_type} does not say when"


def test_every_declared_field_uses_a_bounded_kind():
    for event_type, schema in EVENT_SCHEMAS.items():
        for argument in schema:
            assert argument.kind.value in {
                "ordinal",
                "flag",
                "enum",
                "digest",
                "timestamp",
                "identifier",
            }, f"{event_type}.{argument.name} is not bounded"


def test_only_audit_append_verbs_accept_payloads():
    accepting = {verb.name for verb in VERBS if verb.accepts_payload}
    assert accepting == {"audit.append", "audit.bootstrap.append"}
    regular = next(verb for verb in VERBS if verb.name == "audit.append")
    bootstrap = next(verb for verb in VERBS if verb.name == "audit.bootstrap.append")
    regular_types, = regular.arguments
    bootstrap_types, = bootstrap.arguments
    assert all(not name.startswith("bootstrap.") for name in regular_types.choices)
    assert all(name.startswith("bootstrap.") for name in bootstrap_types.choices)
    assert bootstrap.admits == frozenset({PrincipalClass.ROOT})
    observe = next(verb for verb in VERBS if verb.name == "audit.bootstrap.observe")
    assert not observe.accepts_payload
    assert not observe.arguments
    assert observe.admits == frozenset({PrincipalClass.ROOT})


def test_an_operator_may_read_the_chain_but_not_write_to_it(tmp_path):
    """The separation, exercised from both sides.

    A service principal asking to verify is refused, and an operator asking
    to append is refused. Either one alone would leave the other direction
    untested.
    """

    with pytest.raises(RequestRefused):
        _request("audit.verify", {}, principal=SERVICE)
    with pytest.raises(RequestRefused):
        _request(
            "audit.append",
            {"event_type": "activation.unit_granted"},
            _event(),
            principal=OPERATOR,
        )


def test_the_append_verb_is_not_open_to_an_operator():
    """Daemons record; an operator reads.

    An operator plane that could write into the chain would be an operator
    plane that could write the record of what it did.
    """

    append = next(verb for verb in VERBS if verb.name == "audit.append")
    assert PrincipalClass.OPERATOR not in append.admits


def test_watchdog_schema_tracks_producer_tables():
    from azazel_nexus_runtime.units import UNIT_NAMES
    from azazel_nexus_runtime.watchdog import FenceReason

    fields = {field.name: field for field in EVENT_SCHEMAS["watchdog.fenced"]}
    assert set(fields["unit"].choices) == set(UNIT_NAMES.values())
    assert set(fields["reason"].choices) == {reason.value for reason in FenceReason}
    assert fields["previous_reason"].choices == fields["reason"].choices


@pytest.mark.parametrize("previous_reason", [None, "fence_store_unreadable", "restart_budget_spent"])
def test_audit_accepts_actual_watchdog_transitions(tmp_path, previous_reason):
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager
    from azazel_nexus_runtime.watchdog import FenceReason, FenceStore, WatchdogService

    store = FenceStore(tmp_path / "fences.json")
    if previous_reason:
        store.save({unit: previous_reason for unit in UNIT_NAMES.values()})
    ledger = AuditLedger(tmp_path / "watchdog.jsonl")
    watchdog = WatchdogService(RecordingUnitManager(UNIT_NAMES.values()), ledger, store)
    for unit in UNIT_NAMES.values():
        for reason in FenceReason:
            watchdog._fence(unit, reason, now="2026-09-20T12:00:00Z", detail="bounded diagnostic")
    service = _service(tmp_path)
    for entry in ledger:
        event = dict(entry.event)
        event_type = event.pop("event_type")
        service.handle(_request("audit.append", {"event_type": event_type}, event))
    service.ledger.verify()
    assert service.head_sequence == len(list(ledger))


@pytest.mark.parametrize("field,value", [
    ("detail", "x" * 257), ("detail", "line\nbreak"), ("detail", 1),
    ("previous_reason", "invented"), ("previous_state", "running"),
    ("state", "in_service"), ("unit", "auditd"),
])
def test_watchdog_schema_refuses_invalid_fields(tmp_path, field, value):
    payload = {
        "unit": "azazel-auditd.service", "reason": "unhealthy",
        "detail": "", "previous_state": "in_service", "previous_reason": None,
        "state": "fenced", "occurred_at": "2026-09-20T12:00:00Z",
    }
    payload[field] = value
    with pytest.raises(RequestRefused):
        _service(tmp_path).handle(_request("audit.append", {"event_type": "watchdog.fenced"}, payload))
