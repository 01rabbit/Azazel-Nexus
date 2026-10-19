"""Producer-shaped observations remain bounded data and carry no authority."""

import hashlib
import json
from pathlib import Path

import pytest

from azazel_nexus.edge_intake import (
    EdgeEventRefused,
    EvidenceRecord,
    IncidentTracker,
    canonical,
    parse_edge_event,
    read_intake_status,
)


def edge_event():
    # Edge main.rs sample_event + process_line's serialized structs.
    return {
        "normalized": {
            "ts": "2026-01-01T00:00:00Z",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "attack_type": "test",
            "severity": 1,
            "target_port": 443,
            "protocol": "tcp",
            "sid": 9999,
            "category": "test",
            "event_type": "alert",
            "action": "allowed",
            "confidence": 90,
            "risk_score": 90,
            "ingest_epoch": 0.0,
        },
        "defense": {
            "action": "isolate",
            "reason": "critical severity sid=9999",
            "policy_reason": "severity_critical_contains_immediately",
            "delay_ms": 0,
            "target": "10.0.0.8",
        },
        "enforcement_status": {
            "enforce_enabled": False,
            "enforce_level": "advisory",
            "dry_run": True,
            "high_impact_auto": False,
            "allowed_actions": ["observe", "notify"],
        },
        "enforcement": {
            "mode": "dry_run",
            "trace_id": "trace-1",
            "selected_action": "isolate",
            "target": "10.0.0.8",
            "policy_reason": "severity_critical_contains_immediately:enforce_disabled",
            "command_plan": ["nft example"],
            "rollback_plan": ["nft rollback"],
            "executed_count": 0,
            "failed_count": 0,
            "errors": [],
            "rollback_hint": "no runtime change",
            "result": "planned_not_applied",
            "metadata": {
                "original_dst_port": 443,
                "selected_decoy_port": None,
                "redirect_policy_source": "file",
                "redirect_mapping_matched": False,
                "unsupported_port_fallback": "",
                "fallback_reason": "",
                "release_task_id": "task-1",
                "release_due_epoch": 100.0,
                "release_resource_key": "key",
                "release_owner_token": "token",
                "release_tc_handle": "1:1",
                "release_ledger_state": "planned_only",
            },
        },
        "source": "suricata_eve",
        "pipeline": "rust_event_engine_v1",
    }


def parsed(value=None):
    return parse_edge_event(json.dumps(value or edge_event()).encode())


def test_producer_shape_and_digest_and_detached_event():
    value = edge_event()
    event = parsed(value)
    observation = event.as_dict()
    assert observation["defense"] == value["defense"]
    assert observation["enforcement_status"] == value["enforcement_status"]
    assert "command_plan" not in observation["enforcement"]
    record = EvidenceRecord.receive(event, lambda: 42)
    assert (
        record.digest == "sha256:" + hashlib.sha256(canonical(observation)).hexdigest()
    )
    observation["defense"]["action"] = "redirect"
    assert event.as_dict()["defense"]["action"] == "isolate"
    assert record.received_at == 42


@pytest.mark.parametrize(
    "section,key,value,code",
    [
        ("normalized", "severity", True, "EDGE_TYPE"),
        ("normalized", "severity", -1, "EDGE_RANGE"),
        ("normalized", "severity", 11, "EDGE_RANGE"),
        ("normalized", "target_port", 65536, "EDGE_RANGE"),
        ("normalized", "sid", 2**64, "EDGE_RANGE"),
        ("normalized", "confidence", 101, "EDGE_RANGE"),
        ("normalized", "risk_score", False, "EDGE_TYPE"),
        ("normalized", "ingest_epoch", -0.1, "EDGE_RANGE"),
        ("normalized", "src_ip", "SECRET", "EDGE_RANGE"),
        ("normalized", "dst_ip", "fe80::1%SECRET", "EDGE_RANGE"),
        ("normalized", "ts", "SECRET", "EDGE_RANGE"),
        ("normalized", "attack_type", "SECRET\n", "EDGE_RANGE_attack_type"),
        ("normalized", "protocol", "x" * 257, "EDGE_RANGE"),
        ("normalized", "technique_ids", ["T1234.567", "SECRET"], "EDGE_RANGE"),
        ("normalized", "technique_ids", ["T1234"] * 9, "EDGE_RANGE"),
        ("normalized", "technique_ids", "T1234", "EDGE_TYPE"),
        ("defense", "action", "SECRET", "EDGE_RANGE"),
        ("defense", "delay_ms", True, "EDGE_TYPE"),
        ("enforcement_status", "dry_run", 1, "EDGE_TYPE"),
        ("enforcement_status", "enforce_enabled", True, "EDGE_NOT_OBSERVE_ONLY"),
        ("enforcement_status", "dry_run", False, "EDGE_NOT_OBSERVE_ONLY"),
        ("enforcement_status", "high_impact_auto", True, "EDGE_NOT_OBSERVE_ONLY"),
        ("enforcement_status", "enforce_level", "full-auto", "EDGE_NOT_OBSERVE_ONLY"),
        ("enforcement", "mode", "enforced", "EDGE_NOT_OBSERVE_ONLY"),
        ("enforcement", "executed_count", 1, "EDGE_NOT_OBSERVE_ONLY"),
        ("enforcement", "errors", [{"SECRET": True}], "EDGE_TYPE"),
    ],
)
def test_refused_fields(section, key, value, code):
    event = edge_event()
    event[section][key] = value
    with pytest.raises(EdgeEventRefused) as caught:
        parsed(event)
    assert caught.value.code == code
    assert str(caught.value) == code
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    "section", [None, "normalized", "defense", "enforcement", "enforcement_status"]
)
@pytest.mark.parametrize("change", ["extra", "missing"])
def test_closed_shapes(section, change):
    value = edge_event()
    target = value if section is None else value[section]
    if change == "extra":
        target["SECRET"] = "SECRET"
    else:
        target.pop(next(iter(target)))
    with pytest.raises(EdgeEventRefused, match="^EDGE_SHAPE$"):
        parsed(value)


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"x" * 16385, "EDGE_TOO_LARGE"),
        (b"\xff", "EDGE_JSON"),
        (b"[]", "EDGE_SHAPE"),
        (b'{"x": NaN}', "EDGE_JSON"),
        (b"{", "EDGE_JSON"),
        (b'{"SECRET": 1, "SECRET": 2}', "EDGE_JSON"),
    ],
)
def test_bad_frames(raw, code):
    with pytest.raises(EdgeEventRefused, match="^" + code + "$"):
        parse_edge_event(raw)


def test_zero_severity_u64_and_absent_addresses_match_producer():
    value = edge_event()
    value["normalized"].update(
        severity=0, sid=2**64 - 1, src_ip="", dst_ip="", technique_ids=["T1234.567"]
    )
    assert parsed(value).as_dict()["normalized"] == value["normalized"]


def record(now, sid=1, ids=(), severity=1):
    value = edge_event()
    value["normalized"].update(sid=sid, technique_ids=list(ids), severity=severity)
    return EvidenceRecord.receive(parsed(value), lambda: now)


def test_tracker_open_throttle_update_idle_and_ids():
    tracker = IncidentTracker(lambda: 1000)
    first = record(0, ids=["T1234"])
    (opened,) = tracker.add(first)
    assert opened["transition"] == "opened"
    assert opened["edge_would"] == "isolate"
    assert tracker.add(record(59)) == []
    (updated,) = tracker.add(record(60, ids=["T1234.567"], severity=8))
    assert (updated["count"], updated["most_severe"]) == (3, 1)
    assert updated["technique_ids"] == ["T1234", "T1234.567"]
    assert updated["first_evidence"] == first.digest
    assert tracker.tick(960) == []
    (closed,) = tracker.tick(961)
    assert (closed["transition"], closed["reason"]) == ("closed", "idle")
    assert (
        IncidentTracker(lambda: 0).add(first)[0]["incident_id"] == opened["incident_id"]
    )
    assert tracker.add(record(962))[0]["incident_id"] != opened["incident_id"]


def test_escalation_is_recorded_without_waiting_for_the_throttle():
    tracker = IncidentTracker(lambda: 1000)
    tracker.add(record(0, severity=3))
    # Same or less severe within the interval stays throttled.
    assert tracker.add(record(5, severity=3)) == []
    assert tracker.add(record(6, severity=5)) == []
    (escalated,) = tracker.add(record(7, severity=1))
    assert (escalated["transition"], escalated["most_severe"]) == ("updated", 1)
    # Once escalated, the throttle applies again.
    assert tracker.add(record(8, severity=1)) == []


def test_capacity_closes_oldest_idle_and_technique_union_is_bounded():
    tracker = IncidentTracker(lambda: 0, max_open=2)
    tracker.add(record(0, sid=1, ids=[f"T{i:04}" for i in range(8)]))
    tracker.add(record(1, sid=2))
    tracker.add(record(2, sid=1, ids=["T9999"]))
    assert (
        len(
            next(v for v in tracker.incidents.values() if v["sid"] == 1)[
                "technique_ids"
            ]
        )
        == 8
    )
    closed, opened = tracker.add(record(3, sid=3))
    assert (closed["sid"], closed["reason"], opened["transition"]) == (
        2,
        "capacity",
        "opened",
    )
    assert len(tracker.incidents) == 2


def test_add_after_idle_closes_before_reopening():
    tracker = IncidentTracker(lambda: 0)
    tracker.add(record(0))
    assert [t["transition"] for t in tracker.add(record(901))] == ["closed", "opened"]


def test_status_reader_rejects_unknown_and_unbounded_data():
    assert read_intake_status(b"{}") is None
    assert read_intake_status(b"x" * 8193) is None
    assert read_intake_status(b"\xff") is None


def test_disabled_observation_and_optional_ids_are_accepted():
    value = edge_event()
    value["normalized"]["technique_ids"] = ["T1234", "T1234.567"]
    value["defense"]["action"] = "observe"
    value["enforcement"].update(
        mode="disabled",
        selected_action="observe",
        command_plan=[],
        rollback_plan=[],
        result="no_disruptive_action",
    )
    value["enforcement"]["metadata"].update(
        release_task_id=None,
        release_due_epoch=None,
        release_resource_key=None,
        release_owner_token=None,
        release_tc_handle=None,
        release_ledger_state="not_applicable",
    )
    assert parsed(value).as_dict()["defense"] == value["defense"]


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), 10**1000])
def test_nonfinite_and_huge_ingest_values_have_fixed_refusals(value):
    event = edge_event()
    event["normalized"]["ingest_epoch"] = value
    with pytest.raises(EdgeEventRefused) as caught:
        parsed(event)
    assert str(caught.value) in {"EDGE_JSON", "EDGE_RANGE"}


def test_metadata_shape_and_boolean_are_closed():
    value = edge_event()
    value["enforcement"]["metadata"]["SECRET"] = 1
    with pytest.raises(EdgeEventRefused, match="^EDGE_SHAPE$"):
        parsed(value)
    value = edge_event()
    value["enforcement"]["metadata"]["redirect_mapping_matched"] = 1
    with pytest.raises(EdgeEventRefused, match="^EDGE_TYPE$"):
        parsed(value)


def test_maximum_line_includes_only_json_bytes():
    raw = json.dumps(edge_event()).encode()
    assert parse_edge_event(raw + b" " * (16384 - len(raw))) == parsed()


def test_suricata_compact_timezone_is_rfc3339_ish():
    value = edge_event()
    value["normalized"]["ts"] = "2026-01-01T00:00:00.123456+0000"
    assert parsed(value).as_dict()["normalized"]["ts"] == value["normalized"]["ts"]


@pytest.mark.parametrize("severities", [(8, 4, 1, 0), (0, 1, 4, 8)])
def test_severity_tracks_lowest_value_from_first_event(severities):
    tracker = IncidentTracker(lambda: 0)
    for i, severity in enumerate(severities):
        (transition,) = tracker.add(record(i * 60, severity=severity))
        assert transition["most_severe"] == min(severities[:i + 1])


def test_equivalent_ipv6_addresses_share_an_incident_key():
    tracker = IncidentTracker(lambda: 0)
    for address in ("2001:0DB8:0000::1", "2001:db8::1"):
        value = edge_event()
        value["normalized"].update(src_ip=address, dst_ip="2001:0DB8::2")
        event = parsed(value)
        assert event.as_dict()["normalized"]["dst_ip"] == "2001:db8::2"
        tracker.add(EvidenceRecord.receive(event, lambda: 0))
    assert len(tracker.incidents) == 1
    assert next(iter(tracker.incidents.values()))["count"] == 2


@pytest.mark.parametrize("field", ["attack_type", "category"])
def test_rule_text_limits_and_fixed_field_codes(field):
    value = edge_event()
    value["normalized"][field] = "a" * 1023 + "\t"
    assert parsed(value).as_dict()["normalized"][field] == value["normalized"][field]
    for refused in ("a" * 1025, "secret\x00", "secret\n", "secret\x7f"):
        value["normalized"][field] = refused
        with pytest.raises(EdgeEventRefused, match="^EDGE_RANGE_" + field + "$"):
            parsed(value)
    value["normalized"][field] = 1
    with pytest.raises(EdgeEventRefused, match="^EDGE_TYPE_" + field + "$"):
        parsed(value)


def test_timestamp_refuses_unicode_digits():
    value = edge_event()
    value["normalized"]["ts"] = "2026-01-01T00:00:00.１２３Z"
    with pytest.raises(EdgeEventRefused, match="^EDGE_RANGE$"):
        parsed(value)


def test_opening_rate_is_bounded_and_existing_incidents_still_update():
    instant = [0]
    tracker = IncidentTracker(lambda: 0, monotonic=lambda: instant[0])
    for sid in range(60):
        value = edge_event()
        value["normalized"].update(sid=sid, severity=4, src_ip=f"10.0.0.{sid // 20 + 1}")
        item = EvidenceRecord.receive(parsed(value), lambda: 0)
        assert tracker.add(item)[0]["transition"] == "opened"
    assert tracker.add(record(0, sid=60, severity=4)) == []
    assert tracker.rate_limited == 1
    assert tracker.add(record(0, sid=61, severity=1))[0]["transition"] == "opened"
    value["normalized"].update(sid=0, src_ip="10.0.0.1")
    assert tracker.add(EvidenceRecord.receive(parsed(value), lambda: 60))[0]["transition"] == "updated"
    instant[0] = 60
    assert tracker.add(record(60, sid=60, severity=4))[0]["transition"] == "opened"


def test_scanner_cannot_exhaust_ordinary_or_severe_budget():
    tracker = IncidentTracker(lambda: 0, monotonic=lambda: 0)
    for port in range(100):
        value = edge_event()
        value["normalized"].update(target_port=port, severity=4)
        tracker.add(EvidenceRecord.receive(parsed(value), lambda: 0))
    assert len(tracker.incidents) == 20
    assert tracker.rate_limited == 80
    value["normalized"].update(src_ip="10.0.0.9", severity=4)
    assert tracker.add(EvidenceRecord.receive(parsed(value), lambda: 0))[0]["transition"] == "opened"
    value["normalized"].update(src_ip="10.0.0.10", severity=1)
    assert tracker.add(EvidenceRecord.receive(parsed(value), lambda: 0))[0]["most_severe"] == 1
    for sid in range(29):
        assert tracker.add(record(0, sid=sid))[0]["transition"] == "opened"
    assert tracker.add(record(0, sid=30)) == []


@pytest.mark.parametrize("mapped", ["::ffff:10.0.0.8", "::ffff:a00:8"])
def test_ipv4_mapped_addresses_have_stable_digest_and_incident_id(mapped):
    value = edge_event()
    value["normalized"]["src_ip"] = mapped
    assert parsed(value) == parsed()
    first = EvidenceRecord.receive(parsed(value), lambda: 0)
    plain = EvidenceRecord.receive(parsed(), lambda: 0)
    assert first.digest == plain.digest
    assert IncidentTracker(lambda: 0).add(first) == IncidentTracker(lambda: 0).add(plain)


def test_edge_golden_events_parse():
    # Refresh from Edge process_line whenever Edge's event contract changes.
    # Derived from origin/main main.rs and origin/work/issue-427 (technique_ids).
    fixture = Path(__file__).parents[1] / "fixtures/edge/rust_event_engine_v1.jsonl"
    events = [json.loads(line) for line in fixture.read_bytes().splitlines()]
    assert {e["defense"]["action"] for e in events} == {"notify", "redirect", "isolate"}
    assert {"technique_ids" in e["normalized"] for e in events} == {True, False}
    for event in events:
        assert parsed(event).as_dict()["defense"] == event["defense"]
