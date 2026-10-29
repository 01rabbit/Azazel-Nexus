"""Synthetic historical capability observations; never hardware evidence."""

import pytest

from azazel_nexus.audit import AuditLedger
from azazel_nexus.mio_status import ROUTE_LEDGER, describe, status_summary


@pytest.mark.parametrize("ceiling", ["CORE", "LITE", "FULL"])
def test_last_transition_ceiling_is_separate_from_capability(tmp_path, ceiling):
    path = tmp_path / ROUTE_LEDGER.lstrip("/")
    path.parent.mkdir(parents=True)
    ledger = AuditLedger(path)
    for profile in ("CORE", ceiling):
        ledger.append({"event_type": "mio.capability.transition", "to": "CORE",
                       "occurred_at": "2026-10-19T00:00:00Z",
                       "reasons": {"profile": profile, "resource": "core_reserve_unmeasured",
                                   "trust": "not-checked", "topology": "no_verified_egress",
                                   "health": {"local": "unavailable", "remote": "not_admitted"}}})
    ledger.append({"event_type": "mio.route"})
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    reading = status_summary(root=tmp_path)
    assert reading["ceiling"] == ceiling
    assert reading["state"] == "CORE"
    text = describe(reading)
    assert "core_reserve_unmeasured" in text
    assert "not a grant or admission" in text
    assert "last recorded observation" in text
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize("case", ["missing", "empty", "broken", "malformed", "permission"])
def test_unknown_evidence_never_infers_from_ram(tmp_path, monkeypatch, case):
    path = tmp_path / ROUTE_LEDGER.lstrip("/")
    path.parent.mkdir(parents=True)
    if case == "empty":
        path.touch()
    elif case == "broken":
        path.write_text("not a ledger")
    elif case == "malformed":
        AuditLedger(path).append({"event_type": "mio.capability.transition", "to": "FULL", "reasons": {}})
    elif case == "permission":
        path.touch()
        def denied(self):
            raise PermissionError("secret path")
        monkeypatch.setattr(AuditLedger, "__iter__", denied)
    reading = status_summary(root=tmp_path)
    assert reading["state"] is None and reading["ceiling"] is None
    assert "unknown" in reading["availability"]
    assert "secret" not in str(reading)


def test_reason_sets_match_runtime_enums():
    from azazel_nexus import mio_status
    from azazel_nexus_runtime.mio_capability import HealthReason, ResourceReason, TopologyReason
    for values, enum in ((mio_status.RESOURCE_REASONS, ResourceReason),
                         (mio_status.TOPOLOGY_REASONS, TopologyReason),
                         (mio_status.HEALTH_REASONS, HealthReason)):
        assert values == {item.value for item in enum}


def transition():
    return {"event_type": "mio.capability.transition", "to": "CORE",
            "occurred_at": "2026-10-19T00:00:00Z",
            "reasons": {"profile": "FULL", "resource": "core_reserve_unmeasured",
                        "trust": "not-checked", "topology": "no_verified_egress",
                        "health": {"local": "unavailable", "remote": "not_admitted"}}}


@pytest.mark.parametrize("path,value", [
    (("to",), "FULL\x1b[31m"),
    (("occurred_at",), "2026-10-19T00:00:00Z\x1b[31m"),
    (("occurred_at",), "private\nvalue"),
    (("occurred_at",), None),
    (("reasons", "profile"), "FULL\nprivate"),
    (("reasons", "resource"), "private\x1b[31m"),
    (("reasons", "trust"), "private"),
    (("reasons", "topology"), "private"),
    (("reasons", "health", "local"), "private"),
    (("reasons", "health", "remote"), "private"),
    (("reasons", "health", "unexpected"), "private"),
    (("reasons", "unexpected"), "private"),
    (("reasons",), {"profile": "FULL"}),
])
def test_invalid_transition_is_redacted_in_text_and_json(tmp_path, path, value):
    import json
    event = transition()
    target = event
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    ledger = tmp_path / ROUTE_LEDGER.lstrip("/")
    ledger.parent.mkdir(parents=True)
    AuditLedger(ledger).append(event)
    reading = status_summary(root=tmp_path)
    assert reading["state"] is None and reading["ceiling"] is None
    assert reading["reasons"] == {} and reading["observed_at"] is None
    for text in (describe(reading), json.dumps(reading)):
        assert "private" not in text and "unexpected" not in text
        assert "entryd credentials are not read" in text


@pytest.mark.parametrize("separator", ["T", "\n", "\x1b"])
def test_timestamp_is_canonicalized(tmp_path, separator):
    event = transition()
    event["occurred_at"] = "2026-10-19" + separator + "00:00:00Z"
    ledger = tmp_path / ROUTE_LEDGER.lstrip("/")
    ledger.parent.mkdir(parents=True)
    AuditLedger(ledger).append(event)
    reading = status_summary(root=tmp_path)
    assert reading["observed_at"] == "2026-10-19T00:00:00+00:00"
    # A transition is written when it is observed.
    assert reading["recorded_at"] == reading["observed_at"]


def test_an_unreadable_ledger_carries_no_record_time(tmp_path):
    reading = status_summary(root=tmp_path)
    assert reading["state"] is None and reading["recorded_at"] is None
