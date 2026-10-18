"""Every lifecycle edge checked against an independently stated policy."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from itertools import product

import pytest

from azazel_nexus.integration_broker.states import (
    ALLOWED_TRANSITIONS,
    AdapterRecord,
    Approval,
    BrokerState,
    TransitionRefused,
    expire_if_lease_lapsed,
    restore_record,
    transition,
)

NOW = datetime(2026, 10, 18, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


@dataclass(frozen=True)
class TestLease:
    __test__ = False
    adapter_id: str = "sensor-one"
    verified: bool = True
    expires_at: datetime = NOW + timedelta(seconds=30)


def verified_lease():
    from nacl.signing import SigningKey

    from azazel_nexus.integration_broker.routing import (
        EDGE_LEASE_DOMAIN,
        EDGE_LEASE_SCHEMA,
        EdgeLease,
    )
    from azazel_nexus.knowledge_peer import canonical
    key = SigningKey.generate()
    doc = {"schema": EDGE_LEASE_SCHEMA, "lease_id": "test-lease", "manifest_digest": DIGEST,
           "adapter_id": "sensor-one", "proposal_digest": DIGEST, "commissioning_digest": DIGEST,
           "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(seconds=30)).isoformat()}
    payload = canonical(doc)
    return EdgeLease(key.sign(EDGE_LEASE_DOMAIN + payload).signature + payload).bind(
        trusted_keys={"edge": bytes(key.verify_key)}, adapter_id="sensor-one",
        manifest_digest=DIGEST, proposal_digest=DIGEST, commissioning_digest=DIGEST,
        now=NOW.isoformat())


def restored(state):
    return restore_record("sensor-one", state, DIGEST, NOW, now=NOW, lease=verified_lease())


# Independent readable specification, rather than mirroring table membership.
FORWARD = {
    "disabled": "discovered", "discovered": "staged", "staged": "admitted",
    "admitted": "observe_only", "observe_only": "approval_pending",
    "approval_pending": "active_bounded",
}
FAILURES = {"degraded", "quarantined", "failed", "withdrawing"}


def expected_allowed(before, after):
    if before == after:
        return False
    if before in FAILURES:
        if after == "disabled":
            return True
        return after in {"withdrawing", "quarantined", "failed"}
    if after in FAILURES:
        return True
    if before == "active_bounded":
        return False
    return (FORWARD.get(before) == after or after == "disabled"
            or (before, after) == ("approval_pending", "observe_only"))


@pytest.mark.parametrize(("before", "after"), list(product(BrokerState, repeat=2)))
def test_exhaustive_transition_table(before, after):
    record = restored(before)
    allowed = expected_allowed(before.value, after.value)
    assert (after in ALLOWED_TRANSITIONS[before]) == allowed
    if not allowed:
        with pytest.raises(TransitionRefused, match="transition_not_allowed"):
            transition(record, after, reason="reviewed", now=NOW, approval=verified_lease())
        return
    new, event = transition(record, after, reason="reviewed", now=NOW, approval=verified_lease())
    assert new.state is after
    assert new.since == NOW
    assert record.state is before
    assert event.from_state is before and event.to_state is after
    assert event.reason == "reviewed" and event.occurred_at == NOW
    assert event.adapter_id == record.adapter_id and event.manifest_digest == DIGEST
    assert event.as_event() == {
        "event_type": "broker.adapter.transition", "adapter_id": "sensor-one",
        "from": before.value, "to": after.value, "reason": "reviewed",
        "occurred_at": NOW.isoformat(), "manifest_digest": DIGEST,
        "lease_id": event.lease_id,
        "lease_expires_at": event.lease_expires_at.isoformat() if event.lease_expires_at else None,
    }


def test_unknown_starts_disabled_and_cannot_skip_admission():
    record = AdapterRecord("unknown")
    assert record.state is BrokerState.DISABLED
    for target in (BrokerState.STAGED, BrokerState.ADMITTED, BrokerState.OBSERVE_ONLY,
                   BrokerState.APPROVAL_PENDING, BrokerState.ACTIVE_BOUNDED):
        with pytest.raises(TransitionRefused):
            transition(record, target, reason="discovered", now=NOW, approval=verified_lease())
    discovered, _ = transition(record, BrokerState.DISCOVERED, reason="discovered", now=NOW)
    with pytest.raises(TransitionRefused, match="manifest_required"):
        transition(discovered, BrokerState.STAGED, reason="reviewed", now=NOW)


@pytest.mark.parametrize("approval", [
    None, object(), {"verified": True}, TestLease(verified=False), TestLease(verified=1),
    TestLease(adapter_id="other"), TestLease(expires_at=NOW),
    TestLease(expires_at=NOW - timedelta(seconds=1)),
    TestLease(expires_at=NOW.replace(tzinfo=None)), TestLease(expires_at="tomorrow"),
])
def test_bad_approval_refused(approval):
    record = restored(BrokerState.APPROVAL_PENDING)
    with pytest.raises(TransitionRefused):
        transition(record, BrokerState.ACTIVE_BOUNDED, reason="approved", now=NOW,
                   approval=approval)
    assert record.state is BrokerState.APPROVAL_PENDING


def test_protocol_approval_and_expiry_checked_at_transition_time():
    approval = verified_lease()
    assert isinstance(approval, Approval)
    record = restored(BrokerState.APPROVAL_PENDING)
    active, event = transition(record, BrokerState.ACTIVE_BOUNDED, reason="approved",
                               now=NOW, approval=approval)
    assert active.state is BrokerState.ACTIVE_BOUNDED
    assert "verified" not in event.as_event()
    with pytest.raises(TransitionRefused, match="invalid_approval"):
        transition(record, BrokerState.ACTIVE_BOUNDED, reason="approved",
                   now=approval.expires_at, approval=approval)
    withdrawn, _ = transition(active, BrokerState.WITHDRAWING, reason="lease_expired",
                              now=approval.expires_at, approval=approval)
    assert withdrawn.state is BrokerState.WITHDRAWING


@pytest.mark.parametrize("failure", [BrokerState.DEGRADED, BrokerState.QUARANTINED,
                                     BrokerState.FAILED, BrokerState.WITHDRAWING])
def test_narrowing_does_not_consult_approval(failure):
    class BrokenApproval:
        @property
        def verified(self):
            pytest.fail("narrowing consulted the approval")

    record = restored(BrokerState.ACTIVE_BOUNDED)
    new, _ = transition(record, failure, reason="health_failure", now=NOW,
                        approval=BrokenApproval())
    assert new.state is failure


@pytest.mark.parametrize("reason", ["", "password=secret", "Bearer token", "sk-secret",
                                    "x" * 65, "health\nfailure", "a" * 32, None])
def test_audit_reason_refuses_unbounded_or_secret_material(reason):
    with pytest.raises(TransitionRefused, match="invalid_reason"):
        transition(AdapterRecord("sensor-one"), BrokerState.DISCOVERED, reason=reason, now=NOW)


@pytest.mark.parametrize("now", [NOW.replace(tzinfo=None), NOW - timedelta(seconds=1), None])
def test_bad_time_refused(now):
    with pytest.raises(TransitionRefused, match="invalid_time"):
        transition(AdapterRecord("sensor-one", since=NOW), BrokerState.DISCOVERED,
                   reason="discovered", now=now)


def test_invalid_record_and_target():
    for kwargs in ({"adapter_id": "../id"}, {"state": "disabled"},
                   {"manifest_digest": "bad"}, {"since": NOW.replace(tzinfo=None)}):
        with pytest.raises(TransitionRefused):
            replace(AdapterRecord("sensor-one"), **kwargs)
    with pytest.raises(TransitionRefused):
        transition(AdapterRecord("sensor-one"), "active_bounded", reason="approved", now=NOW)
    with pytest.raises(TransitionRefused):
        transition(None, BrokerState.DISCOVERED, reason="discovered", now=NOW)


def test_policy_table_cannot_be_mutated():
    with pytest.raises(TypeError):
        ALLOWED_TRANSITIONS[BrokerState.DISABLED] = frozenset({BrokerState.ACTIVE_BOUNDED})


@pytest.mark.parametrize("target", [BrokerState.WITHDRAWING, BrokerState.DEGRADED,
                                     BrokerState.QUARANTINED, BrokerState.FAILED, BrokerState.DISABLED])
def test_narrowing_survives_clock_rollback_and_invalid_reason(target):
    record = restored(BrokerState.ADMITTED)
    new, event = transition(record, target, reason="secret\nvalue", now=NOW - timedelta(days=1))
    assert new.state is target and new.since == NOW
    assert event.reason == "reason_invalid" and event.occurred_at == NOW


@pytest.mark.parametrize("state", list(BrokerState)[1:])
def test_direct_non_disabled_construction_is_refused(state):
    with pytest.raises(TransitionRefused, match="restore_required"):
        AdapterRecord("sensor-one", state, DIGEST, NOW)


@pytest.mark.parametrize("state", [BrokerState.ACTIVE_BOUNDED, BrokerState.APPROVAL_PENDING])
def test_restore_without_live_verified_lease_withdraws(state):
    assert restore_record("sensor-one", state, DIGEST, NOW, now=NOW).state is BrokerState.WITHDRAWING
    lease = verified_lease()
    assert restore_record("sensor-one", state, DIGEST, NOW, now=lease.expires_at,
                          lease=lease).state is BrokerState.WITHDRAWING
    assert restore_record("sensor-one", state, DIGEST, NOW, now=NOW,
                          lease=lease).state is state


def test_lease_watchdog_and_audit_binding():
    lease = verified_lease()
    record = restored(BrokerState.APPROVAL_PENDING)
    active, event = transition(record, BrokerState.ACTIVE_BOUNDED, reason="approved", now=NOW, approval=lease)
    assert active.lease_id == event.as_event()["lease_id"] == lease.lease_id
    assert active.lease_expires_at.isoformat() == event.as_event()["lease_expires_at"]
    assert expire_if_lease_lapsed(active, lease, NOW) == (active, None)
    withdrawn, event = expire_if_lease_lapsed(active, lease, lease.expires_at)
    assert withdrawn.state is BrokerState.WITHDRAWING and event.reason == "lease_expired"
    assert expire_if_lease_lapsed(active, None, NOW)[0].state is BrokerState.WITHDRAWING
