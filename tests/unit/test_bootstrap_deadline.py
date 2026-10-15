"""Pure bootstrap deadline transitions; no persistence or service admission."""

from dataclasses import replace
import time

import pytest
from nacl.signing import SigningKey

from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy,
    BootstrapContext,
    VerifiedBootstrapApproval,
    bootstrap_payload,
    verify_bootstrap_approval,
)
from azazel_nexus.bootstrap_deadline import (
    BootstrapDeadline,
    begin_deadline,
    read_boottime_ns,
    revalidate_deadline,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
START = "2026-10-13T00:00:00Z"
END = "2026-10-13T00:05:00Z"
BOOT_ID = "11111111-1111-1111-1111-111111111111"
OPERATOR = "operator-a"
NS = 1_000_000_000


@pytest.fixture
def approval():
    key = SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
    context = BootstrapContext(
        approval_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        node_digest=DIGEST,
        boot_id=BOOT_ID,
        generation=1,
        generation_digest=DIGEST,
        package_digest=DIGEST,
        unit_closure_digest=DIGEST,
        policy_digest=DIGEST,
        approval_policy_digest=policy.digest(),
        security_epoch=7,
        revocation_digest=DIGEST,
    )
    payload = bootstrap_payload(
        context=context, operator=OPERATOR, granted_at=START, expires_at=END,
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    ).signature
    trust = OperatorTrust({OPERATOR: bytes(key.verify_key)})
    verified = verify_bootstrap_approval(
        trust=trust, expected=context, policy=policy, operator=OPERATOR,
        payload=payload, signature=signature, now=START,
    )
    return key, context, trust, policy, verified


def _fresh(key, context, trust, policy, *, granted_at=START, expires_at=END, now=START):
    payload = bootstrap_payload(
        context=context, operator=OPERATOR, granted_at=granted_at,
        expires_at=expires_at,
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    ).signature
    return verify_bootstrap_approval(
        trust=trust, expected=context, policy=policy, operator=OPERATOR,
        payload=payload, signature=signature, now=now,
    )


def _begin(verified, **overrides):
    args = dict(boot_id=BOOT_ID, now=START, boottime_ns=100 * NS,
                clock_trusted=True)
    args.update(overrides)
    return begin_deadline(verified, **args)


def test_deadline_is_unchanged_across_revalidations_and_restart_value(approval):
    key, context, trust, policy, verified = approval
    retained = _begin(verified)
    original_deadline = retained.deadline_boottime_ns

    # Simulate persistence/reload by carrying the same immutable value into a
    # new controller instance; revalidation advances observations only.
    restarted = replace(retained)
    for elapsed, utc in ((120 * NS, "2026-10-13T00:00:20Z"),
                         (240 * NS, "2026-10-13T00:00:40Z")):
        fresh = _fresh(key, context, trust, policy, now=utc)
        restarted = revalidate_deadline(
            restarted, approval=fresh, boot_id=BOOT_ID, now=utc,
            boottime_ns=elapsed, clock_trusted=True,
        )
        assert restarted.deadline_boottime_ns == original_deadline
    assert restarted.admitted_boottime_ns == 100 * NS
    assert restarted.last_boottime_ns == 240 * NS


def test_elapsed_expiry_catches_suspend_when_utc_stalls(approval):
    _, _, _, _, verified = approval
    retained = _begin(verified)
    # UTC has not moved, while BOOTTIME has advanced by more than the grant.
    with pytest.raises(ApprovalRefused, match="elapsed deadline"):
        revalidate_deadline(
            retained, approval=verified, boot_id=BOOT_ID, now=START,
            boottime_ns=401 * NS, clock_trusted=True,
        )


def test_exact_elapsed_deadline_refuses(approval):
    _, _, _, _, verified = approval
    retained = _begin(verified)
    with pytest.raises(ApprovalRefused, match="elapsed deadline"):
        revalidate_deadline(
            retained, approval=verified, boot_id=BOOT_ID, now=START,
            boottime_ns=retained.deadline_boottime_ns, clock_trusted=True,
        )


def test_wall_clock_rollback_within_signed_interval_refuses(approval):
    _, _, _, _, verified = approval
    retained = _begin(verified, now="2026-10-13T00:00:10Z", boottime_ns=110 * NS)
    with pytest.raises(ApprovalRefused):
        revalidate_deadline(
            retained, approval=verified, boot_id=BOOT_ID,
            now="2026-10-13T00:00:05Z", boottime_ns=111 * NS,
            clock_trusted=True,
        )


def test_elapsed_clock_rollback_refuses(approval):
    _, _, _, _, verified = approval
    retained = _begin(verified, now="2026-10-13T00:00:01Z", boottime_ns=110 * NS)
    with pytest.raises(ApprovalRefused):
        revalidate_deadline(
            retained, approval=verified, boot_id=BOOT_ID,
            now="2026-10-13T00:00:02Z", boottime_ns=109 * NS,
            clock_trusted=True,
        )


def test_new_boot_or_changed_approval_context_refuses(approval):
    key, context, trust, policy, verified = approval
    retained = _begin(verified)
    with pytest.raises(ApprovalRefused, match="boot binding"):
        revalidate_deadline(
            retained, approval=verified,
            boot_id="22222222-2222-2222-2222-222222222222",
            now=START, boottime_ns=110 * NS, clock_trusted=True,
        )

    changed = replace(context, generation_digest=OTHER_DIGEST)
    fresh = _fresh(key, changed, trust, policy)
    assert fresh.context == changed
    assert fresh != verified
    with pytest.raises(ApprovalRefused, match="binding changed"):
        revalidate_deadline(
            retained, approval=fresh, boot_id=BOOT_ID, now=START,
            boottime_ns=110 * NS, clock_trusted=True,
        )


def test_fresh_approval_verification_rejects_revoked_operator(approval):
    key, context, _trust, policy, _verified = approval
    payload = bootstrap_payload(
        context=context, operator=OPERATOR, granted_at=START, expires_at=END,
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    ).signature
    revoked_trust = OperatorTrust(
        {OPERATOR: bytes(key.verify_key)}, frozenset({OPERATOR}),
    )
    with pytest.raises(ApprovalRefused, match="actively enrolled"):
        verify_bootstrap_approval(
            trust=revoked_trust, expected=context, policy=policy,
            operator=OPERATOR, payload=payload, signature=signature, now=START,
        )


def test_missing_retained_state_is_not_recreated_by_revalidation(approval):
    _, _, _, _, verified = approval
    with pytest.raises(ApprovalRefused, match="no restart fallback"):
        revalidate_deadline(
            None, approval=verified, boot_id=BOOT_ID, now=START,
            boottime_ns=110 * NS, clock_trusted=True,
        )


def test_untrusted_clock_refuses_at_admission_and_revalidation(approval):
    _, _, _, _, verified = approval
    with pytest.raises(ApprovalRefused, match="trusted clock"):
        _begin(verified, clock_trusted=False)
    retained = _begin(verified)
    with pytest.raises(ApprovalRefused, match="trusted clock"):
        revalidate_deadline(
            retained, approval=verified, boot_id=BOOT_ID, now=START,
            boottime_ns=110 * NS, clock_trusted=False,
        )


def test_clock_reader_uses_only_clock_boottime(monkeypatch):
    calls = []
    expected = 123 * NS
    boottime_id = 7

    def read(clock_id):
        calls.append(clock_id)
        return expected

    monkeypatch.setattr(time, "CLOCK_BOOTTIME", boottime_id, raising=False)
    monkeypatch.setattr(time, "clock_gettime_ns", read)
    assert read_boottime_ns() == expected
    assert calls == [boottime_id]


@pytest.mark.parametrize("value", [-1, True, 1.5, "100"])
def test_clock_reader_rejects_malformed_values(monkeypatch, value):
    monkeypatch.setattr(time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(time, "clock_gettime_ns", lambda _clock_id: value)
    with pytest.raises(ApprovalRefused, match="invalid boot elapsed time"):
        read_boottime_ns()


def test_clock_reader_refuses_when_boottime_is_unavailable(monkeypatch):
    monkeypatch.setattr(time, "CLOCK_BOOTTIME", 7, raising=False)
    calls = []

    def unavailable(_clock_id):
        calls.append(_clock_id)
        raise OSError("clock unavailable")

    monkeypatch.setattr(time, "clock_gettime_ns", unavailable)
    with pytest.raises(ApprovalRefused, match="unavailable"):
        read_boottime_ns()
    assert calls == [7]

    monkeypatch.delattr(time, "CLOCK_BOOTTIME", raising=False)
    with pytest.raises(ApprovalRefused, match="unavailable"):
        read_boottime_ns()


@pytest.mark.parametrize("field,value", [
    ("approval", None),
    ("admitted_at", "not-utc"),
    ("admitted_boottime_ns", True),
    ("deadline_boottime_ns", -1),
    ("deadline_boottime_ns", 301 * NS),
    ("last_utc", "not-utc"),
    ("last_boottime_ns", 100 * NS - 1),
])
def test_deadline_constructor_rejects_invalid_state(approval, field, value):
    _, _, _, _, verified = approval
    retained = _begin(verified)
    with pytest.raises(ApprovalRefused):
        replace(retained, **{field: value})


def test_begin_deadline_rejects_invalid_clock_and_boot_identity(approval):
    _, _, _, _, verified = approval
    for kwargs in (
        {"boottime_ns": True},
        {"boottime_ns": -1},
        {"boot_id": "22222222-2222-2222-2222-222222222222"},
    ):
        with pytest.raises(ApprovalRefused):
            _begin(verified, **kwargs)


def test_deadline_state_is_not_an_authorization_token(approval):
    _, _, _, _, verified = approval
    assert isinstance(_begin(verified), BootstrapDeadline)
    assert not isinstance(_begin(verified), VerifiedBootstrapApproval)


def test_begin_deadline_remaining_is_derived_from_expires_at(approval):
    _key, _context, _trust, _policy, verified = approval
    full = _begin(verified, now=START, boottime_ns=100 * NS)
    assert full.deadline_boottime_ns - 100 * NS == 300 * NS
    later = _begin(verified, now="2026-10-13T00:01:00Z", boottime_ns=500 * NS)
    assert later.deadline_boottime_ns - 500 * NS == 240 * NS
