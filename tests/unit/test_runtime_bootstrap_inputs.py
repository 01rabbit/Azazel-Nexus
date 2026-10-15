"""Protected-input composition tests with entirely injected readers."""

from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_approval import BootstrapContext, VerifiedBootstrapApproval
from azazel_nexus.bootstrap_deadline import BootstrapDeadline
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs as inputs

NOW = "2026-10-13T00:00:00Z"
LATER = "2026-10-13T00:00:01Z"
NS = 1_000_000_000
DIGEST = "sha256:" + "a" * 64
BOOT = "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def protected(monkeypatch):
    context = BootstrapContext(
        approval_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        node_digest=DIGEST,
        boot_id=BOOT,
        generation=3,
        generation_digest=DIGEST,
        package_digest=DIGEST,
        unit_closure_digest=DIGEST,
        policy_digest=DIGEST,
        approval_policy_digest=DIGEST,
        security_epoch=2,
        revocation_digest=DIGEST,
    )
    # Injected trusted producer evidence for this adapter unit test; signature
    # verification is owned by load_bootstrap_approval and mocked below.
    approval = VerifiedBootstrapApproval(
        context, "operator-a", NOW, "2026-10-13T00:05:00Z", DIGEST
    )
    deadline = BootstrapDeadline(approval, NOW, 10 * NS, 310 * NS, NOW, 10 * NS)
    observation = inputs.BootstrapObservation(context, "operator-a", NOW, True)
    observations = [observation, observation]
    calls = {"load": [], "advance": [], "boot": [], "clock": []}
    monkeypatch.setattr(
        inputs,
        "load_bootstrap_approval",
        lambda **kw: calls["load"].append(kw) or approval,
    )
    monkeypatch.setattr(
        inputs, "advance_deadline", lambda **kw: calls["advance"].append(kw) or deadline
    )
    monkeypatch.setattr(
        inputs, "read_boot_id", lambda: calls["boot"].append(True) or BOOT
    )
    monkeypatch.setattr(
        inputs, "read_boottime_ns", lambda: calls["clock"].append(True) or 11 * NS
    )
    source = iter(observations)

    def observe():
        return next(source)

    return context, approval, deadline, calls, observe


@pytest.mark.parametrize("value", [False, None, 1, "trusted"])
def test_missing_or_nonboolean_clock_trust_is_not_observation(protected, value):
    context = protected[0]
    with pytest.raises(ApprovalRefused):
        inputs.BootstrapObservation(context, "operator-a", NOW, value)


@pytest.mark.parametrize(
    "value",
    [None, True, "2026-10-13", "2026-02-30T00:00:00Z", "2026-10-13T00:00:00+00:00"],
)
def test_public_time_boundary_rejects_invalid_or_noncanonical_utc(protected, value):
    with pytest.raises(ApprovalRefused):
        inputs.BootstrapObservation(protected[0], "operator-a", value, True)


def test_calls_loaders_with_independent_current_context_and_advances(protected):
    context, approval, deadline, calls, observe = protected
    result = inputs.ProtectedBootstrapInputs(observe)()
    assert result is deadline
    assert calls["load"] == [
        {"expected": context, "operator": "operator-a", "now": NOW},
        {"expected": context, "operator": "operator-a", "now": NOW},
    ]
    assert calls["advance"] == [
        {
            "approval": approval,
            "boot_id": BOOT,
            "now": NOW,
            "boottime_ns": 11 * NS,
            "clock_trusted": True,
        }
    ]
    assert len(calls["boot"]) == 3
    assert calls["clock"] == [True]


def _run_with_observations(
    monkeypatch, protected, values, *, boots=None, approvals=None, advance_error=None
):
    _context, approval, _deadline, calls, _observe = protected
    stream = iter(values)
    boots = iter(boots or [BOOT] * 3)
    approvals = iter(approvals or [approval, approval])
    monkeypatch.setattr(inputs, "read_boot_id", lambda: next(boots))
    monkeypatch.setattr(
        inputs,
        "load_bootstrap_approval",
        lambda **kw: calls["load"].append(kw) or next(approvals),
    )

    def advance(**kwargs):
        calls["advance"].append(kwargs)
        if advance_error:
            raise advance_error
        return protected[2]

    monkeypatch.setattr(inputs, "advance_deadline", advance)
    return inputs.ProtectedBootstrapInputs(lambda: next(stream))()


def test_observations_must_bind_same_current_context_operator_and_monotonic_time(
    monkeypatch, protected
):
    context, _approval, _deadline, _calls, _observe = protected
    same = inputs.BootstrapObservation(context, "operator-a", NOW, True)
    changed_context = inputs.BootstrapObservation(
        replace(context, generation=4), "operator-a", LATER, True
    )
    changed_operator = inputs.BootstrapObservation(context, "operator-b", LATER, True)
    earlier = inputs.BootstrapObservation(
        context, "operator-a", "2026-10-12T23:59:59Z", True
    )
    for current in (changed_context, changed_operator, earlier):
        with pytest.raises(
            ApprovalRefused, match="protected bootstrap runtime inputs refused"
        ):
            _run_with_observations(monkeypatch, protected, [same, current])


@pytest.mark.parametrize("changed", ["boot_before", "boot_during", "trust"])
def test_boot_and_fresh_trust_must_remain_bound(monkeypatch, protected, changed):
    context, approval, _deadline, _calls, _observe = protected
    observation = inputs.BootstrapObservation(context, "operator-a", NOW, True)
    if changed == "boot_before":
        boots, approvals = ["22222222-2222-2222-2222-222222222222"], None
    elif changed == "boot_during":
        boots, approvals = [BOOT, BOOT, "22222222-2222-2222-2222-222222222222"], None
    else:
        boots = None
        approvals = [approval, replace(approval, payload_digest="sha256:" + "b" * 64)]
    with pytest.raises(
        ApprovalRefused, match="protected bootstrap runtime inputs refused"
    ):
        _run_with_observations(
            monkeypatch,
            protected,
            [observation, observation],
            boots=boots,
            approvals=approvals,
        )


def test_missing_retained_deadline_refuses_without_initialization_fallback(
    monkeypatch, protected
):
    context, approval, _deadline, calls, _observe = protected
    observation = inputs.BootstrapObservation(context, "operator-a", NOW, True)
    secret = "/sensitive/protected/state"

    def missing(**kwargs):
        calls["advance"].append(kwargs)
        raise ApprovalRefused(
            f"missing retained deadline at {secret}; no restart fallback"
        )

    monkeypatch.setattr(inputs, "advance_deadline", missing)
    with pytest.raises(ApprovalRefused) as exc:
        inputs.ProtectedBootstrapInputs(lambda: observation)()
    assert str(exc.value) == "protected bootstrap runtime inputs refused"
    assert secret not in str(exc.value)
    assert len(calls["load"]) == 2
    assert calls["advance"][0]["approval"] is approval


def test_reader_and_clock_exceptions_are_redacted(monkeypatch, protected):
    context, _approval, _deadline, _calls, _observe = protected
    observation = inputs.BootstrapObservation(context, "operator-a", NOW, True)
    monkeypatch.setattr(
        inputs,
        "load_bootstrap_approval",
        lambda **_kw: (_ for _ in ()).throw(OSError("private path detail")),
    )
    with pytest.raises(ApprovalRefused) as exc:
        inputs.ProtectedBootstrapInputs(lambda: observation)()
    assert str(exc.value) == "protected bootstrap runtime inputs refused"
    assert "private path detail" not in str(exc.value)

    # A clock source failure after both approval reads is redacted as well.
    _context, approval, deadline, calls, _observe = protected
    monkeypatch.setattr(
        inputs,
        "load_bootstrap_approval",
        lambda **kw: calls["load"].append(kw) or approval,
    )
    monkeypatch.setattr(
        inputs, "advance_deadline", lambda **kw: calls["advance"].append(kw) or deadline
    )
    monkeypatch.setattr(inputs, "read_boot_id", lambda: BOOT)
    monkeypatch.setattr(
        inputs,
        "read_boottime_ns",
        lambda: (_ for _ in ()).throw(OSError("clock secret")),
    )
    with pytest.raises(ApprovalRefused) as clock_exc:
        inputs.ProtectedBootstrapInputs(lambda: observation)()
    assert str(clock_exc.value) == "protected bootstrap runtime inputs refused"
    assert "clock secret" not in str(clock_exc.value)
