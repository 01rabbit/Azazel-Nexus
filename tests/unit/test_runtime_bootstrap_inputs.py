"""Protected-input composition tests with entirely injected readers."""

from dataclasses import replace
import os

import pytest

from azazel_nexus.bootstrap_approval import BootstrapContext, VerifiedBootstrapApproval
from azazel_nexus.bootstrap_deadline import BootstrapDeadline
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus import bootstrap_deadline_store as deadline_store
from azazel_nexus_runtime import bootstrap_inputs as inputs
from test_bootstrap_deadline_store import state_store  # noqa: F401  (fixture)

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


# --- ProtectedBootstrapInitialAdmission (the only initializer) -------------

@pytest.fixture
def initial(monkeypatch, protected):
    context, approval, deadline, calls, _observe = protected
    calls["begin"] = []
    calls["retain"] = []
    state = replace(deadline)
    monkeypatch.setattr(
        inputs, "begin_deadline", lambda a, **kw: calls["begin"].append((a, kw)) or state
    )
    monkeypatch.setattr(
        inputs, "retain_initial_deadline",
        lambda s: calls["retain"].append(s) or deadline,
    )

    def forbid(**_kw):
        raise AssertionError("advance must not run during first admission")

    monkeypatch.setattr(inputs, "advance_deadline", forbid)
    observation = inputs.BootstrapObservation(context, "operator-a", NOW, True)
    return context, approval, deadline, state, calls, observation


def test_verify_performs_no_store_write(monkeypatch, initial):
    context, approval, _deadline, _state, calls, observation = initial
    result = inputs.ProtectedBootstrapInitialAdmission(lambda: observation).verify()
    assert result == approval
    assert calls["begin"] == [] and calls["retain"] == []


def test_retain_happy_path_begins_from_current_observation_and_retains_once(initial):
    _context, approval, deadline, state, calls, observation = initial
    admission = inputs.ProtectedBootstrapInitialAdmission(lambda: observation)
    assert admission.retain(approval) is deadline
    assert calls["begin"] == [(approval, {
        "boot_id": BOOT, "now": NOW, "boottime_ns": 11 * NS, "clock_trusted": True,
    })]
    assert calls["retain"] == [state]
    assert len(calls["load"]) == 2


@pytest.mark.parametrize("expected", [None, "approval"])
def test_retain_requires_a_verified_approval_object(initial, expected):
    *_, calls, observation = initial
    with pytest.raises(ApprovalRefused, match="protected bootstrap runtime inputs refused"):
        inputs.ProtectedBootstrapInitialAdmission(lambda: observation).retain(expected)
    assert calls["retain"] == []


def test_retain_refuses_when_approval_differs_from_verified(initial):
    _context, approval, _d, _s, calls, observation = initial
    other = replace(approval, payload_digest="sha256:" + "b" * 64)
    with pytest.raises(ApprovalRefused, match="protected bootstrap runtime inputs refused"):
        inputs.ProtectedBootstrapInitialAdmission(lambda: observation).retain(other)
    assert calls["begin"] == [] and calls["retain"] == []


def test_retain_refuses_on_changed_observations_and_boot_before(monkeypatch, initial):
    context, approval, _d, _s, calls, observation = initial
    changed = inputs.BootstrapObservation(
        replace(context, generation=4), "operator-a", LATER, True)
    values = iter([observation, changed])
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInitialAdmission(lambda: next(values)).retain(approval)
    monkeypatch.setattr(inputs, "read_boot_id",
                        lambda: "22222222-2222-2222-2222-222222222222")
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInitialAdmission(lambda: observation).retain(approval)
    assert calls["retain"] == []


def test_retain_refuses_on_boot_change_after_retention(monkeypatch, initial):
    _c, approval, _d, _s, calls, observation = initial
    boots = iter([BOOT, BOOT, "22222222-2222-2222-2222-222222222222"])
    monkeypatch.setattr(inputs, "read_boot_id", lambda: next(boots))
    with pytest.raises(ApprovalRefused, match="protected bootstrap runtime inputs refused"):
        inputs.ProtectedBootstrapInitialAdmission(lambda: observation).retain(approval)


def test_retain_refuses_on_trust_change(monkeypatch, initial):
    _c, approval, _d, _s, calls, observation = initial
    approvals = iter([approval, replace(approval, payload_digest="sha256:" + "b" * 64)])
    monkeypatch.setattr(inputs, "load_bootstrap_approval", lambda **_kw: next(approvals))
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInitialAdmission(lambda: observation).retain(approval)
    assert calls["retain"] == []


def test_retain_refuses_on_stale_window_and_backward_elapsed(monkeypatch, initial):
    _c, approval, _d, _s, calls, observation = initial
    window = type("W", (), {"observed_boottime_ns": 10 * NS,
                            "valid_until_boottime_ns": 20 * NS})()
    stale = inputs.BootstrapObservation.__new__(inputs.BootstrapObservation)
    for field in observation.__dataclass_fields__:
        object.__setattr__(stale, field, getattr(observation, field))
    object.__setattr__(stale, "time_window", window)
    # expired window before retention
    monkeypatch.setattr(inputs, "read_boottime_ns", lambda: 30 * NS)
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInitialAdmission(lambda: stale).retain(approval)
    assert calls["retain"] == []
    # clock moves backward during retention
    times = iter([15 * NS, 14 * NS])
    monkeypatch.setattr(inputs, "read_boottime_ns", lambda: next(times))
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInitialAdmission(lambda: stale).retain(approval)


def test_retain_errors_are_redacted(monkeypatch, initial):
    _c, approval, _d, _s, calls, observation = initial
    secret = "/sensitive/path"

    def exists(_state):
        raise ApprovalRefused(f"initial exists at {secret}")

    monkeypatch.setattr(inputs, "retain_initial_deadline", exists)
    with pytest.raises(ApprovalRefused) as exc:
        inputs.ProtectedBootstrapInitialAdmission(lambda: observation).retain(approval)
    assert str(exc.value) == "protected bootstrap runtime inputs refused"
    assert secret not in str(exc.value)


def test_refresh_adapter_never_initializes(monkeypatch, protected):
    context, _approval, _deadline, calls, _observe = protected
    observation = inputs.BootstrapObservation(context, "operator-a", NOW, True)

    def forbid(*_a, **_kw):
        raise AssertionError("refresh must not initialize")

    monkeypatch.setattr(inputs, "begin_deadline", forbid)
    monkeypatch.setattr(inputs, "retain_initial_deadline", forbid)

    def missing(**_kw):
        raise ApprovalRefused("missing")

    monkeypatch.setattr(inputs, "advance_deadline", missing)
    with pytest.raises(ApprovalRefused, match="protected bootstrap runtime inputs refused"):
        inputs.ProtectedBootstrapInputs(lambda: observation)()


def test_refactored_refresh_keeps_call_sequence(protected):
    _c, _a, deadline, calls, observe = protected
    assert inputs.ProtectedBootstrapInputs(observe)() is deadline
    assert len(calls["boot"]) == 3 and calls["clock"] == [True]
    assert len(calls["advance"]) == 1


def test_real_store_first_admission_then_refresh_returns_same_admitted_fields(
    monkeypatch, state_store,  # noqa: F811
):
    directory, verified, expected, _owner = state_store
    # Same private seams as the store tests; the owner is the test uid.
    uid = os.getuid()
    retain_at, advance_at = deadline_store._retain_initial_at, deadline_store._advance_at
    monkeypatch.setattr(
        deadline_store, "_retain_initial_at",
        lambda fd, state, *, owner: retain_at(fd, state, owner=uid),
    )
    monkeypatch.setattr(
        deadline_store, "_advance_at",
        lambda fd, *, owner, **kw: advance_at(fd, owner=uid, **kw),
    )
    boot = verified.context.boot_id
    clock = {"ns": 100 * NS}
    monkeypatch.setattr(inputs, "read_boot_id", lambda: boot)
    monkeypatch.setattr(inputs, "read_boottime_ns", lambda: clock["ns"])
    monkeypatch.setattr(inputs, "load_bootstrap_approval", lambda **_kw: verified)
    start = "2026-10-13T00:00:00Z"
    observation = inputs.BootstrapObservation(
        verified.context, verified.operator, start, True)
    admission = inputs.ProtectedBootstrapInitialAdmission(lambda: observation)

    assert admission.verify() == verified
    assert not list(directory.iterdir())
    retained = admission.retain(verified)
    assert retained == expected
    assert list(directory.iterdir())

    # A second first-admission never overwrites or advances.
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(ApprovalRefused, match="protected bootstrap runtime inputs refused"):
        admission.retain(verified)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before

    # The real refresh adapter then returns the same admitted fields, advanced.
    clock["ns"] = 110 * NS
    later = inputs.BootstrapObservation(
        verified.context, verified.operator, "2026-10-13T00:00:10Z", True)
    refreshed = inputs.ProtectedBootstrapInputs(lambda: later)()
    assert (refreshed.approval, refreshed.admitted_at, refreshed.admitted_boottime_ns,
            refreshed.deadline_boottime_ns) == (
        retained.approval, retained.admitted_at, retained.admitted_boottime_ns,
        retained.deadline_boottime_ns)
    assert refreshed.last_boottime_ns == 110 * NS
