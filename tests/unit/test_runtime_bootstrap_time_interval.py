"""Both UTC bounds must fit a freshly verified approval; no real clock trust."""

from dataclasses import replace

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs as inputs
from test_runtime_bootstrap_inputs import protected as _protected_fixture, NOW, LATER
from test_bootstrap_approval import signed as _signed_fixture
from azazel_nexus.bootstrap_approval import verify_bootstrap_approval

protected = _protected_fixture
signed = _signed_fixture


def test_interval_verifies_lower_and_upper_and_retains_upper(protected):
    context, _, deadline, calls, _ = protected
    observation = inputs.BootstrapObservation(context, "operator-a", LATER, True, earliest=NOW)
    assert inputs.ProtectedBootstrapInputs(lambda: observation)() is deadline
    assert [call["now"] for call in calls["load"]] == [NOW, LATER, NOW, LATER]
    assert calls["advance"][0]["now"] == LATER


@pytest.mark.parametrize("refuse_at", [NOW, LATER])
def test_either_bound_refusal_prevents_deadline_advance(protected, monkeypatch, refuse_at):
    context, approval, _, calls, _ = protected

    def verify(**kwargs):
        if kwargs["now"] == refuse_at:
            raise ApprovalRefused("outside signed interval")
        return approval

    monkeypatch.setattr(inputs, "load_bootstrap_approval", verify)
    observation = inputs.BootstrapObservation(context, "operator-a", LATER, True, earliest=NOW)
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInputs(lambda: observation)()
    assert calls["advance"] == []


def test_reversed_interval_refuses(protected):
    with pytest.raises(ApprovalRefused):
        inputs.BootstrapObservation(protected[0], "operator-a", NOW, True, earliest=LATER)


def test_lower_bound_rollback_refuses_even_if_upper_is_unchanged(protected):
    context, _, _, calls, _ = protected
    observations = iter([
        inputs.BootstrapObservation(context, "operator-a", LATER, True, earliest=LATER),
        inputs.BootstrapObservation(context, "operator-a", LATER, True, earliest=NOW),
    ])
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInputs(lambda: next(observations))()
    assert calls["advance"] == []


def test_approval_change_across_bounds_refuses(protected, monkeypatch):
    context, approval, _, calls, _ = protected
    monkeypatch.setattr(inputs, "load_bootstrap_approval", lambda **kw:
                        approval if kw["now"] == NOW else replace(approval, operator="operator-b"))
    observation = inputs.BootstrapObservation(context, "operator-a", LATER, True, earliest=NOW)
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInputs(lambda: observation)()
    assert calls["advance"] == []


@pytest.mark.parametrize("earliest, latest, accepted", [
    ("2026-10-12T23:59:59Z", "2026-10-13T00:00:01Z", False),
    ("2026-10-13T00:04:59Z", "2026-10-13T00:05:00Z", False),
    ("2026-10-13T00:00:00Z", "2026-10-13T00:04:59Z", True),
])
def test_real_signature_verifier_requires_entire_interval_inside_grant(
    signed, monkeypatch, earliest, latest, accepted,
):
    _, _, context, arguments = signed
    monkeypatch.setattr(inputs, "load_bootstrap_approval", lambda **kw:
                        verify_bootstrap_approval(**(arguments | kw)))
    observation = inputs.BootstrapObservation(context, "operator-a", latest, True, earliest=earliest)
    if accepted:
        assert inputs._verify_observation(observation).context == context
    else:
        with pytest.raises(ApprovalRefused):
            inputs._verify_observation(observation)
