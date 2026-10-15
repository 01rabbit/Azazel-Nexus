"""Freshness through verification/retention using synthetic elapsed clocks only."""

from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_clock import AdministratorTimeWindow, ProjectedAdministratorTime
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs as inputs
from test_runtime_bootstrap_inputs import protected as _fixture, NOW, LATER, NS

protected = _fixture


def observation(context):
    window = AdministratorTimeWindow(context.node_digest, context.policy_digest, context.boot_id,
                                     NOW, LATER, 10 * NS, 12 * NS)
    return inputs.BootstrapObservation(context, "operator-a", LATER, True, earliest=NOW, time_window=window)


def test_fresh_window_is_checked_before_and_after_retention(protected, monkeypatch):
    context, _, deadline, calls, _ = protected
    current = observation(context)
    times = iter([11 * NS, 12 * NS - 1])
    monkeypatch.setattr(inputs, "read_boottime_ns", lambda: next(times))
    assert inputs.ProtectedBootstrapInputs(lambda: current)() is deadline
    assert calls["advance"][0]["boottime_ns"] == 11 * NS


@pytest.mark.parametrize("first, last, writes", [
    (12 * NS, 12 * NS, 0), (9 * NS, 11 * NS, 0),
    (11 * NS, 12 * NS, 1), (11 * NS, 11 * NS - 1, 1),
])
def test_stale_or_backward_observation_never_returns_retained_grant(
    protected, monkeypatch, first, last, writes,
):
    context, _, _, calls, _ = protected
    current = observation(context)
    times = iter([first, last])
    monkeypatch.setattr(inputs, "read_boottime_ns", lambda: next(times))
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInputs(lambda: current)()
    assert len(calls["advance"]) == writes


@pytest.mark.parametrize("field,value", [("earliest", LATER), ("now", NOW)])
def test_utc_strings_cannot_disagree_with_window(protected, field, value):
    with pytest.raises(ApprovalRefused):
        replace(observation(protected[0]), **{field: value})


def test_point_projection_is_not_a_validity_envelope(protected):
    with pytest.raises(ApprovalRefused):
        replace(observation(protected[0]), time_window=ProjectedAdministratorTime(NOW, LATER, 10 * NS, 12 * NS))


def test_refresh_cannot_drop_window_metadata(protected):
    current = observation(protected[0])
    values = iter([current, replace(current, time_window=None)])
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedBootstrapInputs(lambda: next(values))()
    assert protected[3]["advance"] == []
