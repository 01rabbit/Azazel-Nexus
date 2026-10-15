"""Selected administrator source preserves validity metadata and node binding."""

from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_clock import AdministratorTimeWindow
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs as inputs
from test_runtime_bootstrap_administrator import observed as _observed_fixture

observed = _observed_fixture


@pytest.fixture
def clock(observed, monkeypatch):
    declaration, observation = observed
    context = observation.context
    window = AdministratorTimeWindow(context.node_digest, context.policy_digest, context.boot_id,
                                     "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z", 10, 20)
    calls = []

    def load(*, expected):
        calls.append(expected)
        return window

    monkeypatch.setattr(inputs, "load_administrator_time_window", load)
    return context, window, calls, declaration


def test_source_preserves_explicit_admin_time_window(clock):
    context, window, calls, declaration = clock
    observation = inputs.ProtectedAdministratorClockObservation(lambda: context)()
    assert observation.context == context
    assert observation.operator == declaration.operator
    assert observation.clock_trusted is True
    assert observation.earliest == window.earliest_utc
    assert observation.now == window.latest_utc
    assert observation.time_window is window
    assert calls == [context]


def test_context_change_during_clock_read_refuses(clock):
    context, _, _, _ = clock
    values = iter([context, replace(context, generation=context.generation + 1)])
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedAdministratorClockObservation(lambda: next(values))()


def test_missing_protected_time_does_not_fall_back_to_os_clock(clock, monkeypatch):
    def unavailable(**kwargs):
        raise ApprovalRefused("private diagnostic")

    monkeypatch.setattr(inputs, "load_administrator_time_window", unavailable)
    with pytest.raises(ApprovalRefused) as error:
        inputs.ProtectedAdministratorClockObservation(lambda: clock[0])()
    assert "private diagnostic" not in str(error.value)


def test_mismatched_window_binding_refuses(clock, monkeypatch):
    context, window, _, _ = clock
    monkeypatch.setattr(inputs, "load_administrator_time_window", lambda **_: replace(
        window, node_digest="sha256:" + "f" * 64))
    with pytest.raises(ApprovalRefused):
        inputs.ProtectedAdministratorClockObservation(lambda: context)()


def test_context_is_required_and_cannot_be_a_candidate_payload():
    with pytest.raises(TypeError):
        inputs.ProtectedAdministratorClockObservation()
    with pytest.raises(ValueError):
        inputs.ProtectedAdministratorClockObservation(None)
