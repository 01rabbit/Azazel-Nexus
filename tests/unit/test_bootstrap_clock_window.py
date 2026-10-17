"""Validity windows cover every sampled instant under one UTC envelope."""

import pytest

from azazel_nexus.bootstrap_clock import (
    AdministratorClockLimits,
    project_administrator_time,
    project_administrator_window,
)
from azazel_nexus.bootstrap_approval import parse_bootstrap_time
from azazel_nexus.operator_trust import ApprovalRefused
import azazel_nexus.bootstrap_clock as clock
import test_bootstrap_clock as clock_helpers

NS = clock_helpers.NS


def limits(*, uncertainty=13 * NS, drift=0):
    return AdministratorClockLimits(
        max_anchor_lifetime_ns=20 * NS,
        max_uncertainty_ns=uncertainty,
        drift_ppb=drift,
    )


@pytest.mark.parametrize("drift", [0, 100_000_000, 999_999_999])
def test_window_envelope_contains_point_bounds_across_half_open_interval(drift):
    anchor = clock_helpers.anchor()
    expected = clock_helpers.context()
    policy = limits(drift=drift)
    window = project_administrator_window(
        anchor, expected=expected, boottime_ns=clock_helpers.START, limits=policy,
    )

    assert window.observed_boottime_ns == anchor.boottime_ns
    assert clock_helpers.START < window.valid_until_boottime_ns <= anchor.expires_boottime_ns
    low = parse_bootstrap_time(window.earliest_utc)
    high = parse_bootstrap_time(window.latest_utc)
    instants = {
        window.observed_boottime_ns,
        window.valid_until_boottime_ns - 1,
        (window.observed_boottime_ns + window.valid_until_boottime_ns - 1) // 2,
    }
    for instant in sorted(instants):
        point = project_administrator_time(
            anchor, expected=expected, boottime_ns=instant, limits=policy,
        )
        assert low <= parse_bootstrap_time(point.earliest_utc)
        assert parse_bootstrap_time(point.latest_utc) <= high

    if window.valid_until_boottime_ns < anchor.expires_boottime_ns:
        try:
            next_point = project_administrator_time(
                anchor, expected=expected,
                boottime_ns=window.valid_until_boottime_ns, limits=policy,
            )
        except ApprovalRefused:
            pass
        else:
            assert parse_bootstrap_time(next_point.latest_utc) > high
            excess = parse_bootstrap_time(next_point.latest_utc) - low
            assert excess.total_seconds() * NS > policy.max_uncertainty_ns


def test_narrow_uncertainty_budget_can_produce_one_nanosecond_window():
    anchor = clock_helpers.anchor()
    policy = limits(uncertainty=10 * NS, drift=0)

    window = project_administrator_window(
        anchor, expected=clock_helpers.context(),
        boottime_ns=clock_helpers.START, limits=policy,
    )

    assert window.valid_until_boottime_ns == window.observed_boottime_ns + 1
    point = project_administrator_time(
        anchor, expected=clock_helpers.context(),
        boottime_ns=window.observed_boottime_ns, limits=policy,
    )
    assert (window.earliest_utc, window.latest_utc) == point[:2]


@pytest.mark.parametrize("case", ["before-anchor", "expired", "wrong-boot", "lifetime-policy"])
def test_window_inherits_anchor_binding_lifetime_and_expiry_refusals(case):
    anchor = clock_helpers.anchor()
    expected = clock_helpers.context()
    instant = clock_helpers.START
    policy = limits()
    if case == "before-anchor":
        instant -= 1
    elif case == "expired":
        instant = anchor.expires_boottime_ns
    elif case == "wrong-boot":
        from dataclasses import replace

        expected = replace(expected, boot_id="33333333-3333-4333-8333-333333333333")
    else:
        policy = AdministratorClockLimits(NS, 13 * NS, 0)

    with pytest.raises(ApprovalRefused):
        project_administrator_window(
            anchor, expected=expected, boottime_ns=instant, limits=policy,
        )


def test_window_binary_search_uses_at_most_sixty_five_point_projections(monkeypatch):
    original = clock.project_administrator_time
    calls = []

    def counted(*args, **kwargs):
        calls.append(kwargs["boottime_ns"])
        return original(*args, **kwargs)

    monkeypatch.setattr(clock, "project_administrator_time", counted)
    result = project_administrator_window(
        clock_helpers.anchor(), expected=clock_helpers.context(),
        boottime_ns=clock_helpers.START, limits=limits(drift=500_000_000),
    )

    assert result.valid_until_boottime_ns > result.observed_boottime_ns
    assert len(calls) <= 65
