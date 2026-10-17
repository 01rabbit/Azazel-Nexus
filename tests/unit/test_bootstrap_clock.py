"""Pure UTC projection from an explicit synthetic administrator anchor."""

from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_clock import (
    AdministratorClockLimits,
    AdministratorTimeAnchor,
    project_administrator_time,
)
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_generation import _context

NODE = "sha256:" + "1" * 64
POLICY = "sha256:" + "b" * 64
BOOT = "22222222-2222-4222-8222-222222222222"
EARLIEST = "2026-10-13T12:00:00Z"
LATEST = "2026-10-13T12:00:10Z"
START = 5_000_000_000
EXPIRY = 20_000_000_000
NS = 1_000_000_000
ZERO_DRIFT_LIMITS = AdministratorClockLimits(
    max_anchor_lifetime_ns=20 * NS,
    max_uncertainty_ns=20 * NS,
    drift_ppb=0,
)


def context():
    return _context(node_digest=NODE, policy_digest=POLICY, boot_id=BOOT)


def anchor(**changes):
    values = {
        "node_digest": NODE,
        "policy_digest": POLICY,
        "boot_id": BOOT,
        "earliest_utc": EARLIEST,
        "latest_utc": LATEST,
        "boottime_ns": START,
        "expires_boottime_ns": EXPIRY,
    }
    values.update(changes)
    return AdministratorTimeAnchor(**values)


def test_fractional_elapsed_seconds_round_bounds_outward():
    result = project_administrator_time(
        anchor(), expected=context(), boottime_ns=START + NS + 1,
        limits=ZERO_DRIFT_LIMITS,
    )

    assert result[:2] == ("2026-10-13T12:00:01Z", "2026-10-13T12:00:12Z")
    assert result.observed_boottime_ns == START + NS + 1
    assert result.valid_until_boottime_ns == EXPIRY


def test_exact_second_elapsed_moves_both_bounds_by_exactly_one_second():
    result = project_administrator_time(
        anchor(), expected=context(), boottime_ns=START + 2 * NS,
        limits=ZERO_DRIFT_LIMITS,
    )

    assert result[:2] == ("2026-10-13T12:00:02Z", "2026-10-13T12:00:12Z")


@pytest.mark.parametrize("field,value", [
    ("boot_id", "33333333-3333-4333-8333-333333333333"),
    ("node_digest", "sha256:" + "9" * 64),
    ("policy_digest", "sha256:" + "8" * 64),
])
def test_anchor_must_bind_expected_boot_node_and_policy(field, value):
    with pytest.raises(ApprovalRefused):
        project_administrator_time(
            anchor(), expected=replace(context(), **{field: value}), boottime_ns=START,
            limits=ZERO_DRIFT_LIMITS,
        )


@pytest.mark.parametrize("observed", [EXPIRY, EXPIRY + 1])
def test_exact_expiry_and_later_observations_refuse(observed):
    with pytest.raises(ApprovalRefused):
        project_administrator_time(
            anchor(), expected=context(), boottime_ns=observed, limits=ZERO_DRIFT_LIMITS,
        )


def test_observation_before_anchor_refuses():
    with pytest.raises(ApprovalRefused):
        project_administrator_time(
            anchor(), expected=context(), boottime_ns=START - 1, limits=ZERO_DRIFT_LIMITS,
        )


@pytest.mark.parametrize("boottime", [True, False, 1.0, "5000000000", None])
def test_projection_requires_exact_integer_boottime(boottime):
    with pytest.raises(ApprovalRefused):
        project_administrator_time(
            anchor(), expected=context(), boottime_ns=boottime, limits=ZERO_DRIFT_LIMITS,
        )


@pytest.mark.parametrize("field,value", [
    ("earliest_utc", "2026-10-13T12:00:00.1Z"),
    ("latest_utc", "not-a-time"),
    ("earliest_utc", "2026-02-30T00:00:00Z"),
    ("latest_utc", "2026-10-13T12:00:00+00:00"),
])
def test_anchor_rejects_malformed_noncanonical_utc(field, value):
    with pytest.raises(ApprovalRefused):
        anchor(**{field: value})


def test_anchor_rejects_reversed_utc_interval():
    with pytest.raises(ApprovalRefused):
        anchor(earliest_utc=LATEST, latest_utc=EARLIEST)


@pytest.mark.parametrize("field,value", [
    ("boottime_ns", True),
    ("boottime_ns", -1),
    ("boottime_ns", EXPIRY),
    ("expires_boottime_ns", START),
    ("expires_boottime_ns", False),
    ("expires_boottime_ns", 2**63),
])
def test_anchor_rejects_invalid_or_unbounded_lifetime(field, value):
    with pytest.raises(ApprovalRefused):
        anchor(**{field: value})


@pytest.mark.parametrize("values", [
    (0, 1, 0), (-1, 1, 0), (True, 1, 0), (1.5, 1, 0),
    (1, 0, 0), (1, -1, 0), (1, True, 0), (1, 1.5, 0),
    (1, 1, True), (1, 1, -1), (1, 1, 1_000_000_000),
])
def test_clock_limits_require_positive_bounded_exact_integers(values):
    with pytest.raises(ApprovalRefused):
        AdministratorClockLimits(*values)


def test_clock_limits_have_no_defaults():
    with pytest.raises(TypeError):
        AdministratorClockLimits()


def test_nonzero_drift_widens_bounds_outward():
    limits = AdministratorClockLimits(20 * NS, 20 * NS, 250_000_000)

    result = project_administrator_time(
        anchor(), expected=context(), boottime_ns=START + NS, limits=limits,
    )

    assert result[:2] == ("2026-10-13T12:00:00Z", "2026-10-13T12:00:12Z")


def test_anchor_lifetime_must_fit_policy_limit():
    limits = AdministratorClockLimits(14 * NS, 20 * NS, 0)

    with pytest.raises(ApprovalRefused):
        project_administrator_time(
            anchor(), expected=context(), boottime_ns=START, limits=limits,
        )


def test_final_width_including_fractional_rounding_margin_must_fit_limit():
    narrow_anchor = anchor(earliest_utc=EARLIEST, latest_utc=EARLIEST)
    limits = AdministratorClockLimits(20 * NS, NS - 1, 0)

    with pytest.raises(ApprovalRefused):
        project_administrator_time(
            narrow_anchor, expected=context(), boottime_ns=START + 1, limits=limits,
        )


def test_datetime_overflow_is_redacted_as_projection_refusal():
    near_max = "9999-12-31T23:59:59Z"
    bounded = anchor(earliest_utc=near_max, latest_utc=near_max,
                     boottime_ns=0, expires_boottime_ns=2 * NS)

    with pytest.raises(ApprovalRefused) as caught:
        project_administrator_time(
            bounded, expected=context(), boottime_ns=NS, limits=ZERO_DRIFT_LIMITS,
        )

    assert str(caught.value) == "administrator time projection refused"
    assert caught.value.__cause__ is None
