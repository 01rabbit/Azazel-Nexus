"""Policy-pinned existing-audit pre-start checks with synthetic managers."""

from dataclasses import replace
from hashlib import sha256
import os
from types import SimpleNamespace

import pytest

from azazel_nexus import bootstrap_prestart_policy as policy_codec
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_audit, bootstrap_prestart
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap_audit import _chain  # noqa: F401

pytest_plugins = ("test_runtime_bootstrap_prestart",)


class ReadOnlyManager:
    def __init__(self, *, masked=True, inactive=True):
        self.masked_values = iter(masked if isinstance(masked, (tuple, list)) else [masked] * 4)
        self.inactive_values = iter(inactive if isinstance(inactive, (tuple, list)) else [inactive] * 4)
        self.reads = []

    def is_masked(self, unit):
        self.reads.append(("masked", unit))
        return next(self.masked_values)

    def is_inactive(self, unit):
        self.reads.append(("inactive", unit))
        return next(self.inactive_values)

    def __getattr__(self, name):
        if name in {"mask", "unmask", "start", "stop", "enable", "disable"}:
            pytest.fail(f"pre-start inspection attempted manager write operation: {name}")
        raise AttributeError(name)


def _pinned_policy(configured_data, *, sequence=4, head="a" * 64,
                   max_bytes=12000, max_segments=6):
    context, path, _ = configured_data
    current = policy_codec.decode_prestart_policy(path.read_bytes(), expected=context)
    updated = replace(
        current, audit_sequence=sequence, audit_head=head,
        max_audit_bytes=max_bytes, max_audit_segments=max_segments,
    )
    raw = policy_codec.encode_prestart_policy(updated)
    path.write_bytes(raw)
    path.chmod(0o600)
    return replace(context, policy_digest="sha256:" + sha256(raw).hexdigest()), updated


def test_audit_check_requires_exact_true_masked_and_inactive_before_and_after(
    configured, monkeypatch,
):
    context, _, _ = configured
    manager = ReadOnlyManager(masked=[True, True, True, True], inactive=[True] * 4)
    observation = AuditObservation(1, "a" * 64, 1, 123)
    calls = []
    monkeypatch.setattr(bootstrap_prestart, "inspect_existing_audit", lambda **kwargs: calls.append(kwargs) or observation)

    result = bootstrap_prestart.check_bootstrap_existing_audit(expected=context, manager=manager)

    assert type(result) is AuditObservation
    assert result is observation
    assert len(manager.reads) == 8
    assert calls == [{
        "expected_head": (1, "a" * 64), "max_total_bytes": 10000, "max_segments": 10,
    }]
    assert set(manager.reads) == {
        ("masked", UnitKey.AUDITD), ("inactive", UnitKey.AUDITD),
        ("masked", UnitKey.COMMISSIOND), ("inactive", UnitKey.COMMISSIOND),
    }


@pytest.mark.parametrize("bad", [False, None, 1, "yes"])
@pytest.mark.parametrize("check", ["masked", "inactive"])
def test_non_exact_true_helper_state_prevents_audit_inspection(
    configured, monkeypatch, bad, check,
):
    context, _, _ = configured
    states = [True] * 4
    states[0] = bad
    manager = ReadOnlyManager(**{check: states})
    monkeypatch.setattr(
        bootstrap_prestart, "inspect_existing_audit",
        lambda **_kwargs: pytest.fail("audit must not be inspected"),
    )

    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(expected=context, manager=manager)


def test_audit_observation_must_be_exact_type_and_match_pinned_head(configured, monkeypatch):
    context, _, _ = configured
    manager = ReadOnlyManager()

    class DerivedObservation(AuditObservation):
        pass

    for observed in (
        DerivedObservation(1, "a" * 64, 1, 100),
        AuditObservation(2, "a" * 64, 1, 100),
        AuditObservation(1, "b" * 64, 1, 100),
    ):
        monkeypatch.setattr(bootstrap_prestart, "inspect_existing_audit", lambda **_kwargs: observed)
        with pytest.raises(ApprovalRefused):
            bootstrap_prestart.check_bootstrap_existing_audit(expected=context, manager=manager)


def test_policy_change_after_audit_observation_refuses(configured, monkeypatch):
    context, _, _ = configured
    original = bootstrap_prestart.load_bootstrap_prestart_policy
    calls = []

    def change_after_audit(*, expected):
        policy = original(expected=expected)
        calls.append(None)
        return policy if len(calls) == 1 else replace(policy, max_audit_bytes=policy.max_audit_bytes + 1)

    monkeypatch.setattr(bootstrap_prestart, "load_bootstrap_prestart_policy", change_after_audit)
    monkeypatch.setattr(
        bootstrap_prestart, "inspect_existing_audit",
        lambda **_kwargs: AuditObservation(1, "a" * 64, 1, 100),
    )

    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(
            expected=context, manager=ReadOnlyManager(),
        )


def test_actual_ordinary_audit_chain_matches_rewritten_pinned_policy(
    configured, tmp_path, monkeypatch,
):
    ledger = _chain(tmp_path / "audit")
    expected_head = ledger.head()
    context, _policy = _pinned_policy(
        configured, sequence=expected_head[0], head=expected_head[1],
        max_bytes=65536, max_segments=8,
    )
    owner = os.getuid()
    opens = []

    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=owner))

    def open_ledger(actual_owner):
        assert actual_owner == owner
        opens.append(actual_owner)
        return os.open(ledger.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(bootstrap_audit, "_open_ledger", open_ledger)
    result = bootstrap_prestart.check_bootstrap_existing_audit(
        expected=context, manager=ReadOnlyManager(),
    )

    assert type(result) is AuditObservation
    assert (result.sequence, result.digest) == expected_head
    assert result.segments == len(ledger.segments())
    assert result.total_bytes == sum(path.stat().st_size for path in ledger.segments())
    assert opens == [owner, owner]


def test_combined_prestart_capacity_failure_prevents_audit_inspection(
    configured, monkeypatch,
):
    context, _, _ = configured
    monkeypatch.setattr(
        bootstrap_prestart, "check_bootstrap_capacity",
        lambda **_kwargs: (_ for _ in ()).throw(ApprovalRefused("synthetic capacity refusal")),
    )
    monkeypatch.setattr(
        bootstrap_prestart, "check_bootstrap_existing_audit",
        lambda **_kwargs: pytest.fail("audit inspection must follow successful capacities"),
    )

    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.inspect_bootstrap_prestart(
            expected=context, manager=ReadOnlyManager(),
        )


def test_combined_prestart_runs_capacity_then_pinned_audit_and_returns_observation(
    configured, monkeypatch,
):
    context, _, _ = configured
    observation = AuditObservation(1, "a" * 64, 1, 100)
    calls = []

    def capacity_check(*, expected):
        calls.append(("capacity", expected))

    def audit_check(*, expected, manager):
        calls.append(("audit", expected, manager))
        return observation

    monkeypatch.setattr(bootstrap_prestart, "check_bootstrap_capacity", capacity_check)
    monkeypatch.setattr(bootstrap_prestart, "check_bootstrap_existing_audit", audit_check)
    manager = ReadOnlyManager()

    result = bootstrap_prestart.inspect_bootstrap_prestart(expected=context, manager=manager)

    assert result is observation
    assert calls == [("capacity", context), ("audit", context, manager)]
    assert len(manager.reads) == 8
