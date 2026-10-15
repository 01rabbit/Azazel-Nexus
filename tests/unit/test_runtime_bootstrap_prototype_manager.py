"""Narrow protocol-forwarding tests; these do not prove real manager admission."""

from uuid import uuid4

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus_runtime.bootstrap_manager import (
    BootstrapNarrowingManager,
    _PrototypeBootstrapManager,
)
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed


def _transaction():
    return GrantTransaction(
        boot_id=str(uuid4()),
        context_digest="sha256:" + "a" * 64,
        approval_digest="sha256:" + "b" * 64,
        generation=1,
        generation_digest="sha256:" + "c" * 64,
        grant_id="d" * 32,
        unit_payload_digests=(
            ("azazel-auditd.service", "e" * 64),
            ("azazel-commissiond.service", "f" * 64),
        ),
        phase="pair_grant_intent",
    )


def _manager(kind=_PrototypeBootstrapManager):
    return kind(job_timeout_seconds=1.0)


def _noop():
    return None


def test_prototype_is_subclass_and_open_pair_forwards_exact_objects(monkeypatch):
    manager = _manager()
    transaction = _transaction()
    approval = object()
    callback = _noop
    observation = object()
    calls = []

    def publish(actual_transaction, *, approval, check_publish):
        calls.append((actual_transaction, approval, check_publish))
        return observation

    monkeypatch.setattr(manager, "_publish_and_inspect_pair", publish)

    assert isinstance(manager, BootstrapNarrowingManager)
    assert manager.open_pair(
        transaction, approval=approval, check_publish=callback,
    ) is None
    assert len(calls) == 1
    assert calls[0][0] is transaction
    assert calls[0][1] is approval
    assert calls[0][2] is callback


@pytest.mark.parametrize(
    ("unit", "private_method"),
    [
        (UnitKey.AUDITD, "_start_bound_audit"),
        (UnitKey.COMMISSIOND, "_start_bound_commission"),
    ],
)
def test_start_dispatch_forwards_same_transaction_and_callback(
    monkeypatch, unit, private_method,
):
    manager = _manager()
    transaction = _transaction()
    callback = _noop
    calls = []

    def dispatch(actual_transaction, *, check_start):
        calls.append((actual_transaction, check_start))

    monkeypatch.setattr(manager, private_method, dispatch)

    assert manager.start_and_wait(
        unit, transaction=transaction, check_start=callback,
    ) is None
    assert calls == [(transaction, callback)]
    assert calls[0][0] is transaction
    assert calls[0][1] is callback


@pytest.mark.parametrize("invalid", [UnitKey.WATCHDOG, True, "azazel-auditd.service"])
def test_start_and_readiness_reject_non_pair_or_non_unitkey_before_delegation(
    monkeypatch, invalid,
):
    manager = _manager()
    transaction = _transaction()
    calls = []
    monkeypatch.setattr(
        manager, "_start_bound_audit",
        lambda *_args, **_kwargs: calls.append("audit"),
    )
    monkeypatch.setattr(
        manager, "_start_bound_commission",
        lambda *_args, **_kwargs: calls.append("commission"),
    )
    monkeypatch.setattr(
        manager, "_bound_helper_ready",
        lambda *_args, **_kwargs: calls.append("ready"),
    )

    with pytest.raises(UnitOperationFailed):
        manager.start_and_wait(invalid, transaction=transaction, check_start=lambda: None)
    with pytest.raises(UnitOperationFailed):
        manager.is_ready(invalid)
    assert calls == []


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
def test_readiness_forwards_only_exact_pair_key_and_returns_delegate_result(
    monkeypatch, unit,
):
    manager = _manager()
    calls = []

    def retained():
        calls.append("retained")
        return None

    def ready(actual_unit):
        calls.append(("peer", actual_unit))
        return True

    manager._publication_check = retained
    monkeypatch.setattr(manager, "_bound_helper_ready", ready)
    assert manager.is_ready(unit) is True
    assert calls == ["retained", ("peer", unit), "retained"]


def test_readiness_refuses_before_peer_check_when_retained_publication_fails(
    monkeypatch,
):
    manager = _manager()
    failure = RuntimeError("retained publication unavailable")
    peer_calls = []

    def fail_publication():
        raise failure

    manager._publication_check = fail_publication
    monkeypatch.setattr(
        manager, "_bound_helper_ready", lambda unit: peer_calls.append(unit),
    )
    with pytest.raises(RuntimeError) as raised:
        manager.is_ready(UnitKey.AUDITD)
    assert raised.value is failure
    assert peer_calls == []


def test_readiness_refuses_if_publication_callback_changes_during_peer_check(
    monkeypatch,
):
    manager = _manager()
    calls = []

    def retained():
        calls.append("retained")
        return None

    def ready(unit):
        calls.append(("peer", unit))
        manager._publication_check = None
        return True

    manager._publication_check = retained
    monkeypatch.setattr(manager, "_bound_helper_ready", ready)
    with pytest.raises(UnitOperationFailed):
        manager.is_ready(UnitKey.COMMISSIOND)
    assert calls == ["retained", ("peer", UnitKey.COMMISSIOND)]


def test_readiness_refuses_when_final_retained_publication_check_fails(monkeypatch):
    manager = _manager()
    calls = []
    failure = RuntimeError("publication changed after peer check")

    def retained():
        calls.append("retained")
        if calls.count("retained") == 2:
            raise failure
        return None

    def ready(unit):
        calls.append(("peer", unit))
        return True

    manager._publication_check = retained
    monkeypatch.setattr(manager, "_bound_helper_ready", ready)
    with pytest.raises(RuntimeError) as raised:
        manager.is_ready(UnitKey.AUDITD)
    assert raised.value is failure
    assert calls == ["retained", ("peer", UnitKey.AUDITD), "retained"]


@pytest.mark.parametrize("operation", ["publish", "audit", "commission", "ready"])
def test_delegate_failure_propagates_without_later_delegates(monkeypatch, operation):
    manager = _manager()
    transaction = _transaction()
    failure = RuntimeError("synthetic delegate failure")
    calls = []

    def fail(name):
        def delegate(*_args, **_kwargs):
            calls.append(name)
            raise failure
        return delegate

    monkeypatch.setattr(manager, "_publish_and_inspect_pair", fail("publish"))
    monkeypatch.setattr(manager, "_start_bound_audit", fail("audit"))
    monkeypatch.setattr(manager, "_start_bound_commission", fail("commission"))
    monkeypatch.setattr(manager, "_bound_helper_ready", fail("ready"))
    if operation == "ready":
        manager._publication_check = _noop

    with pytest.raises(RuntimeError) as raised:
        if operation == "publish":
            manager.open_pair(transaction, approval=object(), check_publish=lambda: None)
        elif operation == "audit":
            manager.start_and_wait(
                UnitKey.AUDITD, transaction=transaction, check_start=lambda: None,
            )
        elif operation == "commission":
            manager.start_and_wait(
                UnitKey.COMMISSIOND, transaction=transaction, check_start=lambda: None,
            )
        else:
            manager.is_ready(UnitKey.AUDITD)

    assert raised.value is failure
    assert calls == [operation]


def test_production_narrowing_manager_remains_closed():
    manager = _manager(BootstrapNarrowingManager)
    transaction = _transaction()
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        with pytest.raises(UnitOperationFailed):
            manager.start_and_wait(
                unit, transaction=transaction, check_start=lambda: None,
            )
        assert manager.is_ready(unit) is False
    with pytest.raises(UnitOperationFailed):
        manager.open_pair(
            transaction, approval=object(), check_publish=lambda: None,
        )
