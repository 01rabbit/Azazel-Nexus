"""Publication admission gates the fixed commission start composition."""

import pytest

from azazel_nexus.bootstrap_grant_transaction import advance_transaction
from azazel_nexus_runtime.bootstrap_audit_identity import AuditServiceIdentity
from azazel_nexus_runtime.bootstrap_audit_peer import AuditPeerBinding
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_controller import OWNER, PROFILE_DIGEST
from test_runtime_bootstrap_controller_ready import ReadyThenStartBus, _transaction
from test_runtime_bootstrap_manager import FakeSystemdBusSession


@pytest.mark.parametrize("publication", ["missing", "refused"])
def test_retained_publication_is_required_before_commission_start(publication):
    bus = ReadyThenStartBus()
    sessions = []

    def factory():
        session = FakeSystemdBusSession(bus=bus)
        sessions.append(session)
        return session

    manager = BootstrapNarrowingManager(job_timeout_seconds=5.0,
                                        session_factory=factory)
    manager._controller_binding = (object(), OWNER, PROFILE_DIGEST)
    grant = _transaction("pair_grant_intent")
    manager._controller_grant = grant
    manager._controller_ready_confirmed = True
    identity = AuditServiceIdentity(
        owner=OWNER,
        profile_digest=PROFILE_DIGEST,
        pid=4321,
        invocation_id=b"i" * 16,
    )
    manager._audit_peer_binding = AuditPeerBinding(identity, lambda: identity)

    expected = advance_transaction(grant, "pair_grant_opened")
    expected = advance_transaction(expected, "auditd_start_intent")
    expected = advance_transaction(expected, "auditd_ready")
    expected = advance_transaction(
        expected,
        "audit_intent_recorded",
        evidence_digest="sha256:" + "a" * 64,
    )
    transaction = advance_transaction(expected, "commissiond_start_intent")
    manager._publication_check = (
        None if publication == "missing" else lambda: False
    )
    trusted_checks = []

    with pytest.raises(UnitOperationFailed, match="publication admission"):
        manager._start_bound_commission(
            transaction, check_start=lambda: trusted_checks.append(True)
        )

    assert trusted_checks == []
    assert sessions == [] and bus.calls == [] and not bus.started
    with pytest.raises(UnitOperationFailed, match="retained commission peer binding"):
        manager._commission_binding_source()
