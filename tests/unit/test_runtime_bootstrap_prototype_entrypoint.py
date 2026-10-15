"""Private prototype adapter routing through the real selected supervisor.

Publication, job transport, identities, and readiness responses are synthetic
seams here. This proves adapter/supervisor control flow only; it is not
publication, systemd, or authenticated-peer qualification.
"""

from contextlib import nullcontext
from hashlib import sha256

import pytest

from azazel_nexus_runtime.bootstrap import BootstrapResult
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap_audit_client import AuditAppendReceipt
from azazel_nexus_runtime.bootstrap_audit_identity import AuditServiceIdentity
from azazel_nexus_runtime.bootstrap_commission_identity import CommissionServiceIdentity
from azazel_nexus_runtime.bootstrap_manager import _PrototypeBootstrapManager
from azazel_nexus_runtime.bootstrap_audit_peer import AuditPeerBinding
from azazel_nexus_runtime.bootstrap_commission_peer import CommissionPeerBinding
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from test_runtime_bootstrap import Harness, RecordingManager, evidence as harness_evidence
import test_runtime_bootstrap_entrypoint as composition


def _evidence():
    return harness_evidence.__wrapped__(None)


class FakeClient:
    def __init__(self):
        self.sequence = 1
        self.digest = "a" * 64

    def __call__(self, event):
        self.sequence += 1
        self.digest = sha256(repr(event).encode()).hexdigest()
        return AuditAppendReceipt(self.sequence, self.digest)

    def observe_head(self):
        return self.sequence, self.digest


@pytest.mark.parametrize("fail_audit_start", [False, True])
def test_selected_supervisor_uses_private_prototype_adapter(
    monkeypatch, fail_audit_start,
):
    from azazel_nexus_runtime import bootstrap as bootstrap_module

    events = []
    fallback = RecordingManager()
    manager = _PrototypeBootstrapManager(
        job_timeout_seconds=0.05,
        session_factory=lambda: pytest.fail("synthetic adapter must not open a real bus"),
    )

    # Non-prototype containment methods use the existing deterministic Harness
    # manager. Public open/start/readiness remain the real prototype methods.
    for name in (
        "close_starts", "stop_and_wait", "mask", "is_inactive", "is_masked",
        "confirm_empty_pair", "withdraw_pair",
    ):
        setattr(manager, name, getattr(fallback, name))

    def publish_synthetic(transaction, *, approval, check_publish):
        # This is an explicit fake publication boundary, not a call to the
        # production publication inspector or evidence of a published grant.
        fallback.open_pair(
            transaction, approval=approval, check_publish=check_publish,
        )
        # Publication retains the original pair_grant_intent grant; the
        # supervisor advances its own matching transaction after this returns.
        manager._controller_grant = transaction
        manager._controller_binding = (
            "synthetic-controller-identity", 1000, "sha256:" + "b" * 64,
        )
        manager._publication_check = lambda: harness.events.append("retained-publication-check")

    manager._publish_and_inspect_pair = publish_synthetic
    ready_calls = []

    class ReadinessTransport:
        def observe_head(self):
            ready_calls.append(UnitKey.AUDITD)
            if fail_audit_start:
                raise UnitOperationFailed("synthetic audit readiness refusal")
            return 1, "a" * 64

        def observe_inventory(self):
            ready_calls.append(UnitKey.COMMISSIOND)
            return "sha256:" + "c" * 64

    readiness_transport = ReadinessTransport()
    manager._authenticated_audit_client = readiness_transport
    manager._authenticated_commission_client = readiness_transport
    audit_identity = AuditServiceIdentity(
        owner=":1.77", profile_digest="sha256:" + "b" * 64,
        pid=1234, invocation_id=b"a" * 16,
    )
    commission_identity = CommissionServiceIdentity(
        owner=":1.77", profile_digest="sha256:" + "b" * 64,
        pid=1235, invocation_id=b"c" * 16,
    )
    # These are transport/OS observation seams. The real capture/start methods
    # still create and consume their retained binding objects.
    manager._observe_audit_identity = lambda **_kwargs: audit_identity
    manager._observe_commission_identity = lambda **_kwargs: commission_identity

    starts = []

    def synthetic_owned_job(unit, *, expected_owner, check_start):
        del expected_owner
        assert check_start() is None
        starts.append(unit)
        if fail_audit_start and unit is UnitKey.AUDITD:
            raise UnitOperationFailed("synthetic audit job failure")

    manager._run_owned_start = synthetic_owned_job

    def confirm_controller_ready(transaction, *, check_ready, notify):
        fallback.confirm_controller_ready(
            transaction, check_ready=check_ready, notify=notify,
        )
        manager._controller_ready_confirmed = True

    manager.confirm_controller_ready = confirm_controller_ready
    client = FakeClient()
    manager._bootstrap_audit_client = lambda: client

    harness = Harness(_evidence(), manager=manager)
    events = harness.events

    composition._install_composition(
        monkeypatch, events=events, manager=manager,
    )
    monkeypatch.setattr(composition.entrypoint, "protected_bootstrap_inputs",
                        lambda: harness.refresh)
    monkeypatch.setattr(composition.entrypoint, "protected_bootstrap_generation_admission",
                        lambda: harness.admit)

    original_supervisor = bootstrap_module.BootstrapSupervisor

    def actual_supervisor(**options):
        assert options["record"] is client
        assert options["audit_head_reader"] is client
        options.update(
            grant_store_factory=lambda _guard: nullcontext(harness.grant_store),
            boot_id_reader=lambda: harness.deadline.approval.context.boot_id,
            prestart=lambda _context: AuditObservation(1, "a" * 64, 1, 100),
            audit_continuation=lambda _context, previous: previous,
            boottime_ns=harness.clock,
        )
        return original_supervisor(**options)

    monkeypatch.setattr(composition.entrypoint, "BootstrapSupervisor", actual_supervisor)
    # Composition helper installs the fake manager context; retain this test's
    # one client for both producer and live-head observation.
    manager._bootstrap_audit_client = lambda: client

    if fail_audit_start:
        with pytest.raises(UnitOperationFailed, match="synthetic audit job failure"):
            composition.entrypoint.run_selected_bootstrap(
                "retained", narrow=lambda: events.append("narrow"),
            )
        assert starts == [UnitKey.AUDITD]
        assert ready_calls == []
    else:
        result = composition.entrypoint.run_selected_bootstrap(
            "retained", narrow=lambda: events.append("narrow"),
        )
        assert type(result) is BootstrapResult and result.state == "stopped"
        assert starts == [UnitKey.AUDITD, UnitKey.COMMISSIOND]
        first_commission_ready = ready_calls.index(UnitKey.COMMISSIOND)
        assert first_commission_ready > 0
        assert all(unit is UnitKey.AUDITD for unit in ready_calls[:first_commission_ready])
        assert ready_calls[-2:] == [UnitKey.AUDITD, UnitKey.COMMISSIOND]
        assert isinstance(manager._audit_peer_binding, AuditPeerBinding)
        assert isinstance(manager._commission_peer_binding, CommissionPeerBinding)

    assert any(event == "retained-publication-check" for event in events)
    assert fallback.pair_open is False
    if fail_audit_start:
        assert UnitKey.COMMISSIOND not in starts
