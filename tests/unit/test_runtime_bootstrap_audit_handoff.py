"""Real supervisor/job/capture/client composition with synthetic host and ledger."""

import json
from dataclasses import replace

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_manager as manager_module
from azazel_nexus_runtime.bootstrap_audit_client import BootstrapAuditClient
from azazel_nexus_runtime.bootstrap_manager import _PrototypeBootstrapManager
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
import test_runtime_bootstrap as supervisor_tests
from test_runtime_bootstrap_audit_client import DeadlineSocket, FakeClock
from test_runtime_bootstrap_audit_identity import FakeBus as AuditBus, PID
from test_runtime_bootstrap_audit_peer import HEADER, UID, PRIMARY_GID, _install_peer_evidence
from test_runtime_bootstrap_controller import IDENTITY, OWNER, PROFILE_DIGEST
from test_runtime_bootstrap_controller_ready import ReadyThenStartBus
from test_runtime_bootstrap_manager import FakeSystemdBusSession
from azazel_nexus_runtime.bootstrap_commission_client import BootstrapCommissionClient
from test_runtime_bootstrap_commission_identity import FakeBus as CommissionBus
from test_runtime_bootstrap_commission_peer import (
    ACCOUNTS, _install_peer_evidence as install_commission_peer,
)

evidence = supervisor_tests.evidence


@pytest.mark.parametrize("failure", [
    None, "capture", "peer", "commission-peer", "inventory", "receipt-store",
])
def test_authenticated_audit_handoff_gates_commission(evidence, monkeypatch, failure):
    sessions = []
    submitted = []
    original_job_call = ReadyThenStartBus.call

    async def observed_job_call(bus, message):
        if message.member == "StartUnit":
            submitted.append(message.body[0])
        return await original_job_call(bus, message)

    monkeypatch.setattr(ReadyThenStartBus, "call", observed_job_call)
    controller = ReadyThenStartBus()

    class HelperBus:
        def __init__(self):
            self.audit = AuditBus(fault="wrong-user" if failure == "capture" else None)
            self.commission = CommissionBus()
            self.reader = self.audit
            self.job = ReadyThenStartBus()

        def add_message_handler(self, handler):
            self.job.add_message_handler(handler)

        def remove_message_handler(self, handler):
            self.job.remove_message_handler(handler)

        async def call(self, message):
            if message.member == "LoadUnit":  # fake: same lookup as GetUnit
                message.member = "GetUnit"
            if message.member == "GetUnit":
                self.reader = (self.commission if message.body == ["azazel-commissiond.service"]
                               else self.audit)
            if message.member in {"GetNameOwner", "GetAll"}:
                return await self.reader.call(message)
            return await self.job.call(message)

    def factory():
        bus = controller if len(sessions) < 2 else HelperBus()
        bus.disconnect = lambda: None
        session = FakeSystemdBusSession(bus=bus)
        sessions.append(session)
        return session

    monkeypatch.setattr(manager_module, "current_bootstrap_controller_identity", lambda: IDENTITY)
    real = _PrototypeBootstrapManager(job_timeout_seconds=5.0, session_factory=factory)
    # Handcrafted controller/grant context below stands in for retained
    # publication admission in this synthetic composition.
    real._publication_check = lambda: None
    h = supervisor_tests.Harness(evidence)
    client = real._bootstrap_audit_client()
    h.supervisor.record = client
    h.supervisor.audit_head_reader = client

    def bind(transaction, _approval):
        real._controller_binding = (IDENTITY, OWNER, PROFILE_DIGEST)
        real._controller_grant = transaction

    h.manager.open_pair_after_publish = bind
    h.manager.confirm_controller_ready = real.confirm_controller_ready
    recorded_start = h.manager.start_and_wait

    def start(unit, *, transaction, check_start):
        if unit is UnitKey.COMMISSIOND:
            assert real._audit_binding_source()
            assert h.events and h.events[0]["event_type"] == "bootstrap.grant_intent"
            if failure == "receipt-store":
                changed_digest = "sha256:" + "f" * 64
                assert transaction.audit_receipt_digest != changed_digest
                h.grant_store.journal = replace(transaction, audit_receipt_digest=changed_digest)
        real.start_and_wait(unit, transaction=transaction, check_start=check_start)
        recorded_start(unit, transaction=transaction, check_start=check_start)

    h.manager.start_and_wait = start

    h.manager.is_ready = real.is_ready
    _install_peer_evidence(
        monkeypatch, credentials=(PID + (failure == "peer"), UID, PRIMARY_GID),
    )
    install_commission_peer(
        monkeypatch, credentials=(4321 + (failure == "commission-peer"), *ACCOUNTS[:2]),
    )
    connections = []
    head = [1, "a" * 64]

    class LedgerSocket(DeadlineSocket):
        def sendall(self, data):
            super().sendall(data)
            request = json.loads(data[HEADER.size:])
            if request["verb"] == "audit.bootstrap.append":
                receipt = h.record({"event_type": request["arguments"]["event_type"],
                                    **request["event"]})
                head[:] = receipt.sequence, receipt.event_hash
                result = {"sequence": head[0], "event_hash": head[1]}
            else:
                assert request == {"verb": "audit.bootstrap.observe", "arguments": {}}
                result = {"verified": True, "head_sequence": head[0], "head_hash": head[1]}
            raw = json.dumps({"ok": True, "result": result}).encode()
            self.response = bytearray(HEADER.pack(len(raw)) + raw)

    def connect(_deadline, *, path):
        assert path == "/var/lib/azazel/run/audit/audit.sock"
        connection = LedgerSocket(FakeClock())
        connections.append(connection)
        return connection

    monkeypatch.setattr(BootstrapAuditClient, "_connect", staticmethod(connect))
    commission_connections = []

    def connect_commission(_deadline, *, path):
        assert path == "/var/lib/azazel/run/commission/commission.sock"
        result = {"snapshot": "sha256:" + "b" * 64, "interfaces": []}
        if failure == "inventory":
            result["interfaces"] = None
        raw = json.dumps({"ok": True, "result": result}).encode()
        connection = DeadlineSocket(FakeClock(), HEADER.pack(len(raw)) + raw)
        commission_connections.append(connection)
        return connection

    monkeypatch.setattr(BootstrapCommissionClient, "_connect", staticmethod(connect_commission))
    if failure is None:
        h.supervisor.run()
        assert ("start_and_wait", UnitKey.COMMISSIOND) in h.manager.calls
        assert len(h.events) > 1
        assert submitted == ["azazel-auditd.service", "azazel-commissiond.service"]
        assert ("store.advance", "commissiond_ready") in h.timeline
    else:
        with pytest.raises((AuditUnavailable, UnitOperationFailed, ApprovalRefused)):
            h.supervisor.run()
        if failure in {"capture", "peer"}:
            assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
            assert not h.events
            assert not any(event[0] == "sendall" for c in connections for event in c.events)
        else:
            assert ("store.advance", "commissiond_ready") not in h.timeline
            if failure == "receipt-store":
                assert submitted == ["azazel-auditd.service"]
            if failure == "commission-peer":
                assert not any(e[0] == "sendall" for c in commission_connections for e in c.events)
    assert all(s.closed and s._loop.is_closed() for s in sessions)
    assert all(c.closed for c in connections)
    assert all(c.closed for c in commission_connections)
    assert all(h.manager.masked.values()) and all(h.manager.inactive.values())
