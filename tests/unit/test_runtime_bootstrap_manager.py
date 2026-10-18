import asyncio
from contextlib import nullcontext
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction, PAIR
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap import BootstrapSupervisor
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    MANAGER_PATH,
    PROPERTIES_INTERFACE,
    _unit_object_path,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from azazel_nexus.operator_trust import ApprovalRefused


class FakeDeadlineGuard:
    def __init__(self):
        self.deadlines = []
        self.releases = 0

    def __call__(self, deadline):
        self.deadlines.append(deadline)

    def release_after_stop(self):
        self.releases += 1


@dataclass
class FakeMessage:
    message_type: int
    signature: str
    body: list
    sender: str | None = None
    path: str | None = None
    interface: str | None = None
    member: str | None = None


class FakeBus:
    METHOD_RETURN = 1
    SIGNAL = 4
    OWNER = ":1.51"

    def __init__(
        self, *, result="done", active_state="inactive", hang_member=None, trace=None
    ):
        self.result = result
        self.active_state = active_state
        self.hang_member = hang_member
        self.trace = trace
        self.calls = []
        self.handlers = []
        self.disconnected = False
        self.job_id = 81
        self.job_path = f"/org/freedesktop/systemd1/job/{self.job_id}"

    def add_message_handler(self, handler):
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.handlers.remove(handler)

    def disconnect(self):
        self.disconnected = True
        if hasattr(self, "disconnect_error"):
            raise self.disconnect_error

    def _signal_job_removed(self, unit_name):
        signal = FakeMessage(
            self.SIGNAL,
            "uoss",
            [self.job_id, self.job_path, unit_name, self.result],
            sender=self.OWNER,
            path=MANAGER_PATH,
            interface=MANAGER_INTERFACE,
            member="JobRemoved",
        )
        for handler in tuple(self.handlers):
            handler(signal)

    async def call(self, message):
        reply = await self._respond(message)
        if reply.sender is None:
            reply.sender = message.destination
        return reply

    async def _respond(self, message):
        self.calls.append(message)
        if self.trace is not None:
            self.trace.append(
                ("dbus", message.member, message.body[0] if message.body else None)
            )
        if message.member == self.hang_member:
            await asyncio.Future()
        if message.member == "GetNameOwner":
            return FakeMessage(self.METHOD_RETURN, "s", [self.OWNER])
        if message.member in {"AddMatch", "Subscribe", "Unsubscribe", "RemoveMatch"}:
            return FakeMessage(self.METHOD_RETURN, "", [])
        if message.member == "StopUnit":
            self._signal_job_removed(message.body[0])
            return FakeMessage(self.METHOD_RETURN, "o", [self.job_path])
        if message.member == "GetUnit":
            return FakeMessage(
                self.METHOD_RETURN, "o", [_unit_object_path(message.body[0])]
            )
        if message.member == "Get" and message.interface == PROPERTIES_INTERFACE:
            return FakeMessage(
                self.METHOD_RETURN,
                "v",
                [SimpleNamespace(signature="s", value=self.active_state)],
            )
        raise AssertionError(f"unexpected fake bus call: {message.member}")


class FakeSystemdBusSession:
    """Session facade with a real owned idle asyncio loop and fake transport."""

    def __init__(self, *, bus=None, trace=None):
        self._loop = asyncio.new_event_loop()
        self._bus = bus or FakeBus()
        self._message_factory = lambda **values: SimpleNamespace(**values)
        self._message_type = SimpleNamespace(
            METHOD_RETURN=FakeBus.METHOD_RETURN, SIGNAL=FakeBus.SIGNAL
        )
        self.calls = []
        self.trace = trace
        self.closed = False

    def __call__(self, method, unit):
        self.calls.append((method, unit))
        if self.trace is not None:
            self.trace.append(("manager", method, unit))
        if method == "MaskUnitFiles":
            return [[]]
        if method == "GetUnitFileState":
            return "masked"
        if method == "GetInactiveState":
            return True
        raise AssertionError(f"unexpected synchronous manager call: {method}")

    def close(self):
        try:
            self._bus.disconnect()
        finally:
            if not self._loop.is_closed():
                self._loop.close()
            self.closed = True
            if self.trace is not None:
                self.trace.append(("close",))


def test_stop_and_wait_uses_real_owned_loop_and_confirms_job_then_inactive():
    session = FakeSystemdBusSession()
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=lambda: session
    )

    manager.stop_and_wait(UnitKey.AUDITD)

    members = [message.member for message in session._bus.calls]
    stop = next(message for message in session._bus.calls if message.member == "StopUnit")
    assert stop.body == [UNIT_NAMES[UnitKey.AUDITD], "fail"]
    assert members.index("AddMatch") < members.index("StopUnit")
    assert members.index("Subscribe") < members.index("StopUnit")
    assert members.index("GetUnit") < members.index("Get")
    assert members.count("GetNameOwner") == 3
    assert session._bus.disconnected
    assert session.closed
    assert session._loop.is_closed()
    assert not session._bus.handlers


@pytest.mark.parametrize(
    ("result", "hang_member"),
    [("failed", None), ("done", "StopUnit")],
    ids=["job-error", "timeout"],
)
def test_stop_error_or_timeout_closes_owned_session(result, hang_member):
    session = FakeSystemdBusSession(
        bus=FakeBus(result=result, hang_member=hang_member)
    )
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.02, session_factory=lambda: session
    )

    with pytest.raises(UnitOperationFailed):
        manager.stop_and_wait(UnitKey.AUDITD)

    assert session._bus.disconnected
    assert session.closed
    assert session._loop.is_closed()
    assert not session._bus.handlers


def test_disconnect_cleanup_exception_preserves_primary_stop_failure():
    bus = FakeBus(result="failed")
    bus.disconnect_error = RuntimeError("private disconnect detail")
    session = FakeSystemdBusSession(bus=bus)
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=lambda: session
    )

    with pytest.raises(UnitOperationFailed, match="completion unconfirmed") as exc_info:
        manager.stop_and_wait(UnitKey.AUDITD)

    assert "private disconnect detail" not in str(exc_info.value)
    assert session.closed
    assert session._loop.is_closed()
    assert not bus.handlers


def test_disconnect_cleanup_exception_after_success_is_redacted_refusal():
    bus = FakeBus()
    bus.disconnect_error = RuntimeError("private disconnect detail")
    session = FakeSystemdBusSession(bus=bus)
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=lambda: session
    )

    with pytest.raises(UnitOperationFailed, match="session cleanup failed") as exc_info:
        manager.stop_and_wait(UnitKey.AUDITD)

    assert "private disconnect detail" not in str(exc_info.value)
    assert session.closed
    assert session._loop.is_closed()
    assert not bus.handlers


@pytest.mark.parametrize("timeout", [0, -0.1, float("inf"), float("nan"), True, "0.02"])
def test_nonfinite_nonpositive_or_non_numeric_job_timeout_is_rejected(timeout):
    with pytest.raises(ValueError, match="finite positive job timeout"):
        BootstrapNarrowingManager(job_timeout_seconds=timeout)


def test_each_mask_and_query_operation_uses_and_closes_a_fresh_session():
    sessions = []

    def factory():
        session = FakeSystemdBusSession()
        sessions.append(session)
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=factory
    )
    manager.mask(UnitKey.AUDITD)
    assert manager.is_masked(UnitKey.COMMISSIOND) is True
    assert manager.is_inactive(UnitKey.AUDITD) is True

    assert len(sessions) == 3
    assert all(session.closed and session._loop.is_closed() for session in sessions)
    assert [session.calls for session in sessions] == [
        [
            ("MaskUnitFiles", UNIT_NAMES[UnitKey.AUDITD]),
            ("GetUnitFileState", UNIT_NAMES[UnitKey.AUDITD]),
        ],
        [("GetUnitFileState", UNIT_NAMES[UnitKey.COMMISSIOND])],
        [("GetInactiveState", UNIT_NAMES[UnitKey.AUDITD])],
    ]


@pytest.mark.parametrize("method", ["mask", "is_masked", "is_inactive", "stop_and_wait"])
@pytest.mark.parametrize(
    "unit", [
        "auditd", "azazel-auditd.service", "sshd.service", UnitKey.WATCHDOG,
        None, 7,
    ],
)
def test_wrong_unit_types_or_keys_refuse_before_session_factory(method, unit):
    factory_calls = []

    def factory():
        factory_calls.append(True)
        raise AssertionError("invalid unit reached session factory")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=factory
    )
    with pytest.raises(UnitOperationFailed):
        getattr(manager, method)(unit)
    assert factory_calls == []


@pytest.mark.parametrize("method", ["unmask", "start_and_wait"])
def test_widening_operations_always_refuse_without_session_factory(method):
    factory_calls = []
    checkpoint_calls = []

    def factory():
        factory_calls.append(True)
        raise AssertionError("widening operation reached session factory")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=factory
    )
    with pytest.raises(UnitOperationFailed):
        kwargs = {
            "transaction": None,
            "check_start": lambda: checkpoint_calls.append(True),
        } if method == "start_and_wait" else {}
        getattr(manager, method)(UnitKey.AUDITD, **kwargs)
    assert factory_calls == []
    assert checkpoint_calls == []


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
def test_readiness_is_false_without_opening_a_session(unit):
    factory_calls = []

    def factory():
        factory_calls.append(True)
        raise AssertionError("readiness must not open a bus session")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=factory
    )
    assert manager.is_ready(unit) is False
    assert factory_calls == []


def test_supervisor_attempts_cleanup_but_cannot_claim_missing_deployment_fence():
    trace = []
    sessions = []

    def factory():
        bus = FakeBus(trace=trace)
        session = FakeSystemdBusSession(bus=bus, trace=trace)
        sessions.append(session)
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=factory
    )

    def refuse_refresh():
        trace.append(("refresh",))
        raise ApprovalRefused("refresh deliberately refused")

    supervisor = BootstrapSupervisor(
        manager=manager,
        refresh=refuse_refresh,
        admit_generation=lambda _context: None,
        deadline_guard=FakeDeadlineGuard(),
        record=lambda _event: None,
        controller_ready=lambda: None,
        transaction=lambda: nullcontext(lambda: None),
        grant_store_factory=lambda _guard: nullcontext(SimpleNamespace(
                load_optional=lambda **_kwargs: None,
            create=lambda _journal: None,
            advance=lambda *_args, **_kwargs: None,
        )),
        emergency_narrow=lambda: None,
        stopped=lambda: False,
        wait=lambda _seconds: None,
        poll_seconds=0.01,
        boottime_ns=lambda: 1,
    )

    from azazel_nexus_runtime.bootstrap import BootstrapContainmentFailed

    with pytest.raises(BootstrapContainmentFailed):
        supervisor.run()

    assert not any(event[0] == "refresh" for event in trace)
    stop_units = [
        event[2]
        for event in trace
        if event[:2] == ("dbus", "StopUnit")
    ]
    mask_units = [
        event[2]
        for event in trace
        if event[:2] == ("manager", "MaskUnitFiles")
    ]
    expected_mask_order = [UNIT_NAMES[UnitKey.AUDITD], UNIT_NAMES[UnitKey.COMMISSIOND]]
    assert stop_units == []
    assert mask_units == expected_mask_order * 4
    assert all(
        event[1] not in {"StartUnit", "UnmaskUnitFiles", "EnableUnitFiles"}
        for event in trace
        if event[0] in {"manager", "dbus"}
    )
    assert sessions and all(session.closed and session._loop.is_closed() for session in sessions)


@pytest.mark.parametrize("operation", ["close_starts", "open_pair", "withdraw_pair"])
def test_missing_deployment_fence_refuses_without_bus_operations(operation):
    def forbidden_factory():
        pytest.fail("missing fence must not connect to systemd")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=forbidden_factory,
    )
    transaction = GrantTransaction(
        boot_id="22222222-2222-4222-8222-222222222222",
        context_digest="sha256:" + "a" * 64,
        approval_digest="sha256:" + "b" * 64,
        generation=1,
        generation_digest="sha256:" + "c" * 64,
        grant_id="0123456789abcdef0123456789abcdef",
        unit_payload_digests=tuple((name, "d" * 64) for name in PAIR),
    )
    with pytest.raises(UnitOperationFailed, match="unavailable"):
        if operation == "open_pair":
            manager.open_pair(
                transaction, approval=None, check_publish=lambda: None
            )
        elif operation == "withdraw_pair":
            manager.withdraw_pair(transaction)
        else:
            getattr(manager, operation)()
