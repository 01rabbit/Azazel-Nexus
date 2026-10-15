import asyncio
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_job_drain import BootstrapJobDrain
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.systemd_bus import _unit_object_path
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed


@dataclass
class Reply:
    message_type: int
    signature: str
    body: list
    sender: str | None = None


class FakeBus:
    METHOD_RETURN = 1
    OWNER = ":1.77"

    def __init__(
        self, snapshots=None, *, owner_change=False, bad_reply=None, hang_member=None
    ):
        self.snapshots = list(snapshots or [[], []])
        self.owner_change = owner_change
        self.bad_reply = bad_reply
        self.hang_member = hang_member
        self.calls = []
        self.owner_reads = 0
        self.disconnected = False

    async def call(self, message):
        self.calls.append(message)
        assert message.path in {
            "/org/freedesktop/DBus", "/org/freedesktop/systemd1",
        }
        if message.member != "GetNameOwner":
            assert message.destination == self.OWNER
            assert message.path == "/org/freedesktop/systemd1"
            assert message.interface == "org.freedesktop.systemd1.Manager"
        if message.member == self.hang_member:
            await asyncio.Future()
        if message.member == "GetNameOwner":
            self.owner_reads += 1
            value = ":1.78" if self.owner_change and self.owner_reads > 1 else self.OWNER
            reply = Reply(self.METHOD_RETURN, "s", [value], "org.freedesktop.DBus")
        elif message.member == "ListJobs":
            rows = self.snapshots.pop(0) if self.snapshots else []
            reply = Reply(self.METHOD_RETURN, "a(usssoo)", [rows], self.OWNER)
        elif message.member == "CancelJob":
            reply = Reply(self.METHOD_RETURN, "", [], self.OWNER)
        else:
            raise AssertionError(f"unexpected D-Bus call: {message.member}")
        if message.member == self.bad_reply:
            reply.signature = "wrong"
        return reply

    def disconnect(self):
        self.disconnected = True


def row(job, unit, *, kind="start", state="waiting", path=None, unit_path=None):
    return [
        job,
        unit,
        kind,
        state,
        path or f"/org/freedesktop/systemd1/job/{job}",
        unit_path or _unit_object_path(unit),
    ]


def make_drain(bus, checks=None, timeout=0.1):
    checks = checks if checks is not None else []

    async def check_closed():
        checks.append("check")
        return None

    return BootstrapJobDrain(
        bus=bus,
        message_factory=lambda **values: SimpleNamespace(**values),
        message_type=SimpleNamespace(METHOD_RETURN=FakeBus.METHOD_RETURN),
        timeout_seconds=timeout,
        check_closed=check_closed,
    ), checks


def run(awaitable):
    return asyncio.run(awaitable)


def test_drain_cancels_only_exact_pair_jobs_and_requires_two_empty_snapshots():
    audit = UNIT_NAMES[UnitKey.AUDITD]
    commission = UNIT_NAMES[UnitKey.COMMISSIOND]
    unrelated = "ssh.service"
    bus = FakeBus(
        [
            [
                row(1, audit, state="running"),
                row(2, commission, kind="stop", state="waiting"),
                row(3, unrelated),
            ],
            [],
            [],
        ]
    )
    drain, checks = make_drain(bus)

    assert run(drain.drain()) is None
    assert [call.member for call in bus.calls].count("ListJobs") == 3
    cancellations = [call for call in bus.calls if call.member == "CancelJob"]
    assert [call.body for call in cancellations] == [[1], [2]]
    assert all(call.signature == "u" for call in cancellations)
    assert len(checks) >= 2


@pytest.mark.parametrize(
    "bad_row",
    [
        lambda u, n: row(True, u),
        lambda u, n: row(0, u),
        lambda u, n: row(n, u, path="/wrong"),
        lambda u, n: row(n, u, unit_path="/wrong"),
        lambda u, n: row(n, u, kind=""),
        lambda u, n: row(n, u, kind="bad kind"),
        lambda u, n: row(n, u, state="done"),
        lambda u, n: row(n, u + "/evil"),
    ],
)
def test_malformed_rows_block_all_cancellation_including_pair_rows(bad_row):
    audit = UNIT_NAMES[UnitKey.AUDITD]
    bus = FakeBus([[row(1, audit), bad_row("ssh.service", 2)]])
    drain, _ = make_drain(bus)

    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert not any(call.member == "CancelJob" for call in bus.calls)


def test_duplicate_job_ids_and_oversized_lists_refuse_before_cancel():
    audit = UNIT_NAMES[UnitKey.AUDITD]
    for rows in (
        [row(1, audit), row(1, "ssh.service")],
        [row(i + 1, "ssh.service") for i in range(4097)],
    ):
        bus = FakeBus([rows])
        drain, _ = make_drain(bus)
        with pytest.raises(UnitOperationFailed):
            run(drain.drain())
        assert not any(call.member == "CancelJob" for call in bus.calls)


@pytest.mark.parametrize("bad_reply", ["ListJobs"])
def test_wrong_reply_refuses(bad_reply):
    bus = FakeBus([[]], bad_reply=bad_reply)
    drain, _ = make_drain(bus)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())


def test_cancel_reply_must_be_exact_empty_method_return():
    bus = FakeBus(
        [[row(1, UNIT_NAMES[UnitKey.AUDITD])]], bad_reply="CancelJob"
    )
    drain, _ = make_drain(bus)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())


@pytest.mark.parametrize("member", ["ListJobs", "CancelJob"])
def test_wrong_sender_cannot_confirm_observation_or_cancellation(member):
    class WrongSender(FakeBus):
        async def call(self, message):
            reply = await super().call(message)
            if message.member == member:
                reply.sender = ":1.999"
            return reply

    bus = WrongSender([[row(1, UNIT_NAMES[UnitKey.AUDITD])]])
    drain, _ = make_drain(bus)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    if member == "ListJobs":
        assert not any(call.member == "CancelJob" for call in bus.calls)


def test_guard_loss_after_first_cancel_prevents_second_cancel():
    bus = FakeBus([[
        row(1, UNIT_NAMES[UnitKey.AUDITD]),
        row(2, UNIT_NAMES[UnitKey.COMMISSIOND]),
    ]])

    async def guard():
        if any(call.member == "CancelJob" for call in bus.calls):
            raise RuntimeError("fence lost")

    drain = BootstrapJobDrain(
        bus=bus, message_factory=lambda **values: SimpleNamespace(**values),
        message_type=SimpleNamespace(METHOD_RETURN=FakeBus.METHOD_RETURN),
        timeout_seconds=0.1, check_closed=guard,
    )
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert [call.body for call in bus.calls if call.member == "CancelJob"] == [[1]]


def test_job_disappearing_before_cancel_is_uncertainty_not_success():
    class GoneJob(FakeBus):
        async def call(self, message):
            reply = await super().call(message)
            if message.member == "CancelJob":
                reply.message_type = 3  # D-Bus ERROR, including NoSuchJob.
            return reply

    bus = GoneJob([[row(1, UNIT_NAMES[UnitKey.AUDITD])]])
    drain, _ = make_drain(bus)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    calls = len(bus.calls)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert len(bus.calls) == calls


def test_timeout_is_refusal_not_success():
    bus = FakeBus([[]], hang_member="GetNameOwner")
    drain, _ = make_drain(bus, timeout=0.01)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())


def test_closed_guard_failure_prevents_bus_calls_and_cancellation():
    bus = FakeBus([[row(1, UNIT_NAMES[UnitKey.AUDITD])]])
    checks = []

    async def open_guard():
        checks.append("check")
        return False  # Exact None is required.

    drain = BootstrapJobDrain(
        bus=bus,
        message_factory=lambda **values: SimpleNamespace(**values),
        message_type=SimpleNamespace(METHOD_RETURN=FakeBus.METHOD_RETURN),
        timeout_seconds=0.1,
        check_closed=open_guard,
    )
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert checks
    assert bus.calls == []


def test_guard_change_after_snapshot_prevents_cancellation():
    bus = FakeBus([[row(1, UNIT_NAMES[UnitKey.AUDITD])]])
    checks = []

    async def closes_then_opens():
        checks.append(None)
        return None if len(checks) < 4 else False

    drain = BootstrapJobDrain(
        bus=bus,
        message_factory=lambda **values: SimpleNamespace(**values),
        message_type=SimpleNamespace(METHOD_RETURN=FakeBus.METHOD_RETURN),
        timeout_seconds=0.1,
        check_closed=closes_then_opens,
    )
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert not any(call.member == "CancelJob" for call in bus.calls)


def test_systemd_owner_change_prevents_cancellation():
    bus = FakeBus([[row(1, UNIT_NAMES[UnitKey.AUDITD])]], owner_change=True)
    drain, _ = make_drain(bus)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert not any(call.member == "CancelJob" for call in bus.calls)


def test_persistent_or_running_pair_jobs_are_not_mistaken_for_stopped():
    audit = UNIT_NAMES[UnitKey.AUDITD]
    bus = FakeBus([[row(5, audit, state="running")]] * 8)
    drain, _ = make_drain(bus, timeout=0.5)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert [call.member for call in bus.calls].count("ListJobs") == 8
    assert [call.body for call in bus.calls if call.member == "CancelJob"] == [[5]] * 8


def test_drain_is_single_use():
    bus = FakeBus([[], []])
    drain, _ = make_drain(bus)
    run(drain.drain())
    count = len(bus.calls)
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert len(bus.calls) == count


class OwnedSession:
    def __init__(self, bus):
        self._loop = asyncio.new_event_loop()
        self._bus = bus
        self._message_factory = lambda **values: SimpleNamespace(**values)
        self._message_type = SimpleNamespace(METHOD_RETURN=FakeBus.METHOD_RETURN)
        self.closed = False

    def close(self):
        self._bus.disconnect()
        self._loop.close()
        self.closed = True


@pytest.mark.parametrize("guard_fails", [False, True])
def test_sync_manager_drain_owns_loop_disconnects_and_limits_scope(guard_fails):
    audit = UNIT_NAMES[UnitKey.AUDITD]
    unrelated = "ssh.service"
    bus = FakeBus([[row(10, audit), row(11, unrelated)], [], []])
    session = OwnedSession(bus)
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.2, session_factory=lambda: session
    )

    async def guard():
        return False if guard_fails else None

    if guard_fails:
        with pytest.raises(UnitOperationFailed):
            manager.drain_pending_jobs(check_closed=guard)
        assert not any(call.member == "CancelJob" for call in bus.calls)
    else:
        assert manager.drain_pending_jobs(check_closed=guard) is None
        assert [call.body for call in bus.calls if call.member == "CancelJob"] == [[10]]
        assert [call.member for call in bus.calls].count("ListJobs") == 3
    assert session.closed and bus.disconnected
    assert session._loop.is_closed()
