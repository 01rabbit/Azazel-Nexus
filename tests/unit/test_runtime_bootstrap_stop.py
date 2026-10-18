import asyncio
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_stop import BootstrapStopJobs
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    MANAGER_PATH,
    PROPERTIES_INTERFACE,
    _unit_object_path,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed


@dataclass
class Message:
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

    def __init__(self, *, result="done", state="inactive", owner=":1.40"):
        self.result = result
        self.state = state
        self.owner = owner
        self.calls = []
        self.handlers = []
        self.events = []
        self.stop_reply_hook = None
        self.owner_reads = 0
        self.change_owner_after_first_read = False
        self.job = (73, "/org/freedesktop/systemd1/job/73")
        self.get_unit_reply = None
        self.property_reply = None
        self.fail_unsubscribe = False

    def add_message_handler(self, handler):
        self.events.append("handler-add")
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.events.append("handler-remove")
        self.handlers.remove(handler)

    def signal(
        self,
        *,
        sender=None,
        path=MANAGER_PATH,
        interface=MANAGER_INTERFACE,
        member="JobRemoved",
        signature="uoss",
        body=None,
    ):
        message = Message(
            self.SIGNAL,
            signature,
            [self.job[0], self.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
            if body is None
            else body,
            sender=self.owner if sender is None else sender,
            path=path,
            interface=interface,
            member=member,
        )
        for handler in tuple(self.handlers):
            handler(message)

    async def call(self, message):
        reply = await self._respond(message)
        if reply.sender is None:
            reply.sender = message.destination
        return reply

    async def _respond(self, message):
        self.calls.append(message)
        self.events.append(message.member)
        assert message.member not in {
            "StartUnit",
            "UnmaskUnitFiles",
            "EnableUnitFiles",
            "CancelJob",
        }
        if message.member in {"GetNameOwner", "AddMatch", "RemoveMatch"}:
            assert message.destination == "org.freedesktop.DBus"
        else:
            assert message.destination == self.owner
        if message.member == "Unsubscribe" and self.fail_unsubscribe:
            return Message(3, "", [])
        if message.member == "GetNameOwner":
            self.owner_reads += 1
            owner = self.owner
            if self.change_owner_after_first_read and self.owner_reads > 1:
                owner = ":1.41"
            return Message(self.METHOD_RETURN, "s", [owner])
        if message.member in {"AddMatch", "Subscribe", "Unsubscribe", "RemoveMatch"}:
            return Message(self.METHOD_RETURN, "", [])
        if message.member == "StopUnit":
            if self.stop_reply_hook is not None:
                self.stop_reply_hook()
            return Message(self.METHOD_RETURN, "o", [self.job[1]])
        if message.member == "GetUnit":
            return self.get_unit_reply or Message(
                self.METHOD_RETURN, "o", [_unit_object_path(message.body[0])]
            )
        if message.member == "Get" and message.interface == PROPERTIES_INTERFACE:
            return self.property_reply or Message(
                self.METHOD_RETURN,
                "v",
                [SimpleNamespace(signature="s", value=self.state)],
            )
        raise AssertionError(f"unexpected D-Bus method {message.member}")


def make_client(bus, timeout=5.0, expected_owner=None):
    return BootstrapStopJobs(
        bus=bus,
        message_factory=lambda **kwargs: SimpleNamespace(**kwargs),
        message_type=SimpleNamespace(
            METHOD_RETURN=FakeBus.METHOD_RETURN, SIGNAL=FakeBus.SIGNAL
        ),
        timeout_seconds=timeout,
        expected_owner=expected_owner,
    )


def test_enclosing_owner_mismatch_refuses_before_subscription_or_stop():
    bus = FakeBus()
    with pytest.raises(UnitOperationFailed):
        asyncio.run(make_client(bus, expected_owner=":1.999").stop_and_wait(UnitKey.AUDITD))
    assert [message.member for message in bus.calls] == ["GetNameOwner"]
    assert not bus.handlers


def test_enclosing_owner_match_can_complete_stop():
    bus = FakeBus()
    bus.stop_reply_hook = lambda: bus.signal()
    asyncio.run(make_client(bus, expected_owner=bus.owner).stop_and_wait(UnitKey.AUDITD))
    assert any(message.member == "StopUnit" for message in bus.calls)
    assert not bus.handlers


@pytest.mark.parametrize("member", ["GetNameOwner", "Subscribe", "StopUnit", "Get"])
@pytest.mark.parametrize("sender", [None, ":1.999"])
def test_stop_refuses_reply_from_missing_or_wrong_sender(member, sender):
    async def scenario():
        bus = FakeBus()
        bus.stop_reply_hook = lambda: bus.signal()
        call = bus.call

        async def forged(message):
            reply = await call(message)
            if message.member == member:
                reply.sender = sender
            return reply

        bus.call = forged
        client = make_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client.stop_and_wait(UnitKey.AUDITD)
        assert any(message.member == member for message in bus.calls)
        before = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.stop_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == before

    asyncio.run(scenario())


def test_stops_only_exact_unit_keys_and_installs_job_listener_before_stop():
    async def scenario():
        for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
            bus = FakeBus()
            # The signal arrives before StopUnit returns its job object path.
            bus.stop_reply_hook = lambda: bus.signal(
                body=[73, "/org/freedesktop/systemd1/job/73", UNIT_NAMES[unit], "done"]
            )
            await make_client(bus).stop_and_wait(unit)
            members = [call.member for call in bus.calls]
            assert members.index("AddMatch") < members.index("StopUnit")
            assert members.index("Subscribe") < members.index("StopUnit")
            assert bus.events.index("handler-add") < bus.events.index("StopUnit")
            stop = next(call for call in bus.calls if call.member == "StopUnit")
            assert stop.destination == bus.owner
            assert stop.path == MANAGER_PATH
            assert stop.interface == MANAGER_INTERFACE
            assert stop.signature == "ss"
            assert stop.body == [UNIT_NAMES[unit], "fail"]
            assert all(
                call.destination == bus.owner
                for call in bus.calls
                if call.member
                in {"StopUnit", "GetUnit", "Get", "Subscribe", "Unsubscribe"}
            )
            assert bus.events[-1] == "handler-remove"
            assert not bus.handlers
            assert "Unsubscribe" in members and "RemoveMatch" in members

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "bad",
    [
        "azazel-auditd.service",
        "sshd.service",
        UnitKey.WATCHDOG,
        None,
        4,
    ],
)
def test_refuses_non_pair_or_non_unitkey_without_bus_calls(bad):
    async def scenario():
        bus = FakeBus()
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).stop_and_wait(bad)
        assert bus.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "signal_kind",
    [
        "wrong-owner",
        "wrong-path",
        "wrong-interface",
        "wrong-member",
        "wrong-signature",
        "wrong-shape",
        "wrong-unit",
        "wrong-job-id",
        "wrong-job-path",
    ],
)
def test_ignores_unmatched_job_removed_then_accepts_the_exact_completion(signal_kind):
    async def scenario():
        bus = FakeBus()

        def send():
            args = {}
            if signal_kind == "wrong-owner":
                args["sender"] = ":1.999"
            elif signal_kind == "wrong-path":
                args["path"] = "/wrong"
            elif signal_kind == "wrong-interface":
                args["interface"] = "wrong.Interface"
            elif signal_kind == "wrong-member":
                args["member"] = "UnitRemoved"
            elif signal_kind == "wrong-signature":
                args["signature"] = "ssss"
            elif signal_kind == "wrong-shape":
                args["body"] = [73, "only-two"]
            elif signal_kind == "wrong-unit":
                args["body"] = [73, bus.job[1], "other.service", "done"]
            elif signal_kind == "wrong-job-id":
                args["body"] = [74, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
            elif signal_kind == "wrong-job-path":
                args["body"] = [
                    73,
                    "/org/freedesktop/systemd1/job/74",
                    UNIT_NAMES[UnitKey.AUDITD],
                    "done",
                ]
            bus.signal(**args)
            bus.signal(body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"])

        bus.stop_reply_hook = send
        await make_client(bus).stop_and_wait(UnitKey.AUDITD)

    asyncio.run(scenario())


@pytest.mark.parametrize("result", ["failed", "canceled", "timeout", "", "DONE"])
def test_matching_job_must_report_done(result):
    async def scenario():
        bus = FakeBus()
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], result]
        )
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).stop_and_wait(UnitKey.AUDITD)
        assert bus.events[-1] == "handler-remove"

    asyncio.run(scenario())


def test_pending_native_job_deadline_refuses_without_cancel_or_completion():
    async def scenario():
        bus = FakeBus()
        client = make_client(bus, timeout=0.01)

        # StopUnit returns a native job path, but this synthetic bus never
        # emits JobRemoved. The local observer deadline is not job completion
        # and must not be interpreted as permission to cancel the job.
        with pytest.raises(UnitOperationFailed, match="completion unconfirmed"):
            await client.stop_and_wait(UnitKey.AUDITD)

        members = [message.member for message in bus.calls]
        assert "StopUnit" in members
        assert "CancelJob" not in members
        assert "GetUnit" not in members
        assert bus.events[-1] == "handler-remove"
        assert "Unsubscribe" in members
        assert "RemoveMatch" in members
        assert not bus.handlers

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "reply",
    [
        Message(FakeBus.METHOD_RETURN, "s", ["not a job"]),
        Message(FakeBus.METHOD_RETURN, "o", []),
        Message(FakeBus.METHOD_RETURN, "o", ["/org/freedesktop/systemd1/job/0"]),
        Message(
            FakeBus.METHOD_RETURN, "o", ["/org/freedesktop/systemd1/job/4294967296"]
        ),
        Message(3, "o", ["/org/freedesktop/systemd1/job/73"]),
    ],
)
def test_invalid_stop_reply_refuses_and_cleans_up(reply):
    async def scenario():
        bus = FakeBus()

        async def call(message):
            if message.member == "StopUnit":
                bus.calls.append(message)
                bus.events.append(message.member)
                return reply
            return await original_call(message)

        original_call = bus.call
        bus.call = call
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).stop_and_wait(UnitKey.AUDITD)
        assert bus.events[-1] == "handler-remove"
        assert not bus.handlers

    asyncio.run(scenario())


@pytest.mark.parametrize("state", ["active", "activating", "failed", "inactive-ish"])
def test_requires_exact_inactive_state_after_job_completion(state):
    async def scenario():
        bus = FakeBus(state=state)
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
        )
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).stop_and_wait(UnitKey.AUDITD)

    asyncio.run(scenario())


def test_refuses_systemd_owner_change_and_still_cleans_up():
    async def scenario():
        bus = FakeBus()
        bus.change_owner_after_first_read = True
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
        )
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).stop_and_wait(UnitKey.AUDITD)
        assert bus.events[-1] == "handler-remove"

    asyncio.run(scenario())


def test_queue_overflow_refuses_even_when_matching_completion_is_queued():
    async def scenario():
        bus = FakeBus()

        def overflow():
            for job_id in range(1, 66):
                bus.signal(
                    body=[
                        job_id,
                        f"/org/freedesktop/systemd1/job/{job_id}",
                        UNIT_NAMES[UnitKey.AUDITD],
                        "done",
                    ]
                )

        bus.stop_reply_hook = overflow
        with pytest.raises(UnitOperationFailed, match="unconfirmed"):
            await make_client(bus).stop_and_wait(UnitKey.AUDITD)
        assert bus.events[-1] == "handler-remove"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "member", ["StartUnit", "UnmaskUnitFiles", "EnableUnitFiles", "CancelJob"]
)
def test_no_start_unmask_enable_or_cancel_method_is_called(member):
    async def scenario():
        bus = FakeBus()
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
        )
        await make_client(bus).stop_and_wait(UnitKey.AUDITD)
        assert member not in [call.member for call in bus.calls]

    asyncio.run(scenario())


def test_failed_transaction_poisons_client_and_retry_makes_no_bus_call():
    async def scenario():
        bus = FakeBus()
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "failed"]
        )
        client = make_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client.stop_and_wait(UnitKey.AUDITD)
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="discarded"):
            await client.stop_and_wait(UnitKey.COMMISSIOND)
        assert len(bus.calls) == call_count
        assert not bus.handlers

    asyncio.run(scenario())


def test_cancellation_poisons_client_but_still_cleans_up_observer():
    async def scenario():
        bus = FakeBus()
        entered_stop = asyncio.Event()

        async def blocked_call(message):
            if message.member == "StopUnit":
                bus.calls.append(message)
                bus.events.append(message.member)
                entered_stop.set()
                await asyncio.Future()
            return await original_call(message)

        original_call = bus.call
        bus.call = blocked_call
        client = make_client(bus)
        task = asyncio.create_task(client.stop_and_wait(UnitKey.AUDITD))
        await entered_stop.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert bus.events[-1] == "handler-remove"
        assert not bus.handlers
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="discarded"):
            await client.stop_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == call_count

    asyncio.run(scenario())


def test_observer_cleanup_failure_poisons_client_and_retry_is_refused():
    async def scenario():
        bus = FakeBus()
        bus.fail_unsubscribe = True
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
        )
        client = make_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client.stop_and_wait(UnitKey.AUDITD)
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="discarded"):
            await client.stop_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == call_count
        assert bus.events[-1] == "handler-remove"
        assert not bus.handlers

    asyncio.run(scenario())


def test_handler_removal_failure_is_redacted_poisons_client_and_resets_busy():
    async def scenario():
        bus = FakeBus()
        bus.stop_reply_hook = lambda: bus.signal(
            body=[73, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
        )

        def fail_remove(_handler):
            bus.events.append("handler-remove-failed")
            raise RuntimeError("private bus cleanup detail")

        bus.remove_message_handler = fail_remove
        client = make_client(bus)
        with pytest.raises(UnitOperationFailed) as exc_info:
            await client.stop_and_wait(UnitKey.AUDITD)
        assert "private bus cleanup detail" not in str(exc_info.value)
        assert client._busy is False
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="discarded"):
            await client.stop_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == call_count

    asyncio.run(scenario())


def test_late_cancel_resistant_subscribe_reply_cannot_start_stop_or_later_calls():
    async def scenario():
        bus = FakeBus()
        entered_subscribe = asyncio.Event()
        release_late_reply = asyncio.Event()
        late_reply_returned = asyncio.Event()
        original_call = bus.call

        async def cancellation_resistant_call(message):
            if message.member == "Subscribe":
                bus.calls.append(message)
                bus.events.append(message.member)
                entered_subscribe.set()
                try:
                    await release_late_reply.wait()
                except asyncio.CancelledError:
                    # Model a transport coroutine that finishes despite cancel.
                    await release_late_reply.wait()
                late_reply_returned.set()
                return Message(FakeBus.METHOD_RETURN, "", [])
            return await original_call(message)

        bus.call = cancellation_resistant_call
        client = make_client(bus, timeout=0.02)
        with pytest.raises(UnitOperationFailed, match="unconfirmed"):
            await client.stop_and_wait(UnitKey.AUDITD)
        await entered_subscribe.wait()
        assert "StopUnit" not in [call.member for call in bus.calls]
        assert bus.events[-1] == "handler-remove"
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="discarded"):
            await client.stop_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == call_count

        # Release the detached operation so asyncio.run can shut down cleanly.
        release_late_reply.set()
        await late_reply_returned.wait()
        for _ in range(3):
            await asyncio.sleep(0)
        assert "StopUnit" not in [call.member for call in bus.calls]
        assert len(bus.calls) == call_count
        assert bus.events[-1] == "handler-remove"

    asyncio.run(scenario())


def test_late_cancel_resistant_cleanup_cannot_issue_remove_match():
    async def scenario():
        bus = FakeBus()
        bus.stop_reply_hook = lambda: bus.signal()
        release = asyncio.Event()
        returned = asyncio.Event()
        call = bus.call

        async def resistant(message):
            if message.member != "Unsubscribe":
                return await call(message)
            bus.calls.append(message)
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()
            returned.set()
            return Message(FakeBus.METHOD_RETURN, "", [])

        bus.call = resistant
        client = make_client(bus, timeout=0.02)
        try:
            with pytest.raises(UnitOperationFailed, match="cleanup failed"):
                await client.stop_and_wait(UnitKey.AUDITD)
            count = len(bus.calls)
            assert not bus.handlers
            release.set()
            await asyncio.wait_for(returned.wait(), 0.5)
            await asyncio.sleep(0)
            assert len(bus.calls) == count
            assert "RemoveMatch" not in [message.member for message in bus.calls]
            with pytest.raises(UnitOperationFailed, match="discarded"):
                await client.stop_and_wait(UnitKey.AUDITD)
        finally:
            release.set()

    asyncio.run(scenario())
