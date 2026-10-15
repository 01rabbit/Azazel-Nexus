"""Fake-bus contract tests for the private bootstrap start observer."""

import asyncio
from dataclasses import dataclass
import time
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_start import BootstrapStartJobs
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

    def __init__(self, *, state="inactive", owner=":1.40"):
        self.state = state
        self.owner = owner
        self.calls = []
        self.handlers = []
        self.events = []
        self.owner_reads = 0
        self.change_owner_after_first_read = False
        self.job = (73, "/org/freedesktop/systemd1/job/73")
        self.start_reply_hook = None
        self.preflight_state = None
        self.post_state = None
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
            "StopUnit",
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
        if message.member == "GetUnit":
            return Message(
                self.METHOD_RETURN, "o", [_unit_object_path(message.body[0])]
            )
        if message.member == "Get" and message.interface == PROPERTIES_INTERFACE:
            started = any(c.member == "StartUnit" for c in self.calls)
            if not started:
                state = (
                    self.state if self.preflight_state is None else self.preflight_state
                )
                self.preflight_state = None
            else:
                state = "active" if self.post_state is None else self.post_state
                self.post_state = None
            return Message(
                self.METHOD_RETURN,
                "v",
                [SimpleNamespace(signature="s", value=state)],
            )
        if message.member == "StartUnit":
            if self.start_reply_hook is not None:
                self.start_reply_hook()
            return Message(self.METHOD_RETURN, "o", [self.job[1]])
        raise AssertionError(f"unexpected D-Bus method {message.member}")


def make_client(bus, check_start=None, timeout=0.03, expected_owner=":1.40"):
    if check_start is None:

        def check_start():
            pass

    return BootstrapStartJobs(
        bus=bus,
        message_factory=lambda **kwargs: SimpleNamespace(**kwargs),
        message_type=SimpleNamespace(
            METHOD_RETURN=FakeBus.METHOD_RETURN, SIGNAL=FakeBus.SIGNAL
        ),
        timeout_seconds=timeout,
        check_start=check_start,
        expected_owner=expected_owner,
    )


def _complete(bus, unit=UnitKey.AUDITD, result="done"):
    bus.signal(body=[73, bus.job[1], UNIT_NAMES[unit], result])


@pytest.mark.parametrize("owner", [None, "", "org.freedesktop.systemd1", True, 1])
def test_start_requires_enclosing_unique_owner(owner):
    bus = FakeBus()
    with pytest.raises(ValueError):
        make_client(bus, expected_owner=owner)
    assert bus.calls == []


def test_new_transport_owner_does_not_inherit_previous_grant():
    async def scenario():
        bus = FakeBus(owner=":1.41")
        bus._azazel_systemd_owner = ":1.41"
        client = make_client(bus, expected_owner=":1.40")
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert [call.member for call in bus.calls] == ["GetNameOwner"]
        assert bus.handlers == []
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == count

    asyncio.run(scenario())


@pytest.mark.parametrize("member", ["GetNameOwner", "Get", "StartUnit"])
@pytest.mark.parametrize("sender", [None, ":1.999"])
def test_start_refuses_missing_or_wrong_reply_sender(member, sender):
    async def scenario():
        bus = FakeBus()
        bus.start_reply_hook = lambda: _complete(bus)
        call = bus.call

        async def forged(message):
            reply = await call(message)
            if message.member == member:
                reply.sender = sender
            return reply

        bus.call = forged
        client = make_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert any(message.member == member for message in bus.calls)
        if member != "StartUnit":
            assert not any(message.member == "StartUnit" for message in bus.calls)
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == count

    asyncio.run(scenario())


def test_start_sequence_for_exact_pair_and_three_start_checks():
    async def scenario():
        for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
            bus = FakeBus()
            checks = []

            def check():
                checks.append(len(bus.calls))
                bus.events.append(f"check-{len(checks)}")

            bus.start_reply_hook = lambda: _complete(bus, unit)
            await make_client(bus, check).start_and_wait(unit)
            members = [c.member for c in bus.calls]
            assert checks == sorted(checks) and len(checks) == 3
            assert bus.events.index("check-1") < bus.events.index("GetUnit")
            submission_check = bus.events.index("check-2")
            assert bus.events[submission_check + 1:submission_check + 3] == [
                "GetNameOwner", "StartUnit",
            ]
            assert bus.events.index("check-3") > bus.events.index(
                "Get", bus.events.index("StartUnit") + 1
            )
            assert members.index("GetUnit") < members.index("StartUnit")
            assert members.index("Subscribe") < members.index("StartUnit")
            assert bus.events.index("handler-add") < bus.events.index("StartUnit")
            start = next(c for c in bus.calls if c.member == "StartUnit")
            assert (start.signature, start.body) == ("ss", [UNIT_NAMES[unit], "fail"])
            assert start.destination == bus.owner and start.path == MANAGER_PATH
            assert members.index("StartUnit") < members.index(
                "GetUnit", members.index("StartUnit") + 1
            )
            assert bus.events[-1] == "handler-remove" and not bus.handlers

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "bad", ["azazel-auditd.service", "sshd.service", UnitKey.WATCHDOG, None, 4]
)
def test_refuses_wrong_unit_before_any_bus_call(bad):
    async def scenario():
        bus = FakeBus()
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).start_and_wait(bad)
        assert bus.calls == []

    asyncio.run(scenario())


def test_required_check_start_and_preflight_refusal_happen_before_start():
    async def scenario():
        bus = FakeBus()
        with pytest.raises((TypeError, ValueError)):
            BootstrapStartJobs(
                bus=bus,
                message_factory=lambda **kw: SimpleNamespace(**kw),
                message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4),
                timeout_seconds=1,
                expected_owner=":1.40",
            )
        bus.state = "active"
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).start_and_wait(UnitKey.AUDITD)
        assert "StartUnit" not in [c.member for c in bus.calls]

    asyncio.run(scenario())


@pytest.mark.parametrize("when", ["preflight", "before-start", "after-active"])
def test_check_start_false_or_exception_refuses_at_each_gate(when):
    async def scenario():
        bus = FakeBus()
        count = 0

        def check():
            nonlocal count
            count += 1
            if count == {"preflight": 1, "before-start": 2, "after-active": 3}[when]:
                if when == "after-active":
                    return False
                raise RuntimeError("refused")

        bus.start_reply_hook = lambda: _complete(bus)
        client = make_client(bus, check)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        started = "StartUnit" in [c.member for c in bus.calls]
        assert started is (when == "after-active")
        calls = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == calls

    asyncio.run(scenario())


def test_check_start_must_return_none():
    async def scenario():
        bus = FakeBus()
        bus.start_reply_hook = lambda: _complete(bus)
        with pytest.raises(UnitOperationFailed):
            await make_client(bus, lambda: True).start_and_wait(UnitKey.AUDITD)
        assert "StartUnit" not in [c.member for c in bus.calls]

    asyncio.run(scenario())


def test_slow_check_start_exhausts_budget_before_any_start_or_bus_contact():
    async def scenario():
        bus = FakeBus()

        def slow_check():
            time.sleep(0.04)

        client = make_client(bus, slow_check, timeout=0.01)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert bus.calls == []
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert bus.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize("state", ["active", "activating", "failed", "inactive-ish"])
def test_preflight_requires_exact_inactive_state(state):
    async def scenario():
        bus = FakeBus(state=state)
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).start_and_wait(UnitKey.AUDITD)
        assert "StartUnit" not in [c.member for c in bus.calls]

    asyncio.run(scenario())


@pytest.mark.parametrize("result", ["failed", "canceled", "timeout", "", "DONE"])
def test_matching_job_must_report_done_and_client_cannot_retry(result):
    async def scenario():
        bus = FakeBus()
        bus.start_reply_hook = lambda: _complete(bus, result=result)
        client = make_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.COMMISSIOND)
        assert len(bus.calls) == count and not bus.handlers

    asyncio.run(scenario())


@pytest.mark.parametrize("state", ["inactive", "activating", "failed", "inactive-ish"])
def test_job_done_requires_post_state_active(state):
    async def scenario():
        bus = FakeBus()
        bus.post_state = state
        bus.start_reply_hook = lambda: _complete(bus)
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).start_and_wait(UnitKey.AUDITD)

    asyncio.run(scenario())


def test_successful_job_observation_is_not_dependency_closure_proof():
    """Synthetic counterexample, not real systemd evidence or policy approval.

    Model an already-active external prerequisite becoming inactive while
    StartUnit causes a dependency-start. The target job still completes and
    later target snapshots report active, so this observer can return None
    despite the modeled extra effect. This is precisely why observer success
    is not closure proof and is not acceptable as production policy.
    """
    async def scenario():
        bus = FakeBus()
        modeled_effects = []

        def dependency_interleaving():
            modeled_effects.append(("prerequisite", "active", "inactive"))
            modeled_effects.append(("dependency", "start"))
            bus.signal()

        bus.start_reply_hook = dependency_interleaving
        assert await make_client(bus).start_and_wait(UnitKey.AUDITD) is None

        target_start = next(call for call in bus.calls if call.member == "StartUnit")
        assert target_start.body == [UNIT_NAMES[UnitKey.AUDITD], "fail"]
        assert "CancelJob" not in [call.member for call in bus.calls]
        assert modeled_effects == [
            ("prerequisite", "active", "inactive"),
            ("dependency", "start"),
        ]

    asyncio.run(scenario())


def test_owner_change_is_refused_and_observer_is_cleaned_up():
    async def scenario():
        bus = FakeBus()
        bus.change_owner_after_first_read = True
        bus.start_reply_hook = lambda: _complete(bus)
        with pytest.raises(UnitOperationFailed):
            await make_client(bus).start_and_wait(UnitKey.AUDITD)
        assert bus.events[-1] == "handler-remove" and not bus.handlers

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "kind",
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
def test_ignores_malformed_or_unrelated_job_removed(kind):
    async def scenario():
        bus = FakeBus()

        def hook():
            opts = {}
            if kind == "wrong-owner":
                opts["sender"] = ":1.999"
            if kind == "wrong-path":
                opts["path"] = "/wrong"
            if kind == "wrong-interface":
                opts["interface"] = "wrong.Interface"
            if kind == "wrong-member":
                opts["member"] = "UnitRemoved"
            if kind == "wrong-signature":
                opts["signature"] = "ssss"
            if kind == "wrong-shape":
                opts["body"] = [73, "short"]
            if kind == "wrong-unit":
                opts["body"] = [73, bus.job[1], "other.service", "done"]
            if kind == "wrong-job-id":
                opts["body"] = [74, bus.job[1], UNIT_NAMES[UnitKey.AUDITD], "done"]
            if kind == "wrong-job-path":
                opts["body"] = [
                    73,
                    "/org/freedesktop/systemd1/job/74",
                    UNIT_NAMES[UnitKey.AUDITD],
                    "done",
                ]
            bus.signal(**opts)
            _complete(bus)

        bus.start_reply_hook = hook
        await make_client(bus).start_and_wait(UnitKey.AUDITD)

    asyncio.run(scenario())


def test_timeout_poisons_client_and_cancellation_cleans_observer_without_retry():
    async def scenario():
        bus = FakeBus()
        entered = asyncio.Event()
        original = bus.call

        async def blocked(message):
            if message.member == "StartUnit":
                bus.calls.append(message)
                bus.events.append(message.member)
                entered.set()
                await asyncio.Future()
            return await original(message)

        bus.call = blocked
        client = make_client(bus, timeout=0.02)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert entered.is_set() and bus.events[-1] == "handler-remove"
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == count and not bus.handlers

        bus = FakeBus()
        entered = asyncio.Event()
        original = bus.call

        async def cancel_blocked(message):
            if message.member == "StartUnit":
                bus.calls.append(message)
                bus.events.append(message.member)
                entered.set()
                await asyncio.Future()
            return await original(message)

        bus.call = cancel_blocked
        client = make_client(bus)
        task = asyncio.create_task(client.start_and_wait(UnitKey.AUDITD))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert bus.events[-1] == "handler-remove" and not bus.handlers
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == count

    asyncio.run(scenario())


def test_pending_native_job_deadline_refuses_without_cancel_and_poisons_client():
    async def scenario():
        bus = FakeBus()
        client = make_client(bus, timeout=0.01)

        # StartUnit returns the native job path, but the bus never emits the
        # corresponding JobRemoved signal. Expiry is not job completion.
        with pytest.raises(UnitOperationFailed, match="completion unconfirmed"):
            await client.start_and_wait(UnitKey.AUDITD)

        members = [message.member for message in bus.calls]
        assert "StartUnit" in members
        assert "CancelJob" not in members
        assert "StopUnit" not in members
        assert bus.events[-1] == "handler-remove"
        assert "Unsubscribe" in members
        assert "RemoveMatch" in members
        assert not bus.handlers

        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await client.start_and_wait(UnitKey.AUDITD)
        assert len(bus.calls) == call_count

    asyncio.run(scenario())


def test_cleanup_attempts_unsubscribe_remove_match_and_removes_handler():
    async def scenario():
        bus = FakeBus()
        bus.start_reply_hook = lambda: _complete(bus)
        await make_client(bus).start_and_wait(UnitKey.AUDITD)
        members = [c.member for c in bus.calls]
        assert "Unsubscribe" in members and "RemoveMatch" in members
        assert bus.events[-1] == "handler-remove" and not bus.handlers
        assert not {
            "StopUnit",
            "UnmaskUnitFiles",
            "EnableUnitFiles",
            "CancelJob",
        } & set(members)

    asyncio.run(scenario())
