"""Bounded systemd stop-job observation for the exact bootstrap pair.

The public stop operation does not connect, start, unmask, enable or cancel.
Its private observer is also used by the separate guarded start adapter.
Production has not installed these adapters. Stop completion
is not cgroup emptiness, masking, controller lifetime or reboot fencing.
"""

import asyncio
import math
import re

from .systemd_bus import (
    DESTINATION,
    MANAGER_PATH,
    MANAGER_INTERFACE,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
    _unit_object_path,
)
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed

_DBUS = "org.freedesktop.DBus"
_DBUS_PATH = "/org/freedesktop/DBus"
_RULE = (
    "type='signal',sender='org.freedesktop.systemd1',"
    "path='/org/freedesktop/systemd1',"
    "interface='org.freedesktop.systemd1.Manager',member='JobRemoved'"
)
_JOB = re.compile(r"/org/freedesktop/systemd1/job/([1-9][0-9]*)\Z")
_PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)


def _validate_expected_owner(owner):
    """Validate an enclosing transaction's identity pin, not authorization."""
    if owner is not None and (
        type(owner) is not str
        or re.fullmatch(r":[0-9]+\.[0-9]+", owner) is None
    ):
        raise ValueError("exact systemd unique owner required")
    return owner


class BootstrapStopJobs:
    """Private runtime adapter, not a user-addressable unit-control API.

    The caller supplies a dedicated trusted system-bus connection and its
    dbus-next message types. This adapter must not share Subscribe/Unsubscribe
    ownership with another observer. A whole stop transaction and its cleanup
    each have a finite budget; a timeout never means the stop was undone.
    """

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds: float,
                 expected_owner=None):
        self._expected_owner = _validate_expected_owner(expected_owner)
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("explicit finite positive stop-job timeout required")
        self._bus = bus
        self._message = message_factory
        self._types = message_type
        self._timeout = timeout_seconds
        self._busy = False
        self._usable = True
        self._manager_owner = None
        self._cleanup_open = False
        self._operation_deadline = None

    async def _bounded(self, awaitable):
        deadline = asyncio.get_running_loop().time() + self._timeout
        self._operation_deadline = deadline
        task = asyncio.create_task(awaitable)

        def discard_result(finished):
            try:
                finished.result()
            except BaseException:
                pass

        try:
            done, _pending = await asyncio.wait({task}, timeout=self._timeout)
            if not done or asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError
            return task.result()
        except BaseException:
            self._usable = False
            task.cancel()
            task.add_done_callback(discard_result)
            raise

    async def _call(
        self,
        member,
        signature,
        body,
        reply_signature,
        *,
        path=MANAGER_PATH,
        interface=MANAGER_INTERFACE,
        destination=DESTINATION,
    ):
        cleanup_call = member in {"Unsubscribe", "RemoveMatch"}
        if (cleanup_call and not self._cleanup_open) or (
            not cleanup_call and not self._usable
        ):
            raise UnitOperationFailed("bootstrap stop transaction no longer usable")
        if not cleanup_call and (
            self._operation_deadline is None
            or asyncio.get_running_loop().time() >= self._operation_deadline
        ):
            raise UnitOperationFailed("bootstrap job operation budget exhausted")
        target = ((self._manager_owner or DESTINATION)
                  if destination == DESTINATION else destination)
        reply = await self._bus.call(
            self._message(
                destination=target,
                path=path,
                interface=interface,
                member=member,
                signature=signature,
                body=body,
            )
        )
        if (cleanup_call and not self._cleanup_open) or (
            not cleanup_call and not self._usable
        ):
            raise UnitOperationFailed("late bootstrap stop reply refused")
        if (
            reply.message_type != self._types.METHOD_RETURN
            or getattr(reply, "sender", None) != target
            or reply.signature != reply_signature
            or type(reply.body) is not list
        ):
            raise UnitOperationFailed("bootstrap stop D-Bus reply refused")
        return reply.body

    async def _owner(self):
        result = await self._call(
            "GetNameOwner",
            "s",
            [DESTINATION],
            "s",
            path=_DBUS_PATH,
            interface=_DBUS,
            destination=_DBUS,
        )
        if (
            len(result) != 1
            or type(result[0]) is not str
            or not re.fullmatch(r":[0-9]+\.[0-9]+", result[0])
        ):
            raise UnitOperationFailed("bootstrap systemd owner unavailable")
        admitted = getattr(self._bus, "_azazel_systemd_owner", None)
        if admitted is not None and _validate_expected_owner(admitted) != result[0]:
            raise UnitOperationFailed("admitted systemd owner changed")
        return result[0]

    async def stop_and_wait(self, unit: UnitKey) -> None:
        await self._job(unit)

    async def _job(self, unit: UnitKey, *, _start_check=None,
                   _start_checkpoint=None) -> None:
        # The public stop API never supplies a start guard. Only the separate
        # private-composition start adapter may select that fixed operation.
        if _start_check is not None and _start_checkpoint is not None:
            raise UnitOperationFailed("exclusive bootstrap start checkpoint required")
        starting = _start_check is not None or _start_checkpoint is not None
        if not self._usable:
            raise UnitOperationFailed("bootstrap stop connection must be discarded")
        if type(unit) is not UnitKey or unit not in _PAIR:
            raise UnitOperationFailed("bootstrap stop unit outside exact pair")
        if self._busy:
            raise UnitOperationFailed("bootstrap stop transaction already in progress")
        self._busy = True
        name = UNIT_NAMES[unit]
        queue = asyncio.Queue(maxsize=64)
        owner = None
        overflow = False
        handler_added = False
        match_requested = False
        subscribe_requested = False

        async def check_start(phase):
            deadline = self._operation_deadline
            result = (await _start_checkpoint(phase, deadline)
                      if _start_checkpoint is not None else _start_check())
            if (result is not None or not self._usable or deadline is None
                    or asyncio.get_running_loop().time() >= deadline):
                raise UnitOperationFailed("bootstrap start guard refused")

        async def observe_state(expected):
            path = _unit_object_path(name)
            if await self._call("GetUnit", "s", [name], "o") != [path]:
                raise UnitOperationFailed("bootstrap job unit identity changed")
            state = await self._call(
                "Get", "ss", [UNIT_INTERFACE, "ActiveState"], "v",
                path=path, interface=PROPERTIES_INTERFACE,
            )
            if (
                len(state) != 1
                or getattr(state[0], "signature", None) != "s"
                or getattr(state[0], "value", None) != expected
            ):
                raise UnitOperationFailed("bootstrap job state unconfirmed")

        def receive(message):
            nonlocal overflow
            if (
                message.message_type != self._types.SIGNAL
                or message.sender != owner
                or message.path != MANAGER_PATH
                or message.interface != MANAGER_INTERFACE
                or message.member != "JobRemoved"
                or message.signature != "uoss"
                or type(message.body) is not list
                or len(message.body) != 4
            ):
                return
            job_id, job_path, job_unit, result = message.body
            if (
                type(job_id) is not int
                or not 0 < job_id <= 0xFFFFFFFF
                or type(job_path) is not str
                or type(job_unit) is not str
                or job_unit != name
                or type(result) is not str
            ):
                return
            if queue.full():
                overflow = True
            else:
                queue.put_nowait((job_id, job_path, result))

        async def operation():
            nonlocal owner, handler_added, match_requested, subscribe_requested
            if starting:
                await check_start("before_observation")
            owner = await self._owner()
            if self._expected_owner is not None and owner != self._expected_owner:
                raise UnitOperationFailed("enclosing systemd owner changed")
            self._manager_owner = owner
            if starting:
                await observe_state("inactive")
            self._bus.add_message_handler(receive)
            handler_added = True
            match_requested = True
            if (
                await self._call(
                    "AddMatch",
                    "s",
                    [_RULE],
                    "",
                    path=_DBUS_PATH,
                    interface=_DBUS,
                    destination=_DBUS,
                )
                != []
            ):
                raise UnitOperationFailed("bootstrap signal match refused")
            subscribe_requested = True
            if await self._call("Subscribe", "", [], "") != []:
                raise UnitOperationFailed("bootstrap subscription refused")
            # Listen first: a fast job can finish before the method reply arrives.
            if starting:
                await check_start("before_submission")
                if await self._owner() != owner:
                    raise UnitOperationFailed("bootstrap systemd owner changed before start")
            result = await self._call(
                "StartUnit" if starting else "StopUnit", "ss", [name, "fail"], "o"
            )
            if len(result) != 1 or type(result[0]) is not str:
                raise UnitOperationFailed("bootstrap stop returned no job")
            match = _JOB.fullmatch(result[0])
            if match is None or int(match[1]) > 0xFFFFFFFF:
                raise UnitOperationFailed("bootstrap stop returned invalid job")
            expected_id, expected_path = int(match[1]), result[0]
            while True:
                if overflow:
                    raise UnitOperationFailed("bootstrap job observation overflow")
                job_id, job_path, status = await queue.get()
                if (job_id, job_path) != (expected_id, expected_path):
                    continue
                if status != "done":
                    raise UnitOperationFailed("bootstrap stop job did not succeed")
                break
            if await self._owner() != owner:
                raise UnitOperationFailed("bootstrap systemd owner changed")
            await observe_state("active" if starting else "inactive")
            if starting:
                await check_start("after_completion")
            if overflow or await self._owner() != owner:
                raise UnitOperationFailed("bootstrap stop observation changed")

        async def cleanup():
            errors = []
            for requested, member, signature, body, interface, path, destination in (
                (
                    subscribe_requested,
                    "Unsubscribe",
                    "",
                    [],
                    MANAGER_INTERFACE,
                    MANAGER_PATH,
                    DESTINATION,
                ),
                (
                    match_requested,
                    "RemoveMatch",
                    "s",
                    [_RULE],
                    _DBUS,
                    _DBUS_PATH,
                    _DBUS,
                ),
            ):
                if requested:
                    try:
                        result = await self._call(
                            member,
                            signature,
                            body,
                            "",
                            interface=interface,
                            path=path,
                            destination=destination,
                        )
                        if result != []:
                            errors.append(member)
                    except Exception:
                        errors.append(member)
            if errors:
                raise UnitOperationFailed("bootstrap stop observer cleanup failed")

        failed = False
        try:
            await self._bounded(operation())
        except Exception:
            failed = True
            self._usable = False
            raise UnitOperationFailed("bootstrap stop completion unconfirmed") from None
        except BaseException:
            failed = True
            self._usable = False
            raise
        finally:
            try:
                self._cleanup_open = True
                await self._bounded(cleanup())
            except BaseException as error:
                self._usable = False
                if not failed:
                    if not isinstance(error, Exception):
                        raise
                    raise UnitOperationFailed(
                        "bootstrap stop observer cleanup failed"
                    ) from None
            finally:
                self._cleanup_open = False
                try:
                    if handler_added:
                        self._bus.remove_message_handler(receive)
                except Exception:
                    self._usable = False
                    if not failed:
                        raise UnitOperationFailed(
                            "bootstrap stop handler cleanup failed"
                        ) from None
                finally:
                    self._busy = False
