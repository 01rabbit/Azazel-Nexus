"""Fail-closed composition tests for closing the masked bootstrap pair."""

from __future__ import annotations

import asyncio
import os
import time
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import bootstrap_overlay_files as overlay_files
from azazel_nexus_runtime.bootstrap_close import BootstrapCloseSequence
from azazel_nexus_runtime.bootstrap_masked import MaskedBootstrapPair
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_job_drain import row as job_row
from test_runtime_bootstrap_masked import (
    FakeBus as MaskedFakeBus,
    Message,
    OWNER,
    PAIR,
    _reply,
)
from test_runtime_bootstrap_overlay_files import _environment, _publish


EXPECTED_FRAGMENTS = tuple(
    (unit, "/etc/systemd/system/" + UNIT_NAMES[unit]) for unit in PAIR
)


class FakeBus(MaskedFakeBus):
    """Masked inspector bus extended with the reload and drain protocol."""

    def __init__(self, *, snapshots=None, reload_error=False, hang_member=None,
                 drift_after_reload=False, **kwargs):
        super().__init__(**kwargs)
        self.snapshots = list(snapshots or [[], []])
        self.reload_error = reload_error
        self.hang_member = hang_member
        self.drift_after_reload = drift_after_reload
        self.reloaded = False
        self.job_owner_calls = 0

    async def call(self, message):
        # Keep the masked fixture's request log and handling for owner,
        # profile, unit lookup and properties.
        if message.member in {"Reload", "ListJobs", "CancelJob"}:
            self.calls.append(message)
            if message.member == self.hang_member:
                await asyncio.Future()
            assert message.destination == OWNER
            assert message.path == "/org/freedesktop/systemd1"
            assert message.interface == "org.freedesktop.systemd1.Manager"
            if message.member == "Reload":
                if self.reload_error:
                    return SimpleNamespace(
                        message_type=3, signature="", body=[], sender=OWNER,
                    )
                self.reloaded = True
                return _reply("", sender=OWNER)
            if message.member == "ListJobs":
                rows = self.snapshots.pop(0) if self.snapshots else []
                return _reply("a(usssoo)", rows, sender=OWNER)
            assert message.member == "CancelJob"
            return _reply("", sender=OWNER)

        if message.member == "GetNameOwner":
            self.job_owner_calls += 1
            if self.drift_after_reload and self.reloaded and self.job_owner_calls > 4:
                self.owner_changes = True
        return await super().call(message)


class FakeFiles:
    def __init__(self, bus, *, fragments=EXPECTED_FRAGMENTS, close_error=False,
                 check_error_at=None):
        self.bus = bus
        self.fragments = fragments
        self.close_error = close_error
        self.check_error_at = check_error_at
        self.closed = False
        self.calls = []

    def close(self):
        self.calls.append(("close", len(self.bus.calls)))
        if self.close_error:
            raise OSError("injected file close refusal")
        self.closed = True

    def check(self):
        self.calls.append(("check", len(self.bus.calls)))
        if self.check_error_at == len([call for call, _ in self.calls if call == "check"]):
            raise OSError("injected file check refusal")
        return self.fragments if self.closed else ()


def _sequence(bus, files, timeout_seconds=5.0):
    return BootstrapCloseSequence(
        bus=bus,
        message_factory=Message,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=timeout_seconds,
        files=files,
    )


def _run(awaitable):
    return asyncio.run(awaitable)


def test_close_orders_file_closure_reload_mask_observation_and_drain():
    audit = UNIT_NAMES[UnitKey.AUDITD]
    bus = FakeBus(snapshots=[[job_row(18, audit)], [], []])
    files = FakeFiles(bus)

    result = _run(_sequence(bus, files).close())

    assert isinstance(result, MaskedBootstrapPair)
    assert result.owner == OWNER
    assert result.fragments == EXPECTED_FRAGMENTS
    assert result.fingerprint.startswith("sha256:")
    assert bus.reloaded
    assert [member for member, _ in files.calls][0:2] == ["close", "check"]
    assert [member for member, _ in files.calls].count("check") >= 4
    reload_index = next(i for i, call in enumerate(bus.calls) if call.member == "Reload")
    assert files.calls[0][1] < reload_index
    assert files.calls[1][1] < reload_index
    list_positions = [i for i, call in enumerate(bus.calls) if call.member == "ListJobs"]
    assert len(list_positions) == 3
    file_check_positions = [position for name, position in files.calls if name == "check"]
    assert any(position < list_positions[0] for position in file_check_positions)
    assert any(position > list_positions[-1] for position in file_check_positions)
    assert [call.body for call in bus.calls if call.member == "CancelJob"] == [[18]]
    assert all(call.destination == OWNER for call in bus.calls if call.member == "Reload")


@pytest.mark.parametrize("fragments", [
    (),
    ((UnitKey.AUDITD, EXPECTED_FRAGMENTS[0][1]),),
    EXPECTED_FRAGMENTS + ((UnitKey.AUDITD, "/tmp/unexpected.service"),),
    ((UnitKey.AUDITD, "relative.service"), EXPECTED_FRAGMENTS[1]),
])
def test_unexpected_or_incomplete_file_fragment_set_refuses(fragments):
    bus = FakeBus()
    files = FakeFiles(bus, fragments=fragments)

    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, files).close())


def test_file_close_refusal_stops_before_reload():
    bus = FakeBus()
    files = FakeFiles(bus, close_error=True)

    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, files).close())
    assert not bus.reloaded
    assert not any(call.member in {"Reload", "ListJobs", "CancelJob"} for call in bus.calls)


def test_file_check_refusal_stops_before_reload():
    bus = FakeBus()
    files = FakeFiles(bus, check_error_at=1)

    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, files).close())
    assert not bus.reloaded


def test_reload_error_and_timeout_refuse_without_reporting_closed_pair():
    bus = FakeBus(reload_error=True)
    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, FakeFiles(bus)).close())

    bus = FakeBus(hang_member="Reload")
    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, FakeFiles(bus), timeout_seconds=0.01).close())


def test_owner_drift_during_close_refuses_and_sequence_is_single_use():
    bus = FakeBus(drift_after_reload=True)
    sequence = _sequence(bus, FakeFiles(bus))
    with pytest.raises(UnitOperationFailed):
        _run(sequence.close())
    calls = len(bus.calls)
    with pytest.raises(UnitOperationFailed):
        _run(sequence.close())
    assert len(bus.calls) == calls


def test_jobs_that_do_not_drain_refuse():
    audit = UNIT_NAMES[UnitKey.AUDITD]
    bus = FakeBus(snapshots=[[job_row(29, audit)]] * 16)
    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, FakeFiles(bus)).close())
    assert [call.member for call in bus.calls].count("CancelJob") > 0


def test_slow_synchronous_file_close_cannot_return_success_or_reload_after_budget():
    bus = FakeBus()

    class SlowFiles(FakeFiles):
        def close(self):
            # Deliberately shows that the bus deadline does not preempt file IO.
            # Once IO returns, the overdue transaction must refuse further calls.
            time.sleep(0.03)
            super().close()

    files = SlowFiles(bus)
    with pytest.raises(UnitOperationFailed):
        _run(_sequence(bus, files, timeout_seconds=0.01).close())
    assert files.closed
    assert not bus.reloaded
    assert not any(call.member in {"ListJobs", "CancelJob"} for call in bus.calls)


def test_real_overlay_file_adapter_closes_owned_pair_and_reports_absolute_paths(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)

        class RealOverlayFiles:
            def close(self):
                overlay_files._close_candidates_at(
                    overlay_fd=env["overlay_fd"],
                    masks_fd=env["masks_fd"],
                    higher_priority_fd=env["higher_fd"],
                    journal_store=env["store"],
                    guard=env["guard"],
                    owner_uid=os.getuid(),
                )

            def check(self):
                journal = env["store"].load()
                owned = {name for name, *_identity in journal.owned_files}
                assert owned == {UNIT_NAMES[unit] for unit in PAIR}
                assert all((env["overlay_path"] / name).read_bytes() == b"" for name in owned)
                return tuple(
                    (unit, str(env["overlay_path"] / UNIT_NAMES[unit]))
                    for unit in PAIR
                )

        def report_overlay_fragments(_call_number, name, properties):
            properties["FragmentPath"] = SimpleNamespace(
                signature="s", value=str(env["overlay_path"] / name),
            )
            return properties

        bus = FakeBus(snapshots=[[], []], mutate=report_overlay_fragments)
        result = _run(_sequence(bus, RealOverlayFiles()).close())

        assert result.owner == OWNER
        assert result.fragments == tuple(
            (unit, str(env["overlay_path"] / UNIT_NAMES[unit])) for unit in PAIR
        )
        assert env["store"].load().phase == "closing"
