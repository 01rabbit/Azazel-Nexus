"""Masked-but-not-loaded (GetUnit NoSuchUnit) handling in bootstrap inspectors.

Real systemd 257 answers GetUnit with org.freedesktop.systemd1.NoSuchUnit for a
masked unit it has not loaded. Only the masked/closed-phase observers of the
fixed pair accept that, and only with fresh masked file state and a re-read
that is still not loaded. Everything expecting a loaded unit keeps refusing.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_masked import (
    BootstrapMaskedPairInspector,
    MaskedBootstrapPair,
)
from azazel_nexus_runtime.bootstrap_stop import NOT_LOADED, BootstrapStopJobs
from azazel_nexus_runtime.bootstrap_stopped import BootstrapStoppedPairInspector
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_masked import FakeBus as MaskedFakeBus
from test_runtime_bootstrap_masked import OWNER, PAIR
from test_runtime_bootstrap_start_closure import (
    AUDIT,
    FakeBus as ClosureFakeBus,
    PROFILE_DIGEST,
)
from test_runtime_bootstrap_start_closure import _inspector as closure_inspector
from test_runtime_bootstrap_stop import FakeBus as StopFakeBus
from test_runtime_bootstrap_stopped import (
    OWNER_UID,
    StoppedFakeBus,
    _cgroup,
    _private_dir,
    cgroup_root,  # noqa: F401 - pytest fixture
)

NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
AUDITD, COMMISSIOND = PAIR
EXPECTED = tuple((unit, f"/etc/systemd/system/{UNIT_NAMES[unit]}") for unit in PAIR)


def _error(name, *, sender=OWNER):
    return SimpleNamespace(message_type=3, error_name=name, signature="s",
                           body=["x"], sender=sender)


def _ok(signature, value, *, sender=OWNER):
    return SimpleNamespace(message_type=1, signature=signature, body=[value],
                           sender=sender)


def not_loaded(bus, names, *, file_state="masked", error=NO_SUCH_UNIT,
               error_sender=OWNER, loaded_from=None, state_sender=OWNER,
               loaded_on_read=None):
    """Make GetUnit for `names` answer with a D-Bus error.

    loaded_from: GetUnit number (1-based, per unit) from which it is loaded.
    loaded_on_read: only GetUnit reads of this ordinal are loaded (the re-read).
    """
    original = bus.call
    seen = {}

    async def call(message):
        if message.member == "GetUnitFileState":
            bus.calls.append(message)
            return _ok("s", file_state, sender=state_sender)
        if message.member == "GetUnit" and message.body[0] in names:
            n = seen[message.body[0]] = seen.get(message.body[0], 0) + 1
            if (loaded_from is None or n < loaded_from) and n != loaded_on_read:
                bus.calls.append(message)
                return _error(error, sender=error_sender)
        return await original(message)

    bus.call = call
    return bus


def masked(bus, *, expected=EXPECTED):
    return BootstrapMaskedPairInspector(
        bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=0.2, expected_fragments=expected,
    )


A, C = UNIT_NAMES[AUDITD], UNIT_NAMES[COMMISSIOND]


# --- masked pair ---------------------------------------------------------

def test_masked_accepts_not_loaded_masked_with_distinct_stable_value():
    async def run():
        loaded = await masked(MaskedFakeBus()).inspect()
        one = await masked(not_loaded(MaskedFakeBus(), {A})).inspect()
        both = await masked(not_loaded(MaskedFakeBus(), {A, C})).inspect()
        again = await masked(not_loaded(MaskedFakeBus(), {A})).inspect()
        assert isinstance(one, MaskedBootstrapPair)
        assert loaded.not_loaded == ()
        assert one.not_loaded == (AUDITD,) and both.not_loaded == PAIR
        assert one.fragments == EXPECTED  # file-attested, matches files.check()
        # Never equal to the loaded observation, nor to each other.
        assert len({loaded.fingerprint, one.fingerprint, both.fingerprint}) == 3
        assert one != loaded and one != both
        assert one == again and one.fingerprint == again.fingerprint
    asyncio.run(run())


def test_masked_issues_filestate_and_reread_only_on_no_such_unit():
    async def run():
        bus = not_loaded(MaskedFakeBus(), {A})
        await masked(bus).inspect()
        members = [(c.member, c.body[0]) for c in bus.calls
                   if c.member in {"GetUnit", "GetUnitFileState"}]
        # Per snapshot: GetUnit, GetUnitFileState, GetUnit for auditd.
        assert members[:3] == [("GetUnit", A), ("GetUnitFileState", A), ("GetUnit", A)]
        plain = MaskedFakeBus()
        await masked(plain).inspect()
        assert all(c.member != "GetUnitFileState" for c in plain.calls)
    asyncio.run(run())


def test_masked_without_expected_fragments_still_refuses_no_such_unit():
    async def run():
        bus = not_loaded(MaskedFakeBus(), {A})
        inspector = BootstrapMaskedPairInspector(
            bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
            message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
            timeout_seconds=0.2,
        )
        with pytest.raises(UnitOperationFailed):
            await inspector.inspect()
        assert all(c.member != "GetUnitFileState" for c in bus.calls)
    asyncio.run(run())


@pytest.mark.parametrize("state", ["enabled", "disabled", "static", "masked-runtime", ""])
def test_masked_refuses_not_loaded_but_not_masked(state):
    async def run():
        with pytest.raises(UnitOperationFailed):
            await masked(not_loaded(MaskedFakeBus(), {A}, file_state=state)).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("name", [
    "org.freedesktop.DBus.Error.UnknownObject",
    "org.freedesktop.systemd1.NoSuchUnitX",
    "org.freedesktop.systemd1.nosuchunit",
    "org.freedesktop.systemd1.LoadFailed",
    "org.freedesktop.DBus.Error.AccessDenied",
    None,
])
def test_masked_refuses_other_error_names(name):
    async def run():
        bus = not_loaded(MaskedFakeBus(), {A}, error=name)
        with pytest.raises(UnitOperationFailed):
            await masked(bus).inspect()
        assert all(c.member != "GetUnitFileState" for c in bus.calls)
    asyncio.run(run())


def test_masked_refuses_forged_sender_on_error_or_file_state():
    async def run():
        for options in ({"error_sender": ":1.99"}, {"error_sender": None},
                        {"state_sender": ":1.99"}):
            with pytest.raises(UnitOperationFailed):
                await masked(not_loaded(MaskedFakeBus(), {A}, **options)).inspect()
    asyncio.run(run())


def test_masked_refuses_unit_loaded_at_reread():
    async def run():
        bus = not_loaded(MaskedFakeBus(), {A}, loaded_on_read=2)
        with pytest.raises(UnitOperationFailed):
            await masked(bus).inspect()
    asyncio.run(run())


def test_masked_refuses_unit_loaded_between_snapshots():
    async def run():
        # Snapshot one: not loaded (GetUnit x2 for the re-read); snapshot two: loaded.
        bus = not_loaded(MaskedFakeBus(), {A}, loaded_from=3)
        with pytest.raises(UnitOperationFailed):
            await masked(bus).inspect()
    asyncio.run(run())


def test_masked_refuses_malformed_expected_fragments():
    for bad in (list(EXPECTED), EXPECTED[:1], EXPECTED[::-1],
                ((AUDITD, "relative"), (COMMISSIOND, "/x"))):
        with pytest.raises((ValueError, UnitOperationFailed)):
            masked(MaskedFakeBus(), expected=bad)


# --- stop jobs observe_state ----------------------------------------------

def _stop_client(bus, **kw):
    return BootstrapStopJobs(
        bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
        message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4, ERROR=3),
        timeout_seconds=0.2, **kw,
    )


def _stop_bus(**options):
    bus = StopFakeBus()
    bus.stop_reply_hook = lambda: bus.signal()
    original = bus.call

    async def call(message):
        if message.member == "GetUnitFileState":
            bus.calls.append(message)
            return _ok("s", options.get("file_state", "masked"), sender=bus.owner)
        if message.member == "GetUnit":
            n = options["n"] = options.get("n", 0) + 1
            if n not in options.get("loaded", ()):
                bus.calls.append(message)
                return _error(options.get("error", NO_SUCH_UNIT), sender=bus.owner)
        return await original(message)

    bus.call = call
    return bus


def test_stop_accepts_not_loaded_masked_as_inactive_after_job():
    async def run():
        bus = _stop_bus()
        await _stop_client(bus).stop_and_wait(UnitKey.AUDITD)
        members = [c.member for c in bus.calls]
        assert members.index("StopUnit") < members.index("GetUnitFileState")
        assert "Get" not in members  # no ActiveState read of a missing object
    asyncio.run(run())


@pytest.mark.parametrize("options", [
    {"file_state": "enabled"},
    {"error": "org.freedesktop.DBus.Error.UnknownObject"},
    {"loaded": (2,)},  # loaded at the re-read
])
def test_stop_refuses_unconfirmed_not_loaded(options):
    async def run():
        with pytest.raises(UnitOperationFailed):
            await _stop_client(_stop_bus(**options)).stop_and_wait(UnitKey.AUDITD)
    asyncio.run(run())


def test_start_side_observations_still_refuse_no_such_unit():
    async def run():
        # Pre-start "inactive" check: refused before any subscription.
        bus = _stop_bus()
        client = _stop_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client._job(UnitKey.AUDITD, _start_check=lambda: None)
        assert all(c.member not in {"AddMatch", "Subscribe", "GetUnitFileState"}
                   for c in bus.calls)
        # Post-start "active" check: a not-loaded unit is never active.
        bus = _stop_bus(loaded=(1,))
        client = _stop_client(bus)
        with pytest.raises(UnitOperationFailed):
            await client._job(UnitKey.AUDITD, _start_check=lambda: None)
        assert all(c.member != "GetUnitFileState" for c in bus.calls)
    asyncio.run(run())


# --- stopped pair ----------------------------------------------------------

def _stopped(bus, root_fd):
    async def closed():
        return None

    return BootstrapStoppedPairInspector(
        bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1), timeout_seconds=0.2,
        cgroup_root_fd=root_fd, owner_uid=OWNER_UID, expected_owner=OWNER,
        check_closed=closed,
    )


def test_stopped_accepts_not_loaded_masked_with_absent_cgroup(cgroup_root):  # noqa: F811
    async def run():
        root, fd = cgroup_root
        _cgroup(root, COMMISSIOND)
        _private_dir(root / "system.slice")
        result = await _stopped(not_loaded(StoppedFakeBus(), {A}), fd).inspect()
        assert result.cgroups[0][:2] == (AUDITD, NOT_LOADED)
        assert result.cgroups[0][2][0] == "absent"
        assert result.cgroups[1][1] == "/system.slice/" + C
        assert result.cgroups[1][2][0] == "empty"
        same = await _stopped(not_loaded(StoppedFakeBus(), {A}), fd).inspect()
        assert same == result
    asyncio.run(run())


def test_stopped_refuses_not_loaded_with_remaining_cgroup(cgroup_root):  # noqa: F811
    async def run():
        root, fd = cgroup_root
        for unit in PAIR:
            _cgroup(root, unit)
        with pytest.raises(UnitOperationFailed):
            await _stopped(not_loaded(StoppedFakeBus(), {A}), fd).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("options", [
    {"file_state": "disabled"},
    {"error": "org.freedesktop.DBus.Error.NoReply"},
    {"loaded_from": 2},
    {"loaded_on_read": 2},
])
def test_stopped_refuses_unconfirmed_not_loaded(cgroup_root, options):  # noqa: F811
    async def run():
        root, fd = cgroup_root
        _private_dir(root / "system.slice")
        for unit in PAIR:
            _cgroup(root, unit)
        (root / "system.slice" / A / "cgroup.events").unlink()
        (root / "system.slice" / A).rmdir()
        with pytest.raises(UnitOperationFailed):
            await _stopped(not_loaded(StoppedFakeBus(), {A}, **options), fd).inspect()
    asyncio.run(run())


# --- start closure: deliberately unchanged ---------------------------------

def test_start_closure_still_refuses_no_such_unit_for_roots():
    async def run():
        bus = not_loaded(ClosureFakeBus(), {AUDIT})
        with pytest.raises(UnitOperationFailed):
            await closure_inspector(bus).inspect()
        assert all(c.member != "GetUnitFileState" for c in bus.calls)
        assert PROFILE_DIGEST
    asyncio.run(run())
