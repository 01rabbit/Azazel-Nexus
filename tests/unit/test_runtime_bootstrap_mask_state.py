"""Per-path mask file state, cross-observation closure identity, call-site wiring.

The owned overlay mask is an empty file under /run/systemd/system.control
(systemd reports "masked-runtime"); the installer's /etc/systemd/system link to
/dev/null reports "masked". The required GetUnitFileState value is derived from
the file-attested fragment path, never from the observed manager.
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import bootstrap_close, bootstrap_manager, bootstrap_restore
from azazel_nexus_runtime import bootstrap_stop
from azazel_nexus_runtime.bootstrap_masked import (
    BootstrapMaskedPairInspector,
    MaskedBootstrapPair,
)
from azazel_nexus_runtime.bootstrap_stop import NOT_LOADED
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_close_sequence import (
    test_close_orders_file_closure_reload_mask_observation_and_drain as _close_flow,
)
from test_runtime_bootstrap_empty_gate import (
    test_empty_pair_gate_rechecks_real_fixture_after_previous_success as _empty_flow,
)
from test_runtime_bootstrap_manager_stopped import (
    StoppedManagerFakeBus,
    _cgroup_root,
    _manager,
    _report_overlay_fragments,
    test_stop_closed_pair_closes_reloads_drains_then_stops_reverse_and_observes as _stop_flow,
)
from test_runtime_bootstrap_manager_withdrawal import (
    test_manager_withdraws_real_closed_journal_then_confirms_empty_pair as _withdraw_flow,
)
from test_runtime_bootstrap_masked import FakeBus as MaskedFakeBus
from test_runtime_bootstrap_masked import OWNER, PAIR
from test_runtime_bootstrap_not_loaded import (
    NO_SUCH_UNIT,
    _error,
    _ok,
    _stop_bus,
    _stop_client,
    _stopped,
)
from test_runtime_bootstrap_overlay_files import _environment, _publish
from test_runtime_bootstrap_restore_sequence import (
    test_restore_reloads_stops_reverse_finalizes_then_rechecks_cgroups as _restore_flow,
)
from test_runtime_bootstrap_stopped import (
    StoppedFakeBus,
    _private_dir,
    cgroup_root,  # noqa: F401 - pytest fixture
)

AUDITD, COMMISSIOND = PAIR
A, C = UNIT_NAMES[AUDITD], UNIT_NAMES[COMMISSIOND]
RUN = "/run/systemd/system.control/"
ETC = "/etc/systemd/system/"


def _fragments(auditd_dir, commissiond_dir):
    return ((AUDITD, auditd_dir + A), (COMMISSIOND, commissiond_dir + C))


def _states(bus, unloaded, states):
    """`unloaded` units answer NoSuchUnit; file state per unit name."""
    original = bus.call

    async def call(message):
        if message.member == "GetUnitFileState":
            bus.calls.append(message)
            return _ok("s", states[message.body[0]])
        if message.member == "GetUnit" and message.body[0] in unloaded:
            bus.calls.append(message)
            return _error(NO_SUCH_UNIT)
        return await original(message)

    bus.call = call
    return bus


def _masked(bus, fragments):
    return BootstrapMaskedPairInspector(
        bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=0.2, expected_fragments=fragments,
    )


# --- A2: file state derived from the attested path --------------------------

@pytest.mark.parametrize("directory,state", [(RUN, "masked-runtime"), (ETC, "masked")])
def test_required_file_state_follows_attested_fragment_directory(directory, state):
    async def run():
        fragments = _fragments(directory, directory)
        result = await _masked(
            _states(MaskedFakeBus(), {A, C}, {A: state, C: state}), fragments,
        ).inspect()
        assert result.not_loaded == PAIR and result.fragments == fragments
    asyncio.run(run())


@pytest.mark.parametrize("directory,wrong", [
    (RUN, "masked"), (ETC, "masked-runtime"),
    (RUN, "enabled"), (ETC, "disabled"), (RUN, "masked-runtime "), (ETC, "Masked"),
])
def test_wrong_file_state_for_the_attested_directory_is_refused(directory, wrong):
    async def run():
        fragments = _fragments(directory, directory)
        bus = _states(MaskedFakeBus(), {A}, {A: wrong, C: wrong})
        with pytest.raises(UnitOperationFailed):
            await _masked(bus, fragments).inspect()
    asyncio.run(run())


def test_mixed_per_unit_fragments_require_each_units_own_state():
    async def run():
        fragments = _fragments(RUN, ETC)
        good = {A: "masked-runtime", C: "masked"}
        result = await _masked(
            _states(MaskedFakeBus(), {A, C}, good), fragments).inspect()
        assert result.not_loaded == PAIR and result.fragments == fragments
        for swapped in ({A: "masked", C: "masked"}, {A: "masked-runtime", C: "masked-runtime"},
                        {A: "masked", C: "masked-runtime"}):
            with pytest.raises(UnitOperationFailed):
                await _masked(
                    _states(MaskedFakeBus(), {A, C}, swapped), fragments).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("path", [
    "/usr/lib/systemd/system/", "/tmp/", "/run/systemd/system/", "/etc/systemd/system.control/",
    "/run/systemd/system.control.x/", "/etc/systemd/systemx/",
])
@pytest.mark.parametrize("state", ["masked", "masked-runtime"])
def test_fragment_outside_known_mask_directories_is_refused(path, state):
    async def run():
        fragments = _fragments(path, path)
        bus = _states(MaskedFakeBus(), {A}, {A: state, C: state})
        with pytest.raises(UnitOperationFailed):
            await _masked(bus, fragments).inspect()
        assert all(c.member != "GetUnitFileState" for c in bus.calls)
    asyncio.run(run())


def test_loaded_unit_does_not_consult_file_state():
    async def run():
        bus = MaskedFakeBus()
        await _masked(bus, _fragments(RUN, RUN)).inspect()
        assert all(c.member != "GetUnitFileState" for c in bus.calls)
    asyncio.run(run())


@pytest.mark.parametrize("state", ["masked", "masked-runtime"])
def test_stopped_inspector_accepts_exactly_both_mask_states(cgroup_root, state):  # noqa: F811
    # The stopped inspector has no attested path, but its enclosing check_closed
    # fence has already required the owned masked closure for this snapshot.
    async def run():
        root, fd = cgroup_root
        _private_dir(root / "system.slice")
        bus = _states(StoppedFakeBus(), {A, C}, {A: state, C: state})
        result = await _stopped(bus, fd).inspect()
        assert [row[1] for row in result.cgroups] == [NOT_LOADED, NOT_LOADED]
    asyncio.run(run())


@pytest.mark.parametrize("state", ["enabled", "masked-runtime-x", "", "linked"])
def test_stopped_inspector_refuses_other_states(cgroup_root, state):  # noqa: F811
    async def run():
        root, fd = cgroup_root
        _private_dir(root / "system.slice")
        bus = _states(StoppedFakeBus(), {A}, {A: state, C: state})
        with pytest.raises(UnitOperationFailed):
            await _stopped(bus, fd).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("state,ok", [
    ("masked", True), ("masked-runtime", True), ("enabled", False), ("static", False),
])
def test_stop_job_post_state_accepts_exactly_both_mask_states(state, ok):
    # Only stop jobs on an already-masked, closed pair (stop_closed_pair /
    # restore / containment mask-then-stop) observe the unloaded "inactive".
    async def run():
        client = _stop_client(_stop_bus(file_state=state))
        if ok:
            await client.stop_and_wait(UnitKey.AUDITD)
        else:
            with pytest.raises(UnitOperationFailed):
                await client.stop_and_wait(UnitKey.AUDITD)
    asyncio.run(run())


# --- A3: not_loaded provenance --------------------------------------------

def test_not_loaded_provenance_is_documented_as_file_attested():
    from azazel_nexus_runtime import bootstrap_masked

    stop_source = open(bootstrap_stop.__file__, encoding="utf-8").read()
    masked_source = open(bootstrap_masked.__file__, encoding="utf-8").read()
    assert "file-attested, not systemd-attested" in stop_source
    assert "file-attested" in masked_source and "NOT systemd-attested" in masked_source


# --- A1: closure identity ignores the loaded flag across observations ---------

def _pair(owner=OWNER, not_loaded=(), fragments=None):
    fragments = fragments or _fragments(RUN, RUN)
    return MaskedBootstrapPair(owner, fragments, "sha256:" + "0" * 64, not_loaded)


def test_same_closure_ignores_only_the_loaded_flag():
    loaded, flipped = _pair(), _pair(not_loaded=(COMMISSIOND,))
    assert loaded != flipped
    assert loaded.same_closure(flipped) and flipped.same_closure(loaded)
    assert loaded.same_closure(_pair(not_loaded=PAIR))
    assert not loaded.same_closure(_pair(owner=":1.99"))
    assert not loaded.same_closure(_pair(fragments=_fragments(ETC, RUN)))
    assert not loaded.same_closure(_pair(fragments=_fragments(RUN, RUN)[::-1]))
    assert not loaded.same_closure(object())


def _flipping(bus, root, *, unloaded, on_stop):
    state = {"unloaded": set(unloaded)}
    original = bus.call

    async def call(message):
        if message.member == "GetUnitFileState":
            bus.calls.append(message)
            return _ok("s", "masked-runtime")
        if message.member == "GetUnit" and message.body[0] in state["unloaded"]:
            bus.calls.append(message)
            return _error(NO_SUCH_UNIT)
        reply = await original(message)
        if message.member == "StopUnit":
            on_stop(message.body[0], state, root)
        return reply

    bus.call = call
    return bus


def _drop_cgroup(root, name):
    leaf = root / "system.slice" / name
    (leaf / "cgroup.events").unlink()
    leaf.rmdir()


def _run_stop_closed(tmp_path, monkeypatch, *, unloaded, on_stop):
    with _environment(tmp_path) as env:
        _publish(env)
        monkeypatch.setattr(bootstrap_stop, "_RUNTIME_MASK_DIR",
                            str(env["overlay_path"]) + "/")
        root, root_fd = _cgroup_root(tmp_path)
        bus = _flipping(
            StoppedManagerFakeBus(snapshots=[[], [], [], []],
                                  mutate=_report_overlay_fragments(env)),
            root, unloaded=unloaded, on_stop=on_stop,
        )
        manager, session = _manager(env, bus)
        try:
            return manager.stop_closed_pair(
                cgroup_root_fd=root_fd, owner_uid=os.getuid()), bus
        finally:
            os.close(root_fd)


def test_loaded_to_not_loaded_transition_across_check_closed_is_accepted(
        tmp_path, monkeypatch):
    def on_stop(name, state, root):
        if name == C:  # StopUnit/GC: the masked unit disappears after the stop
            state["unloaded"].add(C)
            _drop_cgroup(root, C)

    result, bus = _run_stop_closed(tmp_path, monkeypatch, unloaded=(), on_stop=on_stop)
    assert result.cgroups[0][1] == "/system.slice/" + A
    assert result.cgroups[1][1] == NOT_LOADED
    assert [c.body[0] for c in bus.calls if c.member == "StopUnit"] == [C, A]


def test_not_loaded_to_loaded_transition_across_check_closed_is_accepted(
        tmp_path, monkeypatch):
    def on_stop(name, state, root):
        if name == C:  # an unloaded masked unit is loaded again (e.g. by a client)
            state["unloaded"].discard(A)

    result, bus = _run_stop_closed(
        tmp_path, monkeypatch, unloaded=(A,), on_stop=on_stop)
    assert all(row[2][0] == "empty" for row in result.cgroups)
    assert result.cgroups[0][1] == "/system.slice/" + A
    assert [c.body[0] for c in bus.calls if c.member == "StopUnit"] == [C, A]


def test_closure_identity_change_is_still_refused_across_check_closed(
        tmp_path, monkeypatch):
    def on_stop(name, state, root):
        if name == C:
            state["unloaded"].add(C)
            _drop_cgroup(root, C)
            bus_ref[0].owner_changes = True  # a different manager owner

    bus_ref = [None]
    with pytest.raises(UnitOperationFailed):
        with _environment(tmp_path) as env:
            _publish(env)
            monkeypatch.setattr(bootstrap_stop, "_RUNTIME_MASK_DIR",
                                str(env["overlay_path"]) + "/")
            root, root_fd = _cgroup_root(tmp_path)
            bus = _flipping(
                StoppedManagerFakeBus(snapshots=[[], [], [], []],
                                      mutate=_report_overlay_fragments(env)),
                root, unloaded=(), on_stop=on_stop)
            bus_ref[0] = bus
            manager, _session = _manager(env, bus)
            try:
                manager.stop_closed_pair(cgroup_root_fd=root_fd, owner_uid=os.getuid())
            finally:
                os.close(root_fd)


# --- A3: every call site hands the owned fragments to the inspector -----------

class _Spy(BootstrapMaskedPairInspector):
    seen = []

    def __init__(self, **kwargs):
        _Spy.seen.append(kwargs.get("expected_fragments"))
        super().__init__(**kwargs)


@pytest.fixture
def spy(monkeypatch):
    _Spy.seen = []
    for module in (bootstrap_manager, bootstrap_close, bootstrap_restore):
        monkeypatch.setattr(module, "BootstrapMaskedPairInspector", _Spy)
    return _Spy


def _all_owned(seen):
    return seen and all(
        type(item) is tuple and tuple(unit for unit, _ in item) == PAIR
        for item in seen)


def test_close_sequence_passes_expected_fragments(spy):
    _close_flow()
    assert len(spy.seen) >= 2 and _all_owned(spy.seen)


def test_restore_sequence_passes_expected_fragments(spy, tmp_path):
    _restore_flow(tmp_path)
    assert len(spy.seen) >= 1 and _all_owned(spy.seen)


def test_stop_closed_pair_sites_pass_expected_fragments(spy, tmp_path):
    _stop_flow(tmp_path)
    # close(), then check_closed around each of two stops and the final close
    # re-check: every construction is owned-fragment bound.
    assert len(spy.seen) >= 6 and _all_owned(spy.seen)


def test_confirm_empty_pair_site_passes_expected_fragments(spy, tmp_path):
    _empty_flow(tmp_path)
    assert len(spy.seen) >= 1 and _all_owned(spy.seen)


def test_withdrawal_sites_pass_expected_fragments(spy, tmp_path):
    _withdraw_flow(tmp_path)
    assert len(spy.seen) >= 3 and _all_owned(spy.seen)
