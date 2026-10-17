"""LoadUnit as the lookup for exactly the published pair, after publication + Reload.

systemd does not load the unreferenced helper pair on its own, so after Reload
GetUnit answers NoSuchUnit. With explicit opt-in flags (default OFF) the start
closure roots, the loaded-unit inspector and the start-side inactive
precondition use Manager.LoadUnit as the lookup for azazel-auditd.service and
azazel-commissiond.service only. No StartUnit, no job. Masked/closed phases and
external units never use it.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import bootstrap_manager as manager_module
from azazel_nexus_runtime.bootstrap_loaded import BootstrapLoadedUnitInspector
from azazel_nexus_runtime.bootstrap_start import BootstrapStartJobs
from azazel_nexus_runtime.bootstrap_start_closure import BootstrapStartClosureInspector
from azazel_nexus_runtime.bootstrap_stop import BootstrapStopJobs
from azazel_nexus_runtime.systemd_bus import _unit_object_path
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_close_sequence import (
    test_close_orders_file_closure_reload_mask_observation_and_drain as _close_flow,
)
from test_runtime_bootstrap_loaded import (
    FakeBus as LoadedFakeBus,
    Message as LoadedMessage,
    OWNER,
    _dependencies,
    _service_settings,
)
from test_runtime_bootstrap_manager_publication import (
    _check_publish,
    _manager_fixture,
    _transaction,
)
from test_runtime_bootstrap_manager_stopped import (
    test_stop_closed_pair_closes_reloads_drains_then_stops_reverse_and_observes as _stop_flow,
)
from test_runtime_bootstrap_masked import FakeBus as MaskedFakeBus
from test_runtime_bootstrap_not_loaded import masked as masked_inspector
from test_runtime_bootstrap_not_loaded import not_loaded as mark_not_loaded
from test_runtime_bootstrap_overlay_files import _environment
from test_runtime_bootstrap_start import FakeBus as StartFakeBus
from test_runtime_bootstrap_start import _complete, make_client
from test_runtime_bootstrap_start_closure import (
    AUDIT,
    COMMISSION,
    CONTROLLER,
    PROFILE_DIGEST,
    FakeBus as ClosureFakeBus,
    _base_graph,
)
from test_runtime_bootstrap_stop import FakeBus as StopFakeBus
from test_runtime_bootstrap_stopped import (
    StoppedFakeBus,
    _private_dir,
    cgroup_root,  # noqa: F401 - pytest fixture
)
from test_runtime_bootstrap_not_loaded import _stopped

NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
PAIR_NAMES = (AUDIT, COMMISSION)
LOAD_ROOTS = frozenset(PAIR_NAMES)
EXTERNAL = "basic.target"


class Lazy:
    """Fake systemd where the named units are unloaded until LoadUnit.

    GetUnit and GetAll on an unloaded unit fail like real systemd. LoadUnit is
    forwarded to the wrapped bus as its GetUnit. Every request is logged.
    """

    def __init__(self, bus, unloaded, *, owner=OWNER, load_path=None, load_sender=...,
                 load_error=None, gc_after_load=False, after=None):
        self.bus, self.unloaded, self.owner = bus, set(unloaded), owner
        self.load_path, self.load_sender = load_path, load_sender
        self.load_error, self.gc_after_load, self.after = load_error, gc_after_load, after
        self.dropped = set()
        self.log = []
        self._original = bus.call
        bus.call = self.call

    def _error(self, name, sender=None):
        return SimpleNamespace(message_type=3, error_name=name, signature="s",
                               body=["x"], sender=sender or self.owner)

    async def call(self, message):
        member = message.member
        body = list(getattr(message, "body", None) or [])
        key = body[0] if member in {"GetUnit", "LoadUnit"} and body else getattr(
            message, "path", None)
        self.log.append((member, key))
        if member == "GetUnit" and body[0] in self.unloaded:
            return self._error(NO_SUCH_UNIT)
        if member == "LoadUnit":
            if self.load_error is not None:
                return self._error(self.load_error)
            self.unloaded.discard(body[0])
            if self.gc_after_load:
                self.dropped.add(_unit_object_path(body[0]))
            proxy = SimpleNamespace(**vars(message))
            proxy.member = "GetUnit"
            reply = SimpleNamespace(**vars(await self._original(proxy)))
            if self.load_path is not None:
                reply.body = [self.load_path]
            if self.load_sender is not ...:
                reply.sender = self.load_sender
            return reply
        if member == "GetAll":
            path = message.path
            if path in self.dropped:
                self.dropped.discard(path)
                return self._error("org.freedesktop.DBus.Error.UnknownObject")
            if any(path == _unit_object_path(name) for name in self.unloaded):
                return self._error("org.freedesktop.DBus.Error.UnknownObject")
        reply = await self._original(message)
        if self.after is not None:
            reply = self.after(message, reply) or reply
        return reply

    def members(self, *names):
        return [entry for entry in self.log if entry[0] in names]


def _closure(bus, *, load_roots=frozenset(), owner=OWNER):
    return BootstrapStartClosureInspector(
        bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
        message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4),
        timeout_seconds=0.5, expected_owner=owner,
        systemd_profile_digest=PROFILE_DIGEST, load_roots=load_roots,
    )


def _loaded(bus, **kwargs):
    return BootstrapLoadedUnitInspector(
        bus=bus, message_factory=LoadedMessage,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1), timeout_seconds=0.5,
        expected_service_settings=_service_settings(), **kwargs,
    )


def _inspect_loaded(inspector, unit=UnitKey.AUDITD):
    return inspector.inspect(unit, expected_dependencies=_dependencies(unit))


FORBIDDEN = {"StartUnit", "StopUnit", "Reload", "MaskUnitFiles", "UnmaskUnitFiles",
             "EnableUnitFiles", "CancelJob", "RestartUnit"}


# --- start closure -----------------------------------------------------------

def test_closure_loads_unloaded_pair_with_loadunit_and_getunit_for_the_controller():
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES)
        observation = await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
        assert set(observation.units) == {CONTROLLER, AUDIT, COMMISSION}
        assert lazy.members("LoadUnit") == [("LoadUnit", n) for n in PAIR_NAMES] * 2
        assert lazy.members("GetUnit") == [("GetUnit", CONTROLLER)] * 2
        assert not {m for m, _ in lazy.log} & FORBIDDEN
    asyncio.run(run())


def test_closure_one_snapshot_exact_call_order():
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES)
        await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
        path = _unit_object_path
        lookup = [e for e in lazy.log if e[0] in {"GetUnit", "LoadUnit", "GetAll"}
                  and e[1] != "/org/freedesktop/systemd1"]
        assert lookup[:6] == [
            ("GetUnit", CONTROLLER), ("GetAll", path(CONTROLLER)),
            ("LoadUnit", AUDIT), ("GetAll", path(AUDIT)),
            ("LoadUnit", COMMISSION), ("GetAll", path(COMMISSION)),
        ]
        assert lookup[6:] == lookup[:6]  # the second snapshot re-asserts the load
    asyncio.run(run())


def test_closure_flags_off_keeps_old_behaviour_and_never_loads():
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES)
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus).inspect()
        assert lazy.members("LoadUnit") == []
        # A loaded pair is read exactly as before.
        plain = ClosureFakeBus()
        await _closure(plain).inspect()
        assert all(c.member != "LoadUnit" for c in plain.calls)
    asyncio.run(run())


def test_closure_loads_only_the_named_roots():
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES)
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus, load_roots=frozenset({AUDIT})).inspect()
        assert lazy.members("LoadUnit") == [("LoadUnit", AUDIT)]
    asyncio.run(run())


def test_closure_external_units_keep_getunit_even_with_load_roots():
    async def run():
        graph = _base_graph()
        graph[AUDIT] = {"Requisite": [CONTROLLER], "Wants": [EXTERNAL]}
        graph[EXTERNAL] = {}
        lazy = Lazy(ClosureFakeBus(graph=graph), PAIR_NAMES)
        await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
        assert ("GetUnit", EXTERNAL) in lazy.log
        assert ("LoadUnit", EXTERNAL) not in lazy.log
        assert {n for m, n in lazy.log if m == "LoadUnit"} == set(PAIR_NAMES)

        graph = _base_graph()
        graph[AUDIT] = {"Requisite": [CONTROLLER], "Wants": [EXTERNAL]}
        graph[EXTERNAL] = {}
        lazy = Lazy(ClosureFakeBus(graph=graph), (*PAIR_NAMES, EXTERNAL))
        with pytest.raises(UnitOperationFailed):  # unloaded external: refuse, not load
            await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
        assert ("LoadUnit", EXTERNAL) not in lazy.log
    asyncio.run(run())


@pytest.mark.parametrize("bad", [
    frozenset({CONTROLLER}), frozenset({EXTERNAL}), frozenset({AUDIT, EXTERNAL}),
    {AUDIT}, [AUDIT], (AUDIT,), "azazel-auditd.service", None,
])
def test_closure_load_roots_must_be_a_frozenset_of_pair_names(bad):
    bus = ClosureFakeBus()
    with pytest.raises(ValueError):
        _closure(bus, load_roots=bad)
    assert bus.calls == []


def test_closure_refuses_wrong_object_path_from_loadunit():
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES, load_path="/org/freedesktop/systemd1/unit/x")
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
        assert [c for c in lazy.log if c[0] == "GetAll" and c[1] == _unit_object_path(AUDIT)] == []
    asyncio.run(run())


@pytest.mark.parametrize("sender", [":1.99", None])
def test_closure_refuses_loadunit_reply_from_other_owner(sender):
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES, load_sender=sender)
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
    asyncio.run(run())


@pytest.mark.parametrize("error", [
    NO_SUCH_UNIT, "org.freedesktop.systemd1.LoadFailed",
    "org.freedesktop.DBus.Error.AccessDenied",
])
def test_closure_refuses_loadunit_errors_including_no_such_unit(error):
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES, load_error=error)
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
        assert [c for c in lazy.log if c[0] == "GetAll"
                and c[1] in {_unit_object_path(n) for n in PAIR_NAMES}] == []
    asyncio.run(run())


def test_closure_refuses_unit_collected_between_load_and_read():
    async def run():
        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES, gc_after_load=True)
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
    asyncio.run(run())


def test_closure_still_refuses_masked_result_after_load():
    async def run():
        def after(message, reply):
            body = reply.body[0] if reply.body else None
            if (isinstance(body, dict) and "LoadState" in body
                    and body["Id"].value == AUDIT):
                body["LoadState"] = type(body["LoadState"])("s", "masked")

        lazy = Lazy(ClosureFakeBus(), PAIR_NAMES, after=after)
        with pytest.raises(UnitOperationFailed):
            await _closure(lazy.bus, load_roots=LOAD_ROOTS).inspect()
    asyncio.run(run())


# --- loaded-unit inspector ----------------------------------------------------

@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
def test_loaded_inspector_loads_unit_per_snapshot_in_exact_order(unit):
    async def run():
        name = UNIT_NAMES[unit]
        lazy = Lazy(LoadedFakeBus(unit), (name,))
        result = await _inspect_loaded(
            _loaded(lazy.bus, expected_owner=OWNER, load_first=True), unit)
        assert result.unit is unit
        assert [(m, k) for m, k in lazy.log if m != "GetNameOwner"] == [
            ("LoadUnit", name), ("GetAll", _unit_object_path(name)),
            ("GetAll", _unit_object_path(name)),
        ] * 2
        assert lazy.members("GetUnit") == []
    asyncio.run(run())


def test_loaded_inspector_flags_off_refuses_not_loaded_and_never_loads():
    async def run():
        lazy = Lazy(LoadedFakeBus(UnitKey.AUDITD), (AUDIT,))
        with pytest.raises(UnitOperationFailed):
            await _inspect_loaded(_loaded(lazy.bus, expected_owner=OWNER))
        assert lazy.members("LoadUnit") == []
        plain = LoadedFakeBus(UnitKey.AUDITD)
        await _inspect_loaded(_loaded(plain))
        assert all(c.member != "LoadUnit" for c in plain.calls)
    asyncio.run(run())


@pytest.mark.parametrize("owner,load_first", [(None, True), (OWNER, 1), (OWNER, "yes")])
def test_loaded_inspector_load_first_requires_pinned_owner_and_bool(owner, load_first):
    bus = LoadedFakeBus(UnitKey.AUDITD)
    with pytest.raises(ValueError):
        _loaded(bus, expected_owner=owner, load_first=load_first)
    assert bus.calls == []


@pytest.mark.parametrize("options", [
    {"load_path": "/org/freedesktop/systemd1/unit/other"},
    {"load_sender": ":1.99"}, {"load_sender": None},
    {"load_error": NO_SUCH_UNIT}, {"gc_after_load": True},
])
def test_loaded_inspector_refuses_bad_load_results(options):
    async def run():
        lazy = Lazy(LoadedFakeBus(UnitKey.AUDITD), (AUDIT,), **options)
        with pytest.raises(UnitOperationFailed):
            await _inspect_loaded(_loaded(lazy.bus, expected_owner=OWNER, load_first=True))
    asyncio.run(run())


def test_loaded_inspector_enclosing_owner_mismatch_refuses_before_any_load():
    async def run():
        lazy = Lazy(LoadedFakeBus(UnitKey.AUDITD), (AUDIT,))
        with pytest.raises(UnitOperationFailed):
            await _inspect_loaded(_loaded(lazy.bus, expected_owner=":1.99", load_first=True))
        assert lazy.members("LoadUnit") == []
    asyncio.run(run())


# --- the private helper ---------------------------------------------------------

def _reader(bus, *, owner=OWNER, manager_owner=OWNER):
    reader = BootstrapStopJobs(
        bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=0.5, expected_owner=owner,
    )
    reader._manager_owner = manager_owner
    return reader


@pytest.mark.parametrize("name", [
    CONTROLLER, EXTERNAL, "AZAZEL-AUDITD.SERVICE", "azazel-auditd.service\n",
    "azazel-auditd.service ", "", None, 7, b"azazel-auditd.service",
    "azazel-auditd@x.service", "../azazel-auditd.service",
])
def test_load_helper_accepts_only_the_two_pair_names_before_any_call(name):
    async def run():
        bus = LoadedFakeBus(UnitKey.AUDITD)
        reader = _reader(bus)
        with pytest.raises(UnitOperationFailed):
            await reader._bounded(reader._load_pair_unit(
                name, _unit_object_path(name) if isinstance(name, str) else "/x"))
        assert bus.calls == []
    asyncio.run(run())


def test_load_helper_requires_exact_object_path_argument_and_owner_pin():
    async def run():
        bus = LoadedFakeBus(UnitKey.AUDITD)
        for reader, path in (
            (_reader(bus), _unit_object_path(COMMISSION)),
            (_reader(bus), "/org/freedesktop/systemd1/unit/azazel_2dauditd_2eservice_"),
            (_reader(bus, owner=None), _unit_object_path(AUDIT)),
            (_reader(bus, manager_owner=None), _unit_object_path(AUDIT)),
            (_reader(bus, manager_owner=":1.99"), _unit_object_path(AUDIT)),
        ):
            with pytest.raises(UnitOperationFailed):
                await reader._bounded(reader._load_pair_unit(AUDIT, path))
        assert bus.calls == []
        lazy = Lazy(bus, ())
        reader = _reader(bus)
        await reader._bounded(reader._load_pair_unit(AUDIT, _unit_object_path(AUDIT)))
        assert lazy.members("LoadUnit") == [("LoadUnit", AUDIT)]
        assert [c.member for c in bus.calls] == ["GetUnit"]
    asyncio.run(run())


# --- start-side inactive precondition ---------------------------------------------

def _start_client(bus, **kwargs):
    client = make_client(bus, expected_owner=bus.owner)
    if kwargs.get("load_first"):
        client = BootstrapStartJobs(
            bus=bus, message_factory=lambda **f: SimpleNamespace(**f),
            message_type=SimpleNamespace(METHOD_RETURN=StartFakeBus.METHOD_RETURN,
                                         SIGNAL=StartFakeBus.SIGNAL),
            timeout_seconds=0.5, check_start=lambda: None,
            expected_owner=bus.owner, load_first=True,
        )
    return client


def test_start_precondition_loads_pair_unit_then_reads_inactive_before_start():
    async def run():
        bus = StartFakeBus()
        bus.start_reply_hook = lambda: _complete(bus, UnitKey.AUDITD)
        lazy = Lazy(bus, (AUDIT,), owner=bus.owner)
        await _start_client(bus, load_first=True).start_and_wait(UnitKey.AUDITD)
        order = [m for m, _ in lazy.log]
        assert [e for e in lazy.log if e[0] == "LoadUnit"] == [("LoadUnit", AUDIT)]
        assert order.index("LoadUnit") < order.index("Get") < order.index("StartUnit")
        assert order.index("LoadUnit") < order.index("AddMatch")
        # The post-job "active" check is a plain GetUnit again.
        assert [e for e in lazy.log if e[0] == "GetUnit"] == [("GetUnit", AUDIT)]
        assert order.index("GetUnit") > order.index("StartUnit")
    asyncio.run(run())


def test_start_precondition_flag_off_refuses_not_loaded_before_subscription():
    async def run():
        bus = StartFakeBus()
        lazy = Lazy(bus, (AUDIT,), owner=bus.owner)
        with pytest.raises(UnitOperationFailed):
            await make_client(bus, expected_owner=bus.owner).start_and_wait(UnitKey.AUDITD)
        members = {m for m, _ in lazy.log}
        assert not members & {"LoadUnit", "StartUnit", "AddMatch", "Subscribe"}
    asyncio.run(run())


@pytest.mark.parametrize("options", [
    {"load_path": "/org/freedesktop/systemd1/unit/other"},
    {"load_sender": ":1.99"}, {"load_error": NO_SUCH_UNIT},
])
def test_start_precondition_bad_load_never_submits_start(options):
    async def run():
        bus = StartFakeBus()
        lazy = Lazy(bus, (AUDIT,), owner=bus.owner, **options)
        with pytest.raises(UnitOperationFailed):
            await _start_client(bus, load_first=True).start_and_wait(UnitKey.AUDITD)
        assert not {m for m, _ in lazy.log} & {"StartUnit", "AddMatch", "Subscribe"}
    asyncio.run(run())


# --- masked / closed phases never use LoadUnit ------------------------------------

@pytest.fixture
def no_load(monkeypatch):
    async def forbidden(self, name, path):
        raise AssertionError("LoadUnit used outside the published-pair lookup")

    monkeypatch.setattr(BootstrapStopJobs, "_load_pair_unit", forbidden)


def test_masked_inspector_never_calls_loadunit(no_load):
    async def run():
        for bus in (MaskedFakeBus(), mark_not_loaded(MaskedFakeBus(), {AUDIT, COMMISSION})):
            await masked_inspector(bus).inspect()
            assert all(c.member != "LoadUnit" for c in bus.calls)
    asyncio.run(run())


def test_stopped_inspector_never_calls_loadunit(no_load, cgroup_root):  # noqa: F811
    async def run():
        root, fd = cgroup_root
        _private_dir(root / "system.slice")
        bus = mark_not_loaded(StoppedFakeBus(), {AUDIT, COMMISSION})
        await _stopped(bus, fd).inspect()
        assert all(c.member != "LoadUnit" for c in bus.calls)
    asyncio.run(run())


def test_stop_job_never_calls_loadunit(no_load):
    async def run():
        from test_runtime_bootstrap_not_loaded import _stop_bus, _stop_client

        bus = _stop_bus()
        await _stop_client(bus).stop_and_wait(UnitKey.AUDITD)
        plain = StopFakeBus()
        plain.stop_reply_hook = lambda: plain.signal()
        await _stop_client(plain).stop_and_wait(UnitKey.AUDITD)
        assert all(c.member != "LoadUnit" for b in (bus, plain) for c in b.calls)
    asyncio.run(run())


def test_close_and_stop_flows_never_call_loadunit(no_load, tmp_path):
    _close_flow()
    _stop_flow(tmp_path)


# --- manager composition ------------------------------------------------------------

def test_publication_loads_unloaded_pair_after_reload_in_exact_order(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        lazy = Lazy(bus, PAIR_NAMES)
        _published, observations = manager._publish_and_inspect_pair(
            _transaction(approval), approval=approval, check_publish=_check_publish([]),
        )
        assert len(observations) == 2
        members = [m for m, _ in lazy.log]
        pair_lookups = [e for e in lazy.log
                        if e[0] in {"GetUnit", "LoadUnit"} and e[1] in PAIR_NAMES]
        assert pair_lookups and all(m == "LoadUnit" for m, _ in pair_lookups)
        assert members.index("Reload") < members.index("LoadUnit")
        # closure x2 (auditd, commissiond) and loaded inspector x2 per unit.
        closure_pass = [AUDIT, COMMISSION, AUDIT, COMMISSION]  # two snapshots
        assert [n for _, n in pair_lookups] == [
            *closure_pass,
            AUDIT, AUDIT, COMMISSION, COMMISSION,  # loaded inspectors (2 snapshots each)
            *closure_pass,  # repeated closure inspection
        ]
        assert not {m for m, _ in lazy.log} & {"StartUnit", "StopUnit", "MaskUnitFiles"}
        assert bus.reload_count == 1

        # Retained re-check: the pair may have been collected again since.
        lazy.unloaded.update(PAIR_NAMES)
        lazy.log.clear()
        manager._check_retained_publication()
        again = [e for e in lazy.log if e[0] in {"GetUnit", "LoadUnit"} and e[1] in PAIR_NAMES]
        assert again and all(m == "LoadUnit" for m, _ in again)
        assert [n for _, n in again] == [
            *closure_pass, AUDIT, AUDIT, COMMISSION, COMMISSION, *closure_pass,
        ]
        assert bus.reload_count == 1


def test_publication_refuses_when_mask_remains_effective_after_load(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)

        def after(message, reply):
            body = reply.body[0] if reply.body else None
            if (isinstance(body, dict) and "LoadState" in body
                    and body.get("Id") is not None and body["Id"].value == AUDIT):
                body["LoadState"] = type(body["LoadState"])("s", "masked")

        Lazy(bus, PAIR_NAMES, after=after)
        with pytest.raises(UnitOperationFailed):
            manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=_check_publish([]),
            )
        assert bus.disconnected and all(session.closed for session in sessions)


def test_flags_are_on_only_for_publication_retained_and_start_composition(
        tmp_path, monkeypatch):
    closures, loadeds, starts = [], [], []

    class ClosureSpy(BootstrapStartClosureInspector):
        def __init__(self, **kwargs):
            closures.append(kwargs.get("load_roots"))
            super().__init__(**kwargs)

    class LoadedSpy(BootstrapLoadedUnitInspector):
        def __init__(self, **kwargs):
            loadeds.append(kwargs.get("load_first"))
            super().__init__(**kwargs)

    class StartSpy:
        def __init__(self, **kwargs):
            starts.append(kwargs.get("load_first"))
            raise UnitOperationFailed("spy")

    monkeypatch.setattr(manager_module, "BootstrapStartClosureInspector", ClosureSpy)
    monkeypatch.setattr(manager_module, "BootstrapLoadedUnitInspector", LoadedSpy)
    monkeypatch.setattr(manager_module, "BootstrapStartJobs", StartSpy)
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        Lazy(bus, PAIR_NAMES)
        manager._publish_and_inspect_pair(
            _transaction(approval), approval=approval, check_publish=_check_publish([]),
        )
        assert closures == [LOAD_ROOTS] * 2 and loadeds == [True] * 2
        manager._check_retained_publication()
        assert closures == [LOAD_ROOTS] * 4 and loadeds == [True] * 4
        manager._controller_ready_confirmed = True
        with pytest.raises(UnitOperationFailed):
            manager._run_owned_start(
                UnitKey.AUDITD, expected_owner=OWNER, check_start=lambda *a: None)
        assert starts == [True]


def test_defaults_are_off():
    import inspect

    assert inspect.signature(BootstrapStartClosureInspector).parameters[
        "load_roots"].default == frozenset()
    assert inspect.signature(BootstrapLoadedUnitInspector).parameters[
        "load_first"].default is False
    assert inspect.signature(BootstrapStartJobs).parameters["load_first"].default is False
    assert inspect.signature(BootstrapStopJobs).parameters["load_first"].default is False
