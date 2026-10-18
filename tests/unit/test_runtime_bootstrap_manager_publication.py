"""Manager-owned publication, Reload and loaded-pair inspection composition."""

import asyncio
from dataclasses import replace
import json
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_grant_transaction import advance_transaction
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_manager as manager_module
from azazel_nexus_runtime.bootstrap_loaded_policy import decode_loaded_bootstrap_policy
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_masked import MaskedBootstrapPair
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    bootstrap_systemd_profile_digest,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_loaded import (
    DBUS_INTERFACE,
    DEPENDENCY_KEYS,
    MANAGER_INTERFACE,
    MANAGER_PATH,
    OWNER,
    PROPERTIES_INTERFACE,
    SYSTEMD_OWNER_DESTINATION,
    UNIT_INTERFACE,
    Variant,
    _object_path,
    _reply,
    _service_properties,
    _unit_properties,
)
from test_runtime_bootstrap_loaded_policy import SETTINGS as DEFAULT_SETTINGS
from test_runtime_bootstrap_loaded_policy import _document, _pinned
from test_runtime_bootstrap_manager import FakeSystemdBusSession
from test_runtime_bootstrap_controller import FakeBus as ControllerFakeBus, IDENTITY as CONTROLLER_IDENTITY
from test_runtime_bootstrap_device_closure import (
    DEVICE_INTERFACE, DEVICE_NAMES, DeviceFakeBus, _graph as _device_graph,
)
from test_runtime_bootstrap_masked import PROFILE_PATHS, PROFILE_VERSION
from test_runtime_bootstrap_overlay_files import PAIR, _approval, _environment
from azazel_nexus_runtime import bootstrap_overlay_files


PROFILE = observe_bootstrap_systemd_profile(
    version=PROFILE_VERSION, unit_path=PROFILE_PATHS,
)
PROFILE_DIGEST = bootstrap_systemd_profile_digest(PROFILE)


class CombinedLoadedBus:
    """Loaded-unit fixture extended with profile and Reload replies."""

    def __init__(self, *, fault=None, file_path=None):
        self.owner = OWNER
        self.calls = []
        self.disconnected = False
        self.profile_calls = 0
        self.reload_count = 0
        self.property_count = 0
        self.unit_get_counts = {}
        self.fault = fault
        self.file_path = file_path
        self.fault_reached = False
        self.unit = UnitKey.AUDITD
        self.unit_name = UNIT_NAMES[self.unit]
        self.path = _object_path(self.unit_name)
        self.controller = ControllerFakeBus(phase="pre-ready")
        self.device_bus = None
        self.audit_device_edge = False

    async def call(self, message):
        if message.member == "LoadUnit":  # fake: LoadUnit is the same lookup as GetUnit
            message.member = "GetUnit"
        if self.device_bus is not None:
            if message.member == "ListUnitsByPatterns":
                return await self.device_bus.call(message)
            if (message.member == "GetUnit" and message.body
                    and message.body[0] in self.device_bus.device_rows):
                return await self.device_bus.call(message)
            device_paths = {
                _object_path(name) for name in self.device_bus.device_rows
            }
            if (message.member == "GetAll" and message.path in device_paths
                    and message.interface == PROPERTIES_INTERFACE
                    and message.body in ([UNIT_INTERFACE], [DEVICE_INTERFACE])):
                return await self.device_bus.call(message)
        if ((message.member == "GetUnit" and message.body == ["azazel-activated.service"])
                or (message.member == "GetAll"
                    and message.path == _object_path("azazel-activated.service"))):
            self.calls.append(message)
            return await self.controller.call(message)
        if message.member == "Reload":
            self.calls.append(message)
            assert message.destination == OWNER
            assert message.path == MANAGER_PATH
            assert message.interface == MANAGER_INTERFACE
            assert message.signature == "" and message.body == []
            self.reload_count += 1
            if self.fault == "reload-error":
                self.fault_reached = True
                reply = _reply("", sender=OWNER)
                reply.message_type = 3
                return reply
            if self.fault == "reload-timeout":
                self.fault_reached = True
                await asyncio.Future()
            if self.fault == "file-mutation-during-reload":
                self.fault_reached = True
                with self.file_path.open("r+b") as stream:
                    data = stream.read()
                    stream.seek(0)
                    stream.write(bytes([data[0] ^ 1]) + data[1:])
                    stream.flush()
            if self.fault == "owner-after-reload":
                self.fault_reached = True
                self.owner = ":1.99"
            if self.fault == "profile-after-reload":
                self.fault_reached = True
                self.profile_drift = True
            return _reply("", sender=OWNER)

        if (message.member == "GetAll" and message.path == MANAGER_PATH
                and message.interface == PROPERTIES_INTERFACE
                and message.body == [MANAGER_INTERFACE]):
            self.calls.append(message)
            self.profile_calls += 1
            version = PROFILE_VERSION
            if self.fault == "profile-before-reload":
                version = "257.13-2~deb13u1"
                self.fault_reached = True
            elif getattr(self, "profile_drift", False):
                version = "257.13-2~deb13u1"
                self.fault_reached = True
            reply = _reply("a{sv}", {
                "Version": Variant("s", version),
                "UnitPath": Variant("as", list(PROFILE_PATHS)),
            }, sender=OWNER)
            if self.fault == "owner-before-reload":
                self.fault_reached = True
                self.owner = ":1.99"
            return reply

        external_paths = getattr(self, "external_paths", {})
        if message.member == "GetUnit" and message.body[0] not in UNIT_NAMES.values():
            self.calls.append(message)
            name = message.body[0]
            path = _object_path(name)
            self.external_paths = {**external_paths, name: path}
            return _reply("o", path, sender=OWNER)
        if (message.member == "GetAll" and message.path in external_paths.values()
                and message.body == [UNIT_INTERFACE]):
            self.calls.append(message)
            name = next(name for name, path in external_paths.items()
                        if path == message.path)
            properties = {
                "Id": Variant("s", name),
                "Names": Variant("as", [name]),
                "Following": Variant("s", ""),
                "LoadState": Variant("s", "loaded"),
                "ActiveState": Variant("s", "active"),
                "NeedDaemonReload": Variant("b", False),
                "Job": Variant("(uo)", [0, "/"]),
            }
            properties.update({key: Variant("as", []) for key in DEPENDENCY_KEYS})
            return _reply("a{sv}", properties, sender=OWNER)

        if message.member == "GetUnit":
            self.unit_name = message.body[0]
            self.unit = next(unit for unit, name in UNIT_NAMES.items()
                             if name == self.unit_name)
            self.unit_get_counts[self.unit_name] = (
                self.unit_get_counts.get(self.unit_name, 0) + 1
            )
            self.path = _object_path(self.unit_name)
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            assert message.path == "/org/freedesktop/DBus"
            assert message.interface == DBUS_INTERFACE
            assert message.member == "GetNameOwner"
            return _reply("s", self.owner, sender="org.freedesktop.DBus")

        assert message.destination == SYSTEMD_OWNER_DESTINATION
        if message.interface == MANAGER_INTERFACE:
            assert message.path == MANAGER_PATH
            assert message.member == "GetUnit"
            return _reply("o", self.path, sender=OWNER)

        assert message.interface == PROPERTIES_INTERFACE
        assert message.path == self.path
        assert message.member == "GetAll" and message.signature == "s"
        assert len(message.body) == 1
        self.property_count += 1
        if message.body[0] == UNIT_INTERFACE:
            properties = _unit_properties(self.unit_name, self.path)
            # BootstrapStartClosureInspector consumes these same shared
            # dependency properties plus the graph node's current state.
            properties["ActiveState"] = Variant("s", "active")
            properties["Job"] = Variant("(uo)", [0, "/"])
            if self.audit_device_edge and self.unit_name == UNIT_NAMES[UnitKey.AUDITD]:
                properties["Requires"] = Variant("as", sorted({
                    *properties["Requires"].value, DEVICE_NAMES[0],
                }))
                properties["After"] = Variant("as", sorted({
                    *properties["After"].value, DEVICE_NAMES[0],
                }))
            if getattr(self, "retained_dependency_drift", False):
                properties["Wants"] = Variant("as", ["basic.target"])
            if (self.fault == "loaded-mismatch" and self.reload_count
                    and self.unit is UnitKey.AUDITD
                    and self.unit_get_counts[self.unit_name] == 3):
                self.fault_reached = True
                properties["NeedDaemonReload"] = Variant("b", True)
            if (self.fault == "second-inspector-mismatch" and self.reload_count
                    and self.unit is UnitKey.COMMISSIOND
                    and self.unit_get_counts[self.unit_name] == 3):
                self.fault_reached = True
                properties["NeedDaemonReload"] = Variant("b", True)
        elif message.body[0] == "org.freedesktop.systemd1.Service":
            properties = _service_properties(self.unit)
        else:
            raise AssertionError(message.body)
        return _reply("a{sv}", properties, sender=OWNER)

    def disconnect(self):
        self.disconnected = True


def _policy():
    document = _document()
    document["systemd_profile_digest"] = PROFILE_DIGEST
    for record in document["units"].values():
        record["service_settings"] = {
            **DEFAULT_SETTINGS,
            "TimeoutStartUSec": 101,
            "TimeoutStopUSec": 202,
            "RuntimeMaxUSec": 303,
            "WatchdogUSec": 404,
        }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return decode_loaded_bootstrap_policy(
        raw, prestart_policy=_pinned(raw, profile_digest=PROFILE_DIGEST)
    )


def _transaction(approval):
    intent = bootstrap_overlay_files.new_overlay_intent(approval)
    return GrantTransaction(
        boot_id=approval.context.boot_id,
        context_digest="sha256:" + intent.context_digest,
        approval_digest=approval.payload_digest,
        generation=approval.context.generation,
        generation_digest=approval.context.generation_digest,
        grant_id=intent.grant_id,
        unit_payload_digests=intent.payload_digests,
        phase="pair_grant_intent",
    )


def _manager_fixture(env, monkeypatch, *, fault=None, policy_change=False,
                     manager_type=BootstrapNarrowingManager, job_timeout_seconds=5.0):
    monkeypatch.setattr(manager_module, "current_bootstrap_controller_identity",
                        lambda: CONTROLLER_IDENTITY)
    approval = _approval()
    policy = _policy()
    bus = CombinedLoadedBus(
        fault=fault,
        file_path=env["overlay_path"] / PAIR[0],
    )
    sessions = []

    def session_factory():
        session = FakeSystemdBusSession(bus=bus)
        sessions.append(session)
        return session

    manager = manager_type(
        job_timeout_seconds=job_timeout_seconds,
        session_factory=session_factory,
    )
    checks = []
    directories = SimpleNamespace(
        arguments={
            "overlay_fd": env["overlay_fd"],
            "masks_fd": env["masks_fd"],
            "higher_priority_fd": env["higher_fd"],
        },
        owner_uid=os.getuid(),
        check=lambda: checks.append("directories.check"),
    )
    manager._publication_inputs = (directories, env["store"], env["guard"])
    manager._closed_observation = MaskedBootstrapPair(
        owner=OWNER,
        fragments=tuple(
            (unit, str(env["masks_path"] / UNIT_NAMES[unit]))
            for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND)
        ),
        fingerprint="sha256:" + "a" * 64,
    )
    confirm_calls = []

    def confirm_empty_pair():
        confirm_calls.append(True)
        return None

    manager.confirm_empty_pair = confirm_empty_pair
    policy_calls = []

    def load_policy(*, expected):
        policy_calls.append(expected)
        if policy_change and len(policy_calls) == 2:
            return replace(policy, digest="sha256:" + "f" * 64)
        return policy

    monkeypatch.setattr(manager_module, "load_loaded_bootstrap_policy", load_policy)
    return manager, sessions, bus, approval, policy, policy_calls, confirm_calls, checks


def _check_publish(calls, *, result=None):
    def check():
        calls.append(True)
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return result
    return check


def test_manager_publishes_reloads_and_inspects_both_units_on_one_owned_session(
    tmp_path, monkeypatch,
):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, policy, policy_calls, confirms, checks = (
            _manager_fixture(env, monkeypatch)
        )
        expected = manager._closed_observation
        tx = _transaction(approval)
        callback_calls = []

        published, inspected = manager._publish_and_inspect_pair(
            tx, approval=approval, check_publish=_check_publish(callback_calls)
        )

        assert published.phase == "published"
        assert env["store"].load() == published
        assert tuple(item.unit for item in inspected) == (
            UnitKey.AUDITD, UnitKey.COMMISSIOND,
        )
        assert all(item.owner == OWNER for item in inspected)
        assert len(callback_calls) >= 1
        assert policy_calls == [approval.context, approval.context]
        assert confirms == [True]
        assert manager._closed_observation is None
        assert [call.member for call in bus.calls].count("Reload") == 1
        assert {call.member for call in bus.calls} <= {
            "GetNameOwner", "GetUnit", "GetAll", "Reload",
        }
        assert bus.reload_count == 1
        session, = sessions
        assert bus.disconnected and session.closed and session._loop.is_closed()
        assert len({id(call) for call in bus.calls}) == len(bus.calls)
        assert checks
        assert expected.owner == OWNER


def test_retained_publication_rechecks_without_reloading(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, _policy_value, policy_calls, *_ = (
            _manager_fixture(env, monkeypatch)
        )
        manager._publish_and_inspect_pair(
            _transaction(approval), approval=approval, check_publish=_check_publish([]),
        )
        reloads = bus.reload_count
        sessions_before = len(sessions)

        assert manager._check_retained_publication() is None

        assert bus.reload_count == reloads == 1
        assert len(sessions) == sessions_before + 1
        assert policy_calls[-1] == approval.context
        assert manager._publication_check is not None
        assert bus.disconnected and all(session.closed for session in sessions)


def test_retained_bound_audit_refuses_hidden_same_sysfs_sibling_before_start(
    tmp_path, monkeypatch,
):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        # Pin the audit-to-device edge in the ordinary loaded policy before
        # publication.  The initial follower graph is valid and has no service
        # activation effect.
        document = _document()
        document["systemd_profile_digest"] = PROFILE_DIGEST
        audit_record = document["units"][UNIT_NAMES[UnitKey.AUDITD]]
        for relation in ("Requires", "After"):
            audit_record["dependencies"][relation] = sorted({
                *audit_record["dependencies"][relation], DEVICE_NAMES[0],
            })
        settings = _policy().units[UnitKey.AUDITD].service_settings
        for record in document["units"].values():
            record["service_settings"] = dict(settings)
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        policy = decode_loaded_bootstrap_policy(
            raw, prestart_policy=_pinned(raw, profile_digest=PROFILE_DIGEST),
        )
        monkeypatch.setattr(
            manager_module, "load_loaded_bootstrap_policy", lambda **_: policy,
        )
        bus.device_bus = DeviceFakeBus(graph=_device_graph(include_alias=False))
        bus.audit_device_edge = True
        grant = _transaction(approval)
        published, _ = manager._publish_and_inspect_pair(
            grant, approval=approval, check_publish=_check_publish([]),
        )
        # Only the sibling's deeper graph changes; root properties still match
        # the already-published/pinned loaded policy exactly.
        bus.device_bus.graph[DEVICE_NAMES[1]]["Wants"] = ["hidden-helper.service"]
        manager._controller_ready_confirmed = True
        bus.controller.phase = "ready"
        transaction = advance_transaction(
            advance_transaction(grant, "pair_grant_opened"), "auditd_start_intent",
        )
        reloads = bus.reload_count

        with pytest.raises(UnitOperationFailed, match="external activation refused"):
            manager._start_bound_audit(transaction, check_start=lambda: None)

        assert not any(call.member == "StartUnit" for call in bus.calls)
        assert not any(call.member == "StartUnit" for call in bus.device_bus.calls)
        assert bus.reload_count == reloads == 1
        assert env["store"].load() == published
        assert published.phase == "published"
        assert bus.device_bus.inventory_reads >= 1
        assert bus.disconnected and all(
            session.closed and session._loop.is_closed() for session in sessions
        )


@pytest.mark.parametrize("change", ["file", "journal", "mask", "policy", "owner", "loaded-dependencies"])
def test_retained_publication_refuses_changed_inputs(tmp_path, monkeypatch, change):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, policy, *_ = _manager_fixture(env, monkeypatch)
        manager._publish_and_inspect_pair(
            _transaction(approval), approval=approval, check_publish=_check_publish([]),
        )
        if change == "file":
            dropin = env["overlay_path"] / PAIR[0]
            with dropin.open("r+b") as stream:
                contents = stream.read()
                stream.seek(0)
                stream.write(bytes([contents[0] ^ 1]) + contents[1:])
                stream.flush()
        elif change == "journal":
            (env["journal_path"] / "overlay-journal.json").write_bytes(b"{}\n")
        elif change == "mask":
            mask = env["masks_path"] / PAIR[0]
            mask.unlink()
            mask.symlink_to("/dev/null")  # same target, different retained identity
        elif change == "policy":
            monkeypatch.setattr(
                manager_module, "load_loaded_bootstrap_policy",
                lambda *, expected: replace(policy, digest="sha256:" + "e" * 64),
            )
        elif change == "owner":
            bus.owner = ":1.99"
        else:
            bus.retained_dependency_drift = True

        with pytest.raises((ApprovalRefused, UnitOperationFailed)):
            manager._check_retained_publication()

        assert bus.reload_count == 1
        assert bus.disconnected and all(session.closed for session in sessions)


def test_close_starts_clears_retained_publication_before_fence_failure(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        manager._publish_and_inspect_pair(
            _transaction(approval), approval=approval, check_publish=_check_publish([]),
        )
        assert callable(manager._publication_check)

        # This fixture has no retained closure fence, so close_starts refuses;
        # clearing the now-stale publication callback must happen first.
        with pytest.raises(UnitOperationFailed, match="start-job fence unavailable"):
            manager.close_starts()

        assert manager._publication_check is None
        with pytest.raises(UnitOperationFailed, match="retained publication admission unavailable"):
            manager._check_retained_publication()
        assert bus.reload_count == 1
        assert bus.disconnected and all(session.closed for session in sessions)


@pytest.mark.parametrize("fault", [
    "owner-before-reload", "owner-after-reload",
    "profile-before-reload", "profile-after-reload",
    "reload-error", "reload-timeout", "file-mutation-during-reload",
    "loaded-mismatch", "second-inspector-mismatch",
])
def test_manager_publication_faults_refuse_and_close_single_session(
    tmp_path, monkeypatch, fault,
):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, _policy_value, _policy_calls, _confirms, _checks = (
            # Only the hanging Reload needs a short bound to reach its deadline.
            _manager_fixture(env, monkeypatch, fault=fault,
                             # The deadline case must still reach the injected Reload hang
                             # before its bound fires; 0.05 s did not under CPU load.
                             job_timeout_seconds=1.0 if fault == "reload-timeout" else 5.0)
        )
        expected_error = (
            "loaded bootstrap observation refused"
            if fault in {"loaded-mismatch", "second-inspector-mismatch"}
                else "publication systemd profile changed"
            if fault in {"profile-before-reload", "profile-after-reload"}
            else "publication manager owner changed"
            if fault in {"owner-before-reload", "owner-after-reload"}
            else None
        )
        expected_exception = TimeoutError if fault == "reload-timeout" else (
            ApprovalRefused if fault == "file-mutation-during-reload" else UnitOperationFailed
        )
        with pytest.raises(expected_exception) as caught:
            manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=_check_publish([])
            )
        if expected_error is not None:
            assert expected_error in str(caught.value)
        assert bus.fault_reached, f"fixture fault {fault!r} was not reached"
        if fault == "second-inspector-mismatch":
            assert [call.body[0] for call in bus.calls if call.member == "GetUnit"
                    and call.body[0] in PAIR] == [
                UNIT_NAMES[UnitKey.AUDITD], UNIT_NAMES[UnitKey.COMMISSIOND],
                UNIT_NAMES[UnitKey.AUDITD], UNIT_NAMES[UnitKey.COMMISSIOND],
                UNIT_NAMES[UnitKey.AUDITD], UNIT_NAMES[UnitKey.AUDITD],
                UNIT_NAMES[UnitKey.COMMISSIOND],
            ]
        session, = sessions
        assert bus.disconnected and session.closed and session._loop.is_closed()
        assert bus.reload_count == (0 if fault.endswith("before-reload") else 1)
        assert manager._closed_observation is None


def test_manager_refuses_preflight_before_publication_or_bus_session(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, _policy_value, _policy_calls, confirms, _checks = (
            _manager_fixture(env, monkeypatch)
        )
        manager.confirm_empty_pair = lambda: False

        with pytest.raises(UnitOperationFailed):
            manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=_check_publish([])
            )

        assert confirms == []
        assert manager._closed_observation is not None
        assert env["store"].load_optional() is None
        assert list(env["overlay_path"].iterdir()) == []
        assert not bus.calls
        assert not sessions  # The session factory is not called on preflight refusal.


def test_manager_refuses_final_loaded_policy_change(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, _policy_value, calls, _confirms, _checks = (
            _manager_fixture(env, monkeypatch, policy_change=True)
        )
        with pytest.raises(UnitOperationFailed):
            manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=_check_publish([])
            )

        assert calls == [approval.context, approval.context]
        session, = sessions
        assert bus.disconnected and session.closed and session._loop.is_closed()
        assert env["store"].load_optional().phase == "published"
        assert manager._closed_observation is None


def test_manager_has_no_full_check_after_session_close_and_keeps_journal(
    tmp_path, monkeypatch,
):
    # The trailing checkpoint after the owned session closes was removed as
    # redundant: bootstrap's check_publish() runs immediately after open_pair
    # returns. No full check may fire once the bus has been used.
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, _policy_value, _policy_calls, _confirms, _checks = (
            _manager_fixture(env, monkeypatch)
        )

        calls = []
        calls_after_bus = []

        def check_publish():
            calls.append(True)
            with pytest.raises(RuntimeError, match="no running event loop"):
                asyncio.get_running_loop()
            if bus.calls:
                calls_after_bus.append(True)
            return None

        manager._publish_and_inspect_pair(
            _transaction(approval), approval=approval, check_publish=check_publish,
        )

        published = env["store"].load_optional()
        assert published is not None and published.phase == "published"
        assert calls and calls_after_bus == []
        assert manager._closed_observation is None
        session, = sessions
        assert bus.disconnected and session.closed and session._loop.is_closed()


@pytest.mark.parametrize("fault", [None, "before-pair", "after-pair", "alias-between-observers"])
def test_manager_observes_external_prerequisites_around_loaded_pair(tmp_path, monkeypatch, fault):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        document = _document()
        document["systemd_profile_digest"] = PROFILE_DIGEST
        for record in document["units"].values():
            record["dependencies"]["Wants"] = ["basic.target"]
            record["dependencies"]["After"] = sorted({
                *record["dependencies"]["After"], "basic.target",
            })
            record["service_settings"] = _policy().units[UnitKey.AUDITD].service_settings
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        policy = decode_loaded_bootstrap_policy(
            raw, prestart_policy=_pinned(raw, profile_digest=PROFILE_DIGEST),
        )
        monkeypatch.setattr(manager_module, "load_loaded_bootstrap_policy", lambda **_: policy)
        original = bus.call
        external_path = _object_path("basic.target")
        external_reads = []
        helper_gets = []

        async def call(message):
            if message.member == "GetUnit" and message.body == ["basic.target"]:
                bus.calls.append(message)
                return _reply("o", external_path)
            if message.path == external_path and message.member == "GetAll":
                bus.calls.append(message)
                read_index = len(external_reads)
                external_reads.append(len(helper_gets))
                inactive = (
                    fault == "before-pair" and read_index >= 2
                ) or (
                    fault == "after-pair" and read_index >= 4
                    and len(helper_gets) >= 8
                )
                properties = {
                    "Id": Variant("s", "basic.target"),
                    "Names": Variant("as", ["basic.target"] + (
                        ["alias.target"]
                        if fault == "alias-between-observers" and read_index == 5
                        else []
                    )),
                    "Following": Variant("s", ""),
                    "LoadState": Variant("s", "loaded"),
                    "ActiveState": Variant("s", "inactive" if inactive else "active"),
                    "NeedDaemonReload": Variant("b", False),
                    "Job": Variant("(uo)", [0, "/"]),
                }
                properties.update({
                    key: Variant("as", [])
                    for key in (
                        "Requires", "Wants", "BindsTo", "Upholds", "UpheldBy",
                        "OnFailure", "OnSuccess", "OnFailureOf", "OnSuccessOf",
                        "Triggers", "TriggeredBy",
                    )
                })
                return _reply("a{sv}", properties)
            if message.member in {"GetUnit", "LoadUnit"} and message.body[0] in PAIR:
                helper_gets.append(message.body[0])
            reply = await original(message)
            if (message.member == "GetAll" and message.body == [UNIT_INTERFACE]
                    and reply.body[0]["Id"].value in PAIR):
                reply.body[0]["Wants"] = Variant("as", ["basic.target"])
                reply.body[0]["After"] = Variant("as", sorted({
                    *reply.body[0]["After"].value, "basic.target",
                }))
            return reply

        bus.call = call
        if fault:
            with pytest.raises(UnitOperationFailed):
                manager._publish_and_inspect_pair(
                    _transaction(approval), approval=approval, check_publish=_check_publish([]),
                )
            assert len(helper_gets) == (4 if fault == "before-pair" else 8)
        else:
            _, observations = manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=_check_publish([]),
            )
            assert len(observations) == 2
            assert external_reads == [2, 4, 4, 4, 8, 8, 10, 12]
            assert len(helper_gets) == 12
        session, = sessions
        assert bus.disconnected and session.closed and session._loop.is_closed()
        assert env["store"].load().phase == "published"
        assert manager._closed_observation is None


@pytest.mark.parametrize("fault", [
    "wrong-pid", "wrong-invocation", "ready-before-reload",
    "job-between-observers", "local-identity-change",
])
def test_manager_binds_controller_identity_and_pre_ready_phase(tmp_path, monkeypatch, fault):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        injected = []

        def mutate(interface, count, props):
            if fault == "wrong-pid" and interface != UNIT_INTERFACE:
                props["MainPID"] = Variant("u", CONTROLLER_IDENTITY.pid + 1)
                injected.append(fault)
            elif fault == "wrong-invocation" and interface == UNIT_INTERFACE:
                props["InvocationID"] = Variant("ay", b"\x99" * 16)
                injected.append(fault)
            elif fault == "job-between-observers" and interface == UNIT_INTERFACE and count >= 3:
                props["Job"] = Variant("(uo)", [987, "/org/freedesktop/systemd1/job/987"])
                injected.append(fault)
            return props

        bus.controller.mutate = mutate
        if fault == "ready-before-reload":
            bus.controller.phase = "ready"
        if fault == "local-identity-change":
            reads = []

            def identity():
                reads.append(True)
                if len(reads) > 1:
                    injected.append(fault)
                return (CONTROLLER_IDENTITY if len(reads) == 1
                        else replace(CONTROLLER_IDENTITY, pid=CONTROLLER_IDENTITY.pid + 1))

            monkeypatch.setattr(manager_module, "current_bootstrap_controller_identity", identity)
        with pytest.raises(UnitOperationFailed):
            manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=_check_publish([]),
            )
        if fault == "ready-before-reload":
            assert bus.controller.unit_calls > 0 and bus.controller.phase == "ready"
        else:
            assert injected and set(injected) == {fault}
        assert bus.reload_count == (1 if fault in {
            "job-between-observers", "local-identity-change",
        } else 0)
        session, = sessions
        assert bus.disconnected and session.closed and session._loop.is_closed()
        assert env["store"].load().phase == "published"
        assert manager._closed_observation is None
