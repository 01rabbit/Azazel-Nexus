"""Pins for the supervised test-VM bootstrap factory switch (condition C2).

The factory builds exactly `_PrototypeBootstrapManager`. Synthetic fakes only;
nothing here touches systemd, a bus, a VM or the network.
"""

import ast
from contextlib import ExitStack, contextmanager
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_manager as module
from azazel_nexus_runtime import bootstrap_overlay_files
from azazel_nexus_runtime.bootstrap_cgroup_mount import BootstrapCgroupMount
from azazel_nexus_runtime.bootstrap_close_files import BootstrapClosedOverlayFiles
from azazel_nexus_runtime.bootstrap_manager import (
    BootstrapNarrowingManager, _PrototypeBootstrapManager,
    bootstrap_narrowing_manager_in_transaction,
)
from azazel_nexus_runtime.bootstrap_withdrawal import BootstrapWithdrawalFiles
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_bound_audit import _harness as _audit_harness
from test_runtime_bootstrap_checkpoint_order import (
    IRREVERSIBLE_PUBLICATION, MANAGER_OPEN_PAIR_CHECKS, _StoreProxy,
)
from test_runtime_bootstrap_manager_publication import (
    _environment, _manager_fixture, _transaction,
)

RUNTIME = Path(module.__file__).resolve().parent

Q9_HEAD_INVENTORY = frozenset({
    "Hello", "GetNameOwner", "GetConnectionUnixProcessID", "GetConnectionUnixUser",
    "Get", "GetAll", "GetUnit", "LoadUnit", "GetUnitFileState", "ListUnitsByPatterns",
    "ListJobs", "Subscribe", "Unsubscribe", "AddMatch", "RemoveMatch", "Reload",
    "StartUnit", "StopUnit", "CancelJob", "MaskUnitFiles",
})
# Members not appearing as literals in bootstrap*.py: Hello is implicit in the
# bus library; MaskUnitFiles is sent by the shared units/systemd_bus layer.
NOT_BOOTSTRAP_LITERALS = frozenset({"Hello", "MaskUnitFiles"})
# Property / signal / local names that merely look like method names.
PROPERTY_NAMES = frozenset({
    "LoadState", "Restart", "ExitType", "KillMode", "KillSignal",
    "SetLoginEnvironment", "ReloadPropagatedFrom", "StopPropagatedFrom",
    "MaskedBootstrapPair", "BindsTo", "UnsetEnvironment",
})
MEMBER_SHAPE = re.compile(
    r"^(Get|Load|List|Start|Stop|Cancel|Mask|Unmask|Enable|Disable|Reload|Restart|"
    r"TryRestart|Kill|Set|Subscribe|Unsubscribe|AddMatch|RemoveMatch|Hello|Freeze|"
    r"Thaw|Clear|Reset|Switch|Exit|Reboot|PowerOff|Halt|Link|Preset|Revert|Dump|"
    r"Lookup|Create|Delete|Ref|Unref|Attach|Abandon|Queue|Try|Wait|Protect|"
    r"Reexecute|Clean|Enqueue|Bind|Mount|Unset|Add|Kexec|SoftReboot|Mark)[A-Za-z]*$"
)
FORBIDDEN_PREFIXES = (
    "Unmask", "Enable", "Disable", "StartTransientUnit", "SetUnitProperties",
    "Restart", "TryRestart", "ReloadOrRestart", "ReloadOrTryRestart", "KillUnit",
    "Reexecute", "Clean", "Enqueue", "Bind", "Mount", "Unset", "Add", "Kexec",
    "SoftReboot", "Mark", "StartUnitWithFlags",
)
FORBIDDEN_NAMES = frozenset({"unmask_and_enable", "UnmaskUnitFiles", "EnableUnitFiles"})
ALLOWED_DBUS_UNIT_MANAGER_METHODS = frozenset({"mask", "state", "is_inactive"})
# Generic forwarders whose member argument is a parameter. Each is explicit;
# every concrete caller still passes a literal covered by the shape scan.
NONCONSTANT_MEMBER_SITES = frozenset({
    ("bootstrap_stop.py", "_call"),            # def _call(... member ...) forwarder
    ("bootstrap_stop.py", "cleanup"),           # loop over literal member tuples
    ("bootstrap_manager_identity.py", "credential"),
})


def _bootstrap_member_literals():
    found = {}
    for path in sorted(RUNTIME.glob("bootstrap*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and MEMBER_SHAPE.match(node.value)
                    and node.value not in PROPERTY_NAMES):
                found.setdefault(node.value, set()).add(path.name)
    return found


# ---- (i) factory return-type pin through the real factory with fakes --------

@contextmanager
def _factory_fakes(monkeypatch, env, *, job_timeout_seconds=2):
    events = []
    closed = object.__new__(BootstrapClosedOverlayFiles)
    withdrawal = object.__new__(BootstrapWithdrawalFiles)
    mount = object.__new__(BootstrapCgroupMount)
    monkeypatch.setattr(BootstrapCgroupMount, "check", lambda self: None)
    monkeypatch.setattr(BootstrapCgroupMount, "fileno", lambda self: 7)
    monkeypatch.setattr(
        module, "validate_cgroup_root",
        lambda fd, uid: SimpleNamespace(st_dev=1, st_ino=2),
    )
    store = object()
    dirs = SimpleNamespace(
        check=lambda: events.append("check"),
        closed_files=lambda **kwargs: closed,
        withdrawal_files=lambda **kwargs: withdrawal,
    )

    @contextmanager
    def resource(value):
        yield value

    monkeypatch.setattr(module, "open_bootstrap_overlay_directories", lambda: resource(dirs))
    monkeypatch.setattr(module, "open_bootstrap_cgroup_mount", lambda: resource(mount))
    monkeypatch.setattr(
        module, "overlay_journal_store_in_transaction", lambda guard: resource(store),
    )
    with bootstrap_narrowing_manager_in_transaction(
        env["guard"], job_timeout_seconds=job_timeout_seconds,
    ) as manager:
        yield manager, (dirs, store, env["guard"])


def test_factory_returns_exactly_the_prototype_manager(tmp_path, monkeypatch):
    with _environment(tmp_path) as env, _factory_fakes(monkeypatch, env) as (manager, inputs):
        assert type(manager) is _PrototypeBootstrapManager
        assert type(manager) is not BootstrapNarrowingManager
        assert manager._publication_inputs == inputs


def test_factory_built_manager_still_refuses_individual_unmask(tmp_path, monkeypatch):
    from azazel_nexus_runtime.units import UnitKey
    with _environment(tmp_path) as env, _factory_fakes(monkeypatch, env) as (manager, _):
        with pytest.raises(UnitOperationFailed):
            manager.unmask(UnitKey.AUDITD)


# ---- (ii) source-level D-Bus member guard -----------------------------------

def test_bootstrap_path_member_names_equal_q9_head_inventory():
    found = _bootstrap_member_literals()
    assert set(found) == Q9_HEAD_INVENTORY - NOT_BOOTSTRAP_LITERALS, found
    shared = (RUNTIME / "units.py").read_text() + (RUNTIME / "systemd_bus.py").read_text()
    assert '"MaskUnitFiles"' in shared


def test_no_widening_or_restart_members_in_bootstrap_modules():
    offenders = {
        name: files for name, files in _bootstrap_member_literals().items()
        if name.startswith(FORBIDDEN_PREFIXES) and name not in Q9_HEAD_INVENTORY
    }
    assert offenders == {}
    for path in RUNTIME.glob("bootstrap*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not (re.fullmatch(r"[A-Za-z]+", node.value)
                            and node.value.startswith(FORBIDDEN_PREFIXES)
                            and node.value not in PROPERTY_NAMES
                            and node.value not in Q9_HEAD_INVENTORY), (path.name, node.value)
            name = (node.id if isinstance(node, ast.Name)
                    else node.attr if isinstance(node, ast.Attribute)
                    else node.value if isinstance(node, ast.Constant)
                    and isinstance(node.value, str) else None)
            assert name not in FORBIDDEN_NAMES, (path.name, name)
            if isinstance(node, ast.alias):
                assert node.name not in FORBIDDEN_NAMES, (path.name, node.name)


def _parents(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_function(node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def _constant_members(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if (isinstance(node, ast.IfExp) and _constant_members(node.body)
            and _constant_members(node.orelse)):
        return _constant_members(node.body) | _constant_members(node.orelse)
    return None


def test_member_arguments_at_call_sites_are_allowlisted_constants():
    seen, nonconstant = set(), set()
    for path in sorted(RUNTIME.glob("bootstrap*.py")):
        tree = ast.parse(path.read_text())
        parents = _parents(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            arguments = []
            if isinstance(node.func, ast.Attribute) and node.func.attr == "_call" and node.args:
                arguments.append(node.args[0])
            arguments += [k.value for k in node.keywords if k.arg == "member"]
            for argument in arguments:
                members = _constant_members(argument)
                if members is None:
                    nonconstant.add((path.name, _enclosing_function(node, parents)))
                else:
                    assert members <= Q9_HEAD_INVENTORY, (path.name, members)
                    seen |= members
    assert nonconstant <= NONCONSTANT_MEMBER_SITES, nonconstant
    assert seen <= Q9_HEAD_INVENTORY


def test_dbus_unit_manager_methods_used_by_bootstrap_modules_are_narrowing_only():
    used = set()
    for path in sorted(RUNTIME.glob("bootstrap*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "DbusUnitManager"):
                used.add(node.attr)
    assert used == ALLOWED_DBUS_UNIT_MANAGER_METHODS


# ---- (iii) no environment selection -----------------------------------------

@pytest.mark.parametrize("variables", [
    {"AZAZEL_BOOTSTRAP_MANAGER": "BootstrapNarrowingManager"},
    {"AZAZEL_BOOTSTRAP_PROTOTYPE": "0", "AZAZEL_BOOTSTRAP_CLOSED": "1"},
    {"AZAZEL_ALLOW_START": "1", "AZAZEL_TEST_VM": "0", "PYTHONINSPECT": "1"},
    {"BOOTSTRAP_MANAGER_CLASS": "_PrototypeBootstrapManager", "DEBUG": "1"},
])
def test_factory_result_is_unchanged_by_environment(tmp_path, monkeypatch, variables):
    for key, value in variables.items():
        monkeypatch.setenv(key, value)
    with _environment(tmp_path) as env, _factory_fakes(monkeypatch, env) as (manager, _):
        assert type(manager) is _PrototypeBootstrapManager


def test_factory_source_does_not_consult_environment_or_argv():
    tree = ast.parse((RUNTIME / "bootstrap_manager.py").read_text())
    factory = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                   and n.name == "bootstrap_narrowing_manager_in_transaction")
    factory.body = factory.body[1:]  # drop the docstring; code only
    text = ast.unparse(factory)
    for token in ("environ", "getenv", "argv", "yaml", "config"):
        assert token not in text
    # The only branch is the leading held-guard type refusal; after it the
    # factory body has no If/IfExp/Compare/BoolOp (no conditional selection).
    lead, rest = factory.body[0], factory.body[1:]
    assert isinstance(lead, ast.If) and ast.unparse(lead.test) == (
        "type(guard) is not BootstrapTransactionGuard")
    nodes = [n for stmt in rest for n in ast.walk(stmt)]
    assert not [n for n in nodes
                if isinstance(n, (ast.If, ast.IfExp, ast.Compare, ast.BoolOp))]
    constructors = [ast.unparse(n.func) for n in nodes if isinstance(n, ast.Call)
                    and ast.unparse(n.func).lstrip("_")[:1].isupper()]
    assert constructors == ["_PrototypeBootstrapManager"], constructors


# ---- (iv) fake-order through the factory-built manager ----------------------

def _factory_manager_type(stack, monkeypatch, env):
    """manager_type adapter so existing fixtures build through the real factory."""
    def build(*, job_timeout_seconds, session_factory):
        manager, _ = stack.enter_context(
            _factory_fakes(monkeypatch, env, job_timeout_seconds=job_timeout_seconds)
        )
        manager._factory = session_factory
        return manager
    return build


def _run_open_pair(tmp_path, monkeypatch, fail_at=None):
    events, state = [], {"checks": 0}
    with ExitStack() as stack:
        env = stack.enter_context(_environment(tmp_path))
        manager, _sessions, bus, approval, *_ = _manager_fixture(
            env, monkeypatch, manager_type=_factory_manager_type(stack, monkeypatch, env),
        )
        assert type(manager) is _PrototypeBootstrapManager
        directories, store, guard = manager._publication_inputs
        manager._publication_inputs = (directories, _StoreProxy(store, events), guard)
        real_create = bootstrap_overlay_files._create_candidate

        def create_candidate(*args, **kwargs):
            events.append("create_file")
            return real_create(*args, **kwargs)

        monkeypatch.setattr(bootstrap_overlay_files, "_create_candidate", create_candidate)
        real_call = bus.call

        async def call(message):
            if message.member == "Reload":
                events.append("reload")
            return await real_call(message)

        bus.call = call

        def check_publish():
            state["checks"] += 1
            events.append("check")
            if state["checks"] == fail_at:
                raise ApprovalRefused("synthetic admission loss")

        error = None
        try:
            manager.open_pair(_transaction(approval), approval=approval,
                              check_publish=check_publish)
        except (ApprovalRefused, UnitOperationFailed,
                bootstrap_overlay_files.OverlayPublicationUncertain) as exc:
            error = exc
    return events, state["checks"], error


def test_factory_manager_open_pair_irreversible_steps_follow_full_check(tmp_path, monkeypatch):
    events, checks, error = _run_open_pair(tmp_path, monkeypatch)
    assert error is None
    assert checks == MANAGER_OPEN_PAIR_CHECKS
    assert [e for e in events if e != "check"] == [
        "journal_create", "create_file", "journal_replace",
        "create_file", "journal_replace", "reload",
    ]
    for index, event in enumerate(events):
        if event in IRREVERSIBLE_PUBLICATION:
            assert index and events[index - 1] == "check", (index, events)


@pytest.mark.parametrize("position", range(1, MANAGER_OPEN_PAIR_CHECKS + 1))
def test_factory_manager_failed_check_stops_next_irreversible_step(
    tmp_path, monkeypatch, position,
):
    events, checks, error = _run_open_pair(tmp_path, monkeypatch, fail_at=position)
    assert error is not None and checks == position
    assert events[-1] == "check"


def _run_start(tmp_path, monkeypatch, fail_at=None):
    events, state = [], {"n": 0}
    with ExitStack() as stack:
        env = stack.enter_context(_environment(tmp_path))
        manager, _sessions, start_bus, transaction = _audit_harness(
            monkeypatch, manager_type=_factory_manager_type(stack, monkeypatch, env),
        )
        assert type(manager) is _PrototypeBootstrapManager
        real_call = start_bus.call

        async def call(message):
            if message.member == "StartUnit":
                events.append("start_unit")
            return await real_call(message)

        start_bus.call = call

        def check_start():
            state["n"] += 1
            events.append("check")
            if state["n"] == fail_at:
                raise ApprovalRefused("synthetic admission loss")

        error = None
        try:
            from azazel_nexus_runtime.units import UnitKey
            manager.start_and_wait(UnitKey.AUDITD, transaction=transaction,
                                   check_start=check_start)
        except (ApprovalRefused, UnitOperationFailed) as exc:
            error = exc
    return events, error


def test_factory_manager_start_unit_follows_a_full_check(tmp_path, monkeypatch):
    events, _error = _run_start(tmp_path, monkeypatch)
    assert "start_unit" in events
    assert events[events.index("start_unit") - 1] == "check", events


def test_factory_manager_failed_check_before_start_unit_prevents_it(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    clean, _ = _run_start(tmp_path / "a", monkeypatch)
    position = clean[:clean.index("start_unit")].count("check")
    assert position >= 1
    events, error = _run_start(tmp_path / "b", monkeypatch, fail_at=position)
    assert error is not None
    assert "start_unit" not in events
