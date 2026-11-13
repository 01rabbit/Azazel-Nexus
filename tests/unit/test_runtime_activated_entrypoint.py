"""The installed activation entrypoint composes only in its systemd context.

The decision and rollback behavior is exercised in
``test_runtime_activated.py``. These tests cover the production composition
root without touching host unit state or the fixed host ledger paths.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import activated, runtime_paths
from azazel_nexus_runtime.systemd_bus import SystemdBusSession
from azazel_nexus_runtime.units import ContextdStopAuthority, DbusUnitManager


@pytest.fixture
def host_cgroup(monkeypatch):
    """These tests drive `main` with fake bus sessions on a host that is not a
    cgroup-v2 systemd node. The reader of the host's cgroup (tested on its own in
    test_runtime_contextd_cgroup.py) answers as a stopped unit's cgroup would."""
    from azazel_nexus_runtime import contextd_cgroup
    monkeypatch.setattr(
        contextd_cgroup, "read_contextd_cgroup",
        lambda active, root=None: "empty" if active in ("inactive", "failed") else "populated")


@pytest.fixture(autouse=True)
def no_host_bootstrap_selection(monkeypatch):
    from azazel_nexus import bootstrap_selection_optional as bootstrap_selection_store
    monkeypatch.setattr(bootstrap_selection_store, "load_optional_bootstrap_selection", lambda: None)


@pytest.mark.parametrize("mode", ["selected", "invalid", "composition-fails", "emergency-unconfirmed"])
def test_selected_bootstrap_routes_without_ordinary_fallback(monkeypatch, capsys, mode, private_os):
    private_os(activated)
    from azazel_nexus import bootstrap_selection_optional as bootstrap_selection_store
    from azazel_nexus.operator_trust import ApprovalRefused
    from azazel_nexus_runtime import bootstrap_entrypoint

    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    monkeypatch.setattr(Path, "is_dir", lambda path: path == Path("/run/systemd/system"))
    selected = object()
    calls = []

    def selection():
        calls.append("selection")
        if mode == "invalid":
            raise ApprovalRefused("invalid selection refused")
        return selected

    def run(actual, *, narrow):
        assert actual is selected and callable(narrow)
        calls.append("bootstrap")
        if mode == "emergency-unconfirmed":
            failure = ApprovalRefused("primary failure refused")
            failure.add_note(bootstrap_entrypoint.EMERGENCY_UNCONFIRMED)
            raise failure
        if mode == "composition-fails":
            raise ApprovalRefused("incomplete gate refused")

    def narrow_invalid(primary, *, narrow):
        assert isinstance(primary, ApprovalRefused) and callable(narrow)
        calls.append("invalid-narrow")

    monkeypatch.setattr(bootstrap_selection_store, "load_optional_bootstrap_selection", selection)
    monkeypatch.setattr(bootstrap_entrypoint, "run_selected_bootstrap", run)
    monkeypatch.setattr(bootstrap_entrypoint, "narrow_invalid_selection", narrow_invalid)
    monkeypatch.setattr(activated, "_run_once", lambda **_: pytest.fail("ordinary fallback"))
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(
        lambda: pytest.fail("bus outside selected composition")
    ))
    assert activated.main([]) == (0 if mode == "selected" else 1)
    assert calls == (["selection", "invalid-narrow"] if mode == "invalid"
                     else ["selection", "bootstrap"])
    output = capsys.readouterr()
    assert "private" not in output.out + output.err
    if mode == "emergency-unconfirmed":
        assert "emergency narrowing unconfirmed" in output.err


class BootBus:
    """A modelled system bus for the bootstrap-stage narrowing: one broker whose state is
    shared by every session (`world`), and the four contextd verbs of the real session."""

    def __init__(self, world, *, breaks_on=None):
        self.world = world
        self.breaks_on = breaks_on
        self.broken = False
        self.limit = None
        world.sessions.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def set_remaining(self, remaining):
        self.limit = remaining
        self.world.bound.append((len(self.world.calls), remaining))

    def _live(self):
        if self.broken:
            raise activated.UnitOperationFailed("the bus session is finished")

    def _maybe_break(self, verb):
        if self.breaks_on == verb:
            self.broken = True
            raise activated.UnitOperationFailed("systemd D-Bus call did not complete")

    def __call__(self, method, unit):
        self._live()
        self.world.calls.append((method, unit))
        if method == "MaskUnitFiles":
            self._maybe_break("mask")
            self.world.masked.add(unit)
            return []
        if method == "GetUnitFileState":
            return "masked" if unit in self.world.masked else "enabled"
        if method == "GetInactiveState":
            return not (unit == activated.CONTEXTD_UNIT and self.world.running)
        pytest.fail("unexpected widening operation")

    def reload(self):
        self._live()
        self.world.calls.append(("Reload", ""))
        self._maybe_break("reload")

    def stop_contextd(self):
        self._live()
        self.world.calls.append(("StopUnit", activated.CONTEXTD_UNIT))
        self.world.running = False
        return "/org/freedesktop/systemd1/job/9"

    def unit_job(self, unit):
        self._live()
        return (0, "/")

    def contextd_active_state(self, unit):
        self._live()
        return "active" if self.world.running else "inactive"

    def contextd_file_state(self, unit):
        self._live()
        return "masked" if unit in self.world.masked else "enabled"


def _boot_world(monkeypatch, *, running, first_breaks_on=None, other_units_stuck=False):
    from azazel_nexus_runtime import activation_withdraw
    world = SimpleNamespace(calls=[], masked=set(), running=running, sessions=[], bound=[])
    made = []

    def connect(*_args):
        bus = BootBus(world, breaks_on=first_breaks_on if not made else None)
        made.append(bus)
        return bus

    monkeypatch.setattr(activated, "reset_grant_markers", lambda _root: None)
    monkeypatch.setattr(activation_withdraw, "remove_contextd_marker", lambda _root: None)
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(connect))
    return world


@pytest.mark.usefixtures("host_cgroup")
def test_bootstrap_narrowing_withdraws_a_running_broker_and_masks_the_rest(monkeypatch, capsys):
    """Granted and running broker: masked, reloaded, stopped, confirmed masked and quiet."""
    world = _boot_world(monkeypatch, running=True)
    activated._narrow_bootstrap_core_units()
    assert world.running is False and activated.CONTEXTD_UNIT in world.masked
    operations = [c for c in world.calls if c[1] in (activated.CONTEXTD_UNIT, "")]
    names = [m for m, _ in operations if m in ("MaskUnitFiles", "Reload", "StopUnit")]
    assert names[:3] == ["MaskUnitFiles", "Reload", "StopUnit"]
    assert world.masked == {d.name for d in activated.CORE_UNITS}
    assert "withdrew the Knowledge Context broker" in capsys.readouterr().err


def test_bootstrap_narrowing_hands_a_failed_mask_to_a_fresh_session(monkeypatch, capsys):
    """The first session finishes on the broker's mask: the withdrawal goes on in a new one,
    the broker ends masked and quiet, every other unit is masked on a session that works,
    and the narrowing still fails closed (the withdrawal is reported unconfirmed)."""
    world = _boot_world(monkeypatch, running=True, first_breaks_on="mask")
    with pytest.raises(activated.UnitOperationFailed):
        activated._narrow_bootstrap_core_units()
    assert len(world.sessions) >= 2 and world.sessions[0].broken
    assert world.masked == {d.name for d in activated.CORE_UNITS} and world.running is False
    assert "could not confirm the withdrawal" in capsys.readouterr().err


def test_bootstrap_narrowing_that_cannot_stop_the_broker_fails_closed_with_a_message(
        monkeypatch, capsys):
    world = _boot_world(monkeypatch, running=True)
    monkeypatch.setattr(BootBus, "stop_contextd", lambda self: (_ for _ in ()).throw(
        activated.UnitOperationFailed("refused")))
    with pytest.raises(activated.UnitOperationFailed):
        activated._narrow_bootstrap_core_units()
    assert activated.CONTEXTD_UNIT in world.masked  # never left unmasked
    assert "could not confirm the withdrawal" in capsys.readouterr().err


@pytest.mark.parametrize("reset_fails", [False, True])
@pytest.mark.usefixtures("host_cgroup")
def test_bootstrap_broad_narrowing_removes_grant_markers_first(monkeypatch, capsys,
                                                            reset_fails):
    """#251 L-7: like _emergency_narrow, markers first; a refusal still remasks."""
    world = _boot_world(monkeypatch, running=False)
    def reset(root):
        world.calls.append(("reset", ""))
        if reset_fails:
            raise RuntimeError("grant markers")

    monkeypatch.setattr(activated, "reset_grant_markers", reset)
    if reset_fails:
        with pytest.raises(activated.UnitOperationFailed):
            activated._narrow_bootstrap_core_units()
    else:
        activated._narrow_bootstrap_core_units()
    assert world.calls[0] == ("reset", "")  # before the first bus call (mask)
    assert [m for m, _ in world.calls].index("reset") < [m for m, _ in world.calls].index(
        "MaskUnitFiles")
    if reset_fails:
        assert "could not remove grant markers during bootstrap narrowing\n" in (
            capsys.readouterr().err)
    assert world.masked == {d.name for d in activated.CORE_UNITS}


def test_entrypoint_rejects_arguments_before_connecting_to_systemd(
    monkeypatch, capsys
) -> None:
    def forbidden_connect():
        raise AssertionError("unexpected system-bus connection")

    monkeypatch.setattr(SystemdBusSession, "connect", forbidden_connect)

    assert activated.main(["--unit", "sshd.service"]) == 2
    assert "accepts no command-line arguments" in capsys.readouterr().err


@pytest.mark.parametrize(
    "uid,systemd_present,invocation_id,root",
    [
        (1000, True, "a" * 32, Path("/")),
        (0, False, "a" * 32, Path("/")),
        (0, True, None, Path("/")),
        (0, True, "malformed", Path("/")),
        (0, True, "a" * 32, Path("/tmp/staged")),
    ],
)
def test_entrypoint_refuses_outside_root_systemd_context_without_bus_access(
    monkeypatch, capsys, uid, systemd_present, invocation_id, root, private_os
) -> None:
    private_os(activated)
    monkeypatch.setattr(activated.os, "geteuid", lambda: uid)
    monkeypatch.setattr(runtime_paths, "ROOT", root)
    if invocation_id is None:
        monkeypatch.delenv("INVOCATION_ID", raising=False)
    else:
        monkeypatch.setenv("INVOCATION_ID", invocation_id)
    original_is_dir = Path.is_dir
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda path: systemd_present
        if path == Path("/run/systemd/system")
        else original_is_dir(path),
    )
    calls = []

    def forbidden_connect():
        calls.append("connect")
        raise AssertionError("unexpected system-bus connection")

    def forbidden_run_once(**_kwargs):
        calls.append("run_once")
        raise AssertionError("unexpected activation pass")

    monkeypatch.setattr(SystemdBusSession, "connect", forbidden_connect)
    monkeypatch.setattr(activated, "_run_once", forbidden_run_once)

    assert activated.main([]) == 1
    assert "requires its root systemd service context" in capsys.readouterr().err
    assert calls == []


def _pass_lock_held(monkeypatch, taken=None):
    """The main pass takes the pass lock; here a lock that is always free."""

    class Lock:
        def __enter__(self):
            return self

        def __exit__(self, *_exc_info):
            return None

    def acquire(root, **kwargs):
        if taken is not None:
            taken.append((root, kwargs))
        return Lock()

    monkeypatch.setattr(activated, "acquire_pass_lock", acquire)



def test_entrypoint_passes_the_system_bus_manager_to_one_fail_closed_pass(
    monkeypatch, capsys, private_os
) -> None:
    private_os(activated)
    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    original_is_dir = Path.is_dir

    def systemd_is_present(path: Path) -> bool:
        if path == Path("/run/systemd/system"):
            return True
        return original_is_dir(path)

    monkeypatch.setattr(Path, "is_dir", systemd_is_present)

    calls: list[tuple[str, str]] = []

    class ReadOnlySession:
        def __call__(self, method: str, unit: str) -> object:
            calls.append((method, unit))
            if method == "MaskUnitFiles":
                return [[(unit, "", "")]]
            if method == "GetUnitFileState":
                return "masked"
            raise AssertionError(f"unexpected service-manager call: {method}")

        def stop_contextd(self):
            raise AssertionError("the pass was replaced; nothing may be stopped")

        def unit_job(self, unit):
            raise AssertionError("the pass was replaced; nothing may be read")

        def contextd_active_state(self, unit):
            raise AssertionError("the pass was replaced; nothing may be read")

        def contextd_file_state(self, unit):
            raise AssertionError("the pass was replaced; nothing may be read")

        def __enter__(self):
            return self

        def __exit__(self, *_exc_info) -> None:
            return None

    session = ReadOnlySession()
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(lambda *_a: session))
    taken: list = []
    _pass_lock_held(monkeypatch, taken)
    observed: dict[str, object] = {}

    def run_once(*, manager, root, now, actor, **extra):
        observed.update(manager=manager, root=root, now=now, actor=actor, **extra)
        return SimpleNamespace(
            granted=(),
            withheld=("commissiond",),
            verdicts=(SimpleNamespace(reason="commissioning_record_absent"),),
        )

    monkeypatch.setattr(activated, "_run_once", run_once)
    from azazel_nexus_runtime import systemd_notify
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: None)
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: None)

    assert activated.main([]) == 0
    assert isinstance(observed["manager"], DbusUnitManager)
    assert observed["manager"].call is session
    assert observed["root"] == Path("/")
    assert observed["actor"] == "azazel-activated"
    assert str(observed["now"]).endswith("Z")
    assert not calls
    # The lock is taken with a bounded wait before the pass, and the pass is
    # given the authority to stop the Knowledge Context broker alone.
    assert len(taken) == 1 and taken[0][0] == Path("/")
    options = dict(taken[0][1])
    assert options.pop("wait_seconds") == activated.PASS_LOCK_WAIT_SECONDS == 25.0
    assert options == {"clock": time.monotonic, "sleep": time.sleep}
    assert isinstance(observed["stop_authority"], ContextdStopAuthority)
    assert observed["invocation_id"] == "a" * 32
    assert "granted=0" in capsys.readouterr().out


def test_entrypoint_does_not_report_a_bus_failure_as_a_safe_pass(
    monkeypatch, capsys, private_os
) -> None:
    private_os(activated)
    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "b" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    original_is_dir = Path.is_dir

    def systemd_is_present(path: Path) -> bool:
        if path == Path("/run/systemd/system"):
            return True
        return original_is_dir(path)

    monkeypatch.setattr(Path, "is_dir", systemd_is_present)
    monkeypatch.setattr(
        SystemdBusSession,
        "connect",
        staticmethod(lambda *_a: (_ for _ in ()).throw(ConnectionError("private detail"))),
    )

    assert activated.main([]) == 1
    error = capsys.readouterr().err
    assert "failed before completing a safe pass: ConnectionError" in error
    assert "private detail" not in error


def test_failure_label_carries_static_message_only_for_allowlisted_literals() -> None:
    from azazel_nexus.operator_trust import ApprovalRefused
    from azazel_nexus_runtime.bootstrap_controller import BootstrapControllerNotReady
    from azazel_nexus_runtime.bootstrap_overlay_files import OverlayPublicationUncertain
    from azazel_nexus_runtime.units import UnitOperationFailed

    label = activated._failure_label
    assert label(UnitOperationFailed("controller one-use start condition refused")) == (
        "UnitOperationFailed: controller one-use start condition refused")
    assert label(ApprovalRefused("bootstrap completion unconfirmed")) == (
        "ApprovalRefused: bootstrap completion unconfirmed")
    # Class-only: other classes, subclasses, unlisted/odd messages, odd args.
    assert label(ConnectionError("private detail")) == "ConnectionError"
    assert label(OSError(13, "/secret/path")) == "PermissionError"
    assert label(OverlayPublicationUncertain("private path /x")) == (
        "OverlayPublicationUncertain")
    assert label(BootstrapControllerNotReady("private")) == "BootstrapControllerNotReady"
    assert label(OverlayPublicationUncertain("bootstrap completion unconfirmed")) == (
        "OverlayPublicationUncertain")
    assert label(ApprovalRefused("private \u00e9 text")) == "ApprovalRefused"
    assert label(ApprovalRefused(b"bootstrap completion unconfirmed")) == "ApprovalRefused"
    assert label(ApprovalRefused(7)) == "ApprovalRefused"
    assert label(ApprovalRefused("not in the allowlist")) == "ApprovalRefused"
    assert label(UnitOperationFailed("x could not be enabled")) == "UnitOperationFailed"
    assert label(UnitOperationFailed("'k' is not a unit this daemon governs. y")) == (
        "UnitOperationFailed")
    assert label(UnitOperationFailed("bootstrap cgroup root unavailable", "b")) == (
        "UnitOperationFailed")
    assert label(UnitOperationFailed()) == "UnitOperationFailed"


def test_static_message_allowlist_matches_reviewed_raise_literals() -> None:
    import ast

    root = Path(activated.__file__).parent
    modules = ("bootstrap", "bootstrap_controller", "bootstrap_entrypoint",
               "bootstrap_manager", "bootstrap_loaded", "bootstrap_resources",
               "bootstrap_restore", "bootstrap_withdrawal", "bootstrap_withdraw_files",
               "bootstrap_restore_files", "units", "systemd_socket")
    found: set[str] = set()
    for module in modules:
        for node in ast.walk(ast.parse((root / f"{module}.py").read_text())):
            if (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
                    and isinstance(node.exc.func, ast.Name)
                    and node.exc.func.id in ("ApprovalRefused", "UnitOperationFailed")
                    and len(node.exc.args) == 1
                    and isinstance(node.exc.args[0], ast.Constant)
                    and type(node.exc.args[0].value) is str):
                found.add(node.exc.args[0].value)
    library = Path(activated.__file__).parents[2].parent / "src" / "azazel_nexus"
    if not library.is_dir():
        import azazel_nexus
        library = Path(azazel_nexus.__file__).parent
    for module in ("bootstrap_selection", "bootstrap_selection_optional",
                   "bootstrap_selection_store", "bootstrap_deadline_store",
                   "bootstrap_grant_store"):
        for node in ast.walk(ast.parse((library / f"{module}.py").read_text())):
            if (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
                    and isinstance(node.exc.func, ast.Name)
                    and node.exc.func.id in ("ApprovalRefused", "UnitOperationFailed")
                    and len(node.exc.args) == 1
                    and isinstance(node.exc.args[0], ast.Constant)
                    and type(node.exc.args[0].value) is str):
                found.add(node.exc.args[0].value)
    from azazel_nexus.bootstrap_selection_store import SELECTION_READ_REASONS
    found.update("protected bootstrap selection refused: " + reason for reason in SELECTION_READ_REASONS)
    found.add("bootstrap helper readiness lost")  # bootstrap._READINESS_LOST
    # ProtectedBootstrapInitialAdmission.retain's wrapper (bootstrap_inputs).
    found.add("protected bootstrap runtime inputs refused")
    # The shared protected-file helpers the deadline store reads through; only
    # these raises, which must still be literal raises in those modules.
    helpers = {
        "activation_store": {"activation approval directory is not private",
                             "activation approval file permissions or size refused",
                             "activation approval file changed while reading"},
        "operator_store": {"operator trust storage is not protected",
                           "operator trust file must have one link"},
    }
    for module, messages in helpers.items():
        literals = {
            node.exc.args[0].value
            for node in ast.walk(ast.parse((library / f"{module}.py").read_text()))
            if (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
                and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == "ApprovalRefused" and len(node.exc.args) == 1
                and isinstance(node.exc.args[0], ast.Constant))
        }
        assert messages <= literals
        found |= messages
    found = {m for m in found if "/" not in m and "{" not in m}
    assert activated._STATIC_FAILURE_MESSAGES == found
    assert all("/" not in m and "{" not in m and m.isascii() and m.isprintable()
               for m in activated._STATIC_FAILURE_MESSAGES)


def test_entrypoint_logs_subclass_message_class_only(monkeypatch, capsys, private_os) -> None:
    private_os(activated)
    from azazel_nexus_runtime.bootstrap_overlay_files import OverlayPublicationUncertain

    _arrange_bus_failure(monkeypatch, OverlayPublicationUncertain("private path /x"))
    assert activated.main([]) == 1
    error = capsys.readouterr().err
    assert "safe pass: OverlayPublicationUncertain" in error
    assert "private" not in error


def _arrange_bus_failure(monkeypatch, failure) -> None:
    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "b" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    original_is_dir = Path.is_dir
    monkeypatch.setattr(
        Path, "is_dir",
        lambda path: True if path == Path("/run/systemd/system") else original_is_dir(path),
    )
    monkeypatch.setattr(
        SystemdBusSession, "connect",
        staticmethod(lambda *_a: (_ for _ in ()).throw(failure)),
    )


def test_entrypoint_logs_static_refusal_message(monkeypatch, capsys, private_os) -> None:
    private_os(activated)
    from azazel_nexus_runtime.units import UnitOperationFailed

    _arrange_bus_failure(
        monkeypatch, UnitOperationFailed("controller one-use start condition refused"))
    assert activated.main([]) == 1
    assert ("failed before completing a safe pass: UnitOperationFailed: "
            "controller one-use start condition refused") in capsys.readouterr().err


def test_entrypoint_logs_prior_boot_refusal_reason(monkeypatch, capsys, private_os) -> None:
    """A refused prior boot journal names why, not only the class (Nexus#324)."""
    private_os(activated)
    from azazel_nexus.operator_trust import ApprovalRefused

    _arrange_bus_failure(monkeypatch, ApprovalRefused("prior boot overlay entry present"))
    assert activated.main([]) == 1
    assert ("failed before completing a safe pass: ApprovalRefused: "
            "prior boot overlay entry present") in capsys.readouterr().err


def test_failure_label_names_withdrawal_and_retirement_reasons() -> None:
    from azazel_nexus.operator_trust import ApprovalRefused
    from azazel_nexus_runtime.bootstrap_withdrawal import BootstrapWithdrawalFiles
    from azazel_nexus_runtime.units import UnitOperationFailed

    label = activated._failure_label
    for message in ("prior boot journal or paths changed",
                    "prior boot journal not bound by this boot's containment",
                    "withdrawal journal or paths changed",
                    "overlay entry remains after withdrawal"):
        assert label(ApprovalRefused(message)) == f"ApprovalRefused: {message}"
    # Raised by the real module, not a hand-built exception.
    with pytest.raises(ApprovalRefused) as raised:
        BootstrapWithdrawalFiles(
            overlay_fd=-1, masks_fd=-1, higher_priority_fd=-1, transient_fd=-1,
            generator_early_fd=-1, overlay_path="/x", masks_path="/x",
            higher_priority_path="/x", transient_path="/x", generator_early_path="/x",
            journal_store=None, guard=None, owner_uid=0)
    assert label(raised.value) == "ApprovalRefused: held withdrawal guard required"
    # The manager's outer refusal keeps the suppressed root reason visible.
    try:
        try:
            raise ApprovalRefused("withdrawal observation changed")
        except ApprovalRefused:
            raise UnitOperationFailed("bootstrap owned withdrawal unconfirmed") from None
    except UnitOperationFailed as exc:
        assert label(exc) == ("UnitOperationFailed: bootstrap owned withdrawal unconfirmed"
                              " <- withdrawal observation changed")


def test_failure_label_follows_reviewed_causes() -> None:
    """A stale selection names its root reason, not just the outer refusal."""
    from azazel_nexus.operator_trust import ApprovalRefused

    def chained():
        try:
            try:
                raise ApprovalRefused("bootstrap selection binding differs")
            except ApprovalRefused:
                raise ApprovalRefused("protected bootstrap selection refused") from None
        except ApprovalRefused:
            raise ApprovalRefused("optional protected bootstrap selection refused") from None

    try:
        chained()
    except ApprovalRefused as exc:
        assert activated._failure_label(exc) == (
            "ApprovalRefused: optional protected bootstrap selection refused"
            " <- protected bootstrap selection refused"
            " <- bootstrap selection binding differs")


def test_failure_label_stops_at_unreviewed_cause() -> None:
    from azazel_nexus.operator_trust import ApprovalRefused

    try:
        try:
            raise ApprovalRefused("secret /etc/path detail")
        except ApprovalRefused as inner:
            raise ApprovalRefused("bootstrap selection required") from inner
    except ApprovalRefused as exc:
        assert activated._failure_label(exc) == "ApprovalRefused: bootstrap selection required"


def test_selection_failure_labels_preserve_each_reviewed_cause():
    from azazel_nexus.bootstrap_selection_store import SELECTION_READ_REASONS, SelectionReadRefused
    import pytest

    for reason in SELECTION_READ_REASONS:
        assert activated._failure_label(SelectionReadRefused(reason)) == (
            "SelectionReadRefused: protected bootstrap selection refused: " + reason)
    with pytest.raises(ValueError, match="unreviewed selection read reason"):
        SelectionReadRefused("private\x1b[31m")
    # Exact types and static messages remain required, even after construction.
    class Derived(SelectionReadRefused):
        pass
    reason = next(iter(SELECTION_READ_REASONS))
    assert activated._failure_label(Derived(reason)) == "Derived"
    error = SelectionReadRefused(reason)
    error.args = ("private detail",)
    assert activated._failure_label(error) == "SelectionReadRefused"


def _ordinary_context(monkeypatch):
    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "c" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    monkeypatch.setattr(Path, "is_dir", lambda path: path == Path("/run/systemd/system"))

    class Session:
        def stop_contextd(self):
            raise AssertionError("no stop in this test")

        def unit_job(self, unit):
            return (0, "/")  # a narrowing confirms no start job is left queued

        def contextd_active_state(self, unit):
            return "inactive"  # the broker is quiet after the narrowing

        def contextd_file_state(self, unit):
            return "masked"

        def __call__(self, method, unit):
            if method == "MaskUnitFiles":
                return [[(unit, "", "")]]
            if method == "GetUnitFileState":
                return "masked"
            if method == "GetInactiveState":
                return True
            raise AssertionError(f"unexpected service-manager call: {method}")

        def reload(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_exc_info):
            return None

    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(lambda *_a: Session()))
    _pass_lock_held(monkeypatch)


@pytest.mark.parametrize("failing", [None, "ready", "barrier", "barrier_timeout"])
@pytest.mark.usefixtures("host_cgroup")
def test_ready_and_barrier_follow_a_recorded_pass(monkeypatch, capsys, failing, private_os):
    """#251 L-2: READY or its barrier failing withdraws every grant and exits 1."""
    private_os(activated)
    from azazel_nexus_runtime import systemd_notify
    from azazel_nexus_runtime.units import UnitOperationFailed

    _ordinary_context(monkeypatch)
    order = []

    def run_once(**_kwargs):
        order.append("pass")
        return SimpleNamespace(granted=("u",), withheld=(), verdicts=())

    def ready():
        order.append("ready")
        if failing == "ready":
            raise UnitOperationFailed("systemd notification refused")

    def barrier():
        order.append("barrier")
        if failing == "barrier":
            raise UnitOperationFailed("systemd notification barrier refused")
        if failing == "barrier_timeout":
            raise UnitOperationFailed("systemd notification barrier timed out")

    def narrow(manager, root, message, **_options):
        order.append(("narrow", root, message))
        error = RuntimeError(f"{message}; emergency remask failures: []")
        error.narrowed = True  # as the real `_emergency_narrow` marks its error
        raise error

    class Ledger:
        def append(self, event):
            order.append(("record", event["event_type"], event["actor"]))

    monkeypatch.setattr(activated, "_run_once", run_once)
    monkeypatch.setattr(activated, "_emergency_narrow", narrow)
    monkeypatch.setattr(activated, "_activation_ledger", lambda root: Ledger())
    monkeypatch.setattr(systemd_notify, "notify_ready", ready)
    monkeypatch.setattr(systemd_notify, "notify_barrier", barrier)
    captured_status = activated.main([])
    captured = capsys.readouterr()
    if failing is None:
        assert captured_status == 0
        assert order == ["pass", "ready", "barrier"]
        assert "completed safely: granted=1" in captured.out
        assert "readiness notification unavailable" not in captured.err
        return
    assert captured_status == 1
    expected = ["pass", "ready"] if failing == "ready" else ["pass", "ready", "barrier"]
    assert order == expected + [
        ("record", "activation.readiness_unconfirmed", "azazel-activated"),
        ("narrow", Path("/"), "activation readiness notification unavailable"),
        # READY may already have released the held start job: the full
        # withdrawal of the broker follows the narrowing and is recorded.
        ("record", "activation.grant_withdrawn", "azazel-activated")]
    # The success line is never printed before (or without) READY.
    assert "completed safely" not in captured.out
    assert "readiness notification unavailable; withdrawing grants" in captured.err
    assert "failed before completing a safe pass" in captured.err


def test_completed_line_follows_ready(monkeypatch, capsys, private_os):
    private_os(activated)
    from azazel_nexus_runtime import systemd_notify

    _ordinary_context(monkeypatch)
    monkeypatch.setattr(activated, "_run_once",
                        lambda **_kwargs: SimpleNamespace(granted=(), withheld=(), verdicts=()))

    def ready():
        assert "completed safely" not in capsys.readouterr().out

    monkeypatch.setattr(systemd_notify, "notify_ready", ready)
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: None)
    assert activated.main([]) == 0
    assert "completed safely: granted=0" in capsys.readouterr().out


def test_no_ready_on_a_failed_pass(monkeypatch, capsys, private_os):
    private_os(activated)
    from azazel_nexus_runtime import systemd_notify

    _ordinary_context(monkeypatch)

    def run_once(**_kwargs):
        raise RuntimeError("private failure")

    monkeypatch.setattr(activated, "_run_once", run_once)
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: pytest.fail("READY on failure"))
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: pytest.fail("barrier on failure"))
    assert activated.main([]) == 1
    assert "failed before completing a safe pass" in capsys.readouterr().err


def test_no_ready_from_the_ordinary_code_on_the_bootstrap_path(monkeypatch, capsys, private_os):
    """The selected bootstrap keeps its own READY protocol; main adds none."""
    private_os(activated)
    from azazel_nexus import bootstrap_selection_optional
    from azazel_nexus_runtime import bootstrap_entrypoint, systemd_notify

    _ordinary_context(monkeypatch)
    monkeypatch.setattr(bootstrap_selection_optional, "load_optional_bootstrap_selection",
                        lambda: object())
    monkeypatch.setattr(bootstrap_entrypoint, "run_selected_bootstrap",
                        lambda selected, *, narrow: SimpleNamespace())
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: pytest.fail("ordinary READY"))
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: pytest.fail("ordinary barrier"))
    assert activated.main([]) == 0



def test_a_connect_that_fails_says_so_at_once_and_fails_closed(monkeypatch, capsys):
    _boot_world(monkeypatch, running=True)

    def refuse(*_args):
        raise activated.UnitOperationFailed("no bus")

    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(refuse))
    with pytest.raises(activated.UnitOperationFailed):
        activated._narrow_bootstrap_core_units()
    err = capsys.readouterr().err
    assert err.count("could not confirm the withdrawal") == 1


@pytest.mark.usefixtures("host_cgroup")
def test_the_emergency_retry_shares_the_first_narrowings_absolute_end(monkeypatch, capsys):
    """One end for the process: once it has passed, a further narrowing says so at once and
    makes no bus call."""
    world = _boot_world(monkeypatch, running=True)
    activated._narrow_bootstrap_core_units()
    end = activated._bootstrap_shared_end
    assert end is not None  # set by the first call
    monkeypatch.setattr(activated, "_bootstrap_shared_end", activated.time.monotonic() - 1.0)
    capsys.readouterr()
    before = len(world.calls)
    with pytest.raises(activated.UnitOperationFailed):
        activated._narrow_bootstrap_core_units()
    assert len(world.calls) == before
    assert capsys.readouterr().err.count("could not confirm the withdrawal") == 1


def test_the_shared_end_fits_inside_the_unit_timeout():
    assert activated._BOOTSTRAP_PROCESS_SECONDS + 10 <= 60  # TimeoutStartSec=60s
    assert activated._BOOTSTRAP_NARROWING_SECONDS <= activated._BOOTSTRAP_PROCESS_SECONDS


@pytest.mark.usefixtures("host_cgroup")
def test_queued_job_records_are_not_a_terminal_message(monkeypatch, capsys):
    """Exactly one terminal message per invocation, and a job record alone is none."""
    world = _boot_world(monkeypatch, running=True)
    real = activated.withdraw_contextd

    def with_job_records(**kwargs):
        kwargs["sink"]({"event_type": "activation.queued_job_replaced"})
        kwargs["sink"]({"event_type": "activation.queued_job_ended"})
        return real(**kwargs)

    monkeypatch.setattr(activated, "withdraw_contextd", with_job_records)
    activated._narrow_bootstrap_core_units()
    err = capsys.readouterr().err
    assert err.count("az-activated bootstrap narrowing") == 1
    assert "withdrew the Knowledge Context broker" in err


@pytest.mark.usefixtures("host_cgroup")
def test_the_session_is_bound_to_the_final_deadline_before_the_other_units(monkeypatch):
    """After the withdrawal (bound to its own, shorter deadline) the other masks run under
    the final deadline: the reserve is not lost."""
    world = _boot_world(monkeypatch, running=True)
    activated._narrow_bootstrap_core_units()
    first_other = next(i for i, (m, u) in enumerate(world.calls)
                       if m == "MaskUnitFiles" and u != activated.CONTEXTD_UNIT)
    bound = [(at, r) for at, r in world.bound if at <= first_other]
    last = bound[-1][1]
    withdrawal_limit = min(r() for _, r in bound)  # the tightest binding seen
    assert last() > withdrawal_limit  # the final deadline was set after the shorter one
    assert last() > activated._BOOTSTRAP_NARROWING_SECONDS - 5.0


def test_a_session_that_finishes_among_the_other_units_is_replaced(monkeypatch):
    world = _boot_world(monkeypatch, running=False)
    real_call = BootBus.__call__
    state = {"n": 0}

    def call(self, method, unit):
        if method == "MaskUnitFiles" and unit != activated.CONTEXTD_UNIT:
            state["n"] += 1
            if state["n"] == 3 and not self.broken:
                self.broken = True
                raise activated.UnitOperationFailed("systemd D-Bus call did not complete")
        return real_call(self, method, unit)

    monkeypatch.setattr(BootBus, "__call__", call)
    try:
        activated._narrow_bootstrap_core_units()
    except activated.UnitOperationFailed:
        pass  # the unit that was in flight is reported
    assert len(world.sessions) >= 2
    assert len(world.masked) == len(activated.CORE_UNITS) - 1  # only the one in flight


def test_every_replacement_session_is_bound_to_the_governing_end(monkeypatch):
    world = _boot_world(monkeypatch, running=False)
    real_call = BootBus.__call__
    state = {"n": 0}

    def call(self, method, unit):
        if method == "MaskUnitFiles" and unit != activated.CONTEXTD_UNIT:
            state["n"] += 1
            if state["n"] == 2 and not self.broken:
                self.broken = True
                raise activated.UnitOperationFailed("systemd D-Bus call did not complete")
        return real_call(self, method, unit)

    monkeypatch.setattr(BootBus, "__call__", call)
    with pytest.raises(activated.UnitOperationFailed):
        activated._narrow_bootstrap_core_units()
    assert len(world.sessions) >= 2
    for session in world.sessions[1:]:
        assert session.limit is not None, "a replacement session was never bound"
        assert 0 < session.limit() <= activated._BOOTSTRAP_NARROWING_SECONDS


@pytest.mark.usefixtures("host_cgroup")
def test_a_job_stage_failure_followed_by_a_withdrawn_broker_says_withdrew(monkeypatch, capsys):
    world = _boot_world(monkeypatch, running=True)
    real = activated.withdraw_contextd

    def with_unconfirmed_job(**kwargs):
        kwargs["sink"]({"event_type": "activation.withdrawal_unconfirmed", "stage": "job"})
        return real(**kwargs)

    monkeypatch.setattr(activated, "withdraw_contextd", with_unconfirmed_job)
    activated._narrow_bootstrap_core_units()
    err = capsys.readouterr().err
    assert err.count("az-activated bootstrap narrowing") == 1 and "withdrew" in err


def test_main_anchors_the_shared_end_at_its_entry(monkeypatch):
    """Not at the first narrowing and not at the process start: at the entry of main."""
    import time as clock_module
    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    original_is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: True if path == Path(
        "/run/systemd/system") else original_is_dir(path))
    seen = []

    def load():
        seen.append(activated._bootstrap_shared_end)
        raise RuntimeError("stop after the anchor")

    import azazel_nexus.bootstrap_selection_optional as optional
    monkeypatch.setattr(optional, "load_optional_bootstrap_selection", load)
    monkeypatch.setattr("azazel_nexus_runtime.bootstrap_entrypoint.narrow_invalid_selection",
                        lambda primary, narrow: None)
    before = clock_module.monotonic()
    activated.main([])
    after = clock_module.monotonic()
    assert seen and before + 50.0 <= seen[0] <= after + 50.0
