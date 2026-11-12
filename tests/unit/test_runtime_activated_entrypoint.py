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


@pytest.mark.parametrize("active", [False, True])
def test_bootstrap_broad_narrowing_attempts_all_core_units_without_start(monkeypatch, active):
    calls = []

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def __call__(self, method, unit):
            calls.append((method, unit))
            if method == "MaskUnitFiles":
                return []
            if method == "GetUnitFileState":
                return "masked"
            if method == "GetInactiveState":
                return not active
            pytest.fail("unexpected widening operation")

    monkeypatch.setattr(activated, "reset_grant_markers", lambda _root: None)
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(Session))
    if active:
        with pytest.raises(activated.UnitOperationFailed):
            activated._narrow_bootstrap_core_units()
    else:
        activated._narrow_bootstrap_core_units()
    assert [unit for method, unit in calls if method == "MaskUnitFiles"] == [
        definition.name for definition in activated.CORE_UNITS
    ]


@pytest.mark.parametrize("reset_fails", [False, True])
def test_bootstrap_broad_narrowing_removes_grant_markers_first(monkeypatch, capsys,
                                                            reset_fails):
    """#251 L-7: like _emergency_narrow, markers first; a refusal still remasks."""
    calls = []

    def reset(root):
        calls.append(("reset", root))
        if reset_fails:
            raise RuntimeError("grant markers")

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def __call__(self, method, unit):
            calls.append((method, unit))
            if method == "MaskUnitFiles":
                return []
            if method == "GetUnitFileState":
                return "masked"
            if method == "GetInactiveState":
                return True
            pytest.fail("unexpected widening operation")

    monkeypatch.setattr(activated, "reset_grant_markers", reset)
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(Session))
    if reset_fails:
        with pytest.raises(activated.UnitOperationFailed):
            activated._narrow_bootstrap_core_units()
    else:
        activated._narrow_bootstrap_core_units()
    assert calls[0] == ("reset", Path("/"))
    assert capsys.readouterr().err == (
        "az-activated could not remove grant markers during bootstrap narrowing\n"
        if reset_fails else "")
    assert [unit for method, unit in calls if method == "MaskUnitFiles"] == [
        definition.name for definition in activated.CORE_UNITS
    ]


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
        raise RuntimeError(f"{message}; emergency remask failures: []")

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

