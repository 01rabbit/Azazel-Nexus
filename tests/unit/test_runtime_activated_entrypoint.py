"""The installed activation entrypoint composes only in its systemd context.

The decision and rollback behavior is exercised in
``test_runtime_activated.py``. These tests cover the production composition
root without touching host unit state or the fixed host ledger paths.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import activated, runtime_paths
from azazel_nexus_runtime.systemd_bus import SystemdBusSession
from azazel_nexus_runtime.units import DbusUnitManager


@pytest.fixture(autouse=True)
def no_host_bootstrap_selection(monkeypatch):
    from azazel_nexus import bootstrap_selection_optional as bootstrap_selection_store
    monkeypatch.setattr(bootstrap_selection_store, "load_optional_bootstrap_selection", lambda: None)


@pytest.mark.parametrize("mode", ["selected", "invalid", "composition-fails", "emergency-unconfirmed"])
def test_selected_bootstrap_routes_without_ordinary_fallback(monkeypatch, capsys, mode):
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

    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(Session))
    if active:
        with pytest.raises(activated.UnitOperationFailed):
            activated._narrow_bootstrap_core_units()
    else:
        activated._narrow_bootstrap_core_units()
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
    monkeypatch, capsys, uid, systemd_present, invocation_id, root
) -> None:
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


def test_entrypoint_passes_the_system_bus_manager_to_one_fail_closed_pass(
    monkeypatch, capsys
) -> None:
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

        def __enter__(self):
            return self

        def __exit__(self, *_exc_info) -> None:
            return None

    session = ReadOnlySession()
    monkeypatch.setattr(SystemdBusSession, "connect", staticmethod(lambda: session))
    observed: dict[str, object] = {}

    def run_once(*, manager, root, now, actor):
        observed.update(manager=manager, root=root, now=now, actor=actor)
        return SimpleNamespace(
            granted=(),
            withheld=("commissiond",),
            verdicts=(SimpleNamespace(reason="commissioning_record_absent"),),
        )

    monkeypatch.setattr(activated, "_run_once", run_once)

    assert activated.main([]) == 0
    assert isinstance(observed["manager"], DbusUnitManager)
    assert observed["manager"].call is session
    assert observed["root"] == Path("/")
    assert observed["actor"] == "azazel-activated"
    assert str(observed["now"]).endswith("Z")
    assert not calls
    assert "granted=0" in capsys.readouterr().out


def test_entrypoint_does_not_report_a_bus_failure_as_a_safe_pass(
    monkeypatch, capsys
) -> None:
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
        staticmethod(lambda: (_ for _ in ()).throw(ConnectionError("private detail"))),
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
               "bootstrap_restore", "units", "systemd_socket")
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
                   "bootstrap_selection_store"):
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
    found = {m for m in found if "/" not in m and "{" not in m}
    assert activated._STATIC_FAILURE_MESSAGES == found
    assert all("/" not in m and "{" not in m and m.isascii() and m.isprintable()
               for m in activated._STATIC_FAILURE_MESSAGES)


def test_entrypoint_logs_subclass_message_class_only(monkeypatch, capsys) -> None:
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
        staticmethod(lambda: (_ for _ in ()).throw(failure)),
    )


def test_entrypoint_logs_static_refusal_message(monkeypatch, capsys) -> None:
    from azazel_nexus_runtime.units import UnitOperationFailed

    _arrange_bus_failure(
        monkeypatch, UnitOperationFailed("controller one-use start condition refused"))
    assert activated.main([]) == 1
    assert ("failed before completing a safe pass: UnitOperationFailed: "
            "controller one-use start condition refused") in capsys.readouterr().err


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
