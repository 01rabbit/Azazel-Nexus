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
            raise ApprovalRefused("private invalid selection")
        return selected

    def run(actual, *, narrow):
        assert actual is selected and callable(narrow)
        calls.append("bootstrap")
        if mode == "emergency-unconfirmed":
            failure = ApprovalRefused("private primary failure")
            failure.add_note(bootstrap_entrypoint.EMERGENCY_UNCONFIRMED)
            raise failure
        if mode == "composition-fails":
            raise ApprovalRefused("private incomplete gate")

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
