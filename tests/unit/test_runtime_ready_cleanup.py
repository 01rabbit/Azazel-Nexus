"""Readiness callback ordering, daemon wiring, and listener cleanup."""

import pytest

from azazel_nexus_runtime import auditd, commissiond, principal, runtime_paths, serve, systemd_notify


class FakeListener:
    def __init__(self, *, timeout_error=None):
        self.timeout_error = timeout_error
        self.closed = False
        self.accept_calls = 0

    def settimeout(self, _timeout):
        if self.timeout_error is not None:
            raise self.timeout_error

    def accept(self):
        self.accept_calls += 1
        raise AssertionError("accept must not run after startup failure")

    def close(self):
        self.closed = True


@pytest.mark.parametrize("failure_point", ["timeout", "engine", "ready"])
def test_startup_failure_closes_listener_and_unlinks_socket(
    tmp_path, monkeypatch, failure_point
):
    path = tmp_path / "daemon.sock"
    path.touch()
    listener = FakeListener(
        timeout_error=RuntimeError("timeout setup failed")
        if failure_point == "timeout"
        else None
    )
    monkeypatch.setattr(serve, "bind_socket", lambda _path, **_kwargs: listener)

    if failure_point == "engine":
        def fail_engine(**_kwargs):
            raise RuntimeError("engine construction failed")

        monkeypatch.setattr(serve, "SocketServer", fail_engine)
    else:
        monkeypatch.setattr(serve, "SocketServer", lambda **_kwargs: object())

    def fail_ready():
        raise RuntimeError("readiness failed")

    ready = fail_ready if failure_point == "ready" else None
    with pytest.raises(RuntimeError):
        serve.serve_forever(
            path=path,
            registry=object(),
            policy=object(),
            audit=lambda _event: None,
            handler=lambda _request: None,
            ready=ready,
        )

    assert listener.closed
    assert listener.accept_calls == 0
    assert not path.exists()


def _capture_serve(monkeypatch, module):
    calls = []

    def fake_serve_forever(**kwargs):
        calls.append(kwargs)
        return 17

    target = serve if module is auditd else module
    monkeypatch.setattr(target, "serve_forever", fake_serve_forever)
    return calls


@pytest.mark.parametrize("module", [auditd, commissiond])
def test_daemon_main_uses_default_readiness_callback(
    monkeypatch, tmp_path, module
):
    calls = _capture_serve(monkeypatch, module)
    def expected_ready():
        pass
    monkeypatch.setattr(systemd_notify, "runtime_ready_callback", lambda: expected_ready)
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", classmethod(lambda cls: object()))
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda _service: object())
    monkeypatch.setattr(runtime_paths, "socket_path", lambda name: tmp_path / f"{name}.sock")

    if module is auditd:
        monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path)
        monkeypatch.setattr(
            module.AuditService,
            "start",
            lambda self: setattr(self, "verified", True),
        )

    assert module.main() == 17
    assert calls[0]["ready"] is expected_ready


@pytest.mark.parametrize("module", [auditd, commissiond])
def test_daemon_main_preserves_explicit_readiness_callback(
    monkeypatch, tmp_path, module
):
    calls = _capture_serve(monkeypatch, module)
    def explicit_ready():
        pass
    monkeypatch.setattr(
        systemd_notify,
        "runtime_ready_callback",
        lambda: pytest.fail("default callback must not replace explicit callback"),
    )
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", classmethod(lambda cls: object()))
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda _service: object())
    monkeypatch.setattr(runtime_paths, "socket_path", lambda name: tmp_path / f"{name}.sock")

    if module is auditd:
        monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path)
        monkeypatch.setattr(
            module.AuditService,
            "start",
            lambda self: setattr(self, "verified", True),
        )

    assert module.main(ready=explicit_ready) == 17
    assert calls[0]["ready"] is explicit_ready


def test_auditd_chain_start_failure_never_resolves_or_calls_readiness(
    monkeypatch, tmp_path
):
    def fail_start(_self):
        raise RuntimeError("ledger verification failed")

    monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path)
    monkeypatch.setattr(auditd.AuditService, "start", fail_start)
    monkeypatch.setattr(
        systemd_notify,
        "runtime_ready_callback",
        lambda: pytest.fail("readiness must not be resolved before chain verification"),
    )
    monkeypatch.setattr(
        serve,
        "serve_forever",
        lambda **_kwargs: pytest.fail("must not serve after chain verification failure"),
    )

    with pytest.raises(RuntimeError, match="ledger verification failed"):
        auditd.main()


def test_auditd_unverified_chain_keeps_diagnostics_but_withholds_readiness(
    monkeypatch, tmp_path
):
    calls = _capture_serve(monkeypatch, auditd)

    def report_broken_chain(service):
        service.verified = False
        service.break_reason = "bad event hash"

    monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path)
    monkeypatch.setattr(auditd.AuditService, "start", report_broken_chain)
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda _service: object())
    monkeypatch.setattr(runtime_paths, "socket_path", lambda name: tmp_path / f"{name}.sock")
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", classmethod(lambda cls: object()))
    monkeypatch.setattr(
        systemd_notify,
        "runtime_ready_callback",
        lambda: pytest.fail("an unverified ledger must not resolve readiness"),
    )

    assert auditd.main() == 17
    kwargs = calls[0]
    assert kwargs["ready"] is None
    diagnostic = kwargs["handler"](
        type("Request", (), {"verb": type("Verb", (), {"name": "audit.verify"})()})()
    )
    assert diagnostic["verified"] is False
    assert diagnostic["break"] == "bad event hash"


def test_listener_remains_available_without_ready_callback(tmp_path, monkeypatch):
    path = tmp_path / "daemon.sock"
    path.touch()

    class DiagnosticListener(FakeListener):
        def accept(self):
            self.accept_calls += 1
            raise OSError("test listener shutdown")

    listener = DiagnosticListener()
    monkeypatch.setattr(serve, "bind_socket", lambda _path, **_kwargs: listener)
    monkeypatch.setattr(serve, "SocketServer", lambda **_kwargs: object())

    result = serve.serve_forever(
        path=path,
        registry=object(),
        policy=object(),
        audit=lambda _event: None,
        handler=lambda _request: {"verified": False},
        ready=None,
    )

    assert result == 0
    assert listener.accept_calls == 1
    assert listener.closed
    assert not path.exists()
