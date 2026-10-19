"""The explainer's append-only audit listener (#213 O1)."""

from __future__ import annotations

import grp
import json
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import auditd, mio_entryd, runtime_paths, serve
from azazel_nexus_runtime.principal import (
    Principal,
    PrincipalClass,
    PrincipalPolicy,
    SocketMisconfigured,
)
from azazel_nexus_runtime.transport import read_frame, send_frame

SERVICE = Principal(uid=900, gid=900, pid=7, classes=frozenset({PrincipalClass.SERVICE}))


def test_submit_listener_registers_append_alone_by_name():
    assert auditd.SUBMIT_REGISTRY.names() == ("audit.append",)
    assert auditd.SUBMIT_REGISTRY.resolve("audit.append", SERVICE) is next(
        verb for verb in auditd.VERBS if verb.name == "audit.append")
    assert mio_entryd.ADVISE_REGISTRY.names() == ("mio.advise",)


@pytest.mark.parametrize(("name", "group"), [("audit-submit", "azaudit-submit"),
                                             ("mio-advise", "azmio-advise")])
@pytest.mark.parametrize("missing", ["group", "leaf"])
def test_an_unprovisioned_listener_is_named_with_its_remedy(tmp_path, monkeypatch, name, group, missing):
    """Runtime upgraded without re-running install.sh: a clear refusal naming
    the group or leaf and the remedy, not a KeyError or a bind traceback."""
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    if missing == "leaf":
        monkeypatch.setattr(grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=4321))
        expected = f"socket leaf .*{name}"
    else:
        runtime_paths.socket_path(name).parent.mkdir(parents=True)

        def absent(_name):
            raise KeyError(_name)
        monkeypatch.setattr(grp, "getgrnam", absent)
        expected = f"group {group} "
    with pytest.raises(SocketMisconfigured, match=expected) as refused:
        runtime_paths.dedicated_listener(name, object())
    assert "re-run packaging/install.sh" in str(refused.value)


def test_operator_leaves_have_no_dedicated_listener():
    with pytest.raises(ValueError):
        runtime_paths.dedicated_listener("audit", object())


def test_auditd_refuses_before_serving_when_unprovisioned(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.ledger_dir().mkdir(parents=True)

    def absent(_name):
        raise KeyError(_name)
    monkeypatch.setattr(grp, "getgrnam", absent)
    monkeypatch.setattr(serve, "serve_forever", lambda **_: pytest.fail("must not serve"))
    with pytest.raises(SocketMisconfigured, match="azaudit-submit"):
        auditd.main(ready=lambda: None)


def _ask(path, verb, arguments=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        send_frame(connection, {"verb": verb, "arguments": arguments or {}})
        connection.shutdown(socket.SHUT_WR)
        return json.loads(read_frame(connection))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_PEERCRED round trip")
def test_real_submit_socket_refuses_every_verb_but_append(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="azaud-", dir="/tmp") as directory:
        monkeypatch.setattr(runtime_paths, "ROOT", Path(directory))
        for leaf in ("audit", "audit-submit"):
            runtime_paths.socket_path(leaf).parent.mkdir(parents=True)
        runtime_paths.ledger_dir().mkdir(parents=True)
        monkeypatch.setattr(runtime_paths, "audit_sink", lambda _name: lambda event: None)
        monkeypatch.setattr(grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=os.getgid()))
        # The caller is an operator here: the operator socket serves it as before.
        policy = PrincipalPolicy(os.getgid(), frozenset())
        monkeypatch.setattr(PrincipalPolicy, "resolve", classmethod(lambda cls, **_: policy))
        ready, stop, errors = threading.Event(), threading.Event(), []

        def run():
            try:
                auditd.main(ready=ready.set, stop=stop.is_set)
            except Exception as error:  # noqa: BLE001 - surfaced below
                errors.append(error)
                ready.set()

        thread = threading.Thread(target=run)
        thread.start()
        operator_path = runtime_paths.socket_path("audit")
        submit = runtime_paths.socket_path("audit-submit")
        try:
            assert ready.wait(5)
            assert not errors, errors
            assert _ask(operator_path, "audit.verify")["ok"] is True
            for verb in ("audit.verify", "audit.bootstrap.append", "audit.bootstrap.observe"):
                assert _ask(submit, verb) == {"ok": False, "refusal": "unknown_verb"}, verb
            # append is a verb there; this non-SERVICE caller is still refused by class.
            assert _ask(submit, "audit.append", {"event_type": "edge.incident.opened"}) == {
                "ok": False, "refusal": "principal_denied"}
        finally:
            stop.set()
            thread.join(5)
        assert not thread.is_alive()
        assert not submit.exists() and not operator_path.exists()
