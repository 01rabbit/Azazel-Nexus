"""The UI account `azui` holds no service or operator authority at any daemon.

`azui` used to be in `SERVICE_ACCOUNTS`, so every daemon that resolved its
principal policy with the default service list (the model fetcher, watchdog,
commissiond) or with that list plus an extra (auditd) classified the UI as a
SERVICE principal. `model.fetch` and `audit.append` admit SERVICE, so a UI
process that could reach those sockets could start an outbound model
acquisition or append audit events.

These tests find every `serve_forever` site in the runtime the same way
`test_incident_explaind.test_explainer_privilege_at_every_runtime_policy_site`
does, rebuild the policy exactly as the site builds it, and check every verb of
every listener the site binds. A new daemon or listener is covered without
editing this file; a site whose policy or registry cannot be rebuilt fails the
test rather than being skipped.
"""

from __future__ import annotations

import ast
import importlib
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import principal
from azazel_nexus_runtime.principal import PrincipalClass, PrincipalPolicy
from azazel_nexus_runtime.protocol import Refusal, RequestRefused
from azazel_nexus_runtime.transport import SocketServer, bind_socket

PACKAGE = Path(principal.__file__).parent
OPERATOR_GID = 7


def _evaluate(node: ast.AST, namespace: dict):
    return eval(compile(ast.Expression(body=node), "<site>", "eval"), dict(namespace))


def _server_sites():
    """`(module name, line, resolve kwargs, {listener: registry})` for every server."""

    sites = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "serve_forever"]
        if not calls:
            continue
        module = importlib.import_module(f"azazel_nexus_runtime.{path.stem}")
        # Some daemons import from `.principal` inside `main()` (auditd's
        # SERVICE_ACCOUNTS); those names are the principal module's.
        namespace = {**vars(principal), **vars(module)}
        for call in calls:
            keywords = {k.arg: k.value for k in call.keywords}
            policy = keywords["policy"]
            assert (isinstance(policy, ast.Call) and isinstance(policy.func, ast.Attribute)
                    and policy.func.attr == "resolve" and isinstance(policy.func.value, ast.Name)
                    and policy.func.value.id == "PrincipalPolicy"
                    and not policy.args), (path.name, call.lineno)
            kwargs = {k.arg: _evaluate(k.value, namespace) for k in policy.keywords}
            registries = {"main": _evaluate(keywords["registry"], namespace)}
            extra = keywords.get("additional_sockets")
            if extra is not None:
                assert isinstance(extra, ast.Tuple), (path.name, call.lineno)
                for element in extra.elts:
                    if isinstance(element, ast.Tuple):
                        # `(socket_path(name), gid, registry)` written out.
                        assert len(element.elts) == 3, (path.name, call.lineno)
                        name = ast.unparse(element.elts[0])
                        registries[name] = _evaluate(element.elts[2], namespace)
                        continue
                    assert (isinstance(element, ast.Call) and isinstance(element.func, ast.Name)
                            and element.func.id == "dedicated_listener"), (path.name, call.lineno)
                    name = _evaluate(element.args[0], namespace)
                    registries[name] = _evaluate(element.args[1], namespace)
            sites.append((path.stem, call.lineno, kwargs, registries))
    return sites


@pytest.fixture
def accounts(monkeypatch):
    table = {name: 2000 + n for n, name in enumerate(principal.DAEMON_ACCOUNTS)}
    monkeypatch.setattr(principal.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=table[name]))
    monkeypatch.setattr(principal.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=OPERATOR_GID))
    return table


def test_azui_is_a_daemon_account_but_never_a_default_service():
    assert "azui" not in principal.SERVICE_ACCOUNTS
    assert "azui" in principal.DAEMON_ACCOUNTS


def test_every_daemon_server_is_found():
    found = {stem for stem, *_ in _server_sites()}
    # The daemons the U4 review named, plus every other socket server today.
    assert {"model_fetchd", "auditd", "watchdog", "commissiond"} <= found
    assert found == {"auditd", "commissiond", "knowledge_lited", "mio_entryd",
                     "knowledge_contextd", "mio_locald", "mio_referenced",
                     "model_fetchd", "watchdog"}


def test_azui_is_refused_every_verb_at_every_daemon(accounts):
    ui = accounts["azui"]
    checked = 0
    for stem, line, kwargs, registries in _server_sites():
        policy = PrincipalPolicy.resolve(**kwargs)
        assert ui not in policy.service_uids, (stem, line)
        # Worst case included: even an azui process wrongly given the operator
        # group, as primary or supplementary, gains no class.
        for gid, groups in ((ui, ()), (OPERATOR_GID, ()), (ui, (OPERATOR_GID,))):
            caller = policy.classify(ui, gid, 1, groups)
            assert caller.classes == frozenset(), (stem, line, gid, groups)
            for listener, registry in registries.items():
                assert registry.names(), (stem, listener)
                for verb in registry.names():
                    with pytest.raises(RequestRefused) as refused:
                        registry.resolve(verb, caller)
                    assert refused.value.refusal is Refusal.PRINCIPAL_DENIED, (stem, listener, verb)
                    checked += 1
    assert checked


def test_legitimate_service_callers_are_still_services(accounts):
    """Narrowing removed azui only; every other listed service keeps its class."""

    by_stem = {}
    for stem, line, kwargs, registries in _server_sites():
        policy = PrincipalPolicy.resolve(**kwargs)
        listed = tuple(kwargs.get("service_accounts", principal.SERVICE_ACCOUNTS))
        assert "azui" not in listed, (stem, line)
        for name in listed:
            caller = policy.classify(accounts[name], accounts[name], 1)
            assert caller.classes == frozenset({PrincipalClass.SERVICE}), (stem, name)
        by_stem[stem] = (policy, registries)

    def admitted(stem, listener, account, verb):
        policy, registries = by_stem[stem]
        caller = policy.classify(accounts[account], accounts[account], 1)
        return registries[listener].resolve(verb, caller).name == verb

    # incident_explaind -> auditd's audit-submit listener.
    assert admitted("auditd", "audit-submit", "azexplain", "audit.append")
    # The specification's service accounts keep audit.append and model.fetch.
    for account in ("azarbiter", "azwatch", "azcommission", "azaudit"):
        assert admitted("auditd", "main", account, "audit.append")
        assert admitted("model_fetchd", "main", account, "model.fetch")
    assert admitted("knowledge_lited", "main", "azexplain", "knowledge.status")


# -- real kernel peer credentials ------------------------------------------

_CLIENT = r"""
import json, socket, struct, sys
path, verb, arguments = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
body = json.dumps({"verb": verb, "arguments": arguments}).encode()
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5.0)
client.connect(path)
client.sendall(struct.pack("!I", len(body)) + body)
client.shutdown(socket.SHUT_WR)
data = b""
while True:
    chunk = client.recv(65536)
    if not chunk:
        break
    data += chunk
sys.stdout.write(data[4:].decode())
"""


def _call_from_another_process(tmp_path, registry, policy, verb, handled, arguments=None):
    path = tmp_path / "d.sock"
    listener = bind_socket(path)
    recorded = []
    engine = SocketServer(registry=registry, policy=policy, audit=recorded.append, deadline=5.0)

    def serve():
        connection, _ = listener.accept()
        with connection:
            engine.serve_connection(connection, lambda request: handled.append(request) or {})

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        out = subprocess.run([sys.executable, "-I", "-c", _CLIENT, str(path), verb,
                              json.dumps(arguments or {})],
                             capture_output=True, text=True, timeout=20, check=True).stdout
    finally:
        worker.join(timeout=10)
        listener.close()
        path.unlink(missing_ok=True)
    assert not worker.is_alive()
    return json.loads(out), recorded


@pytest.fixture
def linux_peer_accounts(monkeypatch):
    if sys.platform != "linux":
        pytest.skip("SO_PEERCRED is Linux-specific")
    if os.getuid() == 0:
        pytest.skip("root is ROOT whatever account it is mapped to")
    real = os.getuid()

    def mapping(as_account):
        table = {name: 3000 + n for n, name in enumerate(principal.DAEMON_ACCOUNTS)}
        assert real not in table.values()
        table[as_account] = real
        monkeypatch.setattr(principal.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=table[name]))
        # The caller's own primary group stands in for azazel-operator: the
        # kernel-attached gid is then the operator group, the worst case.
        monkeypatch.setattr(principal.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    return mapping


def test_real_process_with_azui_credentials_is_refused_every_verb(tmp_path, linux_peer_accounts):
    """A separate process whose kernel uid is azui's, at every daemon's listeners."""

    linux_peer_accounts("azui")
    served = 0
    for stem, line, kwargs, registries in _server_sites():
        policy = PrincipalPolicy.resolve(**kwargs)
        for listener, registry in registries.items():
            for verb in registry.names():
                handled = []
                reply, recorded = _call_from_another_process(tmp_path, registry, policy, verb, handled)
                assert reply == {"ok": False, "refusal": "principal_denied"}, (stem, listener, verb)
                assert handled == [], (stem, listener, verb)
                assert recorded and recorded[-1]["classes"] == []
                assert recorded[-1]["uid"] == os.getuid(), (stem, verb)
                served += 1
    assert served


def test_real_process_explainer_still_reaches_audit_append(tmp_path, linux_peer_accounts):
    from azazel_nexus_runtime import auditd

    linux_peer_accounts("azexplain")
    policy = PrincipalPolicy.resolve(service_accounts=principal.SERVICE_ACCOUNTS + ("azexplain",))
    handled = []
    event_type = auditd._LIMITED_TYPES[0]
    reply, recorded = _call_from_another_process(tmp_path, auditd.SUBMIT_REGISTRY, policy,
                                                 "audit.append", handled, {"event_type": event_type})
    assert reply == {"ok": True, "result": {}}, reply
    assert recorded == []
    assert len(handled) == 1 and handled[0].principal.classes == frozenset({PrincipalClass.SERVICE})
    assert handled[0].principal.uid == os.getuid()
