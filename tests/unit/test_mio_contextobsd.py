"""The model-free context observation unit (#439, docs/adr/0010-context-observation-unit.md).

`azazel-mio-contextobsd.service` is the Knowledge Context broker's only
SERVICE principal and answers the entry service alone. These tests pin who
may reach it (the socket's group and owner on the client side, the kernel
peer uid on the server side), who the broker admits, what the process loads,
and which activation lists it is in.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
from azazel_nexus_runtime import knowledge_contextd, principal, runtime_paths
from azazel_nexus_runtime import mio_contextobsd as obsd
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime.activation_markers import GRANTABLE_UNITS
from azazel_nexus_runtime.hardening import GRANT_MARKER_UNITS, SYSTEM_ACCOUNTS
from azazel_nexus_runtime.principal import DAEMON_ACCOUNTS, PrincipalClass
from azazel_nexus_runtime.protocol import Refusal, RequestRefused
from azazel_nexus_runtime.transport import read_frame, send_frame
from test_mio_context_observe import good_fast, obs_frame
from test_mio_reference import MODEL_MODULES

UNIT = "azazel-mio-contextobsd.service"
LOCALD = "azazel-mio-locald.service"

#: Mission Pack code, and the modules of the model host's own process.
MISSION_MODULES = (
    "azazel_nexus.mission_pack", "azazel_nexus.playbook_selection",
    "azazel_nexus_runtime.mio_playbooks", "azazel_nexus_runtime.mio_generation",
    "azazel_nexus_runtime.mio_socket_client",
)

#: Fake account table: distinct uids, one shared group id for the socket group.
UIDS = {"azmioentry": 41001, "azmioctx": 41002, "azmio": 41003, "azexplain": 41004,
        "azmioref": 41005, "azknowledgeegress": 41006}
GROUP_GID = 42001


# ---- the lists ----------------------------------------------------------

def test_the_unit_is_grantable_and_locald_stays_out():
    assert UNIT in ACTIVATION_UNIT_ALLOWLIST and UNIT in GRANTABLE_UNITS
    assert UNIT in GRANT_MARKER_UNITS
    assert LOCALD not in ACTIVATION_UNIT_ALLOWLIST and LOCALD not in GRANTABLE_UNITS
    definition = next(item for item in CORE_UNITS if item.name == UNIT)
    assert definition.account == "azmioctx"
    assert getattr(definition, "wiring", None) is None


def test_the_account_is_created_and_is_a_daemon_never_a_default_service():
    assert "azmioctx" in SYSTEM_ACCOUNTS and "azmioctx" in DAEMON_ACCOUNTS
    assert "azmioctx" not in principal.SERVICE_ACCOUNTS
    assert obsd.ACCOUNT == "azmioctx" and obsd.ENTRY_ACCOUNT == "azmioentry"
    assert runtime_paths.socket_group(obsd.SOCKET_NAME) == "azmio-contextobs"


def test_main_takes_no_arguments():
    with pytest.raises(SystemExit, match="takes no arguments"):
        obsd.main(["--model", "x"])


# ---- what the process loads ---------------------------------------------

def _loaded(code: str) -> list[str]:
    forbidden = MODEL_MODULES + MISSION_MODULES
    program = textwrap.dedent(f"""
        import sys
        {code}
        print(sorted(m for m in {forbidden!r} if m in sys.modules))
    """)
    result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True,
                            check=True, timeout=60)
    return json.loads(result.stdout.strip().replace("'", '"'))


def test_the_process_loads_no_model_admission_mission_or_knowledge_lite_code():
    assert _loaded("import azazel_nexus_runtime.mio_contextobsd") == []
    # The library admission module is not reached by the module itself either.
    program = ("import sys, azazel_nexus_runtime.mio_contextobsd; "
               "print('azazel_nexus.model_admission' in sys.modules)")
    result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True,
                            check=True, timeout=60)
    assert result.stdout.strip() == "False"


def test_the_request_path_loads_no_model_host_or_mission_code():
    """What the handler imports lazily (the frame reader and the fast core).

    `azazel_nexus.incident_explain` reaches the admission *library* through
    `activation` (as it does in entryd); the model host's modules, the
    runtime, the admission evidence holder and Mission Pack selection stay
    out.
    """
    code = textwrap.dedent("""
        import azazel_nexus_runtime.mio_contextobsd
        import azazel_nexus.incident_explain
        import azazel_nexus_runtime.mio_fast_degraded
        try:
            import azazel_nexus_runtime.mio_fast_assistance
        except ImportError:
            pass
    """).replace("\n", "\n        ")
    loaded = _loaded(code)
    assert [m for m in loaded if m != "azazel_nexus.model_admission"] == []


# ---- the server side: kernel peer credentials -------------------------------

@pytest.fixture
def accounts(monkeypatch):
    def getpwnam(name):
        if name in UIDS:
            return SimpleNamespace(pw_uid=UIDS[name])
        raise KeyError(name)

    def getgrnam(name):
        if name == "azmio-contextobs":
            return SimpleNamespace(gr_gid=GROUP_GID)
        if name == "azknowledge-context-client":
            return SimpleNamespace(gr_gid=GROUP_GID + 1)
        raise KeyError(name)

    monkeypatch.setattr(principal.pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(principal.grp, "getgrnam", getgrnam)
    return UIDS


def _served_policy(main, monkeypatch):
    captured = {}

    class Ledger:
        def __init__(self, path):
            self.path = SimpleNamespace(open=lambda *a, **k: open(os.devnull, *a, **k))

        def verify(self, **_kwargs):
            pass

        def __iter__(self):
            return iter(())

        def append(self, event):
            captured.setdefault("ledger", []).append(event)

    module = sys.modules[main.__module__]
    monkeypatch.setattr(module, "AuditLedger", Ledger)
    monkeypatch.setattr(module, "serve_forever", lambda **kw: captured.update(kw) or 0)
    assert main([]) == 0
    return captured


def _verdict(policy, registry, verb, uid, gid=GROUP_GID, groups=()):
    who = policy.classify(uid, gid, 1234, groups)
    try:
        registry.resolve(verb, who)
    except RequestRefused as refused:
        return refused.refusal
    return "admitted"


def test_the_service_admits_azmioentry_only(accounts, monkeypatch):
    served = _served_policy(obsd.main, monkeypatch)
    policy, registry = served["policy"], served["registry"]
    assert served["path"] == runtime_paths.socket_path("mio-contextobs")
    # The socket is bound to its own group, the one the client verifies.
    assert policy.operator_gid == GROUP_GID
    assert runtime_paths.socket_group("mio-contextobs") == "azmio-contextobs"
    verb = obsd.CONTEXT_OBSERVE_VERB.name
    assert _verdict(policy, registry, verb, UIDS["azmioentry"]) == "admitted"
    # Others in the same group, root, the model host and the explainer are refused.
    for uid in (UIDS["azmio"], UIDS["azexplain"], UIDS["azmioref"], UIDS["azmioctx"], 0, 50000):
        assert _verdict(policy, registry, verb, uid) is Refusal.PRINCIPAL_DENIED, uid
        assert _verdict(policy, registry, verb, uid, gid=1, groups=(GROUP_GID,)) is (
            Refusal.PRINCIPAL_DENIED), uid
    # The handler writes nothing at start, and its handler is the service's.
    assert "ledger" not in served
    assert served["handler"].__self__.__class__ is obsd.ContextObservationService


def test_the_broker_admits_azmioctx_only(accounts, monkeypatch):
    monkeypatch.setattr(knowledge_contextd, "load_commissioning",
                        lambda: SimpleNamespace(status="absent", reason_code=None,
                                                registry_version=None))
    monkeypatch.setattr(knowledge_contextd, "load_observation_rule", lambda: None)
    # The ledger here is a stand-in; so is the writer lock (the real one lives in the
    # broker's state directory, which this test does not create).
    monkeypatch.setattr(knowledge_contextd, "_take_writer_lock",
                        lambda directory: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr(knowledge_contextd, "_take_socket_lock",
                        lambda path: os.open(os.devnull, os.O_RDONLY))
    served = _served_policy(knowledge_contextd.main, monkeypatch)
    policy, registry = served["policy"], served["registry"]
    verb = knowledge_contextd.CONTEXT_VERB.name
    assert _verdict(policy, registry, verb, UIDS["azmioctx"]) == "admitted"
    for uid in (UIDS["azmio"], UIDS["azmioentry"], UIDS["azexplain"], 0):
        assert _verdict(policy, registry, verb, uid) is Refusal.PRINCIPAL_DENIED, uid
        assert _verdict(policy, registry, verb, uid, gid=1, groups=(GROUP_GID,)) is (
            Refusal.PRINCIPAL_DENIED), uid


# ---- real sockets: both sides check ----------------------------------------

class Daemon:
    def __init__(self, main):
        self.ready, self.stop, self.errors = threading.Event(), threading.Event(), []
        self.thread = threading.Thread(target=self._run, args=(main,))

    def _run(self, main):
        try:
            main([], ready=self.ready.set, stop=self.stop.is_set)
        except BaseException as error:  # noqa: BLE001 - surfaced to the test
            self.errors.append(error)
            self.ready.set()

    def __enter__(self):
        self.thread.start()
        assert self.ready.wait(10)
        if self.errors:
            raise self.errors[0]
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(10)
        assert not self.thread.is_alive()


@pytest.fixture
def root(monkeypatch):
    if sys.platform != "linux":
        pytest.skip("Linux SO_PEERCRED required")
    with tempfile.TemporaryDirectory(prefix="azctx-", dir="/tmp") as directory:
        base = Path(directory)
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(runtime_paths, "ROOT", base)
        leaf = runtime_paths.socket_path("mio-contextobs").parent
        leaf.mkdir(parents=True)
        os.chmod(leaf, 0o2710)
        runtime_paths.mio_contextobs_state_dir().mkdir(parents=True)
        monkeypatch.setattr(principal.grp, "getgrnam",
                            lambda name: SimpleNamespace(gr_gid=os.getgid()))
        monkeypatch.setattr(client.grp, "getgrnam",
                            lambda name: SimpleNamespace(gr_gid=os.getgid()))
        yield base


def _ask(deadline_ms=300):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(runtime_paths.socket_path("mio-contextobs")))
        send_frame(connection, {"verb": obsd.CONTEXT_OBSERVE_VERB.name,
                                "arguments": {"deadline_ms": deadline_ms}, "event": obs_frame()})
        connection.shutdown(socket.SHUT_WR)
        return json.loads(read_frame(connection))


def _as_entry(monkeypatch, entry_uid):
    def getpwnam(name):
        if name == "azmioentry":
            return SimpleNamespace(pw_uid=entry_uid)
        raise KeyError(name)

    monkeypatch.setattr(principal.pwd, "getpwnam", getpwnam)


def test_a_caller_that_is_not_entry_is_refused_by_kernel_credentials(root, monkeypatch):
    # This process is in the socket's group but is not the entry account.
    _as_entry(monkeypatch, os.getuid() + 1)
    monkeypatch.setattr(obsd, "request_context", lambda *a, **k: pytest.fail("queried"))
    with Daemon(obsd.main):
        reply = _ask()
    assert reply == {"ok": False, "refusal": "principal_denied"}
    from azazel_nexus.audit import AuditLedger
    events = [entry.event for entry in
              AuditLedger(runtime_paths.mio_contextobs_state_dir() / "contextobs.jsonl")]
    # The socket layer's refusal is the only record; the handler wrote nothing.
    assert [e["event_type"] for e in events] == ["runtime.request_refused"]
    assert events[0]["reason"] == "principal_denied"
    assert events[0]["verb"] == obsd.CONTEXT_OBSERVE_VERB.name


def test_entry_is_served_and_nothing_is_recorded(root, monkeypatch):
    _as_entry(monkeypatch, os.getuid())
    seen = []

    def request_context(query, *, deadline_s):
        seen.append(query)
        raise obsd.KnowledgeContextUnavailable("closed")

    monkeypatch.setattr(obsd, "request_context", request_context)
    with Daemon(obsd.main):
        reply = _ask()
    assert reply["ok"] is True
    result = reply["result"]
    assert result["outcome"] == "context_observed"
    assert set(result["timing"]) == {"context", "broker_ms", "total_ms", "core"}
    assert seen == [{"privacy_class": "P0-public", "techniques": ["T1059", "T1059.001"]}]
    ledger = runtime_paths.mio_contextobs_state_dir() / "contextobs.jsonl"
    assert ledger.read_text() == ""


def test_the_client_checks_the_owner_group_and_peer_of_the_socket(root, monkeypatch):
    _as_entry(monkeypatch, os.getuid())
    def closed(*args, **kwargs):
        raise obsd.KnowledgeContextUnavailable("closed")

    monkeypatch.setattr(obsd, "request_context", closed)
    seen = {}
    real_verify = client.verify_socket

    def verify(path, *, expected_uid, expected_gid):
        seen.update(path=path, uid=expected_uid, gid=expected_gid)
        return real_verify(path, expected_uid=expected_uid, expected_gid=expected_gid)

    monkeypatch.setattr(client, "verify_socket", verify)
    observer = client.ContextObserveSocketClient()
    with Daemon(obsd.main):
        # The service runs as this uid: as azmioctx, it is served.
        monkeypatch.setattr(client.pwd, "getpwnam",
                            lambda name: SimpleNamespace(pw_uid=os.getuid()))
        fast, timing = observer.observe_context_timed(obs_frame(), deadline_s=0.3)
        assert timing is not None and timing["context"] in {"unavailable", "refused"}
        assert seen["path"] == runtime_paths.socket_path("mio-contextobs")
        assert seen["gid"] == os.getgid()
        # A socket owned by anyone but azmioctx is refused before connecting.
        monkeypatch.setattr(client.pwd, "getpwnam",
                            lambda name: SimpleNamespace(pw_uid=os.getuid() + 1))
        fast, timing = observer.observe_context_timed(obs_frame(), deadline_s=0.3)
        assert timing is None
        assert fast["dependency_outcome"]["knowledge"] == "unavailable"


def test_the_client_refuses_a_peer_that_is_not_the_service(monkeypatch):
    """Owner and group pass, but the kernel peer uid is someone else's."""
    monkeypatch.setattr(client, "verify_socket", lambda *a, **k: None)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=41002))
    monkeypatch.setattr(client.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=42001))
    monkeypatch.setattr(client, "peer_credentials", lambda connection: (123, 41003, 42001))
    sent = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, timeout):
            pass

        def connect(self, path):
            pass

        def sendall(self, data):
            sent.append(data)

    monkeypatch.setattr(client.socket, "socket", lambda *a, **k: Connection())
    fast, timing = client.ContextObserveSocketClient().observe_context_timed(
        obs_frame(), deadline_s=0.3)
    assert timing is None and sent == []
    assert fast["dependency_outcome"]["knowledge"] == "rejected"


def test_entry_relays_to_the_new_unit_not_to_locald(monkeypatch, tmp_path):
    from azazel_nexus_runtime import mio_entryd as entry
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    service = entry.MioEntryService()
    assert isinstance(service.context_observer, client.ContextObserveSocketClient)
    assert not hasattr(client.LocalSocketClient, "observe_context_timed")
    assert not hasattr(client.LocalSocketClient, "observe_context")
    calls = []

    def exchange(leaf, account, verb, arguments, *, payload=None, deadline_s):
        calls.append((leaf, account, verb))
        return {"outcome": "context_observed", "fast_assistance": good_fast("unavailable"),
                "timing": {"context": "unavailable", "broker_ms": 1, "total_ms": 2,
                           "core": "ran"}}

    monkeypatch.setattr(client, "_exchange", exchange)
    service._explainer_uid = 4242
    from azazel_nexus_runtime.principal import Principal
    reply = service.handle(SimpleNamespace(
        verb=entry.CONTEXT_OBSERVE_VERB, arguments={"deadline_ms": 350}, payload=obs_frame(),
        principal=Principal(4242, 7, 1, frozenset({PrincipalClass.SERVICE}))))
    assert calls == [("mio-contextobs", "azmioctx", "mio.contextobs.observe")]
    # The reply keeps its shape; the hop's timing is still under `locald`.
    assert set(reply["timing"]) == {"locald", "entry_ms"}


# ---- the broker's outcome and the core's are told apart --------------------

class _BrokenCore:
    """Stands in for mio_fast_assistance and fails as the shared core can."""

    def _frame(self, source, *, with_selection=False):
        raise RuntimeError("core unavailable")

    def fast_assistance(self, *args, **kwargs):  # pragma: no cover - never reached
        raise AssertionError("not called")


def _observe(service, frame=None):
    return service.handle(SimpleNamespace(verb=obsd.CONTEXT_OBSERVE_VERB,
                                          arguments={"deadline_ms": 320},
                                          payload=frame or obs_frame()))


def test_a_core_failure_keeps_the_broker_answer_and_says_so(monkeypatch):
    from _technique_fixture import make_response
    from azazel_nexus.local_advisory import read_fast_assistance

    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance", _BrokenCore())
    monkeypatch.setattr(obsd, "request_context", lambda query, *, deadline_s: make_response(
        ["T1059", "T1059.001"]))
    reply = _observe(obsd.ContextObservationService())
    assert reply["outcome"] == "context_observed"
    assert reply["timing"]["core"] == "failed"
    assert reply["timing"]["context"] == "received"
    fast = reply["fast_assistance"]
    assert fast["state"] == "dependency_unavailable"            # the fixed degraded payload
    record = fast["technique_knowledge"]
    assert (record["transport"], record["verification"]) == ("received", "ok")
    assert fast["full_node_context_status"] == "unavailable"
    assert read_fast_assistance(fast) == fast                   # entry's reader accepts it


def test_a_core_failure_and_a_broker_refusal_are_both_visible(monkeypatch):
    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance", _BrokenCore())

    def refuse(query, *, deadline_s):
        exc = obsd.KnowledgeContextUnavailable("refused")
        exc.stage = "refused_before_send"
        raise exc

    monkeypatch.setattr(obsd, "request_context", refuse)
    reply = _observe(obsd.ContextObservationService())
    assert reply["timing"]["core"] == "failed" and reply["timing"]["context"] == "refused"
    record = reply["fast_assistance"]["technique_knowledge"]
    assert (record["transport"], record["verification"]) == ("refused", "not_run")


def test_a_core_that_ran_says_so(monkeypatch):
    from test_mio_context_observe import FakeCore

    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance", FakeCore())
    monkeypatch.setattr(obsd, "request_context", lambda *a, **k: (_ for _ in ()).throw(
        obsd.KnowledgeContextUnavailable("closed")))
    reply = _observe(obsd.ContextObservationService())
    assert reply["timing"]["core"] == "ran"
    assert reply["fast_assistance"]["state"] != "dependency_unavailable"


@pytest.mark.parametrize("timing", [
    {"context": "received", "broker_ms": 1, "total_ms": 2},                      # no core word
    {"context": "received", "broker_ms": 1, "total_ms": 2, "core": "maybe"},     # unknown word
    {"context": "received", "broker_ms": 1, "total_ms": 2, "core": "ran", "x": 1},
])
def test_the_client_refuses_a_timing_without_the_fixed_core_word(monkeypatch, timing):
    monkeypatch.setattr(client, "_exchange", lambda *a, **k: {
        "outcome": "context_observed", "fast_assistance": good_fast("unavailable"),
        "timing": timing})
    fast, got = client.ContextObserveSocketClient().observe_context_timed(
        obs_frame(), deadline_s=0.3)
    assert got is None and fast["dependency_outcome"]["knowledge"] == "rejected"


def test_entry_carries_the_core_word_to_the_explainer(monkeypatch, tmp_path):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime.principal import Principal
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    service = entry.MioEntryService()
    service._explainer_uid = 4242
    timing = {"context": "received", "broker_ms": 1, "total_ms": 2, "core": "failed"}
    monkeypatch.setattr(client, "_exchange", lambda *a, **k: {
        "outcome": "context_observed", "fast_assistance": good_fast("unavailable"),
        "timing": timing})
    reply = service.handle(SimpleNamespace(
        verb=entry.CONTEXT_OBSERVE_VERB, arguments={"deadline_ms": 350}, payload=obs_frame(),
        principal=Principal(4242, 7, 1, frozenset({PrincipalClass.SERVICE}))))
    assert reply["timing"]["locald"] == timing


@pytest.mark.parametrize("stage,pair", [
    ("withdrawn", ("received", "withdrawn")),
    ("refused_before_send", ("refused", "not_run")),
    ("transport", ("unavailable", "not_run")),
    ("verification", ("refused", "failed")),
])
def test_a_broker_stage_reaches_the_stored_record_as_its_own_pair(root, monkeypatch, stage, pair):
    """request_context's stage -> contextobsd's reply -> the strict stored-record reader (and the UI words)."""
    from azazel_nexus.technique_knowledge import read_projection
    _as_entry(monkeypatch, os.getuid())

    def request_context(query, *, deadline_s):
        refused = obsd.KnowledgeContextUnavailable("broker refused")
        refused.stage = stage
        raise refused

    monkeypatch.setattr(obsd, "request_context", request_context)
    with Daemon(obsd.main):
        reply = _ask()
    tk = reply["result"]["fast_assistance"]["technique_knowledge"]
    assert (tk["transport"], tk["verification"]) == pair
    assert read_projection(tk) == tk
    ui = (ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "ui_static" / "app.js").read_text()
    assert f"{pair[1]}: \"" in ui  # the UI has its own label for the verification word
