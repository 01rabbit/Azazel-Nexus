"""Real Unix sockets: entry reads locald's admission over SO_PEERCRED (A3).

Process-level, not systemd: daemons run in threads of this test process, on
real AF_UNIX sockets with kernel peer credentials. `LOCAL_MODEL_ADMISSION_ENABLED`
is monkeypatched True only where a test says so; no model is installed, no
admission evidence exists, and no inference runs. The "admitted" locald below
is a `LocalRuntimeService` handed a fixture admission result, served through
locald's real registry; it still refuses inference (no measured reserve).
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_locald as locald
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.serve import serve_forever
from azazel_nexus_runtime.transport import bind_socket, read_frame, send_frame

from azazel_nexus import model_admission
from azazel_nexus.route_evidence import Prediction
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.routing import Route

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_PEERCRED required")

FRAME = {"request_id": "admission-socket", "privacy_class": "P2-mission",
         "question": "SSH host-1 T1110.003",
         "context": [{"kind": "auth_log", "text": "Password spray against host-1"}]}


@pytest.fixture
def root(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="azadm-", dir="/tmp") as directory:
        base = Path(directory)
        monkeypatch.setenv("AZAZEL_ROOT", directory)
        monkeypatch.setattr(runtime_paths, "ROOT", base)
        for leaf in ("mio-entry", "mio-advise", "mio", "remote"):
            runtime_paths.socket_path(leaf).parent.mkdir(parents=True)
        runtime_paths.mio_state_dir().mkdir(parents=True)
        runtime_paths.mio_local_state_dir().mkdir(parents=True, exist_ok=True)
        real_getpwnam = client.pwd.getpwnam

        def getpwnam(name):
            if name in {"azmio", "azremote", "azmioentry", "azmioref"}:
                return SimpleNamespace(pw_uid=os.getuid())
            if name in {"azexplain", "azarbiter"}:
                raise KeyError(name)
            return real_getpwnam(name)

        monkeypatch.setattr(client.pwd, "getpwnam", getpwnam)
        monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
        # The test's uid stands in for azmioentry, the one SERVICE locald admits.
        policy = PrincipalPolicy(os.getgid(), frozenset({os.getuid()}))
        monkeypatch.setattr(PrincipalPolicy, "resolve", lambda **kw: policy)
        yield base


class Thread:
    def __init__(self, target):
        self.ready, self.stop, self.errors = threading.Event(), threading.Event(), []
        self.thread = threading.Thread(target=self._run, args=(target,))

    def _run(self, target):
        try:
            target(ready=self.ready.set, stop=self.stop.is_set)
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
        if self.errors:
            raise self.errors[0]


def fixture_locald(admitted):
    """Locald's registry and handler, with a fixture admission result."""
    service = locald.LocalRuntimeService(
        model_id="fixture-model", retriever=object(),
        admitted=lambda model_id: admitted and model_id == "fixture-model")

    def run(*, ready, stop):
        serve_forever(path=runtime_paths.socket_path("mio"), registry=locald.REGISTRY,
                      policy=PrincipalPolicy.resolve(service_accounts=("azmioentry",)),
                      audit=lambda event: None, handler=service.handle,
                      stop=stop, ready=ready)

    return run


def entry_service():
    service = entry.MioEntryService(
        local_admitted=client.LocalAdmissionReader(),
        predictions_reader=lambda: {
            Route.LOCAL: Prediction("local", True, 20, 10, 10, False, "fixture")})
    service.reference.reference = lambda *a, **kw: (None, "no_pack")
    return service


def advise(service, deadline_ms=2000):
    return service.handle(SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": deadline_ms}, payload=dict(FRAME)))


def selected(service):
    chain = RouteChain(service.router.ledger.directory)
    chain.verify()
    return [item.event for item in chain if item.event["event_type"] == "mio.route.selected"][-1]


def spy_exchanges(monkeypatch):
    seen = []
    real = client._exchange

    def spy(leaf, account, verb, arguments, **kwargs):
        try:
            result = real(leaf, account, verb, arguments, **kwargs)
        except Exception as error:
            seen.append((verb, type(error).__name__))
            raise
        seen.append((verb, result))
        return result

    monkeypatch.setattr(client, "_exchange", spy)
    return seen


def test_admitted_locald_over_the_socket_selects_local_then_its_refusal_hands_off(
        root, monkeypatch):
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    seen = spy_exchanges(monkeypatch)
    with Thread(fixture_locald(True)):
        service = entry_service()
        reply = advise(service)
    assert (client.ADMISSION_VERB_NAME, {"admitted": True}) in seen
    assert selected(service)["route"] == Route.LOCAL.value
    # The same locald then refuses the inference itself (no measured
    # reserve): one attempt, no retry, and the deterministic handoff.
    assert any(verb == "mio.local.infer" for verb, _ in seen)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["handoff"]["ai_attempts"] == 1
    assert reply["handoff"]["failures"][0]["route"] == "local"
    assert "advice" not in reply


def test_not_admitted_locald_over_the_socket_is_the_handoff(root, monkeypatch):
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    seen = spy_exchanges(monkeypatch)
    with Thread(fixture_locald(False)):
        service = entry_service()
        reply = advise(service)
    assert (client.ADMISSION_VERB_NAME, {"admitted": False}) in seen
    assert not any(verb == "mio.local.infer" for verb, _ in seen)
    assert Route.LOCAL.value not in selected(service)["permitted"]
    assert reply["handoff"]["ai_attempts"] == 0


def test_shipped_constant_never_reads_even_an_admitted_locald(root, monkeypatch):
    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    seen = spy_exchanges(monkeypatch)
    with Thread(fixture_locald(True)):
        service = entry_service()
        reply = advise(service)
    assert not any(verb in {client.ADMISSION_VERB_NAME, "mio.local.infer"} for verb, _ in seen)
    assert reply["handoff"]["ai_attempts"] == 0


def test_locald_stopped_is_not_admitted(root, monkeypatch):
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    seen = spy_exchanges(monkeypatch)
    service = entry_service()
    reply = advise(service)
    assert not runtime_paths.socket_path("mio").exists()
    # No socket to verify: the exchange raises, and that reads not admitted.
    admission = [result for verb, result in seen if verb == client.ADMISSION_VERB_NAME]
    assert admission == ["SocketMisconfigured"]
    assert Route.LOCAL.value not in selected(service)["permitted"]
    assert reply["handoff"]["ai_attempts"] == 0


def test_locald_refuses_a_caller_that_is_not_its_service(root, monkeypatch):
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    monkeypatch.setattr(PrincipalPolicy, "resolve",
                        lambda **kw: PrincipalPolicy(os.getgid(), frozenset()))
    seen = spy_exchanges(monkeypatch)
    with Thread(fixture_locald(True)):
        assert client.LocalAdmissionReader()() is False
    assert seen == [(client.ADMISSION_VERB_NAME, "ServiceRefused")]


@pytest.mark.parametrize("behaviour", ["malformed", "extra_key", "silent"])
def test_broken_or_silent_locald_is_not_admitted_within_the_bound(root, monkeypatch, behaviour):
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    listener = bind_socket(runtime_paths.socket_path("mio"), expected_gid=os.getgid())
    listener.settimeout(5)
    release = threading.Event()
    requests, errors = [], []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                requests.append(json.loads(read_frame(connection)))
                if behaviour == "malformed":
                    connection.sendall(b"\x00\x00\x00\x05nope!")
                elif behaviour == "extra_key":
                    send_frame(connection, {"ok": True, "result": {
                        "admitted": True, "model_id": "fixture-model"}})
                else:
                    release.wait(5)
        except (OSError, ValueError) as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        began = time.monotonic()
        assert client.LocalAdmissionReader()(deadline_s=0.2) is False
        elapsed = time.monotonic() - began
    finally:
        release.set()
        thread.join(10)
        listener.close()
    assert not thread.is_alive() and not errors
    assert requests == [{"verb": client.ADMISSION_VERB_NAME, "arguments": {}}]
    # A silent peer costs at most the bound it was given (plus scheduling).
    assert elapsed < 1.0


# -- the real locald: expiry withdraws, and the same socket then reads False --


def test_real_locald_expiry_withdraws_and_the_next_read_is_false(root, monkeypatch):
    """`mio_locald.main()` with its own `AdmissionHolder` (clock injected),
    refresh and `withdraw`. Only the evidence store and the serving process
    are replaced: the evidence by the unit tests' admitted candidate, the
    llama server by the providers `prepare_local_models` would hand over.
    """
    from functools import partial

    from azazel_nexus_runtime import model_admission_evidence as loader
    from azazel_nexus_runtime import virtualization_observation
    from test_model_admission_evidence import END, NOW, admitted_candidate

    from azazel_nexus.model_runtime import LLAMA_RUNTIME_ID
    from azazel_nexus.virtualization import SENSORS

    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    now = [NOW]
    candidate = admitted_candidate()
    monkeypatch.setattr(loader, "read_admissions", lambda **kw: loader.AdmissionReading(candidate))
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (1,))
    monkeypatch.setattr(virtualization_observation, "observe_virtualization",
                        lambda: dict.fromkeys(SENSORS, "clear"))
    monkeypatch.setattr(loader, "AdmissionHolder", partial(loader.AdmissionHolder,
                                                           clock=lambda: now[0]))
    prepared = []

    def prepare(candidates, *, staging, audit):
        assert [type(c) for c in candidates] == [loader.Admitted]
        prepared.append(candidates[0].entry.model_id)
        selected_id = candidates[0].entry.model_id
        return {"retriever": object(), "staging": staging, "model_id": selected_id,
                "runtime_id": LLAMA_RUNTIME_ID, "reserve": candidates[0].resources.reserve,
                "admitted": lambda model_id: model_id == selected_id}, []

    monkeypatch.setattr(locald, "prepare_local_models", prepare)
    runtime_paths.mio_local_state_dir().mkdir(parents=True, exist_ok=True)
    seen = spy_exchanges(monkeypatch)
    reader = client.LocalAdmissionReader()
    with Thread(lambda **kw: locald.main([], **kw)):
        assert prepared == ["local-model"]
        assert reader() is True
        now[0] = END  # the approval's expiry, on locald's own clock
        assert reader() is False
        # Withdrawn stays withdrawn: a new approval needs a new start.
        now[0] = NOW
        assert reader() is False
    assert [result for verb, result in seen if verb == client.ADMISSION_VERB_NAME] == [
        {"admitted": True}, {"admitted": False}, {"admitted": False}]
    ledger = (runtime_paths.mio_local_state_dir() / "local.jsonl").read_text()
    assert "EXPIRED" in ledger


# -- withdrawn after the read: model-free output is never AI advice ----------


def test_model_free_reply_after_a_withdrawal_is_not_labelled_ai_advice(root, monkeypatch):
    """Locald answered admitted, then withdrew before the inference: its
    `_infer` serves the model-free keyword retrieval as `advisory`. Entry
    ends that attempt as not advice, so the explainer records the
    deterministic handoff, never "AI advice (local model)"."""
    from azazel_nexus.incident_explain import CONTENT_LABELS, read_mio_reply
    from azazel_nexus.reasoning_playbook import read_library

    library = read_library((Path(__file__).parents[1] / "fixtures/reasoning-playbook.json")
                           .read_bytes())
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    withdrawn = locald.LocalRuntimeService(playbooks=library)  # admitted: False
    replies = []

    def handler(request):
        if request.verb.name == locald.ADMISSION_VERB.name:
            return {"admitted": True}  # the read, just before the withdrawal
        reply = withdrawn.handle(request)
        if request.verb.name == locald.INFER_VERB.name:
            replies.append(reply)
        return reply

    def run(*, ready, stop):
        serve_forever(path=runtime_paths.socket_path("mio"), registry=locald.REGISTRY,
                      policy=PrincipalPolicy.resolve(service_accounts=("azmioentry",)),
                      audit=lambda event: None, handler=handler, stop=stop, ready=ready)

    with Thread(run):
        service = entry_service()
        reply = advise(service)
    # The precondition: locald really did deliver a model-free advisory.
    assert [(r["outcome"], r["provenance"]["source"], r["provenance"]["model_id"])
            for r in replies] == [("advisory", "keyword", "deterministic")]
    assert selected(service)["route"] == Route.LOCAL.value
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert "advice" not in reply
    assert reply["handoff"]["failures"] == [
        {"route": "local", "terminal_event": reply["handoff"]["failures"][0]["terminal_event"],
         "refusal": "not_model_output"}]
    read = read_mio_reply(reply)
    assert read["content_kind"] == "deterministic_notice"
    assert CONTENT_LABELS[read["content_kind"]] != CONTENT_LABELS["ai_advice"]
