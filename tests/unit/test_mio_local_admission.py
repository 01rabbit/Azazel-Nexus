"""Entry reads locald's admission result before LOCAL may be selected (A3).

Mocked exchanges and an injected clock only; the Unix-socket round trips are
in `test_mio_local_admission_socket.py`. `LOCAL_MODEL_ADMISSION_ENABLED`
ships False and is only monkeypatched True inside a test, never in code.
"""

import os
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_locald as locald
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import RequestRefused

from azazel_nexus import model_admission
from azazel_nexus.route_evidence import Prediction
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

FRAME = {"request_id": "admission-test", "privacy_class": "P2-mission",
         "question": "SSH host-1 T1110.003",
         "context": [{"kind": "auth_log", "text": "Password spray against host-1"}]}
LOCAL_PREDICTION = {Route.LOCAL: Prediction("local", True, 20, 10, 10, False, "fixture")}


class Exchange:
    """Stands in for `_exchange`: the fixed probes, and a scripted admission."""

    def __init__(self, admission):
        self.admission = admission
        self.calls = []

    def __call__(self, leaf, account, verb, arguments, *, payload=None, deadline_s=0.5):
        self.calls.append((verb, deadline_s))
        if verb == "model.activate":
            return {"readiness": "refused", "reason": "not admitted"}
        if verb == client.ADMISSION_VERB_NAME:
            assert (leaf, account, arguments, payload) == ("mio", "azmio", {}, None)
            if isinstance(self.admission, BaseException):
                raise self.admission
            return self.admission
        raise ConnectionRefusedError()

    def admission_calls(self):
        return [deadline for verb, deadline in self.calls if verb == client.ADMISSION_VERB_NAME]


@pytest.fixture
def make_service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)

    def make(admission, **kwargs):
        exchange = Exchange(admission)
        monkeypatch.setattr(client, "_exchange", exchange)
        service = entry.MioEntryService(local_admitted=client.LocalAdmissionReader(),
                                        predictions_reader=lambda: dict(LOCAL_PREDICTION),
                                        **kwargs)
        attempts = []
        monkeypatch.setattr(service.local, "handle", lambda request, audit=None: attempts.append(
            request.arguments["deadline_ms"]) or {"outcome": "failed", "refusal": "local_refused"})
        monkeypatch.setattr(service.reference, "reference", lambda *a, **kw: (None, "no_pack"))
        return service, exchange, attempts

    return make


def advise(service, deadline_ms=2000):
    return service.handle(SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": deadline_ms}, payload=dict(FRAME)))


def selected(service):
    chain = RouteChain(service.router.ledger.directory)
    chain.verify()
    return [item.event for item in chain if item.event["event_type"] == "mio.route.selected"][-1]


def enable(monkeypatch):
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)


# -- shipped: the constant is False, so LOCAL is never permitted -------------


def test_the_constant_ships_false():
    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False


def test_disabled_reader_is_false_without_touching_the_socket(monkeypatch):
    monkeypatch.setattr(client, "_exchange", lambda *a, **kw: pytest.fail("socket read"))
    reader = client.LocalAdmissionReader()
    assert reader.enabled() is False
    assert reader() is False
    assert reader(deadline_s=0.5) is False


def test_disabled_entry_never_selects_local_even_if_locald_says_admitted(make_service):
    service, exchange, attempts = make_service({"admitted": True})
    reply = advise(service)
    assert exchange.admission_calls() == []
    assert attempts == []
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["handoff"]["ai_attempts"] == 0
    decision = selected(service)
    assert Route.LOCAL.value not in decision["permitted"]


def test_main_wires_the_locald_reader(make_service, monkeypatch):
    captured = {}
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: "policy")
    runtime_paths.socket_path("mio-advise").parent.mkdir(parents=True)
    assert entry.main([], ready=lambda: None) == 0
    service = captured["handler"].__self__
    assert isinstance(service._local_admitted, client.LocalAdmissionReader)
    # Shipped: the wired reader answers False, as the old default did.
    assert service._local_admitted() is False


# -- enabled (monkeypatched): only an exact True reply permits LOCAL ---------


def test_admitted_locald_lets_local_be_selected(make_service, monkeypatch):
    enable(monkeypatch)
    service, exchange, attempts = make_service({"admitted": True})
    reply = advise(service)
    assert len(exchange.admission_calls()) == 1
    assert selected(service)["route"] == Route.LOCAL.value
    # The attempt fails here (mock), so the one fallback is the handoff.
    assert len(attempts) == 1
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["handoff"]["ai_attempts"] == 1
    assert reply["handoff"]["failures"][0]["route"] == "local"


@pytest.mark.parametrize("admission", [
    {"admitted": False},
    FileNotFoundError(),            # locald stopped: no socket
    ConnectionRefusedError(),       # stale socket, nobody accepting
    TimeoutError(),                 # past the deadline it was given
    client.ServiceRefused("principal_denied"),
    ValueError("M.I.O. service refused"),  # malformed frame or reply
    RuntimeError("anything else"),
    {"admitted": "true"},
    {"admitted": 1},
    {"admitted": None},
    {"admitted": True, "model_id": "x"},
    {"readiness": "ready"},
    {},
], ids=repr)
def test_anything_but_admitted_true_is_the_deterministic_handoff(make_service, monkeypatch,
                                                                  admission):
    enable(monkeypatch)
    service, exchange, attempts = make_service(admission)
    reply = advise(service)
    assert len(exchange.admission_calls()) == 1
    assert attempts == []
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["handoff"]["ai_attempts"] == 0
    assert Route.LOCAL.value not in selected(service)["permitted"]


def test_a_route_request_never_reads_the_admission(make_service, monkeypatch):
    enable(monkeypatch)
    service, exchange, attempts = make_service({"admitted": True})
    service.handle(SimpleNamespace(arguments={
        "privacy_class": PrivacyClass.P0_PUBLIC.value, "deadline_ms": 2000}))
    assert exchange.admission_calls() == [] and attempts == []


def test_the_explainer_still_never_reaches_remote(make_service, monkeypatch):
    enable(monkeypatch)
    service, exchange, attempts = make_service({"admitted": True})
    service._explainer_uid = 4242
    monkeypatch.setattr(service.remote, "handle", lambda *a, **kw: pytest.fail("remote"))
    principal = Principal(4242, 7, 1, frozenset({PrincipalClass.SERVICE}))
    request = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 2000},
                              payload={**FRAME, "privacy_class": "P3-restricted"},
                              principal=principal)
    service.handle(request)
    assert selected(service)["route"] == Route.LOCAL.value
    with pytest.raises(RequestRefused):
        service.handle(SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 2000},
                                       payload=dict(FRAME), principal=principal))


# -- the read stays inside the request's deadline ----------------------------


def test_the_three_reads_share_the_probe_quarter(make_service, monkeypatch):
    enable(monkeypatch)
    now = [100.0]
    service, exchange, _ = make_service({"admitted": True}, clock=lambda: now[0])
    # Each read blocks for the whole bound it was given.
    original = client._exchange

    def blocking(*args, deadline_s=0.5, **kwargs):
        now[0] += deadline_s
        return original(*args, deadline_s=deadline_s, **kwargs)

    monkeypatch.setattr(client, "_exchange", blocking)
    deadline_ms = 500
    left_ms = (deadline_ms - entry.HANDOFF_RESERVE_MS - entry.MIN_AI_ATTEMPT_MS
               - entry.LEDGER_ALLOWANCE_MS)
    advise(service, deadline_ms)
    reads = [deadline for _, deadline in exchange.calls]
    assert len(reads) == 3  # local probe, remote probe (refused), admission
    assert sum(reads) <= left_ms / 4 / 1000 + 1e-9
    assert all(read <= left_ms / 4 / 3 / 1000 + 1e-9 for read in reads)
    # Probes and the admission read left the first attempt its minimum.
    assert selected(service)["route"] == Route.LOCAL.value


def test_no_room_for_the_read_means_not_admitted(make_service, monkeypatch):
    enable(monkeypatch)
    service, exchange, attempts = make_service({"admitted": True})
    # Under MIN_PROBE_S per read: nothing is read and LOCAL is not permitted.
    deadline_ms = (entry.HANDOFF_RESERVE_MS + entry.MIN_AI_ATTEMPT_MS + entry.LEDGER_ALLOWANCE_MS
                   + int(entry.MIN_PROBE_S * 1000 * 4 * 3) - 10)
    advise(service, deadline_ms)
    assert exchange.admission_calls() == []
    assert attempts == []
    assert Route.LOCAL.value not in selected(service)["permitted"]


@pytest.mark.parametrize("deadline_s", [0, -1, float("nan"), "0.5", None])
def test_reader_refuses_a_bad_deadline_without_reading(monkeypatch, deadline_s):
    enable(monkeypatch)
    monkeypatch.setattr(client, "_exchange", lambda *a, **kw: pytest.fail("socket read"))
    assert client.LocalAdmissionReader()(deadline_s=deadline_s) is False


def test_reader_never_asks_for_more_than_the_probe_bound(monkeypatch):
    enable(monkeypatch)
    exchange = Exchange({"admitted": True})
    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.LocalAdmissionReader()(deadline_s=30) is True
    assert exchange.calls == [(client.ADMISSION_VERB_NAME, client.PROBE_MAX_S)]


def test_an_injected_reader_that_raises_is_not_admitted(make_service, monkeypatch):
    service, _, attempts = make_service({"admitted": True})

    def broken():
        raise RuntimeError("reader failed")

    service._local_admitted = broken
    reply = advise(service)
    assert attempts == [] and reply["handoff"]["ai_attempts"] == 0


# -- locald's side of the verb ------------------------------------------------


def test_the_verb_is_read_only_and_service_only():
    verb = locald.ADMISSION_VERB
    assert verb.name == client.ADMISSION_VERB_NAME
    assert verb.arguments == () and not verb.accepts_payload
    assert verb.admits == frozenset({PrincipalClass.SERVICE})
    for kind in (PrincipalClass.OPERATOR, PrincipalClass.ROOT):
        with pytest.raises(RequestRefused):
            locald.REGISTRY.resolve(verb.name, Principal(1000, 1000, 1, frozenset({kind})))
    service = Principal(1000, 1000, 1, frozenset({PrincipalClass.SERVICE}))
    assert locald.REGISTRY.resolve(verb.name, service) is verb


def _locald(admitted=True, provider=True):
    return locald.LocalRuntimeService(
        model_id="fixture-model", admitted=lambda model_id: admitted and model_id == "fixture-model",
        retriever=object() if provider else None)


def _ask(service):
    return service.handle(SimpleNamespace(verb=locald.ADMISSION_VERB, arguments={}))


def test_locald_reports_false_while_the_constant_is_off():
    assert _ask(_locald()) == {"admitted": False}


@pytest.mark.parametrize(("admitted", "provider", "expected"), [
    (True, True, True), (False, True, False), (True, False, False), (False, False, False),
])
def test_locald_reports_its_own_admission_result(monkeypatch, admitted, provider, expected):
    enable(monkeypatch)
    assert _ask(_locald(admitted, provider)) == {"admitted": expected}


def test_a_withdrawal_reads_false_from_the_next_request(monkeypatch):
    enable(monkeypatch)
    service = _locald()
    assert _ask(service) == {"admitted": True}
    # What locald's `withdraw` does on expiry or changed evidence.
    service._retriever = None
    service._server = None
    service._admitted = lambda model_id: False
    assert _ask(service) == {"admitted": False}


def test_the_uncommissioned_model_is_never_reported_admitted(monkeypatch):
    enable(monkeypatch)
    service = locald.LocalRuntimeService(retriever=object())
    assert _ask(service) == {"admitted": False}


# -- only model output is delivered as AI advice -----------------------------


def _delivered(source):
    from azazel_nexus.local_advisory import build_options, delivered_document

    options = build_options(FRAME)
    return delivered_document(FRAME, (), options,
                              {"option_id": "other_suspicious", "kind": "other_suspicious"},
                              list(options), None, "deterministic" if source == "keyword" else "m1",
                              retrieval="keyword" if source == "keyword" else "embedding",
                              provenance=source)


def _infer_request():
    return SimpleNamespace(verb=locald.INFER_VERB, arguments={"deadline_ms": 1000},
                           payload=dict(FRAME))


def test_a_keyword_advisory_from_locald_is_not_advice(monkeypatch):
    monkeypatch.setattr(client, "_exchange",
                        lambda *a, **kw: {**_delivered("keyword"), "outcome": "advisory"})
    events = []
    reply = client.LocalSocketClient().handle(_infer_request(), audit=events.append)
    assert reply == {"outcome": "not_advice", "refusal": "not_model_output"}
    assert events == []


def test_an_embedding_advisory_is_still_delivered(monkeypatch):
    monkeypatch.setattr(client, "_exchange",
                        lambda *a, **kw: {**_delivered("embedding"), "outcome": "advisory"})
    reply = client.LocalSocketClient().handle(_infer_request(), audit=lambda e: None)
    assert reply["outcome"] == "advisory"
    assert reply["provenance"]["source"] == "embedding"


def test_the_model_sources_are_the_delivery_vocabulary_less_keyword():
    from azazel_nexus.local_advisory import _DELIVERY_BANNERS

    assert client.MODEL_SOURCES == set(_DELIVERY_BANNERS) - {"keyword"}
