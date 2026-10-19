"""Handoff references cannot become provider answers or authority decisions."""

import ast
import copy
import inspect
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_locald as local
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalClass, PrincipalPolicy
from azazel_nexus_runtime.protocol import RequestRefused

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.local_advisory import read_delivered, read_reference
from azazel_nexus.reasoning_playbook import read_library
from azazel_nexus.routing import Route


@pytest.fixture
def frame():
    return {"request_id": "reference-test", "privacy_class": "P2-mission",
            "question": "SSH host-1 T1110.003",
            "context": [{"kind": "auth_log", "text": "Password spray against host-1"}]}


@pytest.fixture
def service():
    library = read_library((Path(__file__).parents[1]
                            / "fixtures/reasoning-playbook.json").read_bytes())

    def forbidden(*args, **kwargs):
        pytest.fail("reference reached a provider or admission gate")

    return local.LocalRuntimeService(
        playbooks=library, admitted=forbidden, runtime=forbidden,
        knowledge_lookup=forbidden, retriever=SimpleNamespace(retrieve=forbidden),
        server=SimpleNamespace(start=forbidden, infer=forbidden, embed=forbidden))


def request(frame, deadline=500):
    return SimpleNamespace(verb=local.REFERENCE_VERB,
                           arguments={"deadline_ms": deadline}, payload=frame)


@pytest.mark.parametrize("question", ["SSH host-1 T1110.003", "SSH host-1 T1110.003 のログを確認"])
def test_reference_is_keyword_only_with_fixed_banner(service, frame, question):
    frame["question"] = question
    reply = service.handle(request(frame))
    assert reply["outcome"] == "reference"
    doc = read_reference(reply["reference"])
    assert "advice" not in doc
    assert "model" not in doc["banner"].lower() and "モデル" not in doc["banner"]
    assert doc["provenance"]["source"] == "keyword"
    assert doc["provenance"]["model_id"] == "deterministic"
    assert doc["explanation_source"] == "trusted"
    assert doc["match_evidence"]
    assert "unreviewed" in doc["banner"] or "未レビュー" in doc["banner"]


@pytest.mark.parametrize("mutation", ["banner", "source", "explanation", "extra", "type"])
def test_strict_reference_boundary(service, frame, monkeypatch, mutation):
    doc = service.handle(request(frame))["reference"]
    if mutation == "banner":
        doc["banner"] = "Untrusted replacement banner"
    elif mutation == "source":
        doc["provenance"]["source"] = "model"
    elif mutation == "explanation":
        doc["explanation_source"] = "model"
    elif mutation == "extra":
        doc["advice"] = "answer"
    else:
        doc["provenance"]["state"] = []
    with pytest.raises(ValueError):
        read_reference(doc)
    monkeypatch.setattr(client, "_exchange", lambda *a, **kw: {
        "outcome": "reference", "reference": doc})
    assert client.LocalSocketClient().reference(frame, deadline_ms=500) is None


@pytest.mark.parametrize("failure", [FileNotFoundError(), TimeoutError(), ValueError()])
def test_absent_or_slow_locald_preserves_handoff(frame, tmp_path, monkeypatch, failure):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    service = entry.MioEntryService()
    monkeypatch.setattr(service.local, "observe", lambda: "fixture")
    monkeypatch.setattr(service.remote, "observe", lambda: "fixture")

    def unavailable(*args, **kwargs):
        raise failure

    monkeypatch.setattr(client, "_exchange", unavailable)
    reply = service.handle(SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": 1000}, payload=frame))
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["outcome"] == "refused"
    assert reply["reason"] == "reference_unavailable"
    assert "reference" not in reply and "advice" not in reply


def test_reference_does_not_change_route_outcome_ledger_or_authority(
    service, frame, tmp_path, monkeypatch,
):
    from azazel_nexus import model_admission

    def authority_snapshot():
        return canonical_event_bytes({
            "units": [repr(unit) for unit in CORE_UNITS],
            "local_enabled": model_admission.LOCAL_MODEL_ADMISSION_ENABLED,
        })

    before = authority_snapshot()
    results = []
    for available in (False, True):
        monkeypatch.setattr(runtime_paths, "ROOT", tmp_path / str(available))
        target = entry.MioEntryService()
        target.router._clock = lambda: "2026-10-19T00:00:00Z"
        monkeypatch.setattr(target.local, "observe", lambda: "fixture")
        monkeypatch.setattr(target.remote, "observe", lambda: "fixture")

        def exchange(*args, available=available, **kwargs):
            assert args[2] == "mio.local.reference"
            assert kwargs["deadline_s"] == .5
            assert args[3] == {"deadline_ms": 500}
            if not available:
                raise FileNotFoundError
            return service.handle(request(kwargs["payload"]))

        monkeypatch.setattr(client, "_exchange", exchange)
        reply = target.handle(SimpleNamespace(
            verb=entry.ADVISE_VERB, arguments={"deadline_ms": 1000}, payload=frame))
        assert ("reference" in reply) is available
        assert "advice" not in reply
        results.append((canonical_event_bytes({k: reply[k] for k in ("route", "outcome")}),
                        target.router.ledger.path.read_bytes()))
        assert authority_snapshot() == before
    # Includes complete hash-chain bytes, not merely a reconstructed selection.
    assert results[0] == results[1]


def test_entry_revalidates_reference(service, frame, tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    target = entry.MioEntryService()
    monkeypatch.setattr(target.local, "observe", lambda: "fixture")
    monkeypatch.setattr(target.remote, "observe", lambda: "fixture")
    doc = service.handle(request(frame))["reference"]
    doc["provenance"]["source"] = "embedding"
    monkeypatch.setattr(target.local, "reference", lambda *a, **kw: doc)
    result = target.handle(SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": 1000}, payload=frame))
    assert result["reason"] == "reference_unavailable" and "reference" not in result


@pytest.mark.parametrize("deadline", [0, 501])
def test_reference_deadline_bounds(service, frame, deadline):
    assert service.handle(request(frame, deadline))["refusal"] == "reference_unavailable"
    if deadline == 501:
        with pytest.raises(RequestRefused):
            local.REFERENCE_VERB.bind({"deadline_ms": deadline})


def test_reference_expiry_and_late_socket_reply(service, frame, monkeypatch):
    ticks = iter([0, 1])
    monkeypatch.setattr(local.time, "monotonic", lambda: next(ticks))
    assert service.handle(request(frame))["refusal"] == "reference_unavailable"
    monkeypatch.undo()
    doc = service.handle(request(frame))["reference"]
    ticks = iter([0, 1])
    monkeypatch.setattr(client.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(client, "_exchange", lambda *a, **kw: {
        "outcome": "reference", "reference": doc})
    assert client.LocalSocketClient().reference(frame, deadline_ms=500) is None


def test_reference_principal_policy_is_entry_service_only():
    policy = PrincipalPolicy(100, frozenset({123}), frozenset({123, 456}))
    for uid, gid, allowed in [(123, 100, True), (456, 100, False),
                              (789, 100, False), (0, 0, False)]:
        principal = policy.classify(uid, gid, 1)
        if allowed:
            assert local.REGISTRY.resolve("mio.local.reference", principal) == local.REFERENCE_VERB
        else:
            with pytest.raises(RequestRefused):
                local.REGISTRY.resolve("mio.local.reference", principal)
    assert local.REFERENCE_VERB.admits == {PrincipalClass.SERVICE}
    tree = ast.parse(Path(local.__file__).read_text())
    resolves = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == "resolve"
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "PrincipalPolicy"]
    assert len(resolves) == 1
    assert ast.literal_eval(resolves[0].keywords[0].value) == ("azmioentry",)


def test_reference_call_graph_has_no_inference_or_model_start():
    pending = [local.LocalRuntimeService._reference]
    seen = set()
    forbidden = {"infer", "embed", "start", "Popen", "retrieval_pipeline", "_server",
                 "_retriever", "_runtime", "_admitted", "_knowledge_lookup"}
    while pending:
        function = pending.pop()
        if function in seen:
            continue
        seen.add(function)
        tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                # Regex Match.start reports a text offset; it starts no process.
                regex_offset = (function.__name__ == "_fact_tokens" and node.attr == "start"
                                and isinstance(node.value, ast.Name)
                                and node.value.id in {"m", "match"})
                assert regex_offset or node.attr not in forbidden
            elif isinstance(node, ast.Name):
                assert node.id not in forbidden - {"start"}
                callee = function.__globals__.get(node.id)
                if (inspect.isfunction(callee)
                        and callee.__module__.startswith("azazel_nexus")):
                    pending.append(callee)
    assert local.read_reference in seen and local.match in seen


def test_advisory_banner_provenance_is_checked(service, frame):
    doc = service.handle(request(frame))["reference"]
    body = {"advice": doc.pop("banner"), **doc}
    assert read_delivered(body)["provenance"]["source"] == "keyword"
    for source in ("embedding", "model", "unknown"):
        forged = copy.deepcopy(body)
        forged["provenance"]["source"] = source
        with pytest.raises(ValueError):
            read_delivered(forged)
    assert "model" not in json.dumps(body["advice"]).lower()


@pytest.mark.parametrize("condition", ["no_library", "out_of_scope", "malformed"])
def test_unusable_reference_is_fixed_refusal(service, frame, condition):
    if condition == "no_library":
        service.set_playbooks(None)
    elif condition == "out_of_scope":
        frame.update(question="What is the weather?", context=[])
    else:
        frame["extra"] = "untrusted"
    assert service.handle(request(frame)) == {
        "outcome": "failed", "refusal": "reference_unavailable"}
