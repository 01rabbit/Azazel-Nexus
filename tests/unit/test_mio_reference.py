"""Handoff references come from a model-free service, never a provider answer.

The reference service (`mio_referenced`, `azazel-mio-referenced.service`)
serves verified playbook references on a node with no admitted model. These
tests hold three things: it can reach no model, admission or Knowledge code;
its reply is a labelled reference, never advice; and its absence or a missing
playbook leaves a fixed notice and a fixed reason, never a failed request.
"""

import ast
import copy
import inspect
import json
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_locald as local
from azazel_nexus_runtime import mio_referenced as referenced
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalClass, PrincipalPolicy
from azazel_nexus_runtime.protocol import RequestRefused

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.local_advisory import HANDOFF_NOTICE, read_delivered, read_reference
from azazel_nexus.reasoning_playbook import read_library
from azazel_nexus.routing import Route

LIBRARY = read_library((Path(__file__).parents[1] / "fixtures/reasoning-playbook.json").read_bytes())


@pytest.fixture
def frame():
    return {"request_id": "reference-test", "privacy_class": "P2-mission",
            "question": "SSH host-1 T1110.003",
            "context": [{"kind": "auth_log", "text": "Password spray against host-1"}]}


@pytest.fixture
def service():
    return referenced.ReferenceService(playbooks=LIBRARY, selection_reason="active")


def request(frame, deadline=500):
    return SimpleNamespace(verb=referenced.REFERENCE_VERB,
                           arguments={"deadline_ms": deadline}, payload=frame)


class FakeReference:
    """The entry's reference client, answering from a real ReferenceService."""

    def __init__(self, target=None, reason="reference_service_unavailable"):
        self.target, self.reason, self.calls = target, reason, []

    def reference(self, frame, *, deadline_at):
        self.calls.append(deadline_at)
        if self.target is None:
            return None, self.reason
        reply = self.target.handle(request(frame))
        if reply["outcome"] != "reference":
            return None, reply["reason"]
        return reply["reference"], None


def entry_service(tmp_path, monkeypatch, reference=None):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    target = entry.MioEntryService()
    monkeypatch.setattr(target.local, "observe", lambda: "fixture")
    monkeypatch.setattr(target.remote, "observe", lambda: "fixture")
    if reference is not None:
        target.reference = reference
    return target


def advise(target, frame, deadline=1000):
    return target.handle(SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": deadline}, payload=frame))


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
    assert client.ReferenceSocketClient().reference(frame, deadline_at=1e12) == (
        None, "reference_refused")


@pytest.mark.parametrize("failure", [FileNotFoundError(), TimeoutError(), ValueError()])
def test_absent_or_slow_reference_service_preserves_handoff(frame, tmp_path, monkeypatch, failure):
    target = entry_service(tmp_path, monkeypatch)

    def unavailable(*args, **kwargs):
        raise failure

    monkeypatch.setattr(client, "_exchange", unavailable)
    reply = advise(target, frame)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["outcome"] == "refused"
    assert reply["reference_status"] == "unavailable"
    assert reply["reference_reason"] == "reference_service_unavailable"
    assert reply["reason"] != "reference_unavailable"  # the routing reason is kept
    assert "reference" not in reply and "advice" not in reply
    assert reply["handoff"]["kind"] == "deterministic_notice"
    assert reply["handoff"]["notice"] == HANDOFF_NOTICE["en"]


def test_reference_does_not_change_route_outcome_or_authority(service, frame, tmp_path, monkeypatch):
    from azazel_nexus import model_admission

    def authority_snapshot():
        return canonical_event_bytes({
            "units": [repr(unit) for unit in CORE_UNITS],
            "local_enabled": model_admission.LOCAL_MODEL_ADMISSION_ENABLED,
        })

    before = authority_snapshot()
    results = []
    for available in (False, True):
        target = entry_service(tmp_path / str(available), monkeypatch,
                               FakeReference(service if available else None))
        target.router._clock = lambda: "2026-10-19T00:00:00Z"
        reply = advise(target, frame)
        assert ("reference" in reply) is available
        assert "advice" not in reply
        results.append(canonical_event_bytes({k: reply[k] for k in ("route", "outcome", "reason")}))
        assert authority_snapshot() == before
        assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    assert results[0] == results[1]


def test_entry_revalidates_reference(service, frame, tmp_path, monkeypatch):
    doc = service.handle(request(frame))["reference"]
    doc["provenance"]["source"] = "embedding"
    target = entry_service(tmp_path, monkeypatch,
                           SimpleNamespace(reference=lambda *a, **kw: (doc, None)))
    result = advise(target, frame)
    assert result["reference_status"] == "unavailable" and "reference" not in result
    assert result["reference_reason"] == "reference_refused"


@pytest.mark.parametrize("deadline", [0, 501])
def test_reference_deadline_bounds(service, frame, deadline):
    assert service.handle(request(frame, deadline)) == {
        "outcome": "unavailable", "reason": "invalid_deadline"}
    if deadline == 501:
        with pytest.raises(RequestRefused):
            referenced.REFERENCE_VERB.bind({"deadline_ms": deadline})


def test_reference_expiry_and_late_socket_reply(frame, monkeypatch):
    ticks = iter([0.0, 1.0])
    slow = referenced.ReferenceService(playbooks=LIBRARY, clock=lambda: next(ticks))
    assert slow.handle(request(frame)) == {"outcome": "unavailable", "reason": "deadline"}
    doc = referenced.ReferenceService(playbooks=LIBRARY).handle(request(frame))["reference"]
    now = [64.0]
    seen = []

    def exchange(*args, **kwargs):
        # The bounded share of the one deadline: what is left, capped at 500 ms.
        seen.append((args[3], kwargs["deadline_s"]))
        now[0] = 64.25  # the reply arrives exactly at the deadline
        return {"outcome": "reference", "reference": doc}

    monkeypatch.setattr(client, "_exchange", exchange)
    late = client.ReferenceSocketClient(clock=lambda: now[0])
    assert late.reference(frame, deadline_at=64.25) == (None, "deadline")
    assert seen == [({"deadline_ms": 250}, 0.25)]
    now[0] = 64.0
    document, missing = late.reference(frame, deadline_at=1e6)
    assert missing is None and document["provenance"]["model_id"] == "deterministic"
    assert seen[-1] == ({"deadline_ms": 500}, 0.5)  # capped at the service ceiling


def test_no_reference_request_starts_with_no_time_left(frame, monkeypatch):
    monkeypatch.setattr(client, "_exchange", lambda *a, **kw: pytest.fail("sent with no budget"))
    spent = client.ReferenceSocketClient(clock=lambda: 50.0)
    assert spent.reference(frame, deadline_at=50.0) == (None, "deadline")
    assert spent.reference(frame, deadline_at=49.0) == (None, "deadline")


def test_reference_principal_policy_is_entry_service_only():
    policy = PrincipalPolicy(100, frozenset({123}), frozenset({123, 456}))
    for uid, gid, allowed in [(123, 100, True), (456, 100, False),
                              (789, 100, False), (0, 0, False)]:
        principal = policy.classify(uid, gid, 1)
        if allowed:
            assert referenced.REGISTRY.resolve("mio.reference", principal) == referenced.REFERENCE_VERB
        else:
            with pytest.raises(RequestRefused):
                referenced.REGISTRY.resolve("mio.reference", principal)
    assert referenced.REFERENCE_VERB.admits == {PrincipalClass.SERVICE}
    assert referenced.REGISTRY.names() == ("mio.reference",)
    tree = ast.parse(Path(referenced.__file__).read_text())
    resolves = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == "resolve"
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "PrincipalPolicy"]
    assert len(resolves) == 1
    assert ast.literal_eval(resolves[0].keywords[0].value) == ("azmioentry",)


def test_the_model_host_no_longer_serves_references():
    assert "mio.reference" not in local.REGISTRY.names()
    assert "mio.local.reference" not in local.REGISTRY.names()


def test_reference_call_graph_has_no_inference_or_model_start():
    pending = [referenced.ReferenceService.handle]
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
    assert referenced.read_reference in seen and referenced.match in seen


#: What a model-free process must never load, directly or transitively.
MODEL_MODULES = (
    "azazel_nexus.model_runtime", "azazel_nexus.model_admission",
    "azazel_nexus_runtime.mio_locald", "azazel_nexus_runtime.mio_serve",
    "azazel_nexus_runtime.mio_embedding", "azazel_nexus_runtime.mio_supervisor",
    "azazel_nexus_runtime.model_admission_evidence", "azazel_nexus_runtime.knowledge_client",
    "azazel_nexus_runtime.mio_remoted", "azazel_nexus_runtime.inference_egress",
)


def test_the_reference_process_loads_no_model_admission_or_knowledge_code():
    import subprocess

    code = textwrap.dedent(f"""
        import sys
        import azazel_nexus_runtime.mio_referenced
        loaded = sorted(m for m in {MODEL_MODULES!r} if m in sys.modules)
        print(loaded)
    """)
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                            check=True, timeout=60)
    assert result.stdout.strip() == "[]", result.stdout


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


@pytest.mark.parametrize("condition,reason", [
    ("no_library", "no_pack"), ("store_unreadable", "store_unreadable"),
    ("out_of_scope", "out_of_scope"), ("insufficient", "insufficient_information"),
    ("no_match", "no_matching_playbook"), ("malformed", "malformed_frame"),
])
def test_unusable_reference_is_a_fixed_reason(service, frame, condition, reason):
    if condition == "no_library":
        service.set_playbooks(None, "no_pack")
    elif condition == "store_unreadable":
        service.set_playbooks(None, "store_unreadable")
    elif condition == "out_of_scope":
        frame.update(question="What is the weather?", context=[])
    elif condition == "insufficient":
        frame.update(question="Is this an attack?", context=[])
    elif condition == "no_match":
        frame.update(question="Firewall rule review on host-1",
                     context=[{"kind": "observation", "text": "rule count changed"}])
    else:
        frame["extra"] = "untrusted"
    reply = service.handle(request(frame))
    assert reply == {"outcome": "unavailable", "reason": reason}
    assert reason in referenced.REFERENCE_REASONS


def test_missing_playbook_shows_fixed_notice_and_reason(frame, tmp_path, monkeypatch):
    missing = referenced.ReferenceService(playbooks=None, selection_reason="no_pack")
    target = entry_service(tmp_path, monkeypatch, FakeReference(missing))
    reply = advise(target, frame)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["reference_status"] == "unavailable"
    assert reply["reference_reason"] == "no_pack"
    assert reply["handoff"] == {
        "kind": "deterministic_notice", "notice": HANDOFF_NOTICE["en"],
        "ai_attempts": 0, "failures": [],
    }
    assert "advice" not in reply and "reference" not in reply
    frame["question"] = "SSH host-1 T1110.003 のログを確認"
    assert advise(target, frame)["handoff"]["notice"] == HANDOFF_NOTICE["ja"]


def test_attached_reference_is_labelled_as_a_reference(service, frame, tmp_path, monkeypatch):
    target = entry_service(tmp_path, monkeypatch, FakeReference(service))
    reply = advise(target, frame)
    assert reply["reference_status"] == "attached"
    assert reply["handoff"]["kind"] == "deterministic_reference"
    assert "advice" not in reply and "fields" not in reply
    assert read_reference(reply["reference"])["provenance"]["model_id"] == "deterministic"
    from azazel_nexus.incident_explain import read_mio_reply

    explained = read_mio_reply(reply)
    assert explained["route"] == "deterministic handoff"
    assert explained["reason"] == "mio_handoff"
    assert explained["text"] == reply["reference"]["banner"]


def test_reference_budget_is_what_is_left_of_the_one_deadline(frame, tmp_path, monkeypatch):
    now = [10.0]
    seen = FakeReference()
    target = entry_service(tmp_path, monkeypatch, seen)
    target.router._monotonic = lambda: now[0]
    for deadline in (50, 5000):
        reply = advise(target, frame, deadline)
        assert reply["reference_status"] == "unavailable"
    # The entry passes its own request deadline, measured once at the start.
    assert seen.calls == [10.05, 15.0]


@pytest.mark.parametrize("failed", [
    {"outcome": "failed", "refusal": "local_unavailable"},
    {"outcome": "timed_out", "refusal": "deadline"},
    {"outcome": "not_advice", "refusal": "not_advice"},
])
def test_a_failed_ai_attempt_ends_in_the_handoff_with_reference(
    service, frame, tmp_path, monkeypatch, failed,
):
    from azazel_nexus.route_evidence import Prediction

    target = entry_service(tmp_path, monkeypatch, FakeReference(service))
    target._local_admitted = lambda: True
    target._predictions_reader = lambda: {Route.LOCAL: Prediction(
        "local", True, 100, 10, 10, False, "fixture observations")}
    calls = []
    monkeypatch.setattr(target.local, "handle",
                        lambda request, audit=None: calls.append(request) or dict(failed))
    monkeypatch.setattr(target.remote, "handle", lambda *a, **kw: pytest.fail("remote attempted"))
    reply = advise(target, frame, 2000)
    assert len(calls) == 1  # no retry to the provider that failed
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["reference_status"] == "attached"
    assert reply["handoff"]["ai_attempts"] == 1
    assert reply["handoff"]["failures"][0]["route"] == "local"
    assert reply["handoff"]["failures"][0]["refusal"] == failed["refusal"]
    assert "advice" not in reply
    from azazel_nexus.incident_explain import read_mio_reply

    assert read_mio_reply(reply)["reason"] == "mio_handoff"
