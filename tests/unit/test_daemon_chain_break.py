"""A chain found broken while serving ends nothing (#458).

Each daemon: the request that meets the break is refused with a fixed reason,
every later request is refused, the process keeps serving, and the ledger is
not touched again (a refusal is counted as unrecorded instead).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from azazel_nexus.audit import AuditChainBroken
from azazel_nexus_runtime import (
    knowledge_contextd, mio_contextobsd, mio_locald, mio_referenced, runtime_paths,
)
from azazel_nexus_runtime.protocol import Refusal, RequestRefused


class FakeLedger:
    broken = False
    break_on: set = set()
    unavailable_on: set = set()
    calls: list = []

    def __init__(self, path):
        self.path = SimpleNamespace(open=lambda *a, **k: open("/dev/null", *a, **k))

    def verify(self, **_kwargs):
        pass

    def __iter__(self):
        return iter(())

    def append(self, event):
        FakeLedger.calls.append(event["event_type"])
        if FakeLedger.broken or event["event_type"] in FakeLedger.break_on:
            raise AuditChainBroken("fixture broken tail")
        if event["event_type"] in FakeLedger.unavailable_on:
            from azazel_nexus.audit import AuditUnavailable
            raise AuditUnavailable("fixture write failure")


def _serve(module, monkeypatch, tmp_path, **patches):
    FakeLedger.broken, FakeLedger.calls, FakeLedger.break_on = False, [], set()
    FakeLedger.unavailable_on = set()
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    for name in ("mio_local_state_dir", "mio_reference_state_dir",
                 "mio_contextobs_state_dir", "knowledge_context_state_dir"):
        getattr(runtime_paths, name)().mkdir(parents=True, exist_ok=True)
    # The installer creates the socket directories; the broker only locks inside one.
    runtime_paths.socket_path("knowledge-context").parent.mkdir(parents=True, exist_ok=True)
    captured = {}
    monkeypatch.setattr(module, "AuditLedger", FakeLedger)
    monkeypatch.setattr(module, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(module.PrincipalPolicy, "resolve", lambda **kw: "policy")
    for name, value in patches.items():
        monkeypatch.setattr(module, name, value)
    assert module.main([]) == 0
    return captured


def _refused(handler):
    with pytest.raises(RequestRefused) as refused:
        handler(object())
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE


def _transport_refusal_does_not_end_or_touch(served):
    before = len(FakeLedger.calls)
    served["audit"]({"event_type": "runtime.request_refused", "reason": "x"})
    served["audit"]({"event_type": "runtime.request_refused", "reason": "x"})
    assert len(FakeLedger.calls) == before, "the ledger was touched after the break"


def _selection():
    class Holder:
        selection = SimpleNamespace(reason="r")

        def __init__(self, **kw):
            pass

        def refresh(self, *, audit):
            return None

    return Holder


def test_locald_breaks_to_a_fixed_refusal_and_stops_touching_the_ledger(monkeypatch, tmp_path):
    class Service:
        def __init__(self, **kw):
            pass

        def set_playbooks(self, library):
            pass

        def handle(self, request, *, audit):
            audit({"event_type": "mio.local.request"})
            return {"outcome": "advisory"}

    served = _serve(mio_locald, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    LocalRuntimeService=Service)
    assert served["handler"](object()) == {"outcome": "advisory"}
    FakeLedger.broken = True
    _refused(served["handler"])
    FakeLedger.broken = False
    attempted = len(FakeLedger.calls)
    _refused(served["handler"])
    assert len(FakeLedger.calls) == attempted
    _transport_refusal_does_not_end_or_touch(served)


def test_locald_refuses_a_request_whose_break_was_swallowed_inside(monkeypatch, tmp_path):
    class Service:
        def __init__(self, **kw):
            pass

        def set_playbooks(self, library):
            pass

        def handle(self, request, *, audit):
            try:
                audit({"event_type": "mio.local.request"})
            except Exception:  # noqa: BLE001 - an optional path swallowing the failure
                pass
            return {"outcome": "advisory"}

    served = _serve(mio_locald, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    LocalRuntimeService=Service)
    FakeLedger.broken = True
    _refused(served["handler"])


def test_referenced_breaks_to_a_fixed_refusal_and_stops_touching_the_ledger(monkeypatch, tmp_path):
    class Service:
        def set_playbooks(self, library, reason):
            pass

        def handle(self, request):
            return {"outcome": "advisory", "reason": None}

    served = _serve(mio_referenced, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    ReferenceService=Service)
    assert served["handler"](object())["outcome"] == "advisory"
    FakeLedger.broken = True
    _refused(served["handler"])
    FakeLedger.broken = False
    attempted = len(FakeLedger.calls)
    _refused(served["handler"])
    assert len(FakeLedger.calls) == attempted
    _transport_refusal_does_not_end_or_touch(served)


def test_contextobsd_refusal_records_stop_at_the_break_and_serving_goes_on(monkeypatch, tmp_path):
    from _technique_fixture import make_response
    from test_mio_contextobsd import _observe, obs_frame

    served = _serve(mio_contextobsd, monkeypatch, tmp_path)
    FakeLedger.broken = True
    served["audit"]({"event_type": "runtime.request_refused", "reason": "x"})
    FakeLedger.broken = False
    _transport_refusal_does_not_end_or_touch(served)
    # A valid observation after the daemon's own ledger broke is still relayed.
    monkeypatch.setattr(mio_contextobsd, "request_context",
                        lambda query, *, deadline_s: make_response(["T1059", "T1059.001"]))
    reply = served["handler"](SimpleNamespace(
        verb=mio_contextobsd.CONTEXT_OBSERVE_VERB, arguments={"deadline_ms": 320},
        payload=obs_frame()))
    assert reply["outcome"] == "context_observed"
    assert served["audit"].__self__.refusals_unrecorded >= 1


def test_locald_periodic_work_survives_a_break_and_still_revokes(monkeypatch, tmp_path):
    from azazel_nexus_runtime import model_admission_evidence as evidence

    withdrawn = []

    class Holder:
        reading = SimpleNamespace(embedding=None)

        def start(self, *, audit):
            return self.reading

        def refresh(self, *, withdraw, audit):
            withdraw()
            withdrawn.append(1)
            audit({"event_type": "mio.local.admission"})

        def close(self):
            pass

    class Service:
        def __init__(self, **kw):
            self._retriever = object()

        def set_playbooks(self, library):
            pass

    monkeypatch.setattr(evidence, "AdmissionHolder", Holder)
    monkeypatch.setattr(evidence, "POLL_INTERVAL_SECONDS", 0)
    served = _serve(mio_locald, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    LocalRuntimeService=Service)
    FakeLedger.broken = True
    attempted = len(FakeLedger.calls)
    assert served["stop"]() is False  # no exit
    assert served["stop"]() is False
    assert len(withdrawn) == 2, "the revocation must still run"
    assert len(FakeLedger.calls) <= attempted + 1  # only the first detection touched it
    FakeLedger.broken = False
    settled = len(FakeLedger.calls)
    served["stop"]()
    assert len(FakeLedger.calls) == settled


def _broker(monkeypatch, tmp_path, answer=None):
    from stop_helpers import granted_marker
    from test_knowledge_contextd import OPEN_GATE, _policy, _request

    sent = []

    class Client:
        def request_context(self, **kw):
            sent.append({"recorded_at_call": "knowledge.context.requested" in FakeLedger.calls})
            if answer is None:
                raise OSError("not needed")
            return answer

    commissioning = SimpleNamespace(status="commissioned", reason_code=None, registry_version=None,
                                    client=Client(), policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32)
    real = knowledge_contextd.KnowledgeContextBroker

    def broker(**kw):
        return real(**{**kw, **OPEN_GATE, "grant_marker": granted_marker})

    served = _serve(knowledge_contextd, monkeypatch, tmp_path, KnowledgeContextBroker=broker,
                    load_commissioning=lambda: commissioning, load_observation_rule=lambda: None)
    return served, sent, _request


def test_knowledge_contextd_sends_nothing_once_the_chain_is_broken(monkeypatch, tmp_path):
    served, sent, request = _broker(monkeypatch, tmp_path)
    counter = served["audit"].__self__
    FakeLedger.broken = True
    # The pre-send record finds the break: refused, and nothing was sent.
    assert served["handler"](request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert sent == [] and counter.refusals_unrecorded == 1
    FakeLedger.broken = False
    attempted = len(FakeLedger.calls)
    assert served["handler"](request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert len(FakeLedger.calls) == attempted and sent == []
    assert counter.refusals_unrecorded == 2
    _transport_refusal_does_not_end_or_touch(served)


def test_knowledge_contextd_writes_no_requested_and_sends_nothing_once_the_chain_is_broken(
        monkeypatch, tmp_path):
    # Once the break is known the request still reaches the broker, so that the
    # observation gate (its latch) is judged (#472); what must hold is the
    # intent of #458: no `requested` line, no peer call, the ledger not touched.
    served, sent, request = _broker(monkeypatch, tmp_path)
    FakeLedger.broken = True
    served["handler"](request())
    FakeLedger.broken = False
    attempted = list(FakeLedger.calls)
    assert served["handler"](request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert FakeLedger.calls == attempted and sent == []


def test_knowledge_contextd_reports_the_stage_reached_when_the_completion_record_breaks(
        monkeypatch, tmp_path):
    served, sent, request = _broker(monkeypatch, tmp_path, answer={"authority": "advisory_only"})
    counter = served["audit"].__self__
    FakeLedger.break_on = {"knowledge.context.completed"}
    reply = served["handler"](request())
    assert len(sent) == 1
    assert reply == {"refusal": "unavailable", "stage": "unrecorded"}  # verified, could not be recorded
    assert counter.refusals_unrecorded == 1
    FakeLedger.break_on = set()
    # Known broken now: refused at the entrance, nothing more is sent.
    assert served["handler"](request())["stage"] == "refused_before_send"
    assert len(sent) == 1 and counter.refusals_unrecorded == 2


def test_knowledge_contextd_records_before_it_sends_on_a_sound_chain(monkeypatch, tmp_path):
    served, sent, request = _broker(monkeypatch, tmp_path)
    served["handler"](request())
    assert len(sent) == 1
    assert sent[0]["recorded_at_call"] is True


def test_knowledge_contextd_keeps_the_clients_stage_when_the_break_is_found_recording_its_failure(
        monkeypatch, tmp_path):
    from azazel_nexus_runtime.knowledge_context_socket import KnowledgeContextUnavailable

    served, sent, request = _broker(monkeypatch, tmp_path)
    counter = served["audit"].__self__
    FakeLedger.break_on = {"knowledge.context.completed"}
    reply = served["handler"](request())
    assert len(sent) == 1
    assert reply == {"refusal": "unavailable", "stage": "transport"}  # the client's own, not rewritten
    assert counter.refusals_unrecorded == 1 and counter.broken


def test_a_verified_answer_that_could_not_be_recorded_is_unrecorded_and_never_adopted():
    from azazel_nexus import technique_past_reference as past
    from azazel_nexus_runtime import knowledge_context_socket as kcs
    from azazel_nexus_runtime import mio_contextobsd as obs
    from pathlib import Path

    assert "unrecorded" in kcs.STAGES and "unrecorded" in knowledge_contextd._STAGES
    projection = obs._refusal_projection("unrecorded")
    assert (projection["transport"], projection["verification"]) == ("received", "unrecorded")
    assert past._verified(projection) is None, "only received/ok is ever adopted"
    js = (Path(obs.__file__).parent / "ui_static" / "app.js").read_text(encoding="utf-8")
    assert "unrecorded: \"記録できなかったため、結果を採用していません\"" in js


def test_locald_stops_the_request_when_the_break_is_found_by_its_admission_refresh(
        monkeypatch, tmp_path):
    from azazel_nexus_runtime import model_admission_evidence as evidence

    touched = []

    class Holder:
        reading = SimpleNamespace(embedding=None)

        def start(self, *, audit):
            return self.reading

        def refresh(self, *, withdraw, audit):
            withdraw()
            touched.append("revoked")
            audit({"event_type": "mio.local.admission"})

        def close(self):
            pass

    class Service:
        def __init__(self, **kw):
            pass

        def set_playbooks(self, library):
            touched.append("playbooks")

        def handle(self, request, *, audit):
            touched.append("lookup")
            return {"outcome": "advisory"}

    monkeypatch.setattr(evidence, "AdmissionHolder", Holder)
    served = _serve(mio_locald, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    LocalRuntimeService=Service)
    FakeLedger.break_on = {"mio.local.admission"}
    _refused(served["handler"])
    assert touched == ["revoked"], touched


def test_knowledge_contextd_treats_a_resend_after_settling_as_a_new_request(monkeypatch, tmp_path):
    """5.0 (d): sent once and not recorded; settled; the same request again is sent and recorded once."""
    served, sent, request = _broker(monkeypatch, tmp_path, answer={"authority": "advisory_only"})
    FakeLedger.unavailable_on = {"knowledge.context.completed"}
    first = served["handler"](request())
    assert len(sent) == 1 and first == {"refusal": "unavailable", "stage": "unrecorded"}
    # While it is still owed, nothing is sent.
    FakeLedger.unavailable_on = {"knowledge.context.completed", "audit.late_record"}
    assert served["handler"](request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert len(sent) == 1
    FakeLedger.unavailable_on = set()
    reply = served["handler"](request())          # settled first, then a new request
    assert "response" in reply and len(sent) == 2
    requested = [c for c in FakeLedger.calls if c == "knowledge.context.requested"]
    assert len(requested) == 2                    # one record per request that was sent


def test_locald_does_not_start_new_work_when_the_revocation_record_made_a_debt(monkeypatch, tmp_path):
    """#467: the revocation done, its record unwritten: nothing new starts for the request."""
    from azazel_nexus_runtime import model_admission_evidence as evidence

    started = []

    class Holder:
        reading = SimpleNamespace(embedding=None)

        def start(self, *, audit):
            return self.reading

        def refresh(self, *, withdraw, audit):
            withdraw()
            audit({"event_type": "mio.local.admission"})

        def close(self):
            pass

    class Service:
        def __init__(self, **kw):
            self._retriever = object()

        def set_playbooks(self, library):
            pass

        def handle(self, request, *, audit):
            started.append(request)
            return {"outcome": "assessed"}

    monkeypatch.setattr(evidence, "AdmissionHolder", Holder)
    served = _serve(mio_locald, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    LocalRuntimeService=Service)
    FakeLedger.unavailable_on = {"mio.local.admission", "audit.late_record"}
    _refused(served["handler"])
    assert started == []
    FakeLedger.unavailable_on = set()
    assert served["handler"](object()) == {"outcome": "assessed"}     # settled, then served
    assert len(started) == 1


def test_knowledge_contextd_keeps_the_peers_stage_when_its_failure_cannot_be_recorded_and_records_it_once(
        monkeypatch, tmp_path):
    """The send happened once and failed; the record of the failure is owed: one late record, stage unchanged."""
    served, sent, request = _broker(monkeypatch, tmp_path)           # the client raises: stage `transport`
    FakeLedger.unavailable_on = {"knowledge.context.completed"}
    reply = served["handler"](request())
    assert len(sent) == 1
    assert reply == {"refusal": "unavailable", "stage": "transport"}   # not rewritten to `unrecorded`
    assert FakeLedger.calls.count("knowledge.context.requested") == 1
    FakeLedger.unavailable_on = set()
    served["handler"](request())                                      # a new request: settles first
    served["handler"](request())
    assert FakeLedger.calls.count("audit.late_record") == 1           # recorded once, late
    assert len(sent) == 3                                             # the later two are their own sends


def test_locald_admission_diagnostic_is_the_fixed_refusal_when_its_settling_finds_the_break(
        monkeypatch, tmp_path):
    """#467: a debt is owed; the admission diagnostic settles it, and the settling
    finds the chain broken. That same request gets the fixed refusal of #458,
    not "not admitted"."""
    from azazel_nexus_runtime import model_admission_evidence as evidence

    class Holder:
        reading = SimpleNamespace(embedding=None)

        def start(self, *, audit):
            return self.reading

        def refresh(self, *, withdraw, audit):
            withdraw()
            audit({"event_type": "mio.local.admission"})

        def close(self):
            pass

    class Service:
        def __init__(self, **kw):
            self._retriever = object()

        def set_playbooks(self, library):
            pass

        def handle(self, request, *, audit):
            return {"outcome": "assessed"}

    monkeypatch.setattr(evidence, "AdmissionHolder", Holder)
    served = _serve(mio_locald, monkeypatch, tmp_path, PlaybookSelectionHolder=_selection(),
                    LocalRuntimeService=Service)
    FakeLedger.unavailable_on = {"mio.local.admission", "audit.late_record"}
    _refused(served["handler"])                       # the revocation's record is owed
    FakeLedger.unavailable_on = set()
    FakeLedger.break_on = {"audit.late_record"}       # settling it finds the break
    admission = SimpleNamespace(verb=SimpleNamespace(name=mio_locald.ADMISSION_VERB.name))
    with pytest.raises(RequestRefused) as refused:
        served["handler"](admission)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    _refused(served["handler"])                       # and every request after it
