from types import SimpleNamespace
import copy

import pytest

pytest.importorskip("azazel_mio", reason="the shared MIO package is an optional integration extra")

from azazel_nexus_runtime import mio_fast_assistance as adapter
from azazel_nexus.lite_import import KnowledgeRef
from azazel_nexus.local_advisory import read_fast_assistance, read_frame


def test_adapter_keeps_reports_out_of_facts_and_preserves_trusted_reference(monkeypatch):
    frame = read_frame({"request_id": "fast-lane-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003",
                        "context": [{"kind": "auth_log", "text": "Password spray"}]})
    ref = KnowledgeRef("T1110.003", "Password spraying", "Reference summary", "T1110.003",
                       "sha256:" + "a" * 64, "static", "knowledge_lite", 7, "verified",
                       "2026-10-31T00:00:00Z", "MITRE ATT&CK technique")
    observed = []
    monkeypatch.setattr(adapter, "lookup_context", lambda ids, *, deadline_s:
                        observed.append((ids, deadline_s)) or (ref,))
    result = adapter.fast_assistance(frame, deadline_s=0.2)
    result = read_fast_assistance(result)
    assert observed[0][0] == ("T1110.003",)
    assert result["observations"] == []
    claim, = result["knowledge"]
    assert claim["source_kind"] == "knowledge_lite"
    assert claim["bundle_digest"] == ref.bundle_digest
    assert claim["generation"] == "7"
    assert claim["as_of"] == ref.as_of
    assert claim["freshness"] == "static"
    assert claim["source_citation"] == ref.citation
    assert claim["citation"] == "kn:lite:T1110.003"
    assert claim["revocation_status"] == "clear"
    assert claim["expires_at"] is None


def test_adapter_maps_lookup_failure_to_typed_degradation(monkeypatch):
    frame = read_frame({"request_id": "fast-timeout-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    def timeout(*args, **kwargs):
        raise adapter.KnowledgeUnavailable()
    monkeypatch.setattr(adapter, "lookup_context", timeout)
    result = read_fast_assistance(adapter.fast_assistance(frame, deadline_s=0.2))
    assert result["knowledge"] == []
    assert result["dependency_outcome"]["knowledge"] == "unavailable"


def test_adapter_omits_empty_summary_without_inventing_text(monkeypatch):
    frame = read_frame({"request_id": "empty-summary", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    ref = KnowledgeRef("T1110.003", "Password spraying", "", "T1110.003",
                       "sha256:" + "a" * 64, "static", "knowledge_lite", 7, "verified",
                       "2026-10-31T00:00:00Z", "MITRE ATT&CK technique")
    monkeypatch.setattr(adapter, "lookup_context", lambda *a, **k: (ref,))
    result = read_fast_assistance(adapter.fast_assistance(frame, deadline_s=0.2))
    assert result["knowledge"] == []
    assert result["dependency_outcome"]["knowledge"] == "rejected"


def test_adapter_keeps_valid_refs_and_marks_mixed_projection_partial(monkeypatch):
    frame = read_frame({"request_id": "mixed-summary", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    empty = KnowledgeRef("T1110.003", "Password spraying", "", "T1110.003",
                         "sha256:" + "a" * 64, "static", "knowledge_lite", 7, "verified",
                         "2026-10-31T00:00:00Z", "MITRE ATT&CK technique")
    valid = KnowledgeRef("T1110.003", "Password spraying", "Checked summary", "T1110.003",
                         "sha256:" + "a" * 64, "static", "knowledge_lite", 7, "verified",
                         "2026-10-31T00:00:00Z", "MITRE ATT&CK technique")
    monkeypatch.setattr(adapter, "lookup_context", lambda *a, **k: (valid, empty))
    result = read_fast_assistance(adapter.fast_assistance(frame, deadline_s=0.2))
    assert len(result["knowledge"]) == 1
    assert result["knowledge"][0]["summary"] == "Checked summary"
    assert result["dependency_outcome"]["knowledge"] == "partial"


def test_locald_fast_assess_converts_adapter_exception_to_degradation(monkeypatch):
    from azazel_nexus_runtime import mio_locald as locald
    from azazel_nexus_runtime import mio_fast_assistance
    request = SimpleNamespace(verb=locald.FAST_ASSESS_VERB,
                              arguments={"deadline_ms": 500},
                              payload={"request_id": "boundary-failure",
                                       "privacy_class": "P2-mission",
                                       "question": "T1110", "context": []})
    monkeypatch.setattr(mio_fast_assistance, "fast_assistance",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("private failure")))
    service = locald.LocalRuntimeService()
    first = service.handle(request)
    second = service.handle(request)
    for reply in (first, second):
        fast = read_fast_assistance(reply["fast_assistance"])
        assert reply["outcome"] == "assessed"
        assert fast["state"] == "dependency_unavailable"
        assert fast["dependency_outcome"]["knowledge"] == "unavailable"


def test_local_socket_assess_preserves_failure_classes(monkeypatch):
    from azazel_nexus_runtime import mio_socket_client as client
    frame = {"test": "frame"}
    cases = ((TimeoutError(), "timeout"),
             (client.ServiceRefused("principal_denied"), "rejected"),
             (OSError("socket absent"), "unavailable"),
             (ValueError("malformed"), "rejected"))
    for error, expected in cases:
        def fail(*args, _error=error, **kwargs):
            raise _error
        monkeypatch.setattr(client, "_exchange", fail)
        result = client.LocalSocketClient().assess(frame, deadline_s=0.2)
        assert result["dependency_outcome"]["knowledge"] == expected

    monkeypatch.setattr(client, "_exchange", lambda *a, **k: {
        "outcome": "assessed", "fast_assistance": {"malformed": True}})
    result = client.LocalSocketClient().assess(frame, deadline_s=0.2)
    assert result["dependency_outcome"]["knowledge"] == "rejected"


def test_adapter_collapses_unavailable_knowledge_failure_codes(monkeypatch):
    frame = read_frame({"request_id": "fast-status-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    for error, expected in ((adapter.KnowledgeUnavailable("knowledge_timeout"), "unavailable"),
                            (adapter.KnowledgeUnavailable("knowledge_peer_refused"), "unavailable"),
                            (adapter.KnowledgeUnavailable("knowledge_reply_refused"), "rejected")):
        monkeypatch.setattr(adapter, "lookup_context", lambda *a, _error=error, **k: (_ for _ in ()).throw(_error))
        result = read_fast_assistance(adapter.fast_assistance(frame, deadline_s=0.2))
        assert result["dependency_outcome"]["knowledge"] == expected


def test_fast_assistance_reader_rejects_malformed_fields_before_persistence():
    frame = read_frame({"request_id": "schema-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    valid = adapter.fast_assistance(frame, deadline_s=0)
    assert read_fast_assistance(valid) is valid
    mutations = (
        ("unknowns", [{}]), ("next_checks", [{}]), ("hypotheses", [{}]),
        ("handoff", {}), ("reasoning_trace", [{}]), ("trace_id", []),
        ("frame_id", "mio-0000000000000000-1:other"), ("state", {}),
        ("dependency_outcome", {"knowledge": "absent", "deception": "attacker"}),
    )
    for key, bad in mutations:
        forged = copy.deepcopy(valid)
        forged[key] = bad
        with pytest.raises(ValueError):
            read_fast_assistance(forged)


def test_entry_service_calls_fast_lane_without_changing_deterministic_route(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus.routing import Route

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    target = entry.MioEntryService()
    target.reference = SimpleNamespace(reference=lambda *args, **kwargs:
                                       (None, "reference_service_unavailable"))
    monkeypatch.setattr(target.local, "observe", lambda **_: "fixture")
    monkeypatch.setattr(target.remote, "observe", lambda **_: "fixture")
    checked = []
    order = []
    route = target.router.handle

    def routed(*args, **kwargs):
        order.append("deep_route")
        return route(*args, **kwargs)

    monkeypatch.setattr(target.router, "handle", routed)
    payload = {"schema_version": "mio.assistance.v1", "trace_id": "mio-0000000000000000-1",
               "frame_id": "mio-0000000000000000-1:frame",
               "generation_method": "static_reference", "state": "complete",
               "observations": [], "hypotheses": [], "unknowns": [], "next_checks": [],
               "knowledge": [], "dependency_outcome": {"knowledge": "absent", "deception": "absent"},
               "handoff": None, "reasoning_trace": []}
    def assess(frame, *, deadline_s):
        order.append("fast_assessment")
        checked.append((frame, deadline_s))
        return payload

    monkeypatch.setattr(target.local, "assess", assess)
    request = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 1000},
                              payload={"request_id": "integration", "privacy_class": "P2-mission",
                                       "question": "SSH host-1 T1110.003",
                                       "context": [{"kind": "auth_log", "text": "Password spray"}]})
    reply = target.handle(request)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["fast_assistance"] == payload
    assert checked and checked[0][0] == request.payload and checked[0][1] > 0
    assert checked[0][1] <= entry.FAST_ASSESS_MAX_S
    assert order == ["fast_assessment", "deep_route"]
