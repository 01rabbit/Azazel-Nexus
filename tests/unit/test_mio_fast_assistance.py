from types import SimpleNamespace
import copy
import time

import pytest

pytest.importorskip("azazel_mio", reason="the shared MIO package is an optional integration extra")

from azazel_nexus_runtime import mio_fast_assistance as adapter
from azazel_nexus.local_advisory import read_fast_assistance, read_frame


def test_adapter_uses_model_free_shared_assessment_without_querying_knowledge(monkeypatch):
    frame = read_frame({"request_id": "fast-lane-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003",
                        "context": [{"kind": "auth_log", "text": "Password spray"}]})
    def forbidden_lookup(*args, **kwargs):
        pytest.fail("fast assessment must not query Knowledge")
    from azazel_nexus_runtime import knowledge_client
    monkeypatch.setattr(knowledge_client, "lookup_context", forbidden_lookup)
    result = adapter.fast_assistance(frame, deadline_s=0.2)
    result = read_fast_assistance(result)
    assert result["observations"] == []
    assert result["knowledge"] == []
    assert result["dependency_outcome"]["knowledge"] == "not_queried"
    assert any("did not query Knowledge" in check for check in result["next_checks"])


def test_adapter_binds_explainer_incident_and_only_validated_refs():
    from azazel_mio.id_grammar import ID_KINDS
    from azazel_nexus.incident_explain import build_frame, pending_entry
    from test_incident_explain import transition

    pending = pending_entry(transition())
    source = build_frame(pending, 17)
    source["context"].append({"kind": "caller_report",
                              "text": "edge_would=execute"})
    source = read_frame(source)
    frame = adapter._frame(source)
    expected_trace = f"mio-{pending['incident_id'][4:]}-17"
    expected_refs = tuple(ref["evidence_id"] for ref in pending["evidence"]["refs"])
    assert frame.trace_id == expected_trace
    assert frame.frame_id == expected_trace + ":frame"
    assert ID_KINDS["trace_id"](frame.trace_id)
    assert ID_KINDS["frame_id"](frame.frame_id)
    assert frame.evidence_refs == expected_refs
    assert frame.known_facts == ()
    assert frame.soc_summary.startswith("Validated Edge transition:")
    assert f"edge_would={pending['edge_would']}" in frame.soc_summary
    assert "edge_would=execute" in frame.soc_summary
    assert dict(frame.provenance) == {
        "evidence_refs": ("evidence_plane",),
        "unknowns": ("caller",),
    }
    result = read_fast_assistance(adapter.fast_assistance(source, deadline_s=0.2))
    assert result["trace_id"] == expected_trace
    assert result["frame_id"] == expected_trace + ":frame"
    assert result["observations"] == []
    refs = [ref for hypothesis in result["hypotheses"]
            for ref in hypothesis.get("supporting_evidence_refs", [])]
    assert refs == list(expected_refs)


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


def test_locald_passes_core_only_time_left_after_its_delivery_reserve(monkeypatch):
    from azazel_nexus_runtime import mio_locald

    observed = []
    monkeypatch.setattr(adapter, "fast_assistance",
                        lambda frame, *, deadline_s:
                        observed.append(deadline_s) or {"assessment": "bounded"})
    frame = read_frame({"request_id": "delivery-reserve", "privacy_class": "P3-restricted",
                        "question": "T1110", "context": []})
    service = mio_locald.LocalRuntimeService()
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, arguments={"deadline_ms": 45}, payload=frame,
    ))

    assert observed == [pytest.approx(0.025)]
    assert reply["outcome"] == "assessed"
    assert reply["fast_assistance"] == {"assessment": "bounded"}


def test_zero_locald_budget_returns_timeout_without_calling_shared_core(monkeypatch):
    from azazel_nexus_runtime import mio_locald

    monkeypatch.setattr(adapter.AssistantCore, "explain",
                        lambda *a, **k: pytest.fail("shared core called with zero budget"))
    frame = read_frame({"request_id": "zero-budget", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    service = mio_locald.LocalRuntimeService()
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB,
        arguments={"deadline_ms": int(mio_locald.DELIVERY_RESERVE_S * 1000)},
        payload=frame,
    ))

    fast = read_fast_assistance(reply["fast_assistance"])
    assert reply["outcome"] == "assessed"
    assert fast["knowledge"] == []
    assert fast["dependency_outcome"]["knowledge"] == "timeout"


def test_adapter_marks_knowledge_as_not_queried_without_a_lookup(monkeypatch):
    frame = read_frame({"request_id": "fast-status-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    result = read_fast_assistance(adapter.fast_assistance(frame, deadline_s=0.2))
    assert result["dependency_outcome"]["knowledge"] == "not_queried"


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
    forged = copy.deepcopy(valid)
    forged["knowledge"].append({"invalid": "reference"})
    with pytest.raises(ValueError):
        read_fast_assistance(forged)
    populated = copy.deepcopy(valid)
    populated["knowledge"] = [{
        "kind": "knowledge_lite_advisory", "source_kind": "knowledge_lite",
        "claim_status": "reported_unverified", "technique_id": "T1110.003",
        "name": "Password spraying", "summary": "Reference summary",
        "claim_id": "T1110.003", "bundle_digest": "sha256:" + "a" * 64,
        "freshness": "static", "temporal_validity": "static", "generation": "7",
        "as_of": "2026-10-31T00:00:00Z", "expires_at": None,
        "citation": "kn:lite:T1110.003", "trust_check": "verified",
        "revocation_status": "clear", "trust": "unverified_advisory_only",
        "source_citation": "MITRE ATT&CK technique",
    }]
    populated["dependency_outcome"]["knowledge"] = "not_queried"
    with pytest.raises(ValueError):
        read_fast_assistance(populated)


def test_500ms_entry_service_calls_fast_lane_with_bounded_reply(tmp_path, monkeypatch):
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
    request = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 500},
                              payload={"request_id": "integration", "privacy_class": "P2-mission",
                                       "question": "SSH host-1 T1110.003",
                                       "context": [{"kind": "auth_log", "text": "Password spray"}]})
    started = time.monotonic()
    reply = target.handle(request)
    elapsed = time.monotonic() - started
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["fast_assistance"] == payload
    assert checked and checked[0][0] == request.payload and checked[0][1] > 0
    assert checked[0][1] <= entry.FAST_ASSESS_MAX_S
    assert checked[0][1] <= 0.045
    assert elapsed < 0.5
    assert order == ["fast_assessment", "deep_route"]
