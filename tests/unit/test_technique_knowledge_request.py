"""The observation-triggered technique request: typed entities, a closed make_request entry."""

from __future__ import annotations

import pytest

from _technique_fixture import make_response
from azazel_nexus import technique_knowledge as tk

fabric = pytest.importorskip("azazel_fabric.knowledge_context")
IDS = ["T1110", "T1595.002"]


def ok(response, ids=IDS):
    return tk.validate_technique_response(response, ids)


def _policy(fields=("question",)):
    from azazel_nexus.sanitizer import SanitizerPolicy
    return SanitizerPolicy.from_mapping({
        "version": "t1", "remote_default": "deny",
        "classes": {"P0-public": {"remote": "allow", "fields": list(fields)}},
        "aliases": [], "redactions": [], "limits": {"max_bytes": 4096}})


def _make(frame, policy=None):
    from azazel_nexus.knowledge_context_adapter import make_request
    from azazel_nexus.sanitizer import PrivacyClass
    return make_request(frame, privacy_class=PrivacyClass.P0_PUBLIC, policy=policy or _policy(),
                        mission="m", alias_key=b"k" * 32, requested_at="2026-11-13T00:00:00Z")


def test_request_has_one_typed_entity_per_technique():
    request = _make({"techniques": ["T1110", "T1595.002"]})
    assert [(e.entity_type, e.value) for e in request.entities] == [
        ("attack-technique/v1", "T1110"), ("attack-technique/v1", "T1595.002")]
    assert request.source_ref == "nexus:full-node-context-query"
    assert "question" not in request.model_dump_json()


@pytest.mark.parametrize("bad", [[], ["t1110"], ["T1110", "T1110"], ["T1595.002", "T1110"], ["T1110 "],
                                 ["T1110\n"], ["T111"], ["T1110.1"], [f"T{1000 + n}" for n in range(9)],
                                 "T1110", None, [1110], ["T１１１０"]])
def test_request_refuses_a_bad_technique_set(bad):
    from azazel_nexus.knowledge_context_adapter import KnowledgeContextRefused
    with pytest.raises(KnowledgeContextRefused):
        _make({"techniques": bad})


def test_request_entry_is_closed_and_the_policy_still_decides():
    from azazel_nexus.knowledge_context_adapter import KnowledgeContextRefused
    # no widening: another key beside techniques is not this entry, and goes to the sanitizer
    with pytest.raises(KnowledgeContextRefused):
        _make({"techniques": ["T1110"], "indicator": "203.0.113.9"})
    with pytest.raises(KnowledgeContextRefused):
        _make({"techniques": ["T1110"], "question": "x"})
    # the policy that does not admit the observation question admits no technique query
    with pytest.raises(KnowledgeContextRefused):
        _make({"techniques": ["T1110"]}, _policy(("indicator",)))
    # existing entries are unchanged: a question is still one question entity
    request = _make({"question": "public question"})
    assert [(e.entity_type, e.value) for e in request.entities] == [("question", "public question")]
    # and the technique key is not accepted through any other class
    from azazel_nexus.sanitizer import PrivacyClass
    from azazel_nexus.knowledge_context_adapter import make_request
    with pytest.raises(KnowledgeContextRefused):
        make_request({"techniques": ["T1110"]}, privacy_class=PrivacyClass.P1_ALIASED if hasattr(PrivacyClass, "P1_ALIASED") else PrivacyClass.P3_RESTRICTED,
                     policy=_policy(), mission="m", alias_key=b"k" * 32, requested_at="2026-11-13T00:00:00Z")


def test_a_fabric_valid_answer_round_trips_through_the_validator():
    request = _make({"techniques": IDS})
    response = make_response(IDS)
    response.update(request_id=request.request_id, correlation_id=request.correlation_id)
    parsed = fabric.KnowledgeContextResponseV1.model_validate(response)
    fabric.assert_response_correlates(request, parsed)
    assert ok(parsed.model_dump(mode="json")) == ok(response)


def test_ioc_request_is_unchanged():
    """IOC regression: indicator frames still become one entity per allowed key, sorted by key."""
    policy = _policy(("indicator", "question"))
    request = _make({"indicator": "203.0.113.9", "question": "public question"}, policy)
    assert [(e.entity_type, e.value) for e in request.entities] == [
        ("indicator", "203.0.113.9"), ("question", "public question")]
    assert request.source_ref == "nexus:full-node-context-query"
    assert request.schema_version == "knowledge-context-request/v1"
    # a technique-shaped list under any other key is still refused by the string-only rule
    from azazel_nexus.knowledge_context_adapter import KnowledgeContextRefused
    with pytest.raises(KnowledgeContextRefused):
        _make({"indicator": ["T1110"]}, policy)
    # no existing entry yields the technique entity type
    assert all(e.entity_type != "attack-technique/v1" for e in request.entities)
