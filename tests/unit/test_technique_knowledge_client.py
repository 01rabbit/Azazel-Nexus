"""The client stage words for a technique query: 422, signature, validator, success."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("azazel_fabric.knowledge_context")

from _technique_fixture import make_response
from azazel_nexus import technique_knowledge as tk
from azazel_nexus.sanitizer import SanitizerPolicy
from azazel_nexus_runtime import knowledge_egress
from azazel_nexus_runtime.knowledge_egress import HttpStatusRefused
from test_knowledge_context_transport import NOW, _signed_answer, client, registry

IDS = ["T1110", "T1595.002"]
POLICY = SanitizerPolicy.from_mapping({
    "version": "t1", "remote_default": "deny",
    "classes": {"P0-public": {"remote": "allow", "fields": ["question"]}},
    "aliases": [], "redactions": [], "limits": {"max_bytes": 4096}})


def peer():
    return client(registry(443), enabled=True, max_ttl_seconds=300)


def ask(p, ids=IDS):
    from azazel_nexus.sanitizer import PrivacyClass
    return p.request_context(frame={"techniques": ids}, privacy_class=PrivacyClass.P0_PUBLIC,
                             policy=POLICY, mission="m", alias_key=b"k" * 32, deadline_s=5)


def answering(p, monkeypatch, shape):
    """Replace the wire with a signed answer built from the request body; `shape` edits it."""
    import hashlib
    from nacl.signing import SigningKey
    from azazel_nexus.knowledge_context_adapter import (
        ENVELOPE_DOMAIN, ENVELOPE_SCHEMA, canonical_signed_payload)
    import test_knowledge_context_transport as t

    def post(_peer, _path, body, _deadline):
        request = json.loads(body)
        response = make_response(IDS)
        response.update(request_id=request["request_id"], correlation_id=request["correlation_id"],
                        provider_id="knowledge-node-1", generated_at=NOW,
                        expires_at="2026-11-04T12:00:30Z")
        response["snapshot"]["as_of"] = "2026-11-03T00:00:00Z"
        shape(response)
        envelope = {"schema": ENVELOPE_SCHEMA, "key_id": t.KEY_ID, "issued_at": NOW,
                    "expires_at": "2026-11-04T12:05:00Z", "payload": response}
        canonical = canonical_signed_payload(envelope)
        return t.PEER_KEY.sign(ENVELOPE_DOMAIN + canonical).signature + canonical

    monkeypatch.setattr(p, "_post_path", post)


def stage_of(p):
    with pytest.raises(Exception) as caught:
        ask(p)
    return caught.value.stage


def test_valid_answer_passes_signature_and_validator(monkeypatch):
    p = peer()
    answering(p, monkeypatch, lambda r: None)
    response = ask(p)
    assert tk.project_technique_response(response.model_dump(mode="json"), IDS)["verification"] == "ok"


def test_request_body_carries_typed_entities_not_a_question(monkeypatch):
    p = peer()
    seen = []
    monkeypatch.setattr(p, "_post_path", lambda _p, path, body, _d: seen.append((path, json.loads(body))) or (_ for _ in ()).throw(OSError()))
    stage_of(p)
    path, body = seen[0]
    assert path == "/v1/knowledge-context"
    assert [(e["entity_type"], e["value"]) for e in body["entities"]] == [("attack-technique/v1", t) for t in IDS]
    assert "question" not in json.dumps(body)


def test_validator_refusal_has_its_own_stage_after_a_good_signature(monkeypatch):
    p = peer()
    answering(p, monkeypatch, lambda r: r["limitations"].append("Block the address now."))
    assert stage_of(p) == "technique_verification"


def test_poisoned_name_is_a_validator_refusal_not_a_success(monkeypatch):
    p = peer()
    answering(p, monkeypatch, lambda r: r["facts"][1].update(value="<script>x</script>"))
    assert stage_of(p) == "technique_verification"


def test_http_422_counts_as_a_failed_verification(monkeypatch):
    p = peer()

    def post(*_a):
        raise HttpStatusRefused(422)
    monkeypatch.setattr(p, "_post_path", post)
    assert stage_of(p) == "verification"


@pytest.mark.parametrize("status", [400, 403, 404, 500, 503])
def test_other_statuses_are_transport(monkeypatch, status):
    p = peer()

    def post(*_a):
        raise HttpStatusRefused(status)
    monkeypatch.setattr(p, "_post_path", post)
    assert stage_of(p) == "transport"


def test_bad_signature_is_a_failed_verification_not_a_validator_refusal(monkeypatch):
    p = peer()
    monkeypatch.setattr(p, "_post_path", lambda *_a: b"x" * 200)
    assert stage_of(p) == "verification"


def test_status_line_parser_is_exact():
    import re
    pattern = knowledge_egress._STATUS_LINE
    assert pattern.fullmatch(b"HTTP/1.0 422 Unprocessable Entity").group(1) == b"422"
    assert pattern.fullmatch(b"HTTP/1.1 422").group(1) == b"422"
    for bad in (b"HTTP/2 422 x", b"HTTP/1.1 4222 x", b"XHTTP/1.1 422 x", b"HTTP/1.1 422 x\r\nX: y"):
        assert pattern.fullmatch(bad) is None
