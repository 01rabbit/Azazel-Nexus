"""Trusted streaming context and the bounded local socket client."""

from dataclasses import FrozenInstanceError, asdict

import pytest
from test_knowledge_lited import NOW
from test_knowledge_lited import node as commissioned_node
from test_lite_bundle import _manifest, _signed

from azazel_nexus.lite_import import (
    CommissionedLite,
    KnowledgeRef,
    LiteImport,
    lookup_context,
    lookup_context_reading,
)
from azazel_nexus.revocation import RevocationList


@pytest.fixture
def node(tmp_path, monkeypatch):
    return commissioned_node.__wrapped__(tmp_path, monkeypatch)


def admit_rows(node, rows):
    import json

    _, root, _, _ = node
    (root / "inbox/bundle.tar.gz").write_bytes(_signed(
        _manifest(bundle_version=5),
        {"tables/attack_technique.jsonl": b"".join(json.dumps(row).encode() + b"\n" for row in rows)},
    ))
    importer = LiteImport(CommissionedLite(root))
    assert importer.import_entry(importer.list_inbox()[0].entry_id, now=NOW).admitted


def reading(node, ids=("T1110",)):
    return lookup_context_reading(root=node[1], trust_root=node[2],
                                  technique_ids=ids, query_as_of=NOW)


def test_mapping_plain_text_freshness_and_immutability(node):
    admit_rows(node, [
        {"technique_id": "T1110", "name": "<b>Brute Force</b>",
         "description": "**Text** [label](https://example.test) &amp;\n" + "x" * 300},
        {"technique_id": "T1110.001", "name": "Guessing", "agg_next_expiry": "2027-01-01T00:00:00Z"},
        {"technique_id": "T1110", "name": "expired", "agg_next_expiry": "2020-01-01T00:00:00Z"},
        {"technique_id": "T1110", "name": "invalid expiry", "agg_next_expiry": "bad"},
        {"technique_id": "T1046", "name": "Unrequested"},
    ])
    result = reading(node, ("T1110", "T1110.001"))
    assert result.reason_code == "available"
    assert len(result.refs) == 2
    ref, current = result.refs
    assert ref.technique_id == ref.claim_id == "T1110"
    assert ref.name == "Brute Force"
    assert ref.summary.startswith("Text label & x")
    assert len(ref.summary) == 240
    assert ref.freshness == "static" and current.freshness == "current"
    assert ref.bundle_digest.startswith("sha256:")
    assert reading(node, ("T1110", "T1110.001", "T1110")).refs == result.refs
    with pytest.raises(FrozenInstanceError):
        ref.name = "modified"
    assert lookup_context(root=node[1], trust_root=node[2], technique_ids=("T1110",),
                          query_as_of=NOW) == (ref,)


def test_producer_fixture_technique_primary_key(node):
    import json
    import tarfile
    from pathlib import Path

    fixture = Path(__file__).parents[1] / "fixtures/knowledge-lite/lite.tar.gz"
    with tarfile.open(fixture) as archive:
        rows = archive.extractfile("tables/attack_technique.jsonl").read().splitlines()
    # Preserve the producer's rows, re-sign with this node's test-only key.
    admit_rows(node, [json.loads(row) for row in rows])
    ref, = reading(node).refs
    assert (ref.technique_id, ref.name, ref.summary, ref.claim_id, ref.freshness) == (
        "T1110", "Brute Force", "", "T1110", "static")


def test_stream_output_bound_and_names(node):
    admit_rows(node, [{"technique_id": "T1110", "name": "n" * 200}] * 30)
    result = reading(node)
    assert len(result.refs) == 16
    assert all(len(ref.name) == 120 for ref in result.refs)


@pytest.mark.parametrize("ids", [("T1110",) * 9, ("TA0001",), ("T1110\n",), (1,), ["T1110"]])
def test_invalid_input_fixed_reason(node, ids):
    assert reading(node, ids).reason_code == "invalid_technique_ids"
    assert reading(node, ids).refs == ()


def test_absent_expired_and_empty_context(node):
    assert reading(node).reason_code == "no_bundle"
    assert reading(node, ()).refs == ()
    assert reading(node, ()).reason_code == "no_bundle"
    admit_rows(node, [{"technique_id": "T1110", "name": "old", "agg_next_expiry": "2000-01-01T00:00:00Z"}])
    assert reading(node).reason_code == "no_context"
    assert reading(node).refs == ()


@pytest.mark.parametrize("failure", ["trust", "bundle", "revocations", "revoked"])
def test_trust_rechecked_on_every_lookup(node, failure):
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}])
    assert reading(node).refs
    _, root, trust, revoker = node
    if failure == "trust":
        (trust / "trust.json").unlink()
    elif failure == "bundle":
        (root / "admitted/current.tar.gz").write_bytes(b"corrupt")
    elif failure == "revocations":
        (trust / "revocations.signed").write_bytes(b"corrupt")
    else:
        statement = RevocationList(sequence=1, issued_at=NOW, revoked_generations=frozenset({5}))
        (trust / "revocations.signed").write_bytes(
            revoker.sign(statement.signature_target()).signature + statement.as_payload())
    result = reading(node)
    assert result.refs == ()
    assert result.reason_code == {"trust": "trust_unreadable", "bundle": "bundle_refused",
                                  "revocations": "unverified", "revoked": "revoked"}[failure]


def test_repin_during_iteration_withholds_context(node, monkeypatch):
    import azazel_nexus.lite_import as library

    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}])
    original = library.iter_served

    def changed(*args, **kwargs):
        yield from original(*args, **kwargs)
        (node[2] / "trust.json").write_text("{}")

    monkeypatch.setattr(library, "iter_served", changed)
    assert reading(node).reason_code == "trust_unreadable"
    assert reading(node).refs == ()


def test_client_exchange_and_empty_result(monkeypatch):
    from azazel_nexus_runtime import knowledge_client as client

    ref = KnowledgeRef("T1110", "Brute Force", "", "T1110", "sha256:" + "a" * 64, "static")
    calls = []

    def exchange(*args, **kwargs):
        calls.append((args, kwargs))
        return {"refs": [asdict(ref)], "reason_code": "available"}

    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.lookup_context(("T1110",), deadline_s=0.2) == (ref,)
    assert calls == [(("knowledge-read", "azknowledge", "knowledge.lookup", {"technique_ids": ["T1110"]}),
                      {"deadline_s": 0.2})]
    monkeypatch.setattr(client, "_exchange", lambda *a, **k: {"refs": [], "reason_code": "no_context"})
    assert client.lookup_context(("T1110",)) == ()


@pytest.mark.parametrize("response", [
    {}, {"refs": [], "reason_code": "revoked"}, {"refs": [], "reason_code": "available"},
    {"refs": [{}] * 17, "reason_code": "available"},
    {"refs": [{"text": "must not leak"}], "reason_code": "available"},
])
def test_client_malformed_or_unavailable_fixed_exception(monkeypatch, response):
    from azazel_nexus_runtime import knowledge_client as client

    monkeypatch.setattr(client, "_exchange", lambda *a, **k: response)
    with pytest.raises(client.KnowledgeUnavailable, match="^knowledge unavailable$"):
        client.lookup_context(("T1110",))


@pytest.mark.parametrize("error", [TimeoutError("secret"), PermissionError("secret"), ValueError("secret")])
def test_client_transport_failure_fixed_exception(monkeypatch, error):
    from azazel_nexus_runtime import knowledge_client as client

    def exchange(*a, **k):
        raise error

    monkeypatch.setattr(client, "_exchange", exchange)
    with pytest.raises(client.KnowledgeUnavailable, match="^knowledge unavailable$"):
        client.lookup_context(("T1110",))


def test_stream_stops_at_sixteen_and_empty_query_still_checks_trust(node, monkeypatch):
    import azazel_nexus.lite_import as library

    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}])
    seen = []

    def rows(*args, **kwargs):
        for index in range(100):
            seen.append(index)
            yield {"technique_id": "T1110", "name": "Brute Force"}

    monkeypatch.setattr(library, "iter_served", rows)
    assert len(reading(node).refs) == 16
    assert seen == list(range(16))
    assert reading(node, ()).reason_code == "no_context"
    (node[2] / "trust.json").unlink()
    assert reading(node, ()).reason_code == "trust_unreadable"


def test_client_checks_dedicated_socket_gid_before_connect(monkeypatch):
    from types import SimpleNamespace

    from azazel_nexus_runtime import mio_socket_client

    groups = []
    monkeypatch.setattr(mio_socket_client.pwd, 'getpwnam',
                        lambda account: SimpleNamespace(pw_uid=111))
    def group(name):
        groups.append(name)
        return SimpleNamespace(gr_gid=222)
    monkeypatch.setattr(mio_socket_client.grp, 'getgrnam', group)
    observed = []
    def verify(path, **kwargs):
        observed.append((path, kwargs))
        raise ValueError('stop before connect')
    monkeypatch.setattr(mio_socket_client, 'verify_socket', verify)
    with pytest.raises(ValueError, match='stop before connect'):
        mio_socket_client._exchange('knowledge-read', 'azknowledge', 'knowledge.lookup', {})
    assert groups == ['azknowledge-read']
    assert observed[0][0].name == 'knowledge-read.sock'
    assert observed[0][1] == {'expected_uid': 111, 'expected_gid': 222}
