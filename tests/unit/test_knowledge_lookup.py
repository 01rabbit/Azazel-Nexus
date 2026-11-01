"""Trusted streaming context and the bounded local socket client."""

import json
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
    read_knowledge_refs,
)
from azazel_nexus.revocation import RevocationList


@pytest.fixture
def node(tmp_path, monkeypatch):
    return commissioned_node.__wrapped__(tmp_path, monkeypatch)


_MISSING = object()


def admit_rows(node, rows, **manifest):
    import json

    _, root, _, _ = node
    (root / "inbox/bundle.tar.gz").write_bytes(_signed(
        _manifest(bundle_version=5, **manifest),
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
    assert (ref.source_kind, ref.generation, ref.trust_check) == ('knowledge_lite', 5, 'verified')
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


def _producer_manifest():
    import json
    import tarfile
    from pathlib import Path

    fixture = Path(__file__).parents[1] / "fixtures/knowledge-lite/lite.tar.gz"
    with tarfile.open(fixture) as archive:
        manifest = json.loads(archive.extractfile("manifest.json").read())
        rows = archive.extractfile("tables/attack_technique.jsonl").read().splitlines()
    return manifest, [json.loads(row) for row in rows]


def test_citation_and_as_of_come_from_the_signed_manifest_and_the_lookup(node):
    manifest, rows = _producer_manifest()
    # The producer's own signed provenance block, re-signed with the test key.
    admit_rows(node, rows, profile=manifest["profile"])
    ref, = reading(node).refs
    assert ref.citation == manifest["profile"]["provenance"]["attack_technique"]["dataset"]["citation"]
    assert ref.citation.startswith("MITRE ATT&CK technique")
    assert ref.as_of == NOW
    as_of = lookup_context_reading(root=node[1], trust_root=node[2], technique_ids=("T1110",),
                                   query_as_of="2026-10-18T09:00:00.987654+09:00").refs[0].as_of
    assert as_of == "2026-10-18T00:00:00Z"


@pytest.mark.parametrize("profile", [
    None, {}, {"provenance": []}, {"provenance": {"attack_technique": {"dataset": {}}}},
    {"provenance": {"attack_technique": {"dataset": {"citation": 7}}}},
    {"provenance": {"other": {"dataset": {"citation": "not this dataset"}}}},
])
def test_missing_or_malformed_citation_is_empty_not_refused(node, profile):
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}],
               **({} if profile is None else {"profile": profile}))
    # admit_rows writes tables/attack_technique.jsonl.
    ref, = reading(node).refs
    assert ref.citation == ""
    assert read_knowledge_refs([asdict(ref)]) == (ref,)


@pytest.mark.parametrize("citation", ["&amp;amp;lt;b&amp;amp;gt;nested", "a " * 100,
                                      "&lt;i&gt;x&lt;/i&gt; source"])
def test_producer_citation_settles_to_a_reader_fixed_point(node, citation):
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}],
               profile={"provenance": {"attack_technique": {"dataset": {"citation": citation}}}})
    ref, = reading(node).refs
    assert read_knowledge_refs([asdict(ref)]) == (ref,)


def test_citation_is_plain_bounded_text(node):
    citation = "<b>Cited</b> [link](https://example.test/x) " + "c" * 300
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}],
               profile={"provenance": {"attack_technique": {"dataset": {"citation": citation}}}})
    ref, = reading(node).refs
    assert ref.citation.startswith("Cited link c") and len(ref.citation) == 160
    assert "https" not in ref.citation and "<" not in ref.citation


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
    original = library.iter_served_with_member

    def changed(*args, **kwargs):
        yield from original(*args, **kwargs)
        (node[2] / "trust.json").write_text("{}")

    monkeypatch.setattr(library, "iter_served_with_member", changed)
    assert reading(node).reason_code == "trust_unreadable"
    assert reading(node).refs == ()


def test_client_exchange_and_empty_result(monkeypatch):
    from azazel_nexus_runtime import knowledge_client as client

    ref = KnowledgeRef("T1110", "Brute Force", "", "T1110", "sha256:" + "a" * 64, "static",
                       "knowledge_lite", 5, "verified", NOW, "")
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


@pytest.mark.parametrize("response,expected", [
    ({}, "knowledge_reply_refused"),
    ({"refs": [], "reason_code": "revoked"}, "knowledge_unavailable"),
    ({"refs": [], "reason_code": "state_untrusted"}, "knowledge_unavailable"),
    ({"refs": [], "reason_code": "trust_unreadable"}, "knowledge_unavailable"),
    ({"refs": [], "reason_code": "store_unreadable"}, "knowledge_unavailable"),
    ({"refs": [{}], "reason_code": "state_untrusted"}, "knowledge_reply_refused"),
    ({"refs": [], "reason_code": "available"}, "knowledge_reply_refused"),
    ({"refs": [{}] * 17, "reason_code": "available"}, "knowledge_reply_refused"),
    ({"refs": [{"text": "must not leak"}], "reason_code": "available"}, "knowledge_reply_refused"),
])
def test_client_malformed_or_unavailable_fixed_exception(monkeypatch, response, expected):
    from azazel_nexus_runtime import knowledge_client as client

    monkeypatch.setattr(client, "_exchange", lambda *a, **k: response)
    with pytest.raises(client.KnowledgeUnavailable, match="^knowledge unavailable$") as caught:
        client.lookup_context(("T1110",))
    assert caught.value.code == expected


@pytest.mark.parametrize("error,expected", [(TimeoutError("secret"), "knowledge_unavailable"),
                                       (PermissionError("secret"), "knowledge_unavailable"),
                                       (ValueError("secret"), "knowledge_unavailable"),
                                       (ValueError("M.I.O. peer refused"), "knowledge_unavailable"),
                                       (ValueError("M.I.O. response bound refused"), "knowledge_unavailable"),
                                       (ValueError("M.I.O. service refused"), "knowledge_unavailable"),
                                       (json.JSONDecodeError("secret", "", 0), "knowledge_unavailable")])
def test_client_transport_failure_fixed_exception(monkeypatch, error, expected):
    from azazel_nexus_runtime import knowledge_client as client

    def exchange(*a, **k):
        raise error

    monkeypatch.setattr(client, "_exchange", exchange)
    with pytest.raises(client.KnowledgeUnavailable, match="^knowledge unavailable$") as caught:
        client.lookup_context(("T1110",))
    assert caught.value.code == expected


def test_client_collapses_declared_peer_refusal(monkeypatch):
    from azazel_nexus_runtime import knowledge_client as client
    from azazel_nexus_runtime.mio_socket_client import ServiceRefused

    monkeypatch.setattr(client, "_exchange",
                        lambda *a, **k: (_ for _ in ()).throw(ServiceRefused("principal_denied")))
    with pytest.raises(client.KnowledgeUnavailable) as caught:
        client.lookup_context(("T1110",))
    assert caught.value.code == "knowledge_unavailable"


def test_stream_stops_at_sixteen_and_empty_query_still_checks_trust(node, monkeypatch):
    import azazel_nexus.lite_import as library

    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}])
    seen = []

    def rows(*args, **kwargs):
        for index in range(100):
            seen.append(index)
            yield "tables/attack_technique.jsonl", {"technique_id": "T1110", "name": "Brute Force"}

    monkeypatch.setattr(library, "iter_served_with_member", rows)
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


def test_client_deadline_with_accepting_silent_server(monkeypatch):
    import os
    import socket
    import threading
    import tempfile
    import time
    from types import SimpleNamespace

    from azazel_nexus_runtime import knowledge_client, mio_socket_client

    accepted = threading.Event()
    release = threading.Event()
    errors = []
    # macOS sockaddr_un cannot hold pytest's long temporary directory names.
    with tempfile.TemporaryDirectory(dir='/tmp') as directory, \
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        from pathlib import Path
        path = Path(directory) / 'k.sock'
        try:
            listener.bind(str(path))
        except PermissionError:
            pytest.skip('sandbox denies AF_UNIX bind')
        listener.listen(1)
        listener.settimeout(2)
        def silent_server():
            try:
                with listener.accept()[0]:
                    accepted.set()
                    release.wait(2)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=silent_server)
        worker.start()
        # Only identity/filesystem plumbing is replaced; connect, send and recv
        # use a real socket, including its real monotonic timeout.
        monkeypatch.setattr(mio_socket_client, 'socket_path', lambda _: path)
        monkeypatch.setattr(mio_socket_client.pwd, 'getpwnam',
                            lambda _: SimpleNamespace(pw_uid=os.getuid()))
        monkeypatch.setattr(mio_socket_client.grp, 'getgrnam',
                            lambda _: SimpleNamespace(gr_gid=os.getgid()))
        monkeypatch.setattr(mio_socket_client, 'verify_socket', lambda *a, **k: None)
        monkeypatch.setattr(mio_socket_client, 'peer_credentials',
                            lambda _: (os.getpid(), os.getuid(), os.getgid()))
        try:
            began = time.monotonic()
            with pytest.raises(knowledge_client.KnowledgeUnavailable):
                knowledge_client.lookup_context(('T1110',), deadline_s=0.05)
            elapsed = time.monotonic() - began
            assert accepted.is_set()
            # Allow scheduler jitter, but never wait for the server's 2 s guard.
            assert 0.04 <= elapsed < 0.2
        finally:
            release.set()
            worker.join(timeout=2)
    assert not worker.is_alive()
    assert errors == []


@pytest.mark.parametrize('field,value', [
    ('freshness', 'expired'), ('trust_check', 'unverified'),
    ('source_kind', 'model'), ('generation', True), ('generation', -1),
    ('generation', 2**63),
    # The lookup instant: canonical UTC seconds with Z only.
    ('as_of', '2026-10-18T00:00:00.5Z'), ('as_of', '2026-10-18T00:00:00+00:00'),
    ('as_of', '2026-10-18T09:00:00+09:00'), ('as_of', '2026-10-18T00:00:00'),
    ('as_of', ''), ('as_of', '2026-13-18T00:00:00Z'), ('as_of', 0),
    # The dataset citation: bounded printable text.
    ('citation', 'x' * 161), ('citation', 'line\nbreak'), ('citation', None),
    # Not the fixed point of the producer-side cleaning.
    ('citation', 'two  spaces'), ('citation', 'trailing '), ('citation', '<b>tag</b>'),
    ('citation', 'AT&amp;T'), ('citation', 'see https://example.test'),
    ('as_of', _MISSING), ('citation', _MISSING), ('dataset', 'extra'),
])
def test_provenance_revalidated_at_client_and_delivery(monkeypatch, field, value):
    from azazel_nexus.local_advisory import read_knowledge_refs
    from azazel_nexus_runtime import knowledge_client

    ref = KnowledgeRef('T1110', 'Brute Force', '', 'T1110', 'sha256:' + 'a' * 64,
                       'static', 'knowledge_lite', 5, 'verified', NOW, 'MITRE ATT&CK technique')
    row = {**asdict(ref), field: value}
    if value is _MISSING:
        del row[field]
    monkeypatch.setattr(knowledge_client, '_exchange',
                        lambda *a, **k: {'refs': [row], 'reason_code': 'available'})
    with pytest.raises(knowledge_client.KnowledgeUnavailable):
        knowledge_client.lookup_context(('T1110',))
    with pytest.raises(ValueError, match='invalid_knowledge_refs'):
        read_knowledge_refs([row])


def test_client_transport_uses_one_budget_for_connect_send_and_silent_recv(monkeypatch):
    from types import SimpleNamespace

    from azazel_nexus_runtime import knowledge_client, mio_socket_client

    clock = [10.0]
    timeouts = []
    class SilentSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, timeout):
            timeouts.append(timeout)
        def connect(self, path):
            clock[0] += 0.01
        def sendall(self, data):
            clock[0] += 0.02
        def shutdown(self, mode):
            pass
        def recv(self, size):
            clock[0] += timeouts[-1]
            raise TimeoutError('silent peer')
    monkeypatch.setattr(mio_socket_client.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(mio_socket_client.pwd, 'getpwnam',
                        lambda _: SimpleNamespace(pw_uid=111))
    monkeypatch.setattr(mio_socket_client.grp, 'getgrnam',
                        lambda _: SimpleNamespace(gr_gid=222))
    monkeypatch.setattr(mio_socket_client, 'verify_socket', lambda *a, **k: None)
    monkeypatch.setattr(mio_socket_client, 'peer_credentials', lambda _: (1, 111, 222))
    monkeypatch.setattr(mio_socket_client.socket, 'socket', lambda *a: SilentSocket())
    with pytest.raises(knowledge_client.KnowledgeUnavailable):
        knowledge_client.lookup_context(('T1110',), deadline_s=0.05)
    assert timeouts == pytest.approx([0.05, 0.04, 0.02])
    assert clock[0] == pytest.approx(10.05)


@pytest.mark.parametrize("watermark", ["6", None, "abc", "-1", "9" * 100, "directory", "symlink"])
def test_lookup_refuses_untrusted_watermark(node, watermark):
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}])
    path = node[1] / "state/watermark"
    path.unlink()
    if watermark == "directory":
        path.mkdir()
    elif watermark == "symlink":
        path.symlink_to(node[1] / "inbox/bundle.tar.gz")
    elif watermark is not None:
        path.write_text(watermark)
    result = reading(node)
    assert result.reason_code == "state_untrusted"
    assert result.refs == ()


@pytest.mark.parametrize("floor", ["4", "5"])
def test_lookup_serves_equal_or_newer_than_watermark(node, floor):
    admit_rows(node, [{"technique_id": "T1110", "name": "Brute Force"}])
    (node[1] / "state/watermark").write_text(floor)
    assert reading(node).reason_code == "available"


@pytest.mark.parametrize("text", ["[" * 200000, "<" * 200000, "[a](" * 50000, "&amp;" * 40000])
def test_cleaning_hostile_producer_text_is_bounded(text):
    import time

    from azazel_nexus import lite_import

    manifest = {"profile": {"provenance": {"attack_technique": {"dataset": {"citation": text}}}}}
    began = time.monotonic()
    lite_import._plain_text(text, 240)
    citation = lite_import._dataset_citation(manifest, "tables/attack_technique.jsonl")
    assert time.monotonic() - began < 1.0
    assert len(citation) <= 160


@pytest.mark.parametrize("value", [None, 7, ["x"], {"a": 1}, b"bytes"])
def test_non_text_citation_is_empty(value):
    from azazel_nexus import lite_import

    manifest = {"profile": {"provenance": {"attack_technique": {"dataset": {"citation": value}}}}}
    assert lite_import._dataset_citation(manifest, "tables/attack_technique.jsonl") == ""
