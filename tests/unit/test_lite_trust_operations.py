"""Knowledge Lite trust maintenance on the ordinary path (ADR 0008, S-02, S-14).

* `lite_enrollment`: the first registration as one checked request -- keys,
  roles, threshold, epoch, export policies and the revocation authority --
  bound to the node's verified commissioning, refusing the published fixture
  key, a wrong binding and every threshold that no key set can meet, and
  committing with `trust.json` last so an interrupted run can be repeated.
* `lite_trust_ops`: the transactions root runs as the commissioning account,
  each recorded in auditd before anything changes; a stopped auditd refuses.
* auditd: the new `knowledge.lite.trust_*` records are `azcommission`'s only,
  and one account may hold two prefixes without gaining a third.
* The whole order -- enroll, import, repin, revoke, recover -- in one test,
  on the production code with only the audit sink, the evidence reader and
  the human's confirmation supplied by the test.

Keys are generated for each test and never written down; only public keys
reach a file.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import knowledge_lited, lite_trust_ops, runtime_paths
from azazel_nexus_runtime.auditd import EVENT_SCHEMAS, AuditService, SegmentedLedger
from azazel_nexus_runtime.auditd import REGISTRY as AUDIT_REGISTRY
from azazel_nexus_runtime.knowledge_clock_floor import ClockFloor
from azazel_nexus_runtime.lite_audit import ImportAudit
from azazel_nexus_runtime.lite_revocation_accept import REVOCATION_INPUT, RevocationAcceptance
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.protocol import Refusal, RequestRefused
from azazel_nexus_runtime.repin_confirmation import ANCHOR_FILENAME
from azazel_nexus_runtime.transport import Request
from nacl.signing import SigningKey
from test_knowledge_lite_operator_entry import _bundle, _statement

from azazel_nexus import lab_keys
from azazel_nexus.layout import create_layout
from azazel_nexus.lite_bundle import read_anchors
from azazel_nexus.lite_enrollment import (
    ENROLLMENT_FILENAME,
    ENROLLMENT_REFUSAL_CODES,
    ENROLLMENT_SCHEMA,
    EnrollmentRefused,
    decode_enrollment,
    enroll,
    render_anchors,
)
from azazel_nexus.lite_import import CommissionedTrust, status_summary
from azazel_nexus.lite_trust import TrustStore

NOW = "2026-10-18T00:00:00Z"
BINDING = "sha256:" + "b" * 64
FIXTURE = next(iter(lab_keys.PUBLIC_FIXTURE_KEYS)).hex()
ROOT = PrincipalPolicy(operator_gid=None, service_uids=frozenset()).classify(0, 0, 42)


def _key() -> SigningKey:
    return SigningKey.generate()


def _public(key: SigningKey) -> str:
    return key.verify_key.encode().hex()


def _request(bundle_keys, revokers, **fields) -> dict:
    document = {
        "schema": ENROLLMENT_SCHEMA,
        "commissioning_digest": BINDING,
        "keys": {f"site-bundle-{i}" if i else "site-bundle": _public(key)
                 for i, key in enumerate(bundle_keys)},
        "threshold": 1,
        "revocation_policy": {
            "keys": {f"site-revoker-{i}": _public(key) for i, key in enumerate(revokers)},
            "key_roles": {f"site-revoker-{i}": "revocation-signing" for i in range(len(revokers))},
            "threshold": 1, "generation": 1,
        },
    }
    document.update(fields)
    return document


def _raw(document) -> bytes:
    return json.dumps(document, sort_keys=True).encode()


# -- decoding: what a request may say ------------------------------------------


def test_a_complete_request_renders_the_anchor_the_reader_reads():
    bundle, other, revoker = _key(), _key(), _key()
    document = _request([bundle, other], [revoker], threshold=2,
                        key_roles={"site-bundle": "bundle-signer", "site-bundle-1": "bundle-signer"},
                        required_signer_role="bundle-signer", minimum_security_epoch=3,
                        accepted_export_policy_digests=["sha256:" + "e" * 64])
    request = decode_enrollment(_raw(document))
    assert request.threshold == 2 and request.usable_keys == 2
    text = render_anchors(request).decode()
    assert "threshold = 2" in text and "minimum_security_epoch = 3" in text
    assert f'"site-bundle" = "{_public(bundle)}"' in text
    assert request.digest == "sha256:" + hashlib.sha256(_raw(document)).hexdigest()


@pytest.mark.parametrize("threshold", [0, -1, True, False, "1", 1.0, None, 3])
def test_a_threshold_no_key_set_can_meet_is_refused(threshold):
    document = _request([_key(), _key()], [_key()], threshold=threshold)
    with pytest.raises(EnrollmentRefused) as refused:
        decode_enrollment(_raw(document))
    assert refused.value.code == "threshold_invalid"


def test_the_threshold_counts_only_the_keys_holding_the_required_role():
    document = _request([_key(), _key()], [_key()], threshold=2,
                        key_roles={"site-bundle": "bundle-signer", "site-bundle-1": "other"},
                        required_signer_role="bundle-signer")
    with pytest.raises(EnrollmentRefused) as refused:
        decode_enrollment(_raw(document))
    assert refused.value.code == "threshold_invalid"
    document["threshold"] = 1
    assert decode_enrollment(_raw(document)).usable_keys == 1


@pytest.mark.parametrize("threshold", [0, 2, True])
def test_a_revocation_threshold_no_key_set_can_meet_is_refused(threshold):
    document = _request([_key()], [_key()])
    document["revocation_policy"]["threshold"] = threshold
    with pytest.raises(EnrollmentRefused) as refused:
        decode_enrollment(_raw(document))
    assert refused.value.code == "threshold_invalid"


@pytest.mark.parametrize("case", ["same_material", "same_id", "bundle_role", "revoker_role"])
def test_one_key_never_holds_both_roles(case):
    shared = _key()
    document = _request([shared], [_key()])
    if case == "same_material":
        document["revocation_policy"]["keys"]["site-revoker-0"] = _public(shared)
    elif case == "same_id":
        document["revocation_policy"]["keys"] = {"site-bundle": _public(_key())}
        document["revocation_policy"]["key_roles"] = {"site-bundle": "revocation-signing"}
    elif case == "bundle_role":
        document["key_roles"] = {"site-bundle": "revocation-signing"}
    else:
        document["revocation_policy"]["key_roles"]["site-revoker-0"] = "bundle-signing"
    with pytest.raises(EnrollmentRefused) as refused:
        decode_enrollment(_raw(document))
    assert refused.value.code == "role_conflict"


@pytest.mark.parametrize("where", ["bundle", "revocation"])
def test_the_published_fixture_key_is_refused_in_either_role(where):
    document = _request([_key()], [_key()])
    if where == "bundle":
        document["keys"]["site-bundle"] = FIXTURE
    else:
        document["revocation_policy"]["keys"]["site-revoker-0"] = FIXTURE
    with pytest.raises(EnrollmentRefused) as refused:
        decode_enrollment(_raw(document))
    assert refused.value.code == "public_fixture_key"


def test_the_fixture_key_is_accepted_only_on_a_marked_lab_host(lab_host):
    document = _request([_key()], [_key()])
    document["keys"]["site-bundle"] = FIXTURE
    assert decode_enrollment(_raw(document)).keys["site-bundle"].hex() == FIXTURE


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema="azazel-nexus/lite-enrollment/v2"),
    lambda d: d.update(extra=True),
    lambda d: d.update(sealed=True),
    lambda d: d.update(sealed=False),
    lambda d: d.pop("revocation_policy"),
    lambda d: d.update(commissioning_digest="sha256:short"),
    lambda d: d.update(keys={}),
    lambda d: d.update(keys={"bad id": "00" * 32}),
    lambda d: d["keys"].update({"site-bundle": "AA" * 32}),
    lambda d: d["keys"].update({"copy": d["keys"]["site-bundle"]}),
    lambda d: d.update(minimum_security_epoch=-1),
    lambda d: d.update(minimum_security_epoch=True),
    lambda d: d.update(accepted_export_policy_digests=[]),
    lambda d: d.update(key_roles={"unknown-key": "bundle-signer"}),
    lambda d: d.update(required_signer_role='bad"role'),
    lambda d: d["revocation_policy"].update(generation=0),
    lambda d: d["revocation_policy"].update(extra=1),
])
def test_anything_outside_the_closed_shape_is_refused(mutate):
    document = _request([_key()], [_key()])
    mutate(document)
    with pytest.raises(EnrollmentRefused):
        decode_enrollment(_raw(document))


def test_duplicate_fields_are_refused():
    raw = _raw(_request([_key()], [_key()]))
    with pytest.raises(EnrollmentRefused) as refused:
        decode_enrollment(raw[:-1] + b', "threshold": 1}')
    assert refused.value.code == "request_invalid"


# -- writing: one commit point --------------------------------------------------


@pytest.fixture
def trust_root(tmp_path):
    root = tmp_path / "lite-trust"
    root.mkdir(mode=0o2750)
    root.chmod(0o2750)
    return root


def _modes(root):
    return {str(p.relative_to(root)): stat.S_IMODE(p.stat().st_mode)
            for p in sorted(root.rglob("*"))}


def test_an_enrollment_makes_a_root_every_reader_reads(trust_root):
    bundle, revoker = _key(), _key()
    request = decode_enrollment(_raw(_request([bundle], [revoker])))
    outcome = enroll(trust_root, request, commissioning_digest=BINDING, enrolled_at=NOW,
                     actor="root")
    assert (outcome.bundle_keys, outcome.threshold, outcome.revocation_keys) == (1, 1, 1)
    assert _modes(trust_root) == {"revocation-policy.json": 0o640, "trust": 0o2750,
                                  "trust.json": 0o640, "trust/anchors.toml": 0o640}
    snapshot = CommissionedTrust(trust_root).snapshot()
    assert snapshot.keys == (bundle.verify_key.encode(),)
    assert TrustStore(trust_root).keys(commissioning_digest=BINDING) == snapshot.keys
    # The reader moves from trust_unreadable straight to no_bundle.
    store = trust_root.parent / "knowledge"
    store.mkdir()
    assert status_summary(root=store, trust_root=trust_root,
                          query_as_of=NOW)["reason_code"] == "no_bundle"


@pytest.mark.parametrize("given, code", [(None, "evidence_unavailable"),
                                         ("sha256:" + "c" * 64, "binding_mismatch")])
def test_no_trust_is_written_without_the_nodes_own_commissioning(trust_root, given, code):
    request = decode_enrollment(_raw(_request([_key()], [_key()])))
    with pytest.raises(EnrollmentRefused) as refused:
        enroll(trust_root, request, commissioning_digest=given, enrolled_at=NOW, actor="root")
    assert refused.value.code == code
    assert list(trust_root.iterdir()) == []


def test_an_enrolled_root_is_never_enrolled_again(trust_root):
    first = decode_enrollment(_raw(_request([_key()], [_key()])))
    enroll(trust_root, first, commissioning_digest=BINDING, enrolled_at=NOW, actor="root")
    before = {p: p.read_bytes() for p in trust_root.rglob("*") if p.is_file()}
    second = decode_enrollment(_raw(_request([_key()], [_key()])))
    with pytest.raises(EnrollmentRefused) as refused:
        enroll(trust_root, second, commissioning_digest=BINDING, enrolled_at=NOW, actor="root")
    assert refused.value.code == "already_enrolled"
    assert {p: p.read_bytes() for p in trust_root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("name", ["revocations.signed", "trust-generations", "trust-reserved"])
def test_a_root_holding_anything_but_enrollment_residue_is_refused(trust_root, name):
    (trust_root / name).write_bytes(b"x")
    request = decode_enrollment(_raw(_request([_key()], [_key()])))
    with pytest.raises(EnrollmentRefused) as refused:
        enroll(trust_root, request, commissioning_digest=BINDING, enrolled_at=NOW, actor="root")
    assert refused.value.code == "trust_root_not_empty"


def test_an_interrupted_enrollment_is_completed_by_running_it_again(trust_root, monkeypatch):
    """Killed before the commit: residue nobody trusts, then the same request completes."""
    from azazel_nexus import lite_enrollment

    request = decode_enrollment(_raw(_request([_key()], [_key()])))
    real = lite_enrollment._write

    def crash_at_commit(path, data):
        if path.name == "trust.json":
            raise OSError("power lost")
        real(path, data)
    monkeypatch.setattr(lite_enrollment, "_write", crash_at_commit)
    with pytest.raises(EnrollmentRefused) as refused:
        enroll(trust_root, request, commissioning_digest=BINDING, enrolled_at=NOW, actor="root")
    assert refused.value.code == "write_failed"
    assert sorted(p.name for p in trust_root.iterdir()) == ["revocation-policy.json", "trust"]
    assert not TrustStore(trust_root).is_pinned()
    store = trust_root.parent / "knowledge"
    store.mkdir()
    assert status_summary(root=store, trust_root=trust_root,
                          query_as_of=NOW)["reason_code"] == "trust_unreadable"
    (trust_root / ".enroll-leftover").write_bytes(b"partial")
    monkeypatch.setattr(lite_enrollment, "_write", real)
    enroll(trust_root, request, commissioning_digest=BINDING, enrolled_at=NOW, actor="root")
    assert not (trust_root / ".enroll-leftover").exists()
    assert status_summary(root=store, trust_root=trust_root,
                          query_as_of=NOW)["reason_code"] == "no_bundle"


# -- the transaction: audit first, then the change -----------------------------


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    create_layout(tmp_path)
    commissioning = tmp_path / "etc/azazel/commissioning"
    events: list[dict] = []
    keys = SimpleNamespace(bundle=_key(), revoker=_key(), next_bundle=_key())
    store = tmp_path / "var/lib/azazel/knowledge"
    (store / "inbox").mkdir(parents=True, exist_ok=True)
    floor = runtime_paths.knowledge_state_dir()
    floor.chmod(0o700)
    service = knowledge_lited.KnowledgeLiteService(
        root=store, trust_root=runtime_paths.lite_trust_root(), clock_floor=ClockFloor(floor),
        now=lambda: NOW, import_audit=lambda: ImportAudit(append=events.append))
    return SimpleNamespace(root=tmp_path, commissioning=commissioning, events=events,
                           keys=keys, store=store, service=service,
                           trust=runtime_paths.lite_trust_root(),
                           lock=runtime_paths.state_dir() / "commission")


def _place_request(node, document) -> str:
    raw = _raw(document)
    (node.commissioning / ENROLLMENT_FILENAME).write_bytes(raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _enroll(node, digest, *, commissioning_digest=BINDING, append=None):
    return lite_trust_ops.enroll_transaction(
        confirmed_digest=digest, commissioning_digest=commissioning_digest,
        commissioning_dir=node.commissioning, trust_root=node.trust, lock_dir=node.lock,
        append=append or node.events.append, now=lambda: NOW)


def test_the_request_is_recorded_before_anything_is_written(node):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    seen = []

    def append(event):
        seen.append((event["event_type"], sorted(p.name for p in node.trust.iterdir())))
        node.events.append(event)
    result = _enroll(node, digest, append=append)
    assert result["enrolled"] is True and result["audit_complete"] is True
    assert seen[0] == ("knowledge.lite.trust_enroll_requested", [])
    assert seen[1][0] == "knowledge.lite.trust_enrolled"
    assert "trust.json" in seen[1][1]
    for event in node.events:
        schema = {a.name: a for a in EVENT_SCHEMAS[event["event_type"]]}
        assert set(event) - {"event_type"} == set(schema)
        for name, argument in schema.items():
            argument.coerce(event[name])


def test_a_stopped_auditd_refuses_before_any_change(node):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))

    def unavailable(event):
        raise ConnectionRefusedError("no audit-submit listener")
    result = _enroll(node, digest, append=unavailable)
    assert (result["enrolled"], result["code"], result["audit_complete"]) == (
        False, "audit_unavailable", False)
    assert list(node.trust.iterdir()) == []


def test_a_request_changed_after_confirmation_is_refused_and_recorded(node):
    confirmed = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    _place_request(node, _request([_key()], [node.keys.revoker]))
    result = _enroll(node, confirmed)
    assert (result["enrolled"], result["code"]) == (False, "request_changed")
    assert list(node.trust.iterdir()) == []
    assert [e["event_type"] for e in node.events] == [
        "knowledge.lite.trust_enroll_requested", "knowledge.lite.trust_enroll_refused"]
    assert node.events[0]["request_digest"] == confirmed


@pytest.mark.parametrize("given, code", [(None, "evidence_unavailable"),
                                         ("sha256:" + "c" * 64, "binding_mismatch")])
def test_a_wrong_or_unverified_binding_is_recorded_and_refused(node, given, code):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    result = _enroll(node, digest, commissioning_digest=given)
    assert (result["enrolled"], result["code"]) == (False, code)
    assert node.events[-1] == {"event_type": "knowledge.lite.trust_enroll_refused",
                               "request_digest": digest, "code": code, "occurred_at": NOW}
    assert list(node.trust.iterdir()) == []


def test_a_held_lock_refuses_without_waiting(node):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    with lite_trust_ops.trust_lock(node.lock):
        result = _enroll(node, digest)
    assert result["code"] == "busy" and list(node.trust.iterdir()) == []


def test_every_refusal_code_is_auditds_vocabulary():
    schema = {a.name: a for a in EVENT_SCHEMAS["knowledge.lite.trust_enroll_refused"]}
    assert schema["code"].choices == ENROLLMENT_REFUSAL_CODES


def test_run_enroll_shows_the_binding_and_needs_the_words(node, monkeypatch, capsys):
    _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    monkeypatch.setattr(lite_trust_ops, "_is_root", lambda: True)
    asked = []

    def decline(lines):
        asked.append(lines)
        return False
    code = lite_trust_ops.run_enroll(evidence=lambda: BINDING, confirm=decline,
                                     runner=lambda work: dict(work()), append=node.events.append)
    assert code == 1 and node.events == [] and list(node.trust.iterdir()) == []
    assert "Commissioning binding: matches this node's verified commissioning" in asked[0]
    code = lite_trust_ops.run_enroll(evidence=lambda: BINDING, confirm=lambda lines: True,
                                     runner=lambda work: dict(work()), append=node.events.append)
    assert code == 0
    printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert printed["enrolled"] is True and printed["threshold"] == 1


def test_run_enroll_refuses_without_root_or_a_terminal(node, monkeypatch, capsys):
    _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert lite_trust_ops.run_enroll() == 1
    assert "runs as root" in capsys.readouterr().err
    monkeypatch.setattr(lite_trust_ops, "_is_root", lambda: True)
    assert lite_trust_ops.run_enroll(runner=pytest.fail) == 1
    assert "interactive terminal" in capsys.readouterr().err


def test_an_invalid_request_is_recorded_as_refused_without_asking(node, monkeypatch):
    document = _request([node.keys.bundle], [node.keys.revoker], threshold=0)
    digest = _place_request(node, document)
    monkeypatch.setattr(lite_trust_ops, "_is_root", lambda: True)
    code = lite_trust_ops.run_enroll(evidence=lambda: BINDING, confirm=pytest.fail,
                                     runner=lambda work: dict(work()), append=node.events.append)
    assert code == 1
    assert node.events[-1]["code"] == "threshold_invalid"
    assert node.events[-1]["request_digest"] == digest


# -- the whole order, in one ----------------------------------------------------


def _import(node, blob: bytes) -> dict:
    (node.store / "inbox" / "site-lite.tar.gz").write_bytes(blob)
    verb = knowledge_lited.REGISTRY.resolve("knowledge.import", ROOT)
    entry = hashlib.sha256(blob).hexdigest()
    return node.service.handle(Request(verb=verb, arguments=verb.bind({"entry_id": entry}),
                                       principal=ROOT, payload={}))


def _status(node) -> str:
    return status_summary(root=node.store, trust_root=node.trust, query_as_of=NOW)["reason_code"]


def _store_files(node) -> dict:
    return {p: p.read_bytes() for p in node.store.rglob("*")
            if p.is_file() and "inbox" not in p.parts}


def test_enroll_import_repin_revoke_and_recover(node):
    """S-14's sequence on the production code: one transaction after another."""
    assert _status(node) == "trust_unreadable"
    # 1. First enrollment, from an empty root.
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    assert _status(node) == "no_bundle"
    # 2. Import, recorded by the daemon's own audit.
    result = _import(node, _bundle(node.keys.bundle, version=5, key_id="site-bundle"))
    assert (result["outcome"], result["audit_complete"]) == ("admitted", True)
    assert _status(node) == "available"
    # 3. Key rotation: the pin and the anchor change together (repin with
    # `anchors`), so the next key verifies and the old one no longer does.
    (node.commissioning / ANCHOR_FILENAME).write_text(json.dumps({
        "keys": [_public(node.keys.next_bundle)],
        "anchors": {"keys": {"site-bundle-2": _public(node.keys.next_bundle)}, "threshold": 1},
    }))
    repinned = lite_trust_ops.repin_transaction(
        "rotation", principal=ROOT, commissioning_dir=node.commissioning,
        snapshot_dir=node.lock, ask=lambda challenge: challenge["confirmation_words"],
        append=node.events.append, now=lambda: NOW)
    assert (repinned["promoted"], repinned["generation"]) == (True, 1)
    assert (node.trust / "trust-generations/1.anchors.toml").exists()
    assert _status(node) != "available"
    result = _import(node, _bundle(node.keys.next_bundle, version=6, key_id="site-bundle-2"))
    assert (result["outcome"], result["bundle_version"]) == ("admitted", 6)
    assert _status(node) == "available"
    # 4. Revocation of that generation, by the revocation authority enrolled
    # in step 1 and carried across the repin.
    (node.commissioning / REVOCATION_INPUT).write_bytes(
        _statement(node.keys.revoker, sequence=1, revoked_generations=frozenset({6})))
    accepted = lite_trust_ops.revocation_transaction(
        principal=ROOT, commissioning_dir=node.commissioning, lock_dir=node.lock,
        acceptance=RevocationAcceptance(commissioning_dir=node.commissioning,
                                        append=node.events.append, now=lambda: NOW))
    assert (accepted["accepted"], accepted["sequence"]) == (True, 1)
    assert _status(node) == "revoked"
    # 5. Recovery. auditd stops: the next import is refused before any change.
    before = _store_files(node)

    def stopped(event):
        raise ConnectionRefusedError("auditd stopped")
    node.service.import_audit = lambda: ImportAudit(append=stopped)
    replacement = _bundle(node.keys.next_bundle, version=7, key_id="site-bundle-2")
    refused = _import(node, replacement)
    assert (refused["outcome"], refused["refused"]) == ("refused", "audit_unavailable")
    assert _store_files(node) == before and _status(node) == "revoked"
    # auditd is back: the same entry is imported and serves again.
    node.service.import_audit = lambda: ImportAudit(append=node.events.append)
    result = _import(node, replacement)
    assert (result["outcome"], result["bundle_version"]) == ("admitted", 7)
    assert _status(node) == "available"
    kinds = [e["event_type"] for e in node.events]
    assert kinds[:2] == ["knowledge.lite.trust_enroll_requested", "knowledge.lite.trust_enrolled"]
    assert kinds.index("knowledge.lite.trust_repin_requested") < kinds.index(
        "knowledge.lite.trust_repin_promoted")
    assert kinds.index("knowledge.lite.revocation_requested") < kinds.index(
        "knowledge.lite.revocation_accepted")
    # The repin record is matched with the commissioning ledger's by generation.
    from azazel_nexus.audit import AuditLedger
    ledger = [entry.event for entry in AuditLedger(runtime_paths.commission_ledger_path())]
    promoted = next(e for e in node.events if e["event_type"] == "knowledge.lite.trust_repin_promoted")
    assert {e["generation"] for e in ledger if e["event_type"] == "trust.repin.promoted"} == {
        promoted["generation"]}


def _repin(node, document):
    (node.commissioning / ANCHOR_FILENAME).write_text(json.dumps(document))
    return lite_trust_ops.repin_transaction(
        "rotation", principal=ROOT, commissioning_dir=node.commissioning,
        snapshot_dir=node.lock, ask=lambda challenge: challenge["confirmation_words"],
        append=node.events.append, now=lambda: NOW)


def test_a_later_repin_without_an_anchor_keeps_the_one_in_force(node):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    public = _public(node.keys.next_bundle)
    assert _repin(node, {"keys": [public],
                         "anchors": {"keys": {"site-bundle-2": public}, "threshold": 1}}
                  )["generation"] == 1
    _import(node, _bundle(node.keys.next_bundle, version=6, key_id="site-bundle-2"))
    assert _status(node) == "available"
    # A policy-only change: the anchor of generation 1 stays in force.
    other = _key()
    result = _repin(node, {"keys": [public], "revocation_policy": {
        "keys": {"site-revoker-next": _public(other)},
        "key_roles": {"site-revoker-next": "revocation-signing"},
        "threshold": 1, "generation": 2}})
    assert (result["promoted"], result["generation"]) == (True, 2)
    assert (node.trust / "trust-generations/2.anchors.toml").read_bytes() == (
        node.trust / "trust-generations/1.anchors.toml").read_bytes()
    assert _status(node) == "available"


@pytest.mark.parametrize("generation_anchor", [False, True])
@pytest.mark.parametrize("seal_field", [{}, {"sealed": True}])
def test_a_repin_replacement_preserves_sealing_until_explicit_audited_unseal(
        node, generation_anchor, seal_field):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    if generation_anchor:
        public = _public(node.keys.next_bundle)
        assert _repin(node, {"keys": [public], "anchors": {
            "keys": {"next": public}, "threshold": 1}})["promoted"] is True
    trust = TrustStore(node.trust)
    old_path = trust.anchors_path
    old_path.write_bytes(b"sealed = true\n" + old_path.read_bytes())
    # A rotated key and replacement anchor cannot implicitly clear the seal,
    # whether the current anchor is initial or generation-bound (R393B-02).
    replacement = _key()
    public = _public(replacement)
    anchor = {"keys": {"replacement": public}, "threshold": 1}
    result = _repin(node, {"keys": [public], "anchors": {**anchor, **seal_field}})
    assert result["promoted"] is True
    sealed_path = trust.anchors_path
    assert sealed_path != old_path
    assert read_anchors(sealed_path).sealed is True
    refused = _import(node, _bundle(replacement, version=6, key_id="replacement"))
    assert (refused["outcome"], refused["code"]) == (
        "quarantined", "BUNDLE_ANCHORS_SEALED")
    assert _status(node) != "available"
    # A policy-only repin keeps that active generation's seal as well.
    revoker = _key()
    assert _repin(node, {"keys": [public], "revocation_policy": {
        "keys": {"new-revoker": _public(revoker)},
        "key_roles": {"new-revoker": "revocation-signing"},
        "threshold": 1, "generation": 2}})["promoted"] is True
    assert trust.anchors_path.read_bytes() == sealed_path.read_bytes()
    # Existing confirmation and both ledgers still authorize the explicit
    # recovery; no separate permission boolean is introduced.
    result = _repin(node, {"keys": [public], "anchors": {**anchor, "sealed": False}})
    assert result["promoted"] is True
    assert read_anchors(trust.anchors_path).sealed is False
    assert _import(node, _bundle(replacement, version=7, key_id="replacement"))[
        "outcome"] == "admitted"
    assert _status(node) == "available"
    from azazel_nexus.audit import AuditLedger
    ledger = AuditLedger(runtime_paths.commission_ledger_path())
    assert any(entry.event["event_type"] == "trust.repin.promoted"
               and entry.event["generation"] == result["generation"] for entry in ledger)
    assert any(event["event_type"] == "knowledge.lite.trust_repin_promoted"
               and event["generation"] == result["generation"] for event in node.events)


@pytest.mark.parametrize("field", [
    {"sealed": None}, {"sealed": 0}, {"sealed": 1}, {"sealed": "true"},
    {"sealed": []}, {"revoked": []}, {"seal": True}, {"extra": True},
])
def test_a_repin_refuses_invalid_or_unsupported_anchor_policy_without_unsealing(node, field):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    trust = TrustStore(node.trust)
    path = trust.anchors_path
    path.write_bytes(b"sealed = true\n" + path.read_bytes())
    before = path.read_bytes()
    public = _public(node.keys.bundle)
    result = _repin(node, {"keys": [public], "anchors": {
        "keys": {"site-bundle": public}, "threshold": 1, **field}})
    assert (result["promoted"], result["code"]) == (False, "refused")
    assert trust.current_generation() == 0
    assert path.read_bytes() == before
    assert read_anchors(path).sealed is True


@pytest.mark.parametrize("missing", [False, True])
def test_explicit_unseal_can_recover_an_unreadable_anchor_but_omission_cannot(node, missing):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    trust = TrustStore(node.trust)
    if missing:
        trust.anchors_path.unlink()
    else:
        trust.anchors_path.write_text("sealed = 'invalid'\n")
    public = _public(node.keys.bundle)
    anchor = {"keys": {"site-bundle": public}, "threshold": 1}
    assert _repin(node, {"keys": [public], "anchors": anchor})["promoted"] is False
    assert trust.current_generation() == 0
    result = _repin(node, {"keys": [public], "anchors": {**anchor, "sealed": False}})
    assert result["promoted"] is True
    assert read_anchors(trust.anchors_path).sealed is False
    assert _import(node, _bundle(node.keys.bundle, key_id="site-bundle"))[
        "outcome"] == "admitted"


def test_a_key_change_that_keeps_an_anchor_it_cannot_meet_is_refused(node):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    (node.commissioning / ANCHOR_FILENAME).write_text(json.dumps(
        {"keys": [_public(node.keys.next_bundle)]}))
    result = lite_trust_ops.repin_transaction(
        "rotation", principal=ROOT, commissioning_dir=node.commissioning,
        snapshot_dir=node.lock, ask=lambda challenge: challenge["confirmation_words"],
        append=node.events.append, now=lambda: NOW)
    assert (result["promoted"], result["code"]) == (False, "refused")
    assert TrustStore(node.trust).current_generation() == 0
    assert _status(node) == "no_bundle"


@pytest.mark.parametrize("anchors", [
    {"keys": {"other": "OTHER"}, "threshold": 1},
    {"keys": {"k": "PLACEHOLDER", "other": "OTHER"}, "threshold": 1},
    {"keys": {"k": "PLACEHOLDER"}, "threshold": 0},
    {"keys": {"k": "PLACEHOLDER"}, "threshold": 2},
])
def test_a_repin_anchor_must_name_the_proposed_keys_with_a_meetable_threshold(node, anchors):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    public = _public(node.keys.next_bundle)
    anchors = json.loads(json.dumps(anchors).replace("PLACEHOLDER", public)
                         .replace("OTHER", _public(_key())))
    (node.commissioning / ANCHOR_FILENAME).write_text(json.dumps(
        {"keys": [public], "anchors": anchors}))
    result = lite_trust_ops.repin_transaction(
        "rotation", principal=ROOT, commissioning_dir=node.commissioning,
        snapshot_dir=node.lock, ask=lambda challenge: challenge["confirmation_words"],
        append=node.events.append, now=lambda: NOW)
    assert result["promoted"] is False
    assert TrustStore(node.trust).current_generation() == 0


# -- auditd: the commissioning account's two prefixes ---------------------------


@pytest.fixture
def auditd(tmp_path):
    (tmp_path / "ledger").mkdir()
    service = AuditService(SegmentedLedger(tmp_path / "ledger"))
    service.start()
    service._bound_writer_uids = {"knowledge.lite.import_": 4444,
                                  "knowledge.lite.revocation_": 5555,
                                  "knowledge.lite.trust_": 5555}
    return service


def _append(service, principal, event_type, payload):
    verb = AUDIT_REGISTRY.resolve("audit.append", principal)
    return service.handle(Request(verb=verb, arguments=verb.bind({"event_type": event_type}),
                                  principal=principal, payload=payload))


TRUST_EVENT = ("knowledge.lite.trust_enroll_requested",
               {"request_digest": "sha256:" + "a" * 64, "occurred_at": NOW})
REVOCATION_EVENT = ("knowledge.lite.revocation_requested",
                    {"statement_digest": "sha256:" + "c" * 64, "occurred_at": NOW})
IMPORT_EVENT = ("knowledge.lite.import_started", {"entry_id": "a" * 64, "occurred_at": NOW})


def test_the_commissioning_account_writes_both_of_its_prefixes_and_nothing_else(auditd):
    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({4444, 5555, 6666}))
    commission = policy.classify(5555, 5555, 9)
    for event_type, payload in (TRUST_EVENT, REVOCATION_EVENT):
        assert set(_append(auditd, commission, event_type, payload)) == {"sequence", "event_hash"}
    with pytest.raises(RequestRefused) as refused:
        _append(auditd, commission, *IMPORT_EVENT)
    assert refused.value.refusal is Refusal.PRINCIPAL_DENIED
    for principal in (policy.classify(4444, 4444, 9), policy.classify(6666, 6666, 9),
                      policy.classify(0, 0, 9)):
        with pytest.raises(RequestRefused) as refused:
            _append(auditd, principal, *TRUST_EVENT)
        assert refused.value.refusal is Refusal.PRINCIPAL_DENIED


def test_trust_records_are_bound_to_the_account_the_transaction_becomes():
    from azazel_nexus_runtime.auditd import BOUND_WRITERS

    assert BOUND_WRITERS["knowledge.lite.trust_"] == lite_trust_ops.COMMISSION_ACCOUNT
    assert BOUND_WRITERS["knowledge.lite.revocation_"] == lite_trust_ops.COMMISSION_ACCOUNT
    assert BOUND_WRITERS["knowledge.lite.import_"] == "azknowledge"


def test_a_bound_writer_may_not_record_an_unbound_type(auditd):
    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({5555, 6666}))
    unbound = next(name for name in AUDIT_REGISTRY.resolve(
        "audit.append", policy.classify(6666, 6666, 9)).arguments[0].choices
        if not name.startswith(("knowledge.lite.", "edge.incident.")))
    payload = {a.name: _sample(a) for a in EVENT_SCHEMAS[unbound]}
    # An unbound account may (it is no Lite writer)...
    assert _append(auditd, policy.classify(6666, 6666, 9), unbound, payload)
    # ...the commissioning account may not: it reaches the chain for its own
    # Lite transitions only.
    with pytest.raises(RequestRefused) as refused:
        _append(auditd, policy.classify(5555, 5555, 9), unbound, payload)
    assert refused.value.refusal is Refusal.PRINCIPAL_DENIED


def test_a_missing_commissioning_account_means_nobody_writes_trust_records(auditd):
    auditd._bound_writer_uids["knowledge.lite.trust_"] = None
    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({5555}))
    with pytest.raises(RequestRefused):
        _append(auditd, policy.classify(5555, 5555, 9), *TRUST_EVENT)
    # Still writes its other prefix.
    assert _append(auditd, policy.classify(5555, 5555, 9), *REVOCATION_EVENT)


def test_a_second_auditd_refuses_the_chain_before_reading_it(tmp_path):
    from azazel_nexus_runtime import auditd as module

    (tmp_path / "ledger").mkdir()
    held = module.hold_instance_lock(tmp_path / "ledger")
    try:
        with pytest.raises(module.SecondWriterRefused):
            module.hold_instance_lock(tmp_path / "ledger")
    finally:
        os.close(held)
    os.close(module.hold_instance_lock(tmp_path / "ledger"))
    assert list((tmp_path / "ledger").iterdir()) == []


def test_no_schema_names_a_field_the_daemon_assigns():
    from azazel_nexus_runtime.auditd import ASSIGNED_BY_THE_DAEMON

    clashes = {event_type: [a.name for a in schema if a.name in ASSIGNED_BY_THE_DAEMON]
               for event_type, schema in EVENT_SCHEMAS.items()}
    assert {k: v for k, v in clashes.items() if v} == {}


def _sample(argument):
    from azazel_nexus_runtime.protocol import ArgumentKind

    if argument.kind is ArgumentKind.ENUM:
        return argument.choices[0]
    return {ArgumentKind.DIGEST: "sha256:" + "d" * 64, ArgumentKind.TIMESTAMP: NOW,
            ArgumentKind.ORDINAL: 1, ArgumentKind.IDENTIFIER: "a" * 64}[argument.kind]


def test_every_lite_schema_can_be_appended_by_its_writer(auditd):
    """Each record a Lite writer sends reaches the chain (the accepted
    revocation's `sequence` field once made every one of them refused)."""
    writers = {"knowledge.lite.import_": 4444, "knowledge.lite.revocation_": 5555,
               "knowledge.lite.trust_": 5555}
    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({4444, 5555}))
    for event_type, schema in EVENT_SCHEMAS.items():
        prefix = next((p for p in writers if event_type.startswith(p)), None)
        if prefix is None:
            continue
        payload = {argument.name: _sample(argument) for argument in schema}
        writer = policy.classify(writers[prefix], writers[prefix], 9)
        assert set(_append(auditd, writer, event_type, payload)) == {"sequence", "event_hash"}


def test_an_accepted_list_record_reaches_auditd(tmp_path, auditd, monkeypatch):
    """What `RevocationAcceptance` sends is appended, not refused."""
    import azazel_nexus.revocation as revocation
    from azazel_nexus_runtime import lite_revocation_accept

    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({5555}))
    writer = policy.classify(5555, 5555, 9)

    def append(event):
        _append(auditd, writer, event["event_type"],
                {k: v for k, v in event.items() if k != "event_type"})

    class Accepted:
        sequence, generation = 3, 1
        revoked_digests = revoked_generations = revoked_keys = frozenset()

    (tmp_path / REVOCATION_INPUT).write_bytes(b"x" * 80)
    acceptance = lite_revocation_accept.RevocationAcceptance(
        commissioning_dir=tmp_path, accept=lambda blob: Accepted(), append=append,
        now=lambda: NOW)
    monkeypatch.setattr(revocation, "parse_signed", lambda blob: None)
    result = acceptance.accept(ROOT, REVOCATION_INPUT)
    assert result == {"accepted": True, "code": None, "sequence": 3, "audit_complete": True}
    kinds = [entry.event["event_type"] for entry in auditd.ledger]
    assert kinds == ["knowledge.lite.revocation_requested", "knowledge.lite.revocation_accepted"]


# -- review R390-01: a kept anchor counts what the verifier counts --------------


def test_a_kept_anchor_whose_required_role_no_pinned_key_holds_is_refused(node):
    """A holds the required role, B does not; repinning to B alone keeps an
    anchor nothing can meet, so it is refused before the pointer moves."""
    a, b = node.keys.bundle, node.keys.next_bundle
    document = _request([a, b], [node.keys.revoker], threshold=1,
                        key_roles={"site-bundle": "bundle-signer", "site-bundle-1": "other"},
                        required_signer_role="bundle-signer")
    assert _enroll(node, _place_request(node, document))["enrolled"] is True
    result = _import(node, _bundle(a, version=5, key_id="site-bundle"))
    assert result["outcome"] == "admitted" and _status(node) == "available"
    refused = _repin(node, {"keys": [_public(b)]})
    assert (refused["promoted"], refused["code"]) == (False, "refused")
    assert TrustStore(node.trust).current_generation() == 0
    assert not (node.trust / "trust-current").exists()
    assert _status(node) == "available"
    # The role holder alone is fine.
    assert _repin(node, {"keys": [_public(a)]})["promoted"] is True


def test_a_kept_anchor_whose_only_pinned_key_it_revokes_is_refused(tmp_path):
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.lite_trust import RepinConfirmation as Confirmation
    from azazel_nexus.lite_trust import RepinRequest, TrustRefused

    root = tmp_path / "lite-trust"
    (root / "trust").mkdir(parents=True)
    a, b = _key(), _key()
    (root / "trust/anchors.toml").write_text(
        f'threshold = 1\nrevoked = ["a"]\n[keys]\n"a" = "{_public(a)}"\n"b" = "{_public(b)}"\n')
    TrustStore(root).pin([_public(a), _public(b)], commissioning_digest=BINDING,
                         pinned_at=NOW, actor="root")
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({"keys": [_public(a)]}))
    with pytest.raises(TrustRefused):
        TrustStore(root).repin(RepinRequest(anchor, "rotation", "root"),
                               confirmation=Confirmation("n", NOW),
                               ledger=AuditLedger(tmp_path / "ledger.jsonl"), now=NOW)
    assert TrustStore(root).current_generation() == 0


# -- review R390-02: past the commit point is never "refused" -------------------


def test_enrollment_committed_but_unsynced_is_reported_in_force(node, monkeypatch):
    from azazel_nexus import lite_enrollment

    real = lite_enrollment._write

    def unsynced(path, data):
        real(path, data)
        if path.name == "trust.json":
            raise OSError("directory sync failed after the rename")
    monkeypatch.setattr(lite_enrollment, "_write", unsynced)
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    result = _enroll(node, digest)
    assert (result["enrolled"], result["durability"], result["code"]) == (True, "unsynced", None)
    assert node.events[-1]["event_type"] == "knowledge.lite.trust_enrolled"
    assert node.events[-1]["durability"] == "unsynced"
    assert _status(node) == "no_bundle"


def test_enrollment_whose_commit_cannot_be_read_back_is_unknown(node, monkeypatch):
    from azazel_nexus import lite_enrollment

    real = lite_enrollment._write

    def foreign(path, data):
        if path.name == "trust.json":
            real(path, b'{"keys": []}\n')
            raise OSError("rename landed something else")
        real(path, data)
    monkeypatch.setattr(lite_enrollment, "_write", foreign)
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    result = _enroll(node, digest)
    assert (result["enrolled"], result["durability"]) == (None, "unknown")
    assert [e["event_type"] for e in node.events][-1] == "knowledge.lite.trust_enroll_unconfirmed"
    assert "knowledge.lite.trust_enroll_refused" not in [e["event_type"] for e in node.events]


@pytest.mark.parametrize("fault, expected", [
    ("before_pointer", (False, None, None, "knowledge.lite.trust_repin_refused")),
    ("after_pointer", (True, 1, "pointer_unsynced", "knowledge.lite.trust_repin_promoted")),
    ("promotion_ledger", (True, 1, "ledger_incomplete", "knowledge.lite.trust_repin_promoted")),
    ("pointer_unreadable", (None, None, "unknown", "knowledge.lite.trust_repin_unconfirmed")),
])
def test_a_repin_fault_is_reported_as_the_pointer_reads(node, monkeypatch, fault, expected):
    from azazel_nexus import audit, lite_trust

    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    real_write, real_append = lite_trust._atomic_write, audit.AuditLedger.append

    def write(path, data, **kwargs):
        if path.name == "trust-current" and fault == "before_pointer":
            raise OSError("no space before the rename")
        real_write(path, data, **kwargs)
        if path.name == "trust-current" and fault == "after_pointer":
            raise OSError("directory sync failed after the rename")
        if path.name == "trust-current" and fault == "pointer_unreadable":
            path.write_text("not a number")
            raise OSError("pointer damaged")

    def append(self, event):
        if event["event_type"] == "trust.repin.promoted" and fault == "promotion_ledger":
            raise audit.AuditUnavailable("ledger full")
        return real_append(self, event)
    monkeypatch.setattr(lite_trust, "_atomic_write", write)
    monkeypatch.setattr(audit.AuditLedger, "append", append)
    result = _repin(node, {"keys": [_public(node.keys.bundle)],
                           "anchors": {"keys": {"site-bundle": _public(node.keys.bundle)},
                                       "threshold": 1, "minimum_security_epoch": 1}})
    promoted, generation, state, record = expected
    assert (result["promoted"], result["generation"], result["state"]) == (
        promoted, generation, state)
    assert node.events[-1]["event_type"] == record
    if state in ("pointer_unsynced", "ledger_incomplete"):
        assert node.events[-1]["state"] == state and node.events[-1]["generation"] == 1
        assert TrustStore(node.trust).current_generation() == 1
    if fault == "before_pointer":
        assert TrustStore(node.trust).current_generation() == 0
    kinds = [e["event_type"] for e in node.events]
    assert kinds.count("knowledge.lite.trust_repin_requested") == 1
    if promoted is not False:
        assert "knowledge.lite.trust_repin_refused" not in kinds


@pytest.mark.parametrize("state, code", [("pointer_unsynced", 1), ("ledger_incomplete", 1),
                                         ("unknown", 1), ("complete", 0)])
def test_the_cli_never_reports_an_uncertain_repin_as_unchanged(monkeypatch, capsys, state, code):
    monkeypatch.setattr(lite_trust_ops, "_is_root", lambda: True)
    promoted = None if state == "unknown" else True
    reply = {"promoted": promoted, "code": None, "generation": None if promoted is None else 3,
             "state": state, "audit_complete": True}
    assert lite_trust_ops.run_repin("rotation", runner=lambda work: reply,
                                    ask=lambda c: None) == code
    text = capsys.readouterr()
    assert "unchanged" not in text.err
    if state == "unknown":
        assert "UNKNOWN" in text.err
    elif state != "complete":
        assert "in force but not fully recorded" in text.err


# -- review R390-03: commissiond's repin records in auditd too ------------------


def _daemon(node, append):
    from azazel_nexus_runtime import commissiond

    return commissiond.CommissionService(read_links_fn=lambda: [], append=append,
                                         now=lambda: NOW)


def _daemon_repin(service):
    from azazel_nexus_runtime import commissiond

    def call(verb, arguments):
        bound = commissiond.REGISTRY.resolve(verb, ROOT)
        return service.handle(Request(verb=bound, arguments=bound.bind(arguments),
                                      principal=ROOT, payload={}))
    challenge = call("trust.repin.challenge",
                     {"reason": "rotation", "new_anchor_file": ANCHOR_FILENAME})
    return call("trust.repin.confirm",
                {"nonce": challenge["nonce"], "echo": challenge["confirmation_words"]})


def test_the_daemon_repin_needs_auditds_receipt_first(node):
    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    (node.commissioning / ANCHOR_FILENAME).write_text(json.dumps(
        {"keys": [_public(node.keys.bundle)],
         "anchors": {"keys": {"site-bundle": _public(node.keys.bundle)}, "threshold": 1,
                     "minimum_security_epoch": 2}}))

    def unavailable(event):
        raise ConnectionRefusedError("auditd is not running")
    with pytest.raises(RequestRefused) as refused:
        _daemon_repin(_daemon(node, unavailable))
    assert refused.value.detail == "audit_unavailable"
    assert TrustStore(node.trust).current_generation() == 0
    assert not (node.trust / "trust-reserved").exists()


def test_the_daemon_repin_and_the_commission_ledger_agree_on_the_generation(node):
    from azazel_nexus.audit import AuditLedger

    digest = _place_request(node, _request([node.keys.bundle], [node.keys.revoker]))
    assert _enroll(node, digest)["enrolled"] is True
    (node.commissioning / ANCHOR_FILENAME).write_text(json.dumps(
        {"keys": [_public(node.keys.bundle)],
         "anchors": {"keys": {"site-bundle": _public(node.keys.bundle)}, "threshold": 1,
                     "minimum_security_epoch": 2}}))
    reply = _daemon_repin(_daemon(node, node.events.append))
    assert reply == {"promoted": True, "generation": 1, "state": "complete",
                     "audit_complete": True}
    kinds = [e["event_type"] for e in node.events]
    assert kinds[-2:] == ["knowledge.lite.trust_repin_requested",
                          "knowledge.lite.trust_repin_promoted"]
    ledger = [e.event for e in AuditLedger(runtime_paths.commission_ledger_path())]
    assert [e["generation"] for e in ledger if e["event_type"] == "trust.repin.promoted"] == [
        node.events[-1]["generation"]]


# -- review §3: the narrowed child inherits nothing it does not need ------------


def test_the_child_sheds_inherited_descriptors_and_environment(tmp_path, monkeypatch):
    stray = os.open(tmp_path / "secret", os.O_CREAT | os.O_RDWR, 0o600)
    os.set_inheritable(stray, True)
    monkeypatch.setenv("AZN_TEST_SECRET", "x")
    reader, writer = os.pipe()
    # One below the kept pipe end and one above it.
    above = os.open(tmp_path / "secret", os.O_RDONLY)
    assert stray < writer < above
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        try:
            lite_trust_ops._shed_inherited(writer)
            still_open = []
            for fd in (stray, above):
                try:
                    os.fstat(fd)
                    still_open.append(fd)
                except OSError:
                    pass
            os.write(writer, json.dumps({"open": bool(still_open),
                                         "env": dict(os.environ)}).encode())
        finally:
            os._exit(0)
    os.close(writer)
    seen = json.loads(os.read(reader, 65536))
    os.close(reader)
    os.waitpid(pid, 0)
    os.close(stray)
    os.close(above)
    assert seen == {"open": False, "env": lite_trust_ops.CHILD_ENVIRONMENT}


def test_a_descriptor_above_a_lowered_open_file_limit_is_closed_too(tmp_path):
    """R390b-01: the soft limit lowered after a high descriptor was opened
    must not hide it from the child's clean-up."""
    import resource

    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        status = 1
        try:
            source = os.open(tmp_path / "secret", os.O_CREAT | os.O_RDWR, 0o600)
            high = os.dup2(source, 1000, inheritable=True)
            os.close(source)
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (512, hard))
            lite_trust_ops._shed_inherited(writer)
            try:
                os.fstat(high)
                left = True
            except OSError:
                left = False
            os.write(writer, json.dumps({"left": left}).encode())
            status = 0
        finally:
            os._exit(status)
    os.close(writer)
    seen = os.read(reader, 4096)
    os.close(reader)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert json.loads(seen) == {"left": False}

