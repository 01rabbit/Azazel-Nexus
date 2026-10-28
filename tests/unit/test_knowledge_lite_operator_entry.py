"""Knowledge Lite import and revocation acceptance as operator verbs (assess-c P4).

* `knowledge.import` on `az-knowledge-lited`'s operator socket, ROOT only:
  verifies against the commissioned trust root (pin, anchors, cumulative
  revocations), records every transition for `az-auditd`, and never lets a
  revoked bundle replace the admitted one or raise the watermark.
* `trust.revocation.accept` on `az-commissiond`, ROOT only: the signed list is
  the authority, the files it writes take `trust.json`'s owner, group and mode
  (F3), and the reader then reads `revoked`, not `unverified`.
* The published fixture key is refused at registration and on every
  commissioned read, except on a marked lab host.
* auditd binds each new event type to its one writer account.

Every key here is generated during the test and never written down; only
public keys reach a file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import commissiond, knowledge_lited
from azazel_nexus_runtime.auditd import EVENT_SCHEMAS, AuditService, SegmentedLedger
from azazel_nexus_runtime.auditd import REGISTRY as AUDIT_REGISTRY
from azazel_nexus_runtime.knowledge_clock_floor import ClockFloor
from azazel_nexus_runtime.lite_audit import ImportAudit, import_event
from azazel_nexus_runtime.lite_revocation_accept import (
    REVOCATION_INPUT,
    RevocationAcceptance,
)
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.protocol import Refusal, RequestRefused
from azazel_nexus_runtime.transport import Request
from nacl.signing import SigningKey
from test_lite_bundle import _manifest, _tar

from azazel_nexus import lab_keys
from azazel_nexus.audit import AuditLedger
from azazel_nexus.lite_bundle import BundleRefused, read_anchors
from azazel_nexus.lite_import import (
    CommissionedLite,
    CommissionedTrust,
    LiteImport,
    Transition,
    status_summary,
)
from azazel_nexus.lite_trust import RepinConfirmation, RepinRequest, TrustRefused, TrustStore
from azazel_nexus.revocation import RevocationList
from azazel_nexus.revocation_policy import (
    REVOCATION_SIGNING,
    RevocationPolicy,
    commission_policy,
)

REPO = Path(__file__).resolve().parents[2]
NOW = "2026-10-18T00:00:00Z"
DIGEST = "sha256:" + "d" * 64
KEY_ID = "site-bundle"
POLICY = PrincipalPolicy(operator_gid=123, service_uids=frozenset({900}))
ROOT = POLICY.classify(0, 0, 42)
OPERATOR = POLICY.classify(1000, 123, 43)
SERVICE = POLICY.classify(900, 900, 44)


def _bundle(key: SigningKey, *, version: int = 5, key_id: str = KEY_ID,
            expiry: str = "2027-01-01T00:00:00Z") -> bytes:
    tables = {"tables/attack_technique.jsonl": json.dumps(
        {"technique_id": "T1110", "name": "Brute Force", "agg_next_expiry": expiry}).encode() + b"\n"}
    manifest = {**_manifest(bundle_version=version),
                "files": {path: hashlib.sha256(body).hexdigest() for path, body in tables.items()}}
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    signature = key.sign(manifest_bytes).signature.hex()
    return _tar({"manifest.json": manifest_bytes,
                 "manifest.sig": f"{key_id}:{signature}\n".encode(), **tables})


def _statement(revoker: SigningKey, **fields) -> bytes:
    statement = RevocationList(issued_at=NOW, **fields)
    return revoker.sign(statement.signature_target()).signature + statement.as_payload()


@pytest.fixture
def node(tmp_path):
    root = tmp_path / "var/lib/azazel/knowledge"
    trust = tmp_path / "var/lib/azazel/lite-trust"
    (root / "inbox").mkdir(parents=True)
    (trust / "trust").mkdir(parents=True)
    bundle_key, revoker = SigningKey.generate(), SigningKey.generate()
    public = bundle_key.verify_key.encode().hex()
    (trust / "trust/anchors.toml").write_text(f'threshold = 1\n[keys]\n"{KEY_ID}" = "{public}"\n')
    TrustStore(trust).pin([public], commissioning_digest=DIGEST, pinned_at=NOW, actor="test")
    # §11 step 4: the commissioner's record is group-readable.
    (trust / "trust.json").chmod(0o640)
    commission_policy(trust, RevocationPolicy(keys={"r": revoker.verify_key.encode()},
                                              key_roles={"r": REVOCATION_SIGNING},
                                              threshold=1, generation=1),
                      commissioning_digest=DIGEST, anchors_key_roles={}, anchors_keys={})
    floor = tmp_path / "var/lib/azazel/state/knowledge"
    floor.mkdir(parents=True)
    floor.chmod(0o700)
    events: list[dict] = []
    service = knowledge_lited.KnowledgeLiteService(
        root=root, trust_root=trust, clock_floor=ClockFloor(floor), now=lambda: NOW,
        import_audit=lambda: ImportAudit(append=events.append))
    return SimpleNamespace(root=root, trust=trust, key=bundle_key, revoker=revoker,
                           events=events, service=service, tmp=tmp_path)


def _place(node, blob: bytes, name: str = "site-lite.tar.gz") -> str:
    (node.root / "inbox" / name).write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


def _import(node, entry_id: str, principal=ROOT) -> dict:
    verb = knowledge_lited.REGISTRY.resolve("knowledge.import", principal)
    return node.service.handle(Request(verb=verb, arguments=verb.bind({"entry_id": entry_id}),
                                       principal=principal, payload={}))


def _store(node) -> dict:
    return {str(p.relative_to(node.root)): p.read_bytes()
            for p in node.root.rglob("*") if p.is_file() and "inbox" not in p.parts}


def _status(node) -> dict:
    return status_summary(root=node.root, trust_root=node.trust, query_as_of=NOW)


# -- knowledge.import: who, and against which trust -------------------------


def test_import_is_root_only_and_never_on_the_read_listener():
    for principal in (OPERATOR, SERVICE):
        with pytest.raises(RequestRefused) as refused:
            knowledge_lited.REGISTRY.resolve("knowledge.import", principal)
        assert refused.value.refusal is Refusal.PRINCIPAL_DENIED
    with pytest.raises(RequestRefused):
        knowledge_lited.READ_REGISTRY.resolve("knowledge.import", ROOT)
    verb = knowledge_lited.REGISTRY.resolve("knowledge.import", ROOT)
    for bad in ("../inbox/x", "A" * 64, "0" * 63, "/etc/passwd"):
        with pytest.raises(RequestRefused):
            verb.bind({"entry_id": bad})
    with pytest.raises(RequestRefused):
        verb.bind({"entry_id": "0" * 64, "root": "/tmp"})


def test_an_import_admits_under_commissioned_trust_and_records_each_transition(node):
    entry = _place(node, _bundle(node.key))
    result = _import(node, entry)
    assert result == {"outcome": "admitted", "refused": None, "state": "available",
                      "bundle_version": 5, "gate": None, "code": None, "audit_complete": True}
    kinds = [event["event_type"] for event in node.events]
    assert kinds[0] == "knowledge.lite.import_started"
    assert kinds[-1] == "knowledge.lite.import_admitted"
    admitted = node.events[-1]
    assert admitted["bundle_digest"] == "sha256:" + entry and admitted["bundle_version"] == 5
    # Every record fits the production schema it is appended under.
    for event in node.events:
        assert set(event) - {"event_type"} == {a.name for a in EVENT_SCHEMAS[event["event_type"]]}
    assert _status(node)["state"] == "available"


def test_the_store_local_anchor_is_not_what_the_daemon_import_trusts(node):
    """A bundle the store-local copy would admit, signed outside the pin."""
    other = SigningKey.generate()
    (node.root / "trust").mkdir()
    (node.root / "trust/anchors.toml").write_text(
        f'threshold = 1\n[keys]\n"{KEY_ID}" = "{other.verify_key.encode().hex()}"\n')
    entry = _place(node, _bundle(other))
    result = _import(node, entry)
    assert (result["outcome"], result["gate"]) == ("quarantined", "signature")
    assert not (node.root / "admitted").exists() or not any((node.root / "admitted").iterdir())


@pytest.mark.parametrize("withdrawn", ["digest", "generation", "key"])
def test_a_revoked_bundle_never_replaces_the_admitted_one(node, withdrawn):
    _import(node, _place(node, _bundle(node.key, version=5), "first.tar.gz"))
    before = _store(node)
    newer = _bundle(node.key, version=6)
    fields = {"digest": {"revoked_digests": frozenset({"sha256:" + hashlib.sha256(newer).hexdigest()})},
              "generation": {"revoked_generations": frozenset({6})},
              "key": {}}[withdrawn]
    if withdrawn == "key":
        # A second pinned key signs the newer bundle; the list withdraws it.
        second = SigningKey.generate()
        newer = _bundle(second, version=6, key_id="second")
        anchors = node.trust / "trust/anchors.toml"
        anchors.write_text(anchors.read_text() + f'"second" = "{second.verify_key.encode().hex()}"\n')
        record = json.loads((node.trust / "trust.json").read_text())
        record["keys"] = sorted(record["keys"] + [second.verify_key.encode().hex()])
        (node.trust / "trust.json").write_text(json.dumps(record))
        fields = {"revoked_keys": frozenset({second.verify_key.encode().hex()})}
    (node.trust / "revocations.signed").write_bytes(_statement(node.revoker, sequence=1, **fields))
    result = _import(node, _place(node, newer, "second.tar.gz"))
    assert (result["outcome"], result["gate"], result["code"]) == (
        "quarantined", "anchors", "BUNDLE_REVOKED")
    after = _store(node)
    # The admitted bundle and the watermark are untouched; only quarantine grew.
    assert {k: v for k, v in after.items() if not k.startswith("quarantine")} == before
    assert after["state/watermark"] == b"5\n"


@pytest.mark.parametrize("case, code", [
    ("no_policy", "unverified"), ("no_pin", "trust_unreadable"), ("clock", "clock_untrusted"),
    ("absent", "not_in_inbox"),
])
def test_an_unusable_trust_or_clock_changes_nothing(node, case, code):
    entry = _place(node, _bundle(node.key))
    if case == "no_policy":
        (node.trust / "revocation-policy.json").unlink()
    elif case == "no_pin":
        (node.trust / "trust.json").unlink()
    elif case == "clock":
        node.service.clock_floor.admit("2030-01-01T00:00:00Z")
    elif case == "absent":
        entry = "0" * 64
    result = _import(node, entry)
    assert (result["outcome"], result["refused"]) == ("refused", code)
    assert _store(node) == {}
    assert not (node.root / "quarantine").exists()


def test_no_import_starts_without_its_audit_record(node):
    def unavailable(event):
        raise OSError("auditd unreachable")

    node.service.import_audit = lambda: ImportAudit(append=unavailable)
    result = _import(node, _place(node, _bundle(node.key)))
    assert (result["outcome"], result["refused"], result["audit_complete"]) == (
        "refused", "audit_unavailable", False)
    assert _store(node) == {}


def test_a_lost_outcome_record_is_reported_not_hidden(node):
    seen = []

    def flaky(event):
        if event["event_type"] == "knowledge.lite.import_admitted":
            raise OSError("auditd went away")
        seen.append(event)

    node.service.import_audit = lambda: ImportAudit(append=flaky)
    result = _import(node, _place(node, _bundle(node.key)))
    assert (result["outcome"], result["audit_complete"]) == ("admitted", False)


def test_every_import_transition_maps_to_a_declared_schema():
    sample = {"entry_id": "a" * 64, "at": NOW, "directories": ["admitted"], "code": "unverified",
              "bundle_digest": "sha256:" + "b" * 64, "gate": "anchors",
              "bundle_version": 1, "served": 1, "withheld": 0, "static_reference": 0}
    for transition in (Transition.IMPORT_STARTED, Transition.STORE_TIGHTENED,
                       Transition.STATE_UNTRUSTED, Transition.REFUSED,
                       Transition.QUARANTINED, Transition.ADMITTED):
        event = import_event(transition, sample)
        schema = {a.name: a for a in EVENT_SCHEMAS[event["event_type"]]}
        assert set(event) - {"event_type"} == set(schema)
        for name, argument in schema.items():
            argument.coerce(event[name])


# -- trust.revocation.accept and F3 ----------------------------------------


@pytest.fixture
def acceptance(node):
    commissioning = node.tmp / "etc/azazel/commissioning"
    commissioning.mkdir(parents=True)
    events: list[dict] = []
    accept = RevocationAcceptance(
        commissioning_dir=commissioning, append=events.append, now=lambda: NOW,
        accept=lambda blob: CommissionedTrust(node.trust).accept_revocation(blob))
    return SimpleNamespace(dir=commissioning, events=events, accept=accept)


def test_revocation_accept_is_root_only_with_one_fixed_input():
    for principal in (OPERATOR, SERVICE):
        with pytest.raises(RequestRefused):
            commissiond.REGISTRY.resolve("trust.revocation.accept", principal)
    verb = commissiond.REGISTRY.resolve("trust.revocation.accept", ROOT)
    assert verb.bind({"revocation_file": REVOCATION_INPUT})
    for bad in ("../revocations.signed", "/etc/azazel/commissioning/lite-revocations.signed"):
        with pytest.raises(RequestRefused):
            verb.bind({"revocation_file": bad})


def test_an_accepted_list_is_read_as_revoked_by_the_daemon_f3(node, acceptance):
    """F3: the list takes trust.json's owner, group and mode, not 0600."""
    _import(node, _place(node, _bundle(node.key)))
    (acceptance.dir / REVOCATION_INPUT).write_bytes(
        _statement(node.revoker, sequence=1, revoked_generations=frozenset({5})))
    result = acceptance.accept.accept(ROOT, REVOCATION_INPUT)
    assert result == {"accepted": True, "code": None, "sequence": 1, "audit_complete": True}
    pinned = (node.trust / "trust.json").stat()
    for name in ("revocations.signed", "revocation-policy.json"):
        written = (node.trust / name).stat()
        assert (written.st_uid, written.st_gid) == (pinned.st_uid, pinned.st_gid), name
        assert stat.S_IMODE(written.st_mode) == stat.S_IMODE(pinned.st_mode) == 0o640, name
    assert node.service.handle(None)["reason_code"] == "revoked"
    assert [e["event_type"] for e in acceptance.events] == [
        "knowledge.lite.revocation_requested", "knowledge.lite.revocation_accepted"]
    for event in acceptance.events:
        schema = {a.name: a for a in EVENT_SCHEMAS[event["event_type"]]}
        assert set(event) - {"event_type"} == set(schema)
        for name, argument in schema.items():
            argument.coerce(event[name])


@pytest.mark.parametrize("case, code", [
    ("replay", "replay"), ("re_enable", "re_enable"), ("malformed", "malformed"),
    ("stranger", "unverified"), ("no_pin", "trust_unreadable"),
])
def test_a_refused_statement_changes_nothing(node, acceptance, case, code):
    first = _statement(node.revoker, sequence=2, revoked_generations=frozenset({4}))
    (node.trust / "revocations.signed").write_bytes(first)
    blob = {
        "replay": _statement(node.revoker, sequence=2, revoked_generations=frozenset({4, 9})),
        "re_enable": _statement(node.revoker, sequence=3),
        "malformed": b"x" * 80,
        "stranger": _statement(SigningKey.generate(), sequence=3,
                               revoked_generations=frozenset({4})),
        "no_pin": _statement(node.revoker, sequence=3, revoked_generations=frozenset({4})),
    }[case]
    if case == "no_pin":
        (node.trust / "trust.json").unlink()
    before = {p.name: p.read_bytes() for p in node.trust.iterdir() if p.is_file()}
    (acceptance.dir / REVOCATION_INPUT).write_bytes(blob)
    result = acceptance.accept.accept(ROOT, REVOCATION_INPUT)
    assert (result["accepted"], result["code"]) == (False, code)
    assert {p.name: p.read_bytes() for p in node.trust.iterdir() if p.is_file()} == before
    assert acceptance.events[-1]["event_type"] == "knowledge.lite.revocation_refused"


def test_no_list_is_accepted_without_its_audit_record(node, acceptance):
    def unavailable(event):
        raise OSError("auditd unreachable")

    acceptance.accept.append = unavailable
    (acceptance.dir / REVOCATION_INPUT).write_bytes(
        _statement(node.revoker, sequence=1, revoked_generations=frozenset({5})))
    assert acceptance.accept.accept(ROOT, REVOCATION_INPUT)["code"] == "audit_unavailable"
    assert not (node.trust / "revocations.signed").exists()


def test_the_revocation_input_is_a_bounded_regular_file_never_a_link(node, acceptance):
    target = node.tmp / "elsewhere.signed"
    target.write_bytes(_statement(node.revoker, sequence=1))
    (acceptance.dir / REVOCATION_INPUT).symlink_to(target)
    with pytest.raises(RequestRefused):
        acceptance.accept.accept(ROOT, REVOCATION_INPUT)
    with pytest.raises(RequestRefused) as refused:
        acceptance.accept.accept(OPERATOR, REVOCATION_INPUT)
    assert refused.value.refusal is Refusal.PRINCIPAL_DENIED


def test_a_writable_trust_record_refuses_acceptance(node, acceptance):
    (node.trust / "trust.json").chmod(0o660)
    (acceptance.dir / REVOCATION_INPUT).write_bytes(
        _statement(node.revoker, sequence=1, revoked_generations=frozenset({5})))
    assert acceptance.accept.accept(ROOT, REVOCATION_INPUT)["code"] == "unverified"
    assert not (node.trust / "revocations.signed").exists()


def test_commissiond_dispatches_the_verb(node, acceptance):
    service = commissiond.CommissionService(read_links_fn=lambda: [],
                                            commissioning_dir=acceptance.dir,
                                            snapshot_dir=node.tmp, revocation=acceptance.accept)
    (acceptance.dir / REVOCATION_INPUT).write_bytes(
        _statement(node.revoker, sequence=1, revoked_generations=frozenset({5})))
    verb = commissiond.REGISTRY.resolve("trust.revocation.accept", ROOT)
    result = service.handle(Request(verb=verb, arguments=verb.bind(
        {"revocation_file": REVOCATION_INPUT}), principal=ROOT, payload={}))
    assert result["accepted"] is True


#: What the reading account runs: the daemon's own trust reader.
READER = """
import sys
from pathlib import Path
from azazel_nexus.lite_import import CommissionedTrust, TrustUnusable
try:
    snapshot = CommissionedTrust(Path(sys.argv[1])).snapshot()
    print("revoked" if snapshot.revocations.revokes_generation(5) else "not-revoked")
except TrustUnusable as unusable:
    print(unusable.code)
"""


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="F3 across accounts needs root to own files as two uids")
def test_f3_another_account_in_the_group_reads_the_accepted_list():
    """The commissioner writes; a different uid in the group reads `revoked` state."""
    writer_uid, reader_uid, group = 4241, 4242, 4243
    base = Path(tempfile.mkdtemp(dir="/var/tmp"))
    try:
        base.chmod(0o755)
        trust = base / "lite-trust"
        (trust / "trust").mkdir(parents=True)
        key, revoker = SigningKey.generate(), SigningKey.generate()
        public = key.verify_key.encode().hex()
        (trust / "trust/anchors.toml").write_text(f'threshold = 1\n[keys]\n"{KEY_ID}" = "{public}"\n')
        TrustStore(trust).pin([public], commissioning_digest=DIGEST, pinned_at=NOW, actor="test")
        commission_policy(trust, RevocationPolicy(keys={"r": revoker.verify_key.encode()},
                                                  key_roles={"r": REVOCATION_SIGNING},
                                                  threshold=1, generation=1),
                          commissioning_digest=DIGEST, anchors_key_roles={}, anchors_keys={})
        for path in (trust, trust / "trust"):
            os.chown(path, writer_uid, group)
            path.chmod(0o2750)
        for path in (trust / "trust.json", trust / "revocation-policy.json",
                     trust / "trust/anchors.toml"):
            os.chown(path, writer_uid, group)
            path.chmod(0o640)
        CommissionedTrust(trust).accept_revocation(
            _statement(revoker, sequence=1, revoked_generations=frozenset({5})))
        reader = subprocess.run(
            [sys.executable, "-c", READER, str(trust)], user=reader_uid, group=group,
            extra_groups=[group], capture_output=True, timeout=60, check=False)
        assert reader.stdout.strip() == b"revoked", reader.stderr[-500:]
    finally:
        shutil.rmtree(base)


# -- the published fixture key ----------------------------------------------


def test_every_vendored_fixture_key_is_listed():
    for anchors in (REPO / "contract/azazel-knowledge-lite/anchors.toml",
                    REPO / "tests/fixtures/knowledge-lite/anchors.toml"):
        assert set(read_anchors(anchors).keys.values()) <= lab_keys.PUBLIC_FIXTURE_KEYS


def _fixture_key() -> str:
    (key,) = read_anchors(REPO / "contract/azazel-knowledge-lite/anchors.toml").keys.values()
    return key.hex()


def test_pin_refuses_the_fixture_key_off_a_lab_host(tmp_path):
    with pytest.raises(TrustRefused, match="PUBLIC_FIXTURE_KEY"):
        TrustStore(tmp_path).pin([_fixture_key()], commissioning_digest=DIGEST,
                                 pinned_at=NOW, actor="test")
    assert not (tmp_path / "trust.json").exists()


def test_pin_accepts_the_fixture_key_on_a_marked_lab_host(tmp_path, lab_host):
    TrustStore(tmp_path).pin([_fixture_key()], commissioning_digest=DIGEST,
                             pinned_at=NOW, actor="lab")


@pytest.mark.parametrize("role", ["bundle", "revocation"])
def test_repin_refuses_the_fixture_key_in_either_role(node, role):
    document = {"keys": [node.key.verify_key.encode().hex()]}
    if role == "bundle":
        document["keys"].append(_fixture_key())
    else:
        document["revocation_policy"] = {
            "keys": {"fixture": _fixture_key()}, "key_roles": {"fixture": REVOCATION_SIGNING},
            "threshold": 1, "generation": 2}
    proposed = node.tmp / "repin-anchor.json"
    proposed.write_text(json.dumps(document))
    before = sorted(p.name for p in node.trust.iterdir())
    with pytest.raises(TrustRefused):
        TrustStore(node.trust).repin(
            RepinRequest(proposed, "rotation", "root"),
            confirmation=RepinConfirmation("sha256:" + "0" * 64, NOW),
            ledger=AuditLedger(node.tmp / "commission.jsonl"), now=NOW)
    assert sorted(p.name for p in node.trust.iterdir() if p.name != "trust-staging") == [
        name for name in before if name != "trust-staging"]
    assert TrustStore(node.trust).current_generation() == 0


def test_a_hand_pinned_fixture_key_makes_the_trust_root_unusable(node):
    """A trust.json written around `pin` still does not make the fixture usable."""
    contract = REPO / "contract/azazel-knowledge-lite"
    record = json.loads((node.trust / "trust.json").read_text())
    record["keys"] = [_fixture_key()]
    (node.trust / "trust.json").write_text(json.dumps(record))
    shutil.copy(contract / "anchors.toml", node.trust / "trust/anchors.toml")
    entry = _place(node, (contract / "lite.tar.gz").read_bytes())
    assert _status(node)["reason_code"] == "trust_unreadable"
    assert (_import(node, entry)["refused"]) == "trust_unreadable"
    assert _store(node) == {}


def test_commissioned_anchors_refuse_the_fixture_key_off_a_lab_host(tmp_path):
    contract = REPO / "contract/azazel-knowledge-lite"
    root = tmp_path / "store"
    (root / "inbox").mkdir(parents=True)
    (root / "trust").mkdir()
    shutil.copy(contract / "anchors.toml", root / "trust/anchors.toml")
    with pytest.raises(BundleRefused) as refused:
        CommissionedLite(root).anchors()
    assert refused.value.code == "ANCHOR_PUBLIC_FIXTURE_KEY"
    shutil.copy(contract / "lite.tar.gz", root / "inbox/lite.tar.gz")
    service = LiteImport(CommissionedLite(root))
    outcome = service.import_entry(service.list_inbox()[0].entry_id, now=NOW)
    assert not outcome.admitted and outcome.refusal.code == "ANCHOR_PUBLIC_FIXTURE_KEY"


def test_commissioned_anchors_accept_the_fixture_key_on_a_lab_host(tmp_path, lab_host):
    contract = REPO / "contract/azazel-knowledge-lite"
    (tmp_path / "trust").mkdir()
    shutil.copy(contract / "anchors.toml", tmp_path / "trust/anchors.toml")
    assert CommissionedLite(tmp_path).anchors().keys


# -- auditd binds each new event type to its writer -------------------------


@pytest.fixture
def auditd(tmp_path):
    (tmp_path / "ledger").mkdir()
    service = AuditService(SegmentedLedger(tmp_path / "ledger"))
    service.start()
    service._bound_writer_uids = {"knowledge.lite.import_": 4444,
                                  "knowledge.lite.revocation_": 5555}
    return service


def _append(service, principal, event_type, payload):
    verb = AUDIT_REGISTRY.resolve("audit.append", principal)
    return service.handle(Request(verb=verb, arguments=verb.bind({"event_type": event_type}),
                                  principal=principal, payload=payload))


@pytest.mark.parametrize("event_type, payload, writer", [
    ("knowledge.lite.import_started", {"entry_id": "a" * 64, "occurred_at": NOW}, 4444),
    ("knowledge.lite.revocation_requested",
     {"statement_digest": "sha256:" + "c" * 64, "occurred_at": NOW}, 5555),
])
def test_only_the_bound_account_may_write_a_lite_record(auditd, event_type, payload, writer):
    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({4444, 5555, 6666}))
    receipt = _append(auditd, policy.classify(writer, writer, 9), event_type, payload)
    assert set(receipt) == {"sequence", "event_hash"}
    other = 5555 if writer == 4444 else 4444
    for principal in (policy.classify(other, other, 9), policy.classify(6666, 6666, 9),
                      policy.classify(0, 0, 9)):
        with pytest.raises(RequestRefused) as refused:
            _append(auditd, principal, event_type, payload)
        assert refused.value.refusal is Refusal.PRINCIPAL_DENIED


def test_a_missing_writer_account_means_nobody_writes(auditd):
    auditd._bound_writer_uids = {"knowledge.lite.import_": None,
                                 "knowledge.lite.revocation_": None}
    policy = PrincipalPolicy(operator_gid=None, service_uids=frozenset({4444}))
    with pytest.raises(RequestRefused):
        _append(auditd, policy.classify(4444, 4444, 9), "knowledge.lite.import_started",
                {"entry_id": "a" * 64, "occurred_at": NOW})
