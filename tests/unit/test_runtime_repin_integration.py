"""Challenge and confirmation through the production adapter and real promotion."""

import json
import stat

import pytest
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.protocol import RequestRefused
from azazel_nexus_runtime.repin_confirmation import ANCHOR_FILENAME, RepinConfirmation
from nacl.signing import SigningKey
from test_lite_bundle import _tar

from azazel_nexus import lite_trust
from azazel_nexus.audit import AuditLedger
from azazel_nexus.layout import create_layout, spec_for
from azazel_nexus.lite_bundle import BundleRefused, TrustAnchors, verify_bundle
from azazel_nexus.lite_trust import TrustStore

NOW = "2026-10-17T01:00:00Z"
DIGEST = "sha256:" + "a" * 64
ROOT = PrincipalPolicy(operator_gid=123, service_uids=frozenset()).classify(0, 0, 42)


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    create_layout(tmp_path)
    store = TrustStore(runtime_paths.lite_trust_root())
    old, new = SigningKey.generate(), SigningKey.generate()
    store.pin([bytes(old.verify_key).hex()], commissioning_digest=DIGEST,
              pinned_at=NOW, actor="root")
    # Production commissioning provisions this file as azcommission:azknowledge.
    store.path.chmod(0o640)
    directory = tmp_path / "etc/azazel/commissioning"
    (directory / ANCHOR_FILENAME).write_text(json.dumps({
        "keys": [bytes(new.verify_key).hex()],
    }))
    confirmation = RepinConfirmation(
        commissioning_dir=directory,
        snapshot_dir=runtime_paths.state_dir() / "commission",
        now=lambda: NOW,
    )
    return store, old, new, confirmation


def confirm(confirmation):
    challenge = confirmation.challenge(ROOT, "rotation", ANCHOR_FILENAME)
    return confirmation.confirm(ROOT, challenge["nonce"], challenge["confirmation_words"])


def verify(store, key):
    manifest = json.dumps({
        "bundle_format_version": 1, "bundle_version": 7, "kind": "full", "files": {},
    }, sort_keys=True).encode()
    bundle = _tar({
        "manifest.json": manifest,
        "manifest.sig": b"signer:" + key.sign(manifest).signature.hex().encode() + b"\n",
    })
    keys = store.keys(commissioning_digest=DIGEST)
    return verify_bundle(bundle, anchors=TrustAnchors(
        threshold=1, keys={"signer": keys[0]}, revoked=frozenset(), key_roles={},
    ))


def test_real_production_promotion_audit_and_new_bundle_key(node):
    store, old, new, confirmation = node
    verify(store, old)
    before = store.path.read_bytes()
    assert confirm(confirmation) == {"promoted": True, "generation": 1}
    assert (store.root / "trust.json").read_bytes() == before
    assert store.keys(commissioning_digest=DIGEST) == (bytes(new.verify_key),)
    assert verify(store, new).signers == ("signer",)
    with pytest.raises(BundleRefused):
        verify(store, old)
    ledger = AuditLedger(runtime_paths.commission_ledger_path())
    ledger.verify()
    events = [entry.event for entry in ledger]
    assert [event.pop("event_type") for event in events] == [
        "trust.repin.authorized", "trust.repin.promoted",
    ]
    assert events[0] == events[1]
    assert set(events[0]) == {
        "generation", "old_fingerprint", "new_fingerprint", "principal", "at", "reason",
    }
    assert events[0]["principal"] == "root"
    assert events[0]["at"] == NOW and events[0]["reason"] == "rotation"
    assert events[0]["generation"] == 1
    assert events[0]["old_fingerprint"] != events[0]["new_fingerprint"]
    assert not list(confirmation.snapshot_dir.glob(".repin-*"))
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o640


@pytest.mark.parametrize("failure", ["pointer", "audit"])
def test_real_production_failure_keeps_old_root_and_bundle(node, monkeypatch, failure):
    store, old, _, confirmation = node
    original = store.path.read_bytes()
    write = lite_trust._atomic_write

    def fail_pointer(path, payload, **kwargs):
        if path.name == "trust-current":
            raise OSError("injected promotion failure")
        return write(path, payload, **kwargs)

    def fail_audit(*args, **kwargs):
        raise OSError("injected audit failure")

    if failure == "pointer":
        monkeypatch.setattr(lite_trust, "_atomic_write", fail_pointer)
    else:
        monkeypatch.setattr(AuditLedger, "append", fail_audit)
    with pytest.raises(RequestRefused):
        confirm(confirmation)
    assert store.current_generation() == 0
    assert store.path.read_bytes() == original
    verify(store, old)
    assert not list(confirmation.snapshot_dir.glob(".repin-*"))
    assert [entry.event["event_type"] for entry in AuditLedger(
        runtime_paths.commission_ledger_path(),
    )] == (["trust.repin.authorized"] if failure == "pointer" else [])


def test_production_paths_and_least_privilege_declaration():
    from azazel_nexus_runtime.hardening import PROFILES

    spec = spec_for("/var/lib/azazel/lite-trust")
    assert (spec.owner, spec.group, spec.mode) == ("azcommission", "azknowledge", 0o2750)
    profile = next(p for p in PROFILES if p.unit == "azazel-commissiond.service")
    assert set(profile.read_write_paths) == {
        "/var/lib/azazel/lite-trust", "/var/lib/azazel/state/commission",
        "/var/lib/azazel/run/commission",
    }
    assert profile.supplementary_groups == ("azknowledge",)
    assert runtime_paths.lite_trust_root() == runtime_paths.ROOT / "var/lib/azazel/lite-trust"
    assert runtime_paths.commission_ledger_path() == (
        runtime_paths.ROOT / "var/lib/azazel/state/commission/commission.jsonl"
    )
    anchor = spec_for("/etc/azazel/commissioning")
    assert (anchor.owner, anchor.group, anchor.mode) == ("root", "azcommission", 0o750)
