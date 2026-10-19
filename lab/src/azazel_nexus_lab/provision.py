"""Lab-root-only fixture provisioning; no production resource gate is fabricated."""
from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus.audit import AuditLedger
from azazel_nexus.lite_import import CommissionedLite, LiteImport
from azazel_nexus.lite_trust import TrustStore
from azazel_nexus.revocation_policy import (
    REVOCATION_SIGNING,
    RevocationPolicy,
    commission_policy,
)

from .artifacts import canonical, create_key, envelope, output, resign_fixture

DATA = Path(__file__).parent / "data"


def now():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def provision(root, key):
    public = bytes(key.verify_key).hex()
    digest = "sha256:" + hashlib.sha256(bytes(key.verify_key)).hexdigest()
    trust = root / "var/lib/azazel/lite-trust"
    store = root / "var/lib/azazel/knowledge"
    anchors = f'threshold = 1\n[keys]\n"lab" = "{public}"\n'
    for directory in (trust, store):
        (directory / "trust").mkdir(parents=True, exist_ok=True)
        (directory / "trust/anchors.toml").write_text(anchors)
    TrustStore(trust).pin([public], commissioning_digest=digest, pinned_at=now(), actor="lab")
    revoker = create_key(root / "keys", "revocation.key")
    policy = RevocationPolicy(keys={"lab-revoker": bytes(revoker.verify_key)},
                              key_roles={"lab-revoker": REVOCATION_SIGNING},
                              threshold=1, generation=1)
    commission_policy(trust, policy, commissioning_digest=digest,
                      anchors_key_roles={}, anchors_keys={})
    (store / "inbox").mkdir(exist_ok=True)
    payload = resign_fixture(DATA / "lite.tar.gz", key)
    (root / "knowledge.lab-signed").write_bytes(envelope(payload, key, "knowledge-fixture"))
    (store / "inbox/lab.tar.gz").write_bytes(payload)
    ledger = AuditLedger(root / "lite-import.jsonl")
    service = LiteImport(CommissionedLite(store), recorder=lambda transition, event: ledger.append(
        output(event_type=transition.value, **event)))
    entry, = service.list_inbox()
    imported = service.import_entry(entry.entry_id, now=now())
    if not imported.admitted:
        raise ValueError("lab Knowledge fixture import refused")
    assets = root / "assets"
    assets.mkdir()
    baseline = assets / "azazel-baseline.json"
    shutil.copyfile(DATA / baseline.name, baseline)
    pack = output(kind="mission-pack", selection="playbooks/baseline",
                  asset_sha256=hashlib.sha256(baseline.read_bytes()).hexdigest(),
                  trusted_keys={"lab": public})
    media = root / "media"
    media.mkdir()
    (media / "mission-pack.signed").write_bytes(envelope(canonical(pack), key, "mission-pack"))
    # Native production validators MUST refuse this envelope. No fabricated
    # reserve record, tested tuple, LUKS claim, native admission receipt or
    # feature bypass is written in order to force a successful selection.
    return {"knowledge": "imported", "mission_pack": "lab-envelope-only",
            "production_pack_selection": "refused", "commissioning_digest": digest}
