"""Unmodified real Knowledge CLI output, commissioned with its public lab key."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tomllib

from azazel_nexus.lite_import import CommissionedLite, CommissionedTrust, LiteImport
from azazel_nexus.lite_trust import TrustStore

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/knowledge-lite-real"
NOW = "2026-10-18T00:00:00Z"


def commission_real_fixture(store: Path, trust: Path) -> str:
    provenance = json.loads((FIXTURE / "provenance.json").read_text())
    archive = FIXTURE / "lite.tar.gz"
    entry_id = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert entry_id == provenance["archive_sha256"]
    assert provenance["producer_commit"] == "09d234cde0ceb447a3ebc7e9704eef4758ac4a4d"
    anchors = (FIXTURE / "anchors.toml").read_text()
    public = next(iter(tomllib.loads(anchors)["keys"].values()))
    # Replace this disposable node's synthetic anchor before commissioning.
    (trust / "trust.json").unlink()
    (trust / "trust/anchors.toml").write_text(anchors)
    TrustStore(trust).pin([public], commissioning_digest="sha256:" + "a" * 64,
                         pinned_at=NOW, actor="test")
    shutil.copyfile(archive, store / "inbox/real-producer.tar.gz")
    return entry_id


def test_real_archive_imports_without_rewriting(tmp_path, monkeypatch):
    import test_knowledge_lited
    service, store, trust, _ = test_knowledge_lited.node.__wrapped__(tmp_path, monkeypatch)
    entry_id = commission_real_fixture(store, trust)
    importer = LiteImport(CommissionedLite(store), trust=CommissionedTrust(trust))
    result = importer.import_entry(entry_id, now=NOW)
    assert result.admitted
    assert hashlib.sha256((store / "admitted/current.tar.gz").read_bytes()).hexdigest() == entry_id
    assert service.handle(None)["state"] == "available"
    from azazel_nexus.lite_import import lookup_context_reading
    reading = lookup_context_reading(root=store, trust_root=trust,
                                     technique_ids=("T1110",), query_as_of=NOW)
    ref, = reading.refs
    assert ref.technique_id == "T1110"
    assert ref.generation == 5
    assert ref.trust_check == "verified"
    assert ref.citation.startswith("MITRE ATT&CK technique")
    assert ref.freshness == "static"
    assert ref.bundle_digest == "sha256:" + entry_id
    with tarfile.open(FIXTURE / "lite.tar.gz") as archive:
        assert all(member.name in {"manifest.json", "manifest.sig"}
                   or member.name.startswith("tables/") for member in archive.getmembers())
