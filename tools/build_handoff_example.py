#!/usr/bin/env python3
"""Build the documented handoff package example from a fixture, never a node.

    python3 tools/build_handoff_example.py            # rewrite docs/examples/handoff/
    python3 tools/build_handoff_example.py --check    # exit 1 if the copy is stale

The fixture is a throw-away `AZAZEL_ROOT` tree: incident transitions written
with `AuditLedger` exactly as the intake chains them, explained by the real
`az-incident-explaind` `Explainer` (with a fixed local-advice reply and a
fixed Knowledge citation instead of sockets), an audit chain, and the
operator snapshots. Addresses in it are documentation ranges (RFC 5737) and
are there to show that they do not reach the package. The package is
generated with `provenance: fixture`, which the Markdown states on its first
line. `tests/unit/test_handoff.py` regenerates it and compares bytes.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "docs" / "examples" / "handoff"
INCIDENT = "inc-5eed0000c0ffee01"
#: 2026-10-29T03:14:00Z, and the package generated two hours later.
OPENED = 1_793_243_640.0
GENERATED = OPENED + 7200
DIGESTS = ("sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64)
BUNDLE = "sha256:" + "ab" * 32


def transition(event_type, at, count, severity, would, policy, first, latest, **extra):
    value = {
        "event_type": "edge.incident." + event_type, "incident_id": INCIDENT,
        "src_ip": "192.0.2.10", "sid": 2010937, "target_port": 3306, "count": count,
        "first_seen": OPENED, "last_seen": at, "last_update": at, "most_severe": severity,
        "technique_ids": ["T1046"], "first_evidence": first, "latest_evidence": latest,
        "edge_would": would, "policy_reason": policy,
        "attack_type": "ET SCAN Suspicious inbound to mySQL port 3306 from 192.0.2.10",
        "category": "Attempted Information Leak", "protocol": "tcp",
    }
    value.update(extra)
    return value


def build_fixture(root: Path) -> None:
    """Write the fixture tree under `root` (an empty directory)."""
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.lite_import import KnowledgeRef
    from azazel_nexus.local_advisory import build_options, delivered_document
    from azazel_nexus.operator_snapshots import knowledge_snapshot
    from azazel_nexus_runtime.incident_explaind import Explainer

    def directory(path, mode=0o755):
        path = root / path
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
        return path

    incidents = directory("var/lib/azazel/edge-incidents", 0o750)
    state = directory("var/lib/azazel/incident-explain", 0o700)
    status_dir = directory("var/lib/azazel/run/incident-explain-status")

    def mio(frame):
        options = build_options(frame)
        body = delivered_document(frame, (), options,
                                  {"option_id": "other_suspicious", "kind": "other_suspicious"},
                                  list(options), None, "deterministic")
        return {"route": "local", "outcome": "answered", "reason": "local",
                "ledger_seq": 1, **body}

    def knowledge(ids):
        return [KnowledgeRef(
            technique_id="T1046", name="Network Service Discovery",
            summary="Adversaries may scan for services running on remote hosts.",
            claim_id="T1046", bundle_digest=BUNDLE, freshness="current",
            source_kind="knowledge_lite", generation=7, trust_check="verified",
            as_of="2026-10-29T03:14:30Z",
            citation="MITRE ATT&CK technique, as ingested into azazel-knowledge")]

    clock = [OPENED + 30]
    explainer = Explainer(incidents=incidents, state=state,
                          status_path=status_dir / "status.json", clock=lambda: clock[0],
                          monotonic=lambda: clock[0], mio=mio, knowledge=knowledge,
                          audit=lambda event: None)
    # Prepared first: an explainer that starts on existing history seeds
    # past it rather than explaining it.
    explainer.prepare()
    day = incidents / "2026-10-29.jsonl"
    ledger = AuditLedger(day)
    ledger.append(transition("opened", OPENED, 1, 3, "throttle",
                             "severity_elevated_throttle_reversible", DIGESTS[0], DIGESTS[0]))
    explainer.poll()
    ledger.append(transition("updated", OPENED + 60, 14, 2, "redirect",
                             "severity_high_redirect_to_decoy", DIGESTS[0], DIGESTS[1],
                             evidence_stored=False))
    clock[0] = OPENED + 120
    explainer.poll()

    audit = directory("var/lib/azazel/state/audit", 0o700)
    chain = AuditLedger(audit / "2026-10-29.jsonl")
    chain.append({"event_type": "activation.unit_granted", "unit": "auditd", "generation": 3,
                  "digest": DIGESTS[2], "occurred_at": "2026-10-29T02:50:00Z",
                  "actor": "operator-a"})
    chain.append({"event_type": "edge.incident.opened", "incident_id": INCIDENT,
                  "most_severe": 3, "edge_would": "throttle", "count": 1,
                  "technique_count": 1, "occurred_at": "2026-10-29T03:14:00Z"})
    chain.append({"event_type": "edge.incident.escalated", "incident_id": INCIDENT,
                  "most_severe": 2, "edge_would": "redirect", "count": 14,
                  "technique_count": 1, "occurred_at": "2026-10-29T03:15:00Z"})

    floor = directory("var/lib/azazel/state/knowledge", 0o700)
    (floor / "clock-floor.json").write_bytes(json.dumps(
        {"floor_utc": "2026-10-29T05:00:00Z",
         "schema": "azazel-nexus/knowledge-clock-floor/v1"},
        sort_keys=True, separators=(",", ":")).encode() + b"\n")
    timesync = directory("run/systemd/timesync")
    (timesync / "synchronized").write_bytes(b"")
    os.chmod(timesync / "synchronized", 0o644)

    def snapshot(leaf, value):
        path = directory("var/lib/azazel/run/" + leaf) / "status.json"
        path.write_text(json.dumps(value))

    snapshot("knowledge-status", knowledge_snapshot(
        {"state": "available", "reason_code": "available", "generation": 8,
         "freshness": "current"}, GENERATED - 20))
    snapshot("edge-intake-status", {
        "schema": "azazel-nexus/edge-intake-status/v1", "written_at": GENERATED - 3,
        "last_accepted_at": OPENED + 60, "accepted": 14, "processed": 14,
        "last_processed_at": OPENED + 60, "refused": {"evidence_segment_full": 1},
        "open_incidents": 0, "queue_drops": 0, "storage_failed": False})
    # The explainer's own snapshot is from the fixture's clock: rewrite its
    # time so the example shows a current one.
    status = json.loads((status_dir / "status.json").read_text())
    status["written_at"] = GENERATED - 1
    (status_dir / "status.json").write_text(json.dumps(status))


def generate(work: Path) -> dict:
    """`{name: bytes}` of the example package, built under `work`."""
    from azazel_nexus.handoff import build_package, encode_files

    root = work / "root"
    root.mkdir()
    build_fixture(root)
    package = build_package(INCIDENT, now=GENERATED, principal="root", root=root,
                            provenance="fixture")
    return encode_files(package)


def main(argv=None) -> int:
    check = "--check" in (sys.argv[1:] if argv is None else argv)
    with tempfile.TemporaryDirectory(dir=REPO, prefix=".handoff-example-") as work:
        files = generate(Path(work))
    if check:
        stale = [name for name, raw in files.items()
                 if not (EXAMPLE / name).is_file() or (EXAMPLE / name).read_bytes() != raw]
        if stale:
            print("stale: " + ", ".join(stale) + " (run tools/build_handoff_example.py)")
            return 1
        return 0
    EXAMPLE.mkdir(parents=True, exist_ok=True)
    for name, raw in files.items():
        (EXAMPLE / name).write_bytes(raw)
    print("written: " + ", ".join(sorted(files)))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO / "src"))
    sys.path.insert(0, str(REPO / "runtime" / "src"))
    raise SystemExit(main())
