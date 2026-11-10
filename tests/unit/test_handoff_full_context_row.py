"""A recent row that carries a Full Context projection must not change the package.

New fixtures only; the existing golden vectors are untouched. The digests below
are the current bytes for this row, recorded so a later change that lets Full
state reach the root/operator package is visible.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from azazel_nexus import handoff, runtime_paths

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("example", REPO / "tools" / "build_handoff_example.py")
example = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(example)

BASE = {"state": "frame_ready", "unknowns": ["synthetic unknown"],
        "next_checks": ["synthetic check"], "knowledge": [],
        "dependency_outcome": {"knowledge": "available", "deception": "absent"}}
FULL = {"full_node_context_status": "received", "outcome": "complete",
        "source_kind": "fabric_knowledge_context_response_v1",
        "claim_status": "source_reported_unverified",
        "trust": "unverified_advisory_only", "snapshot_state": "complete",
        "generated_at": "2026-10-29T03:15:00Z", "expires_at": "2026-10-29T04:15:00Z",
        "limitations": ["Source reports are unverified and advisory only.",
                        "Producer limitations were reported; their text is withheld."]}
# Strings that exist only because the row carries a Full projection.
FULL_ONLY = ("full_node_context", "fabric_knowledge_context_response_v1",
             "source_reported_unverified", "unverified_advisory_only",
             "Producer limitations were reported", "2026-10-29T04:15:00Z")
GOLDEN_FULL_ROW = {
    "root": {"handoff.json": "361bf176dcdf2714da8e17e92dc7049bae7bd1a684490330b41a1da3e26990ea", "handoff.ja.md": "214ab83ac9227ca332d7cc45fd9163ef95fadf728eb9c5b7fffce8d6b059aa6a", "manifest.json": "6e66e03ad9a47f115e25ba881506f350dfed56f83af9a3281c230d8853021e2a"},
    "operator": {"handoff.json": "83b18e63fea9607b40ad424ad750777b753fd6ac5e3ae41e7422f52e2cc08c7a", "handoff.ja.md": "8bb7e6dc5b657665b8409ee5949bd2d9aadda9aca73ab5619f23e6780ca0463e", "manifest.json": "4636ca4a74713bf76f5829c7b65dc1f6476ef99cfa383fee6131ede0430d37fc"},
}


def _root(tmp_path, name, fast):
    root = tmp_path / name
    root.mkdir()
    example.build_fixture(root)
    path = root / "var/lib/azazel/run/incident-explain-status/recent.json"
    doc = json.loads(path.read_text())
    doc["incidents"][0]["explanation"]["fast_assistance"] = fast
    path.write_text(json.dumps(doc))
    for leaf in runtime_paths.UI_COPIES:
        src = runtime_paths.snapshot_path(leaf, root)
        if src.is_file():
            dst = runtime_paths.snapshot_path(leaf, root, reader="ui")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst)
    return root


def _files(root, principal, monkeypatch=None):
    if principal == "ui":
        # The UI path reads the AZAZEL_ROOT tree, as ui_serve does.
        monkeypatch.setenv("AZAZEL_ROOT", str(root))
        root = None
    return handoff.encode_files(handoff.build_package(
        example.INCIDENT, now=example.GENERATED, principal=principal, root=root))


def _row_is_read(root):
    from azazel_nexus.incident_explain import read_recent_incidents
    path = root / "var/lib/azazel/run/incident-explain-status/recent.json"
    return read_recent_incidents(path.read_bytes()) is not None


def _digests(files):
    return {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}


def test_the_fixture_row_with_full_projection_passes_the_strict_reader(tmp_path):
    # Guards against a vacuous test: a refused row would be dropped silently.
    assert _row_is_read(_root(tmp_path, "r", {**BASE, "full_node_context": FULL}))


@pytest.mark.parametrize("principal", ["root", "operator"])
def test_full_state_does_not_change_root_or_operator_bytes(tmp_path, principal):
    without = _files(_root(tmp_path, "a", BASE), principal)
    with_full = _files(_root(tmp_path, "b", {**BASE, "full_node_context": FULL}), principal)
    assert with_full == without


@pytest.mark.parametrize("principal", ["root", "operator"])
def test_full_row_digest_vector(tmp_path, principal):
    files = _files(_root(tmp_path, "c", {**BASE, "full_node_context": FULL}), principal)
    assert _digests(files) == GOLDEN_FULL_ROW[principal]


@pytest.mark.parametrize("principal", ["root", "operator", "ui"])
def test_full_projection_text_never_reaches_the_package(tmp_path, monkeypatch, principal):
    files = _files(_root(tmp_path, "d", {**BASE, "full_node_context": FULL}), principal, monkeypatch)
    for name, data in files.items():
        text = data.decode("utf-8")
        for mark in FULL_ONLY:
            assert mark not in text, (principal, name, mark)
