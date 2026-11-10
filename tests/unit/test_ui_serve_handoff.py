"""`GET /api/handoff/<id>`: the handoff package for a logged-in viewer (U35 A)."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from azazel_nexus import handoff, runtime_paths
from azazel_nexus_runtime import ui_serve

from test_ui_serve import Harness

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("example", REPO / "tools" / "build_handoff_example.py")
example = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(example)
INCIDENT = example.INCIDENT


@pytest.fixture
def ui(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    example.build_fixture(root)
    # The UI's copies, as the snapshot writers make them.
    for name in runtime_paths.UI_COPIES:
        src = runtime_paths.snapshot_path(name, root)
        if src.is_file():
            dst = runtime_paths.snapshot_path(name, root, reader="ui")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst)
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    harness = Harness(tmp_path / "h")
    harness.clock.now = example.GENERATED
    harness.root = root
    yield harness
    harness.close()


def get(ui, path, sid=None):
    headers = [("Cookie", f"azui_session={sid}")] if sid else []
    return ui.request("GET", path, headers=headers)


def test_unauthenticated_is_401(ui):
    r = get(ui, f"/api/handoff/{INCIDENT}")
    assert r.status == 401 and r.json() == {"error": "login_required"}


def test_logged_in_gets_package_markdown_manifest(ui):
    sid, _ = ui.login()
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 200, r.body
    assert r.header("cache-control") == "no-store"
    d = r.json()
    assert {"incident_id", "generated_at", "principal_class", "package", "markdown",
            "manifest", "manifest_sha256"} <= set(d)
    assert d["incident_id"] == d["package"]["incident"]["incident_id"] == INCIDENT
    assert d["principal_class"] == "ui" == d["package"]["generator"]["principal_class"]
    assert d["manifest"]["incident_id"] == INCIDENT
    assert d["manifest"]["generated_at"] == d["generated_at"]
    assert d["markdown"].startswith("# ")
    names = {f["name"] for f in d["manifest"]["files"]}
    assert names == {handoff.JSON_NAME, handoff.MARKDOWN_NAME}
    sources = {s["source"]: s for s in d["package"]["sources"]}
    for name in ("incident_ledger", "explanation_ledger", "audit_chain", "knowledge_clock_floor"):
        assert sources[name]["reason_code"] == "not_readable_by_principal"
    assert sources["recent_incidents_snapshot"]["readable_by"] == "ui"


def test_manifest_digests_match_the_returned_content(ui):
    import hashlib

    sid, _ = ui.login()
    d = get(ui, f"/api/handoff/{INCIDENT}", sid).json()
    md = next(f for f in d["manifest"]["files"] if f["name"] == handoff.MARKDOWN_NAME)
    assert hashlib.sha256(d["markdown"].encode()).hexdigest() == md["sha256"]
    js = next(f for f in d["manifest"]["files"] if f["name"] == handoff.JSON_NAME)
    assert hashlib.sha256(handoff._canonical(d["package"])).hexdigest() == js["sha256"]


@pytest.mark.parametrize("bad", ["latest", "inc-ZZZ", "..%2F", "../", "inc-" + "0" * 17,
                                 "inc-" + "0" * 15, "inc-" + "A" * 16, "", f"{INCIDENT}/x"])
def test_malformed_ids_are_404(ui, bad):
    sid, _ = ui.login()
    r = get(ui, f"/api/handoff/{bad}", sid)
    assert r.status == 404 and r.json() == {"error": "not_found"}


def test_well_formed_but_unknown_id_is_404(ui):
    sid, _ = ui.login()
    r = get(ui, "/api/handoff/inc-0000000000000000", sid)
    assert r.status == 404 and r.json() == {"error": "not_found"}


def test_leak_scan_failure_is_a_fixed_500(ui, monkeypatch):
    sid, _ = ui.login()
    real = handoff.build_package

    def leaky(*a, **k):
        p = real(*a, **k)
        p["observed_facts"]["leak"] = "192.0.2.10"
        return p
    monkeypatch.setattr(handoff, "build_package", leaky)
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 500 and r.json() == {"error": "handoff_refused"}
    assert b"192.0.2" not in r.body


def test_oversize_is_a_fixed_500(ui, monkeypatch):
    sid, _ = ui.login()
    monkeypatch.setattr(ui_serve, "HANDOFF_MAX_BYTES", 10)
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 500 and r.json() == {"error": "handoff_too_large"}


def test_post_is_refused_and_nothing_is_written(ui):
    sid, csrf = ui.login()
    before = sorted(p for p in ui.root.rglob("*"))
    r = ui.post(f"/api/handoff/{INCIDENT}", {}, token=csrf, cookie=f"azui_session={sid}")
    assert r.status == 404
    assert sorted(p for p in ui.root.rglob("*")) == before
