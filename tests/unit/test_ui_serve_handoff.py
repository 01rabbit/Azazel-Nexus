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
    harness = Harness(tmp_path / "h", source=ui_serve.LiveSource(lambda *a, **k: 0))
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
    assert set(d["files"]) == {handoff.JSON_NAME, handoff.MARKDOWN_NAME, handoff.MANIFEST_NAME}
    assert d["package"]["generator"]["command"] is None
    assert d["package"]["generator"]["entry"] == "ui_get_handoff"
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


# -- A2 ------------------------------------------------------------------------

import hashlib  # noqa: E402

from azazel_nexus_runtime.ui_serve import SESSION_MAX_S  # noqa: E402

from test_ui_serve import DEMO  # noqa: E402


def tree_digest(root):
    return sorted((str(p.relative_to(root)), hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in root.rglob("*") if p.is_file())


def test_fixture_source_is_404(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    h = Harness(tmp_path / "h")  # FixtureSource
    try:
        sid, _ = h.login()
        r = get(h, f"/api/handoff/{INCIDENT}", sid)
        assert r.status == 404 and r.json() == {"error": "not_found"}
    finally:
        h.close()


def test_files_are_the_saved_bytes_unicode_included(ui):
    sid, _ = ui.login()
    d = get(ui, f"/api/handoff/{INCIDENT}", sid).json()
    assert any(ord(c) > 127 for c in d["files"][handoff.MARKDOWN_NAME])
    assert d["markdown"] == d["files"][handoff.MARKDOWN_NAME]
    manifest = json.loads(d["files"][handoff.MANIFEST_NAME])
    assert manifest == d["manifest"]
    assert hashlib.sha256(d["files"][handoff.MANIFEST_NAME].encode()).hexdigest() \
        == d["manifest_sha256"]
    for entry in manifest["files"]:
        raw = d["files"][entry["name"]].encode("utf-8")
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        assert len(raw) == entry["bytes"]


def test_session_expiry_and_logout_give_401(ui):
    sid, csrf = ui.login()
    assert get(ui, f"/api/handoff/{INCIDENT}", sid).status == 200
    out = ui.post("/api/logout", {}, token=csrf, cookie=f"azui_session={sid}")
    assert out.status == 200
    assert get(ui, f"/api/handoff/{INCIDENT}", sid).status == 401
    sid, _ = ui.login()
    ui.clock.advance(SESSION_MAX_S + 1)
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 401 and r.header("cache-control") == "no-store"


def test_bad_host_and_query_are_refused(ui):
    sid, _ = ui.login()
    r = ui.request("GET", f"/api/handoff/{INCIDENT}", host="evil.example",
                   headers=[("Cookie", f"azui_session={sid}")])
    assert r.status == 421
    r = get(ui, f"/api/handoff/{INCIDENT}?x=1", sid)
    assert r.status == 400 and r.json() == {"error": "query_or_fragment_refused"}


def test_failures_carry_no_store(ui, monkeypatch):
    sid, _ = ui.login()
    for path in ("/api/handoff/latest", "/api/handoff/inc-0000000000000000"):
        assert get(ui, path, sid).header("cache-control") == "no-store"

    def boom(*a, **k):
        raise RuntimeError("192.0.2.1")
    monkeypatch.setattr(handoff, "build_package", boom)
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 500 and r.json() == {"error": "handoff_refused"}
    assert r.header("cache-control") == "no-store" and b"192.0.2" not in r.body


def test_unserializable_package_is_a_fixed_500(ui, monkeypatch):
    sid, _ = ui.login()
    real = handoff.build_package

    def odd(*a, **k):
        p = real(*a, **k)
        p["observed_facts"]["x"] = float("nan")
        return p
    monkeypatch.setattr(handoff, "build_package", odd)
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 500 and r.json() == {"error": "handoff_refused"}


def test_concurrent_generation_is_429_and_lock_is_released(ui):
    sid, _ = ui.login()
    assert ui.app._handoff_lock.acquire(blocking=False)
    try:
        r = get(ui, f"/api/handoff/{INCIDENT}", sid)
        assert r.status == 429 and r.json() == {"error": "handoff_busy"}
        assert r.header("cache-control") == "no-store"
    finally:
        ui.app._handoff_lock.release()
    assert get(ui, f"/api/handoff/{INCIDENT}", sid).status == 200
    assert not ui.app._handoff_lock.locked()


def test_size_limit_boundary(ui, monkeypatch):
    sid, _ = ui.login()
    size = len(get(ui, f"/api/handoff/{INCIDENT}", sid).body)
    monkeypatch.setattr(ui_serve, "HANDOFF_MAX_BYTES", size)
    assert get(ui, f"/api/handoff/{INCIDENT}", sid).status == 200
    monkeypatch.setattr(ui_serve, "HANDOFF_MAX_BYTES", size - 1)
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 500 and r.json() == {"error": "handoff_too_large"}


def test_root_only_sources_are_never_opened(ui, monkeypatch):
    sid, _ = ui.login()
    opened = []
    real_open, real_list = handoff._open_regular, handoff._list_days
    real_chain = handoff._read_incident_chain
    monkeypatch.setattr(handoff, "_open_regular",
                        lambda path, limit: (opened.append(str(path)), real_open(path, limit))[1])
    monkeypatch.setattr(handoff, "_list_days",
                        lambda d: (opened.append(str(d)), real_list(d))[1])
    monkeypatch.setattr(handoff, "_read_incident_chain",
                        lambda *a, **k: (opened.append("incident_chain"), real_chain(*a, **k))[1])
    assert get(ui, f"/api/handoff/{INCIDENT}", sid).status == 200
    for path in opened:
        for root_only in ("edge-incidents", "incident-explain/explanations", "state/audit",
                          "clock-floor", "incident_chain"):
            assert root_only not in path, path
        assert "/run/ui-read/" in path or "/run/systemd/" in path, path


def test_no_fallback_to_operator_copies(ui):
    sid, _ = ui.login()
    shutil.rmtree(ui.root / "var/lib/azazel/run/ui-read")
    assert (runtime_paths.snapshot_path("incident_recent", ui.root)).is_file()
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status == 404 and r.json() == {"error": "not_found"}


def test_stale_copy_is_labelled(ui):
    sid, _ = ui.login()
    path = runtime_paths.snapshot_path("incident_recent", ui.root, reader="ui")
    doc = json.loads(path.read_text())
    doc["written_at"] = example.GENERATED - 3600
    path.write_text(json.dumps(doc))
    d = get(ui, f"/api/handoff/{INCIDENT}", sid).json()
    snap = next(s for s in d["package"]["sources"] if s["source"] == "recent_incidents_snapshot")
    assert snap["freshness"] != "fresh"


def test_corrupt_guidance_binding_is_refused(ui):
    sid, _ = ui.login()
    path = runtime_paths.snapshot_path("incident_recent", ui.root, reader="ui")
    doc = json.loads(path.read_text())
    expl = doc["incidents"][0]["explanation"]
    expl["guidance"] = {"content_kind": "bogus"}
    path.write_text(json.dumps(doc))
    r = get(ui, f"/api/handoff/{INCIDENT}", sid)
    assert r.status in (404, 500) and set(r.json()) == {"error"}
    assert r.status != 200


def test_success_writes_nothing(ui):
    sid, _ = ui.login()
    before = tree_digest(ui.root)
    assert get(ui, f"/api/handoff/{INCIDENT}", sid).status == 200
    assert tree_digest(ui.root) == before


GOLDEN = {
    "root": {"handoff.json": "361bf176dcdf2714da8e17e92dc7049bae7bd1a684490330b41a1da3e26990ea",
             "handoff.ja.md": "214ab83ac9227ca332d7cc45fd9163ef95fadf728eb9c5b7fffce8d6b059aa6a",
             "manifest.json": "6e66e03ad9a47f115e25ba881506f350dfed56f83af9a3281c230d8853021e2a"},
    "operator": {"handoff.json": "83b18e63fea9607b40ad424ad750777b753fd6ac5e3ae41e7422f52e2cc08c7a",
                 "handoff.ja.md": "8bb7e6dc5b657665b8409ee5949bd2d9aadda9aca73ab5619f23e6780ca0463e",
                 "manifest.json": "4636ca4a74713bf76f5829c7b65dc1f6476ef99cfa383fee6131ede0430d37fc"},
}


@pytest.mark.parametrize("principal", ["root", "operator"])
def test_cli_bytes_are_unchanged(tmp_path, principal):
    root = tmp_path / "r"
    root.mkdir()
    example.build_fixture(root)
    files = handoff.encode_files(handoff.build_package(
        INCIDENT, now=example.GENERATED, principal=principal, root=root))
    assert {k: hashlib.sha256(v).hexdigest() for k, v in files.items()} == GOLDEN[principal]


def test_capabilities_live_and_fixture(ui, tmp_path, monkeypatch):
    sid, _ = ui.login()
    caps = get(ui, "/api/view", sid).json()["capabilities"]
    assert caps == {"handoff": True, "full_context_from_observation": False}
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    h = Harness(tmp_path / "h2")
    try:
        s2, _ = h.login()
        assert get(h, "/api/view", s2).json()["capabilities"] == {
            "handoff": False, "full_context_from_observation": None}
        # capabilities never authorize: server judgement is independent.
        monkeypatch.setattr(h.app, "_capabilities",
                            lambda: {"handoff": True, "full_context_from_observation": True})
        h.app._view_cache = None
        assert get(h, "/api/view", s2).json()["capabilities"] == {
            "handoff": True, "full_context_from_observation": True}
        assert get(h, f"/api/handoff/{INCIDENT}", s2).status == 404
        assert get(h, f"/api/handoff/{INCIDENT}").status == 401
    finally:
        h.close()


def test_capability_follows_observation_rule_file(ui, monkeypatch):
    """U39 F: live reads the rule file (valid true; absent or defective false)."""
    import os
    from azazel_nexus_runtime import knowledge_context_config as cfg
    from test_knowledge_context_config import put_rule, rule_file
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    from azazel_nexus_runtime import runtime_paths as rt_paths
    monkeypatch.setattr(rt_paths, "ROOT", ui.root)
    sid, _ = ui.login()

    def caps():
        ui.app._view_cache = None
        return get(ui, "/api/view", sid).json()["capabilities"]["full_context_from_observation"]

    assert caps() is False
    put_rule(ui.root)
    assert caps() is True
    put_rule(ui.root, raw=b"{not json")
    assert caps() is False
    rule_file(ui.root).unlink()
    assert caps() is False


def test_ui_serve_does_not_import_the_observation_constant():
    assert "OBSERVATION_FULL_CONTEXT_QUERY" not in (
        REPO / "runtime/src/azazel_nexus_runtime/ui_serve.py").read_text()
