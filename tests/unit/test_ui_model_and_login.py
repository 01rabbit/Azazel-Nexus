"""What the read-only UI sends a browser, and `azazel-nexus ui-login` (U5).

Library halves of the UI: `ui_model.project` (the browser document as an
allowlist over the status read model) and `ui_login` (the strict reader of
the one-use login code and the operator's read-only command).
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from azazel_nexus import ui_login, ui_model
from azazel_nexus.cli import main

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "tests" / "fixtures" / "ui" / "demo-status-view.json"


def _demo():
    return json.loads(DEMO.read_text(encoding="utf-8"))


# -- the projection ----------------------------------------------------------------


def test_the_demo_fixture_is_a_status_read_model():
    from azazel_nexus.status_view import SCHEMA

    view = _demo()
    assert view["schema"] == SCHEMA
    rows = view["sections"]["edge_loop"]["recent"]["snapshot"]["incidents"]
    assert rows and all(row["edge_decision"]["executed"] is False for row in rows)


def test_the_document_copies_only_the_screens_sections_and_fixed_authority():
    model = ui_model.project(_demo(), origin={"kind": "fixture"}, served_at="t")
    assert model["schema"] == ui_model.SCHEMA
    assert set(model["sections"]) == set(ui_model.UI_SECTIONS)
    assert "interfaces" not in model["sections"]
    assert model["authority"] == {
        "decision_and_enforcement": "edge", "nexus": "observe_explain_advise",
        "edge_decisions": "would_not_executed", "execution_results": "not_accepted",
        "reason_code": "nexus_accepts_observe_only"}
    # The demo carries every section the screens use, the operator
    # snapshots and the NOC section included, so nothing is pending.
    assert model["pending"] == {}
    assert model["read_model"] == {"status": "read", "reason_code": None,
                                   "schema": "azazel-nexus/status-view/1"}


def test_a_section_an_older_read_model_lacks_is_pending_not_healthy():
    """A read model from before U2/U3 (or a fixture saved then) has no
    snapshot or NOC sections: each is pending with a fixed code."""
    view = _demo()
    for name in ("knowledge_status", "mio_status", "services", "storage", "noc"):
        del view["sections"][name]
    model = ui_model.project(view, origin={"kind": "fixture"}, served_at="t")
    assert model["pending"] == {name: "section_absent_from_read_model" for name in (
        "knowledge_status", "mio_status", "services", "storage", "noc")}
    assert not set(model["pending"]) & set(model["sections"])


def test_an_unknown_section_is_not_passed_through():
    view = _demo()
    view["sections"]["raw_journal"] = {"lines": ["SECRET"]}
    model = ui_model.project(view, origin={"kind": "fixture"}, served_at="t")
    assert "raw_journal" not in model["sections"]
    assert "SECRET" not in json.dumps(model)


@pytest.mark.parametrize("view", [None, [], "x", {"schema": "other", "sections": {}},
                                  {"schema": "azazel-nexus/status-view/1", "sections": []}])
def test_a_view_that_is_not_the_read_model_is_unavailable_not_empty(view):
    model = ui_model.project(view, origin={"kind": "live"}, served_at="t")
    assert model["read_model"] == {"status": "unavailable", "reason_code": "read_model_refused"}
    assert model["sections"] == {}
    assert set(model["pending"]) == set(ui_model.UI_SECTIONS)
    assert set(model["pending"].values()) == {"read_model_unavailable"}
    assert model["clock"]["status"] == "unknown"


def test_access_words_outside_the_vocabulary_become_unreadable():
    model = ui_model.project(_demo(), origin={"kind": "live"}, served_at="t",
                             access={"a": "readable", "b": "<script>", "c": "permission_denied"})
    assert model["access"] == {"a": "readable", "b": "unreadable", "c": "permission_denied"}


def test_the_setup_guide_is_copied_field_by_field():
    setup = {"schema": "azazel-nexus/setup/1", "notice": "n", "read_only": True,
             "provider_admission": "blocked", "hg05": "unmeasured",
             "enforcement_readiness": "not-established", "mio": {"secret": 1},
             "steps": [{"name": "a", "status": "needed", "reason": "r", "next_command": "c",
                        "private": "x"}, "junk"]}
    model = ui_model.project(_demo(), origin={"kind": "live"}, served_at="t", setup=setup)
    assert model["setup"] == {"status": "read", "reason_code": None,
                              "schema": "azazel-nexus/setup/1", "notice": "n", "read_only": True,
                              "provider_admission": "blocked", "hg05": "unmeasured",
                              "enforcement_readiness": "not-established",
                              "steps": [{"name": "a", "status": "needed", "reason": "r",
                                         "next_command": "c"}]}
    bad = ui_model.project(_demo(), origin={"kind": "live"}, served_at="t",
                           setup={"schema": "other"})
    assert bad["setup"] == {"status": "unavailable", "reason_code": "setup_guide_unavailable"}


def test_the_projection_of_every_status_scenario_holds_no_identifier(tmp_path, monkeypatch):
    """Over the status read model's own scenarios: nothing the terminal keeps."""
    sys.path.insert(0, str(Path(__file__).parent))
    from test_status_view import SCENARIOS, run_scenario

    for name in sorted(SCENARIOS):
        with monkeypatch.context() as patch:
            scenario = tmp_path / name
            scenario.mkdir()
            code, out, _ = run_scenario(name, scenario, patch, json_flag=True)
            assert code == 0
            text = ui_model.browser_json(ui_model.project(
                json.loads(out), origin={"kind": "live"}, served_at="t")).decode()
            # The sysfs tree's kernel names, PCI slots and port labels, the
            # tmp path, exception text: none reaches the page. (`if-N` is the
            # read model's own pseudonymous handle, not an interface name.)
            for secret in (str(scenario), "enp4s0", "enp5s0", "0000:04:00.0", "LAN1", "LAN2",
                           "0x8086", "SECRET", "192.0.2.1", "bus_path", "physical_label",
                           "/sys/", "Traceback", "aa:bb:cc"):
                assert secret not in text, (name, secret)


def test_browser_json_escapes_markup_and_line_separators_and_round_trips():
    value = {"s": "</script><img src=x onerror=alert(1)>&  ", "n": 1}
    raw = ui_model.browser_json(value)
    for forbidden in (b"<", b">", b"&", " ".encode(), " ".encode()):
        assert forbidden not in raw
    assert json.loads(raw) == value
    with pytest.raises(ValueError):
        ui_model.browser_json({"x": float("nan")})


# -- the login code reader ----------------------------------------------------------------


def _record(**change):
    record = {"schema": ui_login.SCHEMA, "code": "ABCDEFGHJK", "issued_at": 1000.0,
              "expires_at": 1060.0, "url": "http://127.0.0.1:8443/"}
    record.update(change)
    return json.dumps(record).encode()


def test_the_reader_accepts_the_published_shape():
    assert ui_login.read_login_code(_record())["code"] == "ABCDEFGHJK"


@pytest.mark.parametrize("raw", [
    _record(schema="other"), _record(code="abcdefghjk"), _record(code="ABCDEFGHJ0"),
    _record(code="ABCDEFGHJKL"), _record(expires_at=1061.0), _record(expires_at=1000.0),
    _record(issued_at="1000"), _record(url="http://evil.example/"),
    _record(url="http://127.0.0.1:8443/?code=X"), _record(extra=1),
    b"{", b"[]", b"x" * (ui_login.LOGIN_CODE_BYTES + 1),
    json.dumps({"schema": ui_login.SCHEMA}).encode(),
])
def test_the_reader_refuses_anything_else(raw):
    with pytest.raises(ValueError):
        ui_login.read_login_code(raw)


@pytest.mark.parametrize("typed, expected", [
    ("ABCDEFGHJK", "ABCDEFGHJK"), ("abcde-fghjk", "ABCDEFGHJK"), (" ABCDE FGHJK ", "ABCDEFGHJK"),
    ("ABCDE-FGHJ", None), ("ABCDE-FGHJ0", None), (None, None), (5, None), ("A" * 65, None),
])
def test_normalize_code(typed, expected):
    assert ui_login.normalize_code(typed) == expected


# -- `azazel-nexus ui-login` --------------------------------------------------------------


def _publish(tmp_path, raw):
    path = ui_login.login_code_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    return path


def _run(monkeypatch, tmp_path, now):
    from azazel_nexus import cli

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(cli, "_now", lambda: now)
    out = io.StringIO()
    code = main(["ui-login"], out=out, err=io.StringIO())
    return code, out.getvalue()


def test_ui_login_prints_the_code_and_the_url_and_nothing_else(tmp_path, monkeypatch):
    _publish(tmp_path, _record(issued_at=1_800_000_000.0, expires_at=1_800_000_060.0))
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    code, out = _run(monkeypatch, tmp_path, "2027-01-15T08:00:20Z")
    assert code == 0
    assert "ABCDE-FGHJK" in out and "valid for 40 more seconds" in out
    assert "http://127.0.0.1:8443/" in out and "?" not in out.split("Open ")[1].split()[0]
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before


def test_ui_login_refuses_an_expired_or_future_code(tmp_path, monkeypatch):
    _publish(tmp_path, _record(issued_at=1_800_000_000.0, expires_at=1_800_000_060.0))
    code, out = _run(monkeypatch, tmp_path, "2027-01-15T08:01:00Z")
    assert code == 1 and "expired" in out and "ABCDE" not in out
    code, out = _run(monkeypatch, tmp_path, "2027-01-15T07:59:00Z")
    assert code == 1 and "future" in out and "ABCDE" not in out


def test_ui_login_without_a_readable_code_says_why(tmp_path, monkeypatch):
    code, out = _run(monkeypatch, tmp_path, "2027-01-15T08:00:00Z")
    assert code == 1 and "no login code is readable" in out
    path = _publish(tmp_path, b"not json")
    assert _run(monkeypatch, tmp_path, "2027-01-15T08:00:00Z")[0] == 1
    path.unlink()
    target = tmp_path / "elsewhere.json"
    target.write_bytes(_record(issued_at=1_800_000_000.0, expires_at=1_800_000_060.0))
    os.symlink(target, path)
    code, out = _run(monkeypatch, tmp_path, "2027-01-15T08:00:20Z")
    assert code == 1 and "ABCDE" not in out


def test_the_epoch_used_above_is_the_one_the_dates_name():
    from datetime import datetime

    assert datetime.fromisoformat("2027-01-15T08:00:00Z").timestamp() == 1_800_000_000.0
