"""Static checks of the read-only UI: tab/summary names and kept open state."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "runtime/src/azazel_nexus_runtime/ui_static"


def _t(name):
    return (STATIC / name).read_text(encoding="utf-8")


def test_names_are_distinct():
    html, labels, js = _t("index.html"), _t("labels.json"), _t("app.js")
    assert ">専門情報</button>" in html and ">詳細</button>" not in html
    assert '"detail": "専門情報"' in labels and '"detail": "詳細"' not in labels
    assert "「専門情報」画面" in js and "「詳細」画面" not in js
    assert "案内の詳細（競合説明" in js and "詳細（競合説明" not in js.replace("案内の詳細（競合説明", "")
    assert "案内の属性：" in js


def test_open_state_kept_and_dropped():
    js = _t("app.js")
    assert 'addEventListener("toggle"' in js and "state.open[okey]" in js
    assert "gDetail.open = state.open[okey] === true" in js
    login = js[js.index("function showLogin"):]
    assert "discardView();" in login[:login.index("request(")]
    assert "state.open = {}" in js[js.index("function discardView"):js.index("function showRefused")]


def test_model_free_display_is_not_called_failure():
    js = _t("app.js")
    assert "モデル生成の見解：なし" in js and "記録コード（診断用）" in js
    assert '"失敗コード"' not in js


def test_show_login_clears_panels_and_live_text():
    js = _t("app.js")
    login = js[js.index("function showLogin"):]
    assert "discardView();" in login[:login.index("request(")]
    body = js[js.index("function discardView"):js.index("function showRefused")]
    assert 'clear($("panel-" + n))' in body
    assert 'state.announced = ""' in body and '$("live").textContent = ""' in body


def _poll(js):
    return js[js.index("function poll()"):js.index("function selectTab")]


def test_non_200_never_keeps_protected_content_on_refusal_and_never_advances_success_time():
    js = _t("app.js")
    poll = _poll(js)
    # 401 -> login (cleared), 403/421 -> discarded refusal screen, never the stale banner
    assert poll.index("r.status === 401") < poll.index("showLogin(") < poll.index("r.status === 403")
    assert "showRefused(r.status)" in poll
    refused = js[js.index("function showRefused"):js.index("function showLogin")]
    assert "discardView();" in refused and 'kind: "refused"' in refused
    # the success time moves only on a valid 200
    assert js.count("state.lastOk = Date.now()") == 1
    ok = poll[poll.index("r.status === 200"):poll.index("r.status === 404")]
    assert "state.lastOk = Date.now()" in ok and "validModel(r.data)" in ok
    # failures keep the model but say so; they never touch lastOk
    fail = js[js.index("function fail("):js.index("function poll()")]
    assert "lastOk" not in fail and "state.fail = " in fail


def test_late_responses_are_dropped_by_a_generation_counter():
    js = _t("app.js")
    poll = _poll(js)
    assert "var gen = ++state.gen" in poll and poll.count("gen !== state.gen") >= 1
    assert "function fail(gen, kind, status) {\n    if (gen !== state.gen)" in js
    assert "state.gen++" in js[js.index("function showLogin"):js.index("function showApp")]


def test_failure_text_is_fixed_and_never_shows_a_body_or_exception():
    js = _t("app.js")
    reason = js[js.index("function failReason"):js.index("function showConn")]
    assert "r.data" not in reason and "error.message" not in js and "String(e" not in js
    for kind in ("refused", "timeout", "network", "server", "missing", "rejected", "invalid"):
        assert 'f.kind === "%s"' % kind in reason
    assert "現在の状態を確認できたものではありません" in js and "表示できる前回データはありません" in js
    assert "判別できません" in reason  # 404 is not asserted to be a deletion or a temporary gap


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("mode", ["", "start_retry", "unauth", "soc_state"])
def test_poll_behaviour_against_a_stub_dom(tmp_path, mode):
    """Runs the real app.js: failures keep stale content under a notice, refusals discard it,
    a response that arrives after logout never repaints, and the first load retries."""
    from azazel_nexus.ui_model import project
    from azazel_nexus_runtime.ui_serve import browser_json

    model = tmp_path / "model.json"
    model.write_bytes(browser_json(project(None, origin={"kind": "fixture", "notice": "n"},
                                           served_at="2026-11-10T00:00:00Z",
                                           read_reason="status_read_failed")))
    out = subprocess.run(
        ["node", str(Path(__file__).with_name("ui_poll_harness.js")), str(STATIC / "app.js"),
         str(STATIC / "labels.json"), str(model)],
        capture_output=True, text=True, timeout=60, env={**os.environ, "MODE": mode}, check=True)
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert "harness_error" not in result, result
    failed = [k for k, v in result.items() if k != "conn_debug" and v is not True]
    assert not failed and len(result) >= 1, result


def test_handoff_card_uses_epoch_seq_and_labels():
    import json
    js, labels = _t("app.js"), json.loads(_t("labels.json"))
    assert "state.epoch++" in js[js.index("function discardView"):js.index("function showRefused")]
    fetch = js[js.index("function fetchHandoff"):js.index("function handoffCard")]
    assert "epoch === state.epoch && seq === state.hseq" in fetch and "state.gen" not in fetch
    assert "/api/handoff/" in fetch and "X-CSRF" not in fetch
    for key in ("fetch", "busy", "not_found", "failed", "save_json", "save_md", "unexecuted", "reported_none", "time_note"):
        assert labels["handoff"][key], key
    assert "取得できませんでした" in labels["handoff"]["failed"]
    assert set(labels["basis_titles"]) == {"observed", "reported", "mio_inference", "knowledge_ref",
                                           "edge_decision", "execution_result"}
    assert "not_queried" in labels["fullnode"]


def test_handoff_save_uses_server_strings_and_checks_digest():
    js = _t("app.js")
    card = js[js.index("function handoffCard"):js.index("function short(")]
    assert "JSON.stringify" not in card and 'd.files[spec[0]]' in card
    assert "crypto.subtle.digest" in js and "照合" in card and "保存不可（契約不一致）" in _t("labels.json")
    assert "r.status === 429" in js


def test_knowledge_dependency_and_fullnode_vocabulary_is_labelled():
    import json
    labels = json.loads(_t("labels.json"))
    assert {"not_queried", "received", "unavailable", "unknown"} <= set(labels["fullnode"])
    assert {"available", "partial", "absent", "not_queried", "timeout", "expired", "rejected",
            "unavailable", "unknown"} <= set(labels["kdep"])
    assert "fast_assistance なし" in labels["handoff"]["fast_missing"]
    assert "fullNodeStatus(fastAll)" in _t("app.js")


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_handoff_card_behaviour_in_a_stub_dom(tmp_path):
    """Legacy-layout fetch, stale seq/epoch/refusal handling, verified-only save, timeout with previous result."""
    from azazel_nexus.ui_model import project
    from azazel_nexus_runtime.ui_serve import browser_json

    model = tmp_path / "model.json"
    model.write_bytes(browser_json(project(None, origin={"kind": "fixture", "notice": "n"},
                                           served_at="2026-11-10T00:00:00Z", read_reason="status_read_failed")))
    out = subprocess.run(["node", str(Path(__file__).resolve().parents[2] / "tests" / "js" / "handoff_card.test.js"),
                          str(STATIC / "app.js"), str(STATIC / "labels.json"), str(model)],
                         capture_output=True, text=True, timeout=60, check=False)
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert "harness_error" not in result, result
    assert len(result) == 6 and all(v is True for v in result.values()), result
