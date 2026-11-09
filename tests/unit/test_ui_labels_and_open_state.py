"""Static checks of the read-only UI: tab/summary names and kept open state."""
from pathlib import Path

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
