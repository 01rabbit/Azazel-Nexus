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
    assert "state.open = {}" in login[:login.index("request(")]


def test_model_free_display_is_not_called_failure():
    js = _t("app.js")
    assert "モデル生成の見解：なし" in js and "記録コード（診断用）" in js
    assert '"失敗コード"' not in js


def test_show_login_clears_panels_and_live_text():
    js = _t("app.js")
    login = js[js.index("function showLogin"):]
    head = login[:login.index("request(")]
    assert 'clear($("panel-" + n))' in head
    assert 'state.announced = ""' in head and '$("live").textContent = ""' in head
