from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("render_playbook_page", ROOT / "tools/render_playbook_page.py")
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


def _embedded(page: str) -> dict:
    script = re.search(r"const DATA = (.*?);\nconst LABELS", page, re.DOTALL).group(1)
    return json.loads(script.replace("<\\/", "</"))


def test_baseline_renders_every_entry_without_placeholders():
    page = renderer.render(renderer.DEFAULT_LAYER)
    layer = json.loads(renderer.DEFAULT_LAYER.read_text(encoding="utf-8"))
    data = _embedded(page)
    assert not re.search(r"__(?:DATA|N|VER)__", page)
    assert [e["id"] for e in data["entries"]] == [e["id"] for e in layer["entries"]]
    assert sum(n for _, _, n in data["cats"]) == len(layer["entries"])
    assert f"全 {len(layer['entries'])} 種類" in page


def test_text_cannot_close_the_inline_script(tmp_path):
    layer = json.loads(renderer.DEFAULT_LAYER.read_text(encoding="utf-8"))
    layer["entries"][0]["title"]["en"] = "Ends </script><b>"
    path = tmp_path / "layer.json"
    path.write_text(json.dumps(layer, ensure_ascii=False), encoding="utf-8")
    page = renderer.render(path)
    assert page.count("</script>") == 1
    assert _embedded(page)["entries"][0]["title"]["en"] == "Ends </script><b>"


def test_invalid_layer_produces_no_page(tmp_path):
    path = tmp_path / "layer.json"
    path.write_text(json.dumps({"schema": "unknown"}), encoding="utf-8")
    with pytest.raises(ValueError):
        renderer.render(path)


def test_cli_writes_the_page(tmp_path):
    out = tmp_path / "page.html"
    assert renderer.main(["-o", str(out)]) == 0
    assert "<title>Azazel 既定プレイブック</title>" in out.read_text(encoding="utf-8")
