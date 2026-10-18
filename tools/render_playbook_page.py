"""Render a reasoning-playbook layer as a single human-readable HTML page.

Review aid only: the page reads the layer, it never admits, signs, composes or
installs one. The layer is checked with tools/check_playbooks.py first, so a
malformed layer produces no page. Output is one self-contained file (styles,
script and data inline; fonts from Google Fonts with system fallbacks).
"""

from __future__ import annotations

import argparse
import html
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_LAYER = ROOT / "playbooks/baseline/azazel-baseline.json"
TEMPLATE = HERE / "playbook_page/template.html"
CATEGORIES = {
    "authentication": "認証", "network": "通信", "endpoint": "端末", "web_application": "Webアプリ",
    "email": "メール", "cloud": "クラウド", "vulnerability": "脆弱性", "data_exfiltration": "情報持ち出し",
    "insider": "内部不正", "availability": "可用性・DoS", "deception": "おとり",
    "supply_chain": "サプライチェーン", "edge_network": "ネットワーク周辺",
}
SOURCES = {
    "mitre-attack": "ATT&CK", "mitre-d3fend": "D3FEND", "owasp-top10-2021": "OWASP Top 10",
    "owasp-asvs": "OWASP ASVS", "owasp-cheatsheet": "OWASP CS", "nist-sp800-61r3": "NIST 800-61",
    "cisa-kev": "CISA KEV",
}


def _checker():
    spec = importlib.util.spec_from_file_location("check_playbooks", HERE / "check_playbooks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def page_data(layer: dict) -> dict:
    entries = [{
        "id": e["id"], "status": e["status"], "cat": e["category"],
        "catja": CATEGORIES.get(e["category"], e["category"]), "title": e["title"],
        "refs": [{"s": SOURCES.get(r["source"], r["source"]), "src": r["source"], "id": r["id"]}
                 for r in e["references"]],
        "kw": e["match"]["keywords"], "tech": e["match"]["attack_techniques"], "g": e["guidance"],
    } for e in layer["entries"]]
    counts = {c: sum(1 for e in entries if e["cat"] == c) for c in CATEGORIES}
    return {"entries": entries, "cats": [[c, CATEGORIES[c], n] for c, n in counts.items() if n],
            "version": layer["version"], "library": layer["library_id"]}


def render(layer_path: Path, template_path: Path = TEMPLATE) -> str:
    layer = _checker().check_path(layer_path)
    data = page_data(layer)
    # Inline JSON inside <script>: "</" must not close the element early.
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return (template_path.read_text(encoding="utf-8")
            .replace("__DATA__", payload)
            .replace("__N__", str(len(data["entries"])))
            .replace("__VER__", html.escape(layer["version"])))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("layer", nargs="?", type=Path, default=DEFAULT_LAYER)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.write_text(render(args.layer), encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
