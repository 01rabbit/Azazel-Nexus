#!/usr/bin/env python3
"""Screenshots of the read-only UI on a systemd rehearsal node (ADR-0007).

Runs in a Chromium container that shares the rehearsal container's network
namespace (`--network container:<node>`), so `127.0.0.1:8443` is that node's
`azazel-ui.socket`. Reuses the DevTools-over-a-pipe driver of
`../ui-browser-2026-10-29/harness.py` (no debugging port). Logs in with a code
an `azazel-operator` member read on the node, captures the named screens and
writes `<label>-<screen>.png` (palette PNG, at most 2600 px high), the text of
each screen under `text/`, and `<label>.json` (each card's title, word, tone
and reason, the summary's four answers, every request the page made). The
code itself is written nowhere. Evidence artefact: no unit installs or runs it.

    python3 shoot.py --code CODE_FILE --out DIR --label LABEL [--narrow] SCREEN...
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ui-browser-2026-10-29"))
from harness import NARROW, UI_PORT, WIDE, Cdp, Page, login, tab  # noqa: E402

CARDS_JS = """(() => [...document.querySelectorAll('article.card')].map(c => ({
  panel: c.closest('section').id.replace('panel-', ''),
  title: (c.querySelector('h3') || {}).textContent,
  word: ((c.querySelector(':scope > .badge .en') || {}).textContent || ''),
  tone: [...c.classList].find(k => k.startsWith('tone-')),
  reason: ((c.querySelector(':scope > .reason .en') || {}).textContent || '')
})))()"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--narrow", action="store_true")
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    parser.add_argument("screens", nargs="+")
    args = parser.parse_args(argv)
    work = Path(os.environ.get("HARNESS_WORK", "/tmp/shoot"))
    work.mkdir(parents=True, exist_ok=True)
    (args.out / "text").mkdir(parents=True, exist_ok=True)
    # A fresh profile each run: a session cookie left by an earlier run would
    # skip the login this run is meant to perform.
    shutil.rmtree(work / f"profile-{args.label}", ignore_errors=True)
    cdp = Cdp(args.chromium, work / f"profile-{args.label}", work / f"{args.label}-netlog.json",
              work / "chromium.log")
    record = {"label": args.label, "chromium": cdp.call("Browser.getVersion")["product"],
              "screens": {}}
    try:
        page = Page(cdp)
        page.size(*(NARROW if args.narrow else WIDE))
        record["login"] = login(page, UI_PORT, args.code)
        page.wait("window.document.querySelectorAll('#panel-overview article.card').length >= 4",
                  what="answers")
        for name in args.screens:
            tab(page, name)
            png = args.out / f"{args.label}-{name}.png"
            record["screens"][name] = {"png": png.name, **page.shot(png)}
            text = page.eval(f"document.getElementById('panel-{name}').innerText")
            (args.out / "text" / f"{args.label}-{name}.txt").write_text(text, encoding="utf-8")
        record["cards"] = page.eval(CARDS_JS)
        record["summary"] = page.eval(
            "fetch('/api/view', {credentials: 'same-origin'}).then(r => r.json())"
            ".then(m => ({summary: m.summary, access: m.access, observers: m.observers,"
            " snapshot_reader: m.snapshot_reader}))")
        record["scroll_width"] = page.eval("[document.documentElement.scrollWidth,"
                                           " document.documentElement.clientWidth]")
        record["requests"] = sorted(set(page.requests()))
        record["green_on_unknownish"] = page.eval(
            "[...document.querySelectorAll('article.card')].filter(c => /tone-ok/.test(c.className)"
            " && /permission_denied|unknown|stale|not_collected|observer_not_enabled/.test("
            "(c.querySelector(':scope > .badge .en')||{}).textContent||'')).length")
    finally:
        cdp.close()
    (args.out / f"{args.label}.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"label": args.label, "screens": list(record["screens"]),
                      "answers": {k: v.get("status") for k, v in
                                  (record["summary"] or {}).get("summary", {}).items()}},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
