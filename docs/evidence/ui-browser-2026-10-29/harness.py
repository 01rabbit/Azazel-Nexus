#!/usr/bin/env python3
"""Headless-Chromium evidence for the read-only UI (U6). Container only.

Runs **inside one container started with `--network none`**: the UI (live
mode over a scratch `AZAZEL_ROOT`, and fixture mode for the XSS check) and
Chromium share the container's loopback. Chromium is driven through the
DevTools protocol over a pipe (`--remote-debugging-pipe`), so no debugging
port is opened. The page is logged into with the code the UI wrote, typed
through `Input.insertText` and submitted with the Enter key.

    python3 harness.py --repo /w/repo --out /out [--only STATE ...]

Inputs are written with the product's own writers and builders
(`SnapshotWriter`, `operator_snapshots.*_snapshot`, the NOC observer against
this container's netlink, and the status read-model test builders for the
Edge loop snapshots). They are **fixtures written to disk**, not the output
of running daemons; the UI reads them exactly as on a node.

Writes PNG screenshots, the text of each screen (`innerText`), a per-card
tone table and `result.json` (every request Chromium's pages made, the
NetLog summary, the checks). This file is an evidence artefact: no unit
installs or runs it.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

UI_PORT = 8443
XSS_PORT = 8444
SCREENS = ("overview", "incidents", "noc", "knowledge", "setup")
WIDE = (1280, 1000)
NARROW = (360, 780)
OVERSIZE = 300 * 1024
# The cards each snapshot feeds (overview screen titles, app.js).
SNAPSHOT_CARDS = ("通信（NOC）", "AI 経路（運用者向け snapshot）",
                  "Knowledge Lite（運用者向け snapshot）", "サービス",
                  "Edge 受信（intake）", "説明器（explainer）")
XSS_TEXT = '<img src=x onerror="window.__azxss=1"><script>window.__azxss=2</script>'


# -- the DevTools protocol over a pipe ------------------------------------------


class Cdp:
    """Chromium's `--remote-debugging-pipe`: NUL-terminated JSON on fds 3/4."""

    def __init__(self, chromium: str, profile: Path, netlog: Path, log: Path):
        to_child_r, self._w = os.pipe()
        self._r, from_child_w = os.pipe()
        args = [chromium, "--headless=new", "--remote-debugging-pipe", "--no-sandbox",
                "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                "--disable-background-networking", "--disable-component-update",
                "--disable-sync", "--disable-default-apps", "--disable-extensions",
                # Chromium's own background services (component updater, network
                # time, autofill server, safe browsing). Off, so that the NetLog
                # holds only what the page asked for.
                "--disable-features=NetworkTimeServiceQuerying,AutofillServerCommunication,"
                "OptimizationHints,MediaRouter,Translate,CertificateTransparencyComponentUpdater",
                "--disable-client-side-phishing-detection", "--no-pings",
                "--disable-domain-reliability", "--safebrowsing-disable-auto-update",
                "--disable-field-trial-config",
                "--hide-scrollbars", "--lang=ja-JP", "--force-device-scale-factor=1",
                "--enable-logging=stderr", "--v=0",
                f"--log-net-log={netlog}", "--net-log-capture-mode=Default",
                f"--user-data-dir={profile}", "about:blank"]

        # Chromium reads commands on fd 3 and writes replies on fd 4; bash (dash
        # takes single-digit descriptors only)
        # places the two pipe ends there and replaces itself with Chromium.
        wrapper = ["/bin/bash", "-c", f'exec "$0" "$@" 3<&{to_child_r} 4>&{from_child_w}'] + args
        self.log = open(log, "wb")
        self.proc = subprocess.Popen(wrapper, pass_fds=(to_child_r, from_child_w),
                                     stdout=self.log, stderr=subprocess.STDOUT)
        os.close(to_child_r)
        os.close(from_child_w)
        self._id = 0
        self._lock = threading.Lock()
        self._cond = threading.Condition()
        self._replies: dict[int, dict] = {}
        self.events: list[dict] = []
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        buf = b""
        while True:
            chunk = os.read(self._r, 65536)
            if not chunk:
                return
            buf += chunk
            while b"\0" in buf:
                raw, buf = buf.split(b"\0", 1)
                msg = json.loads(raw)
                with self._cond:
                    if "id" in msg:
                        self._replies[msg["id"]] = msg
                    else:
                        self.events.append(msg)
                    self._cond.notify_all()

    def call(self, method, params=None, session=None, timeout=30.0):
        with self._lock:
            self._id += 1
            mid = self._id
        msg = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        os.write(self._w, json.dumps(msg).encode() + b"\0")
        deadline = time.monotonic() + timeout
        with self._cond:
            while mid not in self._replies:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(method)
                self._cond.wait(left)
            reply = self._replies.pop(mid)
        if "error" in reply:
            raise RuntimeError(f"{method}: {reply['error']}")
        return reply.get("result", {})

    def close(self):
        try:
            self.call("Browser.close", timeout=10)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


class Page:
    def __init__(self, cdp: Cdp):
        self.cdp = cdp
        target = cdp.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = cdp.call("Target.attachToTarget",
                                {"targetId": target, "flatten": True})["sessionId"]
        for domain in ("Page", "Network", "Runtime", "DOM", "CSS", "Log"):
            self.call(f"{domain}.enable")
        self.call("Emulation.setTimezoneOverride", {"timezoneId": "Asia/Tokyo"})
        self.call("Emulation.setLocaleOverride", {"locale": "ja-JP"})

    def call(self, method, params=None, timeout=30.0):
        return self.cdp.call(method, params, session=self.session, timeout=timeout)

    def eval(self, expression):
        result = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                                "awaitPromise": True})
        if "exceptionDetails" in result:
            raise RuntimeError(json.dumps(result["exceptionDetails"])[:500])
        return result["result"].get("value")

    def wait(self, expression, timeout=30.0, what=""):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.eval(expression):
                return
            time.sleep(0.25)
        raise TimeoutError(what or expression)

    def size(self, width, height):
        self.call("Emulation.setDeviceMetricsOverride",
                  {"width": width, "height": height, "deviceScaleFactor": 1,
                   "mobile": width < 600})

    def navigate(self, url):
        self.call("Page.navigate", {"url": url})
        self.wait("document.readyState === 'complete'", what="load " + url)

    def shot(self, path: Path, max_height: int = 2600):
        """The whole page (up to `max_height` CSS px), as a palette PNG."""

        metrics = self.call("Page.getLayoutMetrics")["cssContentSize"]
        width = int(self.eval("document.documentElement.clientWidth"))
        height = min(int(metrics["height"]), max_height)
        data = self.call("Page.captureScreenshot", {
            "format": "png", "captureBeyondViewport": True,
            "clip": {"x": 0, "y": 0, "width": width, "height": height, "scale": 1}})["data"]
        path.write_bytes(base64.b64decode(data))
        raw = path.stat().st_size
        shrink(path)
        return {"bytes": path.stat().st_size, "raw_bytes": raw, "width": width,
                "height": height, "page_height": int(metrics["height"])}

    def requests(self):
        return [e["params"]["request"]["url"] for e in self.cdp.events
                if e.get("sessionId") == self.session
                and e.get("method") == "Network.requestWillBeSent"]

    def console(self):
        out = []
        for e in self.cdp.events:
            if e.get("sessionId") != self.session:
                continue
            if e.get("method") == "Runtime.consoleAPICalled":
                out.append({"kind": "console", "type": e["params"]["type"]})
            elif e.get("method") == "Runtime.exceptionThrown":
                out.append({"kind": "exception",
                            "text": e["params"]["exceptionDetails"].get("text")})
            elif e.get("method") == "Log.entryAdded":
                entry = e["params"]["entry"]
                out.append({"kind": "log", "level": entry["level"], "source": entry["source"],
                            "text": entry["text"][:200]})
        return out


def shrink(path: Path, colors: int = 48) -> None:
    """Reduce a screenshot to a palette PNG (text stays sharp; size drops ~4x)."""

    from PIL import Image

    with Image.open(path) as image:
        small = image.convert("RGB").quantize(colors=colors, method=Image.Quantize.MEDIANCUT,
                                              dither=Image.Dither.NONE)
    small.save(path, format="PNG", optimize=True)


# -- the inputs the UI reads -------------------------------------------------------


class Node:
    """A scratch node root; every snapshot written with the product's writers."""

    def __init__(self, root: Path):
        self.root = root
        from azazel_nexus import runtime_paths as paths

        self.paths = {
            "edge_intake_status": paths.edge_intake_status_path(),
            "incident_explain_status": paths.incident_explain_status_path(),
            "incident_recent": paths.incident_recent_path(),
            "audit_status": paths.audit_status_path(),
            "knowledge_status": paths.knowledge_status_path(),
            "mio_status": paths.mio_status_path(),
            "units_status": paths.units_status_path(),
            "noc_status": paths.noc_status_path(),
        }
        for path in self.paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        self.scratch = root / "scratch"
        self.scratch.mkdir(exist_ok=True)
        self._fresh = threading.Event()
        self._lock = threading.Lock()
        threading.Thread(target=self._keep_fresh, daemon=True).start()

    def build(self, written_at: float, claims: bool = False) -> dict[str, dict]:
        """Every snapshot, written at `written_at`.

        By default the Knowledge and M.I.O. snapshots say what knowledge-lited
        and mio-entryd would write over this scratch node, which has no Lite
        store and no route ledger: `unavailable`/`trust_unreadable` and "no
        record yet" -- the same as the page's direct reads of the same node.
        `claims=True` writes snapshots that claim `available` and a recorded
        reading instead, which the direct reads cannot confirm (the mismatch
        state).
        """
        import test_status_view as tsv
        from azazel_nexus import operator_snapshots as snap
        from azazel_nexus_runtime import noc_snapshot

        tsv.NOW = written_at  # the builders' other times follow the write time
        units = {}
        for unit in snap.OBSERVED_UNITS:
            units[unit] = {"LoadState": "masked", "ActiveState": "inactive", "SubState": "dead"}
        for unit in ("azazel-activated.service", "azazel-auditd.service"):
            units[unit] = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
        units["azazel-mio-entryd.service"] = {"LoadState": "loaded", "ActiveState": "failed",
                                              "SubState": "failed"}
        return {
            "edge_intake_status": tsv._intake(written_at - 2, decoy={"accepted": 1,
                                              "last_accepted_at": written_at - 9}),
            "incident_explain_status": tsv._explainer(self.scratch, written_at - 1,
                                                      knowledge_available=True),
            "incident_recent": tsv._recent(written_at - 1),
            "audit_status": tsv._audit(written_at - 20),
            "knowledge_status": snap.knowledge_snapshot(
                {"state": "available", "reason_code": "available", "generation": 5,
                 "freshness": "current"} if claims else
                {"state": "unavailable", "reason_code": "trust_unreadable", "generation": None,
                 "freshness": "absent"}, written_at),
            "mio_status": snap.mio_snapshot(
                {"state": "CORE", "reasons": {
                    "profile": "LITE", "resource": "core_reserve_unmeasured",
                    "trust": "not-checked", "topology": "no_verified_egress",
                    "health": {"local": "not_admitted", "remote": "unavailable"}}} if claims else None,
                time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(written_at - 60))
                if claims else None, uncertain=False, written_at=written_at),
            "units_status": snap.units_snapshot(units, written_at),
            # The real passive observer, on this container's netlink and sysfs.
            "noc_status": noc_snapshot.observe(
                __import__("azazel_nexus_runtime.noc_observe", fromlist=["collect"]).collect,
                clock=lambda: written_at),
        }

    @staticmethod
    def body(value) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def _clean(self, path: Path):
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)

    def _place(self, path: Path, data: bytes):
        tmp = path.with_name(".harness-" + path.name)
        tmp.write_bytes(data)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)

    def write(self, mode: str, now: float | None = None):
        """Put every snapshot into `mode` (fresh, mismatch, absent, broken, stale, future,
        symlink, oversize)."""

        self._fresh.clear()
        now = time.time() if now is None else now
        with self._lock:
            if mode == "fresh":
                values = self.build(now)
            elif mode == "mismatch":
                values = self.build(now, claims=True)
            elif mode == "stale":
                values = self.build(now - 3600)
            elif mode == "future":
                values = self.build(now + 3600)
            else:
                values = self.build(now)
            for name, path in self.paths.items():
                self._clean(path)
                data = self.body(values[name])
                if mode == "absent":
                    continue
                if mode == "broken":
                    data = b'{"schema":'
                elif mode == "oversize":
                    data = data[:-1] + b" " * OVERSIZE + b"\n"
                if mode == "symlink":
                    real = self.scratch / f"elsewhere-{name}.json"
                    real.write_bytes(data)
                    path.symlink_to(real)
                else:
                    self._place(path, data)
        if mode in ("fresh", "mismatch"):
            self._fresh.set()

    def _keep_fresh(self):
        # The Edge loop snapshots go stale after 30 s; a daemon rewrites them.
        while True:
            self._fresh.wait()
            time.sleep(3)
            if self._fresh.is_set():
                with self._lock:
                    values = self.build(time.time())
                    for name in ("edge_intake_status", "incident_explain_status",
                                 "incident_recent"):
                        if self._fresh.is_set():
                            self._place(self.paths[name], self.body(values[name]))


def xss_fixture(repo: Path, out: Path) -> Path:
    value = json.loads((repo / "tests/fixtures/ui/demo-status-view.json").read_text())
    sections = value["sections"]
    sections["fabric"]["status"] = XSS_TEXT
    sections["fabric"]["reason_code"] = XSS_TEXT
    sections["fabric"]["version"] = XSS_TEXT
    rows = sections["edge_loop"]["recent"]["snapshot"]["incidents"]
    for row in rows:
        ex = row.get("explanation") or {}
        if ex.get("summary"):
            ex["summary"] = XSS_TEXT
        for ref in ex.get("knowledge_refs") or []:
            ref["name"] = XSS_TEXT
    rows[0]["incident_id"] = XSS_TEXT
    path = out / "xss-status-view.json"
    path.write_text(json.dumps(value, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


# -- the page ---------------------------------------------------------------------


CARDS_JS = """(() => [...document.querySelectorAll('section[role=tabpanel]')].flatMap(p =>
  [...p.querySelectorAll(':scope > .grid > article.card, :scope article.card')].map(c => ({
    panel: p.id.replace('panel-', ''),
    title: (c.querySelector('h3') || {}).textContent || '',
    tone: ([...c.classList].find(k => k.startsWith('tone-')) || '').replace('tone-', ''),
    word: ((c.querySelector(':scope > .badge .ja') || {}).textContent || ''),
    en: ((c.querySelector(':scope > .badge .en') || {}).textContent || ''),
    mark: ((c.querySelector(':scope > .badge .mark') || {}).textContent || ''),
    reason: ((c.querySelector(':scope > .reason .en') || {}).textContent || ''),
    ok_badges_inside: c.querySelectorAll('.badge.tone-ok').length
  }))))()"""


def login(page: Page, port: int, login_file: Path) -> dict:
    page.navigate(f"http://127.0.0.1:{port}/")
    page.wait("!document.getElementById('login').hidden", what="login form")
    for _ in range(40):
        if login_file.exists():
            break
        time.sleep(0.25)
    code = json.loads(login_file.read_text())["code"]
    page.eval("document.getElementById('login-code').focus()")
    page.call("Input.insertText", {"text": code})
    for kind in ("keyDown", "keyUp"):
        page.call("Input.dispatchKeyEvent", {"type": kind, "key": "Enter", "code": "Enter",
                                             "windowsVirtualKeyCode": 13, "text": "\r"
                                             if kind == "keyDown" else ""})
    page.wait("!document.getElementById('panels').hidden && "
              "document.querySelectorAll('#panel-overview article.card').length > 3",
              what="logged in")
    # The code itself is not kept in any output.
    return {"logged_in": True, "login_form_hidden": page.eval(
        "document.getElementById('login').hidden")}


def tab(page: Page, name: str):
    page.eval(f"document.getElementById('tab-{name}').click()")
    page.wait(f"!document.getElementById('panel-{name}').hidden", what="tab " + name)
    page.eval("window.scrollTo(0, 0)")
    time.sleep(0.3)


def capture(page: Page, out: Path, label: str, screens=SCREENS) -> dict:
    record = {"label": label, "screens": {}}
    for name in screens:
        tab(page, name)
        png = out / f"{label}-{name}.png"
        size = page.shot(png)
        text = page.eval(f"document.getElementById('panel-{name}').innerText")
        (out / "text").mkdir(exist_ok=True)
        (out / "text" / f"{label}-{name}.txt").write_text(text, encoding="utf-8")
        record["screens"][name] = {"png": png.name, **size}
    record["cards"] = page.eval(CARDS_JS)
    record["unlabelled_field_names"] = page.eval(
        "[...document.querySelectorAll('.key')].filter(k => k.textContent.startsWith('（未登録の項目名）'))"
        ".map(k => k.querySelector('.en').textContent)")
    record["banner"] = page.eval("document.getElementById('origin').innerText")
    record["conn"] = page.eval("document.getElementById('conn').innerText")
    tab(page, "overview")
    return record


def snapshot_cards(cards) -> list[dict]:
    return [c for c in cards if c["panel"] == "overview" and c["title"] in SNAPSHOT_CARDS]


def wait_for(page: Page, predicate_js: str, what: str, timeout=30.0):
    page.wait(predicate_js, timeout=timeout, what=what)


def card_tone_js(title: str) -> str:
    return ("(() => { const c = [...document.querySelectorAll('#panel-overview article.card')]"
            f".find(c => (c.querySelector('h3')||{{}}).textContent === {json.dumps(title)});"
            " return c ? [...c.classList].find(k => k.startsWith('tone-')) : null; })()")


def fonts_of(page: Page, selector: str) -> list:
    doc = page.call("DOM.getDocument", {"depth": 0})["root"]["nodeId"]
    node = page.call("DOM.querySelector", {"nodeId": doc, "selector": selector})["nodeId"]
    return page.call("CSS.getPlatformFontsForNode", {"nodeId": node})["fonts"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--chromium", default="/usr/bin/chromium")
    ap.add_argument("--only", nargs="*", default=None,
                    help="run only these steps (normal, narrow, mismatch, degraded, recovered, xss)")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--attach-code", type=Path, default=None,
                    help="do not start a UI: log into the one already listening on "
                         "127.0.0.1:8443 (the systemd rehearsal, sharing that "
                         "container's network namespace) with the code in this file")
    args = ap.parse_args(argv)
    if args.attach_code is not None:
        return attach(args)
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    work = Path(os.environ.get("HARNESS_WORK", "/w/harness"))
    root = Path(os.environ["AZAZEL_ROOT"])
    work.mkdir(parents=True, exist_ok=True)
    steps = set(args.only or ("normal", "narrow", "mismatch", "degraded", "recovered", "xss"))
    pre = args.prefix

    node = Node(root)
    node.write("fresh")
    login_file = work / "ui-login" / "login-code.json"
    login_file.parent.mkdir(exist_ok=True)
    env = dict(os.environ)
    ui = subprocess.Popen(
        [sys.executable, str(args.repo / "tools/ui_socket_activate.py"), "--port", str(UI_PORT),
         "--", sys.executable, "-m", "azazel_nexus_runtime.ui_serve",
         "--login-file", str(login_file)],
        env=env, stdout=open(work / "ui.log", "wb"), stderr=subprocess.STDOUT)
    procs = [ui]
    xss_ui = None
    if "xss" in steps:
        xss_login = work / "ui-login-xss" / "login-code.json"
        xss_login.parent.mkdir(exist_ok=True)
        fixture = xss_fixture(args.repo, work)
        xss_ui = subprocess.Popen(
            [sys.executable, str(args.repo / "tools/ui_socket_activate.py"),
             "--port", str(XSS_PORT), "--", sys.executable, "-m",
             "azazel_nexus_runtime.ui_serve", "--fixture", str(fixture),
             "--login-file", str(xss_login)],
            env=env, stdout=open(work / "ui-xss.log", "wb"), stderr=subprocess.STDOUT)
        procs.append(xss_ui)
    time.sleep(1.5)

    cdp = Cdp(args.chromium, work / "profile", out / f"{pre}netlog.json", work / "chromium.log")
    result = {"chromium": cdp.call("Browser.getVersion"), "states": {}, "checks": {}}
    failures = []

    def check(name, ok, detail=None):
        result["checks"][name] = {"ok": bool(ok), "detail": detail}
        if not ok:
            failures.append(name)

    try:
        page = Page(cdp)
        page.size(*WIDE)
        result["login"] = login(page, UI_PORT, login_file)
        result["fonts_ja_heading"] = fonts_of(page, "#panel-overview article.card h3")
        result["page_lang"] = page.eval("document.documentElement.lang")

        if "normal" in steps:
            node.write("fresh")
            time.sleep(3)
            wait_for(page, card_tone_js("Edge 受信（intake）") + " === 'tone-ok'", "fresh intake")
            rec = capture(page, out, pre + "normal")
            result["states"]["normal"] = rec
            ok_cards = [c["title"] for c in snapshot_cards(rec["cards"]) if c["tone"] == "ok"]
            check("normal.fresh_snapshots_shown", "Edge 受信（intake）" in ok_cards, ok_cards)

        if "narrow" in steps:
            node.write("fresh")
            page.size(*NARROW)
            time.sleep(3)
            rec = capture(page, out, pre + "narrow", screens=("overview", "incidents"))
            rec["scroll_width"] = page.eval("document.documentElement.scrollWidth")
            rec["client_width"] = page.eval("document.documentElement.clientWidth")
            result["states"]["narrow"] = rec
            check("narrow.no_horizontal_scroll", rec["scroll_width"] <= rec["client_width"],
                  [rec["scroll_width"], rec["client_width"]])
            page.size(*WIDE)

        if "mismatch" in steps:
            node.write("mismatch")
            wait_for(page, card_tone_js("Knowledge Lite（運用者向け snapshot）") + " === 'tone-ok'",
                     "mismatch", timeout=40)
            time.sleep(1)
            rec = capture(page, out, pre + "mismatch", screens=("overview",))
            rec["notes"] = page.eval(
                "[...document.querySelectorAll('#panel-overview article.card')].map(c => ["
                "(c.querySelector('h3')||{}).textContent, [...c.querySelectorAll(':scope > .note, :scope > .path')]"
                ".map(n => n.textContent)]).filter(r => r[1].length)")
            result["states"]["mismatch"] = rec
            said = {title: " ".join(notes) for title, notes in rec["notes"]}
            check("mismatch.both_cards_say_they_disagree", all(
                "一致しません" in said.get(t, "") for t in (
                    "Knowledge Lite", "Knowledge Lite（運用者向け snapshot）",
                    "AI 経路（M.I.O.）", "AI 経路（運用者向け snapshot）")), said)

        if "degraded" in steps:
            for mode in ("absent", "broken", "stale", "future", "symlink", "oversize"):
                node.write(mode)
                # Wait until every snapshot card has left the fresh state.
                wait_for(page, "(" + " && ".join(
                    card_tone_js(t) + " !== 'tone-ok'" for t in SNAPSHOT_CARDS) + ")",
                    "degraded " + mode, timeout=40)
                time.sleep(8)  # the view cache (2 s) and the page's poll (5 s)
                rec = capture(page, out, pre + "degraded-" + mode, screens=("overview",))
                rec["overview_text_has_ok_word_in_snapshot_cards"] = page.eval(
                    "[...document.querySelectorAll('#panel-overview article.card')].filter(c =>"
                    f" {json.dumps(list(SNAPSHOT_CARDS))}.includes((c.querySelector('h3')||{{}})"
                    ".textContent)).some(c => c.innerText.includes('正常'))")
                result["states"]["degraded-" + mode] = rec
                cards = snapshot_cards(rec["cards"])
                green = [c["title"] for c in cards if c["tone"] == "ok" or c["ok_badges_inside"]]
                check(f"degraded.{mode}.no_green", not green and len(cards) == len(SNAPSHOT_CARDS)
                      and not rec["overview_text_has_ok_word_in_snapshot_cards"],
                      {c["title"]: [c["tone"], c["word"], c["en"], c["reason"]] for c in cards})

        if "recovered" in steps:
            node.write("fresh")
            wait_for(page, card_tone_js("Edge 受信（intake）") + " === 'tone-ok'",
                     "recovered intake", timeout=40)
            time.sleep(1)
            rec = capture(page, out, pre + "recovered", screens=("overview",))
            result["states"]["recovered"] = rec
            check("recovered.same_as_normal",
                  {c["title"]: c["tone"] for c in snapshot_cards(rec["cards"])} ==
                  {c["title"]: c["tone"] for c in snapshot_cards(
                      result["states"].get("normal", rec)["cards"])},
                  {c["title"]: c["tone"] for c in snapshot_cards(rec["cards"])})

        result["requests_live"] = page.requests()
        result["console_live"] = page.console()

        if "xss" in steps:
            xpage = Page(cdp)
            xpage.size(*WIDE)
            xpage.eval("0")
            login(xpage, XSS_PORT, work / "ui-login-xss" / "login-code.json")
            xpage.eval("window.__azcsp = 0; document.addEventListener("
                       "'securitypolicyviolation', () => { window.__azcsp++; })")
            rec = capture(xpage, out, pre + "xss", screens=("overview", "incidents"))
            probe = xpage.eval("""(() => ({
              flag: window.__azxss === undefined ? null : window.__azxss,
              csp_violations_after_load: window.__azcsp,
              images: document.images.length,
              scripts: document.scripts.length,
              script_srcs: [...document.scripts].map(s => s.getAttribute('src')),
              text_occurrences: (document.body.textContent.split('<img src=x onerror=').length - 1),
              fabric_card: (() => { const c = [...document.querySelectorAll('#panel-overview article.card')]
                .find(c => (c.querySelector('h3')||{}).textContent === 'Fabric 状態表示');
                return c ? {tone: [...c.classList].find(k => k.startsWith('tone-')),
                            word: (c.querySelector('.badge .ja')||{}).textContent,
                            en: (c.querySelector('.badge .en')||{}).textContent} : null; })()
            }))()""")
            rec["probe"] = probe
            result["states"]["xss"] = rec
            result["requests_xss"] = xpage.requests()
            result["console_xss"] = xpage.console()
            check("xss.not_executed", probe["flag"] is None and probe["images"] == 0
                  and probe["scripts"] == 1 and probe["text_occurrences"] >= 3, probe)
            check("xss.fabric_status_not_green", probe["fabric_card"]
                  and probe["fabric_card"]["tone"] != "tone-ok", probe["fabric_card"])
    finally:
        cdp.close()
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    unlabelled = sorted({name for rec in result["states"].values()
                         for name in rec.get("unlabelled_field_names", [])})
    check("labels.every_field_name_has_a_japanese_label", not unlabelled, unlabelled)
    allowed = (f"http://127.0.0.1:{UI_PORT}/", f"http://127.0.0.1:{XSS_PORT}/")
    page_reqs = result.get("requests_live", []) + result.get("requests_xss", [])
    external = [u for u in page_reqs if not u.startswith(allowed)]
    result["page_requests_total"] = len(page_reqs)
    result["page_requests_external"] = external
    check("network.page_requests_all_loopback", not external, external)
    result["netlog"] = netlog_summary(out / f"{pre}netlog.json")
    check("network.netlog_page_initiated_all_loopback",
          not result["netlog"]["page_initiated_external"],
          result["netlog"]["page_initiated_external"])
    check("network.netlog_no_external_request_completed",
          not result["netlog"]["external_completed"], result["netlog"]["external_completed"])
    result["failures"] = failures
    (out / f"{pre}result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
    print(json.dumps({"failures": failures, "checks": {k: v["ok"] for k, v in
                                                      result["checks"].items()}}, indent=1))
    return 1 if failures else 0


def attach(args) -> int:
    """Log into an already running `azazel-ui.socket` and capture every screen."""

    out: Path = args.out
    work = Path(os.environ.get("HARNESS_WORK", "/w/harness"))
    work.mkdir(parents=True, exist_ok=True)
    pre = args.prefix
    cdp = Cdp(args.chromium, work / "profile", out / f"{pre}netlog.json", work / "chromium.log")
    result = {"chromium": cdp.call("Browser.getVersion"), "states": {}}
    try:
        page = Page(cdp)
        page.size(*WIDE)
        result["login"] = login(page, UI_PORT, args.attach_code)
        rec = capture(page, out, pre + "systemd")
        rec["access_words"] = page.eval(
            "[...document.querySelectorAll('article.card')].map(c => [c.closest('section').id,"
            " (c.querySelector('h3')||{}).textContent, (c.querySelector(':scope > .badge .en')||{})"
            ".textContent, (c.querySelector(':scope > .reason .en')||{}).textContent])")
        result["states"]["systemd"] = rec
        result["requests"] = page.requests()
        result["console"] = page.console()
    finally:
        cdp.close()
    result["netlog"] = netlog_summary(out / f"{pre}netlog.json")
    (out / f"{pre}result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
    denied = [w for w in rec["access_words"] if w[2] == "permission_denied"]
    print(json.dumps({"permission_denied_cards": denied}, ensure_ascii=False, indent=1))
    return 0 if denied else 1


def netlog_summary(path: Path) -> dict:
    """Every URL request in Chromium's NetLog, split by who started it.

    A request the page made carries the page's origin as `initiator`; one the
    browser process makes for itself (component updater and the like) says
    `not an origin`. Each request's final `net_error` is kept (0 = completed;
    -106 = ERR_INTERNET_DISCONNECTED under `--network none`).
    """

    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.rstrip().endswith("}"):
        text = text.rstrip().rstrip(",") + "]}"
    data = json.loads(text)
    kinds = {v: k for k, v in data["constants"]["logEventTypes"].items()}
    requests: dict[int, dict] = {}
    for event in data.get("events", []):
        kind = kinds.get(event["type"])
        params = event.get("params") or {}
        sid = event["source"]["id"]
        if kind == "URL_REQUEST_START_JOB" and "url" in params:
            requests[sid] = {"url": params["url"], "initiator": params.get("initiator"),
                             "method": params.get("method"), "net_error": None,
                             "annotation": None}
        elif kind == "REQUEST_ALIVE" and sid in requests and "net_error" in params:
            requests[sid]["net_error"] = params["net_error"]
        elif kind == "REQUEST_ALIVE" and "traffic_annotation" in params:
            requests.setdefault(sid, {"url": params.get("url"), "initiator": None,
                                      "method": None, "net_error": None, "annotation": None})
            requests[sid]["annotation"] = params["traffic_annotation"]
    rows = [r for r in requests.values() if r["url"]]
    loopback = ("http://127.0.0.1:",)
    page = [r for r in rows if (r["initiator"] or "").startswith(loopback)]
    browser = [r for r in rows if r not in page]

    def short(r):
        url = r["url"].split("?", 1)[0]
        return {"url": url, "initiator": r["initiator"], "method": r["method"],
                "net_error": r["net_error"]}

    return {"events": len(data.get("events", [])), "requests": len(rows),
            "page_initiated": [short(r) for r in page],
            "page_initiated_external": [short(r) for r in page
                                        if not r["url"].startswith(loopback)],
            "browser_initiated": [short(r) for r in browser],
            "browser_initiated_completed": [short(r) for r in browser
                                            if r["net_error"] not in (-106, None)
                                            and not r["url"].startswith(loopback)],
            # The navigations typed into the browser (no initiator) are the
            # page's own URL; anything else here is the browser's own service.
            "external_completed": [short(r) for r in rows if not r["url"].startswith(loopback)
                                   and r["net_error"] == 0]}


if __name__ == "__main__":
    sys.exit(main())
