// Drives the real app.js against a stub DOM and a scripted fetch. Prints one JSON object of named checks.
const fs = require("fs"), vm = require("vm"), path = require("path");
const [,, jsPath, labelsPath, modelPath] = process.argv;
const MODEL = JSON.parse(fs.readFileSync(modelPath, "utf8")), LABELS = JSON.parse(fs.readFileSync(labelsPath, "utf8"));
class N {
  constructor(tag) { this.tag = tag; this.children = []; this._t = ""; this.hidden = false; this.className = ""; this.attrs = {}; this.ls = {}; this.value = ""; this.dataset = {}; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); }
  set textContent(v) { this.children = []; this._t = String(v); }
  get textContent() { return this._t + this.children.map(c => c.textContent).join(""); }
  get innerText() { return this.textContent; }
  setAttribute(k, v) { this.attrs[k] = v; } getAttribute(k) { return this.attrs[k]; }
  addEventListener(t, f) { this.ls[t] = f; } focus() {} closest() { return null; } querySelectorAll() { return []; }
}
const nodes = {}; const doc = { getElementById: id => nodes[id] || (nodes[id] = new N(id)), createElement: t => new N(t),
  createTextNode: s => { const n = new N("#t"); n._t = String(s); return n; }, addEventListener() {} };
let clock = 1e12, timers = [];
const sandbox = { Node: N, document: doc, window: { scrollY: 0, scrollTo() {} }, console,
  setTimeout: (f, ms) => { const t = { f, at: clock + ms, id: timers.length + 1 }; timers.push(t); return t.id; },
  clearTimeout: id => { timers = timers.filter(t => t.id !== id); },
  Date: class extends Date { static now() { return clock; } }, AbortController, Promise, JSON, Object, Array, Math, String, Number, isNaN, isFinite, Error };
let script = {}; // path -> async function(opts) -> {status, body|invalid}
sandbox.fetch = async (p, o) => { const h = script[p]; if (!h) throw new TypeError("no route " + p); const r = await h(o);
  if (r.reject) throw new TypeError("net"); return { status: r.status, json: async () => { if (r.invalid) throw new SyntaxError("bad"); return r.body; } }; };
vm.createContext(sandbox); vm.runInContext(fs.readFileSync(jsPath, "utf8"), sandbox);
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r)); };
const advance = async ms => { clock += ms; const due = timers.filter(t => t.at <= clock); timers = timers.filter(t => t.at > clock); for (const t of due) t.f(); await flush(); };
const T = id => doc.getElementById(id).textContent;
const panelChars = () => ["overview", "incidents", "noc", "knowledge", "detail", "setup"].map(n => T("panel-" + n).length).reduce((a, b) => a + b, 0);
const ok = (b) => ({ status: 200, body: b });
const res = {};
(async () => {
  let view = () => ok(MODEL), gate = null;
  script = { "/static/labels.json": async () => ok(LABELS), "/api/session": async () => ok({ authenticated: true, csrf: "c" }),
    "/api/view": async () => (gate ? gate() : view()), "/api/logout": async () => ok({ authenticated: false }) };
  sandbox.document.getElementById("logout"); doc.getElementById("tab-overview");
  // fire DOMContentLoaded handler registered via document.addEventListener: grab it by re-running with spy
  let start; doc.addEventListener = (t, f) => { start = f; }; vm.runInContext(fs.readFileSync(jsPath, "utf8"), sandbox);
  ["overview","incidents","noc","knowledge","detail","setup"].forEach(n => { doc.getElementById("tab-" + n); doc.getElementById("panel-" + n); });
  if (process.env.MODE === "start_retry") {
    let n = 0; script["/static/labels.json"] = async () => (n++ < 1 ? { reject: true } : ok(LABELS));
    script["/api/session"] = async () => ok({ authenticated: false, login_token: "t" });
    start(); await flush();
    res.start_fail_flagged = /更新停止/.test(T("conn"));
    res.conn_debug = T("conn").slice(0, 40);
    await advance(5000);
    res.start_retried_and_cleared = !/更新停止/.test(T("conn")) && doc.getElementById("login").hidden === false;
    console.log(JSON.stringify(res)); return;
  }
  if (process.env.MODE === "unauth") {
    start(); await flush(); view = () => ({ status: 401, body: { error: "login_required" } });
    script["/api/session"] = async () => ok({ authenticated: false, login_token: "t" });
    await advance(5000);
    res.s401_login_and_cleared = doc.getElementById("login").hidden === false && panelChars() === 0 && T("live") === "" && doc.getElementById("panels").hidden === true;
    console.log(JSON.stringify(res)); return;
  }
  if (process.env.MODE === "soc_state") {
    // #419 selection/layout state and #416 stale/refusal handling must not leak into one another.
    const row = id => ({ incident_id: id, state: "open", most_severe: 1, last_seen: 1 });
    const withRows = ids => { const m = JSON.parse(JSON.stringify(MODEL)); m.sections = m.sections || {};
      m.sections.edge_loop = { intake: { status: "ok" }, recent: { status: "ok", snapshot: { incidents: ids.map(row) } } }; return m; };
    const find = (n, f) => { if (f(n)) return n; for (const c of n.children) { const r = find(c, f); if (r) return r; } return null; };
    const panel = () => doc.getElementById("panel-incidents");
    const click = key => find(panel(), n => n.dataset && n.dataset.focusKey === key).ls.click();
    const shows = (w) => panel().textContent.includes(w);
    view = () => ok(withRows(["inc-a", "inc-b"]));
    start(); await flush();
    click("layout"); click("incident:inc-a");
    res.selected_detail_shown = shows("インシデント inc-a") && shows("従来の表示に戻す");
    view = () => ({ status: 503, body: {} }); await advance(5000);
    res.temp_failure_keeps_selection_and_layout = shows("インシデント inc-a") && shows("従来の表示に戻す") && /更新停止/.test(T("conn"));
    view = () => ok(withRows(["inc-b"])); await advance(5000);
    res.vanished_target_not_replaced = shows("現在の保持一覧にありません") && !shows("インシデント inc-a") && !shows("インシデント inc-b" + "  ");
    view = () => ok(withRows(["inc-a", "inc-b"])); await advance(5000);
    res.reappearing_target_selection_kept = shows("インシデント inc-a");
    view = () => ({ status: 403, body: {} }); await advance(5000);
    res.s403_clears_everything = panelChars() === 0;
    view = () => ok(withRows(["inc-a", "inc-b"])); await advance(5000);
    res.after403_layout_and_selection_reset = shows("SOC 一覧レイアウトを試す") && !shows("インシデント inc-a ") ;
    click("layout");
    res.after403_no_selected_detail = shows("一覧からインシデントを選んで") && !shows("選択した行は現在の保持一覧にありません");
    click("incident:inc-b"); view = () => ({ status: 401, body: {} }); script["/api/session"] = async () => ok({ authenticated: false, login_token: "t" });
    await advance(5000);
    view = () => ok(withRows(["inc-a", "inc-b"])); script["/api/session"] = async () => ok({ authenticated: true, csrf: "c" });
    res.s401_clears_panels = panelChars() === 0;
    console.log(JSON.stringify(res)); return;
  }
  start(); await flush();
  res.initial_valid = panelChars() > 0 && /最終取得/.test(T("conn"));
  const okConn = T("conn"), chars0 = panelChars();
  view = () => ({ status: 500, body: { error: "SECRET-DETAIL" } }); await advance(5000);
  res.temp_keeps_content = panelChars() > 0 && /更新停止/.test(T("conn")) && /現在の状態を確認できたものではありません/.test(T("conn"));
  res.temp_last_ok_not_advanced = T("conn").includes(new Date(1e12).toLocaleTimeString("ja-JP"));
  res.no_secret = !T("conn").includes("SECRET-DETAIL") && !T("panels").includes("SECRET-DETAIL");
  view = () => ok(MODEL); await advance(5000);
  res.recovers = /最終取得/.test(T("conn")) && !/更新停止/.test(T("conn"));
  for (const [name, r] of [["s404", { status: 404, body: {} }], ["badjson", { status: 200, invalid: true }], ["wrongschema", ok({ schema: "x", sections: {}, pending: {} })], ["s400", { status: 400, body: {} }], ["net", { reject: true }]]) {
    view = () => r; await advance(5000);
    res[name + "_keeps_and_flags"] = panelChars() > 0 && /更新停止/.test(T("conn"));
    view = () => ok(MODEL); await advance(5000);
  }
  view = () => ({ status: 403, body: {} }); await advance(5000);
  res.s403_discards = panelChars() === 0 && /破棄/.test(T("conn")) && T("live") === "" && doc.getElementById("panels").hidden === true;
  view = () => ok(MODEL); await advance(5000);
  res.after403_restores = panelChars() > 0 && doc.getElementById("panels").hidden === false;
  // late response after logout must not repaint
  let release; gate = () => new Promise(r => { release = () => r(ok(MODEL)); });
  await advance(5000); // poll in flight, waiting
  script["/api/session"] = async () => ok({ authenticated: false, login_token: "t" });
  doc.getElementById("logout").ls.click(); await flush();
  gate = null; release(); await flush(); await advance(5000);
  res.late_after_logout_no_repaint = panelChars() === 0 && T("live") === "" && doc.getElementById("login").hidden === false;
  console.log(JSON.stringify(res));
})().catch(e => { console.log(JSON.stringify({ harness_error: String(e && e.stack || e) })); });
