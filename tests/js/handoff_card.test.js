// Drives the real app.js (stub DOM, scripted fetch) through the handoff card. Usage: node handoff_card.test.js app.js labels.json model.json
const fs = require("fs"), vm = require("vm"), assert = require("node:assert/strict"), nodeCrypto = require("crypto");
const [,, jsPath, labelsPath, modelPath] = process.argv;
const MODEL = JSON.parse(fs.readFileSync(modelPath, "utf8")), LABELS = JSON.parse(fs.readFileSync(labelsPath, "utf8"));
class N {
  constructor(tag) { this.tag = tag; this.children = []; this._t = ""; this.hidden = false; this.className = ""; this.attrs = {}; this.ls = {}; this.value = ""; this.dataset = {}; this.disabled = false; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); }
  set textContent(v) { this.children = []; this._t = String(v); }
  get textContent() { return this._t + this.children.map(c => c.textContent).join(""); }
  setAttribute(k, v) { this.attrs[k] = v; } getAttribute(k) { return this.attrs[k]; }
  addEventListener(t, f) { this.ls[t] = f; } focus() {} click() {} closest() { return null; } querySelectorAll() { return []; }
}
const nodes = {};
const doc = { body: new N("body"), getElementById: id => nodes[id] || (nodes[id] = new N(id)), createElement: t => new N(t),
  createTextNode: s => { const n = new N("#t"); n._t = String(s); return n; }, addEventListener() {} };
let clock = 1e12, timers = [], saved = [];
const sandbox = { Node: N, document: doc, window: { scrollY: 0, scrollTo() {}, crypto: nodeCrypto.webcrypto }, crypto: nodeCrypto.webcrypto, TextEncoder, console,
  Blob: class { constructor(parts, o) { this.parts = parts; this.type = o && o.type; } },
  URL: { createObjectURL: b => { saved.push(b); return "blob:x"; }, revokeObjectURL() {} },
  setTimeout: (f, ms) => { const t = { f, at: clock + ms, id: timers.length + 1 }; timers.push(t); return t.id; },
  clearTimeout: id => { timers = timers.filter(t => t.id !== id); },
  Date: class extends Date { static now() { return clock; } }, AbortController, Promise, JSON, Object, Array, Math, String, Number, isNaN, isFinite, Error, RegExp, Uint8Array };
let routes = {};
sandbox.fetch = (p, o) => new Promise((resolve, reject) => {
  const h = routes[p.startsWith("/api/handoff/") ? "/api/handoff/" : p]; if (!h) return reject(new TypeError("no route " + p));
  if (o && o.signal) o.signal.addEventListener("abort", () => reject(Object.assign(new Error("abort"), { name: "AbortError" })));
  Promise.resolve(h(p, o)).then(r => { if (r === "hang") return; if (r.reject) return reject(new TypeError("net"));
    resolve({ status: r.status, json: async () => { if (r.invalid) throw new SyntaxError("bad"); return r.body; } }); });
});
vm.createContext(sandbox);
let start; doc.addEventListener = (t, f) => { start = f; }; vm.runInContext(fs.readFileSync(jsPath, "utf8"), sandbox);
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
const advance = async ms => { clock += ms; const due = timers.filter(t => t.at <= clock); timers = timers.filter(t => t.at > clock); for (const t of due) t.f(); await flush(); };
const T = id => doc.getElementById(id).textContent;
const panel = () => doc.getElementById("panel-incidents");
const find = (n, f) => { if (f(n)) return n; for (const c of n.children) { const r = find(c, f); if (r) return r; } return null; };
const findAll = (n, f, out = []) => { if (f(n)) out.push(n); n.children.forEach(c => findAll(c, f, out)); return out; };
const fetchButtons = () => findAll(panel(), n => n.tag === "button" && n.textContent === "引継ぎを取得");
const saveButtons = () => findAll(panel(), n => n.tag === "button" && /を保存$/.test(n.textContent));
const ok = b => ({ status: 200, body: b });
const ID1 = "inc-00000000000000a1", ID2 = "inc-00000000000000b2";
const sha = s => nodeCrypto.createHash("sha256").update(s, "utf8").digest("hex");
function handoff(id, tweak = () => ({})) {
  const j = '{"incident":"' + id + '","メモ":"日本語"}\n', md = "# 引継ぎ " + id + "\n", mf = { files: [
    { name: "handoff.json", sha256: sha(j), bytes: Buffer.byteLength(j) }, { name: "handoff.ja.md", sha256: sha(md), bytes: Buffer.byteLength(md) }] };
  const mfs = JSON.stringify(mf);
  const body = { incident_id: id, generated_at: "2026-11-10T12:00:00Z", principal_class: "ui", package: { ai_assessment: { slow_advisory: {} }, knowledge: { status: "partial" } },
    markdown: md, manifest: mf, manifest_sha256: sha(mfs), files: { "handoff.json": j, "handoff.ja.md": md, "manifest.json": mfs } };
  return Object.assign(body, tweak(body) || {});
}
function remanifest(b, edit) { const m = JSON.parse(b.files["manifest.json"]); edit(m); const t = JSON.stringify(m);
  return { files: Object.assign({}, b.files, { "manifest.json": t }), manifest_sha256: sha(t) }; }
const row = id => ({ incident_id: id, state: "open", most_severe: 1, last_seen: 1 });
const model = () => { const m = JSON.parse(JSON.stringify(MODEL)); m.sections = m.sections || {};
  m.sections.edge_loop = { intake: { status: "ok" }, recent: { status: "ok", snapshot: { incidents: [row(ID1), row(ID2)] } } }; return m; };
let view = () => ok(model());
const res = {};
(async () => {
  routes = { "/static/labels.json": () => ok(LABELS), "/api/session": () => ok({ authenticated: true, csrf: "c" }), "/api/view": () => view() };
  ["overview","incidents","noc","knowledge","detail","setup"].forEach(n => { doc.getElementById("tab-" + n); doc.getElementById("panel-" + n); });
  start(); await flush();
  // 1. legacy layout: no selected incident, fetch works, save only after verification.
  assert.equal(fetchButtons().length, 2, "both rows carry a handoff button in the legacy layout");
  let release; routes["/api/handoff/"] = () => new Promise(r => { release = r; });
  fetchButtons()[0].ls.click(); await flush();
  assert.match(panel().textContent, /取得中/); assert.equal(saveButtons().length, 0);
  release(ok(handoff(ID1))); await flush();
  assert.match(panel().textContent, /取得済み/); assert.equal(saveButtons().length, 3, "3 save buttons after verification");
  assert.match(panel().textContent, /binding なし/);
  assert.equal(saved.length, 0); saveButtons()[0].ls.click(); assert.equal(saved.length, 1);
  assert.equal(saved[0].parts[0], handoff(ID1).files["handoff.json"]);
  res.legacy_fetch_and_verified_save = true;
  // 2. tampered / missing / size mismatch / manifest mismatch: no save buttons, createObjectURL never called.
  for (const [name, tweak] of [["json", b => ({ files: Object.assign({}, b.files, { "handoff.json": b.files["handoff.json"] + " " }) })],
      ["md", b => ({ files: Object.assign({}, b.files, { "handoff.ja.md": "x" }) })],
      ["manifest", b => ({ manifest_sha256: "0".repeat(64) })],
      ["size", b => remanifest(b, m => { m.files[0].bytes += 1; })],
      ["entry", b => remanifest(b, m => { m.files.pop(); })],
      ["nofiles", b => ({ files: undefined })], ["twofiles", b => ({ files: { "handoff.json": "a", "handoff.ja.md": "b" } })]]) {
    saved.length = 0; routes["/api/handoff/"] = () => ok(handoff(ID1, tweak));
    fetchButtons()[0].ls.click(); await flush();
    assert.equal(saveButtons().length, 0, name); assert.equal(saved.length, 0, name);
    assert.match(panel().textContent, /信用しないでください|保存不可/, name);
  }
  res.verification_failures_never_save = true;
  // 3. old seq: ID1 then ID2 requested; ID1's late answer is dropped.
  const waiting = []; routes["/api/handoff/"] = p => new Promise(r => waiting.push([p, r]));
  fetchButtons()[0].ls.click(); await flush(); fetchButtons()[1].ls.click(); await flush();
  waiting[0][1](ok(handoff(ID1))); await flush();
  assert.match(panel().textContent, /取得中/);
  waiting[1][1](ok(handoff(ID2))); await flush();
  assert.match(panel().textContent, /取得済み/);
  res.old_seq_dropped = true;
  // 4. old seq refusal must not discard the current view.
  const w2 = []; routes["/api/handoff/"] = p => new Promise(r => w2.push(r));
  fetchButtons()[0].ls.click(); await flush(); fetchButtons()[1].ls.click(); await flush();
  w2[0]({ status: 403, body: {} }); await flush();
  assert.ok(panel().textContent.length > 0 && fetchButtons().length === 2, "stale 403 did not clear the view");
  w2[1](ok(handoff(ID2))); await flush(); assert.match(panel().textContent, /取得済み/);
  const w3 = []; routes["/api/handoff/"] = p => new Promise(r => w3.push(r));
  fetchButtons()[0].ls.click(); await flush(); let logins = 0; routes["/api/session"] = () => { logins++; return ok({ authenticated: true, csrf: "c" }); };
  w3[0]({ status: 401, body: {} }); await flush(); assert.ok(logins >= 1, "current 401 returns to login (session re-read)");
  res.stale_refusal_ignored_current_obeyed = true;
  // 5. old epoch: discardView (403 on the poll) then a late 200 must not reappear.
  await advance(5000);
  assert.ok(fetchButtons().length === 2, "app is back");
  const w4 = []; routes["/api/handoff/"] = p => new Promise(r => w4.push(r));
  fetchButtons()[0].ls.click(); await flush();
  view = () => ({ status: 403, body: {} }); await advance(5000);
  assert.equal(fetchButtons().length, 0, "403 discarded the view");
  w4[0](ok(handoff(ID1))); await flush(); view = () => ({ status: 403, body: {} });
  assert.ok(!/取得済み/.test(panel().textContent), "late answer after discard did not repaint");
  res.old_epoch_dropped_after_discard = true;
  view = () => ok(model()); await advance(5000);
  // 6. timeout keeps the previous good result under an explicit label.
  routes["/api/handoff/"] = () => ok(handoff(ID1)); fetchButtons()[0].ls.click(); await flush();
  assert.match(panel().textContent, /取得済み/);
  routes["/api/handoff/"] = () => "hang"; fetchButtons()[0].ls.click(); await flush();
  await advance(20000);
  assert.match(panel().textContent, /取得できませんでした/); assert.match(panel().textContent, /別時点の結果（取得時刻/);
  assert.match(panel().textContent, new RegExp(ID1));
  res.timeout_keeps_previous_result_labelled = true;
  console.log(JSON.stringify(res));
})().catch(e => { console.log(JSON.stringify({ harness_error: String(e && e.stack || e) })); process.exit(1); });
