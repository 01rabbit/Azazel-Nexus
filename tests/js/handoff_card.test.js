// Drives the real app.js (stub DOM, scripted fetch) through the handoff card. Usage: node handoff_card.test.js app.js labels.json model.json
const fs = require("fs"), vm = require("vm"), assert = require("node:assert/strict"), nodeCrypto = require("crypto");
const [,, jsPath, labelsPath, modelPath] = process.argv;
const MODEL = JSON.parse(fs.readFileSync(modelPath, "utf8")), LABELS = JSON.parse(fs.readFileSync(labelsPath, "utf8"));
class N {
  constructor(tag) { this.tag = tag; this.children = []; this._t = ""; this.hidden = false; this.className = ""; this.attrs = {}; this.ls = {}; this.value = ""; this.dataset = {}; this.disabled = false; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { if (gate.hold && c.tag === "button" && /を保存$/.test(c.textContent)) gate.leaks.push(c.textContent); this.children.push(c); return c; }
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
// The real digest is used. Only the hand-over of its result can be held, so a test can look at the "verifying" state and then let it finish.
const gate = { hold: false, pending: [], leaks: [], // leaks: save buttons created (even if replaced in the same tick) while the digest result is held
  release() { this.hold = false; const p = this.pending.splice(0); p.forEach(f => f()); } };
const gatedCrypto = { subtle: { digest: (alg, data) => nodeCrypto.webcrypto.subtle.digest(alg, data)
  .then(buf => gate.hold ? new Promise(r => gate.pending.push(() => r(buf))) : buf) } };
const sandbox = { Node: N, document: doc, window: { scrollY: 0, scrollTo() {}, crypto: gatedCrypto }, crypto: gatedCrypto, TextEncoder, console,
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
const WAIT_MS = 5000; // real time (not the fake clock), measured outside the sandbox
// Every handoff card in the panel (one per incident), each from its fetch button to 140 characters on, so the status line and any 照合 text show.
const observed = () => { const t = panel().textContent.replace(/\s+/g, " "), cards = t.match(/引継ぎを取得状態：.{0,140}/g) || ["(no handoff card) " + t.slice(0, 120)];
  const t0 = panel().textContent, v = /■ 照合に失敗/.test(t0) ? "failed" : /● 照合：/.test(t0) ? "verified" : /◆ 照合中/.test(t0) ? "verifying" : "none";
  const refusal = (t.match(/■ .{0,200}/g) || []).join(" | ") || "(none)";
  return "save buttons=" + saveButtons().length + ", held digests=" + gate.pending.length + ", save buttons created while held=" + JSON.stringify(gate.leaks)
    + ", verification line=" + v + ", refusal lines=" + JSON.stringify(refusal) + ", handoff cards=" + JSON.stringify(cards); };
// Poll a user-visible condition until it holds, yielding to the event loop (so the digest threadpool can finish). No fixed sleep.
// pred is checked before the deadline on purpose: the limit only stops a hang, it does not judge speed.
// opts.invariant is checked on every poll (before pred); a break fails at once with the last observation.
async function waitFor(expected, pred, opts = {}) {
  const ms = opts.ms || WAIT_MS, t0 = process.hrtime.bigint();
  for (;;) {
    if (opts.invariant && !opts.invariant()) throw new Error("invariant broken while waiting for: " + expected + "; invariant: " + opts.invariantName + "; last observed: " + observed());
    if (pred()) return;
    if (Number(process.hrtime.bigint() - t0) / 1e6 > ms) throw new Error("timeout after " + ms + "ms waiting for: " + expected + "; last observed: " + observed());
    await new Promise(r => setImmediate(r));
  }
}
const BUSY = /取得中|照合中/;
const settled = re => () => re.test(panel().textContent) && !BUSY.test(panel().textContent);
const hasSave = n => () => saveButtons().length === n;
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
  mf.incident_id = id; const mfs = JSON.stringify(mf);
  const body = { incident_id: id, generated_at: "2026-11-10T12:00:00Z", principal_class: "ui", package: { incident: { incident_id: id, state: "open" }, time: { last_seen: "1970-01-01T00:00:01Z" },
      observed_facts: { summary: { count: 3, most_severe: 1 } }, ai_assessment: { slow_advisory: {} }, knowledge: { status: "partial" } },
    markdown: md, manifest: mf, manifest_sha256: sha(mfs), files: { "handoff.json": j, "handoff.ja.md": md, "manifest.json": mfs } };
  return Object.assign(body, tweak(body) || {});
}
function remanifest(b, edit) { const m = JSON.parse(b.files["manifest.json"]); edit(m); const t = JSON.stringify(m);
  return { files: Object.assign({}, b.files, { "manifest.json": t }), manifest_sha256: sha(t) }; }
let ROWX = {};
const row = id => Object.assign({ incident_id: id, state: "open", most_severe: 1, last_seen: 1, count: 3 }, ROWX);
let CAPS = { handoff: true, full_context_from_observation: false };
const model = () => { const m = JSON.parse(JSON.stringify(MODEL)); m.sections = m.sections || {};
  if (CAPS === undefined) { delete m.capabilities; } else { m.capabilities = CAPS; }
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
  gate.hold = true; release(ok(handoff(ID1)));
  // A1: all three digests were computed but their results are held, so the card shows "verifying" and no save button.
  await waitFor("fetched card with verification pending (3 digests held)", () => /取得済み/.test(panel().textContent) && /照合中/.test(panel().textContent) && gate.pending.length === 3,
    { invariant: () => saveButtons().length === 0 && gate.leaks.length === 0, invariantName: "no save button while the digest result is held" });
  assert.equal(saveButtons().length, 0, "A1: no save button while verification is held"); assert.deepEqual(gate.leaks, [], "A1: no save button was ever created while held");
  gate.release();
  // A2: one button each for JSON, Japanese Markdown and manifest.
  await waitFor("3 save buttons after verification", hasSave(3));
  const names = saveButtons().map(b => b.textContent);
  for (const k of ["save_json", "save_md", "save_manifest"]) assert.equal(names.filter(x => x === LABELS.handoff[k]).length, 1, "A2: exactly one " + k + " button in " + JSON.stringify(names));
  assert.equal(names.length, 3, "A2: 3 save buttons");
  assert.match(panel().textContent, /取得済み/);
  assert.match(panel().textContent, /binding 照合不可/); assert.ok(!/別時点: 画面/.test(panel().textContent));
  assert.equal(saved.length, 0); saveButtons()[0].ls.click(); assert.equal(saved.length, 1);
  assert.equal(saved[0].parts[0], handoff(ID1).files["handoff.json"]);
  res.legacy_fetch_and_verified_save = true;
  // 1b. U36 card counts: package.unconfirmed and the deterministic required checks, not the (empty) AI advisory.
  routes["/api/handoff/"] = () => ok(handoff(ID1, b => ({ package: Object.assign({}, b.package, { unconfirmed: Array.from({ length: 11 }, (_, i) => "u" + i),
    ai_assessment: { slow_advisory: { status: "unavailable", unknowns: [], next_checks: [] }, deterministic_guidance: { guidance: { next_checks: [{ id: "a", tier: "required" }, { id: "b", tier: "required" }, { id: "c", tier: "optional" }] } } } }) })));
  fetchButtons()[0].ls.click(); await flush();
  const ct = panel().textContent;
  assert.match(ct, /未確認事項（引継ぎ資料の unconfirmed）11 件/); assert.match(ct, /必須の確認（決定論案内）2 件/);
  assert.match(ct, /AI 助言の未確認／確認候補なし（AI 回答なし.*status unavailable/); assert.ok(!/0 件/.test(ct), "no misleading 0 件");
  assert.match(ct, /binding 照合不可/); assert.match(ct, /保存物の hash 照合とは別/);
  res.card_counts_from_package = true;
  // 2. tampered / missing / size mismatch / manifest mismatch: no save buttons, createObjectURL never called.
  for (const [name, reason, tweak] of [["json", /handoff\.json の sha256 が一致しない/, b => ({ files: Object.assign({}, b.files, { "handoff.json": b.files["handoff.json"] + " " }) })],
      ["md", /handoff\.ja\.md の sha256 が一致しない/, b => ({ files: Object.assign({}, b.files, { "handoff.ja.md": "x" }) })],
      ["manifest", /manifest\.json の sha256 が manifest_sha256 と一致しない/, b => ({ manifest_sha256: "0".repeat(64) })],
      ["size", /handoff\.json の大きさが一致しない/, b => remanifest(b, m => { m.files[0].bytes += 1; })],
      ["entry", /handoff\.ja\.md の manifest エントリが無い/, b => remanifest(b, m => { m.files.pop(); })],
      ["nofiles", /files に 3 ファイル/, b => ({ files: undefined })], ["twofiles", /files に 3 ファイル/, b => ({ files: { "handoff.json": "a", "handoff.ja.md": "b" } })]]) {
    saved.length = 0; routes["/api/handoff/"] = () => ok(handoff(ID1, tweak));
    fetchButtons()[0].ls.click();
    // A3: wait until this scene's own refusal reason is shown (not an earlier scene's, not the initial state), then check no save button.
    await waitFor("refusal for " + name + " (" + reason + ") and no busy marker", settled(reason));
    assert.equal(saveButtons().length, 0, "A3 " + name); assert.equal(saved.length, 0, name);
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
  assert.match(panel().textContent, /取得済み/); await waitFor("previous result verified (3 save buttons) before the refetch", hasSave(3));
  routes["/api/handoff/"] = () => "hang"; fetchButtons()[0].ls.click(); await flush();
  await advance(20000);
  assert.match(panel().textContent, /取得できませんでした/); assert.match(panel().textContent, /別時点の結果（取得時刻/);
  assert.match(panel().textContent, new RegExp(ID1));
  res.timeout_keeps_previous_result_labelled = true;
  // 7. incident state (3b) and no-permission (3a) symbols, list and detail, legacy and SOC layouts.
  const states = () => { const m = JSON.parse(JSON.stringify(MODEL)); m.sections = m.sections || {};
    const rows = [["inc-00000000000000a1", "open", "permission_denied"], ["inc-00000000000000b2", "closed", "available"],
      ["inc-00000000000000c3", "weird_state", "available"], ["inc-00000000000000d4", "open", "not_read"]]
      .map(([id, st, ex]) => ({ incident_id: id, state: st, most_severe: 1, last_seen: 1, explanation: { state: ex } }));
    m.sections.edge_loop = { intake: { status: "ok" }, recent: { status: "ok", snapshot: { incidents: rows } } }; return m; };
  view = () => ok(states()); await advance(5000);
  const card = id => findAll(panel(), n => n.tag === "article" && n.textContent.includes("インシデント " + id))[0].textContent;
  assert.match(card("inc-00000000000000a1"), /◉未解決open/); assert.match(card("inc-00000000000000b2"), /○終了（Edge 観測グループ終了）closed/);
  assert.match(card("inc-00000000000000d4"), /◉未解決open/); assert.match(card("inc-00000000000000c3"), /？不明weird_state/);
  assert.match(card("inc-00000000000000a1"), /⊘権限なしpermission_denied/, "detail: no-permission symbol then word then code");
  assert.match(card("inc-00000000000000d4"), /⊘権限なし：読んでいない（権限なし）not_read/, "detail: not_read keeps the sr-only prefix");
  assert.ok(findAll(panel(), n => n.attrs && n.attrs["aria-hidden"] === "true" && n.textContent === "⊘").length >= 2, "the symbol is aria-hidden");
  assert.ok(!/観測中/.test(card("inc-00000000000000a1")), "incident state no longer uses the generic open word");
  const toggle = findAll(panel(), n => n.tag === "button" && n.textContent.includes("SOC 一覧")); toggle[0].ls.click(); await flush();
  const tableRows = findAll(panel(), n => n.tag === "tr").map(n => n.textContent);
  assert.ok(tableRows.some(t => /◉未解決open/.test(t) && /⊘権限なしpermission_denied/.test(t)), "list: open row with no-permission symbol");
  assert.ok(tableRows.some(t => /○終了（Edge 観測グループ終了）closed/.test(t) && !/⊘/.test(t)));
  assert.ok(tableRows.some(t => /？不明weird_state/.test(t)));
  assert.ok(tableRows.every(t => !/[◉○？⊘]\s*(1|重大)/.test(t)), "severity carries no symbol");
  res.incident_state_and_denied_symbols = true;
  findAll(panel(), n => n.tag === "button" && n.textContent.includes("従来の表示に戻す"))[0].ls.click(); await flush();
  // 8. capabilities gate (closed): only handoff === true shows the fetch button; nothing else is shown instead of it.
  for (const caps of [undefined, { handoff: false, full_context_from_observation: null }, { handoff: null }, { handoff: "true" }, { handoff: 1 }, "x", {}]) {
    CAPS = caps; view = () => ok(model()); await advance(5000);
    assert.equal(fetchButtons().length, 0, "no fetch button for " + JSON.stringify(caps)); assert.equal(saveButtons().length, 0);
    assert.match(panel().textContent, /この起動では引継ぎを取得できません|引継ぎの可否は不明/);
  }
  CAPS = { handoff: true, full_context_from_observation: false }; await advance(5000); assert.equal(fetchButtons().length, 2);
  // 9. nested incident_id mismatch is a contract violation: dropped, nothing saved.
  for (const tweak of [b => ({ package: Object.assign({}, b.package, { incident: { incident_id: ID2, state: "open" } }) }),
      b => ({ manifest: Object.assign({}, b.manifest, { incident_id: ID2 }) })]) {
    routes["/api/handoff/"] = () => ok(handoff(ID1, tweak)); fetchButtons()[0].ls.click(); await flush();
    assert.match(panel().textContent, /状態：■ 取得できませんでした/); assert.ok(!/状態：● 取得済み/.test(panel().textContent), "mismatch is not accepted");
  }
  // 10. four-step match. Row values: open / most_severe 1 / last_seen 1 / count 3.
  const fetched = async tweak => { routes["/api/handoff/"] = () => ok(handoff(ID1, tweak)); fetchButtons()[0].ls.click(); await flush(); return panel().textContent; };
  const pk = (b, o) => ({ package: Object.assign({}, b.package, o) });
  const withBinding = (b, rid) => pk(b, { ai_assessment: { slow_advisory: { binding: { request_id: rid } } } });
  let t = await fetched(); assert.match(t, /binding 照合不可/); assert.ok(!/別時点: 画面|同一遷移・説明内容/.test(t), "one-sided binding is neither match nor diff");
  t = await fetched(b => withBinding(b, "r1")); assert.match(t, /binding 照合不可/);
  const bindRow = rid => { const m = model(); m.sections.edge_loop.recent.snapshot.incidents[0].explanation = { slow_analysis: { binding: { request_id: rid } } }; return m; };
  view = () => ok(bindRow("r1")); await advance(5000);
  t = await fetched(b => withBinding(b, "r1")); assert.match(t, /観測 4 項目一致（state/); assert.ok(!/別時点: 画面/.test(t));
  await waitFor("verified card, 4 items match, 3 save buttons", () => settled(/観測 4 項目一致/)() && hasSave(3)());
  t = await fetched(b => withBinding(b, "r2")); assert.match(t, /別時点: 画面の行と package/);
  // The warning paragraph belongs to the verified card, so wait for verification before looking for it.
  await waitFor("verified card, time-difference warning, 3 save buttons kept", () => settled(/別時点: 画面の行と package/)() && hasSave(3)());
  const warn = findAll(panel(), n => n.tag === "p" && /^▲ 別時点/.test(n.textContent))[0]; assert.ok(warn, "warning shown with save buttons kept");
  t = await fetched(b => Object.assign(withBinding(b, "r1"), { package: Object.assign({}, withBinding(b, "r1").package, { observed_facts: { summary: { count: 4, most_severe: 1 } } }) }));
  assert.match(t, /別時点: 画面/, "both bindings equal but count differs");
  // row changes after the fetch: re-render shows 別時点
  routes["/api/handoff/"] = () => ok(handoff(ID1)); fetchButtons()[0].ls.click(); await flush();
  for (const [k, v] of [["count", 4], ["last_seen", 5], ["state", "closed"]]) {
    view = () => { const m = model(); m.sections.edge_loop.recent.snapshot.incidents[0][k] = v; return ok(m); }; await advance(5000);
    assert.match(panel().textContent, /別時点: 画面/, k);
  }
  view = () => ok(model()); await advance(5000);
  // 照合不可: too_large count, malformed last_seen, null field. No coercion.
  view = () => { const m = model(); m.sections.edge_loop.recent.snapshot.incidents[0].count = "too_large"; return ok(m); }; await advance(5000);
  t = await fetched(); assert.match(t, /照合不可（必要な欄/); assert.ok(!/別時点: 画面/.test(t));
  view = () => ok(model()); await advance(5000);
  t = await fetched(b => pk(b, { time: { last_seen: "yesterday" } })); assert.match(t, /照合不可（必要な欄/);
  t = await fetched(b => pk(b, { observed_facts: { summary: { count: "3", most_severe: 1 } } })); assert.match(t, /照合不可（必要な欄/, "string count is not coerced");
  t = await fetched(b => pk(b, { incident: { incident_id: ID1, state: null } })); assert.match(t, /照合不可（必要な欄/);
  // calendar strictness: impossible dates never normalise into a match (binding and other 3 items equal).
  view = () => ok(bindRow("r1")); await advance(5000);
  // Date.parse is spied in the sandbox: an impossible value must be rejected by the explicit validation, never reach the parser.
  const parsed = []; const nativeParse = Date.parse; sandbox.Date.parse = (x) => { parsed.push(x); return nativeParse(x); };
  for (const bad of ["2026-02-29T00:00:00Z", "2026-02-30T00:00:00Z", "2026-11-10T00:00:60Z", "2026-11-10T24:00:00Z", "2026-13-10T00:00:00Z",
                     "2026-11-10T00:00:00+24:00", "2026-11-10T00:00:00-24:00", "2026-11-10T00:00:00+00:60", "2026-11-10T00:00:00-00:60"]) {
    t = await fetched(b => withBinding(pk(b, { time: { last_seen: bad } }), "r1")); assert.match(t, /照合不可（必要な欄/, bad); assert.ok(!/観測 4 項目一致/.test(t), bad);
    assert.ok(!parsed.includes(bad), "rejected before Date.parse: " + bad);
  }
  delete sandbox.Date.parse;
  t = await fetched(b => withBinding(pk(b, { time: { last_seen: "1970-01-01T00:00:01Z" } }), "r1")); assert.match(t, /観測 4 項目一致（state/, "valid Z");
  t = await fetched(b => withBinding(pk(b, { time: { last_seen: "1970-01-01T09:00:01+09:00" } }), "r1")); assert.match(t, /観測 4 項目一致（state/, "valid +09:00");
  t = await fetched(b => withBinding(pk(b, { time: { last_seen: "2024-02-29T00:00:00Z" } }), "r1")); assert.match(t, /別時点: 画面/, "leap day is valid (differs from row)");
  view = () => ok(model()); await advance(5000);
  // 11. Full-query capability line: three values, rendered in the incident detail.
  for (const [v, re] of [[false, /観測起点の Full 照会: 無効（規則ファイルなし）/], [true, /観測起点の Full 照会: 規則ファイルが有効（UI が読んだ時点。broker・grant・peer の状態は示しません）/], [null, /観測起点の Full 照会: 不明/], [undefined, /観測起点の Full 照会: 不明/]]) {
    CAPS = v === undefined ? {} : { handoff: true, full_context_from_observation: v }; view = () => ok(model()); await advance(5000);
    assert.match(panel().textContent, re, String(v));
  }
  CAPS = undefined; await advance(5000); assert.match(panel().textContent, /観測起点の Full 照会: 不明/, "old model without the key");
  // 12. 421 discards (401 is not exercised here) capabilities and the held handoff; a late answer stays dropped; 503 keeps them.
  CAPS = { handoff: true, full_context_from_observation: false }; view = () => ok(model()); await advance(5000);
  view = () => ({ status: 503, body: {} }); await advance(5000); assert.equal(fetchButtons().length, 2, "503 keeps the view");
  const w5 = []; routes["/api/handoff/"] = () => new Promise(r => w5.push(r)); fetchButtons()[0].ls.click(); await flush();
  view = () => ({ status: 421, body: {} }); await advance(5000); assert.equal(fetchButtons().length, 0, "421 discards");
  w5[0](ok(handoff(ID1))); await flush(); assert.ok(!/取得済み/.test(panel().textContent), "late answer after 421 dropped");
  // 13. U39 F: past full-node reference line (server word only), also without fast_assistance.
  CAPS = { handoff: true, full_context_from_observation: false };
  const refText = async (extra) => { ROWX = extra; view = () => ok(model()); await advance(5000); return panel().textContent; };
  for (const w of ["not_recorded", "none", "unknown", "expired", "set_changed", "in_window"]) {
    const t = await refText({ full_node_reference: w });
    assert.match(t, /過去のフルノード参照：/, w); assert.ok(t.includes(LABELS.fullnode_ref[w]), w);
    assert.match(t, /fast_assistance なし/, "reference shown next to fast_missing: " + w);
  }
  let t13 = await refText({ full_node_reference: "in_window" });
  assert.match(t13, /照会した集合と同じで期限内の過去の参照があります（未検証の助言。今回の照会結果ではありません）/);
  assert.ok(!/(^|[^無])有効/.test(t13.replace(/観測起点[^\n]*/, "")), "in_window is not read as valid");
  for (const w of ["not_recorded", "unknown", "expired", "set_changed"]) assert.ok(!/有効(です|な参照)/.test(LABELS.fullnode_ref[w]), w);
  t13 = await refText({ full_node_reference: "bogus" }); assert.match(t13, /過去のフルノード参照：（未登録：bogus）/);
  t13 = await refText({}); assert.match(t13, /過去のフルノード参照：不明（記録なし/);
  const partial = await refText({ full_node_reference: "in_window", explanation: { fast_assistance: { full_node_context_status: "received",
    full_node_context: { full_node_context_status: "received", outcome: "partial" } } } });
  assert.match(partial, /過去のフルノード参照：照会した集合と同じ/); assert.match(partial, /今回の照会結果ではありません/);
  ROWX = {};
  console.log(JSON.stringify(res));
})().catch(e => { console.log(JSON.stringify({ harness_error: String(e && e.stack || e) })); process.exit(1); });
