/*
 * Azazel-Nexus read-only UI.
 *
 * Every string from the server is written with textContent. No innerHTML,
 * outerHTML, insertAdjacentHTML, document.write, eval or Function
 * constructor is used anywhere (tests/unit/test_ui_serve.py checks this
 * file). Nothing here performs an action on the node: the only requests
 * are GET of the read model and POST of login/logout.
 */
(function () {
  "use strict";

  var POLL_MS = 5000;
  var state = { labels: null, csrf: null, loginToken: null, model: null,
    lastOk: null, timer: null, announced: "", failing: false };

  var LOGIN_ERRORS = {
    login_refused: "コードが違うか、使用済み・期限切れです。端末で azazel-nexus ui-login をもう一度実行してください。",
    login_throttled: "誤ったコードが続けて送られたため、ログインを一時的に受け付けていません（最大 30 秒）。このホストの別のアカウントが送っている可能性があります。少し待ってから、新しいコードで試してください。",
    csrf_refused: "ページの有効期限が切れました。再読み込みしてください。",
    origin_refused: "このページ以外からの送信は受け付けません。",
    host_refused: "このアドレスでは受け付けません。http://127.0.0.1 で開いてください。"
  };

  // -- DOM helpers (textContent only) ---------------------------------------

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function add(parent) {
    for (var i = 1; i < arguments.length; i++) {
      if (arguments[i]) { parent.appendChild(arguments[i]); }
    }
    return parent;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  // -- vocabulary ------------------------------------------------------------

  function word(value) {
    var entry = state.labels && Object.prototype.hasOwnProperty.call(state.labels.words, value)
      ? state.labels.words[value] : null;
    if (value === null || value === undefined) { return { ja: "値なし", tone: "unknown", en: "null" }; }
    if (!entry) { return { ja: "未定義の語", tone: "unknown", en: String(value) }; }
    return { ja: entry[0], tone: entry[1], en: String(value) };
  }

  function reasonText(code) {
    if (code === null || code === undefined) { return null; }
    var table = state.labels ? state.labels.reasons : {};
    return Object.prototype.hasOwnProperty.call(table, code) ? table[code] : "（説明未登録の理由コード）";
  }

  function badge(value, toneOverride) {
    var w = word(value);
    var tone = toneOverride || w.tone;
    var mark = state.labels && state.labels.tones[tone] ? state.labels.tones[tone].mark : "？";
    var node = el("span", "badge tone-" + tone);
    var m = el("span", "mark", mark);
    m.setAttribute("aria-hidden", "true");
    var toneWord = state.labels && state.labels.tones[tone] ? state.labels.tones[tone].ja : "不明";
    add(node, m, el("span", "sr-only", toneWord + "："), el("span", "ja", w.ja), el("span", "en", w.en));
    return node;
  }

  function reasonLine(code) {
    if (code === null || code === undefined) { return null; }
    var node = el("span", "reason");
    add(node, el("span", null, "理由：" + reasonText(code)), el("span", "en", code));
    return node;
  }

  function toEpoch(value) {
    if (typeof value === "number" && isFinite(value)) { return value * 1000; }
    if (typeof value === "string") { var t = Date.parse(value); return isNaN(t) ? null : t; }
    return null;
  }

  function age(ms) {
    var s = Math.round((Date.now() - ms) / 1000);
    if (s < -5) { return "未来の時刻（" + (-s) + " 秒先）"; }
    if (s < 0) { s = 0; }
    if (s < 120) { return s + " 秒前"; }
    if (s < 7200) { return Math.round(s / 60) + " 分前"; }
    if (s < 172800) { return Math.round(s / 3600) + " 時間前"; }
    return Math.round(s / 86400) + " 日前";
  }

  function when(label, value, missingReason) {
    var ms = toEpoch(value);
    if (ms === null) {
      return el("span", "when", label + "：なし" + (missingReason ? "（" + reasonText(missingReason) + "）" : ""));
    }
    var d = new Date(ms);
    return el("span", "when", label + "：" + d.toLocaleString("ja-JP") + "（" + age(ms) + "）");
  }

  function kv(rows) {
    var dl = el("dl", "kv");
    rows.forEach(function (row) {
      if (!row) { return; }
      var dd = el("dd");
      if (row[1] instanceof Node) { dd.appendChild(row[1]); } else { dd.textContent = text(row[1]); }
      add(dl, el("dt", null, row[0]), dd);
    });
    return dl;
  }

  function text(value) {
    if (value === null || value === undefined) { return "なし"; }
    if (value === true) { return "はい"; }
    if (value === false) { return "いいえ"; }
    if (Array.isArray(value)) { return value.length ? value.map(text).join("、") : "なし"; }
    if (typeof value === "object") { return JSON.stringify(value); }
    return String(value);
  }

  function card(title, value, opts) {
    opts = opts || {};
    var w = word(value);
    var tone = opts.tone || w.tone;
    var node = el("article", "card tone-" + tone);
    add(node, el("h3", null, title), badge(value, opts.tone), reasonLine(opts.reason));
    if (opts.time) { node.appendChild(opts.time); }
    (opts.children || []).forEach(function (child) { if (child) { node.appendChild(child); } });
    return node;
  }

  function block(title) {
    var node = el("div", "block");
    node.appendChild(el("h4", null, title));
    return node;
  }

  function list(items) {
    var ul = el("ul", "plain");
    items.forEach(function (item) {
      var li = el("li");
      if (item instanceof Node) { li.appendChild(item); } else { li.textContent = text(item); }
      ul.appendChild(li);
    });
    return ul;
  }

  // -- read model access ----------------------------------------------------

  function section(name) { return state.model && state.model.sections ? state.model.sections[name] : undefined; }

  function accessWord(name) {
    var access = state.model && state.model.access ? state.model.access[name] : undefined;
    return access || null;
  }

  /* A section the account could not read is "permission denied", not "absent". */
  function statusWithAccess(status, reason, accessName) {
    var a = accessName ? accessWord(accessName) : null;
    var unknownish = status === "unavailable" || status === "unknown" || status === "not_collected";
    if (a === "permission_denied" && unknownish) {
      return { status: "permission_denied", reason: "access_permission_denied", original: reason };
    }
    return { status: status, reason: reason, original: null };
  }

  function evaluatedAt() { return when("評価時刻（status 実行）", state.model ? state.model.as_of : null, "clock_unknown"); }

  function pendingCard(title, name) {
    var reason = state.model && state.model.pending ? state.model.pending[name] : "section_absent_from_read_model";
    return card(title, "not_collected", { reason: reason, time: evaluatedAt() });
  }

  /* Keys whose string value is a word of the vocabulary (labelled, never raw),
     and keys whose value is a reason code. Everything else is shown as data. */
  var WORD_KEYS = { status: true, state: true, freshness: true, collection: true };
  var REASON_KEYS = { reason_code: true, reason: true };

  function tree(value, depth) {
    if (value === null || typeof value !== "object") { return document.createTextNode(text(value)); }
    if (depth > 6) { return document.createTextNode("（省略）"); }
    if (Array.isArray(value)) {
      if (!value.length) { return document.createTextNode("なし"); }
      return list(value.map(function (item) {
        return item !== null && typeof item === "object" ? tree(item, depth + 1) : text(item);
      }));
    }
    var rows = [];
    Object.keys(value).sort().forEach(function (key) {
      var v = value[key];
      if (WORD_KEYS[key] && typeof v === "string") { rows.push([key, badge(v)]); }
      else if (REASON_KEYS[key] && typeof v === "string") { rows.push([key, reasonLine(v)]); }
      else if (key === "conditions" && Array.isArray(v) && v.length) { rows.push([key, list(v.map(reasonLine))]); }
      else if (v !== null && typeof v === "object") { rows.push([key, tree(v, depth + 1)]); }
      else { rows.push([key, v]); }
    });
    return kv(rows);
  }

  /* A read-model section: its word (permission denied when this account could
     not open its source), its reason, when it was written, and its fields --
     the scalar ones only when `compact`, otherwise all of them, each word
     through the label table. */
  function genericCard(title, sec, opts) {
    opts = opts || {};
    var s = statusWithAccess(sec.status, sec.reason_code, opts.access || null);
    var rows = {};
    Object.keys(sec).forEach(function (key) {
      var v = sec[key];
      if (key === "status" || key === "reason_code" || key === "source") { return; }
      if (opts.compact && v !== null && typeof v === "object" &&
          !(Array.isArray(v) && v.every(function (item) { return item === null || typeof item !== "object"; }))) { return; }
      rows[key] = v;
    });
    var source = sec.source || {};
    return card(title, s.status, { reason: s.reason,
      time: when("観測時刻", source.written_at || source.observed_at, source.reason_code),
      children: [tree(rows, 0)] });
  }

  // -- screens ---------------------------------------------------------------

  function overview(panel) {
    var grid = el("div", "grid");
    var edge = section("edge_core") || {};
    var enf = section("enforcement") || {};
    var edgeStatus = statusWithAccess(edge.status, edge.reason_code, null);
    add(grid, card("防御状態（Edge）", edgeStatus.status, {
      reason: edgeStatus.reason, time: edge.probe && edge.probe.observed_at
        ? when("probe 観測時刻", edge.probe.observed_at) : evaluatedAt(),
      children: [kv([
        ["Edge 準備完了", edge.ready],
        ["enforcement ready", enf.enforcement_ready],
        ["edge-baseline-ready", enf.edge_baseline_ready],
        ["commissioning 記録", enf.commissioning_record],
        ["probe 結果", edge.probe ? edge.probe.result : null],
        ["セキュリティ上の指摘", (edge.findings || []).filter(function (f) { return f.security; }).length + " 件"]
      ])]
    }));
    add(grid, card("実行モード", "observe-only-fixed", { tone: "info",
      reason: state.model.authority ? state.model.authority.reason_code : null, time: evaluatedAt(),
      children: [el("p", null, "observe-only：Nexus は Edge の実行結果を受理しない構成です。「実行中」の表示枠はありません。Edge の判断は常に would（未実行）として表示します。")] }));
    var noc = section("noc");
    add(grid, noc ? genericCard("通信（NOC）", noc, { compact: true, access: "noc_status" })
      : pendingCard("通信（NOC）", "noc"));
    var mio = section("mio") || {};
    var mioStatus = statusWithAccess(mio.status, mio.reason_code, "mio_route_ledger");
    var reading = mio.reading || {};
    add(grid, card("AI 経路（M.I.O.）", mioStatus.status, { reason: mioStatus.reason,
      time: when("記録時刻", reading.observed_at, mio.reason_code),
      children: [kv([["上限（記録）", reading.ceiling], ["状態", reading.state]]),
        el("p", "small", reading.notice || "")] }));
    var mioSnap = section("mio_status");
    add(grid, mioSnap ? genericCard("AI 経路（運用者向け snapshot）", mioSnap, { compact: true, access: "mio_status" })
      : pendingCard("AI 経路（運用者向け snapshot）", "mio_status"));
    var kl = section("knowledge_lite") || {};
    var klStatus = statusWithAccess(kl.status, kl.reason_code, "knowledge_lite");
    add(grid, card("Knowledge Lite", klStatus.status, { reason: klStatus.reason,
      time: evaluatedAt(), children: [kv([["鮮度", kl.freshness ? badge(kl.freshness) : null],
        ["世代", kl.generation]])] }));
    var ks = section("knowledge_status");
    add(grid, ks ? genericCard("Knowledge Lite（運用者向け snapshot）", ks, { compact: true, access: "knowledge_status" })
      : pendingCard("Knowledge Lite（運用者向け snapshot）", "knowledge_status"));
    var services = section("services");
    var units = (section("health") || []).filter(function (h) { return h.subject === "systemd units"; })[0];
    add(grid, services ? genericCard("サービス", services, { compact: true, access: "units_status" }) : card("サービス", "not_collected", {
      reason: state.model.pending.services, time: evaluatedAt(),
      children: units ? [reasonLine(units.reason_code)] : [] }));
    var storage = section("storage");
    var audit = (section("health") || []).filter(function (h) { return h.subject === "audit"; })[0];
    if (storage) { add(grid, genericCard("保存容量", storage)); } else {
      var auditStatus = audit ? statusWithAccess(audit.status, audit.reason_code, "audit_status") : { status: null, reason: null };
      add(grid, card("保存容量", "not_collected", { reason: state.model.pending.storage, time: evaluatedAt(),
        children: [block("監査の容量（auditd の snapshot）"), audit ? badge(auditStatus.status) : null,
          audit ? reasonLine(auditStatus.reason) : null, audit && audit.detail ? el("p", "small", audit.detail) : null,
          audit && audit.source ? when("観測時刻", audit.source.written_at, audit.source.reason_code) : null] }));
    }
    var loop = section("edge_loop") || {};
    ["intake", "explainer"].forEach(function (name) {
      var part = loop[name] || {};
      var src = part.source || {};
      var s = statusWithAccess(part.status, part.reason_code,
        name === "intake" ? "edge_intake_status" : "incident_explain_status");
      add(grid, card(name === "intake" ? "Edge 受信（intake）" : "説明器（explainer）", s.status, {
        reason: s.reason, time: when("観測時刻", src.written_at, src.reason_code) }));
    });
    var fabric = section("fabric") || {};
    add(grid, card("Fabric 状態表示", fabric.status, { reason: fabric.reason_code, time: evaluatedAt(),
      children: [kv([["版", fabric.version]])] }));
    var integ = section("integration") || {};
    add(grid, card("継続するもの", "continuing", { tone: "info", time: evaluatedAt(),
      children: [el("p", null, "どの状態でも継続：" + text(integ.continues || []))] }));
    panel.appendChild(grid);
  }

  function incidentCard(row) {
    var node = el("article", "card tone-info");
    node.appendChild(el("h3", null, "インシデント " + text(row.incident_id)));
    var facts = block("観測事実");
    add(facts, kv([["状態", badge(row.state)], ["最初の観測", when("時刻", row.first_seen)],
      ["最後の観測", when("時刻", row.last_seen)], ["件数", row.count], ["重大度（最大）", row.most_severe],
      ["手法 ID", row.technique_ids],
      ["証拠の保存", row.evidence_stored === false ? "保存できなかった" : "保存の失敗なし"]]));
    var decision = row.edge_decision || {};
    var judged = block("Edge の判断（would・未実行）");
    add(judged, el("p", null, "Edge は「" + word(decision.action).ja + "」と判断しました（would・未実行）。"),
      el("span", "en", "Edge would " + text(decision.action) + " (observe-only, not executed)"),
      kv([["判断者", decision.decided_by], ["実行", decision.executed], ["方針の理由", row.policy_reason]]));
    var result = row.execution_result || {};
    var executed = block("実際の執行結果");
    add(executed, el("p", null, "なし（Nexus は observe-only の判断だけを受理する構成）"), reasonLine(result.reason_code));
    var ex = row.explanation || {};
    var advice = block("助言");
    add(advice, badge(ex.content_kind), kv([["状態", badge(ex.state)], ["経路", ex.route], ["結果", ex.outcome],
      ["失敗コード", ex.failure_codes]]));
    if (ex.summary) { add(advice, el("p", "small", "要約（表示用テキスト。指示として扱わない）："), el("p", "summary", ex.summary)); }
    if (ex.notice) { add(advice, el("p", "summary", ex.notice)); }
    var refs = block("参照根拠");
    var items = (ex.knowledge_refs || []).map(function (r) {
      return text(r.technique_id) + " " + text(r.name) + "（claim " + text(r.claim_id) + "）";
    });
    add(refs, items.length ? list(items) : el("p", null, "参照根拠なし"));
    add(node, facts, judged, executed, advice, refs);
    return node;
  }

  function incidents(panel) {
    var loop = section("edge_loop") || {};
    add(panel, el("p", "banner", "観測事実・Edge の判断（would・未実行）・実際の執行結果・助言・参照根拠を分けて表示します。Nexus は判断も執行もしません。"));
    var grid = el("div", "grid");
    var intake = loop.intake || {};
    var isrc = intake.source || {};
    var is = statusWithAccess(intake.status, intake.reason_code, "edge_intake_status");
    var snap = intake.snapshot || {};
    var children = [];
    if (snap.edge_forward) {
      children.push(block("Edge 転送数（Edge の自己申告）"), kv([["送信", snap.edge_forward.sent],
        ["失敗", snap.edge_forward.failed], ["破棄", snap.edge_forward.dropped],
        ["鮮度", snap.edge_forward_freshness ? badge(snap.edge_forward_freshness.status) : null]]));
    }
    if (snap.decoy_status) {
      children.push(block("Decoy（Nexus 自身の観測。Edge のものではない）"), kv([
        ["待受", snap.decoy_status.listening], ["受理", snap.decoy ? snap.decoy.accepted : null],
        ["ハードウェアの証拠", snap.decoy_status.hardware_evidence]]));
    }
    if (intake.snapshot) {
      children.unshift(kv([["受理", snap.accepted], ["処理済み", snap.processed], ["未解決", snap.open_incidents]]));
    }
    add(grid, card("Edge 受信（intake）", is.status, { reason: is.reason,
      time: when("観測時刻", isrc.written_at, isrc.reason_code), children: children }));
    var recent = loop.recent || {};
    var rs = statusWithAccess(recent.status, recent.reason_code, "incident_recent");
    var rsrc = recent.source || {};
    add(grid, card("最近のインシデント（一覧の snapshot）", rs.status, { reason: rs.reason,
      time: when("観測時刻", rsrc.written_at, rsrc.reason_code) }));
    panel.appendChild(grid);
    var rows = recent.snapshot && Array.isArray(recent.snapshot.incidents) ? recent.snapshot.incidents : [];
    var list2 = el("div", "grid");
    rows.forEach(function (row) { list2.appendChild(incidentCard(row)); });
    if (!rows.length) { list2.appendChild(el("p", null, "表示できるインシデントはありません（一覧が無いか、読めないか、空です）。")); }
    add(panel, el("h2", null, "インシデント一覧"), list2);
  }

  function noc(panel) {
    var sec = section("noc");
    var grid = el("div", "grid");
    if (sec) { grid.appendChild(genericCard("NOC 受動観測", sec, { access: "noc_status" })); } else {
      grid.appendChild(card("NOC 受動観測", "not_collected", { reason: state.model.pending.noc, time: evaluatedAt(),
        children: [el("p", null, "interface・経路・DNS／DHCP 設定・通信量と誤りは、read model に NOC 節があると表示されます。到達性と名前解決は能動確認しません（受動観測のみ）。interface 名・アドレスはこの画面に出しません。")] }));
    }
    panel.appendChild(grid);
  }

  function knowledge(panel) {
    var grid = el("div", "grid");
    var kl = section("knowledge_lite") || {};
    var s = statusWithAccess(kl.status, kl.reason_code, "knowledge_lite");
    var readiness = kl.readiness || {};
    var crypto = kl.cryptographic_implementation || {};
    add(grid, card("Knowledge Lite", s.status, { reason: s.reason, time: evaluatedAt(), children: [
      kv([["鮮度", kl.freshness ? badge(kl.freshness) : null], ["世代", kl.generation],
        ["機能としての成立", readiness.word], ["暗号実装", crypto.status ? badge(crypto.status) : null]]),
      reasonLine(crypto.reason_code), block("意味すること"), el("p", null, readiness.means || ""),
      block("意味しないこと"), list(readiness.does_not_mean || [])] }));
    var ks = section("knowledge_status");
    add(grid, ks ? genericCard("Knowledge Lite（運用者向け snapshot）", ks, { access: "knowledge_status" })
      : pendingCard("Knowledge Lite（運用者向け snapshot）", "knowledge_status"));
    var modules = section("external_modules") || [];
    modules.forEach(function (m) {
      if (String(m.name).indexOf("Knowledge") === -1) { return; }
      add(grid, card("外部 Knowledge peer（" + text(m.name) + "）", m.state, { time: evaluatedAt(), children: [
        el("p", null, m.state === "absent" ? "未設定：peer は commission されていません（無いのが設計どおりの状態）。" : ""),
        el("p", "small", m.reason)] }));
    });
    var refs = [];
    var loop = section("edge_loop") || {};
    var rows = loop.recent && loop.recent.snapshot && Array.isArray(loop.recent.snapshot.incidents)
      ? loop.recent.snapshot.incidents : [];
    rows.forEach(function (row) {
      ((row.explanation || {}).knowledge_refs || []).forEach(function (r) {
        refs.push(text(r.technique_id) + " " + text(r.name) + "（claim " + text(r.claim_id) + "、インシデント " + text(row.incident_id) + "）");
      });
    });
    add(grid, card("引用元（最近のインシデントの参照根拠）", refs.length ? "read" : "none", { time: evaluatedAt(),
      children: [refs.length ? list(refs) : el("p", null, "引用はありません。")] }));
    panel.appendChild(grid);
  }

  function setup(panel) {
    if (state.model.lab_host) {
      panel.appendChild(el("p", "banner", "LAB HOST：このホストはラボ用です。commission などの本番手順はここでは利用できません。"));
    }
    add(panel, el("p", "banner", "コマンドは表示するだけです。この画面は何も実行しません。端末で内容を確認してから実行してください。"));
    var grid = el("div", "grid");
    var guide = state.model.setup || {};
    if (guide.status !== "read") {
      grid.appendChild(card("セットアップ手順", guide.status, { reason: guide.reason_code, time: evaluatedAt() }));
    } else {
      (guide.steps || []).forEach(function (step) {
        grid.appendChild(card(text(step.name), step.status, { time: evaluatedAt(), children: [
          el("p", null, step.reason || ""), step.next_command ? el("span", "small", "次のコマンド（表示のみ）") : null,
          step.next_command ? el("code", "cmd", step.next_command) : null] }));
      });
      grid.appendChild(card("provider admission", guide.provider_admission, { time: evaluatedAt(),
        children: [kv([["HG-05", guide.hg05], ["enforcement readiness", guide.enforcement_readiness]]),
          el("p", "small", guide.notice || "")] }));
    }
    var loop = section("edge_loop") || {};
    var explainer = loop.explainer && loop.explainer.snapshot ? loop.explainer.snapshot : null;
    if (explainer && explainer.chain_broken) {
      grid.appendChild(card("復旧：インシデントチェーン", "failed", { time: when("観測時刻", explainer.written_at),
        children: [el("p", null, "説明器のチェーンが壊れています。復旧の手掛かり："), el("code", "cmd", explainer.recovery_hint || "")] }));
    }
    (section("health") || []).forEach(function (h) {
      var accessName = h.subject === "audit" ? "audit_status" : null;
      var s = statusWithAccess(h.status, h.reason_code, accessName);
      grid.appendChild(card("health：" + text(h.subject), s.status === "ok" ? "ok" : s.status, {
        reason: s.reason, time: h.source && h.source.written_at !== undefined
          ? when("観測時刻", h.source.written_at, h.source.reason_code) : evaluatedAt(),
        children: [h.detail ? el("p", "small", h.detail) : null] }));
    });
    var services = section("services");
    add(grid, services ? genericCard("サービス（unit ごと）", services, { access: "units_status" })
      : pendingCard("サービス（unit ごと）", "services"));
    var storage = section("storage");
    add(grid, storage ? genericCard("保存容量（場所ごと）", storage) : pendingCard("保存容量（場所ごと）", "storage"));
    var actions = section("next_actions") || [];
    var acts = el("div", "card tone-info");
    acts.appendChild(el("h3", null, "次の操作（status の next）"));
    if (!actions.length) { acts.appendChild(el("p", null, "未処理の項目はありません。")); }
    actions.forEach(function (a) {
      var item = el("div", "block");
      if (a.lab_host_unavailable_step) {
        item.appendChild(el("p", null, a.lab_host_unavailable_step + "：ラボホストでは利用不可（本番配備が必要）"));
      } else {
        add(item, el("p", null, a.summary === null ? "（端末でのみ表示する内容）" : a.summary),
          a.command ? el("code", "cmd", a.command) : null);
      }
      acts.appendChild(item);
    });
    grid.appendChild(acts);
    var enf = section("enforcement") || {};
    if ((enf.missing_profiles || []).length) {
      grid.appendChild(card("不足している profile", "needed", { reason: enf.reason_code, time: evaluatedAt(),
        children: [list(enf.missing_profiles)] }));
    }
    panel.appendChild(grid);
  }

  var SCREENS = { overview: overview, incidents: incidents, noc: noc, knowledge: knowledge, setup: setup };

  function originBanner() {
    var box = $("origin");
    clear(box);
    var m = state.model;
    if (!m) { return; }
    var origin = m.origin || {};
    if (origin.kind === "fixture") {
      add(box, el("p", "banner", "fixture 表示：保存済みの read model を表示しています。このノードの現在の状態ではありません。"));
    } else {
      add(box, el("p", "small", "出所：このノードの read model（" + text(origin.reader) + "、アカウント " + text(origin.account) + " で読取）"));
    }
    if (m.read_model && m.read_model.status !== "read") {
      add(box, el("p", "banner bad", "read model を取得できません：" + reasonText(m.read_model.reason_code)),
        el("span", "en", m.read_model.reason_code));
    }
  }

  function summary() {
    var parts = [];
    var edge = section("edge_core");
    if (edge) { parts.push("Edge " + word(edge.status).ja); }
    var kl = section("knowledge_lite");
    if (kl) { parts.push("Knowledge " + word(kl.status).ja); }
    var mio = section("mio");
    if (mio) { parts.push("AI 経路 " + word(mio.status).ja); }
    var loop = section("edge_loop");
    var rows = loop && loop.recent && loop.recent.snapshot ? loop.recent.snapshot.incidents || [] : [];
    parts.push("インシデント " + rows.length + " 件");
    return "概況：" + parts.join("、");
  }

  function render() {
    originBanner();
    Object.keys(SCREENS).forEach(function (name) {
      var panel = $("panel-" + name);
      clear(panel);
      add(panel, el("h2", null, state.labels.sections[name]));
      try { SCREENS[name](panel); } catch (e) {
        panel.appendChild(el("p", "banner bad", "この画面を表示できません（表示側の内部エラー）。"));
      }
    });
    var said = summary();
    if (said !== state.announced) { state.announced = said; $("live").textContent = said; }
  }

  // -- connection, login, polling ---------------------------------------------

  function showConn() {
    var box = $("conn");
    clear(box);
    if (state.failing) {
      add(box, el("p", "banner bad", "UI サーバーに接続できません。表示は最終取得時点のものです" +
        (state.lastOk ? "（" + age(state.lastOk) + "）。" : "。")));
    } else if (state.lastOk) {
      add(box, el("span", "small", "最終取得：" + new Date(state.lastOk).toLocaleTimeString("ja-JP")));
    }
  }

  function request(method, path, body, token) {
    var headers = { "Accept": "application/json" };
    var options = { method: method, credentials: "same-origin", cache: "no-store", headers: headers,
      redirect: "error", referrerPolicy: "no-referrer" };
    if (method === "POST") {
      headers["Content-Type"] = "application/json";
      headers["X-CSRF-Token"] = token || "";
      options.body = JSON.stringify(body || {});
    }
    return fetch(path, options).then(function (response) {
      return response.json().then(function (data) { return { status: response.status, data: data }; },
        function () { return { status: response.status, data: {} }; });
    });
  }

  function showLogin(message) {
    stopPolling();
    state.csrf = null;
    $("login").hidden = false;
    $("tabs").hidden = true;
    $("panels").hidden = true;
    $("logout").hidden = true;
    $("login-msg").textContent = message || "";
    return request("GET", "/api/session").then(function (r) {
      state.loginToken = r.data.login_token || null;
      if (r.data.authenticated) { state.csrf = r.data.csrf; showApp(); }
    });
  }

  function showApp() {
    $("login").hidden = true;
    $("tabs").hidden = false;
    $("panels").hidden = false;
    $("logout").hidden = false;
    $("login-code").value = "";
    poll();
  }

  function stopPolling() { if (state.timer) { clearTimeout(state.timer); state.timer = null; } }

  function poll() {
    stopPolling();
    request("GET", "/api/view").then(function (r) {
      if (r.status === 401) { showLogin("セッションが終了しました。もう一度ログインしてください。"); return; }
      if (r.status !== 200) { throw new Error("status"); }
      state.model = r.data;
      state.lastOk = Date.now();
      state.failing = false;
      render();
      showConn();
      state.timer = setTimeout(poll, POLL_MS);
    }).catch(function () {
      state.failing = true;
      showConn();
      state.timer = setTimeout(poll, POLL_MS);
    });
  }

  function selectTab(name, focus) {
    Object.keys(SCREENS).forEach(function (n) {
      var tab = $("tab-" + n);
      var on = n === name;
      tab.setAttribute("aria-selected", on ? "true" : "false");
      tab.tabIndex = on ? 0 : -1;
      $("panel-" + n).hidden = !on;
      if (on && focus) { tab.focus(); }
    });
  }

  function wire() {
    var names = Object.keys(SCREENS);
    names.forEach(function (name, index) {
      var tab = $("tab-" + name);
      tab.addEventListener("click", function () { selectTab(name, false); });
      tab.addEventListener("keydown", function (event) {
        var next = null;
        if (event.key === "ArrowRight") { next = names[(index + 1) % names.length]; }
        if (event.key === "ArrowLeft") { next = names[(index + names.length - 1) % names.length]; }
        if (event.key === "Home") { next = names[0]; }
        if (event.key === "End") { next = names[names.length - 1]; }
        if (next) { event.preventDefault(); selectTab(next, true); }
      });
    });
    $("login-form").addEventListener("submit", function (event) {
      event.preventDefault();
      var code = $("login-code").value;
      request("POST", "/api/login", { code: code }, state.loginToken).then(function (r) {
        if (r.status === 200 && r.data.authenticated) { state.csrf = r.data.csrf; showApp(); return; }
        var reason = r.data && r.data.error;
        showLogin(LOGIN_ERRORS[reason] || "ログインできませんでした。");
      }).catch(function () { $("login-msg").textContent = "UI サーバーに接続できません。"; });
    });
    $("logout").addEventListener("click", function () {
      request("POST", "/api/logout", {}, state.csrf).then(function () { showLogin("ログアウトしました。"); },
        function () { showLogin(""); });
    });
  }

  function start() {
    wire();
    request("GET", "/static/labels.json").then(function (r) {
      state.labels = r.data;
      return request("GET", "/api/session");
    }).then(function (r) {
      if (r.data.authenticated) { state.csrf = r.data.csrf; showApp(); } else {
        state.loginToken = r.data.login_token || null;
        $("login").hidden = false;
      }
    }).catch(function () {
      state.failing = true;
      showConn();
    });
  }

  document.addEventListener("DOMContentLoaded", start);
}());
