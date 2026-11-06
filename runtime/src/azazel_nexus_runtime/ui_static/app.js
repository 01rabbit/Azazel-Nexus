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

  /* A field name: its Japanese label with the name itself in small type. */
  function keyLabel(key) {
    var table = state.labels && state.labels.keys ? state.labels.keys : {};
    var known = Object.prototype.hasOwnProperty.call(table, key);
    var node = el("span", "key");
    add(node, el("span", null, known ? table[key] : "（未登録の項目名）"), el("span", "en", key));
    return node;
  }

  function knownText(value) {
    var table = state.labels && state.labels.texts ? state.labels.texts : {};
    return typeof value === "string" && Object.prototype.hasOwnProperty.call(table, value) ? table[value] : null;
  }

  /* A sentence from the node. A fixed one is shown in Japanese with the
     original in small type; any other is shown as the original, labelled so. */
  function prose(value) {
    if (value === null || value === undefined || value === "") { return null; }
    var original = String(value);
    var ja = knownText(original);
    var node = el("div", "prose");
    if (ja !== null) { add(node, el("p", null, ja), el("p", "small orig", "原文：" + original)); }
    else { node.appendChild(el("p", "small orig", "詳細（英語の原文）：" + original)); }
    return node;
  }

  function humanBytes(n) {
    if (typeof n !== "number" || !isFinite(n) || n < 0) { return null; }
    var units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? String(n) : n.toFixed(n < 10 ? 2 : 1)) + " " + units[i];
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

  function duration(s) {
    if (typeof s !== "number" || !isFinite(s) || s < 0) { return "不明"; }
    if (s < 120) { return s + " 秒"; }
    if (s < 7200) { return Math.round(s / 60) + " 分"; }
    if (s < 172800) { return Math.round(s / 3600) + " 時間"; }
    return Math.round(s / 86400) + " 日";
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
      var dt = el("dt");
      if (row[0] instanceof Node) { dt.appendChild(row[0]); } else { dt.textContent = text(row[0]); }
      add(dl, dt, dd);
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
    var node = el("article", "card tone-" + tone + (opts.wide ? " wide" : ""));
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
      if (WORD_KEYS[key] && typeof v === "string") { rows.push([keyLabel(key), badge(v)]); }
      else if (REASON_KEYS[key] && typeof v === "string") { rows.push([keyLabel(key), reasonLine(v)]); }
      else if (key === "conditions" && Array.isArray(v) && v.length) { rows.push([keyLabel(key), list(v.map(reasonLine))]); }
      else if (/_at$/.test(key) && typeof v === "number") { rows.push([keyLabel(key), when("時刻", v)]); }
      else if (knownText(v) !== null) { rows.push([keyLabel(key), prose(v)]); }
      else if (v !== null && typeof v === "object") { rows.push([keyLabel(key), tree(v, depth + 1)]); }
      else { rows.push([keyLabel(key), v]); }
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
      children: (opts.notes || []).concat([tree(rows, 0)]) });
  }

  /* Storage: one row per location -- where, its word, available / total in
     readable units. A null value is left out, never shown as "なし". */
  function storageCard(title, sec) {
    var source = sec.source || {};
    var table = el("table", "loc");
    var head = el("tr");
    ["場所", "状態", "空き / 全体"].forEach(function (h) { head.appendChild(el("th", null, h)); });
    table.appendChild(head);
    var keys = state.labels && state.labels.keys ? state.labels.keys : {};
    (sec.locations || []).forEach(function (loc) {
      var tr = el("tr");
      var where = el("td");
      var name = Object.prototype.hasOwnProperty.call(keys, loc.label) ? keys[loc.label] : text(loc.label);
      add(where, el("span", null, name), el("span", "en", loc.label));
      if (loc.read_only === true) { where.appendChild(el("span", "note", "読取専用")); }
      if (loc.same_filesystem_as) {
        var same = Object.prototype.hasOwnProperty.call(keys, loc.same_filesystem_as) ? keys[loc.same_filesystem_as] : loc.same_filesystem_as;
        where.appendChild(el("span", "note", "「" + same + "」と同じファイルシステム"));
      }
      var st = el("td");
      add(st, badge(loc.status), loc.reason_code ? reasonLine(loc.reason_code) : null);
      var size = el("td", "num");
      var avail = humanBytes(loc.available_bytes);
      var total = humanBytes(loc.total_bytes);
      if (avail !== null || total !== null) { size.textContent = (avail !== null ? avail : "") + (total !== null ? " / " + total : ""); }
      add(tr, where, st, size);
      table.appendChild(tr);
    });
    var s = statusWithAccess(sec.status, sec.reason_code, null);
    return card(title, s.status, { reason: s.reason, wide: true,
      time: when("観測時刻", source.observed_at, source.reason_code),
      children: [table, el("p", "small", "空きは root 以外が使える量（available）。")] });
  }

  /* Units: one row per unit -- its word, systemd's three states, the reason. */
  function unitsCard(title, sec) {
    var s = statusWithAccess(sec.status, sec.reason_code, "units_status");
    var source = sec.source || {};
    var units = sec.snapshot && Array.isArray(sec.snapshot.units) ? sec.snapshot.units : [];
    var children = [];
    if ((sec.conditions || []).length) { children.push(list(sec.conditions.map(reasonLine))); }
    if (units.length) {
      var table = el("table", "loc");
      var head = el("tr");
      ["unit", "状態", "systemd（読込・稼働・詳細）"].forEach(function (h) { head.appendChild(el("th", null, h)); });
      table.appendChild(head);
      units.forEach(function (u) {
        var tr = el("tr");
        var st = el("td");
        add(st, badge(u.status), u.reason_code ? reasonLine(u.reason_code) : null);
        var states = [u.load_state, u.active_state, u.sub_state].filter(function (x) { return x !== null && x !== undefined; });
        var sd = el("td", null, states.join(" / "));
        // `not-loaded` is GetUnit's word: a oneshot whose unit object was
        // released after it stopped says it too, so it is not "not installed".
        if (u.load_state && state.labels.summary && state.labels.summary.load_state[u.load_state]) {
          sd.appendChild(el("span", "note", state.labels.summary.load_state[u.load_state]));
        }
        add(tr, el("td", "unit", text(u.unit)), st, sd);
        table.appendChild(tr);
      });
      children.push(table);
    }
    return card(title, s.status, { reason: s.reason, wide: true,
      time: when("観測時刻", source.written_at, source.reason_code), children: children });
  }

  function positive(status) {
    var tone = word(status).tone;
    return tone === "ok" || tone === "info";
  }

  /* The same thing read two ways: directly by this page's account, and from
     the snapshot its daemon writes. Each card says which path it is; a direct
     read this account may not make says so; and when the two disagree, both
     cards say they disagree instead of leaving one to look wrong. */
  function pairNotes(direct, snapSec, snapAccess, daemon) {
    var snap = snapSec ? statusWithAccess(snapSec.status, snapSec.reason_code, snapAccess) : null;
    var forDirect = [el("p", "small path", "経路：この画面のアカウント（azui）が直接読んだ結果")];
    var copy = state.model && state.model.snapshot_reader === "ui" ? "の UI 用コピー（run/ui-read、azui が読める）" : "";
    var forSnap = [el("p", "small path", "経路：daemon（" + daemon + "）が書いた snapshot" + copy + "。直接の読取とは別の経路")];
    if (direct.status === "permission_denied") {
      forDirect.push(el("p", "note", "このアカウントでは直接読めません。daemon の snapshot（「運用者向け snapshot」のカード）を参照してください。"));
    } else if (snap && snap.status !== "permission_denied" && positive(direct.status) !== positive(snap.status)) {
      var said = "▲ 直接の読取（" + word(direct.status).ja + "）と daemon の snapshot（" + word(snap.status).ja +
        "）が一致しません。直接の読取は情報源が無い・読めない・壊れている場合に、snapshot は daemon が別の状態を見ているか古い場合に食い違います。各カードの理由と時刻を確認してください。";
      forDirect.push(el("p", "note warn", said));
      forSnap.push(el("p", "note warn", said));
    }
    return { direct: forDirect, snap: forSnap };
  }

  // -- screens ---------------------------------------------------------------

  /* The four answers of the normal screen (`ui_model.summarize`): is
     communication kept, what is happening, what is handled automatically,
     what the person on duty does next. Observed facts, AI inference, Edge's
     decision and the execution result are separate blocks, never merged. */
  var BASIS_TITLES = { observed: "観測事実", ai_inference: "AI の推測", edge_decision: "Edge の判断（would・未実行）",
    execution_result: "実際の執行結果" };

  function basisLine(b) {
    var text_ = label("basis", b.code);
    var node = el("li");
    node.appendChild(el("span", null, text_));
    if (b.code === "default_route" && b.families) {
      node.appendChild(el("span", "note", "IPv4：" + label("path", b.families.ipv4) + "、IPv6：" + label("path", b.families.ipv6)));
      if (b.observed_at !== undefined) { node.appendChild(when("観測時刻", b.observed_at)); }
    } else if (b.code === "edge_unit_state") {
      node.appendChild(el("span", "note", "azazel-edge-core.service：" + text(b.active_state)));
    } else if (b.code === "open_incidents_total") {
      node.appendChild(el("span", "note", typeof b.count === "number" ? "未解決 " + b.count + " 件（受信側の台帳の件数）"
        : "受信側の件数を確認できない"));
    } else if (b.code === "open_incidents_listed") {
      node.appendChild(el("span", "note", "一覧の未解決 " + b.count + " 件（一覧は最新 " + b.shown + " 件まで）" +
        (typeof b.most_severe === "number" ? "、最も重大な重大度 " + b.most_severe + "（数値が小さいほど重大）" : "")));
      if (b.latest !== null && b.latest !== undefined) { node.appendChild(when("最後の観測", b.latest)); }
      if (b.reason_code) { node.appendChild(reasonLine(b.reason_code)); }
    } else if (b.code === "list_differs_from_intake") {
      node.appendChild(el("span", "note warn", "受信側は " + b.count + " 件、一覧は " + b.listed + " 件。" +
        (b.listed < b.count ? "一覧に載っていない未解決があり得る（一覧は最新 20 件まで、説明器の遅れ・失敗で欠ける）"
          : "一覧に未解決が残っているが受信側の件数は少ない（終了の反映遅れの可能性）")));
    } else if (b.code === "explainer_behind") {
      node.appendChild(el("span", "note warn", text(b.counter) + "：" + b.count));
    } else if (b.code === "ai_explanations") {
      node.appendChild(el("span", "note", b.count + " 件に AI の説明あり（推測。事実ではない）"));
    } else if (b.code === "would_not_executed") {
      var acts = Object.keys(b.actions || {});
      node.appendChild(el("span", "note", acts.length ? acts.map(function (a) {
        return word(a).ja + "（" + a + "）" + b.actions[a] + " 件"; }).join("、") : "未解決のインシデントに Edge の判断はありません"));
    } else if (b.reason_code) {
      node.appendChild(reasonLine(b.reason_code));
    }
    node.appendChild(el("span", "en", b.code));
    return node;
  }

  function label(kind, value) {
    var table = state.labels && state.labels.summary && state.labels.summary[kind] ? state.labels.summary[kind] : {};
    if (value === null || value === undefined) { return "未観測"; }
    return Object.prototype.hasOwnProperty.call(table, value) ? table[value] : "（未登録：" + value + "）";
  }

  function answerCard(title, a) {
    a = a || { status: null, basis: [] };
    var children = [];
    BASIS_KINDS.forEach(function (kind) {
      var items = (a.basis || []).filter(function (b) { return b.kind === kind; });
      if (!items.length) { return; }
      var b = block(BASIS_TITLES[kind]);
      b.appendChild(list(items.map(basisLine)));
      children.push(b);
    });
    if (a.intake) { children.push(el("p", "small", "受信（intake）の状態：" + reasonText(a.intake))); }
    return card(title, a.status, { reason: a.reason_code, wide: true, time: evaluatedAt(), children: children });
  }

  var BASIS_KINDS = ["observed", "ai_inference", "edge_decision", "execution_result"];

  function nextCard(a) {
    a = a || { status: null, items: [] };
    var ol = el("ol", "steps");
    (a.items || []).forEach(function (item) {
      var li = el("li");
      add(li, el("p", null, label("next", item.code)), el("span", "en", item.code));
      if (item.sources) { li.appendChild(el("p", "small", "対象：" + item.sources.map(function (s) {
        return label("source", s); }).join("、"))); }
      if (item.step) { li.appendChild(el("p", "small", "手順：" + text(item.step))); }
      if (item.screen) { li.appendChild(el("p", "small", "画面：" + text(state.labels.sections[item.screen] || item.screen))); }
      if (item.command) { add(li, el("span", "small", "端末のコマンド（表示のみ。この画面は実行しない）"), el("code", "cmd", item.command)); }
      ol.appendChild(li);
    });
    return card("担当者が次にすること", a.status, { reason: a.reason_code, wide: true, time: evaluatedAt(), children: [ol] });
  }

  function overview(panel) {
    var s = state.model.summary || {};
    add(panel, el("p", "banner", "この画面は 4 つの問いに答えます。観測事実・AI の推測・Edge の判断・実際の執行結果を分けて示し、未知・古い・権限がない情報は「正常」と表示しません。専門的な情報は「詳細」画面にあります。"));
    var grid = el("div", "grid");
    add(grid, answerCard("通信は維持されているか", s.communication),
      answerCard("何が起きているか", s.events),
      answerCard("何を自動対処しているか", s.response),
      nextCard(s.next));
    panel.appendChild(grid);
  }

  /* The operator_view section (S-04): admission gates, catalog, import and
     the confirmations an operator may be asked for. Each row's value and
     reason as the read adapter gave them; an unread input says so. */
  function operatorViewCard(ov) {
    if (!ov) { return pendingCard("モデル・提供元の承認（operator view）", "operator_view"); }
    var children = [];
    var provider = ov.provider || {};
    children.push(block("提供元（provider）の状態"), kv([["状態", provider.state],
      ["承認の切替（ビルド）", ov.admission_build_switch]]));
    if ((provider.reason_codes || []).length) { children.push(list(provider.reason_codes.map(reasonLine))); }
    var inputs = ov.inputs || {};
    children.push(block("読んだ情報源"), kv(Object.keys(inputs).sort().map(function (k) {
      return [keyLabel(k), badge(inputs[k])]; })));
    (ov.sections || []).forEach(function (sec) {
      var b = block(label("ov_section", sec.key));
      b.appendChild(list((sec.rows || []).map(function (r) {
        var li = el("div", "row");
        if (r.axis === undefined && r.nominal_gib !== undefined) {
          add(li, keyLabel("possibility"), el("span", null, " " + r.nominal_gib + " GiB → " + text(r.profile) +
            (r.is_this_node ? "（このノード）" : "")));
          return li;
        }
        add(li, keyLabel(r.axis), el("span", null, " " + text(r.value)),
          r.reason_code ? reasonLine(r.reason_code) : null, prose(r.reason));
        return li;
      })));
      children.push(b);
    });
    var ops = block("運用者が行う確認（この画面からは実行できない）");
    ops.appendChild(list((ov.operations || []).map(function (o) {
      var li = el("div", "row");
      add(li, el("span", null, label("confirmation", o.confirmation) + "：" + (o.available ? "可能" : "不可")),
        el("span", "en", o.confirmation), prose(o.reason));
      return li;
    })));
    children.push(ops, prose(ov.status_sentence));
    return card("モデル・提供元の承認（operator view）", ov.status, { reason: ov.reason_code, wide: true,
      time: evaluatedAt(), children: children });
  }

  function detail(panel) {
    var grid = el("div", "grid");
    // First: which admission gates refuse, and what this account could read.
    add(grid, operatorViewCard(section("operator_view")));
    var edge = section("edge_core") || {};
    var enf = section("enforcement") || {};
    var edgeStatus = statusWithAccess(edge.status, edge.reason_code, null);
    add(grid, card("防御状態（Edge）", edgeStatus.status, {
      reason: edgeStatus.reason, time: edge.probe && edge.probe.observed_at
        ? when("probe 観測時刻", edge.probe.observed_at) : evaluatedAt(),
      children: [kv([
        ["Edge 準備完了", edge.ready],
        ["執行の準備（enforcement ready）", enf.enforcement_ready],
        ["Edge 基準の準備（edge-baseline-ready）", enf.edge_baseline_ready],
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
    // How long the reading has been unchanged is information, not a verdict;
    // stale comes only from the writer's liveness evidence (#358 option 1).
    var live = mio.liveness || {};
    var evidence = { operator_snapshot: "運用者向け snapshot", route_ledger_record: "route ledger の記録" };
    var mioSnap = section("mio_status");
    var mioNotes = pairNotes(mioStatus, mioSnap, "mio_status", "mio-entryd");
    add(grid, card("AI 経路（M.I.O.）", mioStatus.status, { reason: mioStatus.reason,
      time: when("記録時刻", reading.observed_at, mio.reason_code),
      children: mioNotes.direct.concat([kv([["上限（記録）", reading.ceiling], ["状態", reading.state],
        ["変化していない期間（情報）", duration(mio.age_s)],
        ["書き手（entryd）の生存", badge(live.status)],
        ["生存の証拠", Object.prototype.hasOwnProperty.call(evidence, live.evidence) ? evidence[live.evidence] : "なし"],
        live.reason_code ? ["生存の判定理由", reasonLine(live.reason_code)] : null]),
        prose(reading.notice)]) }));
    add(grid, mioSnap ? genericCard("AI 経路（運用者向け snapshot）", mioSnap, { compact: true, access: "mio_status",
      notes: mioNotes.snap }) : pendingCard("AI 経路（運用者向け snapshot）", "mio_status"));
    var kl = section("knowledge_lite") || {};
    var klStatus = statusWithAccess(kl.status, kl.reason_code, "knowledge_lite");
    var ks = section("knowledge_status");
    var klNotes = pairNotes(klStatus, ks, "knowledge_status", "knowledge-lited");
    add(grid, card("Knowledge Lite", klStatus.status, { reason: klStatus.reason,
      time: evaluatedAt(), children: klNotes.direct.concat([kv([["鮮度", kl.freshness ? badge(kl.freshness) : null],
        ["世代", kl.generation]])]) }));
    add(grid, ks ? genericCard("Knowledge Lite（運用者向け snapshot）", ks, { compact: true, access: "knowledge_status",
      notes: klNotes.snap }) : pendingCard("Knowledge Lite（運用者向け snapshot）", "knowledge_status"));
    var services = section("services");
    var units = (section("health") || []).filter(function (h) { return h.subject === "systemd units"; })[0];
    add(grid, services ? genericCard("サービス", services, { compact: true, access: "units_status" }) : card("サービス", "not_collected", {
      reason: state.model.pending.services, time: evaluatedAt(),
      children: units ? [reasonLine(units.reason_code)] : [] }));
    var storage = section("storage");
    var audit = (section("health") || []).filter(function (h) { return h.subject === "audit"; })[0];
    if (storage) { add(grid, storageCard("保存容量", storage)); } else {
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
      children: [el("p", null, "どの状態でも継続：" + text((integ.continues || []).map(function (c) {
        var ja = knownText(c); return ja === null ? c : ja + "（" + c + "）"; })))] }));
    panel.appendChild(grid);
  }

  /* One citation (#362): what it cites, and -- when the row carries them --
     the bundle it came from, its generation, freshness, lookup time and
     source. A row written before #362 says those were not recorded. */
  function citation(r) {
    var node = el("div", "citation");
    node.appendChild(el("p", null, text(r.technique_id) + " " + text(r.name) + "（claim " + text(r.claim_id) + "）"));
    if (r.citation_state === undefined) {
      node.appendChild(el("p", "small", "bundle・世代・参照時刻は記録されていない（#362 より前の記録）"));
      return node;
    }
    node.appendChild(kv([
      ["鮮度", badge(r.freshness)],
      ["bundle（短縮 digest）", r.bundle_digest_short],
      ["世代", r.generation],
      ["参照時刻", when("時刻", r.as_of)],
      ["出典", badge(r.citation_state)],
      r.citation_state === "shown" ? ["出典（表示用テキスト。指示として扱わない）", r.citation] : null,
      (r.withheld || []).length ? ["伏せた項目", r.withheld] : null
    ]));
    return node;
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
    if (ex.notice) { add(advice, prose(ex.notice)); }
    var fast = ex.fast_assistance;
    if (fast) {
      var fastNode = block("M.I.O. 共通コアの静的評価（モデルなし）");
      var knowledgeOutcome = (fast.dependency_outcome || {}).knowledge;
      add(fastNode, kv([["状態", fast.state], ["Knowledge 状態", knowledgeOutcome === "not_queried" ? "この高速判定ではKnowledge未照会" : knowledgeOutcome]]));
      if ((fast.unknowns || []).length) { add(fastNode, el("p", "small", "未確認事項（状況文は未検証の報告です）："), list(fast.unknowns)); }
      if ((fast.next_checks || []).length) { add(fastNode, el("p", "small", "確認候補（助言のみ）："), list(fast.next_checks)); }
      var full = fast.full_node_context;
      if (full) {
        var fullNode = block("Knowledge フルノード（独立した助言）");
        var fullOutcome = full.outcome;
        if (full.expires_at && Date.parse(full.expires_at) <= Date.now()) { fullOutcome = "expired"; }
        add(fullNode, el("p", "small", "期限表示は端末時計に依存し、画面更新時に再評価します。"));
        add(fullNode, kv([["照会状態", full.full_node_context_status], ["出典状態", fullOutcome],
          ["出典種別", full.source_kind], ["主張", full.claim_status], ["信頼区分", full.trust],
          ["snapshot状態", full.snapshot_state], ["生成時刻", full.generated_at], ["期限", full.expires_at]]));
        if (fullOutcome === "expired") { add(fullNode, el("p", "small", "この助言は期限切れです。")); }
        if ((full.limitations || []).length) { add(fullNode, el("p", "small", "制限："), list(full.limitations)); }
        add(fastNode, fullNode);
      }
      (fast.knowledge || []).forEach(function (item) {
        add(fastNode, el("p", "small", "Knowledge Lite・報告済み未検証の参照: " + text(item.technique_id) + " — " + text(item.name)));
        if (item.summary) { add(fastNode, el("p", "small", text(item.summary))); }
        add(fastNode, el("p", "small", "鮮度: " + text(item.freshness) + "・参照時刻: " + text(item.as_of) + "・失効状態: " + text(item.revocation_status)));
        if (item.citation) { add(fastNode, el("p", "small", "出典: " + text(item.citation))); }
      });
      add(node, fastNode);
    }
    var slow = ex.slow_analysis;
    if (slow) {
      var slowNode = block("M.I.O. 非同期モデル提案（未検証・助言のみ）");
      add(slowNode, kv([["状態", slow.state], ["検証区分", slow.verification], ["使用量", slow.usage]]));
      var budget = slow.budget;
      if (budget) {
        add(slowNode, kv([["生成予算", budget.outcome], ["資料の範囲", budget.coverage],
          ["省略件数", budget.omitted_units], ["停止確認", ({pending:"停止確認待ち",confirmed:"停止確認済み",unconfirmed:"停止未確認",not_needed:"停止要求なし"})[budget.cleanup_state]],
          ["後発の失効", budget.superseded ? "失効" : "なし"]]));
        if (budget.outcome === "legacy_unverified") {
          add(slowNode, el("p", "small", "旧記録・予算未確認。高速評価の静的助言を参照してください。"));
        } else if (budget.outcome === "unsupported") {
          add(slowNode, el("p", "small", "未対応の生成予算形式です。高速評価の静的助言を参照してください。"));
        }
        if (budget.coverage === "selected") {
          add(slowNode, el("p", "small", "選択した根拠に基づく生成助言（未検証、一部資料省略）"));
        }
      } else if (slow.state === "complete") {
        add(slowNode, el("p", "small", "旧記録・生成予算未確認。高速評価の静的助言を参照してください。"));
      }
      add(slowNode, el("p", "small", "Edge の判断、説明台帳の記録、高速評価とは別の時間軸です。事実・判断・実行指示として扱わないでください。"));
      if (slow.state === "complete" && slow.verification === "model_proposed_unverified" &&
          budget && budget.version === 1 && budget.outcome === "within_budget" &&
          (budget.coverage === "intact" || budget.coverage === "selected") &&
          budget.cleanup_state === "not_needed" && budget.superseded === false) {
        [["仮説（未検証）", slow.hypotheses], ["未確認事項", slow.unknowns], ["確認候補", slow.next_checks]]
          .forEach(function (entry) {
            if (Array.isArray(entry[1]) && entry[1].length) {
              add(slowNode, el("p", "small", entry[0]), list(entry[1]));
            }
          });
      }
      add(node, slowNode);
    }
    var refs = block("参照根拠");
    var items = (ex.knowledge_refs || []).map(citation);
    add(refs, items.length ? list(items) : el("p", null, "参照根拠なし"));
    if (typeof ex.knowledge_refs_omitted === "number") {
      add(refs, el("p", "small", "ほかに " + ex.knowledge_refs_omitted + " 件の引用が記録されている（表示していない）"));
    }
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

  /* The verified bundle's display facts (#362). `null` is "none", and a fact
     the read model withheld says so instead of looking absent. */
  function bundleFacts(kl) {
    var b = kl.bundle;
    var withheld = kl.withheld || [];
    if (!b) {
      var hidden = withheld.some(function (w) { return String(w).indexOf("bundle.") === 0; });
      return el("p", null, hidden ? "伏せた（信頼済みの bundle ではない、または形が正しくない）" : "なし（信頼済みの bundle を読んでいない）");
    }
    function fact(name) { return b[name] === null && withheld.indexOf("bundle." + name) !== -1 ? "伏せた" : b[name]; }
    return kv([["短縮 digest", fact("digest_short")], ["署名鍵 ID", fact("signer_key_ids")],
      ["静的な主張", fact("static_count")], ["期限つきの主張", fact("current_count")],
      ["最も近い期限", b.next_expiry ? when("期限", b.next_expiry) : fact("next_expiry")]]);
  }

  function knowledge(panel) {
    var grid = el("div", "grid");
    var kl = section("knowledge_lite") || {};
    var s = statusWithAccess(kl.status, kl.reason_code, "knowledge_lite");
    var readiness = kl.readiness || {};
    var crypto = kl.cryptographic_implementation || {};
    var ks = section("knowledge_status");
    var notes = pairNotes(s, ks, "knowledge_status", "knowledge-lited");
    add(grid, card("Knowledge Lite", s.status, { reason: s.reason, time: evaluatedAt(), children: notes.direct.concat([
      kv([["鮮度", kl.freshness ? badge(kl.freshness) : null], ["世代", kl.generation],
        ["機能としての成立", readiness.word], ["暗号実装", crypto.status ? badge(crypto.status) : null]]),
      block("bundle（信頼済みのときだけ）"), bundleFacts(kl),
      reasonLine(crypto.reason_code), block("意味すること"), prose(readiness.means),
      block("意味しないこと"), list((readiness.does_not_mean || []).map(prose))]) }));
    add(grid, ks ? genericCard("Knowledge Lite（運用者向け snapshot）", ks, { access: "knowledge_status", notes: notes.snap })
      : pendingCard("Knowledge Lite（運用者向け snapshot）", "knowledge_status"));
    var modules = section("external_modules") || [];
    modules.forEach(function (m) {
      if (String(m.name).indexOf("Knowledge") === -1) { return; }
      add(grid, card("外部 Knowledge peer（" + text(m.name) + "）", m.state, { time: evaluatedAt(), children: [
        el("p", null, m.state === "absent" ? "未設定：peer は commission されていません（無いのが設計どおりの状態）。" : ""),
        prose(m.reason)] }));
    });
    var refs = [];
    var loop = section("edge_loop") || {};
    var rows = loop.recent && loop.recent.snapshot && Array.isArray(loop.recent.snapshot.incidents)
      ? loop.recent.snapshot.incidents : [];
    rows.forEach(function (row) {
      ((row.explanation || {}).knowledge_refs || []).forEach(function (r) {
        var item = citation(r);
        item.appendChild(el("p", "small", "インシデント " + text(row.incident_id)));
        refs.push(item);
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
          prose(step.reason), step.next_command ? el("span", "small", "次のコマンド（表示のみ）") : null,
          step.next_command ? el("code", "cmd", step.next_command) : null] }));
      });
      grid.appendChild(card("provider admission（提供元の承認）", guide.provider_admission, { time: evaluatedAt(),
        children: [kv([["HG-05（Core 予約の測定）", guide.hg05], ["執行の準備（enforcement readiness）", guide.enforcement_readiness]]),
          prose(guide.notice)] }));
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
        children: [prose(h.detail)] }));
    });
    var services = section("services");
    add(grid, services ? unitsCard("サービス（unit ごと）", services)
      : pendingCard("サービス（unit ごと）", "services"));
    var storage = section("storage");
    add(grid, storage ? storageCard("保存容量（場所ごと）", storage) : pendingCard("保存容量（場所ごと）", "storage"));
    var actions = section("next_actions") || [];
    var acts = el("div", "card tone-info");
    acts.appendChild(el("h3", null, "次の操作（status の next）"));
    if (!actions.length) { acts.appendChild(el("p", null, "未処理の項目はありません。")); }
    actions.forEach(function (a) {
      var item = el("div", "block");
      if (a.lab_host_unavailable_step) {
        item.appendChild(el("p", null, a.lab_host_unavailable_step + "：ラボホストでは利用不可（本番配備が必要）"));
      } else {
        add(item, a.summary === null ? el("p", null, "（端末でのみ表示する内容）") : prose(a.summary),
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

  var SCREENS = { overview: overview, incidents: incidents, noc: noc, knowledge: knowledge, detail: detail,
    setup: setup };

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
    var s = (state.model && state.model.summary) || {};
    var parts = [];
    [["通信", "communication"], ["出来事", "events"], ["自動対処", "response"], ["次の操作", "next"]].forEach(function (p) {
      var a = s[p[1]];
      parts.push(p[0] + " " + word(a ? a.status : null).ja);
    });
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
