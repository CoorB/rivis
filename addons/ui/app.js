/* Rivis main window (UI overhaul phase 1), served at /rivis/ by proxy_panel.py.
 *
 * Proxyman's arrangement with Rivis's own engine underneath. No new backend:
 *   calls     GET ../flows once, then mitmweb's live feed (websocket ../updates: flows/add|update|remove|reset)
 *   filters   plain text and the chips run here; a ~filter is checked by the panel API (an invalid one would make
 *             mitmweb close the feed), then sent on the feed as mitmweb's "search" filter, which answers with ids
 *   bodies    ../flows/<id>/<request|response>/content.data
 *   tools     the panel API (../proxy/api/<op>) that the classic drawer uses: state, nocache, columns_set, export,
 *             mock, bp_add, retry, filters_*. Tool windows (tools.js, tool-*.js) get what they need through
 *             window.RivisApp (below); a tool without a window yet opens in the classic view.
 * Everything shown from a call is escaped (esc) before it reaches innerHTML. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private window: the choice lasts this page only */ } },
  };
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
  const MOD = isMac ? "⌘" : "Ctrl+", ALT = isMac ? "⌥" : "Alt+", SHIFT = isMac ? "⇧" : "Shift+";

  // ── theme: the classic view's choice (rivis-theme), else the OS ──────────────────────────────────────────────────
  const mq = matchMedia("(prefers-color-scheme: dark)");
  const applyTheme = () => {
    const t = store.get("rivis-theme", "");
    document.documentElement.dataset.theme = t === "dark" || t === "light" ? t : (mq.matches ? "dark" : "light");
  };
  applyTheme();
  if (mq.addEventListener) mq.addEventListener("change", applyTheme);

  // ── server ───────────────────────────────────────────────────────────────────────────────────────────────────────
  const xsrf = () => {
    let v = (document.cookie.match(/(?:^|;\s*)_mitmproxy_xsrf=([^;]+)/) || [])[1];
    if (!v) {       // tornado only checks that the cookie and the header match: make the pair on first use
      v = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
      document.cookie = "_mitmproxy_xsrf=" + v + "; path=/; SameSite=Strict";
    }
    return v;
  };
  async function http(url, opts = {}, ms = 15000) {
    const c = new AbortController(), t = setTimeout(() => c.abort(), ms);
    try { return await fetch(url, Object.assign({ credentials: "same-origin", signal: c.signal }, opts)); }
    catch (e) { throw new Error(e.name === "AbortError" ? "Rivis did not answer within " + Math.round(ms / 1000) + " s" : e.message); }
    finally { clearTimeout(t); }
  }
  async function api(op, body, ms) {
    const r = await http("../proxy/api/" + op, body === undefined ? {} : {
      method: "POST", headers: { "Content-Type": "application/json", "X-XSRFToken": xsrf() }, body: JSON.stringify(body) }, ms);
    let j = {};
    try { j = await r.json(); } catch (e) { j = { error: "HTTP " + r.status }; }
    if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
    return j;
  }
  async function openCapture(file, mode) {
    const form = new FormData(); form.append("file", file);
    const r = await http("../flows/dump?mode=" + encodeURIComponent(mode), {
      method: "POST", headers: { "X-XSRFToken": xsrf() }, body: form }, 30000);
    if (!r.ok) throw new Error((await r.text()).trim() || "Could not open the capture file (HTTP " + r.status + ")");
    let answer = {};
    try { answer = await r.json(); } catch (e) { /* a replacement may return an empty answer */ }
    loadFlows(); pollState();
    return answer;
  }

  // ── model ────────────────────────────────────────────────────────────────────────────────────────────────────────
  const S = {
    byId: new Map(), order: [], seq: new Map(), nextSeq: 1,
    view: [], sel: null, follow: store.get("rivis-ui-follow", "1") === "1", record: true, held: new Map(),
    chip: "all", status: null, text: "", expr: "", match: null, source: null, sort: { col: null, desc: false },
    state: null, live: false,
    pins: (() => { try { return new Set(JSON.parse(store.get("rivis-ui-pins", "[]"))); } catch (e) { return new Set(); } })(),
  };
  const savePins = () => store.set("rivis-ui-pins", JSON.stringify([...S.pins]));
  // mitmweb keeps a call's highlight as one of its marker emojis (so the classic view shows the same colour)
  // [colour, label, emoji mitmweb sends back, shortcode mitmweb stores: it renders any value it does not know as 🔴]
  const MARKS = [["red", "Red", "🔴", ":red_circle:"], ["orange", "Orange", "🟠", ":orange_circle:"], ["yellow", "Yellow", "🟡", ":yellow_circle:"],
    ["green", "Green", "🟢", ":green_circle:"], ["blue", "Blue", "🔵", ":large_blue_circle:"], ["purple", "Purple", "🟣", ":purple_circle:"]];
  const markOf = (f) => { const m = f.marked && MARKS.find((x) => x[2] === f.marked || x[3] === f.marked || x[0] === f.marked); return m ? m[0] : ""; };
  const userComment = (f) => (f.comment && !/^(mock|rule|script|breakpoint)\b/.test(f.comment)) ? f.comment : "";
  const CHIPS = [["all", "All"], ["http", "HTTP"], ["https", "HTTPS"], ["ws", "WebSocket"], ["json", "JSON"], ["form", "Form"], ["xml", "XML"],
    ["js", "JS"], ["css", "CSS"], ["graphql", "GraphQL"], ["doc", "Document"], ["media", "Media"]];
  const STATUS = ["1xx", "2xx", "3xx", "4xx", "5xx"];
  const hdr = (msg, name) => {
    if (!msg || !msg.headers) return "";
    const n = name.toLowerCase(), h = msg.headers.find((x) => String(x[0]).toLowerCase() === n);
    return h ? String(h[1]) : "";
  };
  const ctype = (f) => (hdr(f.response, "content-type") || hdr(f.request, "content-type")).toLowerCase();
  const isGraphQL = (f) => /graphql/i.test(f.request.path) || (/json/.test(hdr(f.request, "content-type")) && /\bgraphql\b/i.test(f.request.path));
  const CHIP_TEST = {
    all: () => true,
    http: (f) => f.request.scheme === "http",
    https: (f) => f.request.scheme === "https",
    ws: (f) => !!f.websocket || /^websocket$/i.test(hdr(f.request, "upgrade")),
    json: (f) => /json/.test(ctype(f)),
    form: (f) => /x-www-form-urlencoded|multipart\/form-data/.test(hdr(f.request, "content-type").toLowerCase()),
    xml: (f) => /xml/.test(ctype(f)) && !/html/.test(ctype(f)),
    js: (f) => /javascript|ecmascript/.test(ctype(f)),
    css: (f) => /text\/css/.test(ctype(f)),
    graphql: isGraphQL,
    doc: (f) => /text\/html|xhtml/.test(ctype(f)),
    media: (f) => /^(image|video|audio|font)\//.test(ctype(f)),
  };
  const urlOf = (f) => {
    const r = f.request, port = r.port && r.port !== (r.scheme === "https" ? 443 : 80) ? ":" + r.port : "";
    return r.scheme + "://" + (r.pretty_host || r.host) + port + r.path;
  };
  const hostOf = (f) => f.request.pretty_host || f.request.host || "";
  const srcKey = (f) => { const s = S.state && S.state.sources; return s && f.client_conn ? s.by_conn[f.client_conn.id] : null; };
  const duration = (f) => (f.response && f.response.timestamp_end && f.request.timestamp_start)
    ? (f.response.timestamp_end - f.request.timestamp_start) * 1000 : null;
  const size = (f) => (f.request.contentLength || 0) + (f.response && f.response.contentLength || 0);
  const fmtMs = (ms) => ms == null ? "" : ms < 1000 ? Math.round(ms) + " ms" : (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + " s";
  const fmtBytes = (n) => n == null ? "" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
  const fmtTime = (ts) => { if (!ts) return ""; const d = new Date(ts * 1000); return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); };

  function visible(f) {
    if (f.type !== "http") return false;
    if (!CHIP_TEST[S.chip](f)) return false;
    if (S.status) { const c = f.response ? String(f.response.status_code)[0] : ""; if (c !== S.status[0]) return false; }
    if (S.match && !S.match.has(f.id)) return false;
    if (S.text) { let decoded = urlOf(f); try { decoded = decodeURIComponent(decoded); } catch (e) { /* keep the URL as sent */ }
      if (!urlOf(f).toLowerCase().includes(S.text) && !decoded.toLowerCase().includes(S.text) && !(f.request.method || "").toLowerCase().startsWith(S.text)) return false; }
    if (S.source) {
      if (S.source.host && hostOf(f) !== S.source.host) return false;
      if (S.source.key) { const k = srcKey(f) || ""; if (S.source.key.endsWith("|") ? !k.startsWith(S.source.key) : k !== S.source.key) return false; }
    }
    return true;
  }
  const SORTERS = {
    seq: (f) => S.seq.get(f.id), path: urlOf, method: (f) => f.request.method, status: (f) => f.response ? f.response.status_code : 0,
    size: (f) => size(f) || 0, time: (f) => duration(f) || 0, duration: (f) => duration(f) || 0, timestamp: (f) => f.request.timestamp_start || 0,
    content_type: ctype, source_app: (f) => srcLabel(f), comment: (f) => f.comment || "",
  };
  function rebuildView() {
    const keep = S.order.filter((id) => { const f = S.byId.get(id); return f && visible(f); });
    if (S.sort.col) {
      const get = SORTERS[S.sort.col] || ((f) => colText(f, S.sort.col));
      const val = new Map(keep.map((id) => [id, get(S.byId.get(id))]));
      keep.sort((a, b) => { const x = val.get(a), y = val.get(b); const r = x < y ? -1 : x > y ? 1 : 0; return S.sort.desc ? -r : r; });
    }
    S.view = keep;
    drawList(true);
    drawSources();
    drawStatus();
  }

  // ── columns (the per-project choice the classic view's picker saves: state.columns) ───────────────────────────────
  const COLS = {
    seq: { label: "#", w: "54px" }, path: { label: "URL", w: "minmax(240px, 4fr)" }, method: { label: "Method", w: "74px" },
    status: { label: "Status", w: "66px" }, size: { label: "Size", w: "78px" }, time: { label: "Time", w: "78px" },
    timestamp: { label: "Start time", w: "104px" }, duration: { label: "Duration", w: "84px" }, content_type: { label: "Content type", w: "minmax(110px, 1fr)" },
    source_app: { label: "Client", w: "minmax(110px, 1fr)" }, comment: { label: "Comment", w: "minmax(100px, 1fr)" },
  };
  const BUILTINS = ["path", "method", "status", "size", "time", "timestamp", "duration", "content_type", "source_app", "comment"];
  const columns = () => ["seq"].concat(((S.state && S.state.columns) || ["path", "method", "status", "size", "time", "timestamp"]));
  const colDef = (c) => COLS[c] || { label: c.replace(/^(request|response):/, (m, side) => (side === "request" ? "Req " : "Res ")), w: "minmax(100px, 1fr)" };
  const gridCols = () => columns().map((c) => colDef(c).w).join(" ") + " 28px";
  function srcLabel(f) {
    const k = srcKey(f), rows = (S.state && S.state.sources && S.state.sources.list) || [];
    const row = k && rows.find((r) => r.key === k);
    return row ? (row.app || row.device || row.label) : "";
  }
  function colText(f, c) {
    if (c.startsWith("request:")) return hdr(f.request, c.slice(8));
    if (c.startsWith("response:")) return hdr(f.response, c.slice(9));
    return { content_type: ctype(f).split(";")[0], source_app: srcLabel(f), comment: f.comment || "" }[c] || "";
  }
  function cellHTML(f, c) {
    const r = f.request, s = f.response;
    switch (c) {
      case "seq": return `<span class="rv-muted">${S.seq.get(f.id)}</span>`;
      case "path": {
        const tags = (f.comment && /^(mock|rule|script)/.test(f.comment)) ? `<span class="rv-tag">${esc(f.comment.split(/\s/)[0])}</span>` : "";
        const note = userComment(f) ? `<span class="rv-cmt" title="${esc(userComment(f))}">💬</span>` : "";
        return `<span class="rv-host">${esc(urlOf(f).slice(0, -r.path.length))}</span>${esc(r.path)}${tags}${note}`;
      }
      case "method": return `<span class="rv-m rv-m-${esc(r.method)}">${esc(r.method)}</span>`;
      case "status":
        if (f.intercepted) return `<span class="rv-paused" title="Paused at a breakpoint: click to edit it">⏸ paused</span>`;
        if (f.error) return `<span class="rv-err" title="${esc(f.error.msg)}">${s ? esc(s.status_code) + " ✕ failed" : "failed"}</span>`;
        return s ? `<span class="rv-s${String(s.status_code)[0]}">${s.status_code}</span>` : `<span class="rv-muted">…</span>`;
      case "size": return esc(fmtBytes(size(f)));
      case "time": case "duration": return esc(fmtMs(duration(f)));
      case "timestamp": return esc(fmtTime(r.timestamp_start));
      default: return esc(colText(f, c));
    }
  }

  // ── call list: only the rows on screen exist ──────────────────────────────────────────────────────────────────
  const ROW_H = 26;
  const tscroll = $("tscroll"), rowsEl = $("rows"), spaceEl = $("tspace");
  function drawHead() {
    const cols = columns();
    $("thead").style.gridTemplateColumns = gridCols();
    $("thead").innerHTML = cols.map((c) => `<div class="rv-th" data-col="${esc(c)}" role="columnheader"${S.sort.col === c ? ` aria-sort="${S.sort.desc ? "descending" : "ascending"}"` : ""}>${esc(colDef(c).label)}</div>`).join("")
      + `<div class="rv-th rv-colpick" id="colpick" role="button" tabindex="0" title="Choose columns" aria-label="Choose columns">+</div>`;
  }
  function drawList(force) {
    const n = S.view.length, h = tscroll.clientHeight || 400;
    spaceEl.style.height = n * ROW_H + "px";
    tscroll.setAttribute("aria-rowcount", String(n));
    const first = Math.max(0, Math.floor(tscroll.scrollTop / ROW_H) - 5), last = Math.min(n, Math.ceil((tscroll.scrollTop + h) / ROW_H) + 5);
    const key = first + ":" + last + ":" + n;
    if (!force && drawList.key === key) return;
    drawList.key = key;
    const grid = gridCols(), cols = columns();
    rowsEl.style.top = first * ROW_H + "px";
    let html = "";
    for (let i = first; i < last; i++) {
      const f = S.byId.get(S.view[i]);
      if (!f) continue;
      html += `<div class="rv-tr${markOf(f) ? " rv-mark-" + markOf(f) : ""}${f.intercepted ? " rv-is-paused" : ""}" role="row" data-id="${esc(f.id)}" aria-rowindex="${i + 1}" aria-selected="${f.id === S.sel}" style="grid-template-columns:${grid}">`
        + cols.map((c) => `<div class="rv-td${c === "path" ? " rv-url" : ""}" role="gridcell">${cellHTML(f, c)}</div>`).join("") + `<div></div></div>`;
    }
    rowsEl.innerHTML = html;
    const empty = $("empty");
    empty.hidden = n > 0;
    if (!n) {
      const selected = S.source && (S.source.host || (S.state && S.state.sources && (S.state.sources.list || [])
        .find((r) => r.key === S.source.key) || {}).app || (S.source.key || "").split("|")[1]);
      empty.innerHTML = S.order.length ? "No call matches the filter" + (selected ? " for <b>" + esc(selected) + "</b>" : "") + "."
        : "No calls yet. Start the app on a simulator, emulator or device that is set up for Rivis. <button type=\"button\" class=\"rv-btn\" data-empty-dev>Set up a device</button>";
    }
  }
  $("empty").addEventListener("click", (e) => { if (e.target.closest("[data-empty-dev]")) window.RivisTools.open("devices"); });
  tscroll.addEventListener("scroll", () => drawList(false));
  addEventListener("resize", () => drawList(true));

  function showRow(id) {
    const i = S.view.indexOf(id), top = i * ROW_H;
    if (i >= 0 && (top < tscroll.scrollTop || top + ROW_H > tscroll.scrollTop + tscroll.clientHeight)) tscroll.scrollTop = Math.max(0, top - tscroll.clientHeight / 2);
    drawList(false);
  }
  function select(id, scroll) {
    S.sel = id;
    for (const el of rowsEl.children) el.setAttribute("aria-selected", String(el.dataset.id === id));
    if (scroll && id) showRow(id);
    drawDetail();
    if (id) api("flow_selected", { id }).catch(() => {});      // flow retention keeps the selected call
  }
  function activate(id) {
    setFollow(false); select(id, false); tscroll.focus({ preventScroll: true });
    const f = S.byId.get(id);
    if (f && f.intercepted && window.RivisTools) window.RivisTools.open("paused", { id: f.id });
  }
  // A call that arrives during a press redraws the rows, so the browser sends the click to the list, not the row: select
  // the row that was under the pointer when it went down, unless the pointer moved (a drag is not a click).
  let press = null, pressedAt = 0;
  rowsEl.addEventListener("pointerdown", (e) => {
    const tr = e.button === 0 && e.target.closest(".rv-tr");
    press = tr ? { id: tr.dataset.id, x: e.clientX, y: e.clientY } : null;
    if (press && S.follow) setFollow(false);              // following would scroll the list under the pointer mid-press
  });
  addEventListener("pointerup", (e) => {
    const p = press; press = null;
    if (!p || e.button !== 0 || Math.abs(e.clientX - p.x) > 4 || Math.abs(e.clientY - p.y) > 4) return;
    pressedAt = performance.now(); activate(p.id);
  });
  addEventListener("pointercancel", () => { press = null; });
  rowsEl.addEventListener("click", (e) => {             // keyboard and assistive-technology clicks
    if (performance.now() - pressedAt < 600) return;
    const tr = e.target.closest(".rv-tr"); if (tr) activate(tr.dataset.id);
  });
  tscroll.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    if (!S.view.length) return;
    let i = S.view.indexOf(S.sel);
    i = e.key === "Home" ? 0 : e.key === "End" ? S.view.length - 1 : e.key === "ArrowDown" ? Math.min(S.view.length - 1, i + 1) : Math.max(0, i - 1);
    setFollow(false);
    select(S.view[i], true);
  });
  $("thead").addEventListener("click", (e) => {
    if (e.target.closest("#colpick")) return pickColumns();
    const th = e.target.closest("[data-col]"); if (!th) return;
    const c = th.dataset.col;
    S.sort = S.sort.col !== c ? { col: c, desc: false } : S.sort.desc ? { col: null, desc: false } : { col: c, desc: true };
    drawHead(); rebuildView();
    if (S.follow) followNewest();                         // newest first: the newest call is now at the top, not the end
    else if (S.sel) showRow(S.sel);                       // keep the selected call in view after the reorder
  });
  $("thead").addEventListener("keydown", (e) => { if (e.target.id === "colpick" && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); pickColumns(); } });

  // ── live feed ────────────────────────────────────────────────────────────────────────────────────────────────────
  function addFlow(f) {
    if (!S.byId.has(f.id)) { S.order.push(f.id); S.seq.set(f.id, S.nextSeq++); }
    S.byId.set(f.id, f);
  }
  function dropFlow(id) {        // the call, its number and a pending hold all go (review: the numbers grew forever)
    S.byId.delete(id); S.seq.delete(id); S.held.delete(id);
    S.order = S.order.filter((x) => x !== id);
  }
  // at most one redraw per 80 ms, and always one: a debounce never fired while calls kept arriving (review)
  let viewT = 0;
  const viewSoon = () => {
    if (viewT) return;
    viewT = setTimeout(() => { viewT = 0; rebuildView(); followNewest(); if (S.sel && S.byId.has(S.sel)) refreshDetailIfChanged(); }, 80);
  };
  let loading = null;            // events that arrive while a /flows snapshot loads are replayed on top of it (review)
  function onFeed(m) {
    if (loading) { loading.push(m); return; }
    const p = m.payload || {};
    if (m.type === "flows/add" || m.type === "flows/update") {
      const f = p.flow || p;
      if (!f || !f.id) return;
      if (S.match && p.matching_filters && "search" in p.matching_filters) { if (p.matching_filters.search) S.match.add(f.id); else S.match.delete(f.id); }
      if (!S.record && !S.byId.has(f.id)) { S.held.set(f.id, f); drawStatus(); return; }   // one entry per call
      addFlow(f);
      viewSoon();
    } else if (m.type === "flows/remove") {
      const id = typeof p === "string" ? p : p.id;
      dropFlow(id);
      if (S.sel === id) { S.sel = null; drawDetail(); }
      viewSoon(); drawStatus();
    } else if (m.type === "flows/reset") {
      loadFlows();
    } else if (m.type === "flows/filterUpdate" && p.name === "search" && S.expr) {
      S.match = new Set(p.matching_flow_ids || []);
      viewSoon();
    }
  }
  let ws = null, wsTries = 0;
  function connect() {
    ws = new WebSocket(location.origin.replace(/^http/, "ws") + "/updates");
    ws.addEventListener("open", () => { S.live = true; wsTries = 0; drawStatus(); if (S.expr) sendExpr(S.expr); });
    ws.addEventListener("message", (e) => { try { onFeed(JSON.parse(e.data)); } catch (err) { /* one bad message must not stop the feed */ } });
    ws.addEventListener("close", () => { S.live = false; drawStatus(); setTimeout(() => { connect(); loadFlows(); }, Math.min(10000, 500 * 2 ** wsTries++)); });
  }
  let loadGen = 0;
  async function loadFlows() {
    const gen = ++loadGen, buffered = loading || [];
    loading = buffered;                         // from now on the feed is buffered, not applied
    try {
      const r = await http("../flows", {}, 30000);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const list = await r.json();
      if (gen !== loadGen) return;             // a newer load is running: it applies, this one does not
      const ids = new Set(list.map((f) => f.id));
      for (const id of [...S.byId.keys()]) if (!ids.has(id)) dropFlow(id);
      for (const f of list) {
        if (!S.record && !S.byId.has(f.id)) S.held.set(f.id, f);    // paused: the pause holds across a resync
        else addFlow(f);
      }
    } catch (e) { toast("Could not load the calls: " + e.message, true); }
    finally {
      if (gen === loadGen) {
        loading = null;
        buffered.forEach(onFeed);               // newer than the snapshot: applied on top of it
        if (S.sel && !S.byId.has(S.sel)) { S.sel = null; drawDetail(); }     // the selected call is gone (review)
        rebuildView(); followNewest(); drawStatus();
      }
    }
  }
  const sendExpr = (expr) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "flows/updateFilter", payload: { name: "search", expr } })); };

  // ── Record / Follow / Clear ──────────────────────────────────────────────────────────────────────────────────────
  function setRecord(on) {
    S.record = on;
    $("tb-record").setAttribute("aria-pressed", String(on));
    $("tb-record").querySelector(".rv-tb-l").textContent = on ? "Record" : "Paused";
    if (on && S.held.size) { S.held.forEach(addFlow); S.held.clear(); rebuildView(); followNewest(); }
    drawStatus();
  }
  function setFollow(on) {
    S.follow = on; store.set("rivis-ui-follow", on ? "1" : "0");
    $("tb-follow").setAttribute("aria-pressed", String(on));
    if (on) followNewest();
  }
  function followNewest() {
    if (!S.follow || !S.view.length) return;
    const newest = S.sort.col ? S.view.reduce((a, b) => (S.seq.get(b) > S.seq.get(a) ? b : a)) : S.view[S.view.length - 1];
    if (newest !== S.sel) select(newest, true); else showRow(newest);
    if (!S.sort.col) tscroll.scrollTop = tscroll.scrollHeight;
  }
  async function clearAll() {
    const n = S.order.length;
    if (!n) return toast("The list is already empty");
    if (!await ask("Clear all " + n + " calls?", "Saved sessions, rules and scripts are not affected.", "Clear all", true)) return;
    try {
      const r = await http("../clear", { method: "POST", headers: { "X-XSRFToken": xsrf() } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      S.byId.clear(); S.order = []; S.seq.clear(); S.sel = null; S.held.clear(); rebuildView(); drawDetail(); toast("List cleared");
    } catch (e) { toast("Could not clear the list: " + e.message, true); }
  }
  async function deleteFlow(id) {
    try {
      const r = await http("../flows/" + encodeURIComponent(id), { method: "DELETE", headers: { "X-XSRFToken": xsrf() } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      dropFlow(id);
      if (S.sel === id) { S.sel = null; drawDetail(); }
      rebuildView();
    } catch (e) { toast("Could not delete the call: " + e.message, true); }
  }
  $("tb-record").onclick = () => setRecord(!S.record);
  $("tb-follow").onclick = () => setFollow(!S.follow);
  $("tb-clear").onclick = clearAll;

  // ── tools in the toolbar (lit when on; tool windows come in phase 2) ─────────────────────────────────────────────
  const TOOLS = [
    ["map", "Map Local", `${ALT}${MOD}L`], ["remote", "Map Remote", `${ALT}${MOD}R`], ["bp", "Breakpoint", `${ALT}${MOD}B`],
    ["scripts", "Scripting", ""], ["net", "Network", ""], ["block", "Block List", `${ALT}${MOD}X`], ["nocache", "No Caching", `${ALT}${MOD}N`],
  ];
  // toolbar id → its window (tools.js) and how it opens
  const TOOL_WIN = { map: ["map"], remote: ["rules", { type: "map_remote" }], block: ["rules", { type: "block" }], bp: ["bp"], scripts: ["scripts"], net: ["net"] };
  function toolState(id) {
    const st = S.state; if (!st) return { on: false, n: 0 };
    const rules = st.rules || [];
    const count = (act) => rules.filter((r) => r.enabled && act.includes(r.action)).length;
    if (id === "map") { const n = count(["map_local", "respond"]); return { on: n > 0, n }; }
    if (id === "remote") { const n = count(["map_remote"]); return { on: n > 0, n }; }
    if (id === "block") { const n = count(["block", "drop"]); return { on: n > 0, n }; }
    if (id === "bp") { const n = (st.breakpoints || []).filter((b) => b.enabled !== false).length; return { on: n > 0, n }; }
    if (id === "scripts") { const n = (st.scripts || []).filter((s) => s.enabled).length; return { on: n > 0, n }; }
    if (id === "net") return { on: (st.throttle && st.throttle !== "off") || Number(st.loss) > 0, n: 0 };
    if (id === "nocache") return { on: !!st.no_cache, n: 0 };
    return { on: false, n: 0 };
  }
  function drawTools() {
    $("tb-tools").innerHTML = TOOLS.map(([id, label, key]) => {
      const t = toolState(id);
      return `<button class="rv-tb${t.on ? " on" : ""}" data-tool="${id}" aria-pressed="${t.on}" title="${esc(label + (key ? " (" + key + ")" : "") + (id === "nocache" ? " — click to switch" : hasWin(id) ? "" : " — opens in the classic view"))}">`
        + `<span class="rv-tb-l">${esc(label)}</span>${t.n ? `<span class="rv-n">${t.n}</span>` : ""}</button>`;
    }).join("") + `<button class="rv-tb" type="button" id="tb-more" aria-haspopup="menu" aria-expanded="false">More</button>`;
  }
  const TOOL_TAB = { map: "map", remote: "rules", block: "rules", bp: "bp", scripts: "scripts", net: "net" };
  const hasWin = (id) => !!(TOOL_WIN[id] && window.RivisTools && window.RivisTools.has(TOOL_WIN[id][0]));
  async function openTool(id) {
    if (id === "nocache") {
      const on = !(S.state && S.state.no_cache);
      try { const r = await api("nocache", { on }); S.state = r.state || S.state; drawTools(); drawStatus(); toast("No Caching " + (on ? "on" : "off")); }
      catch (e) { toast(e.message, true); }
      return;
    }
    if (hasWin(id)) return window.RivisTools.open(TOOL_WIN[id][0], TOOL_WIN[id][1]);
    window.open("../#rivis-tool=" + TOOL_TAB[id], "rivis-classic");
  }
  $("tb-tools").addEventListener("click", (e) => { const b = e.target.closest("[data-tool]"); if (b) openTool(b.dataset.tool); });
  $("tb-tools").addEventListener("click", (e) => {
    const b = e.target.closest("#tb-more"); if (!b) return;
    if (!$("menu").hidden && $("menu")._rvMore) { closeMenu(); return; }
    const items = [["compose", "Compose", `${ALT}${MOD}C`], ["devices", "Devices", `${ALT}${MOD}D`],
      ["collections", "Collections", ""], ["sessions", "Sessions", ""], ["compare", "Compare", ""], ["classic", "Classic view", ""]];
    const m = $("menu"); m._rvMore = true;
    m.innerHTML = items.map(([id, label, key]) => `<button role="menuitem" data-more="${id}"><span>${label}</span><kbd>${esc(key)}</kbd></button>`).join("");
    m.hidden = false; b.setAttribute("aria-expanded", "true");
    const r = b.getBoundingClientRect(); m.style.left = Math.max(6, Math.min(r.left, innerWidth - m.offsetWidth - 6)) + "px";
    m.style.top = Math.min(r.bottom + 4, innerHeight - m.offsetHeight - 6) + "px";
    m.querySelector("button").focus();
  });

  // ── filter bar ───────────────────────────────────────────────────────────────────────────────────────────────────
  function drawChips() {
    $("chips").innerHTML = CHIPS.map(([id, label]) => `<button class="rv-chip" data-chip="${id}" aria-pressed="${S.chip === id}">${esc(label)}</button>`).join("")
      + `<span class="rv-tb-sep"></span>` + STATUS.map((s) => `<button class="rv-chip" data-status="${s}" aria-pressed="${S.status === s}">${s}</button>`).join("");
    const saved = (S.state && S.state.saved_filters) || [];
    $("saved").innerHTML = saved.map((x, i) => `<button class="rv-chip" data-saved="${i}" aria-pressed="${$("q").value === x.filter}" title="${esc(x.filter)}${i < 9 ? " (" + ALT + (i + 1) + ")" : ""}">★ ${esc(x.name)}</button>`).join("");
  }
  $("chips").addEventListener("click", (e) => {
    const c = e.target.closest("[data-chip]"), st = e.target.closest("[data-status]");
    if (c) S.chip = c.dataset.chip;
    else if (st) S.status = S.status === st.dataset.status ? null : st.dataset.status;
    else return;
    drawChips(); rebuildView();
  });
  $("saved").addEventListener("click", (e) => { const b = e.target.closest("[data-saved]"); if (b) applySaved(Number(b.dataset.saved)); });
  $("saved").addEventListener("contextmenu", (e) => {
    const chip = e.target.closest("[data-saved]"); if (!chip) return;
    e.preventDefault(); closeMenu();
    const rows = (S.state && S.state.saved_filters) || [], i = Number(chip.dataset.saved), row = rows[i];
    if (!row) return;
    const m = $("menu");
    m.innerHTML = [["rename", "Rename"], ["delete", "Delete"], ["left", "Move left"], ["right", "Move right"]]
      .map(([act, label]) => `<button role="menuitem" data-filter-act="${act}"${(act === "left" && !i) || (act === "right" && i === rows.length - 1) ? " disabled" : ""}>${label}</button>`).join("");
    m.hidden = false;
    m.style.left = Math.max(6, Math.min(e.clientX, innerWidth - m.offsetWidth - 6)) + "px";
    m.style.top = Math.max(6, Math.min(e.clientY, innerHeight - m.offsetHeight - 6)) + "px";
    m.querySelectorAll("[data-filter-act]").forEach((b) => { b.onclick = async () => {
      const act = b.dataset.filterAct; closeMenu();
      try {
        let r;
        if (act === "rename") {
          r = await askText("Rename filter", "", row.name, async (name) => {
            if (!name || name === row.name) throw new Error(name === row.name ? "Choose a different name" : "Name is required");
            return api("filters_save", { old: row.name, name });
          });
          if (!r) return;
        } else if (act === "delete") {
          if (!await ask("Delete saved filter " + row.name + "?", "", "Delete", true)) return;
          r = await api("filters_delete", { name: row.name });
        } else {
          const names = rows.map((x) => x.name), j = act === "left" ? i - 1 : i + 1;
          [names[i], names[j]] = [names[j], names[i]];
          r = await api("filters_order", { names });
        }
        S.state.saved_filters = r.filters; drawChips();
      } catch (err) { toast(err.message, true); }
    }; });
    m.querySelector("button").focus();
  });
  function applySaved(i) {
    const x = ((S.state && S.state.saved_filters) || [])[i];
    if (!x) return;
    $("q").value = $("q").value === x.filter ? "" : x.filter;
    setQuery($("q").value);
  }
  let qT = 0, qSeq = 0;
  $("q").addEventListener("input", () => { qSeq++; clearTimeout(qT); qT = setTimeout(() => setQuery($("q").value), 150); });
  $("q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { clearTimeout(qT); setQuery($("q").value); }
    if (e.key === "Escape") { $("q").value = ""; setQuery(""); $("q").blur(); }
  });
  async function setQuery(raw) {
    const seq = ++qSeq, v = raw.trim();
    $("qerr").textContent = "";
    document.querySelector(".rv-search").classList.remove("bad");
    if (!v.startsWith("~") && !v.startsWith("!")) {
      S.text = v.toLowerCase();
      if (S.expr) { S.expr = ""; S.match = null; sendExpr(""); }
      drawChips(); rebuildView(); return;
    }
    // a mitmproxy filter: checked first (an invalid one would make mitmweb close the live feed), then run there
    let ok = true, err = "";
    try { const r = await api("filter_check", { filter: v }); ok = r.ok !== false; err = r.error || ""; } catch (e) { ok = false; err = e.message; }
    if (seq !== qSeq || $("q").value.trim() !== v) return;     // the box says something else by now (review)
    if (!ok) {
      document.querySelector(".rv-search").classList.add("bad");
      $("qerr").textContent = "Not a valid filter: " + err;
      return;
    }
    S.text = ""; S.expr = v; S.match = new Set();
    sendExpr(v);
    drawChips(); rebuildView();
  }

  // ── sources: devices and apps (proxy_source), then domains ───────────────────────────────────────────────────────
  function drawSources() {
    const q = $("sq").value.trim().toLowerCase();
    const counts = new Map(), unknown = ((S.state && S.state.sources && S.state.sources.list) || []).find((r) => r.kind === "unknown");
    for (const id of S.order) { const f = S.byId.get(id); if (f) { const key = srcKey(f) || (unknown && unknown.key); if (key) counts.set(key, (counts.get(key) || 0) + 1); } }
    const rows = ((S.state && S.state.sources && S.state.sources.list) || []).map((r) => Object.assign({}, r, { count: counts.get(r.key) || 0 }));
    const kinds = { ios: "iOS Simulator", android: "Android emulator", phone: "Phone or tablet", browser: "Web browser", mac: "This Mac", unknown: "Unknown" };
    const on = (src) => S.source && ((src.key && S.source.key === src.key) || (src.host && S.source.host === src.host));
    const hosts = new Map();
    for (const id of S.order) { const f = S.byId.get(id); if (f && f.type === "http") hosts.set(hostOf(f), (hosts.get(hostOf(f)) || 0) + 1); }
    let html = `<button class="rv-src" data-src-all aria-pressed="${!S.source}"><span class="rv-sname">All calls</span><span class="rv-scount">${S.order.length}</span></button>`;
    const pins = [...S.pins].filter((h) => !q || h.toLowerCase().includes(q));
    if (pins.length) html += `<div class="rv-sh">Pinned</div>` + pins.map((h) => `<div class="rv-src-wrap"><button class="rv-src" data-src-host="${esc(h)}" aria-pressed="${!!on({ host: h })}" title="${esc(h)}"><span class="rv-sname">📌 ${esc(h)}</span><span class="rv-scount">${hosts.get(h) || 0}</span></button>`
      + `<button class="rv-unpin" data-unpin="${esc(h)}" aria-label="Unpin ${esc(h)}" title="Unpin">✕</button></div>`).join("");
    const devices = new Map();
    rows.forEach((r) => { const dk = r.kind + "|" + r.device + "|"; if (!devices.has(dk)) devices.set(dk, { label: r.device || kinds[r.kind] || r.kind, kind: r.kind, apps: [] }); devices.get(dk).apps.push(r); });
    let dev = "";
    for (const [dk, d] of devices) {
      const total = d.apps.reduce((a, r) => a + (r.count || 0), 0);
      const name = d.label + (d.label !== kinds[d.kind] ? " · " + (kinds[d.kind] || d.kind) : "");
      if (q && !name.toLowerCase().includes(q) && !d.apps.some((r) => (r.app || "").toLowerCase().includes(q))) continue;
      dev += `<button class="rv-src" data-src-key="${esc(dk)}" aria-pressed="${!!on({ key: dk })}" title="${esc(name)}"><span class="rv-sname">${esc(name)}</span><span class="rv-scount">${total}</span></button>`;
      d.apps.filter((r) => r.app).forEach((r) => {
        if (q && !(r.app || "").toLowerCase().includes(q) && !name.toLowerCase().includes(q)) return;
        dev += `<button class="rv-src rv-sub" data-src-key="${esc(r.key)}" aria-pressed="${!!on({ key: r.key })}" title="${esc(r.id || r.app)}"><span class="rv-sname">${esc(r.app)}</span><span class="rv-scount">${r.count || 0}</span></button>`;
      });
    }
    if (dev) html += `<div class="rv-sh">Apps and devices</div>` + dev;
    const top = [...hosts].filter(([h]) => !q || h.toLowerCase().includes(q)).sort((a, b) => b[1] - a[1]).slice(0, 60);
    if (top.length) html += `<div class="rv-sh">Domains</div>` + top.map(([h, n]) => `<button class="rv-src" data-src-host="${esc(h)}" aria-pressed="${!!on({ host: h })}" title="${esc(h)}"><span class="rv-sname">${esc(h)}</span><span class="rv-scount">${n}</span></button>`).join("");
    $("sources").innerHTML = html;
  }
  $("sources").addEventListener("click", (e) => {
    const un = e.target.closest("[data-unpin]");
    if (un) { S.pins.delete(un.dataset.unpin); savePins(); if (S.source && S.source.host === un.dataset.unpin) { S.source = null; rebuildView(); } drawSources(); return; }
    const b = e.target.closest(".rv-src"); if (!b) return;
    if ("srcAll" in b.dataset) S.source = null;
    else if (b.dataset.srcKey) S.source = S.source && S.source.key === b.dataset.srcKey ? null : { key: b.dataset.srcKey };
    else if (b.dataset.srcHost) S.source = S.source && S.source.host === b.dataset.srcHost ? null : { host: b.dataset.srcHost };
    drawSources(); rebuildView();
  });
  $("sq").addEventListener("input", drawSources);
  // ⌘K then Enter: pin what was typed (a domain), or the first domain that matches it, and show only it
  $("sq").addEventListener("keydown", (e) => {
    if (e.key === "Escape") { $("sq").value = ""; drawSources(); tscroll.focus(); return; }
    if (e.key !== "Enter") return;
    e.preventDefault();
    const q = $("sq").value.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    if (!q) return;
    const known = [...new Set(S.order.map((id) => S.byId.get(id)).filter(Boolean).map(hostOf))];
    const h = known.find((x) => x.toLowerCase() === q) || known.find((x) => x.toLowerCase().includes(q)) || q;
    S.pins.add(h); savePins(); S.source = { host: h }; $("sq").value = "";
    drawSources(); rebuildView(); toast("Pinned " + h);
  });
  let srcT = 0;
  const sourcesSoon = () => { clearTimeout(srcT); srcT = setTimeout(drawSources, 400); };

  // ── request | response ───────────────────────────────────────────────────────────────────────────────────────────
  const D = { req: store.get("rivis-ui-req-tab", "header"), res: store.get("rivis-ui-res-tab", "body"), bodies: new Map(), images: [], sig: "" };
  const REQ_TABS = [["header", "Header"], ["query", "Query"], ["body", "Body"], ["tree", "Tree"], ["cookies", "Cookies"], ["raw", "Raw"]];
  const RES_TABS = [["header", "Header"], ["body", "Body"], ["tree", "Tree"], ["raw", "Raw"]];
  const TREE_MAX = 24 * 1024 * 1024, TEXT_MAX = 512 * 1024, HEX_MAX = 4096;
  function parseTree(text) {
    return new Promise((resolve, reject) => {
      const worker = new Worker("./tree-worker.js");
      worker.onmessage = (e) => { worker.terminate(); e.data.error ? reject(new SyntaxError(e.data.error)) : resolve(e.data.data); };
      worker.onerror = (e) => { worker.terminate(); reject(new Error(e.message)); };
      worker.postMessage(text);
    });
  }
  const sigOf = (f) => f ? f.id + ":" + (f.response ? f.response.status_code + ":" + f.response.contentLength + ":" + (f.response.timestamp_end || 0) : "-") + ":" + (f.request.contentLength || 0) + ":" + ((f.error && f.error.msg) || "") + ":" + JSON.stringify(f.websocket && f.websocket.messages_meta) : "";
  function refreshDetailIfChanged() { const f = S.byId.get(S.sel); if (sigOf(f) !== D.sig) drawDetail(); }
  async function body(f, side, forTree) {
    const msg = f[side]; if (!msg) return { text: "", bytes: 0 };
    const limit = forTree ? TREE_MAX : TEXT_MAX;
    const k = f.id + ":" + side + ":" + limit + ":" + (msg.contentHash || msg.contentLength) + ":" + (msg.timestamp_end || "");
    if (D.bodies.has(k)) return D.bodies.get(k);
    const p = (async () => {
      const r = await http("../flows/" + encodeURIComponent(f.id) + "/" + side + "/content.data", {}, 30000);
      if (!r.ok) throw new Error("HTTP " + r.status);
      // Read only the view's bound plus one byte, then cancel. The real size is the message's own.
      const parts = []; let got = 0;
      const reader = r.body.getReader();
      while (got <= limit) { const { done, value } = await reader.read(); if (done) break; parts.push(value); got += value.byteLength; }
      reader.cancel().catch(() => {});
      const all = new Uint8Array(Math.min(got, limit + 1)); let off = 0;
      for (const part of parts) { const n = Math.min(part.byteLength, all.length - off); all.set(part.subarray(0, n), off); off += n; if (off >= all.length) break; }
      const buf = all.buffer, size = msg.contentLength != null ? msg.contentLength : got;
      const text = new TextDecoder("utf-8", { fatal: false }).decode(buf.byteLength > TEXT_MAX ? buf.slice(0, TEXT_MAX) : buf);
      const head = new Uint8Array(buf, 0, Math.min(buf.byteLength, HEX_MAX));
      return { text, data: all, bytes: Math.max(size, buf.byteLength), head, binary: isBinary(msg, text),
               full: buf.byteLength > TEXT_MAX ? new TextDecoder().decode(buf) : text };
    })();
    D.bodies.set(k, p);
    if (D.bodies.size > 3) D.bodies.delete(D.bodies.keys().next().value);
    return p;
  }
  const kvTable = (rows) => rows.length ? `<table class="rv-kv">${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table>` : `<div class="rv-note">None</div>`;
  const queryRows = (f) => { const q = f.request.path.split("?")[1]; if (!q) return []; return q.split("&").map((p) => { const [k, ...v] = p.split("="); const d = (x) => { try { return decodeURIComponent(x.replace(/\+/g, " ")); } catch (e) { return x; } }; return [d(k), d(v.join("="))]; }); };
  const cookieRows = (f) => { const c = hdr(f.request, "cookie"); return c ? c.split(/;\s*/).filter(Boolean).map((p) => { const i = p.indexOf("="); return [p.slice(0, i), p.slice(i + 1)]; }) : []; };
  function paneHead(side, title, tabs, cur) {
    return `<div class="rv-ph"><h2>${title}</h2><div class="rv-tabs" role="tablist">${tabs.map(([id, l]) => `<button class="rv-tab" role="tab" data-pane="${side}" data-tab="${id}" aria-selected="${cur === id}">${l}</button>`).join("")}</div>`
      + `<div class="rv-find"><input type="search" data-find="${side}" placeholder="Search in body (${MOD}F)" aria-label="Search in ${side === "req" ? "request" : "response"} body" value="${esc(findText[side])}"><span class="rv-fc" data-fc="${side}"></span>`
      + `<button class="rv-ib" data-fprev="${side}" title="Previous (${SHIFT}Enter)" aria-label="Previous match">↑</button><button class="rv-ib" data-fnext="${side}" title="Next (Enter)" aria-label="Next match">↓</button></div></div>`;
  }
  const findText = { req: "", res: "" };
  async function drawDetail() {
    D.images.forEach((url) => URL.revokeObjectURL(url)); D.images = [];
    const f = S.byId.get(S.sel);
    D.sig = sigOf(f);
    const req = $("pane-req"), res = $("pane-res");
    if (!f) {
      req.innerHTML = paneHead("req", "Request", REQ_TABS, D.req) + `<div class="rv-pb"><div class="rv-note">Select a call to see its request.</div></div>`;
      res.innerHTML = paneHead("res", "Response", RES_TABS, D.res) + `<div class="rv-pb"><div class="rv-note">and its response, side by side.</div></div>`;
      return;
    }
    if (!f.websocket && D.res === "messages") D.res = "body";
    const r = f.request, s = f.response, mySig = D.sig;
    const sline = f.error ? `<span class="rv-err">${s ? esc(s.status_code) + " · " : ""}Failed: ${esc(f.error.msg)}</span>` : s ? `${s.status_code} ${esc(s.reason || "")}` : "waiting…";
    req.innerHTML = paneHead("req", "Request", REQ_TABS, D.req) + `<div class="rv-pb" data-body="req" tabindex="0"><div class="rv-first">${esc(r.method)} ${esc(urlOf(f))} ${esc(r.http_version || "")}</div><div class="rv-dyn"></div></div>`;
    res.innerHTML = paneHead("res", `Response · ${sline}`, f.websocket ? RES_TABS.concat([["messages", "Messages"]]) : RES_TABS, D.res) + `<div class="rv-pb" data-body="res" tabindex="0"><div class="rv-dyn"></div></div>`;
    await Promise.all([fillPane(f, "req", mySig), fillPane(f, "res", mySig)]);
  }
  async function fillPane(f, side, mySig) {
    const el = document.querySelector(`[data-body="${side}"] .rv-dyn`); if (!el) return;
    const msg = side === "req" ? f.request : f.response, tab = side === "req" ? D.req : D.res;
    if (side === "res" && tab === "messages" && f.websocket) {
      el.innerHTML = `<div class="rv-note">Loading messages…</div>`;
      try {
        const r = await http("../flows/" + encodeURIComponent(f.id) + "/messages/content/Auto.json?lines=5000");
        if (!r.ok) throw new Error("HTTP " + r.status);
        const messages = await r.json();
        if (D.sig !== mySig || D.res !== tab) return;
        el.innerHTML = messages.map((m) => `<div class="rv-ws-message"><div class="rv-note">${m.from_client ? "Sent →" : "Received ←"} · ${esc(fmtTime(m.timestamp))} · ${esc(m.description || m.view_name)}</div><pre>${esc(m.text)}</pre></div>`).join("")
          + (!messages.length ? `<div class="rv-note">No messages yet.</div>` : "")
          + (messages.length < f.websocket.messages_meta.count ? `<div class="rv-note">Showing the first ${messages.length} messages (up to 5000 lines).</div>` : "");
      } catch (e) { if (D.sig === mySig) el.innerHTML = `<div class="rv-note rv-err">Could not load messages: ${esc(e.message)}</div>`; }
      return;
    }
    if (!msg) { el.innerHTML = `<div class="rv-note">${f.error ? "No response: " + esc(f.error.msg) : "No response yet."}</div>`; return; }
    if (tab === "header") { el.innerHTML = kvTable(msg.headers || []); return find(side, false); }
    if (tab === "query") { el.innerHTML = kvTable(queryRows(f)); return find(side, false); }
    if (tab === "cookies") { el.innerHTML = kvTable(cookieRows(f)); return find(side, false); }
    if (msg.contentLength == null && /text\/event-stream/i.test(hdr(msg, "content-type"))) {
      el.innerHTML = `<div class="rv-note">Streamed response: events were forwarded as they arrived and were not stored.</div>`;
      return;
    }
    el.innerHTML = `<div class="rv-note">Loading…</div>`;
    const imageType = hdr(msg, "content-type").split(";")[0].trim().toLowerCase();
    const previewImage = tab === "body" && /^image\//.test(imageType);
    let b;
    try { b = await body(f, side === "req" ? "request" : "response", tab === "tree" || previewImage); } catch (e) { if (D.sig === mySig) el.innerHTML = `<div class="rv-note rv-err">Could not load the body: ${esc(e.message)}</div>`; return; }
    if (D.sig !== mySig || D[side] !== tab) return; // another call or tab was selected meanwhile
    if (tab === "raw") {
      const head = side === "req" ? `${msg.method} ${msg.path} ${msg.http_version}` : `${msg.http_version} ${msg.status_code} ${msg.reason || ""}`;
      el.innerHTML = `<pre>${esc(head + "\n" + (msg.headers || []).map(([k, v]) => k + ": " + v).join("\n") + "\n\n" + b.text)}</pre>` + clipNote(b);
      return find(side, false);
    }
    if (!b.bytes) { el.innerHTML = `<div class="rv-note">No body.</div>`; return find(side, false); }
    if (tab === "tree") {
      let doc;
      if (b.bytes > TREE_MAX) { el.innerHTML = `<div class="rv-note">The body is ${esc(fmtBytes(b.bytes))}: the tree shows bodies up to 24 MB. Use Body and search in it.</div>`; return; }
      try { doc = await parseTree(b.full); } catch (e) { el.innerHTML = `<div class="rv-note">Not JSON — see Body.</div>`; return; }
      if (D.sig !== mySig || D[side] !== tab) return;
      el.innerHTML = `<div class="rv-tree" role="tree"></div>`;
      const t = el.firstChild; t.append(treeNode(doc, "$", null, 0, true)); t.dataset.ready = "1";
      return find(side, false);
    }
    if (previewImage) {
      if (b.bytes > TREE_MAX) { el.innerHTML = `<div class="rv-note">Image preview is limited to 24 MB (${esc(fmtBytes(b.bytes))}).</div>`; return; }
      const url = URL.createObjectURL(new Blob([b.data], { type: imageType })); D.images.push(url);
      el.innerHTML = `<img class="rv-image" alt="Captured image response" style="max-width:100%;height:auto">`;
      el.firstChild.src = url;
      return;
    }
    if (b.binary) {
      el.innerHTML = `<div class="rv-note">Binary body, ${esc(fmtBytes(b.bytes))} (${esc((hdr(msg, "content-type") || "no content type").split(";")[0])}). First ${esc(fmtBytes(b.head.length))} as hex:</div><pre>${esc(hexView(b.head))}</pre>`;
      return find(side, false);
    }
    let text = b.text;
    if (/json/.test((hdr(msg, "content-type") || "").toLowerCase()) && b.bytes <= TEXT_MAX) { try { text = JSON.stringify(JSON.parse(b.full), null, 2); } catch (e) { /* not valid JSON: as it came */ } }
    const clipped = text.length > TEXT_MAX;           // also after pretty-printing, which makes a body longer
    el.innerHTML = `<pre>${esc(clipped ? text.slice(0, TEXT_MAX) : text)}</pre>` + (clipped || b.bytes > TEXT_MAX ? `<div class="rv-note">Showing the first 512 KB of ${esc(fmtBytes(b.bytes))}. Search covers what is shown; the Tree covers the whole body up to 24 MB.</div>` : "");
    find(side, false);
  }
  const clipNote = (b) => b.bytes > TEXT_MAX ? `<div class="rv-note">Showing the first 512 KB of ${esc(fmtBytes(b.bytes))}.</div>` : "";
  // A binary body laid out as text (a megabyte of unbroken replacement characters) froze the page: show it as hex.
  const TEXTUAL = /^(text\/|application\/(json|.*\+json|xml|.*\+xml|javascript|ecmascript|x-www-form-urlencoded|graphql|x-ndjson|problem\+json))/;
  function isBinary(msg, text) {
    const ct = (hdr(msg, "content-type") || "").toLowerCase().split(";")[0].trim();
    if (ct && TEXTUAL.test(ct)) return false;
    if (/^(image|video|audio|font)\/|octet-stream|protobuf|grpc|zip|pdf/.test(ct)) return true;
    const sample = text.slice(0, 4096);
    let odd = 0;
    for (let i = 0; i < sample.length; i++) { const c = sample.charCodeAt(i); if (c === 0xfffd || (c < 32 && c !== 9 && c !== 10 && c !== 13)) odd++; }
    return sample.length > 0 && odd / sample.length > 0.1;
  }
  function hexView(bytes) {
    let out = "";
    for (let o = 0; o < bytes.length; o += 16) {
      const row = bytes.subarray(o, o + 16);
      out += o.toString(16).padStart(8, "0") + "  " + [...row].map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48)
        + "  " + [...row].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("") + "\n";
    }
    return out;
  }

  // JSON tree: branches are built when opened; big arrays 200 entries at a time; search opens what matches
  const PAGE = 200;
  // a folded branch's one-line preview (as Proxyman shows): its first entries, values cut short; plain text, never markup
  function jsonPreview(v, max = 90) {
    const short = (x) => x === null ? "null" : Array.isArray(x) ? `[${x.length}]` : typeof x === "object" ? `{${Object.keys(x).length}}`
      : typeof x === "string" ? JSON.stringify(x.length > 24 ? x.slice(0, 24) + "…" : x) : String(x);
    const parts = [], arr = Array.isArray(v), keys = arr ? null : Object.keys(v), n = arr ? v.length : keys.length;
    let len = 0, i = 0;
    for (; i < n && len < max; i++) { const t = arr ? short(v[i]) : `${keys[i]}: ${short(v[keys[i]])}`; parts.push(t); len += t.length + 2; }
    return parts.join(", ") + (i < n ? ", …" : "");
  }
  function treeNode(v, path, key, depth, open) {
    const isObj = v && typeof v === "object", entries = isObj ? (Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v)) : [];
    const wrap = document.createElement("div");
    const line = document.createElement("div");
    line.className = "rv-tl"; line.dataset.path = path; line.setAttribute("role", "treeitem");
    const k = key === null ? "" : `<span class="rv-k">${typeof key === "number" ? key : esc(JSON.stringify(key))}</span>: `;
    if (isObj) {
      const kind = Array.isArray(v) ? `[${entries.length}]` : `{${entries.length}}`;
      line.innerHTML = `<span class="rv-tog" aria-hidden="true">${open ? "▾" : "▸"}</span>${k}<span class="rv-sum">${kind}</span>${entries.length ? `<span class="rv-prev">${esc(jsonPreview(v))}</span>` : ""}<button class="rv-copy" data-copy="path">copy path</button><button class="rv-copy" data-copy="value">copy value</button>`;
      line.setAttribute("aria-expanded", String(!!open));
      wrap.append(line);
      const kids = document.createElement("div"); kids.className = "rv-tn"; kids.hidden = !open;
      wrap.append(kids);
      line._rvFill = (n) => {
        const have = kids._rvN || 0, upto = Math.min(entries.length, n || have + PAGE);
        if (kids.lastChild && kids.lastChild._rvMore) kids.lastChild.remove();
        for (let i = have; i < upto; i++) { const [ek, ev] = entries[i]; kids.append(treeNode(ev, path + (Array.isArray(v) ? `[${ek}]` : (/^[A-Za-z_$][\w$]*$/.test(ek) ? "." + ek : `[${JSON.stringify(ek)}]`)), ek, depth + 1, ev && typeof ev === "object" && Object.keys(ev).length <= 100 && depth < 1)); }
        kids._rvN = upto;
        if (upto < entries.length) { const m = document.createElement("button"); m.className = "rv-ib"; m._rvMore = true; m.textContent = `Show ${Math.min(PAGE, entries.length - upto)} more of ${entries.length - upto}`; m.onclick = () => line._rvFill(); kids.append(m); }
      };
      line._rvEntries = entries;
      if (open) line._rvFill(PAGE);
    } else {
      const cls = typeof v === "string" ? "rv-vs" : typeof v === "number" ? "rv-vn" : v === null ? "rv-vz" : "rv-vb";
      const shown = typeof v === "string" && v.length > 500 ? JSON.stringify(v.slice(0, 500)) + `… (${fmtBytes(v.length)})` : typeof v === "string" ? JSON.stringify(v) : String(v);
      line.innerHTML = `<span class="rv-tog"></span>${k}<span class="${cls}">${esc(shown)}</span><button class="rv-copy" data-copy="path">copy path</button><button class="rv-copy" data-copy="value">copy value</button>`;
      wrap.append(line);
    }
    line._rvValue = v;
    return wrap;
  }
  function toggleNode(line, force) {
    const kids = line.nextElementSibling; if (!kids || !line._rvFill) return;
    const open = force === undefined ? kids.hidden : force;
    if (open && !kids._rvN) line._rvFill(PAGE);
    kids.hidden = !open; line.setAttribute("aria-expanded", String(open));
    line.querySelector(".rv-tog").textContent = open ? "▾" : "▸";
  }
  let lastPane = "res";          // Cmd+F searches the pane clicked last
  $("detail").addEventListener("pointerdown", (e) => { const p = e.target.closest("#pane-req, #pane-res"); if (p) lastPane = p.id === "pane-req" ? "req" : "res"; });
  $("detail").addEventListener("click", (e) => {
    const tab = e.target.closest("[data-tab]");
    if (tab) { D[tab.dataset.pane] = tab.dataset.tab; store.set("rivis-ui-" + tab.dataset.pane + "-tab", tab.dataset.tab); return drawDetail(); }
    const cp = e.target.closest("[data-copy]");
    if (cp) { const line = cp.closest(".rv-tl"); return copy(cp.dataset.copy === "path" ? line.dataset.path : JSON.stringify(line._rvValue, null, 2), cp.dataset.copy === "path" ? "Path copied" : "Value copied"); }
    const tog = e.target.closest(".rv-tl");
    if (tog && tog._rvFill) toggleNode(tog);
    const nx = e.target.closest("[data-fnext],[data-fprev]");
    if (nx) step(nx.dataset.fnext || nx.dataset.fprev, nx.dataset.fnext ? 1 : -1);
  });

  // search inside a body: every match highlighted (CSS Custom Highlight API), n of N, Enter / Shift+Enter
  const hits = { req: [], res: [] }, cur = { req: 0, res: 0 };
  let findT = 0;
  $("detail").addEventListener("input", (e) => { const s = e.target.dataset.find; if (!s) return; findText[s] = e.target.value; clearTimeout(findT); findT = setTimeout(() => find(s, true), 150); });
  $("detail").addEventListener("keydown", (e) => {
    const s = e.target.dataset && e.target.dataset.find; if (!s) return;
    if (e.key === "Enter") { e.preventDefault(); step(s, e.shiftKey ? -1 : 1); }
    if (e.key === "Escape") { e.target.value = ""; findText[s] = ""; find(s, false); }
  });
  function find(side, jump) {
    const pane = document.querySelector(`[data-body="${side}"]`), fc = document.querySelector(`[data-fc="${side}"]`);
    hits[side] = []; cur[side] = 0;
    const q = (findText[side] || "").toLowerCase();
    if (pane && q) {
      const tree = pane.querySelector(".rv-tree");
      if (tree) openMatches(tree, q);
      const walk = document.createTreeWalker(pane.querySelector(".rv-dyn") || pane, NodeFilter.SHOW_TEXT);
      for (let n = walk.nextNode(); n && hits[side].length < 5000; n = walk.nextNode()) {
        if (n.parentElement && n.parentElement.closest(".rv-copy,.rv-tog,.rv-prev")) continue;
        const t = n.data.toLowerCase();
        for (let i = t.indexOf(q); i >= 0 && hits[side].length < 5000; i = t.indexOf(q, i + q.length)) { const r = new Range(); r.setStart(n, i); r.setEnd(n, i + q.length); hits[side].push(r); }
      }
    }
    paint();
    if (fc) fc.textContent = q ? (hits[side].length ? `1 of ${hits[side].length}` : "0 of 0") : "";
    if (jump && hits[side].length) reveal(side);
  }
  // Search the parsed document itself (not what is built), then open just the paths to the first 200 matches: no
  // limit on array length, no stringifying of whole branches again and again (review).
  function openMatches(tree, q) {
    const root = tree.querySelector(".rv-tl"); if (!root) return;
    const paths = [], stack = [[root._rvValue, []]];
    let visited = 0;
    while (stack.length && paths.length < 200 && visited < 3e6) {
      const [v, path] = stack.pop(); visited++;
      if (v && typeof v === "object") {
        const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
        for (let i = entries.length - 1; i >= 0; i--) {
          const [k, x] = entries[i], p = path.concat(i);
          if (!Array.isArray(v) && String(k).toLowerCase().includes(q)) paths.push(p);
          stack.push([x, p]);
        }
      } else if ((typeof v === "string" ? JSON.stringify(v) : String(v)).toLowerCase().includes(q) && path.length) paths.push(path);
    }
    for (const path of paths) {       // walk down: open each branch and build it far enough to reach the entry
      let line = root;
      for (const i of path) {
        if (!line._rvFill) break;
        toggleNode(line, true);
        const kids = line.nextElementSibling;
        if (i >= (kids._rvN || 0)) line._rvFill(i + 1);
        const w = kids.children[i]; if (!w) break;
        line = w.firstElementChild;
      }
    }
  }
  function paint() {
    if (!window.CSS || !CSS.highlights) return;
    const all = [...hits.req, ...hits.res];
    if (all.length) CSS.highlights.set("rv-find", new Highlight(...all)); else CSS.highlights.delete("rv-find");
    const c = ["req", "res"].map((s) => hits[s][cur[s]]).filter(Boolean);
    if (c.length) CSS.highlights.set("rv-find-cur", new Highlight(...c)); else CSS.highlights.delete("rv-find-cur");
  }
  function step(side, d) {
    const n = hits[side].length; if (!n) return;
    cur[side] = (cur[side] + d + n) % n;
    const fc = document.querySelector(`[data-fc="${side}"]`); if (fc) fc.textContent = `${cur[side] + 1} of ${n}`;
    paint(); reveal(side);
  }
  function reveal(side) {
    const r = hits[side][cur[side]]; if (!r) return;
    const el = r.startContainer.parentElement; if (el) el.scrollIntoView({ block: "center" });
  }

  // ── right-click on a call (Proxyman's menu; Map Local and Breakpoint go through the panel API) ──────────────────────
  function openMenu(x, y, id) {
    const f = S.byId.get(id); if (!f) return;
    select(id, false);
    const host = hostOf(f), pinned = S.pins.has(host);
    const items = [
      ["url", "Copy URL", ""], ["curl", "Copy as cURL", ""], ["-"],
      ["repeat", "Repeat", ""], ["edit", "Edit and Repeat…", ""], ["compare", "Compare with…", ""], ["-"],
      ["map", "Map Local…", `${ALT}${MOD}L`], ["remote", "Map Remote…", `${ALT}${MOD}R`], ["bp", "Breakpoint (request and response)", `${ALT}${MOD}B`],
      ["block", "Block this endpoint", ""], ["-"],
      ["pin", (pinned ? "Unpin " : "Pin ") + host, ""], ["mark", "Highlight", "▸"], ["comment", userComment(f) ? "Edit Comment…" : "Comment…", ""], ["-"],
      ["host", "Show only " + host, ""], ["delete", "Delete", "⌫"],
    ];
    const m = $("menu"); m._rvMore = false;
    m.innerHTML = items.map(([a, l, k]) => a === "-" ? "<hr>" : `<button role="menuitem" data-act="${a}"><span>${esc(l)}</span><kbd>${esc(k)}</kbd></button>`).join("")
      + `<div class="rv-marks" role="group" aria-label="Highlight colour" hidden>${MARKS.map(([c, l]) => `<button role="menuitemradio" aria-checked="${markOf(f) === c}" data-mark="${c}" class="rv-swatch rv-mark-${c}" title="${l}" aria-label="${l}"></button>`).join("")}<button role="menuitem" data-mark="" class="rv-swatch-none" title="No highlight">None</button></div>`;
    m.hidden = false;
    const w = m.offsetWidth, h = m.offsetHeight;
    m.style.left = Math.min(x, innerWidth - w - 6) + "px"; m.style.top = Math.min(y, innerHeight - h - 6) + "px";
    m._rvId = id;
    m.querySelector("button").focus();
  }
  const closeMenu = () => { $("menu").hidden = true; $("tb-more").setAttribute("aria-expanded", "false"); };
  rowsEl.addEventListener("contextmenu", (e) => { const tr = e.target.closest(".rv-tr"); if (!tr) return; e.preventDefault(); setFollow(false); openMenu(e.clientX, e.clientY, tr.dataset.id); });
  addEventListener("mousedown", (e) => { if (!$("menu").hidden && !e.target.closest("#menu")) closeMenu(); });
  addEventListener("wheel", (e) => { if (!$("menu").hidden && !e.target.closest("#menu")) closeMenu(); }, { passive: true });
  addEventListener("blur", () => { if (!$("menu").hidden) closeMenu(); });
  $("menu").addEventListener("keydown", (e) => {
    const b = [...$("menu").querySelectorAll("button")], i = b.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); b[(i + 1) % b.length].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); b[(i - 1 + b.length) % b.length].focus(); }
    if (e.key === "Escape") { const back = $("menu")._rvMore ? $("tb-more") : tscroll; closeMenu(); back.focus(); }
  });
  $("menu").addEventListener("click", async (e) => {
    const more = e.target.closest("[data-more]");
    if (more) { const id = more.dataset.more; closeMenu(); if (id === "classic") window.open("../", "rivis-classic"); else window.RivisTools.open(id); return; }
    const mk = e.target.closest("[data-mark]");
    if (mk) { const id = $("menu")._rvId, m = MARKS.find((x) => x[0] === mk.dataset.mark); closeMenu(); return setFlow(id, { marked: m ? m[3] : "" }); }
    const b = e.target.closest("[data-act]"); if (!b) return;
    if (b.dataset.act === "mark") { const g = $("menu").querySelector(".rv-marks"); g.hidden = false; g.querySelector("button").focus(); return; }
    const id = $("menu")._rvId, f = S.byId.get(id); closeMenu();
    if (!f) return;
    try {
      if (b.dataset.act === "url") copy(urlOf(f), "URL copied");
      if (b.dataset.act === "curl") { const r = await api("export", { flow_id: id, fmt: "curl" }); copy(r.text, "cURL copied (secrets masked)"); }
      if (b.dataset.act === "repeat") { await api("retry", { flow_id: id, edits: {} }); toast("Repeated — the new call is at the end of the list"); }
      if (b.dataset.act === "map") {
        if (window.RivisMapLocal) return window.RivisMapLocal.fromFlow(id);
        const r = await api("mock", { flow_id: id }); S.state = r.state || S.state; drawTools(); toast("Map Local on for this endpoint");
      }
      if (b.dataset.act === "bp") {
        await api("bp_add", { flow_id: id, request: true, response: true }); pollState();
        toast("Breakpoint on — the next call to this endpoint pauses here");
        if (window.RivisTools) window.RivisTools.open("bp");
      }
      if (b.dataset.act === "remote" || b.dataset.act === "block") {
        const u = new URL(urlOf(f)), match = "^" + (u.origin + u.pathname).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        if (window.RivisTools && window.RivisTools.has("rules")) window.RivisTools.open("rules", { type: b.dataset.act === "remote" ? "map_remote" : "block", new: b.dataset.act === "remote" ? "map_remote" : "block", preset: { match, method: f.request.method, replace: u.origin } });
      }
      if (b.dataset.act === "edit") {
        if (window.RivisTools && window.RivisTools.has("repeat")) window.RivisTools.open("repeat", { fromFlow: id });
        else window.open("../#/flows/" + encodeURIComponent(id) + "/request", "rivis-classic");
      }
      if (b.dataset.act === "compare") window.RivisTools.open("compare", { left: id });
      if (b.dataset.act === "pin") { const h = hostOf(f); if (S.pins.has(h)) S.pins.delete(h); else S.pins.add(h); savePins(); drawSources(); toast(S.pins.has(h) ? "Pinned " + h + " to the sidebar" : "Unpinned " + h); }
      if (b.dataset.act === "comment") {
        const text = await askText(userComment(f) ? "Edit comment" : "Comment", "Shown on the call in the list.", userComment(f));
        if (text !== null) setFlow(id, { comment: text });
      }
      if (b.dataset.act === "host") { S.source = { host: hostOf(f) }; drawSources(); rebuildView(); }
      if (b.dataset.act === "delete") deleteFlow(id);
    } catch (err) { toast(err.message, true); }
  });

  // ── dialogs, toast, copy ─────────────────────────────────────────────────────────────────────────────────────────
  let dialogOwner = null;
  function ownDialog(cancel) {
    if (dialogOwner) dialogOwner();
    dialogOwner = cancel || null;
  }
  function ask(title, text, yes, danger) {
    return new Promise((resolve) => {
      ownDialog();
      const d = $("dialog"), sc = $("scrim");
      d.innerHTML = `<h3>${esc(title)}</h3><p>${esc(text)}</p><div class="rv-btns"><button class="rv-btn" id="dno">Cancel</button><button class="rv-btn ${danger ? "d" : "p"}" id="dyes">${esc(yes)}</button></div>`;
      d.hidden = sc.hidden = false;
      const back = document.activeElement;
      const done = (v) => { d.hidden = sc.hidden = true; d.onkeydown = null; if (back && back.focus) back.focus(); resolve(v); };
      $("dyes").onclick = () => done(true); $("dno").onclick = () => done(false); sc.onclick = () => done(false);
      d.onkeydown = (e) => { if (e.key === "Escape") done(false); };
      $("dyes").focus();
    });
  }
  async function pickColumns() {
    ownDialog();
    const cur = columns().slice(1), d = $("dialog"), sc = $("scrim");
    const labels = Object.assign({}, ...BUILTINS.map((c) => ({ [c]: COLS[c].label })));
    const extra = cur.filter((c) => !BUILTINS.includes(c));
    d.innerHTML = `<h3>Columns</h3><p>Saved for this project; the classic view uses the same choice.</p><div class="rv-cols">`
      + BUILTINS.concat(extra).map((c) => `<label><input type="checkbox" data-c="${esc(c)}" ${cur.includes(c) ? "checked" : ""}> ${esc(labels[c] || colDef(c).label)}</label>`).join("")
      + `</div><label>Header column <input type="text" id="hcol" placeholder="response:Content-Type" style="flex:1"></label>`
      + `<div class="rv-btns" style="margin-top:12px"><button class="rv-btn" id="dno">Cancel</button><button class="rv-btn p" id="dyes">Save</button></div>`;
    d.hidden = sc.hidden = false;
    const close = () => { d.hidden = sc.hidden = true; };
    $("dno").onclick = close; sc.onclick = close; d.onkeydown = (e) => { if (e.key === "Escape") close(); };
    $("dyes").onclick = async () => {
      const want = [...d.querySelectorAll("[data-c]")].filter((x) => x.checked).map((x) => x.dataset.c);
      const h = $("hcol").value.trim(); if (h) want.push(/^(request|response):/i.test(h) ? h.replace(/^(\w+):/, (m, s) => s.toLowerCase() + ":") : "response:" + h);
      if (!want.includes("path")) want.unshift("path");
      try { const r = await api("columns_set", { columns: want }); S.state = r.state || S.state; S.state.columns = r.columns || want; close(); drawHead(); drawList(true); }
      catch (e) { toast(e.message, true); }
    };
    d.querySelector("input").focus();
  }
  let toastT = 0;
  function toast(text, err) { const t = $("toast"); t.textContent = text; t.className = "rv-toast show" + (err ? " err" : ""); clearTimeout(toastT); toastT = setTimeout(() => (t.className = "rv-toast"), err ? 5000 : 2600); }
  // mitmweb's own flow update: highlight colour (marked) and comment live on the call itself
  async function setFlow(id, change) {
    try {
      const r = await http("../flows/" + encodeURIComponent(id), { method: "PUT", headers: { "Content-Type": "application/json", "X-XSRFToken": xsrf() }, body: JSON.stringify(change) });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const f = S.byId.get(id); if (f) Object.assign(f, change);
      drawList(true);
    } catch (e) { toast("Could not change the call: " + e.message, true); }
  }
  function askText(title, text, value, validate) {
    return new Promise((resolve) => {
      ownDialog();
      let settled = false, submitting = false;
      const d = $("dialog"), sc = $("scrim"), back = document.activeElement;
      const paint = () => {
        d.innerHTML = `<h3>${esc(title)}</h3>${text ? `<p>${esc(text)}</p>` : ""}<form><textarea id="dtext" rows="3" style="width:100%;margin-bottom:12px;padding:6px;font:inherit">${esc(value || "")}</textarea>`
          + `<p id="dtext-err" class="rv-err" hidden role="alert"></p>`
          + `<div class="rv-btns"><button type="button" class="rv-btn" id="dno">Cancel</button><button type="submit" class="rv-btn p">Save</button></div></form>`;
      };
      paint();
      d.hidden = sc.hidden = false;
      const done = (v) => { if (settled || dialogOwner !== cancel) return; settled = true; dialogOwner = null; d.hidden = sc.hidden = true; d.onkeydown = null; if (back && back.focus) back.focus(); resolve(v); };
      const cancel = () => done(null);
      dialogOwner = cancel;
      const submit = async () => {
        if (settled || dialogOwner !== cancel || submitting) return;
        submitting = true;
        const err = $("dtext-err"), save = d.querySelector('button[type=submit]'), v = $("dtext").value.trim();
        err.hidden = true;
        if (validate) {
          save.disabled = true;
          try { const r = await validate(v); done(r !== undefined ? r : v); }
          catch (e) { if (settled || dialogOwner !== cancel) return; submitting = false; err.textContent = e.message || String(e); err.hidden = false; save.disabled = false; $("dtext").focus(); }
          return;
        }
        done(v);
      };
      d.querySelector("form").onsubmit = (e) => { e.preventDefault(); submit(); };
      $("dno").onclick = () => done(null); sc.onclick = () => done(null);
      d.onkeydown = (e) => { if (e.key === "Escape") done(null); if (e.key === "Enter" && (isMac ? e.metaKey : e.ctrlKey)) { e.preventDefault(); submit(); } };
      $("dtext").focus();
    });
  }
  async function copy(text, done) {
    try { await navigator.clipboard.writeText(text); toast(done); }
    catch (e) { await ask("Copy this text", text.length > 2000 ? text.slice(0, 2000) + "…" : text, "Done"); }
  }

  // ── status bar ───────────────────────────────────────────────────────────────────────────────────────────────────
  function drawStatus() {
    const st = S.state || {}, p = st.project || {};
    const port = (st.proxy && st.proxy.port) || (st.listen && st.listen.port) || "";
    const map = toolState("map"), bp = toolState("bp");
    $("status").innerHTML = `<span><span class="rv-live${S.live && S.record ? "" : " off"}"></span>${!S.record ? "Paused" : S.live ? "Live" : "Reconnecting…"}</span>`
      + `<span><b>${S.view.length}</b> of ${S.order.length} calls</span>`
      + (st.retention && st.retention.trimmed ? `<span>${st.retention.trimmed} older calls trimmed (keeps up to ${st.retention.limit})</span>` : "")
      + (S.held.size ? `<span><b>${S.held.size}</b> waiting — press Record</span>` : "")
      + (p.label ? `<span>Project <b>${esc(p.label)}</b></span>` : "")
      + (map.on ? `<span>Map Local on (${map.n})</span>` : "") + (bp.on ? `<span>${bp.n} breakpoint${bp.n === 1 ? "" : "s"}</span>` : "")
      + (st.no_cache ? `<span>No Caching on</span>` : "")
      + (st.lan && st.lan.on ? `<span>Wi-Fi ${esc(st.lan.addresses.join(", "))}</span>` : "");
    $("tb-project").textContent = p.label ? "Project: " + p.label : "";
  }

  // ── panel state (tools, sources, columns, saved filters) ──────────────────────────────────────────────────────────
  const stateFns = [];
  let pollT = 0;
  async function pollState() {
    clearTimeout(pollT);
    try {
      const st = await api("state", undefined, 10000);
      const colsChanged = JSON.stringify((S.state || {}).columns) !== JSON.stringify(st.columns);
      const savedChanged = JSON.stringify((S.state || {}).saved_filters) !== JSON.stringify(st.saved_filters);
      S.state = st;
      drawTools(); drawStatus(); sourcesSoon();
      stateFns.forEach((fn) => { try { fn(st); } catch (e) { /* one tool window must not stop the poll */ } });
      drawBanners(st);
      if (colsChanged) { drawHead(); drawList(true); }
      if (savedChanged) drawChips();
      if (S.source && S.source.key) rebuildView();
    } catch (e) { /* the feed's own indicator says when Rivis is gone */ }
    pollT = setTimeout(pollState, 2000);
  }

  // ── shortcuts (Proxyman's) ───────────────────────────────────────────────────────────────────────────────────────
  document.addEventListener("rivis-command", (e) => {
    const detail = e.detail;
    if (["map", "remote", "block", "bp", "scripts", "net", "nocache"].includes(detail)) openTool(detail);
    else if (detail === "clear") clearAll();
    else if (detail === "follow") setFollow(!S.follow);
    else if (detail === "filter" || detail === "sources") { const input = $(detail === "filter" ? "q" : "sq"); input.focus(); input.select(); }
    else if (detail === "record") $("tb-record").click();
    else if (detail === "classic") location.href = "../";
    else if (detail === "allow") openAllowList();
  });
  function openAllowList() {
    const w = window.RivisTools.open("net", { focus: '[data-net-tls-add="allow"]' });
    if (w) { const field = w.body.querySelector('[data-net-tls-add="allow"]'); if (field) field.scrollIntoView({ block: "center" }); }
  }
  addEventListener("keydown", (e) => {
    const mod = isMac ? e.metaKey : e.ctrlKey, typing = e.target.closest && e.target.closest("input, textarea, select, [contenteditable]");
    if (!$("dialog").hidden) return;
    if (mod && e.altKey && e.code === "KeyF") { e.preventDefault(); $("q").focus(); $("q").select(); return; }
    // a text field keeps its keys (review); ⌥⌘ tool chords type nothing, so they open their tool from anywhere, as in Proxyman
    if (typing && !(mod && (e.code === "KeyK" || e.code === "KeyF")) && !(mod && e.altKey && /^Key[ALRBXN]$/.test(e.code))) return;
    if (mod && e.shiftKey && (e.key === "Backspace" || e.key === "Delete")) { e.preventDefault(); clearAll(); return; }
    if (mod && e.shiftKey && e.code === "KeyL") { e.preventDefault(); setFollow(!S.follow); return; }
    if (mod && e.altKey && e.code === "KeyN") { e.preventDefault(); openTool("nocache"); return; }
    if (mod && e.altKey && e.code === "KeyA") { e.preventDefault(); openAllowList(); return; }
    if (mod && e.altKey && e.code === "KeyL") { e.preventDefault(); openTool("map"); return; }
    if (mod && e.altKey && e.code === "KeyR") { e.preventDefault(); openTool("remote"); return; }
    if (mod && e.altKey && e.code === "KeyB") { e.preventDefault(); openTool("bp"); return; }
    if (mod && e.altKey && e.code === "KeyC") { e.preventDefault(); window.RivisTools.open("compose"); return; }
    if (mod && e.altKey && e.code === "KeyD") { e.preventDefault(); window.RivisTools.open("devices"); return; }
    if (mod && e.altKey && e.code === "KeyX") { e.preventDefault(); openTool("block"); return; }
    if (!mod && !e.altKey && e.key === "?") { e.preventDefault(); showHelp(); return; }
    if (mod && !e.altKey && !e.shiftKey && e.code === "KeyK") { e.preventDefault(); $("sq").focus(); $("sq").select(); return; }
    if (mod && !e.altKey && !e.shiftKey && e.code === "KeyF" && (!typing || e.target.closest("#detail"))) {
      const side = e.target.closest && e.target.closest("#pane-req") ? "req" : e.target.closest && e.target.closest("#pane-res") ? "res" : lastPane;
      e.preventDefault(); const inp = document.querySelector(`[data-find="${side}"]`); if (inp) { inp.focus(); inp.select(); } return;
    }
    if (e.altKey && !mod && /^Digit[1-9]$/.test(e.code)) { e.preventDefault(); applySaved(Number(e.code.slice(5)) - 1); return; }
    if (!typing && (e.key === "Backspace" || e.key === "Delete") && S.sel && e.target.closest && e.target.closest("#tscroll")) { e.preventDefault(); deleteFlow(S.sel); }
  });

  // detail height (drag the splitter; remembered)
  const main = document.querySelector(".rv-main");
  const h0 = Number(store.get("rivis-ui-detail-h", "0")); if (h0 > 100) main.style.setProperty("--rv-detail-h", h0 + "px");
  $("hsplit").addEventListener("pointerdown", (e) => {
    e.preventDefault();
    const bottom = main.getBoundingClientRect().bottom;
    const move = (ev) => { const h = Math.max(160, Math.min(main.clientHeight - 140, bottom - ev.clientY)); main.style.setProperty("--rv-detail-h", h + "px"); store.set("rivis-ui-detail-h", String(Math.round(h))); drawList(true); };
    const up = () => { removeEventListener("pointermove", move); removeEventListener("pointerup", up); };
    addEventListener("pointermove", move); addEventListener("pointerup", up);
  });

  // ── start ────────────────────────────────────────────────────────────────────────────────────────────────────────
  setFollow(S.follow);
  drawHead(); drawChips(); drawTools(); drawStatus(); drawDetail();
  pollState();
  loadFlows().then(() => drawSources());
  connect();
  // ── notices (another app holds the Mac proxy, untrusted certificate, update) ─────────────────────────────────────
  let loadedVersion = null, proxyFixShown = false;
  function drawBanners(st) {
    if (loadedVersion === null && st.version) loadedVersion = st.version;
    if (loadedVersion && st.version && st.version !== loadedVersion) { location.reload(); return; }   // updated: the new page
    const name = (st.product && st.product.name) || "Rivis", sp = st.system_proxy, out = [];
    if (sp && sp.fixed && !proxyFixShown) { proxyFixShown = true; toast(`Fixed: another proxy app had left your Mac's proxy on ${sp.host}:${sp.port} with nothing running there.`); }
    if (sp && !sp.fixed) proxyFixShown = false;
    if (sp && sp.owner && !sp.ours)
      out.push(`<div class="rv-banner warn" role="alert" data-banner="proxy"><span><b>${esc(sp.owner)}</b> is your Mac's proxy (${esc(sp.host)}:${esc(sp.port)}): the iOS Simulator sends its calls there, not to ${esc(name)}. Quit ${esc(sp.owner)}; ${esc(name)} cleans up what it leaves behind.</span></div>`);
    const un = st.untrusted || [];
    if (un.length)
      out.push(`<div class="rv-banner warn" role="alert" data-banner="untrusted"><span>A simulator or emulator does not trust the ${esc(name)} certificate, so <b>${esc(un[0].host)}</b>${un.length > 1 ? ` and ${un.length - 1} more` : ""} ${un.length > 1 ? "pass" : "passes"} through without being recorded.</span>`
        + `<button class="rv-btn" data-bn="setup">Set up devices</button><button class="rv-btn" data-bn="retry">Decrypt again</button></div>`);
    const u = st.update || {};
    if (u.installing) out.push(`<div class="rv-banner info" role="status" data-banner="update"><span>Updating ${esc(name)} to ${esc(u.installing.version)}… It restarts by itself in about a minute, and this page reloads.</span></div>`);
    else if (u.available && store.get("rivis-update-later", "") !== u.available.version)
      out.push(`<div class="rv-banner info" role="status" data-banner="update"><span>${esc(name)} ${esc(u.available.version)} is available.${u.available.notes ? " " + esc(u.available.notes) : ""}</span>`
        + `<button class="rv-btn p" data-bn="update">Update to ${esc(u.available.version)}</button><button class="rv-btn" data-bn="later">Later</button></div>`);
    const html = out.join("");
    if ($("banners").dataset.html !== html) { $("banners").dataset.html = html; $("banners").innerHTML = html; drawList(true); }
  }
  $("banners").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-bn]"); if (!b) return;
    const st = S.state || {};
    try {
      if (b.dataset.bn === "setup") { if (window.RivisTools && window.RivisTools.has("devices")) window.RivisTools.open("devices"); else window.open("../#rivis-tool=net", "rivis-classic"); }
      if (b.dataset.bn === "retry") { await api("untrusted_retry", {}); toast("Decrypting again from the next connection"); pollState(); }
      if (b.dataset.bn === "update") { await api("update_install", {}, 120000); toast("Updating… it restarts by itself in about a minute"); pollState(); }
      if (b.dataset.bn === "later") { store.set("rivis-update-later", ((st.update || {}).available || {}).version || ""); drawBanners(st); }
    } catch (err) { toast(err.message, true); }
  });

  // ── help, settings, first run ────────────────────────────────────────────────────────────────────────────────────
  const KEYS = [
    [`${MOD}K`, "Find or pin a domain in the sidebar"], [`${ALT}${MOD}F`, "Filter the list"], [`${SHIFT}${MOD}L`, "Auto-select the newest call (follow)"],
    [`${SHIFT}${MOD}⌫`, "Clear the list"], [`${ALT}${MOD}L`, "Map Local"], [`${ALT}${MOD}R`, "Map Remote"], [`${ALT}${MOD}B`, "Breakpoint"],
    [`${ALT}${MOD}X`, "Block List"], [`${ALT}${MOD}N`, "No Caching"], [`${ALT}${MOD}A`, "Allow List (hosts to decrypt)"], [`${ALT}1 … ${ALT}9`, "Saved filters"], [`${MOD}F`, "Search in the request or response body"],
    ["↑ ↓", "Move through the list"], ["⌫", "Delete the selected call"], [`${MOD}↩`, "Continue a paused call · send in Edit and Repeat"], [`${MOD}S`, "Save in Map Local"], ["Esc", "Close the front window"],
  ];
  function showDialog(html, focusSel) {
    ownDialog();
    const d = $("dialog"), sc = $("scrim"), back = document.activeElement;
    d.className = "rv-dialog wide"; d.innerHTML = html; d.hidden = sc.hidden = false;
    const done = () => { d.hidden = sc.hidden = true; d.className = "rv-dialog"; d.onkeydown = null; if (back && back.focus) back.focus(); };
    d.querySelectorAll("[data-close]").forEach((b) => (b.onclick = done)); sc.onclick = done;
    d.onkeydown = (e) => { if (e.key === "Escape") { e.preventDefault(); done(); } };
    (d.querySelector(focusSel || "[data-close]") || d).focus();
    return { d, done };
  }
  function showHelp() {
    const name = (S.state && S.state.product && S.state.product.name) || "Rivis";
    showDialog(`<h3>${esc(name)} — shortcuts</h3><p>Laid out like Proxyman: sources on the left, tools in the toolbar, request and response side by side. Right-click a call for its actions.</p>
      <table class="rv-keys">${KEYS.map(([k, t]) => `<tr><td>${esc(k)}</td><td>${esc(t)}</td></tr>`).join("")}</table>
      <h4>Coming from Proxyman</h4><p>Map Local, Map Remote, Breakpoint, Block List, No Caching, Scripting and Network are in the toolbar; Compose, Devices, Collections and Sessions are under More. The classic view is still one click away (top right).</p>
      <div class="rv-btns"><button class="rv-btn p" data-close>Close</button></div>`);
  }
  function showSettings() {
    const t = store.get("rivis-theme", "") || "system";
    const { d } = showDialog(`<h3>Settings</h3><h4>Appearance</h4>
      ${[["system", "Follow the Mac"], ["light", "Light"], ["dark", "Dark"]].map(([v, l]) => `<label><input type="radio" name="theme" value="${v}"${t === v ? " checked" : ""}> ${l}</label>`).join("")}
      <h4>Welcome</h4><p><button class="rv-btn" id="set-welcome">Show the welcome again</button></p>
      <h4>Version</h4><p>${esc((S.state && S.state.version) || "")}</p>
      <div class="rv-btns"><button class="rv-btn p" data-close>Done</button></div>`, "input[name=theme]:checked");
    d.querySelectorAll("input[name=theme]").forEach((r) => (r.onchange = () => { store.set("rivis-theme", r.value === "system" ? "" : r.value); applyTheme(); }));
    d.querySelector("#set-welcome").onclick = () => { store.set("rivis-ui-welcome", ""); showWelcome(); };
  }
  function showWelcome() {
    const name = (S.state && S.state.product && S.state.product.name) || "Rivis";
    const { d, done } = showDialog(`<h3>Welcome to the new ${esc(name)} window</h3>
      <p>It works like Proxyman: pick an app or domain on the left, click a call, and its request and response show side by side. Right-click a call to Map Local, Breakpoint, Map Remote, Block, Pin, Highlight or Comment it.</p>
      <p>The tools are in the toolbar and open in their own windows; a paused call opens by itself. Press <b>?</b> any time for the shortcuts.</p>
      <div class="rv-btns"><button class="rv-btn" id="w-keys">Shortcuts</button><button class="rv-btn p" id="w-ok">Got it</button></div>`, "#w-ok");
    const close = () => { store.set("rivis-ui-welcome", "done"); done(); };
    d.querySelector("#w-ok").onclick = close;
    d.querySelector("#w-keys").onclick = () => { close(); showHelp(); };
    d.onkeydown = (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } };
  }
  $("tb-help").addEventListener("click", showHelp);
  $("tb-settings").addEventListener("click", showSettings);
  setTimeout(() => { if (store.get("rivis-ui-welcome", "") !== "done" && $("dialog").hidden) showWelcome(); }, 700);

  window.__rivisUI = S;          // tests and support read the model (never written from outside)
  // what the tool windows may use: the server, the selection, the page's own dialogs. The state arrives every 2 s
  // (onState), and at once after a change (refresh).
  window.RivisApp = Object.freeze({
    $, esc, api, openCapture, toast, ask, copy, MOD, ALT, SHIFT, isMac,
    state: () => S.state, selected: () => (S.sel && S.byId.get(S.sel)) || null, flow: (id) => S.byId.get(id) || null,
    recentFlows: () => S.order.slice(-100).reverse().map((id) => S.byId.get(id)).filter((f) => f && f.type === "http"),
    currentFilter: () => {
      if (S.expr || !S.text) return S.expr || "";
      // The filter parser consumes backslashes inside quotes. Character classes preserve literal regex punctuation.
      const quote = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, (c) => c === "[" ? "[[]" : c === "]" ? "[]]" : c === "\\" ? "[\\\\]" : c === "^" ? "[\\^]" : "[" + c + "]").replace(/'/g, "\\'");
      return "~u '" + quote(S.text) + "'";
    },
    select: (id) => { setFollow(false); select(id, true); },
    urlOf, hostOf, fmtBytes, fmtMs,
    onState: (fn) => { stateFns.push(fn); if (S.state) fn(S.state); },
    refresh: () => pollState(),
    toolsChanged: () => { drawTools(); drawStatus(); },
  });
})();
