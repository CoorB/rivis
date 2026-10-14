/* Product-neutral panel — injected into mitmweb by proxy_panel.py.
 * A self-contained drawer (shadow DOM, so mitmweb's CSS and ours never collide), modelled on
 * FRTMProxy / Proxyman: This call · Compose · Map Local · Breakpoints · Network (incl. TLS decryption list) ·
 * Scripts · Rules, "Copy as …" code generation, plus a pop-up
 * editor that opens by itself when a call pauses at a breakpoint (Continue / Skip / Abort).
 * Talks only to /proxy/api/* with mitmweb's own XSRF scheme (cookie _mitmproxy_xsrf → X-XSRFToken).
 */
(() => {
  if (window.__proxyPanel) return;
  window.__proxyPanel = true;
  const W = 460;

  const xsrf = () => (document.cookie.match(/(?:^|;\s*)_mitmproxy_xsrf=([^;]+)/) || [])[1] || "";
  const api = async (op, body) => {
    const opts = body === undefined
      ? { credentials: "same-origin" }
      : { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-XSRFToken": xsrf() }, body: JSON.stringify(body) };
    const r = await fetch("./proxy/api/" + op, opts);
    let j = {};
    try { j = await r.json(); } catch (e) { j = { error: "HTTP " + r.status }; }
    if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
    return j;
  };
  const selectedFlow = () => {   // mitmweb keeps the selection in the hash: #/flows/<id>/<tab>
    const p = location.hash.replace(/^#\/?/, "").split("?")[0].split("/");
    return p[0] === "flows" && p[1] ? p[1] : null;
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const hostPath = (u) => { try { const x = new URL(u); return [x.host, x.pathname]; } catch (e) { return ["", u]; } };
  // a rule's match regex → readable "host/path" for lists
  const pretty = (r) => {
    if (r.note && r.note.startsWith("from ")) { const u = r.note.split(" ").pop(); const [h, p] = hostPath(u); return h + p; }
    if (r.note && r.note.startsWith("manual: ")) return r.note.slice(8);
    if (r.label) return r.label;
    return String(r.match || "").replace(/^\^https\?:\/\//, "").replace(/\(:\\d\+\)\?/, "").replace(/\(\\\?\|\$\)$/, "")
      .replace(/\\([.\-\/])/g, "$1").replace(/\[\^\/:\]\*/g, "*").replace(/\.\*/g, "*");
  };

  const host = document.createElement("div");
  host.id = "proxy-panel-host";
  document.body.appendChild(host);
  const root = host.attachShadow({ mode: "open" });
  // mitmweb has single-key shortcuts on window (d = delete, a = resume, r = replay…) and swallows
  // keys it thinks are shortcuts. It cannot see that focus is in OUR text boxes (shadow DOM), so
  // keep every key press inside the panel from ever reaching its window handler.
  ["keydown", "keypress", "keyup"].forEach((t) => host.addEventListener(t, (e) => e.stopPropagation()));
  root.innerHTML = `
  <style>
    :host { all: initial; }
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .fab { position: fixed; right: 18px; bottom: 34px; z-index: 2147483000; background: #0f766e; color: #fff;
           border: 0; border-radius: 22px; padding: 10px 16px; font-weight: 600; font-size: 13px; cursor: pointer;
           box-shadow: 0 4px 14px rgba(0,0,0,.25); }
    .fab .dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:#fbbf24; margin-left:6px; }
    .fab.paused { background:#c2410c; }
    .drawer { position: fixed; top: 0; right: 0; height: 100vh; width: ${W}px; max-width: 100vw; z-index: 2147483001;
              background: #fff; color: #111; border-left: 1px solid #ddd; box-shadow: -8px 0 24px rgba(0,0,0,.12);
              display: none; flex-direction: column; font-size: 13px; }
    .drawer.open { display: flex; }
    header { display:flex; align-items:center; gap:8px; padding: 10px 14px; border-bottom: 1px solid #eee; }
    header b { font-size: 15px; flex: 1; }
    .x { border:0; background:none; font-size:20px; cursor:pointer; color:#666; }
    nav { display:flex; flex-wrap:wrap; border-bottom:1px solid #eee; padding: 0 6px; }
    nav button { flex:none; border:0; background:none; padding:9px 7px; cursor:pointer; font-size:12px; color:#555;
                 border-bottom: 2px solid transparent; white-space:nowrap; }
    nav button.on { color:#0f766e; border-bottom-color:#0f766e; font-weight:600; }
    nav .cnt:empty { display:none; }
    nav .cnt { background:#e0f2f1; color:#0f766e; border-radius:8px; padding:0 5px; font-size:10px; margin-left:3px; }
    nav .cnt.err { background:#fee2e2; color:#b91c1c; }
    main { flex:1; overflow:auto; padding: 12px 14px; }
    h4 { margin: 14px 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color:#888; }
    h4:first-child { margin-top: 2px; }
    .call { background:#f6f7f8; border-radius:8px; padding:8px 10px; word-break: break-all; font-size:12px; }
    .m { font-weight:700; margin-right:6px; }
    .btns { display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; align-items:center; }
    button.b { border:1px solid #d0d5da; background:#fff; border-radius:6px; padding:6px 10px; cursor:pointer; font-size:12px; color:#111; }
    button.b:hover { background:#f0fdfa; border-color:#0f766e; }
    button.b:disabled { opacity:.5; cursor:default; }
    button.p { background:#0f766e; color:#fff; border-color:#0f766e; }
    button.p:hover { background:#115e59; }
    button.d { color:#b91c1c; }
    button.warn { background:#c2410c; color:#fff; border-color:#c2410c; }
    .row { display:flex; align-items:center; gap:8px; padding:8px 0; border-bottom:1px solid #f0f0f0; }
    .row .n { flex:1; min-width:0; }
    .row .n div { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .tag { font-size:10px; padding:1px 6px; border-radius:8px; background:#e0f2f1; color:#0f766e; margin-left:4px; }
    .chip { font-size:11px; padding:3px 8px; border-radius:10px; border:1px solid #d0d5da; background:#fff; cursor:pointer; color:#555; }
    .chip.on { background:#0f766e; color:#fff; border-color:#0f766e; }
    .sub { color:#888; font-size:11px; }
    .sw { position:relative; width:34px; height:20px; flex:none; }
    .sw input { opacity:0; width:0; height:0; }
    .sw span { position:absolute; inset:0; background:#ccc; border-radius:10px; cursor:pointer; transition:.15s; }
    .sw span:before { content:""; position:absolute; width:16px; height:16px; left:2px; top:2px; background:#fff; border-radius:50%; transition:.15s; }
    .sw input:checked + span { background:#0f766e; }
    .sw input:checked + span:before { transform: translateX(14px); }
    select, input[type=number], input[type=text] { border:1px solid #d0d5da; border-radius:6px; padding:5px 7px; font-size:12px; background:#fff; color:#111; }
    input.grow { flex:1; min-width:0; }
    textarea { width:100%; min-height: 260px; height: calc(100vh - 420px); font-family: ui-monospace, Menlo, monospace; font-size:12px;
               border:1px solid #d0d5da; border-radius:6px; padding:8px; resize:vertical; background:#fff; color:#111; }
    .muted { color:#888; }
    .toast { position: fixed; left: 50%; transform: translateX(-50%); bottom: 24px; z-index: 2147483003; background:#111;
             color:#fff; padding:8px 14px; border-radius:8px; font-size:12px; display:none; max-width:80vw; }
    .toast.err { background:#b91c1c; }
    .card { display:flex; gap:10px; align-items:flex-start; border:1px solid #e3e6e9; border-radius:10px; padding:9px 11px;
            margin-bottom:7px; cursor:pointer; }
    .card:hover { border-color:#0f766e; }
    .card.on { border-color:#0f766e; background:#f0fdfa; }
    .card .ic { font-size:16px; width:22px; text-align:center; }
    .card .t { font-weight:600; }
    .card .ok { margin-left:auto; color:#0f766e; font-weight:700; }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap:8px; margin-top:8px; }
    .grid label { font-size:11px; color:#666; display:flex; flex-direction:column; gap:3px; }
    .seg { display:flex; gap:0; margin: 8px 0 6px; }
    .seg button { border:1px solid #d0d5da; background:#fff; padding:5px 12px; cursor:pointer; font-size:12px; color:#555; }
    .seg button:first-child { border-radius:6px 0 0 6px; } .seg button:last-child { border-radius:0 6px 6px 0; }
    .seg button.on { background:#0f766e; border-color:#0f766e; color:#fff; }
    .hrow { display:flex; gap:4px; margin-bottom:4px; }
    .hrow input { flex:1; min-width:0; font-family: ui-monospace, Menlo, monospace; font-size:11px; }
    .hrow input:first-child { flex: 0 0 38%; }
    .krow { display:flex; gap:4px; margin-bottom:4px; align-items:center; }
    .krow input[type=text] { flex:1; min-width:0; font-family: ui-monospace, Menlo, monospace; font-size:11px; }
    .krow input[type=checkbox] { flex:none; }
    .chip span[data-tlsrm] { margin-left:4px; cursor:pointer; opacity:.7; }
    .pause { position: fixed; inset: 0; z-index: 2147483002; background: rgba(0,0,0,.35); display:none; align-items:center; justify-content:center; }
    .pause.open { display:flex; }
    .sheet { background:#fff; color:#111; width: min(860px, 94vw); max-height: 92vh; display:flex; flex-direction:column; border-radius:12px;
             box-shadow: 0 20px 60px rgba(0,0,0,.35); overflow:hidden; }
    .sheet header { background:#fff7ed; border-bottom:1px solid #fed7aa; }
    .sheet main { padding: 12px 16px; }
    .sheet footer { display:flex; gap:8px; justify-content:flex-end; padding: 10px 16px; border-top:1px solid #eee; align-items:center; }
    .sheet textarea { height: 38vh; }
    table.diff { width:100%; border-collapse:collapse; font-size:11px; table-layout:fixed; }
    table.diff td, table.diff th { border-bottom:1px solid #eee; padding:4px 5px; vertical-align:top; word-break:break-all; text-align:left; }
    table.diff th { color:#888; font-weight:600; }
    table.diff td.k { font-family: ui-monospace, Menlo, monospace; color:#555; }
    td.a { background:#fef2f2; } td.b { background:#f0fdf4; }
    .rec { color:#dc2626; font-weight:700; }
    pre.code { white-space:pre-wrap;word-break:break-word;background:#f6f7f8;border-radius:7px;padding:8px;font:11px ui-monospace,Menlo,monospace;max-height:260px;overflow:auto; }
    .errbox { background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:7px;padding:8px;margin-top:6px; }
    @media (prefers-color-scheme: dark) {
      td.a { background:#3b1d1d; } td.b { background:#14301d; } table.diff td, table.diff th { border-color:#2c3034; }
      .drawer, .sheet { background:#1c1f22; color:#e6e6e6; border-color:#333; }
      header, nav, .row, .sheet footer { border-color:#2c3034; }
      .sheet header { background:#3a2a16; border-color:#9a6a2a; }
      .call, pre.code { background:#26292d; }
      button.b, .chip, .seg button { background:#26292d; color:#e6e6e6; border-color:#3a3f44; }
      select, input, textarea { background:#26292d !important; color:#e6e6e6 !important; border-color:#3a3f44 !important; }
      .card { border-color:#3a3f44; } .card.on { background:#13302c; }
    }
  </style>
  <button class="fab" id="fab">Proxy<span class="dot" id="fabdot" style="display:none"></span></button>
  <div class="drawer" id="drawer">
    <header><b id="ptitle">Proxy tools</b><select id="project" title="Changes the list view only; restart to load another project's rules"></select><button class="x" id="close" title="Close">×</button></header>
    <nav>
      <button data-t="call" class="on">This call</button>
      <button data-t="compose">Compose</button>
      <button data-t="map">Map Local<span class="cnt" id="c-map"></span></button>
      <button data-t="bp">Breakpoints<span class="cnt" id="c-bp"></span></button>
      <button data-t="net">Network</button>
      <button data-t="coll">Collections<span class="cnt" id="c-coll"></span></button>
      <button data-t="cmp">Compare</button>
      <button data-t="sess">Sessions</button>
      <button data-t="scripts">Scripts<span class="cnt" id="c-scripts"></span></button>
      <button data-t="rules">Rules<span class="cnt" id="c-rules"></span></button>
    </nav>
    <main id="main"></main>
  </div>
  <div class="pause" id="pause"><div class="sheet" id="sheet"></div></div>
  <div class="toast" id="toast"></div>`;

  const $ = (id) => root.getElementById(id);
  let tab = "call", state = null, editing = null, pausedOpen = null, dismissed = new Set();
  let viewers = { tokens:[], graphql_ops:[], graphql_error_ids:[], complete:false };
  const toast = (msg, err) => {
    const t = $("toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : ""); t.style.display = "block";
    clearTimeout(toast._t); toast._t = setTimeout(() => (t.style.display = "none"), err ? 5000 : 2500);
  };
  const busy = new Set();
  const run = async (op, body, ok) => {
    const key = op + JSON.stringify(body || {});
    if (busy.has(key)) return;
    busy.add(key);
    try { const r = await api(op, body); if (r.state) state = r.state; if (ok) toast(typeof ok === "function" ? ok(r) : ok); render(); return r; }
    catch (e) { toast(e.message, true); }
    finally { busy.delete(key); }
  };
  const sw = (id, on, extra = "") => `<label class="sw"><input type="checkbox" ${id} ${on ? "checked" : ""} ${extra}><span></span></label>`;

  // headers editor: rows of [name, value]
  const headersHTML = (rows, idp) => `<div id="${idp}">${(rows || []).map(([k, v]) =>
      `<div class="hrow"><input type="text" value="${esc(k)}" placeholder="Header"><input type="text" value="${esc(v)}" placeholder="Value"><button class="b d" data-hdel>✕</button></div>`).join("")}</div>
    <button class="b" data-hadd="${idp}">+ Add header</button>`;
  const wireHeaders = (scope) => {
    scope.querySelectorAll("[data-hdel]").forEach((b) => (b.onclick = () => b.parentElement.remove()));
    scope.querySelectorAll("[data-hadd]").forEach((b) => (b.onclick = () => {
      const box = root.getElementById(b.dataset.hadd);
      const d = document.createElement("div"); d.className = "hrow";
      d.innerHTML = `<input type="text" placeholder="Header"><input type="text" placeholder="Value"><button class="b d" data-hdel>✕</button>`;
      box.appendChild(d); d.querySelector("[data-hdel]").onclick = () => d.remove(); d.querySelector("input").focus();
    }));
  };
  const readHeaders = (idp) => [...root.getElementById(idp).querySelectorAll(".hrow")]
    .map((r) => [...r.querySelectorAll("input")].map((i) => i.value)).filter(([k]) => k.trim());
  const jsonCheck = (ta, out) => { try { JSON.parse(ta.value); out.textContent = "✓ valid JSON"; return true; } catch (x) { out.textContent = ta.value.trim() ? "⚠ not JSON: " + x.message : ""; return !ta.value.trim(); } };

  const flowCache = { at: 0, byId: new Map(), pending: null };
  async function refreshFlows() {
    if (!flowCache.pending) flowCache.pending = fetch("./flows", { credentials: "same-origin" })
      .then((r) => r.json()).then((all) => {
        flowCache.byId = new Map(all.map((f) => [f.id, f])); flowCache.at = Date.now();
      }).finally(() => { flowCache.pending = null; });
    await flowCache.pending;
  }
  async function flowsById(id) {
    try {
      const fresh = Date.now() - flowCache.at < 800;
      if (fresh && flowCache.byId.has(id)) return flowCache.byId.get(id);
      await refreshFlows();
      return flowCache.byId.get(id) || null;
    }
    catch (e) { return null; }
  }
  async function builtinContent(id, side, views) {
    for (const view of views) {
      try {
        const r = await fetch(`./flows/${id}/${side}/content/${encodeURIComponent(view)}.json`, { credentials:"same-origin" });
        if (r.ok) return await r.json();
      } catch (e) { /* use the panel-side schema-less fallback */ }
    }
    return null;
  }

  let renderSeq = 0;
  async function render() {
    const seq = ++renderSeq;
    if (!state) state = await api("state").catch(() => null);
    if (seq !== renderSeq) return;
    if (!state) { $("main").innerHTML = '<p class="muted">Cannot reach the panel API.</p>'; return; }
    badges();
    root.querySelectorAll("nav button").forEach((b) => b.classList.toggle("on", b.dataset.t === tab));
    const m = $("main");
    if (editing) return editing.kind === "script" ? renderScriptEditor(m) : renderEditor(m);
    if (tab === "call") return renderCall(m, seq);
    if (tab === "compose") return renderCompose(m);
    if (tab === "map") return renderMap(m);
    if (tab === "bp") return renderBp(m);
    if (tab === "net") return renderNet(m);
    if (tab === "coll") return renderColl(m);
    if (tab === "cmp") return renderCmp(m, seq);
    if (tab === "sess") return renderSess(m);
    if (tab === "scripts") return renderScripts(m);
    return renderRules(m);
  }
  function badges() {
    const maps = state.rules.filter((r) => r.action === "map_local");
    const on = (xs) => xs.filter((x) => x.enabled !== false).length;
    $("c-map").textContent = on(maps) || ""; $("c-bp").textContent = on(state.breakpoints) || "";
    const skipped = state.skipped_rules || [];
    $("c-rules").textContent = skipped.length ? `⚠ ${skipped.length}` : (on(state.rules) || "");
    $("c-rules").classList.toggle("err", skipped.length > 0);
    const cl = state.collections || { items: [] };
    $("c-coll").textContent = cl.recording ? "● REC" : (cl.items.filter((x) => x.replay).length || "");
    const scriptErrors = Object.keys((state.script_status || {}).errors || {}).length;
    $("c-scripts").textContent = scriptErrors ? `⚠ ${scriptErrors}` : (on(state.scripts || []) || "");
    $("c-scripts").classList.toggle("err", scriptErrors > 0);
    const active = on(state.rules) || on(state.breakpoints) || state.throttle !== "off";
    $("fabdot").style.display = active ? "inline-block" : "none";
    $("fab").classList.toggle("paused", state.paused.length > 0);
    const label = state.project.label || state.view_project;
    const product = state.product.name || "Proxy";
    $("ptitle").textContent = `${product} · ${label}`;
    const options = state.projects.map((p) => `<option value="${esc(p.id)}" ${p.id === state.view_project ? "selected" : ""}>${esc(p.label || p.id)}</option>`).join("");
    if ($("project").innerHTML !== options) $("project").innerHTML = options;
    $("fab").firstChild.textContent = state.paused.length ? `${label} · ${state.paused.length} paused` : label;
  }

  // ───────────── This call ─────────────
  async function renderCall(m, seq) {
    const id = selectedFlow();
    const f = id ? await flowsById(id) : null;
    if (seq !== renderSeq) return;
    if (f && f.type === "tcp") {       // a host that is not decrypted: only the tunnel is visible
      const conn = f.server_conn || {}, hostName = conn.sni || (f.client_conn || {}).sni || (conn.address || [""])[0] || "", portNo = (conn.address || [])[1];
      m.innerHTML = `<div class="call"><span class="m">TUNNEL</span>${esc(hostName)}${portNo ? ":" + esc(portNo) : ""}
          <div class="sub">🔒 not decrypted — host only, no URL, headers or body</div></div>
        ${tlsQuickHTML(hostName)}`;
      wireTlsQuick(f.id, hostName);
      return;
    }
    if (!f || f.type !== "http") {
      m.innerHTML = '<p class="muted">Select a call in the list to Map Local it, set a breakpoint, force an error, block or delay it.</p>';
      return;
    }
    const r = f.request, s = f.response;
    const bpFor = state.breakpoints.find((b) => b.label === r.pretty_host + r.path.split("?")[0] && b.method === r.method);
    let viewer = null;
    try { viewer = await api("viewer", { flow_id: f.id }); } catch (e) { /* call tools still work */ }
    if (viewer && viewer.grpc) {
      const views = viewer.grpc.content_type === "protobuf" ? ["Protocol Buffer", "gRPC/Protocol Buffer"] : ["gRPC/Protocol Buffer", "Protocol Buffer"];
      const decoded = await Promise.all([builtinContent(f.id, "request", views), s ? builtinContent(f.id, "response", views) : null]);
      viewer.grpc.builtin_request = decoded[0]; viewer.grpc.builtin_response = decoded[1];
    }
    if (seq !== renderSeq) return;
    m.innerHTML = `
      <div class="call"><span class="m">${esc(r.method)}</span>${esc(r.scheme + "://" + r.pretty_host + r.path)}
        <div class="sub">${s ? "→ " + s.status_code : "no response yet"}</div></div>
      <h4>Map Local</h4>
      <div class="sub">Save this response and serve it instead of the server. Edit body, status and headers.</div>
      <div class="btns"><button class="b p" id="mock" ${s ? "" : "disabled"}>Map Local this call…</button></div>
      <h4>Breakpoint</h4>
      <div class="btns">
        <span class="chip ${bpFor && bpFor.request ? "on" : ""}" data-ph="request">Request</span>
        <span class="chip ${bpFor && bpFor.response ? "on" : ""}" data-ph="response">Response</span>
        <span class="sub">${bpFor ? "breakpoint ON for this endpoint" : "click to pause this endpoint"}</span></div>
      <h4>Request</h4>
      <div class="btns"><button class="b" id="retry">Edit &amp; Retry…</button>
        <button class="b" id="curl">Copy cURL</button><button class="b" id="curlurl">Copy URL</button>
        <button class="b" id="cmpA">Compare: set as A</button></div>
      <div class="btns"><button class="b" id="compose">Compose from this call</button></div>
      <h4>Copy as</h4>${copyAsHTML("ca")}
      <div class="btns">${state.focus_host === r.pretty_host
          ? `<button class="b p" id="focus">Showing only ${esc(r.pretty_host)} — show all</button>`
          : `<button class="b" id="focus">Show only ${esc(r.pretty_host)}</button>`}</div>
      <h4>Quick errors</h4>
      <div class="btns">
        <select id="code">${[500, 503, 504, 401, 403, 404, 400, 429].map((c) => `<option>${c}</option>`).join("")}</select>
        <button class="b" id="force">Force status</button>
        <button class="b" id="block">Block (network error)</button></div>
      <div class="btns"><input type="number" id="ms" value="8000" step="1000" style="width:90px"> ms
        <button class="b" id="delay">Delay this call</button></div>
      <p class="sub">These apply to every future call to this endpoint (same method + path, any query) until you turn them off.</p>
      ${tlsQuickHTML(r.pretty_host)}
      ${viewerHTML(viewer)}${viewerListsHTML()}`;
    $("mock").onclick = async () => {
      const res = await run("mock", { flow_id: f.id }, (x) => (x.existing ? "Opened existing mock '" : "Map Local '") + x.name + "' is ON");
      if (res) openEditor(res.name);
    };
    root.querySelectorAll("[data-ph]").forEach((c) => (c.onclick = () => {
      const want = { request: !!(bpFor && bpFor.request), response: !!(bpFor && bpFor.response) };
      want[c.dataset.ph] = !want[c.dataset.ph];
      if (!want.request && !want.response) return bpFor && run("bp_delete", { name: bpFor.name }, "Breakpoint removed");
      run("bp_add", { flow_id: f.id, ...want }, "Breakpoint ON — matching calls will pause");
    }));
    $("retry").onclick = () => openRetry(f.id);
    $("compose").onclick = async () => {
      const res = await run("compose_get", { flow_id: f.id });
      if (!res) return;
      loadDraft(res.spec, ""); tab = "compose"; render();
    };
    wireCopyAs("ca", () => ({ flow_id: f.id }));
    wireTlsQuick(f.id, r.pretty_host);
    $("curl").onclick = () => copyExport(f.id, "curl");
    $("curlurl").onclick = () => copyExport(f.id, "url");
    $("cmpA").onclick = () => { cmpA = { id: f.id, label: r.method + " " + r.pretty_host + r.path }; tab = "cmp"; toast("Now select another call — Compare tab"); render(); };
    $("focus").onclick = () => run("focus_host", { host: state.focus_host === r.pretty_host ? null : r.pretty_host }, state.focus_host === r.pretty_host ? "Showing all hosts" : "Showing only " + r.pretty_host);
    $("force").onclick = () => run("quick", { flow_id: f.id, kind: "status", status: $("code").value }, (x) => "Rule '" + x.name + "' ON");
    $("block").onclick = () => run("quick", { flow_id: f.id, kind: "block" }, (x) => "Rule '" + x.name + "' ON");
    $("delay").onclick = () => run("quick", { flow_id: f.id, kind: "delay", ms: $("ms").value }, (x) => "Rule '" + x.name + "' ON");
    m.querySelectorAll("[data-copy-json]").forEach((b) => (b.onclick = () => navigator.clipboard.writeText(decodeURIComponent(b.dataset.copyJson)).then(() => toast("Copied decoded JSON"))));
    m.querySelectorAll("[data-gql]").forEach((b) => (b.onclick = () => run("graphql_filter", { name: b.dataset.gql === state.graphql_operation ? null : b.dataset.gql }, b.dataset.gql === state.graphql_operation ? "GraphQL filter cleared" : "Showing " + b.dataset.gql)));
  }

  function jpretty(value) { return esc(JSON.stringify(value, null, 2)); }
  function gqlPretty(query) {
    let out = "", indent = 0, string = false, escapeNext = false, space = false;
    const pad = () => "  ".repeat(indent);
    for (const ch of String(query || "")) {
      if (string) {
        out += ch;
        if (escapeNext) escapeNext = false; else if (ch === "\\") escapeNext = true; else if (ch === '"') string = false;
        continue;
      }
      if (ch === '"') { if (space && out && !out.endsWith("\n")) out += " "; space = false; string = true; out += ch; continue; }
      if (/\s/.test(ch)) { space = true; continue; }
      if (ch === "{") { out = out.trimEnd() + " {\n"; indent++; out += pad(); space = false; continue; }
      if (ch === "}") { indent = Math.max(0, indent - 1); out = out.trimEnd() + "\n" + pad() + "}"; space = true; continue; }
      if (space && out && !out.endsWith("\n") && !out.endsWith("(") && !",:)".includes(ch)) out += " ";
      out += ch; space = false;
    }
    return out.trim();
  }
  function viewerHTML(v) {
    if (!v) return "";
    let out = "";
    if (v.tokens && v.tokens.length) out += `<h4>JWT (${v.tokens.length})</h4>` + v.tokens.map((t) => {
      const times = Object.entries(t.times || {}).map(([k, x]) => `${k}: ${x.local}${x.relative ? " · " + x.relative : ""}`).join("<br>");
      return `<div class="call"><b>${esc(t.where)}</b> · alg ${esc(t.alg || "—")} · kid ${esc(t.kid || "—")}<div class="sub">signature not verified<br>${times}</div>
        <div class="btns"><button class="b" data-copy-json="${encodeURIComponent(JSON.stringify(t.header, null, 2))}">Copy header JSON</button><button class="b" data-copy-json="${encodeURIComponent(JSON.stringify(t.payload, null, 2))}">Copy payload JSON</button></div>
        <pre class="code">Header\n${jpretty(t.header)}\n\nPayload\n${jpretty(t.payload)}</pre></div>`;
    }).join("");
    if (v.graphql && v.graphql.length) out += `<h4>GraphQL</h4>` + v.graphql.map((g) => `<div class="call"><b>${esc(g.type)} ${esc(g.name)}</b><pre class="code">${esc(gqlPretty(g.query))}</pre><b>Variables</b><pre class="code">${jpretty(g.variables)}</pre></div>`).join("") +
      (v.graphql_response ? `<b>Response data</b><pre class="code">${jpretty(v.graphql_response.data)}</pre>${v.graphql_response.errors && v.graphql_response.errors.length ? `<div class="errbox"><b>ERR · GraphQL errors (HTTP status may still be 200)</b><pre class="code">${jpretty(v.graphql_response.errors)}</pre></div>` : ""}` : "");
    if (v.grpc) {
      const content = (builtin, fallback) => {
        if (!builtin) return jpretty(fallback);
        if (Array.isArray(builtin)) return esc(builtin.map((x) => x.text || JSON.stringify(x, null, 2)).join("\n\n"));
        return esc(typeof builtin.text === "string" ? builtin.text : JSON.stringify(builtin.text ?? builtin, null, 2));
      };
      out += `<h4>gRPC / protobuf</h4><div class="call"><b>${esc(v.grpc.service)}/${esc(v.grpc.method)}</b><div class="sub">grpc-status ${esc(v.grpc.status ?? "—")} · ${esc(v.grpc.message || "")}<br>${v.grpc.builtin_request || v.grpc.builtin_response ? "mitmproxy built-in content view" : esc(v.grpc.decoder + " · built-in view unavailable, using fallback")}</div><b>Request</b><pre class="code">${content(v.grpc.builtin_request, v.grpc.request || {error:v.grpc.request_error})}</pre><b>Response</b><pre class="code">${content(v.grpc.builtin_response, v.grpc.response || {error:v.grpc.response_error})}</pre></div>`;
    }
    return out;
  }
  function viewerListsHTML() {
    const v = viewers;
    let out = `<h4>Tokens seen this session (${v.tokens.length})</h4>` + (v.tokens.length ? v.tokens.map((t) => `<div class="row"><div class="n"><div><b>${esc(t.sub || "(no sub)")}</b> <span class="tag">${esc(t.alg || "JWT")}</span></div><div class="sub">iat ${esc(t.iat ?? "—")} · first: ${esc(t.method)} ${esc(t.url)}</div></div></div>`).join("") : '<p class="muted">No JWTs seen.</p>');
    out += `<h4>GraphQL ops</h4>` + (v.graphql_ops.length ? v.graphql_ops.map((g) => `<button class="chip ${state.graphql_operation === g.name ? "on" : ""}" data-gql="${esc(g.name)}">${esc(g.name)} · ${g.count}${g.errors ? " · ERR " + g.errors : ""}</button>`).join(" ") : '<p class="muted">No GraphQL operations seen.</p>');
    return out;
  }

  // ───────────── Map Local manager ─────────────
  function renderMap(m) {
    const maps = state.rules.map((r, i) => [r, i]).filter(([r]) => r.action === "map_local");
    m.innerHTML = `
      <h4>New Map Local rule</h4>
      <div class="btns" style="margin-top:0"><input type="text" id="mh" class="grow" placeholder="Host (or paste a full URL)">
        <input type="text" id="mp" class="grow" placeholder="Path" value="/"></div>
      <div class="btns"><select id="mm"><option value="">ANY</option>${["GET", "POST", "PUT", "PATCH", "DELETE"].map((x) => `<option>${x}</option>`).join("")}</select>
        status <input type="number" id="ms2" value="200" style="width:70px">
        <button class="b p" id="madd">Add rule</button></div>
      <div class="sub">Wildcards: * and ? in host or path. Faster: select a call and use “Map Local this call”.</div>
      <h4>Rules (${maps.length})</h4>
      ${maps.length ? maps.map(([r, i]) => `
        <div class="row">${sw(`data-i="${i}"`, r.enabled !== false)}
          <div class="n"><div><b>${esc(pretty(r))}</b></div>
            <div class="sub">${esc(r.method || "ANY")} · status ${esc(r.status || 200)} · ${esc(r.name)}</div></div>
          <button class="b" data-edit="${i}">Edit</button><button class="b d" data-del="${i}" title="Delete">✕</button></div>`).join("")
      : '<p class="muted">No Map Local rules yet.</p>'}`;
    const split = () => { const v = $("mh").value.trim(); if (/^https?:\/\//.test(v)) { const [h, p] = hostPath(v); $("mh").value = h; $("mp").value = p; } };
    $("mh").onchange = split;
    $("madd").onclick = async () => {
      split();
      const res = await run("maplocal_add", { host: $("mh").value, path: $("mp").value, method: $("mm").value, status: $("ms2").value }, (x) => "Map Local '" + x.name + "' added");
      if (res) openEditor(res.name);
    };
    wireRuleRows(m);
  }

  // ───────────── Breakpoints manager ─────────────
  function renderBp(m) {
    const bps = state.breakpoints;
    m.innerHTML = `
      ${state.paused.length ? `<div class="call" style="background:#fff7ed">⏸ ${state.paused.length} call(s) paused <button class="b warn" id="showp">Open</button></div>` : ""}
      <h4>New breakpoint</h4>
      <div class="btns" style="margin-top:0"><input type="text" id="bh" class="grow" placeholder="Host (or paste a full URL)">
        <input type="text" id="bpth" class="grow" placeholder="Path" value="/*"></div>
      <div class="btns"><select id="bm"><option value="">ANY</option>${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((x) => `<option>${x}</option>`).join("")}</select>
        <span class="chip on" data-nph="request">Request</span><span class="chip on" data-nph="response">Response</span>
        <button class="b" id="bsel">Use selected call</button><button class="b p" id="badd">Add breakpoint</button></div>
      <div class="sub">Request = pause before it reaches the server · Response = pause before the app gets it.</div>
      <h4>Breakpoints (${bps.length})</h4>
      ${bps.length ? bps.map((b, i) => `
        <div class="row">${sw(`data-bi="${i}"`, b.enabled !== false)}
          <div class="n"><div><b>${esc(pretty(b))}</b></div><div class="sub">${esc(b.method || "Any HTTP method")}</div></div>
          <span class="chip ${b.request ? "on" : ""}" data-bph="${i}:request">Req</span>
          <span class="chip ${b.response ? "on" : ""}" data-bph="${i}:response">Resp</span>
          <button class="b d" data-bdel="${i}">✕</button></div>`).join("")
      : '<p class="muted">No breakpoints.</p>'}`;
    root.querySelectorAll("[data-nph]").forEach((c) => (c.onclick = () => c.classList.toggle("on")));
    const ph = (p) => root.querySelector(`[data-nph=${p}]`).classList.contains("on");
    const split = () => { const v = $("bh").value.trim(); if (/^https?:\/\//.test(v)) { const [h, p] = hostPath(v); $("bh").value = h; $("bpth").value = p; } };
    $("bh").onchange = split;
    $("bsel").onclick = async () => {
      const f = selectedFlow() && await flowsById(selectedFlow());
      if (!f) return toast("Select a call in the list first", true);
      $("bh").value = f.request.pretty_host; $("bpth").value = f.request.path.split("?")[0]; $("bm").value = f.request.method;
    };
    $("badd").onclick = () => { split(); run("bp_add", { host: $("bh").value, path: $("bpth").value, method: $("bm").value, request: ph("request"), response: ph("response") }, (x) => "Breakpoint '" + x.name + "' ON"); };
    root.querySelectorAll("[data-bi]").forEach((c) => (c.onchange = () => run("bp_update", { name: bps[c.dataset.bi].name, enabled: c.checked }, c.checked ? "ON" : "off")));
    root.querySelectorAll("[data-bph]").forEach((c) => (c.onclick = () => {
      const [i, p] = c.dataset.bph.split(":"); const b = bps[i];
      const next = { request: b.request, response: b.response }; next[p] = !next[p];
      if (!next.request && !next.response) return toast("Keep Request or Response on — or delete the breakpoint", true);
      run("bp_update", { name: b.name, ...next });
    }));
    root.querySelectorAll("[data-bdel]").forEach((b) => (b.onclick = () => run("bp_delete", { name: bps[b.dataset.bdel].name }, "Breakpoint removed")));
    $("showp") && ($("showp").onclick = () => { dismissed.clear(); openPaused(state.paused[0].id); });
  }

  // ───────────── Network: traffic profiles ─────────────
  function renderNet(m) {
    const icons = { off: "∿", "3g-urban": "📶", "lte-congested": "📉", "high-latency-vpn": "🔒", "packet-loss-8": "⚠", manual: "⚙" };
    const desc = (p) => p.desc || `${p.latency_ms}ms ±${p.jitter_ms}ms latency · ↓${p.down_kbps}kbps / ↑${p.up_kbps}kbps · ${p.loss_pct}% packet loss`;
    const cur = state.throttle || "off";
    const known = state.profiles.some((p) => p.id === cur);
    const mn = state.manual;
    m.innerHTML = `
      <h4>Traffic profiles</h4>
      <div class="sub" style="margin-bottom:8px">Simulate degraded networks on the proxy. Applies to calls matching
        <input type="text" id="tm" value="${esc(state.throttle_match)}" style="width:150px" placeholder="all calls"></div>
      ${state.profiles.map((p) => `
        <div class="card ${p.id === cur ? "on" : ""}" data-prof="${p.id}"><div class="ic">${icons[p.id] || "•"}</div>
          <div><div class="t">${esc(p.name)}</div><div class="sub">${esc(desc(p))}</div></div>${p.id === cur ? '<div class="ok">✓</div>' : ""}</div>`).join("")}
      ${!known ? `<div class="sub">Current: ${esc(cur)} (set from the command line)</div>` : ""}
      <div id="manual" style="${cur === "manual" ? "" : "display:none"}">
        <div class="grid">
          <label>Latency ms<input type="number" data-mk="latency_ms" value="${esc(mn.latency_ms)}"></label>
          <label>Jitter ms<input type="number" data-mk="jitter_ms" value="${esc(mn.jitter_ms)}"></label>
          <label>Download kbps (0 = unlimited)<input type="number" data-mk="down_kbps" value="${esc(mn.down_kbps)}"></label>
          <label>Upload kbps (0 = unlimited)<input type="number" data-mk="up_kbps" value="${esc(mn.up_kbps)}"></label>
          <label>Packet loss %<input type="number" step="0.5" data-mk="loss_pct" value="${esc(mn.loss_pct)}"></label>
          <label>Extra response delay ms<input type="number" data-mk="response_delay_ms" value="${esc(mn.response_delay_ms)}"></label>
        </div>
        <div class="btns"><button class="b p" id="mapply">Apply manual profile</button></div>
      </div>
      ${tlsSectionHTML()}
      <h4>List view</h4>
      <div class="row">${sw('id="project-filter"', state.project_only)}<div class="n">Only ${esc(state.project.label)} calls <div class="sub">uses this profile's hosts regex</div></div></div>
      <div class="sub">View profile: ${esc(state.project.label)}. Switching here changes only the list view; restart with <code>--project ${esc(state.view_project)}</code> to load that project's rules.</div>
      <div class="row">${sw('id="dns"', state.show_dns)}<div class="n">Show DNS / UDP rows <div class="sub">off = HTTP(S) requests only</div></div></div>
      <div class="row">${sw('id="sty"', styleOn())}<div class="n">Proxyman-style list <div class="sub">compact rows, coloured methods and status codes (this browser only)</div></div></div>`;
    wireTlsSection();
    root.querySelectorAll("[data-prof]").forEach((c) => (c.onclick = () => {
      if (c.dataset.prof === "manual") { $("manual").style.display = ""; root.querySelectorAll("[data-prof]").forEach((x) => x.classList.toggle("on", x === c)); return; }
      run("profile", { id: c.dataset.prof, match: $("tm").value }, "Network: " + c.querySelector(".t").textContent);
    }));
    $("mapply").onclick = () => {
      const manual = {}; root.querySelectorAll("[data-mk]").forEach((i) => (manual[i.dataset.mk] = Number(i.value || 0)));
      run("profile", { id: "manual", manual, match: $("tm").value }, "Network: manual profile");
    };
    $("tm").onchange = () => run("profile", { id: cur, match: $("tm").value }, "Applies to: " + ($("tm").value || "all calls"));
    $("project-filter").onchange = () => run("view", { project: state.view_project, project_only: $("project-filter").checked, show_dns: false }, "List updated");
    $("dns").onchange = () => run("view", { project_only: false, show_dns: $("dns").checked }, "List updated");
    $("sty").onchange = () => { setStyle($("sty").checked); toast($("sty").checked ? "Proxyman-style list ON" : "Original mitmweb look"); };
  }

  // ───────────── Copy URL / cURL ─────────────
  async function copyExport(id, fmt) {
    const mask = maskOn();
    const r = await run("export", { flow_id: id, fmt, mask });
    if (!r) return;
    try { await navigator.clipboard.writeText(r.text); toast(fmt === "url" ? "URL copied" : "cURL copied" + (mask ? " (secrets masked)" : " — contains secrets!")); }
    catch (e) { prompt("Copy:", r.text); }
  }

  // ───────────── Collections (record → replay) ─────────────
  let collOpen = null, collEntries = null;
  function renderColl(m) {
    const c = state.collections;
    m.innerHTML = `
      <h4>Record</h4>
      ${c.recording
        ? `<div class="call"><span class="rec">● Recording</span> into <b>${esc(c.recording)}</b> — use the app now; every matching call is saved with its real response.
             <div class="btns"><button class="b warn" id="cstop">Stop recording</button></div></div>`
        : `<div class="btns" style="margin-top:0"><input type="text" id="cname" class="grow" placeholder="Collection name, e.g. cards-journey-sit">
             <button class="b p" id="crec">Start recording</button></div>
           <div class="btns">Record calls matching <input type="text" id="cmatch" class="grow" value="${esc(c.record_match)}"></div>`}
      <h4>Replay</h4>
      <div class="row">${sw('id="cstrict"', c.strict)}<div class="n">Strict replay <div class="sub">matching calls not in an enabled collection get 404 instead of reaching the server</div></div></div>
      <h4>Collections (${c.items.length})</h4>
      ${c.items.length ? c.items.map((x, i) => `
        <div class="row">${sw(`data-ci="${i}"`, x.replay, c.recording === x.name ? "disabled" : "")}
          <div class="n"><div><b>${esc(x.name)}</b>${c.recording === x.name ? ' <span class="rec">● REC</span>' : ""}</div>
            <div class="sub">${x.count} calls${x.created ? " · " + new Date(x.created * 1000).toLocaleString() : ""}${x.replay ? " · replaying" : ""}</div></div>
          <button class="b" data-cview="${i}">${collOpen === x.name ? "Hide" : "Calls"}</button>
          <button class="b" data-cexp="${i}">HAR</button><button class="b d" data-cdel="${i}">✕</button></div>
        ${collOpen === x.name ? `<div id="centries" class="sub">loading…</div>` : ""}`).join("")
      : '<p class="muted">No collections yet. Record a journey, then switch it on to replay it as mocks.</p>'}
      <h4>Import</h4>
      <div class="btns" style="margin-top:0"><input type="file" id="chf" accept=".har,application/json" style="font-size:11px">
        <input type="text" id="chn" placeholder="name" style="width:120px"><button class="b" id="cimp">Import HAR</button></div>
      <p class="sub">Collections stay in ${esc(state.project_state)}/collections. No Git sync — recordings must not leave the workstation.</p>`;
    $("crec") && ($("crec").onclick = () => run("coll_record", { name: $("cname").value, record_match: $("cmatch").value }, "Recording into " + $("cname").value));
    $("cstop") && ($("cstop").onclick = () => run("coll_stop", {}, "Recording stopped"));
    $("cstrict").onchange = () => run("coll_strict", { strict: $("cstrict").checked }, $("cstrict").checked ? "Strict replay ON" : "Strict replay off");
    m.querySelectorAll("[data-ci]").forEach((cb) => (cb.onchange = () => run("coll_replay", { name: c.items[cb.dataset.ci].name, enabled: cb.checked }, cb.checked ? "Replaying " + c.items[cb.dataset.ci].name : "Replay off")));
    m.querySelectorAll("[data-cdel]").forEach((b) => (b.onclick = () => { const n = c.items[b.dataset.cdel].name; if (confirm("Delete collection '" + n + "'?")) run("coll_delete", { name: n }, "Deleted " + n); }));
    m.querySelectorAll("[data-cexp]").forEach((b) => (b.onclick = async () => {
      const r = await run("coll_export", { name: c.items[b.dataset.cexp].name });
      if (!r) return;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(r.har, null, 2)], { type: "application/json" }));
      a.download = r.filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }));
    m.querySelectorAll("[data-cview]").forEach((b) => (b.onclick = () => { const n = c.items[b.dataset.cview].name; collOpen = collOpen === n ? null : n; render(); }));
    $("cimp").onclick = async () => {
      const file = $("chf").files[0];
      if (!file) return toast("Choose a .har file first", true);
      let har; try { har = JSON.parse(await file.text()); } catch (e) { return toast("Not a valid HAR (JSON) file", true); }
      const name = $("chn").value.trim() || file.name.replace(/\.har$|\.json$/i, "").replace(/[^A-Za-z0-9._-]/g, "-");
      run("coll_import", { name, har }, (x) => "Imported " + x.count + " calls into " + name);
    };
    if (collOpen) api("coll_entries", { name: collOpen }).then((r) => {
      const box = $("centries"); if (!box) return;
      box.innerHTML = r.entries.length ? r.entries.map((e) => `<div class="row" style="padding:4px 0"><div class="n"><div>${esc(e.method)} ${esc(e.host)}${esc(e.path)}${e.query ? "?" + esc(e.query) : ""}</div></div>
        <span class="tag">${esc(e.status)}</span><button class="b d" data-edel="${e.i}">✕</button></div>`).join("") : "empty";
      box.querySelectorAll("[data-edel]").forEach((b) => (b.onclick = () => run("coll_entry_delete", { name: collOpen, i: b.dataset.edel }, "Removed")));
    }).catch((e) => toast(e.message, true));
  }

  // ───────────── Compare two calls ─────────────
  let cmpA = null, cmpResult = null;
  async function renderCmp(m, seq) {
    const id = selectedFlow();
    const f = id ? await flowsById(id) : null;
    if (seq !== renderSeq) return;
    const lab = (x) => x ? `${esc(x.method)} ${esc(x.url || x.label)}${x.status ? " → " + x.status : ""}` : "";
    m.innerHTML = `
      <h4>A</h4><div class="call">${cmpA ? esc(cmpA.label) : '<span class="muted">not set — select a call and press “Set selected as A”</span>'}</div>
      <div class="btns"><button class="b" id="seta" ${f ? "" : "disabled"}>Set selected as A</button>
        <button class="b p" id="docmp" ${cmpA && f && f.id !== cmpA.id ? "" : "disabled"}>Compare A with selected</button></div>
      <div class="sub">${f ? "Selected: " + esc(f.request.method + " " + f.request.pretty_host + f.request.path) : "Select a call in the list."}</div>
      <div id="cmpout"></div>`;
    $("seta").onclick = () => { cmpA = { id: f.id, label: f.request.method + " " + f.request.pretty_host + f.request.path }; cmpResult = null; render(); };
    $("docmp").onclick = async () => { const r = await run("diff", { a: cmpA.id, b: f.id }); if (r) { cmpResult = r; drawCmp(); } };
    if (cmpResult) drawCmp();
    function drawCmp() {
      const r = cmpResult, out = $("cmpout"); if (!out) return;
      const tbl = (rows, kind) => rows.length ? `<table class="diff"><tr><th style="width:34%">${kind === "text" ? "" : "field"}</th><th>A</th><th>B</th></tr>${rows.map(([k, a, b]) =>
          kind === "text" ? `<tr><td class="k">${k === "-" ? "only A" : "only B"}</td><td class="${k === "-" ? "a" : ""}">${k === "-" ? esc(a) : ""}</td><td class="${k === "+" ? "b" : ""}">${k === "+" ? esc(a) : ""}</td></tr>`
                          : `<tr><td class="k">${esc(k)}</td><td class="a">${esc(a)}</td><td class="b">${esc(b)}</td></tr>`).join("")}</table>`
        : '<div class="sub">identical</div>';
      out.innerHTML = `
        <h4>Summary</h4><table class="diff"><tr><td class="k">A</td><td colspan="2">${lab(r.a)}</td></tr><tr><td class="k">B</td><td colspan="2">${lab(r.b)}</td></tr></table>
        <h4>Response body (${r.resp_body.rows.length} differences)</h4>${tbl(r.resp_body.rows, r.resp_body.kind)}
        <h4>Response headers</h4>${tbl(r.resp_headers)}
        <h4>Request body</h4>${tbl(r.req_body.rows, r.req_body.kind)}
        <h4>Request headers</h4>${tbl(r.req_headers)}`;
    }
  }

  // ───────────── Sessions: save / reload whole captures ─────────────
  function renderSess(m) {
    const ss = state.sessions || [];
    m.innerHTML = `
      <h4>Save the current capture</h4>
      <div class="btns" style="margin-top:0"><input type="text" id="sn" class="grow" placeholder="Session name, e.g. ticket-1234-repro"></div>
      <div class="btns"><input type="text" id="snote" class="grow" placeholder="Note (optional): what this capture shows"></div>
      <div class="btns"><label class="sub"><input type="checkbox" id="svis"> only calls visible with the current filter</label>
        <button class="b p" id="ssave">Save session</button></div>
      <h4>Saved sessions (${ss.length})</h4>
      ${ss.length ? ss.map((x, i) => `
        <div class="row" style="align-items:flex-start"><div class="n"><div><b>${esc(x.name)}</b></div>
            <div class="sub">${x.count} calls · ${new Date(x.created * 1000).toLocaleString()}${x.hosts && x.hosts.length ? " · " + esc(x.hosts.slice(0, 3).join(", ")) : ""}</div>
            <div class="sub" data-note="${i}" title="click to edit" style="cursor:text;white-space:normal">${x.note ? "📝 " + esc(x.note) : "<i>add a note…</i>"}</div></div>
          <button class="b" data-sload="${i}">Open</button><button class="b" data-shar="${i}">HAR</button><button class="b d" data-sdel="${i}">✕</button></div>`).join("")
      : '<p class="muted">No saved sessions yet.</p>'}
      <p class="sub">Open adds the saved calls to the list (choose “replace” to clear it first). Sessions stay in ${esc(state.project_state)}/sessions.
        Per-call notes and bookmarks: use mitmweb’s <b>Comment</b> tab and <b>Mark</b> button — they are saved with the session.</p>`;
    $("ssave").onclick = () => run("sess_save", { name: $("sn").value.trim(), note: $("snote").value, visible_only: $("svis").checked }, (x) => "Saved " + x.count + " calls");
    m.querySelectorAll("[data-sload]").forEach((b) => (b.onclick = () => {
      const x = ss[b.dataset.sload];
      const replace = confirm("Open '" + x.name + "'.\n\nOK = replace the current list\nCancel = add to the current list");
      run("sess_load", { name: x.name, replace }, (r) => "Opened " + r.count + " calls");
    }));
    m.querySelectorAll("[data-sdel]").forEach((b) => (b.onclick = () => { const x = ss[b.dataset.sdel]; if (confirm("Delete session '" + x.name + "'?")) run("sess_delete", { name: x.name }, "Deleted"); }));
    m.querySelectorAll("[data-note]").forEach((d) => (d.onclick = () => {
      const x = ss[d.dataset.note]; const note = prompt("Note for " + x.name, x.note || "");
      if (note !== null) run("sess_note", { name: x.name, note }, "Note saved");
    }));
    m.querySelectorAll("[data-shar]").forEach((b) => (b.onclick = async () => {
      const r = await run("sess_har", { name: ss[b.dataset.shar].name });
      if (!r) return;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(r.har, null, 2)], { type: "application/json" }));
      a.download = r.filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }));
  }

  // ───────────── Per-project scripts ─────────────
  function renderScripts(m) {
    const scripts = state.scripts || [], status = state.script_status || {};
    const errorHTML = (error) => error ? `<br><span class="tag" style="background:#fee2e2;color:#b91c1c">ERROR</span>
      <span style="color:#b91c1c">${esc(error.message || error)}${error.time ? " · " + esc(error.time) : ""}</span>
      ${error.traceback ? `<pre class="code" style="color:#b91c1c">${esc(error.traceback)}</pre>` : ""}` : "";
    m.innerHTML = `${status.node_message ? `<div class="errbox">${esc(status.node_message)}. Python scripts still work.</div>` : ""}
      <h4>New script</h4>
      <div class="btns" style="margin-top:0"><input id="sn" type="text" class="grow" placeholder="name">
        <select id="sl"><option value="js">JavaScript</option><option value="py">Python</option></select></div>
      <div class="btns"><select id="stpl"><option value="header">Request header</option><option value="json">JSON response field</option><option value="mock">Local mock</option><option value="latency">Endpoint latency</option><option value="token">Log token refresh</option></select>
        <input id="smatch" type="text" class="grow" value="." placeholder="URL regex"><select id="smethod"><option value="">ANY</option>${["GET","POST","PUT","PATCH","DELETE"].map((x) => `<option>${x}</option>`).join("")}</select>
        <button class="b p" id="snew">New</button></div>
      <p class="sub">Rules run first, then enabled scripts in filename order. Python and JavaScript are trusted user code and run with your user rights. The Node VM omits process, require and network helpers to prevent accidents, but it is NOT a security boundary.</p>
      <h4>Scripts (${scripts.length})</h4>${scripts.length ? scripts.map((s, i) => `<div class="row">${sw(`data-si="${i}"`, s.enabled !== false)}
        <div class="n"><div><b>${esc(s.name)}</b><span class="tag">${esc(s.lang)}</span></div><div class="sub">${esc(s.method || "ANY")} · ${esc(s.match || ".")} · ${esc(s.file)}${s.exists ? "" : " · FILE MISSING"}${errorHTML(status.errors && status.errors[s.file])}</div></div>
        <button class="b" data-sedit="${i}">Edit</button><button class="b d" data-sdelete="${i}">✕</button></div>`).join("") : '<p class="muted">No scripts yet.</p>'}`;
    $("snew").onclick = async () => {
      const r = await run("script_new", { name: $("sn").value, lang: $("sl").value, template: $("stpl").value, match: $("smatch").value, method: $("smethod").value }, (x) => "Created " + x.file);
      if (r) openScript(r.file);
    };
    m.querySelectorAll("input[data-si]").forEach((c) => (c.onchange = () => run("script_toggle", { file: scripts[c.dataset.si].file, enabled: c.checked }, c.checked ? "Script ON" : "Script off")));
    m.querySelectorAll("[data-sedit]").forEach((b) => (b.onclick = () => openScript(scripts[b.dataset.sedit].file)));
    m.querySelectorAll("[data-sdelete]").forEach((b) => (b.onclick = () => { const s = scripts[b.dataset.sdelete]; if (confirm("Delete script '" + s.name + "' and its source file?")) run("script_delete", { file: s.file }, "Deleted " + s.file); }));
  }

  async function openScript(file) {
    try { const r = await api("script_get", { file }); editing = { kind:"script", ...r }; render(); }
    catch (e) { toast(e.message, true); }
  }
  function renderScriptEditor(m) {
    const e = editing, s = e.script;
    m.innerHTML = `<div class="btns" style="margin-top:0"><button class="b" id="sback">← Back</button><b style="flex:1">${esc(s.file)}</b></div>
      <div class="btns"><input id="sematch" type="text" class="grow" value="${esc(s.match || ".")}" placeholder="URL regex"><select id="semethod"><option value="">ANY</option>${["GET","POST","PUT","PATCH","DELETE"].map((x) => `<option ${s.method === x ? "selected" : ""}>${x}</option>`).join("")}</select></div>
      <textarea id="sebody" spellcheck="false">${esc(e.content)}</textarea><div class="btns"><button class="b p" id="sesave">Save</button><span class="sub">${esc(e.file)}</span></div>`;
    $("sback").onclick = () => { editing = null; render(); };
    $("sesave").onclick = async () => {
      const r = await run("script_put", { file:s.file, match:$("sematch").value, method:$("semethod").value, content:$("sebody").value }, "Script saved — hot reloads within 1 s");
      if (r) { editing = null; tab = "scripts"; render(); }
    };
  }

  // ───────────── Proxyman-style list (restyles mitmweb's own table) ─────────────
  const STYLE_ID = "proxy-restyle";
  const migrateStyle = () => { try {
    if (localStorage.getItem(STYLE_ID) === null && localStorage.getItem("neo-restyle") !== null)
      localStorage.setItem(STYLE_ID, localStorage.getItem("neo-restyle"));
  } catch (e) { /* private window */ } };
  migrateStyle();
  const styleOn = () => { try { return localStorage.getItem(STYLE_ID) !== "off"; } catch (e) { return true; } };
  function setStyle(on) {
    try { localStorage.setItem("proxy-restyle", on ? "on" : "off"); } catch (e) { /* private window */ }
    let el = document.getElementById(STYLE_ID);
    if (!on) { el && el.remove(); return; }
    if (el) return;
    el = document.createElement("style"); el.id = STYLE_ID;
    el.textContent = `
      .flow-table table { font-size: 12.5px; }
      .flow-table tbody tr { height: 26px; }
      .flow-table tbody tr:nth-child(even) { background: rgba(0,0,0,.025); }
      .flow-table tbody tr:hover { background: rgba(15,118,110,.07); }
      .flow-table tbody tr.selected, .flow-table tbody tr.selected:hover { background: #0f766e !important; color: #fff !important; }
      .flow-table tbody tr.selected td { color: #fff !important; }
      .flow-table td.col-path { font-family: ui-monospace, Menlo, monospace; font-size: 12px; }
      .flow-table td.col-method[data-m] { font-weight:700; font-size:11px; letter-spacing:.02em; }
      .flow-table td[data-m=GET] { color:#15803d; }
      .flow-table td[data-m=POST] { color:#1d4ed8; }
      .flow-table td[data-m=PUT], .flow-table td[data-m=PATCH] { color:#b45309; }
      .flow-table td[data-m=DELETE] { color:#b91c1c; }
      .flow-table td[data-m=OPTIONS], .flow-table td[data-m=HEAD], .flow-table td[data-m=CONNECT] { color:#6b7280; }
      .flow-table td.col-status[data-s] { font-weight:700; }
      .flow-table td.col-status[data-gql-error="1"]::after { content:" ERR"; color:#dc2626; font-size:9px; margin-left:3px; }
      .flow-table td[data-s="2"] { color:#15803d; }
      .flow-table td[data-s="3"] { color:#6b7280; }
      .flow-table td[data-s="4"] { color:#c2410c; }
      .flow-table td[data-s="5"] { color:#dc2626; }
      .flow-table tbody tr.intercepted td { background:#fff7ed !important; }
      .flow-table td.col-size, .flow-table td.col-time { color:#6b7280; font-variant-numeric: tabular-nums; }
      @media (prefers-color-scheme: dark) {
        .flow-table td[data-m=GET], .flow-table td[data-s="2"] { color:#4ade80; } .flow-table td[data-m=POST] { color:#93c5fd; }
        .flow-table td[data-m=PUT], .flow-table td[data-m=PATCH], .flow-table td[data-s="4"] { color:#fbbf24; }
        .flow-table td[data-m=DELETE], .flow-table td[data-s="5"] { color:#f87171; }
      }`;
    document.head.appendChild(el);
  }
  // tag method / status cells so the CSS above can colour them (CSS cannot read cell text).
  // Only data-* attributes on mitmweb's own <td>s — never touch their children, React owns those.
  function tagCells() {
    // host-only tunnel rows (not decrypted): attribute on the <tr> only, so React's children stay untouched
    // (the path cell of a TCP flow reads "client ↔ server"; reading the row itself stays right when mitmweb virtualizes the list)
    document.querySelectorAll(".flow-table tbody tr").forEach((tr) => {
      const cell = tr.querySelector("td.col-path");
      const tunnel = cell && cell.textContent.includes(" ↔ ") ? "1" : "0";
      if (tr.dataset.tunnel !== tunnel) tr.dataset.tunnel = tunnel;
    });
    if (!styleOn()) return;
    document.querySelectorAll(".flow-table td.col-method, .flow-table td.col-status").forEach((td) => {
      const t = td.textContent.trim();
      if (td.classList.contains("col-method")) { if (td.dataset.m !== t) td.dataset.m = t; }
      else { const v = /^\d/.test(t) ? t.charAt(0) : "x"; if (td.dataset.s !== v) td.dataset.s = v; }
    });
    const errors = new Set(viewers.graphql_error_ids || []);
    const ordered = [...flowCache.byId.keys()];
    document.querySelectorAll(".flow-table tbody tr").forEach((tr, index) => {
      const link = tr.querySelector('a[href*="#/flows/"]');
      const match = link && link.getAttribute("href").match(/#\/flows\/([^/]+)/);
      const flowId = match ? match[1] : (tr.dataset.flowId || tr.dataset.id || ordered[index]);
      const cell = tr.querySelector("td.col-status");
      if (cell) cell.dataset.gqlError = flowId && errors.has(flowId) ? "1" : "0";
    });
  }
  if (!document.getElementById("proxy-tunnel-style")) {
    const tunnelStyle = document.createElement("style"); tunnelStyle.id = "proxy-tunnel-style";
    tunnelStyle.textContent = `.flow-table tbody tr[data-tunnel="1"] td { opacity:.7; font-style:italic; }
      .flow-table tbody tr[data-tunnel="1"] td.col-path::after { content:" 🔒 not decrypted"; font-style:normal; font-size:10px; color:#b45309; }`;
    document.head.appendChild(tunnelStyle);
  }
  setStyle(styleOn());
  new MutationObserver(() => { clearTimeout(tagCells._t); tagCells._t = setTimeout(tagCells, 60); })
    .observe(document.body, { childList: true, subtree: true, characterData: true });

  // ───────────── Edit & Retry (request editor in the sheet) ─────────────
  async function openRetry(id) {
    let p;
    try { p = await api("retry_get", { flow_id: id }); } catch (e) { return toast(e.message, true); }
    $("sheet").innerHTML = `
      <header style="background:#f0fdfa;border-color:#99f6e4"><b>↻ Edit &amp; Retry</b><span class="sub">sends a copy; the original stays in the list</span></header>
      <main>
        <div class="btns" style="margin-top:0"><select id="rm">${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((x) => `<option ${x === p.method ? "selected" : ""}>${x}</option>`).join("")}</select>
          <input type="text" id="ru" class="grow" value="${esc(p.url)}"></div>
        <div class="seg"><button data-rsub="body" class="on">Body</button><button data-rsub="headers">Headers</button></div>
        <div id="rpb"><textarea id="rb" spellcheck="false" ${p.req_body_editable ? "" : "readonly"}>${esc(p.req_body)}</textarea></div>
        <div id="rph" style="display:none">${headersHTML(p.req_headers, "rhd")}</div>
      </main>
      <footer><button class="b" id="rcancel">Cancel</button><button class="b p" id="rsend">Send</button></footer>`;
    $("pause").classList.add("open");
    wireHeaders($("sheet"));
    root.querySelectorAll("[data-rsub]").forEach((b) => (b.onclick = () => {
      $("rpb").style.display = b.dataset.rsub === "body" ? "" : "none"; $("rph").style.display = b.dataset.rsub === "headers" ? "" : "none";
      root.querySelectorAll("[data-rsub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    $("rcancel").onclick = () => $("pause").classList.remove("open");
    $("rsend").onclick = async () => {
      const edits = { method: $("rm").value, url: $("ru").value, headers: readHeaders("rhd") };
      if ($("rb").value !== p.req_body && !$("rb").readOnly) edits.body = $("rb").value;
      const r = await run("retry", { flow_id: id, edits }, "Sent — the new call is at the bottom of the list");
      if (r) $("pause").classList.remove("open");
    };
  }

  // ───────────── Copy as … (code generation, secrets masked by default) ─────────────
  const maskOn = () => { try { return localStorage.getItem("proxy-mask") !== "off"; } catch (e) { return true; } };
  const lastTarget = () => { try { return localStorage.getItem("proxy-copyas") || "curl"; } catch (e) { return "curl"; } };
  const remember = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } };
  const copyAsHTML = (idp) => `
    <div class="btns"><select id="${idp}-t">${(state.codegen_targets || []).map((t) =>
        `<option value="${esc(t.id)}" ${t.id === lastTarget() ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</select>
      <button class="b p" id="${idp}-go">Copy</button>
      <label class="sub" style="display:flex;gap:4px;align-items:center"><input type="checkbox" id="${idp}-mask" ${maskOn() ? "checked" : ""}> Mask secrets</label></div>
    <div class="sub" id="${idp}-note">${maskOn() ? "Authorization and cookie values become &lt;redacted&gt;." : "⚠ Tokens and cookies WILL be included — do not paste into tickets or chats."}</div>`;
  function wireCopyAs(idp, payload) {
    $(idp + "-mask").onchange = () => {
      remember("proxy-mask", $(idp + "-mask").checked ? "on" : "off");
      $(idp + "-note").innerHTML = $(idp + "-mask").checked ? "Authorization and cookie values become &lt;redacted&gt;."
        : "⚠ Tokens and cookies WILL be included — do not paste into tickets or chats.";
    };
    $(idp + "-go").onclick = async () => {
      const target = $(idp + "-t").value, mask = $(idp + "-mask").checked;
      remember("proxy-copyas", target);
      const r = await run("codegen", { ...payload(), target, mask });
      if (!r) return;
      const label = $(idp + "-t").selectedOptions[0].textContent;
      try { await navigator.clipboard.writeText(r.text); toast("Copied as " + label + (mask ? " (secrets masked)" : " — contains secrets!")); }
      catch (e) { prompt("Copy:", r.text); }
    };
  }

  // ───────────── TLS: which hosts are decrypted ─────────────
  const tlsRe = (pattern) => {   // same wildcard rules as proxy_common.tls_host_regex, for hints only
    let p = String(pattern).trim().toLowerCase().replace(/\.+$/, ""), port = "";
    const m = p.match(/^([^:]*):(\d+)$/);
    if (m) { p = m[1]; port = m[2]; }
    const body = [...p].map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\\/-]/g, "\\$&"))).join("");
    return new RegExp("^" + body + (port ? ":" + port : "(?::\\d+)?") + "$", "i");
  };
  const tlsCovers = (list, host) => (list || []).filter((p) => { try { return tlsRe(p).test(host); } catch (e) { return false; } });
  function tlsVerdict(host) {
    const t = state.tls || { mode: "all", allow: [], ignore: [] };
    if (t.mode === "all") return { on: true, why: "TLS mode is all — every host is decrypted" };
    if (t.mode === "allow") { const hit = tlsCovers(t.allow, host); return hit.length ? { on: true, why: "allowed by " + hit.join(", ") } : { on: false, why: "mode allow — not in the allow list" }; }
    const hit = tlsCovers(t.ignore, host);
    return hit.length ? { on: false, why: "ignored by " + hit.join(", ") } : { on: true, why: "mode ignore — not in the ignore list" };
  }
  function tlsQuickHTML(host) {
    const v = tlsVerdict(host);
    return `<h4>TLS</h4>
      <div class="sub">${v.on ? "🔓 decrypted" : "🔒 NOT decrypted (tunnel only)"} — ${esc(v.why)}</div>
      <div class="btns"><button class="b" id="tlsdec" ${v.on ? "disabled" : ""}>Decrypt ${esc(host)}</button>
        <button class="b" id="tlsno" ${v.on ? "" : "disabled"}>Don't decrypt ${esc(host)}</button></div>
      <div class="sub">${esc((state.tls || {}).note || "")}</div>`;
  }
  function wireTlsQuick(flowId, host) {
    const go = (decrypt) => run("tls_host", { flow_id: flowId, host, decrypt }, (x) => x.message);
    if ($("tlsdec")) $("tlsdec").onclick = () => go(true);
    if ($("tlsno")) $("tlsno").onclick = () => go(false);
  }
  function tlsSectionHTML() {
    const t = state.tls || { mode: "all", allow: [], ignore: [] };
    const modes = [["all", "Decrypt all hosts"], ["allow", "Only the allow list"], ["ignore", "All except the ignore list"]];
    const list = (which, title) => `
      <div class="sub" style="margin-top:8px"><b>${title}</b>${t.mode === which ? " · active" : ""}</div>
      <div class="btns" style="margin-top:4px">${t[which].map((p) => `<span class="chip">${esc(p)} <span data-tlsrm="${which}" data-p="${esc(p)}" title="Remove">✕</span></span>`).join("") || '<span class="sub">(none)</span>'}</div>
      <div class="btns"><input type="text" class="grow" data-tlsadd="${which}" placeholder="*.example.test or api.example.test:8443"><button class="b" data-tlsaddbtn="${which}">Add</button></div>`;
    return `<h4>TLS decryption (SSL proxying list)</h4>
      <div class="seg" id="tlsmode">${modes.map(([id, label]) => `<button data-tm="${id}" class="${t.mode === id ? "on" : ""}">${label}</button>`).join("")}</div>
      ${t.error ? `<div class="errbox">${esc(t.error)}</div>` : ""}
      ${list("allow", "Allow list")}${list("ignore", "Ignore list")}
      <div class="sub" style="margin-top:6px">${esc(t.note || "")}</div>`;
  }
  function wireTlsSection() {
    const t = state.tls;
    root.querySelectorAll("[data-tm]").forEach((b) => (b.onclick = () => run("tls_set", { mode: b.dataset.tm }, "TLS mode: " + b.dataset.tm)));
    root.querySelectorAll("[data-tlsrm]").forEach((x) => (x.onclick = () => run("tls_set", { [x.dataset.tlsrm]: t[x.dataset.tlsrm].filter((p) => p !== x.dataset.p) }, "Removed " + x.dataset.p)));
    const add = (which) => {
      const input = root.querySelector(`[data-tlsadd="${which}"]`), value = input.value.trim().toLowerCase();
      if (value) run("tls_set", { [which]: t[which].concat(t[which].includes(value) ? [] : [value]) }, "Added " + value);
    };
    root.querySelectorAll("[data-tlsaddbtn]").forEach((b) => (b.onclick = () => add(b.dataset.tlsaddbtn)));
    root.querySelectorAll("[data-tlsadd]").forEach((i) => (i.onkeydown = (e) => { if (e.key === "Enter") add(i.dataset.tlsadd); }));
  }

  // ───────────── Compose (a new request from scratch) ─────────────
  const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  const newDraft = () => ({ name: "", method: "GET", url: "", query: [], headers: [], body_mode: "none", body: "", form: [], note: "" });
  let draft = newDraft(), composeSub = "params", varRows = null, focusNew = null;
  const encQ = (x) => encodeURIComponent(x).replace(/%7B/gi, "{").replace(/%7D/gi, "}");
  const decQ = (x) => { try { return decodeURIComponent(String(x).replace(/\+/g, " ")); } catch (e) { return x; } };
  const urlParts = (u) => {
    const h = u.indexOf("#"), plain = h >= 0 ? u.slice(0, h) : u, q = plain.indexOf("?");
    return q < 0 ? [plain, ""] : [plain.slice(0, q), plain.slice(q + 1)];
  };
  function urlFromRows() {          // table → URL (only ticked rows)
    const base = urlParts(draft.url)[0], on = draft.query.filter((r) => r[2] !== false && String(r[0]).length);
    draft.url = base + (on.length ? "?" + on.map((r) => encQ(r[0]) + "=" + encQ(r[1])).join("&") : "");
  }
  function rowsFromUrl() {          // URL → table (unticked rows are kept)
    const q = urlParts(draft.url)[1];
    const parsed = q ? q.split("&").filter(Boolean).map((p) => { const i = p.indexOf("="); return i < 0 ? [decQ(p), "", true] : [decQ(p.slice(0, i)), decQ(p.slice(i + 1)), true]; }) : [];
    draft.query = parsed.concat(draft.query.filter((r) => r[2] === false));
  }
  const specOf = () => ({ method: draft.method, url: draft.url, query: draft.query, headers: draft.headers,
    body_mode: draft.body_mode, body: draft.body, form: draft.form });
  const loadDraft = (spec, name) => {
    draft = { ...newDraft(), ...spec, name: name || "" };
    ["query", "headers", "form"].forEach((k) => (draft[k] = (draft[k] || []).map((r) => [r[0], r[1], r[2] !== false])));
    if (!(spec.query || []).length) rowsFromUrl();
    composeSub = "params";
  };
  const kvHTML = (key, rows, ph) => `<div data-kv="${key}">${rows.map((r, i) =>
      `<div class="krow" data-i="${i}"><input type="checkbox" title="send this row" ${r[2] === false ? "" : "checked"}><input type="text" value="${esc(r[0])}" placeholder="${ph[0]}"><input type="text" value="${esc(r[1])}" placeholder="${ph[1]}"><button class="b d" data-kdel>✕</button></div>`).join("")}</div>
    <button class="b" data-kadd="${key}">+ Add</button>`;
  const rowsOf = (key) => (key === "vars" ? varRows : draft[key]);
  function wireKV(scope) {
    scope.querySelectorAll("[data-kv]").forEach((box) => {
      const key = box.dataset.kv;
      box.querySelectorAll(".krow").forEach((row) => {
        const i = Number(row.dataset.i), [cb, k, v] = row.querySelectorAll("input");
        const sync = () => {
          rowsOf(key)[i] = [k.value, v.value, cb.checked];
          if (key === "query") { urlFromRows(); if ($("cu")) $("cu").value = draft.url; }
        };
        k.oninput = sync; v.oninput = sync; cb.onchange = sync;
        row.querySelector("[data-kdel]").onclick = () => { rowsOf(key).splice(i, 1); if (key === "query") urlFromRows(); render(); };
      });
    });
    scope.querySelectorAll("[data-kadd]").forEach((b) => (b.onclick = () => { rowsOf(b.dataset.kadd).push(["", "", true]); focusNew = b.dataset.kadd; render(); }));
  }
  function composeSection() {
    if (composeSub === "params") return `<div class="sub" style="margin-bottom:6px">Stays in sync with the URL. Untick a row to keep it without sending it.</div>${kvHTML("query", draft.query, ["name", "value"])}`;
    if (composeSub === "headers") return `${kvHTML("headers", draft.headers, ["Header", "Value"])}
      <div class="btns"><button class="b" id="ctok">Use latest token for this host</button></div>
      <div class="sub">Takes the newest <code>Authorization: Bearer</code> JWT seen for the URL's host, stores it as <code>{{token}}</code> and adds the header.</div>`;
    if (composeSub === "vars") {
      if (!varRows) varRows = Object.entries((state.composer || {}).vars || {}).map(([k, v]) => [k, v, true]);
      return `<div class="sub" style="margin-bottom:6px">Use <code>{{name}}</code> in the URL, headers, params and body. Stored per project in composer/vars.json.</div>
        ${kvHTML("vars", varRows, ["name", "value"])}<div class="btns"><button class="b p" id="cvsave">Save variables</button></div>`;
    }
    const modes = [["none", "None"], ["json", "JSON"], ["form", "Form"], ["raw", "Raw"]];
    const seg = `<div class="seg">${modes.map(([id, l]) => `<button data-bm="${id}" class="${draft.body_mode === id ? "on" : ""}">${l}</button>`).join("")}</div>`;
    if (draft.body_mode === "json") return `${seg}<textarea id="cb" spellcheck="false" style="min-height:150px;height:210px">${esc(draft.body)}</textarea>
      <div class="btns"><button class="b" id="cpretty">Pretty-print</button><span class="sub" id="cjs"></span></div>`;
    if (draft.body_mode === "raw") return `${seg}<textarea id="cb" spellcheck="false" style="min-height:150px;height:210px">${esc(draft.body)}</textarea>`;
    if (draft.body_mode === "form") return `${seg}${kvHTML("form", draft.form, ["field", "value"])}`;
    return `${seg}<p class="muted">No request body.</p>`;
  }
  function drawSection() {
    const area = $("carea"); area.innerHTML = composeSection(); wireKV(area);
    area.querySelectorAll("[data-bm]").forEach((b) => (b.onclick = () => { draft.body_mode = b.dataset.bm; drawSection(); }));
    if ($("cb")) $("cb").oninput = () => { draft.body = $("cb").value; if (draft.body_mode === "json") jsonCheck($("cb"), $("cjs")); };
    if ($("cpretty")) $("cpretty").onclick = () => {
      try { draft.body = JSON.stringify(JSON.parse($("cb").value), null, 2); $("cb").value = draft.body; jsonCheck($("cb"), $("cjs")); }
      catch (e) { $("cjs").textContent = "⚠ not JSON: " + e.message; }
    };
    if ($("cvsave")) $("cvsave").onclick = () => {
      const vars = {}; varRows.forEach(([k, v]) => { if (String(k).trim()) vars[String(k).trim()] = v; });
      varRows = null; run("compose_vars", { vars }, "Variables saved");
    };
    if ($("ctok")) $("ctok").onclick = useLatestToken;
  }
  async function useLatestToken() {
    const vars = (state.composer || {}).vars || {};
    const base = urlParts(draft.url)[0].replace(/{{\s*([A-Za-z_][\w.-]*)\s*}}/g, (_, n) => vars[n] ?? "");
    let host = "";
    try { host = new URL(base).hostname; } catch (e) { return toast("Enter the URL first — the token is looked up by host", true); }
    const t = await run("compose_token", { host });
    if (!t) return;
    draft.headers = draft.headers.filter((h) => String(h[0]).toLowerCase() !== "authorization").concat([["Authorization", "Bearer {{token}}", true]]);
    varRows = null;
    await run("compose_vars", { vars: { ...vars, token: t.token } }, `Using the latest token for ${host} (sub ${t.sub || "?"}) as {{token}}`);
  }
  function renderCompose(m) {
    const names = (state.composer || {}).names || [];
    const count = { params: draft.query.filter((r) => r[2] !== false).length, headers: draft.headers.filter((r) => r[2] !== false).length };
    const subs = [["params", "Params"], ["headers", "Headers"], ["body", "Body"], ["vars", "Variables"]];
    m.innerHTML = `
      <div class="btns" style="margin-top:0"><select id="cs"><option value="">Saved requests…</option>${names.map((n) => `<option ${n === draft.name ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
        <button class="b" id="cload">Load</button><button class="b" id="csave">Save</button><button class="b" id="csaveas">Save as…</button>
        <button class="b" id="cren" ${names.includes(draft.name) ? "" : "disabled"}>Rename</button>
        <button class="b d" id="cdel" ${names.includes(draft.name) ? "" : "disabled"}>Delete</button><button class="b" id="cnew">New</button></div>
      ${draft.name ? `<div class="sub">Saved request: <b>${esc(draft.name)}</b> · CLI: <code>${esc((state.product || {}).cli || "proxy")} compose send ${esc(draft.name)}</code></div>` : ""}
      ${draft.note ? `<div class="sub">${esc(draft.note)}</div>` : ""}
      ${(state.composer || {}).error ? `<div class="errbox">${esc(state.composer.error)}</div>` : ""}
      <div class="btns"><input type="text" id="cm" list="cmlist" value="${esc(draft.method)}" style="width:96px" placeholder="METHOD">
        <datalist id="cmlist">${METHODS.map((x) => `<option value="${x}">`).join("")}</datalist>
        <input type="text" id="cu" class="grow" value="${esc(draft.url)}" placeholder="https://host/path?x=1  or  {{edge}}/path"></div>
      <div class="seg">${subs.map(([id, l]) => `<button data-cs="${id}" class="${composeSub === id ? "on" : ""}">${l}${count[id] ? " (" + count[id] + ")" : ""}</button>`).join("")}</div>
      <div id="carea"></div>
      <div class="btns"><button class="b p" id="csend">Send</button><span class="sub">goes through your rules and scripts; appears at the bottom of the list as “composed”</span></div>
      <h4>Copy as</h4>${copyAsHTML("cc")}`;
    drawSection();
    $("cm").oninput = () => (draft.method = $("cm").value.trim().toUpperCase());
    $("cu").oninput = () => { draft.url = $("cu").value; rowsFromUrl(); if (composeSub === "params") drawSection(); };
    root.querySelectorAll("[data-cs]").forEach((b) => (b.onclick = () => { composeSub = b.dataset.cs; if (composeSub !== "vars") varRows = null; render(); }));
    $("cnew").onclick = () => { draft = newDraft(); composeSub = "params"; render(); };
    $("cload").onclick = async () => {
      const name = $("cs").value; if (!name) return toast("Pick a saved request first", true);
      const r = await run("compose_load", { name }); if (!r) return;
      loadDraft(r.spec, name); render();
    };
    const saveAs = async (name) => {
      if (!name) return;
      const r = await run("compose_save", { name, spec: specOf() }, "Saved " + name);
      if (r) { draft.name = name; render(); }
    };
    $("csave").onclick = () => (draft.name ? saveAs(draft.name) : saveAs(prompt("Save as (letters, digits . _ -):", "")));
    $("csaveas").onclick = () => saveAs(prompt("Save as (letters, digits . _ -):", draft.name || ""));
    $("cren").onclick = async () => {
      const next = prompt("New name:", draft.name); if (!next || next === draft.name) return;
      const r = await run("compose_rename", { old: draft.name, new: next }, "Renamed to " + next);
      if (r) { draft.name = next; render(); }
    };
    $("cdel").onclick = async () => {
      if (!confirm("Delete saved request '" + draft.name + "'?")) return;
      const r = await run("compose_delete", { name: draft.name }, "Deleted " + draft.name);
      if (r) { draft.name = ""; render(); }
    };
    $("csend").onclick = () => run("compose_send", { spec: specOf() }, (x) => "Sent " + x.method + " " + x.url + " — see the bottom of the list");
    wireCopyAs("cc", () => ({ spec: specOf() }));
    if (focusNew) {
      const rows = m.querySelectorAll(`[data-kv="${focusNew}"] .krow`);
      if (rows.length) rows[rows.length - 1].querySelectorAll("input")[1].focus();
      focusNew = null;
    }
  }

  // ───────────── All rules ─────────────
  function describe(r) {
    const a = r.action;
    if (a === "map_local") return "serves file" + (r.status ? " (" + r.status + ")" : "");
    if (a === "respond") return "answers " + r.status;
    if (a === "status") return "status → " + r.status;
    if (a === "delay") return "+" + r.ms + " ms";
    if (a === "json_patch") return "edits " + Object.keys(r.set || {}).join(", ");
    if (a === "set_header") return (r.value == null ? "removes " : "sets ") + r.header;
    if (a === "map_remote") return "→ " + r.with;
    return a;
  }
  function renderRules(m) {
    const skipped = state.skipped_rules || [];
    if (!state.rules.length && !skipped.length) { m.innerHTML = '<p class="muted">No rules yet. Select a call and use “This call”.</p>'; return; }
    m.innerHTML = (skipped.length ? `<div class="call" style="background:#fef2f2;color:#b91c1c"><b>⚠ ${skipped.length} rule(s) skipped</b>${skipped.map((r) => `<div class="sub" style="color:#b91c1c">${esc(r.name)} — ${esc(r.error)}</div>`).join("")}</div>` : "") + state.rules.map((r, i) => `
      <div class="row">${sw(`data-i="${i}"`, r.enabled !== false)}
        <div class="n"><div><b>${esc(r.name)}</b><span class="tag">${esc(r.action)}</span></div>
          <div class="sub">${esc(r.method ? r.method + " " : "")}${esc(pretty(r))} — ${esc(describe(r))}</div></div>
        ${r.action === "map_local" ? `<button class="b" data-edit="${i}">Edit</button>` : ""}
        <button class="b d" data-del="${i}" title="Delete">✕</button></div>`).join("") +
      `<p class="sub">Saved in ${esc(state.rules_file)} — also editable with <code>${esc(state.product.cli)} rules</code>.</p>`;
    wireRuleRows(m);
  }
  function wireRuleRows(m) {
    m.querySelectorAll("input[data-i]").forEach((c) => (c.onchange = () =>
      run("toggle", { name: state.rules[c.dataset.i].name, enabled: c.checked }, c.checked ? "ON" : "off")));
    m.querySelectorAll("[data-del]").forEach((b) => (b.onclick = () => {
      const n = state.rules[b.dataset.del].name;
      if (confirm("Delete rule '" + n + "'?")) run("delete", { name: n }, "Deleted " + n);
    }));
    m.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => openEditor(state.rules[b.dataset.edit].name)));
  }

  // ───────────── Map Local editor (Body / Headers, like FRTMProxy) ─────────────
  async function openEditor(name) {
    try { const r = await api("mockfile_get", { name }); editing = { name, sub: "body", ...r }; render(); }
    catch (e) { toast(e.message, true); }
  }
  function renderEditor(m) {
    const e = editing;
    m.innerHTML = `
      <div class="btns" style="margin-top:0"><button class="b" id="back">← Back</button>
        <b style="flex:1;align-self:center;overflow:hidden;text-overflow:ellipsis">${esc(e.name)}</b>
        status <input type="number" id="st" value="${esc(e.status)}" style="width:70px"></div>
      <div class="sub" style="margin-top:6px">${esc(e.method || "ANY")} ${esc(pretty({ match: e.match }))}</div>
      <div class="seg"><button data-sub="body" class="${e.sub === "body" ? "on" : ""}">Body</button><button data-sub="headers" class="${e.sub === "headers" ? "on" : ""}">Headers</button></div>
      <div id="pbody" style="${e.sub === "body" ? "" : "display:none"}">
        <textarea id="body" spellcheck="false" ${e.editable ? "" : "readonly"}>${esc(e.content)}</textarea>
        <div class="btns"><button class="b" id="fmt">Format JSON</button><span class="sub" id="jsonok"></span></div></div>
      <div id="phdr" style="${e.sub === "headers" ? "" : "display:none"}">${headersHTML(e.headers, "hd")}
        <div class="sub">Content-Type defaults to the file type when not set.</div></div>
      <div class="btns"><button class="b p" id="save" ${e.editable ? "" : "disabled"}>Save</button><span class="sub" id="dirty"></span></div>
      <div class="sub">${esc(e.file)} — the next matching call gets this.</div>`;
    const ta = $("body");
    jsonCheck(ta, $("jsonok"));
    ta.oninput = () => { jsonCheck(ta, $("jsonok")); editing.content = ta.value; $("dirty").textContent = "Modified"; };
    root.querySelectorAll("[data-sub]").forEach((b) => (b.onclick = () => {
      editing.content = ta.value; editing.headers = readHeaders("hd"); editing.status = $("st").value; editing.sub = b.dataset.sub; render();
    }));
    wireHeaders(m);
    $("back").onclick = () => { editing = null; render(); };
    $("fmt").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2) + "\n"; ta.oninput(); } catch (x) { toast("Not JSON — cannot format", true); } };
    $("save").onclick = async () => {
      if (!jsonCheck(ta, $("jsonok")) && !confirm("This is not valid JSON. Save anyway?")) return;
      const headers = readHeaders("hd");
      const r = await run("mockfile_put", { name: e.name, content: ta.value, status: $("st").value, headers }, "Saved — next call gets it");
      if (r) editing = { ...editing, content: ta.value, status: $("st").value, headers };
    };
  }

  // ───────────── Paused call sheet (opens by itself) ─────────────
  async function openPaused(id) {
    try { pausedOpen = await api("paused_get", { id }); pausedOpen.sub = "body"; drawPaused(); }
    catch (e) { pausedOpen = null; $("pause").classList.remove("open"); toast(e.message, true); }
  }
  function drawPaused() {
    const p = pausedOpen, isResp = p.phase === "response";
    const q = state ? state.paused.length : 1;
    $("sheet").innerHTML = `
      <header><b>⏸ Paused at ${isResp ? "response" : "request"}${q > 1 ? ` · ${q} waiting` : ""}</b>
        <span class="sub" style="max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.method)} ${esc(p.url)}</span></header>
      <main>
        ${isResp ? `<div class="btns" style="margin-top:0">Status <input type="number" id="pst" value="${esc(p.status)}" style="width:80px"></div>`
                 : `<div class="btns" style="margin-top:0"><select id="pm">${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((x) => `<option ${x === p.method ? "selected" : ""}>${x}</option>`).join("")}</select>
                    <input type="text" id="pu" class="grow" value="${esc(p.url)}"></div>`}
        <div class="seg"><button data-psub="body" class="${p.sub === "body" ? "on" : ""}">Body</button><button data-psub="headers" class="${p.sub === "headers" ? "on" : ""}">Headers</button></div>
        <div id="ppb" style="${p.sub === "body" ? "" : "display:none"}"><textarea id="pb" spellcheck="false" ${(isResp ? p.resp_body_editable : p.req_body_editable) ? "" : "readonly"}>${esc(isResp ? p.resp_body : p.req_body)}</textarea>
          <div class="btns"><button class="b" id="pfmt">Format JSON</button><span class="sub" id="pjs"></span></div></div>
        <div id="pph" style="${p.sub === "headers" ? "" : "display:none"}">${headersHTML(isResp ? p.resp_headers : p.req_headers, "phd")}</div>
      </main>
      <footer><span class="sub" style="margin-right:auto">The app is waiting — continue within its timeout (~30–60 s).</span>
        <button class="b d" id="pabort">Abort</button><button class="b" id="pskip">Skip (send unchanged)</button>
        <button class="b p" id="pcont">Continue</button></footer>`;
    $("pause").classList.add("open");
    const ta = $("pb"); jsonCheck(ta, $("pjs")); ta.oninput = () => jsonCheck(ta, $("pjs"));
    wireHeaders($("sheet"));
    root.querySelectorAll("[data-psub]").forEach((b) => (b.onclick = () => {
      $("ppb").style.display = b.dataset.psub === "body" ? "" : "none"; $("pph").style.display = b.dataset.psub === "headers" ? "" : "none";
      root.querySelectorAll("[data-psub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    $("pfmt").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); jsonCheck(ta, $("pjs")); } catch (x) { toast("Not JSON", true); } };
    const done = async (op, edits) => {
      const id = p.id;
      const r = await run(op, { id, edits }, op === "paused_continue" ? "Continued with your edits" : op === "paused_skip" ? "Sent unchanged" : "Aborted");
      if (!r) return;
      pausedOpen = null; $("pause").classList.remove("open");
      const next = (state.paused || []).find((x) => !dismissed.has(x.id));
      if (next) openPaused(next.id);
    };
    $("pcont").onclick = () => {
      const original = isResp ? p.resp_body : p.req_body;
      const edits = { headers: readHeaders("phd") };
      if (ta.value !== original && !ta.readOnly) edits.body = ta.value;   // untouched body: bytes pass through as-is
      if (isResp) edits.status = Number($("pst").value); else { edits.method = $("pm").value; edits.url = $("pu").value; }
      done("paused_continue", edits);
    };
    $("pskip").onclick = () => done("paused_skip");
    $("pabort").onclick = () => done("paused_abort");
  }

  // poll for paused calls so the sheet opens by itself, like FRTMProxy / Proxyman
  let viewerPoll = null;
  async function refreshViewerSummaries() {
    if (viewerPoll || !$("drawer").classList.contains("open")) return viewerPoll;
    viewerPoll = api("viewer_summaries", { limit:12 }).then((r) => {
      viewers = r.viewers || viewers;
      tagCells();
    }).catch(() => {}).finally(() => { viewerPoll = null; });
    return viewerPoll;
  }
  async function poll() {
    try {
      const s = await api("state");
      state = s; badges();
      if ($("drawer").classList.contains("open")) await refreshViewerSummaries();
      await refreshFlows(); tagCells();
      const waiting = s.paused.filter((x) => !dismissed.has(x.id));
      if (!pausedOpen && waiting.length && !$("pause").classList.contains("open")) openPaused(waiting[0].id);
      if (pausedOpen && !s.paused.some((x) => x.id === pausedOpen.id)) { pausedOpen = null; $("pause").classList.remove("open"); }
      if ($("drawer").classList.contains("open") && tab === "coll" && !editing && !root.activeElement && s.collections.recording) render();
      if ($("drawer").classList.contains("open") && !editing && (tab === "bp" || tab === "rules" || tab === "map" || tab === "scripts") && !root.activeElement) render();
    } catch (e) { /* mitmweb restarting: try again */ }
    setTimeout(poll, 1200);
  }

  const setOpen = (open) => {
    $("drawer").classList.toggle("open", open);
    document.body.style.marginRight = open ? W + "px" : "";   // push mitmweb over instead of covering it
    document.body.style.width = open ? `calc(100% - ${W}px)` : "";
    window.dispatchEvent(new Event("resize"));
  };
  $("fab").onclick = () => {
    if (state && state.paused.length && !pausedOpen) { dismissed.clear(); return openPaused(state.paused[0].id); }
    setOpen(!$("drawer").classList.contains("open")); state = null; render(); refreshViewerSummaries().then(() => {
      if ($("drawer").classList.contains("open") && tab === "call" && !editing) render();
    });
  };
  $("close").onclick = () => setOpen(false);
  $("pause").onclick = (e) => { if (e.target === $("pause")) { dismissed.add(pausedOpen && pausedOpen.id); pausedOpen = null; $("pause").classList.remove("open"); toast("Still paused — reopen from the project button"); } };
  $("project").onchange = () => run("view", { project: $("project").value, project_only: state.project_only, show_dns: state.show_dns }, "View changed; restart to load this project's rules");
  root.querySelectorAll("nav button").forEach((b) => (b.onclick = () => { tab = b.dataset.t; editing = null; render(); }));
  // mitmweb changes the selection with history.replaceState, which fires no "hashchange" —
  // so watch the selected call id ourselves
  let lastSel = selectedFlow();
  setInterval(() => {
    const cur = selectedFlow();
    if (cur === lastSel) return;
    lastSel = cur;
    if ($("drawer").classList.contains("open") && (tab === "call" || tab === "cmp") && !editing) render();
  }, 300);
  poll();
})();
