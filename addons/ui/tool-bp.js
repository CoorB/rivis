/* Breakpoint (⌥⌘B): the rule list, and the paused call, which opens by itself when a call stops, as in Proxyman.
 * Ops (panel API): bp_add {flow_id | host, path | match, method, request, response}, bp_update {name, enabled |
 * match, method, request, response}, bp_delete {name}, paused_get {id}, paused_continue|skip|abort {id, edits},
 * paused_resume_all. A paused call waits for the app's own timeout (about 30–60 s), so the window says so. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;

  // ── the rule list ────────────────────────────────────────────────────────────────────────────────────────────────
  const sig = (st) => JSON.stringify([st.breakpoints, (st.paused || []).length]);
  T.register("bp", {
    title: "Breakpoint", width: 760, height: 460,
    render(w) {
      w.data.sig = null; w.data.edit = w.data.edit || null;
      w.body.innerHTML = `<div class="rv-win-bar">
          <button type="button" class="rv-btn p" data-bp-new>+ Add Rule</button>
          <span class="rv-win-hint">A matching call stops before it is sent (request) or before the app gets it (response).
            Right-click a call → Breakpoint adds one for that endpoint.</span></div>
        <div class="rv-paused-banner" hidden></div>
        <div class="rv-rules" data-bp-list></div><div class="rv-editor" data-bp-ed hidden></div>`;
      w.body.querySelector("[data-bp-new]").onclick = () => editRule(w, null);
      w.body.addEventListener("change", async (e) => {
        const c = e.target.closest("[data-bp-on]");
        if (c) { await ui.run("bp_update", { name: c.dataset.bpOn, enabled: c.checked }, c.checked ? "Breakpoint on" : "Breakpoint off"); return; }
        const ph = e.target.closest("[data-bp-ph]");
        if (ph) {
          const b = rules().find((x) => x.name === ph.dataset.bpName);
          if (!b) return;
          const next = { request: !!b.request, response: !!b.response, [ph.dataset.bpPh]: ph.checked };
          if (!next.request && !next.response) { ph.checked = true; A.toast("Keep Request, Response or both — or turn the rule off", true); return; }
          await ui.run("bp_update", { name: b.name, ...next });
        }
      });
      w.body.addEventListener("click", async (e) => {
        const del = e.target.closest("[data-bp-del]");
        if (del && await A.ask("Delete breakpoint " + del.dataset.bpDel + "?", "Calls that are paused by it continue unchanged.", "Delete", true)) {
          await ui.run("bp_delete", { name: del.dataset.bpDel }, "Breakpoint deleted");
          if (w.data.edit && w.data.edit.name === del.dataset.bpDel) closeEditor(w);
        }
        const ed = e.target.closest("[data-bp-edit]");
        if (ed) editRule(w, rules().find((x) => x.name === ed.dataset.bpEdit) || null);
        const op = e.target.closest("[data-open-paused]");
        if (op) T.open("paused", { id: op.dataset.openPaused });
      });
    },
    onState(st, w) {
      if (!w) return;
      const s = sig(st);
      if (s === w.data.sig) return;
      w.data.sig = s;
      const bps = st.breakpoints || [], paused = st.paused || [];
      w.setSub(bps.length ? `${bps.filter((b) => b.enabled !== false).length} of ${bps.length} on` : "");
      const banner = w.body.querySelector(".rv-paused-banner");
      banner.hidden = !paused.length;
      banner.innerHTML = paused.length ? `⏸ ${paused.length} call${paused.length === 1 ? " is" : "s are"} paused <button type="button" class="rv-btn" data-open-paused="${esc(paused[0].id)}">Open</button>` : "";
      const list = w.body.querySelector("[data-bp-list]");
      const focusKey = document.activeElement && w.body.contains(document.activeElement) ? keyOf(document.activeElement) : null;
      list.innerHTML = bps.length ? `<table class="rv-rtable"><thead><tr><th>On</th><th>Method</th><th>URL</th><th>Request</th><th>Response</th><th></th></tr></thead><tbody>`
        + bps.map((b) => `<tr data-name="${esc(b.name)}"${b.enabled === false ? ' class="off"' : ""}>
            <td><input type="checkbox" data-bp-on="${esc(b.name)}" aria-label="Breakpoint ${esc(b.name)} on" ${b.enabled === false ? "" : "checked"}></td>
            <td>${esc(b.method || "Any")}</td>
            <td class="rv-mono rv-ell" title="${esc(b.match)}">${esc(b.label || b.match)}</td>
            <td><input type="checkbox" data-bp-ph="request" data-bp-name="${esc(b.name)}" aria-label="Pause the request" ${b.request ? "checked" : ""}></td>
            <td><input type="checkbox" data-bp-ph="response" data-bp-name="${esc(b.name)}" aria-label="Pause the response" ${b.response ? "checked" : ""}></td>
            <td class="rv-act"><button type="button" class="rv-lnk" data-bp-edit="${esc(b.name)}">Edit</button>
              <button type="button" class="rv-icon-btn" data-bp-del="${esc(b.name)}" aria-label="Delete breakpoint ${esc(b.name)}">✕</button></td></tr>`).join("")
        + `</tbody></table>`
        : ui.empty("No breakpoints", "Add a rule, or right-click a call in the list → Breakpoint.");
      if (focusKey) { const el = w.body.querySelector(focusKey); if (el) el.focus({ preventScroll: true }); }
    },
    dirty: (w) => !!(w.data.edit && w.data.edit.dirty),
  });
  const rules = () => (A.state() || {}).breakpoints || [];
  const keyOf = (el) => {
    for (const a of ["data-bp-on", "data-bp-edit", "data-bp-del"]) if (el.hasAttribute(a)) return `[${a}="${CSS.escape(el.getAttribute(a))}"]`;
    if (el.hasAttribute("data-bp-ph")) return `[data-bp-ph="${el.dataset.bpPh}"][data-bp-name="${CSS.escape(el.dataset.bpName)}"]`;
    return null;
  };

  function editRule(w, b) {
    const ed = w.body.querySelector("[data-bp-ed]");
    const isRe = !!b;                       // an existing rule is a regex on the URL; a new one is a wildcard URL
    w.data.edit = { name: b ? b.name : null, dirty: false };
    ed.hidden = false;
    ed.innerHTML = `<h4>${b ? "Edit " + esc(b.name) : "New breakpoint"}</h4>
      <div class="rv-form">
        <label>Method ${ui.methodSelect("bpm", b && b.method, "Any")}</label>
        <label class="grow">URL <input type="text" id="bpu" spellcheck="false" value="${esc(b ? b.match : "")}"
          placeholder="${isRe ? "regex on the full URL" : "api.example.com/v1/accounts/*"}"></label>
        <label><input type="checkbox" id="bpre" ${isRe ? "checked" : ""}> Regex</label>
      </div>
      <div class="rv-form"><label><input type="checkbox" id="bpq" ${!b || b.request ? "checked" : ""}> Request</label>
        <label><input type="checkbox" id="bpr" ${b && b.response ? "checked" : ""}> Response</label>
        <span class="rv-win-hint">* matches anything, ? one character.</span>
        <span class="rv-spacer"></span>
        <button type="button" class="rv-btn" data-bp-cancel>Cancel</button><button type="button" class="rv-btn p" data-bp-save>${b ? "Save" : "Add"}</button></div>`;
    ed.oninput = () => { w.data.edit.dirty = true; };
    ed.querySelector("[data-bp-cancel]").onclick = () => closeEditor(w);
    ed.querySelector("[data-bp-save]").onclick = async () => {
      const url = ed.querySelector("#bpu").value.trim(), method = ed.querySelector("#bpm").value;
      const request = ed.querySelector("#bpq").checked, response = ed.querySelector("#bpr").checked;
      if (!url) { A.toast("Enter the URL to stop at", true); ed.querySelector("#bpu").focus(); return; }
      if (!request && !response) { A.toast("Pick Request, Response or both", true); return; }
      const re = ed.querySelector("#bpre").checked;
      let r;
      if (b) r = await ui.run("bp_update", Object.assign({ name: b.name, method, request, response }, re ? { match: url } : { match: wildcardRe(url) }), "Breakpoint saved");
      else r = await ui.run("bp_add", Object.assign({ method, request, response }, re ? { match: url } : ui.splitUrl(url)), "Breakpoint added — the next matching call pauses");
      if (r) closeEditor(w);
    };
    ed.querySelector("#bpu").focus();
  }
  function closeEditor(w) { const ed = w.body.querySelector("[data-bp-ed]"); ed.hidden = true; ed.innerHTML = ""; w.data.edit = null; }
  // the server's wildcard_regex, for turning an edited wildcard URL into the rule's regex (bp_update takes a regex)
  const wildcardRe = (t) => {
    let { host, path } = ui.splitUrl(t);
    if (/^https?:\/\//i.test(host)) { try { const u = new URL(host); host = u.host; path = u.pathname; } catch (e) { /* kept as typed */ } }
    const wc = (x, star) => [...x].map((c) => c === "*" ? star : c === "?" ? "." : c.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")).join("");
    const pth = path.startsWith("/") ? path : "/" + path;
    return "^https?://" + wc(host.toLowerCase(), "[^/:]*") + "(:\\d+)?" + wc(pth, ".*") + "(\\?|$)";
  };

  // ── the paused call ──────────────────────────────────────────────────────────────────────────────────────────────
  const dismissed = new Set();
  T.register("paused", {
    title: "Paused call", width: 860, height: 600, always: true,
    render(w, opts) {
      const st = A.state() || {}, paused = st.paused || [];
      const id = (opts && opts.id) || (paused.find((p) => !dismissed.has(p.id)) || paused[0] || {}).id;
      if (!id) { w.body.innerHTML = ui.empty("Nothing is paused", "When a call matches a breakpoint, it shows here by itself."); w.foot.hidden = true; w.data.p = null; return; }
      if (w.data.p && w.data.p.id === id && w.data.loaded) return;       // already showing it (and maybe edited)
      w.data = { p: { id }, loaded: false, sub: "body" };
      w.body.innerHTML = `<p class="rv-win-hint">Loading…</p>`; w.foot.hidden = true;
      A.api("paused_get", { id }).then((p) => { if (w.data.p && w.data.p.id === id) { w.data.p = p; w.data.loaded = true; drawPaused(w); } })
        .catch((e) => { w.body.innerHTML = ui.empty("This call is not paused any more", esc(e.message)); w.data.p = null; });
    },
    onState(st, w) {
      const paused = st.paused || [];
      [...dismissed].forEach((id) => { if (!paused.some((p) => p.id === id)) dismissed.delete(id); });
      const shown = w && w.shown;
      if (shown && w.data.p && w.data.p.id && !paused.some((p) => p.id === w.data.p.id)) {
        // gone (the app gave up, or it was resumed elsewhere): show the next one or say so
        const next = paused.find((p) => !dismissed.has(p.id));
        w.data.p = null;
        if (next) T.open("paused", { id: next.id });
        else w.body.innerHTML = ui.empty("This call is not paused any more", "It was continued elsewhere or the app stopped waiting.");
        w.foot.hidden = true;
        return;
      }
      if (shown) { const q = w.el.querySelector("[data-pq]"); if (q) q.textContent = paused.length > 1 ? paused.length + " waiting" : ""; return; }
      const next = paused.find((p) => !dismissed.has(p.id));
      if (next) T.open("paused", { id: next.id });              // opens by itself, like Proxyman
    },
    dirty: (w) => !!(w.data.p && w.data.loaded && isDirty(w)),
    closed(w) { if (w.data.p && w.data.p.id) dismissed.add(w.data.p.id); },
  });

  function drawPaused(w) {
    const p = w.data.p, resp = p.phase === "response";
    const body = resp ? p.resp_body : p.req_body, editable = resp ? p.resp_body_editable : p.req_body_editable;
    w.data.orig = { body, headers: JSON.stringify(resp ? p.resp_headers : p.req_headers), status: String(p.status), method: p.method, url: p.url };
    w.setSub((resp ? "Response" : "Request") + " · " + p.method + " " + p.url);
    w.body.innerHTML = `
      <div class="rv-paused-head ${resp ? "resp" : "req"}"><b>⏸ Paused at the ${resp ? "response — edit what the app receives" : "request — edit what is sent"}</b>
        <span data-pq></span></div>
      ${resp ? `<div class="rv-form"><label>Status <input type="number" id="pst" min="100" max="999" value="${esc(p.status)}" style="width:90px"></label>
                  <span class="rv-mono rv-ell rv-muted">${esc(p.method)} ${esc(p.url)}</span></div>`
             : `<div class="rv-form">${ui.methodSelect("pm", p.method).replace('<option value="">Any</option>', "")}
                  <input type="text" id="pu" class="grow" aria-label="URL" spellcheck="false" value="${esc(p.url)}"></div>
                <p class="rv-win-hint" data-pnext>${p.response_next ? "Continue, and the response pauses next — that is where you change what the app receives."
                  : `To change what the app receives, <button type="button" class="rv-lnk" data-presp>pause its response too</button>.`}</p>`}
      ${ui.seg("psub", [["body", resp ? "Response body" : "Request body"], ["headers", "Headers"], ["form", "Form"]], w.data.sub)}
      <div class="rv-psub" data-pane="body"><textarea id="pb" class="rv-code" spellcheck="false" aria-label="Body" placeholder="No body" ${editable ? "" : "readonly"}>${esc(body)}</textarea>
        <div class="rv-form">${body && editable ? `<button type="button" class="rv-btn" data-pfmt>Format JSON</button>` : ""}<span class="rv-win-hint" data-pjs></span></div></div>
      <div class="rv-psub" data-pane="headers" hidden>${ui.kvHTML(resp ? p.resp_headers : p.req_headers, "phd")}</div>
      <div class="rv-psub" data-pane="form" hidden></div>`;
    w.foot.hidden = false;
    w.foot.innerHTML = `<span class="rv-win-hint">The app is waiting — continue within its timeout (about 30–60 s).
        <button type="button" class="rv-lnk" data-pall>Resume all</button> · <button type="button" class="rv-lnk" data-pbpoff>Turn off this breakpoint</button></span>
      <span class="rv-spacer"></span>
      <button type="button" class="rv-btn d" data-pabort>Abort</button>
      <button type="button" class="rv-btn" data-pskip title="Send it as it was">Skip</button>
      <button type="button" class="rv-btn p" data-pcont title="Send it with your edits (${A.MOD}↩)">Continue</button>`;
    ui.kvWire(w.body);
    const ta = w.body.querySelector("#pb"), js = w.body.querySelector("[data-pjs]");
    const check = () => { const s = ui.jsonState(ta.value); js.textContent = s === "ok" ? "Valid JSON" : s === "bad" && /^\s*[[{]/.test(ta.value) ? "Not valid JSON" : ""; js.className = "rv-win-hint " + (s === "bad" ? "bad" : ""); };
    check(); ta.oninput = check;
    w.body.querySelectorAll("[data-psub]").forEach((b) => (b.onclick = () => setSub(w, b.dataset.psub)));
    const fmt = w.body.querySelector("[data-pfmt]");
    if (fmt) fmt.onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); check(); } catch (e) { A.toast("The body is not JSON", true); } };
    const presp = w.body.querySelector("[data-presp]");
    if (presp) presp.onclick = async () => {
      if (await ui.run("bp_add", { flow_id: p.id, request: true, response: true }, "The response of this call pauses too")) {
        p.response_next = true;
        w.body.querySelector("[data-pnext]").textContent = "Continue, and the response pauses next — that is where you change what the app receives.";
      }
    };
    w.foot.querySelector("[data-pcont]").onclick = () => finish(w, "paused_continue");
    w.foot.querySelector("[data-pskip]").onclick = () => finish(w, "paused_skip");
    w.foot.querySelector("[data-pabort]").onclick = () => finish(w, "paused_abort");
    w.foot.querySelector("[data-pall]").onclick = async () => { const r = await ui.run("paused_resume_all", {}); if (r) A.toast("Resumed " + (r.resumed || 0) + " paused call(s) unchanged"); };
    w.foot.querySelector("[data-pbpoff]").onclick = () => bpOff(w);
    w.el.onkeydown = (e) => { if ((A.isMac ? e.metaKey : e.ctrlKey) && e.key === "Enter") { e.preventDefault(); finish(w, "paused_continue"); } };
    const q = w.el.querySelector("[data-pq]"), n = ((A.state() || {}).paused || []).length;
    if (q) q.textContent = n > 1 ? n + " waiting" : "";
    (w.body.querySelector(resp ? "#pst" : "#pu") || ta).focus({ preventScroll: true });
  }

  function setSub(w, sub) {
    const p = w.data.p, resp = p.phase === "response";
    if (w.data.sub === "form" && !applyForm(w)) return;
    if (sub === "form") drawForm(w);
    w.data.sub = sub;
    w.body.querySelectorAll("[data-pane]").forEach((x) => (x.hidden = x.dataset.pane !== sub));
    w.body.querySelectorAll("[data-psub]").forEach((x) => x.setAttribute("aria-selected", String(x.dataset.psub === sub)));
    void resp;
  }

  // the Form view: query parameters (request), headers and body fields of a JSON object or an URL encoded form
  function drawForm(w) {
    const p = w.data.p, resp = p.phase === "response", pane = w.body.querySelector('[data-pane="form"]');
    const headers = ui.kvRead(w.body, "phd"), raw = w.body.querySelector("#pb").value;
    const type = ((headers.find(([k]) => k.toLowerCase() === "content-type") || [])[1] || "").toLowerCase();
    let kind = "none", fields = [];
    if (/x-www-form-urlencoded/.test(type)) { kind = "urlencoded"; fields = [...new URLSearchParams(raw).entries()]; }
    else {
      try { const d = JSON.parse(raw); if (d && typeof d === "object" && !Array.isArray(d)) { kind = "json"; fields = Object.entries(d); } }
      catch (e) { if (!raw.trim() && /json/.test(type)) kind = "json"; }
    }
    w.data.formKind = kind;
    let url = null;
    if (!resp) { try { url = new URL(w.body.querySelector("#pu").value); } catch (e) { url = null; } }
    const types = ["string", "number", "boolean", "null", "json"];
    const jrow = (k, v) => {
      const t = v === null ? "null" : typeof v === "object" ? "json" : typeof v === "number" ? "number" : typeof v === "boolean" ? "boolean" : "string";
      const val = t === "json" ? JSON.stringify(v) : v === null ? "" : String(v);
      return `<div class="rv-kvr rv-kvr3"><input type="text" aria-label="JSON key" placeholder="Key" value="${esc(k)}">`
        + `<select aria-label="Value type">${types.map((x) => `<option${x === t ? " selected" : ""}>${x}</option>`).join("")}</select>`
        + `<input type="text" aria-label="JSON value" placeholder="Value" value="${esc(val)}"><button type="button" class="rv-icon-btn" data-kvdel aria-label="Remove">✕</button></div>`;
    };
    pane.innerHTML = (resp ? "" : `<h4>Query parameters</h4>${ui.kvHTML(url ? [...url.searchParams.entries()] : [], "pfq")}`)
      + `<h4>Body fields</h4>` + (kind === "json" ? `<div class="rv-kvg" id="pfj">${fields.map(([k, v]) => jrow(k, v)).join("")}</div><button type="button" class="rv-lnk" data-pfjadd>+ Add field</button>`
        : kind === "urlencoded" ? ui.kvHTML(fields, "pff")
        : `<p class="rv-win-hint">${raw.trim() ? "This body is not a JSON object or a URL encoded form: edit it in the body view." : "No body fields. Type a body in the body view to add some."}</p>`);
    const add = pane.querySelector("[data-pfjadd]");
    if (add) add.onclick = () => { const t = document.createElement("div"); t.innerHTML = jrow("", ""); const r = t.firstElementChild; pane.querySelector("#pfj").appendChild(r); r.querySelector("input").focus(); };
  }
  function applyForm(w) {
    const p = w.data.p, resp = p.phase === "response";
    try {
      if (!resp && w.body.querySelector("#pfq")) {
        const u = new URL(w.body.querySelector("#pu").value); u.search = "";
        ui.kvRead(w.body, "pfq").forEach(([k, v]) => u.searchParams.append(k, v));
        w.body.querySelector("#pu").value = u.href;
      }
      const ta = w.body.querySelector("#pb");
      if (w.data.formKind === "urlencoded") ta.value = new URLSearchParams(ui.kvRead(w.body, "pff")).toString();
      if (w.data.formKind === "json") {
        const obj = {};
        w.body.querySelectorAll("#pfj .rv-kvr").forEach((r) => {
          const [ki, vi] = r.querySelectorAll("input"), t = r.querySelector("select").value, k = ki.value, v = vi.value;
          if (!k) return;
          if (t === "number") { const n = Number(v); if (!v.trim() || !Number.isFinite(n)) throw new Error("Enter a number for " + k); obj[k] = n; }
          else if (t === "boolean") { if (v !== "true" && v !== "false") throw new Error("Use true or false for " + k); obj[k] = v === "true"; }
          else if (t === "null") obj[k] = null;
          else if (t === "json") obj[k] = JSON.parse(v);
          else obj[k] = v;
        });
        ta.value = JSON.stringify(obj);
      }
      ta.dispatchEvent(new Event("input"));
      return true;
    } catch (e) { A.toast("Form: " + e.message, true); return false; }
  }

  function edits(w) {
    const p = w.data.p, resp = p.phase === "response", ta = w.body.querySelector("#pb");
    const e = { headers: ui.kvRead(w.body, "phd") };
    if (ta.value !== w.data.orig.body && !ta.readOnly) e.body = ta.value;     // an untouched body passes through byte for byte
    if (resp) e.status = Number(w.body.querySelector("#pst").value);
    else { e.method = w.body.querySelector("#pm").value; e.url = w.body.querySelector("#pu").value; }
    return e;
  }
  function isDirty(w) {
    const p = w.data.p, resp = p.phase === "response", o = w.data.orig;
    if (!w.body.querySelector("#pb")) return false;
    const e = edits(w);
    return e.body !== undefined || JSON.stringify(e.headers) !== o.headers || (resp ? String(e.status) !== o.status : e.method !== o.method || e.url !== o.url);
  }
  async function finish(w, op) {
    const p = w.data.p;
    if (!p || !p.id) return;
    if (op === "paused_continue" && w.data.sub === "form" && !applyForm(w)) return;
    if (op === "paused_continue" && w.body.querySelector("#pst")) {
      const s = Number(w.body.querySelector("#pst").value);
      if (!(s >= 100 && s <= 999)) { A.toast("The status must be a number from 100 to 999", true); return; }
    }
    const r = await ui.run(op, { id: p.id, edits: op === "paused_continue" ? edits(w) : undefined },
      op === "paused_continue" ? "Continued with your edits" : op === "paused_skip" ? "Sent unchanged" : "Aborted");
    if (!r) return;
    w.data.p = null;
    const st = await A.api("state").catch(() => null);
    const next = st && (st.paused || []).find((x) => x.id !== p.id && !dismissed.has(x.id));
    if (next) T.open("paused", { id: next.id });
    else T.close("paused", true);
  }
  async function bpOff(w) {
    const p = w.data.p;
    const hits = rules().filter((b) => b.enabled !== false && (!b.method || b.method === p.method) && (() => { try { return new RegExp(b.match).test(p.url); } catch (e) { return false; } })());
    for (const b of hits) await A.api("bp_update", { name: b.name, enabled: false }).catch(() => {});
    let n = 0;
    // the proxy picks the change up within a second: a call let go at its request can still stop at its response
    for (let i = 0; i < 4; i++) {
      n += ((await A.api("paused_resume_all", {}).catch(() => ({}))).resumed || 0);
      await new Promise((ok) => setTimeout(ok, 700));
      if (!(((await A.api("state").catch(() => ({}))).paused || []).length)) break;
    }
    w.data.p = null; T.close("paused", true); A.refresh(); A.toolsChanged();
    A.toast((hits.length ? "Breakpoint off" : "No matching breakpoint found") + (n ? " — resumed " + n + " waiting call(s)" : ""));
  }
})();
