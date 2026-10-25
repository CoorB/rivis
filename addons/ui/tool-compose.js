/* Edit and Repeat: change a captured request (method, URL, headers, body) and send a copy; the original stays in the
 * list and the copy is added as a new call. Ops: retry_get {flow_id} → {method, url, req_headers, req_body,
 * req_body_editable}; retry {flow_id, edits} → {id}. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;

  T.register("repeat", {
    title: "Edit and Repeat", width: 820, height: 560,
    render(w, opts) {
      const id = opts && opts.fromFlow;
      if (!id) { if (!w.data.p) { w.body.innerHTML = ui.empty("Pick a call", "Right-click a call in the list → Edit and Repeat."); w.foot.hidden = true; } return; }
      if (w.data.p && w.data.id === id) return;
      w.data = { id, p: null, sub: "body" };
      w.body.innerHTML = `<p class="rv-win-hint">Loading…</p>`; w.foot.hidden = true;
      A.api("retry_get", { flow_id: id }).then((p) => { if (w.data.id === id) { w.data.p = p; draw(w); } })
        .catch((e) => { w.body.innerHTML = ui.empty("Cannot repeat this call", esc(e.message)); });
    },
    dirty: (w) => !!(w.data.p && changed(w)),
  });

  function draw(w) {
    const p = w.data.p;
    w.setSub(p.method + " " + p.url);
    w.body.innerHTML = `<p class="rv-win-hint">Sends a copy with your changes. The original stays in the list; the copy appears as a new call.</p>
      <div class="rv-form">${ui.methodSelect("rpm", p.method).replace('<option value="">Any</option>', "")}
        <input type="text" id="rpu" class="grow" aria-label="URL" spellcheck="false" value="${esc(p.url)}"></div>
      ${ui.seg("rpsub", [["body", "Body"], ["headers", "Headers"]], "body")}
      <div data-rppane="body"><textarea id="rpb" class="rv-code" spellcheck="false" aria-label="Request body" placeholder="No body" ${p.req_body_editable ? "" : "readonly"}>${esc(p.req_body)}</textarea>
        <div class="rv-form"><button type="button" class="rv-btn" data-rpfmt>Format JSON</button><span class="rv-win-hint" data-rpjs></span></div></div>
      <div data-rppane="headers" hidden>${ui.kvHTML(p.req_headers, "rph")}</div>`;
    w.foot.hidden = false;
    w.foot.innerHTML = `<span class="rv-spacer"></span><button type="button" class="rv-btn" data-rpcancel>Cancel</button>
      <button type="button" class="rv-btn p" data-rpsend title="Send (${A.MOD}↩)">Send</button>`;
    ui.kvWire(w.body);
    const ta = w.body.querySelector("#rpb"), js = w.body.querySelector("[data-rpjs]");
    const check = () => { const s = ui.jsonState(ta.value); js.textContent = s === "ok" ? "Valid JSON" : ""; };
    check(); ta.oninput = check;
    w.body.querySelectorAll("[data-rpsub]").forEach((b) => (b.onclick = () => {
      w.body.querySelectorAll("[data-rppane]").forEach((x) => (x.hidden = x.dataset.rppane !== b.dataset.rpsub));
      w.body.querySelectorAll("[data-rpsub]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    }));
    w.body.querySelector("[data-rpfmt]").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); check(); } catch (e) { A.toast("The body is not JSON", true); } };
    w.foot.querySelector("[data-rpcancel]").onclick = () => T.close("repeat");
    w.foot.querySelector("[data-rpsend]").onclick = () => send(w);
    w.el.onkeydown = (e) => { if ((A.isMac ? e.metaKey : e.ctrlKey) && e.key === "Enter") { e.preventDefault(); send(w); } };
    w.body.querySelector("#rpu").focus();
  }
  function changed(w) {
    const p = w.data.p, b = w.body;
    if (!b.querySelector("#rpu")) return false;
    return b.querySelector("#rpm").value !== p.method || b.querySelector("#rpu").value !== p.url || b.querySelector("#rpb").value !== p.req_body
      || JSON.stringify(ui.kvRead(b, "rph")) !== JSON.stringify(p.req_headers);
  }
  async function send(w) {
    const p = w.data.p, b = w.body;
    const edits = { method: b.querySelector("#rpm").value, url: b.querySelector("#rpu").value.trim(), headers: ui.kvRead(b, "rph") };
    try { new URL(edits.url); } catch (e) { A.toast("Enter a full URL, starting with http:// or https://", true); return; }
    if (b.querySelector("#rpb").value !== p.req_body && !b.querySelector("#rpb").readOnly) edits.body = b.querySelector("#rpb").value;
    const r = await ui.run("retry", { flow_id: w.data.id, edits }, "Sent — the copy is in the list");
    if (!r) return;
    w.data.p = null;
    T.close("repeat", true);
    if (r.id) setTimeout(() => { if (A.flow(r.id)) A.select(r.id); }, 600);
  }
})();

/* Compose: draft requests, saved requests, variables and generated copies. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;
  const fresh = () => ({ name: "", method: "GET", url: "", query: [], headers: [], body_mode: "none", body: "", form: [], note: "" });
  const parts = (url) => { const plain = url.split("#")[0], at = plain.indexOf("?"); return at < 0 ? [plain, ""] : [plain.slice(0, at), plain.slice(at + 1)]; };
  const dec = (s) => { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch (e) { return s; } };
  const enc = (s) => encodeURIComponent(s).replace(/%7B/gi, "{").replace(/%7D/gi, "}");
  const signature = (st) => JSON.stringify([st.composer, st.codegen_targets]);
  const spec = (d) => ({ method: d.method, url: d.url, query: d.query, headers: d.headers, body_mode: d.body_mode, body: d.body, form: d.form });
  function fromUrl(d) {
    const q = parts(d.url)[1];
    d.query = (q ? q.split("&").filter(Boolean).map((p) => { const at = p.indexOf("="); return [dec(at < 0 ? p : p.slice(0, at)), dec(at < 0 ? "" : p.slice(at + 1)), true]; }) : [])
      .concat(d.query.filter((r) => r[2] === false));
  }
  function toUrl(d) { const on = d.query.filter((r) => r[2] !== false && r[0]); d.url = parts(d.url)[0] + (on.length ? "?" + on.map((r) => enc(r[0]) + "=" + enc(r[1])).join("&") : ""); }
  function load(w, source, name) {
    const d = Object.assign(fresh(), source || {}, { name: name || "" });
    for (const key of ["query", "headers", "form"]) d[key] = (d[key] || []).map((r) => [r[0], r[1], r[2] !== false]);
    if (!d.query.length) fromUrl(d);
    w.data.draft = d; w.data.saved = JSON.stringify(spec(d)); w.data.sub = "params"; w.data.vars = null; w.data.pickName = name || ""; w.data.answerId = null; w.data.result = ""; draw(w);
  }
  T.register("compose", {
    title: "Compose", width: 860, height: 620,
    render(w, opts) {
      if (!w.data.draft) load(w, fresh(), "");
      if (opts && opts.fromFlow && opts.fromFlow !== w.data.flow) {
        w.data.flow = opts.fromFlow;
        A.api("compose_get", { flow_id: opts.fromFlow }).then((r) => { load(w, r.spec, ""); w.data.saved = JSON.stringify(spec(fresh())); }).catch((e) => A.toast(e.message, true));
      } else draw(w);
    },
    onState(st, w) { if (w && signature(st) !== w.data.sig) { w.data.sig = signature(st); draw(w, true); } },
    dirty(w) { return !!(w.data.draft && (JSON.stringify(spec(w.data.draft)) !== w.data.saved || (w.data.vars && w.data.varsDirty))); },
  });
  function rows(w, key) { return key === "vars" ? w.data.vars : w.data.draft[key]; }
  function kv(w, key, labels) {
    return `<div class="rv-kvg" data-compose-kv="${key}">` + rows(w, key).map((r, i) =>
      `<div class="rv-kvr rv-kvr3" data-row="${i}"><input type="checkbox" aria-label="Use ${esc(labels[0])}" ${r[2] !== false ? "checked" : ""}>
      <input type="text" aria-label="${esc(labels[0])}" value="${esc(r[0])}" placeholder="${esc(labels[0])}">
      <input type="text" aria-label="${esc(labels[1])}" value="${esc(r[1])}" placeholder="${esc(labels[1])}">
      <button type="button" class="rv-icon-btn" data-compose-del="${key}" aria-label="Remove ${esc(labels[0])}">✕</button></div>`).join("")
      + `</div><button type="button" class="rv-btn" data-compose-add="${key}">+ Add</button>`;
  }
  function drawSection(w) {
    const d = w.data.draft, box = w.body.querySelector("[data-compose-area]"); if (!box) return;
    const sub = w.data.sub;
    if (sub === "params") box.innerHTML = `<p class="rv-win-hint">Params stay in sync with the URL. Untick one to keep it without sending it.</p>` + kv(w, "query", ["Name", "Value"]);
    if (sub === "headers") box.innerHTML = kv(w, "headers", ["Header", "Value"]) + `<div class="rv-form"><button type="button" class="rv-btn" data-compose-token>Use latest token for this host</button></div><p class="rv-win-hint">Adds Authorization: Bearer {{token}} from the newest token seen for this host.</p>`;
    if (sub === "vars") {
      if (!w.data.vars) w.data.vars = Object.entries(((A.state() || {}).composer || {}).vars || {}).map(([k, v]) => [k, v, true]);
      box.innerHTML = `<p class="rv-win-hint">Use {{name}} in the URL, headers, params and body. Saved for this project.</p>` + kv(w, "vars", ["Name", "Value"]) + `<button type="button" class="rv-btn p" data-compose-vars>Save variables</button>`;
    }
    if (sub === "body") {
      box.innerHTML = ui.seg("compose-mode", [["none", "None"], ["json", "JSON"], ["form", "Form"], ["raw", "Raw"]], d.body_mode)
        + (d.body_mode === "form" ? kv(w, "form", ["Field", "Value"]) : d.body_mode === "none" ? `<p class="rv-win-hint">No request body.</p>`
          : `<textarea class="rv-code" data-compose-body aria-label="Request body" spellcheck="false">${esc(d.body)}</textarea>${d.body_mode === "json" ? `<div class="rv-form"><button type="button" class="rv-btn" data-compose-pretty>Pretty-print</button><span class="rv-win-hint" data-compose-json></span></div>` : ""}`);
    }
    box.onclick = async (e) => {
      const b = e.target.closest("button"); if (!b) return;
      if (b.dataset.composeMode) { d.body_mode = b.dataset.composeMode; drawSection(w); return; }
      if (b.dataset.composeAdd) { rows(w, b.dataset.composeAdd).push(["", "", true]); if (b.dataset.composeAdd === "vars") w.data.varsDirty = true; drawSection(w); box.querySelector(`[data-compose-kv="${b.dataset.composeAdd}"] .rv-kvr:last-child input[type=text]`).focus(); return; }
      if (b.dataset.composeDel) { rows(w, b.dataset.composeDel).splice(Number(b.closest("[data-row]").dataset.row), 1); if (b.dataset.composeDel === "query") { toUrl(d); w.body.querySelector("[data-compose-url]").value = d.url; } if (b.dataset.composeDel === "vars") w.data.varsDirty = true; drawSection(w); return; }
      if (b.hasAttribute("data-compose-pretty")) { try { d.body = JSON.stringify(JSON.parse(d.body), null, 2); drawSection(w); } catch (err) { box.querySelector("[data-compose-json]").textContent = "Not JSON: " + err.message; } return; }
      if (b.hasAttribute("data-compose-vars")) { const vars = {}; w.data.vars.forEach(([k, v]) => { if (k.trim()) vars[k.trim()] = v; }); if (await ui.run("compose_vars", { vars }, "Variables saved")) { w.data.varsDirty = false; w.data.vars = null; } return; }
      if (b.hasAttribute("data-compose-token")) await token(w);
    };
    box.oninput = (e) => {
      if (e.target.matches("[data-compose-body]")) { d.body = e.target.value; return; }
      const row = e.target.closest("[data-row]"); if (!row) return;
      const key = row.closest("[data-compose-kv]").dataset.composeKv, index = Number(row.dataset.row), inputs = row.querySelectorAll("input");
      rows(w, key)[index] = [inputs[1].value, inputs[2].value, inputs[0].checked];
      if (key === "query") { toUrl(d); w.body.querySelector("[data-compose-url]").value = d.url; }
      if (key === "vars") w.data.varsDirty = true;
    };
  }
  async function token(w) {
    const d = w.data.draft, vars = ((A.state() || {}).composer || {}).vars || {};
    const base = parts(d.url)[0].replace(/{{\s*([A-Za-z_][\w.-]*)\s*}}/g, (_, name) => vars[name] ?? "");
    let host; try { host = new URL(base).hostname; } catch (e) { A.toast("Enter the URL first — the token is looked up by host", true); return; }
    const t = await ui.run("compose_token", { host }); if (!t) return;
    d.headers = d.headers.filter((h) => String(h[0]).toLowerCase() !== "authorization").concat([["Authorization", "Bearer {{token}}", true]]);
    if (await ui.run("compose_vars", { vars: { ...vars, token: t.token } }, `Using the latest token for ${host} as {{token}}`)) { w.data.vars = null; drawSection(w); }
  }
  function draw(w, stateOnly) {
    const d = w.data.draft, st = A.state() || {}, names = (st.composer || {}).names || [];
    if (stateOnly && w.body.contains(document.activeElement)) {
      const chosen = w.body.querySelector("[data-compose-saved]");
      if (chosen) { const old = chosen.value; chosen.innerHTML = `<option value="">Saved requests…</option>` + names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join(""); chosen.value = old; }
      const target = w.body.querySelector("[data-compose-target]");
      if (target) { const old = target.value; target.innerHTML = (st.codegen_targets || []).map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join(""); if ([...target.options].some((x) => x.value === old)) target.value = old; }
      return;
    }
    w.setSub((d.name ? d.name + " · " : "") + (d.method || "GET") + (d.url ? " " + d.url : " new request"));
    w.body.innerHTML = `<div class="rv-form"><select data-compose-saved aria-label="Saved requests"><option value="">Saved requests…</option>${names.map((n) => `<option value="${esc(n)}" ${n === (w.data.pickName || d.name) ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
      <button type="button" class="rv-btn" data-compose-action="load">Load</button><button type="button" class="rv-btn" data-compose-action="new">New</button><button type="button" class="rv-btn" data-compose-action="selected">From selected call</button><button type="button" class="rv-btn" data-compose-action="paste">Paste cURL…</button></div>
      <div class="rv-form"><button type="button" class="rv-btn" data-compose-action="save">Save</button><button type="button" class="rv-btn" data-compose-action="saveas">Save as…</button>
      <button type="button" class="rv-btn" data-compose-action="rename" ${names.includes(d.name) ? "" : "disabled"}>Rename</button><button type="button" class="rv-btn" data-compose-action="delete" ${names.includes(d.name) ? "" : "disabled"}>Delete</button></div>
      ${d.note ? `<p class="rv-win-hint">${esc(d.note)}</p>` : ""}${(st.composer || {}).error ? `<p class="rv-win-err">${esc(st.composer.error)}</p>` : ""}
      <div class="rv-form"><input type="text" data-compose-method list="compose-methods" aria-label="Method" value="${esc(d.method)}" spellcheck="false">
      <datalist id="compose-methods">${ui.methods.slice(1).map((m) => `<option value="${m}"></option>`).join("")}</datalist>
      <input type="text" class="grow" data-compose-url aria-label="URL" placeholder="https://host/path?x=1 or {{edge}}/path" value="${esc(d.url)}" spellcheck="false"><button type="button" class="rv-btn p" data-compose-action="send">Send</button></div>
      ${ui.seg("compose-tab", [["params", "Params"], ["headers", "Headers"], ["body", "Body"], ["vars", "Variables"]], w.data.sub)}
      <div data-compose-area></div><p class="rv-win-hint">Runs through your rules and scripts. The call appears in the list tagged COMPOSED.</p>
      <div data-compose-result>${w.data.result || ""}</div>
      <h4>Copy as</h4><div class="rv-form"><select data-compose-target aria-label="Copy as language">${(st.codegen_targets || []).map((t) => `<option value="${esc(t.id)}" ${t.id === w.data.target ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</select>
      <button type="button" class="rv-btn" data-compose-action="copy">Copy</button><label><input type="checkbox" data-compose-mask ${w.data.mask === false ? "" : "checked"}> Mask secrets</label></div>
      ${noteMask(w.data.mask !== false)}`;
    drawSection(w);
    w.body.querySelector("[data-compose-method]").oninput = (e) => { d.method = e.target.value.trim().toUpperCase(); };
    w.body.querySelector("[data-compose-saved]").onchange = (e) => { w.data.pickName = e.target.value; };
    w.body.querySelector("[data-compose-target]").onchange = (e) => { w.data.target = e.target.value; };
    w.body.querySelector("[data-compose-mask]").onchange = (e) => { w.data.mask = e.target.checked; w.body.querySelector("[data-compose-mask-note]").textContent = e.target.checked ? "Tokens, cookies, API keys and passwords are redacted." : "Tokens and cookies will be included; keep this out of tickets and chats."; };
    w.body.querySelector("[data-compose-url]").oninput = (e) => { d.url = e.target.value; fromUrl(d); if (w.data.sub === "params") drawSection(w); w.setSub((d.method || "GET") + " " + d.url); };
    w.body.querySelectorAll("[data-compose-tab]").forEach((b) => b.onclick = () => { w.data.sub = b.dataset.composeTab; w.body.querySelectorAll("[data-compose-tab]").forEach((x) => x.setAttribute("aria-selected", String(x === b))); drawSection(w); });
    w.body.querySelectorAll("[data-compose-action]").forEach((b) => b.onclick = () => action(w, b.dataset.composeAction));
    w.el.onkeydown = (e) => { if ((A.isMac ? e.metaKey : e.ctrlKey) && e.key === "Enter") { e.preventDefault(); action(w, "send"); } };
  }
  const noteMask = (mask) => `<p class="rv-win-hint" data-compose-mask-note>${mask ? "Tokens, cookies, API keys and passwords are redacted." : "Tokens and cookies will be included; keep this out of tickets and chats."}</p>`;
  async function nameInPage(title, value) {
    const box = document.createElement("form"); box.className = "rv-editor";
    box.innerHTML = `<label>${esc(title)} <input type="text" required value="${esc(value || "")}" aria-label="Name"></label> <button class="rv-btn p" type="submit">Continue</button> <button class="rv-btn" type="button">Cancel</button>`;
    const w = T.win("compose"); w.body.prepend(box); const input = box.querySelector("input"); input.focus();
    return new Promise((resolve) => { box.onsubmit = (e) => { e.preventDefault(); const v = input.value.trim(); box.remove(); resolve(v); }; box.querySelector("[type=button]").onclick = () => { box.remove(); resolve(null); }; box.onkeydown = (e) => { if (e.key === "Escape") { e.stopPropagation(); box.remove(); resolve(null); } }; });
  }
  async function action(w, kind) {
    const d = w.data.draft, st = A.state() || {}, names = (st.composer || {}).names || [];
    if (kind === "new") { if (T.win("compose").def.dirty(w) && !await A.ask("Start a new request?", "Unsaved changes in this draft will be lost.", "New request", true)) return; load(w, fresh(), ""); return; }
    if (kind === "selected") { const f = A.selected(); if (!f) { A.toast("Select a call in the list first", true); return; } if (T.win("compose").def.dirty(w) && !await A.ask("Compose from selected call?", "Unsaved changes in this draft will be lost.", "Use call", true)) return;
      try { const r = await A.api("compose_get", { flow_id: f.id }); load(w, r.spec, ""); w.data.saved = JSON.stringify(spec(fresh())); } catch (e) { A.toast(e.message, true); } return; }
    if (kind === "paste") {
      const command = await textInPage(w, "Paste cURL command"); if (!command) return;
      try { const r = await A.api("compose_from_curl", { command }); load(w, r.spec, ""); w.data.saved = JSON.stringify(spec(fresh())); A.toast((r.ignored || []).length ? "Ignored: " + r.ignored.join(", ") : "cURL loaded into Compose"); } catch (e) { A.toast(e.message, true); }
      return;
    }
    if (kind === "load") {
      const name = w.body.querySelector("[data-compose-saved]").value; if (!name) { A.toast("Pick a saved request first", true); return; }
      if (T.win("compose").def.dirty(w) && !await A.ask("Load " + name + "?", "Unsaved changes in this draft will be lost.", "Load", true)) return;
      const r = await ui.run("compose_load", { name }); if (r) load(w, r.spec, name); return;
    }
    if (kind === "save" || kind === "saveas") {
      const name = kind === "save" && d.name ? d.name : await nameInPage("Save as", d.name); if (!name) return;
      const exists = names.includes(name);
      if (exists && name !== d.name && !await A.ask("Replace " + name + "?", "The saved request with this name will be replaced.", "Replace", true)) return;
      if (await ui.run("compose_save", { name, spec: spec(d), overwrite: exists }, "Saved " + name)) { d.name = name; w.data.saved = JSON.stringify(spec(d)); draw(w); } return;
    }
    if (kind === "rename") { const next = await nameInPage("New name", d.name); if (!next || next === d.name) return; if (await ui.run("compose_rename", { old: d.name, new: next }, "Renamed to " + next)) { d.name = next; draw(w); } return; }
    if (kind === "delete") { if (await A.ask("Delete saved request " + d.name + "?", "The saved request will be removed.", "Delete", true) && await ui.run("compose_delete", { name: d.name }, "Deleted " + d.name)) { d.name = ""; draw(w); } return; }
    if (kind === "send") { const r = await ui.run("compose_send", { spec: spec(d) }); if (r) { A.toast("Sent " + r.method + " " + r.url + " — it is in the list, tagged COMPOSED"); showAnswer(w, r.id); } return; }
    if (kind === "copy") {
      const target = w.body.querySelector("[data-compose-target]").value, mask = w.body.querySelector("[data-compose-mask]").checked;
      const r = await ui.run("codegen", { spec: spec(d), target, mask }); if (!r) return;
      try { await navigator.clipboard.writeText(r.text); A.toast("Copied as " + target + (mask ? " (secrets masked)" : " — contains secrets!")); }
      catch (e) { await textInPage(w, "Copy this text", r.text, true); }
    }
  }
  async function showAnswer(w, id) {
    w.data.answerId = id;
    w.data.result = '<h4>Answer</h4><p class="rv-win-hint">Waiting for the response…</p>';
    const box = w.body.querySelector("[data-compose-result]"); if (box) box.innerHTML = w.data.result;
    for (let i = 0; i < 100; i++) {
      if (w.data.answerId !== id) return;
      const f = A.flow(id);
      if (f && (f.response || f.error)) {
        let answer = f.error ? f.error.msg : "";
        if (f.response) {
          try { const res = await fetch("../flows/" + encodeURIComponent(id) + "/response/content.data"); if (res.ok) answer = (await res.text()).slice(0, 65536); }
          catch (e) { answer = e.message; }
        }
        if (w.data.answerId !== id) return;
        w.data.result = `<h4>Answer${f.response ? " · " + esc(f.response.status_code) : ""}</h4><pre class="rv-code">${esc(answer)}</pre>`;
        const current = w.body.querySelector("[data-compose-result]"); if (current) current.innerHTML = w.data.result;
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (w.data.answerId !== id) return;
    w.data.result = '<h4>Answer</h4><p class="rv-win-hint">The response is still pending. Find the call in the list.</p>';
    const current = w.body.querySelector("[data-compose-result]"); if (current) current.innerHTML = w.data.result;
  }
  function textInPage(w, title, value, readonly) {
    const box = document.createElement("div"); box.className = "rv-editor";
    box.innerHTML = `<label>${esc(title)}<textarea class="rv-code" aria-label="${esc(title)}" ${readonly ? "readonly" : ""}>${esc(value || "")}</textarea></label><div class="rv-form"><button type="button" class="rv-btn p" data-done>${readonly ? "Done" : "Import"}</button><button type="button" class="rv-btn" data-cancel>Cancel</button></div>`;
    w.body.prepend(box); const area = box.querySelector("textarea"); area.focus();
    return new Promise((resolve) => { const done = (v) => { box.remove(); resolve(v); }; box.querySelector("[data-done]").onclick = () => done(readonly ? null : area.value); box.querySelector("[data-cancel]").onclick = () => done(null); box.onkeydown = (e) => { if (e.key === "Escape") { e.stopPropagation(); done(null); } }; });
  }
})();
