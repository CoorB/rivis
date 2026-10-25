/* Map Local (⌥⌘L): the rule list on the left, the selected rule's response on the right (status, variants, body,
 * headers), as in Proxyman's Map Local window. Right-click a call → Map Local opens it here on that call's response.
 * Ops: maplocal_add {host, path, method, status, literal_query} → {name, existing}; mock {flow_id} → {name, draft |
 * existing}; mockfile_get {name}; mockfile_put {name, status, headers, content?}; mockvariant {name, action, variant,
 * new_name}; toggle {name, enabled}; delete {name}; maplocal_folder_add {name, base, folder}; proxyman_import {}.
 * A rule made from a call is a draft until it is saved: closing it unsaved deletes it, so it never answers a call. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;
  const BIG = 1024 * 1024;          // above this, JSON is checked after typing pauses, not on every key

  const maps = () => (((A.state() || {}).rules) || []).filter((r) => r.action === "map_local");
  const pretty = (r) => {
    if (r.note && /^(from|manual:) /.test(r.note)) return r.note.replace(/^(from|manual:) /, "");
    if (r.base) return r.base + "*";
    return r.match || "";
  };

  T.register("map", {
    title: "Map Local", width: 980, height: 620,
    render(w, opts) {
      w.data.sig = null;
      if (!w.data.built) {
        w.data.built = true;
        w.body.classList.add("rv-win-flush");
        w.body.innerHTML = `<div class="rv-win-bar rv-pad">
            <button type="button" class="rv-btn p" data-ml-new>+ Add Rule</button>
            <button type="button" class="rv-btn" data-ml-folder>Map a Folder…</button>
            <button type="button" class="rv-btn" data-ml-import>Import from Proxyman…</button>
            <span class="rv-win-hint">Faster: right-click a call → Map Local.</span></div>
          <div class="rv-split2 rv-pad-x"><div class="rv-list2" role="listbox" aria-label="Map Local rules" tabindex="0" data-ml-list></div>
            <div class="rv-ml-ed" data-ml-ed></div></div>`;
        wire(w);
      }
      if (opts && opts.name) select(w, opts.name, opts);
      else if (!w.data.name) drawEditor(w);
    },
    onState(st, w) {
      if (!w) return;
      const ms = (st.rules || []).filter((r) => r.action === "map_local");
      const s = JSON.stringify([ms, (st.rule_hits || {}).rules]);
      if (s === w.data.sig) return;
      w.data.sig = s;
      w.setSub(ms.length ? `${ms.filter((r) => r.enabled !== false).length} of ${ms.length} on` : "");
      drawList(w, ms);
      if (w.data.name && !ms.some((r) => r.name === w.data.name) && !(w.data.e && w.data.e.dirty)) { w.data.name = null; w.data.e = null; drawEditor(w); }
    },
    dirty: (w) => !!(w.data.e && changed(w)),
    async closed(w) { await dropDraft(w); w.data.name = null; w.data.e = null; },
  });

  function drawList(w, ms) {
    const box = w.body.querySelector("[data-ml-list]");
    const had = document.activeElement && box.contains(document.activeElement) ? document.activeElement.dataset.mlName || (document.activeElement.dataset.mlOn ? "on:" + document.activeElement.dataset.mlOn : null) : null;
    const hits = ((A.state() || {}).rule_hits || {}).rules || {};
    box.innerHTML = ms.length ? ms.map((r) => {
      const h = hits[r.name], st = ((r.variants || []).find((v) => v.name === r.active) || {}).status || r.status || 200;
      return `<div role="option" tabindex="-1" data-ml-name="${esc(r.name)}" aria-selected="${r.name === w.data.name}">
        <input type="checkbox" data-ml-on="${esc(r.name)}" aria-label="${esc(r.name)} on" ${r.enabled === false ? "" : "checked"}>
        <span class="rv-ml-row"><b class="rv-mono">${esc(pretty(r))}</b>
          <span class="rv-win-hint">${esc(r.method || "Any")} · ${esc(st)}${r.base ? " · folder" : ""}${r.active ? " · " + esc(r.active) : ""}${r.draft ? " · not saved" : ""}${h && h.count ? ` · used ${h.count}×` : ""}</span></span></div>`;
    }).join("") : ui.empty("No Map Local rules", "Right-click a call → Map Local, or + Add Rule.");
    if (had) { const el = had.startsWith("on:") ? box.querySelector(`[data-ml-on="${CSS.escape(had.slice(3))}"]`) : box.querySelector(`[data-ml-name="${CSS.escape(had)}"]`); if (el) el.focus({ preventScroll: true }); }
  }

  function wire(w) {
    const list = w.body.querySelector("[data-ml-list]");
    list.addEventListener("change", (e) => {
      const c = e.target.closest("[data-ml-on]");
      if (c) ui.run("toggle", { name: c.dataset.mlOn, enabled: c.checked }, c.checked ? "Map Local on" : "Map Local off");
    });
    list.addEventListener("click", (e) => {
      if (e.target.closest("[data-ml-on]")) return;
      const o = e.target.closest("[data-ml-name]");
      if (o) select(w, o.dataset.mlName);
    });
    list.addEventListener("keydown", (e) => {
      if (e.target.closest("[data-ml-on]") && e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      const opts = [...list.querySelectorAll("[data-ml-name]")], i = opts.indexOf(e.target.closest("[data-ml-name]"));
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const n = opts[Math.max(0, Math.min(opts.length - 1, (i < 0 ? -1 : i) + (e.key === "ArrowDown" ? 1 : -1)))];
        if (n) { n.focus(); select(w, n.dataset.mlName, { keepFocus: true }); }
      }
      if ((e.key === "Delete" || e.key === "Backspace") && i >= 0) { e.preventDefault(); remove(w, opts[i].dataset.mlName); }
    });
    w.body.querySelector("[data-ml-new]").onclick = () => newRule(w);
    w.body.querySelector("[data-ml-folder]").onclick = () => folder(w);
    w.body.querySelector("[data-ml-import]").onclick = async () => {
      if (!await A.ask("Import from Proxyman", "Reads Proxyman's Map Local rules on this Mac (its saved rule tree) and adds them to this project.", "Import")) return;
      const r = await ui.run("proxyman_import", {});
      if (r) A.toast(r.summary || "Imported");
    };
  }

  async function select(w, name, opts) {
    if (w.data.name === name && w.data.e) { if (!(opts && opts.keepFocus)) focusEditor(w); return; }
    if (w.data.e && changed(w) && !await A.ask("Leave this response?", "Your changes to " + w.data.name + " are not saved.", "Discard changes", true)) return;
    await dropDraft(w);
    w.data.name = name; w.data.e = null;
    w.body.querySelectorAll("[data-ml-name]").forEach((o) => o.setAttribute("aria-selected", String(o.dataset.mlName === name)));
    try {
      const r = await A.api("mockfile_get", { name });
      if (w.data.name !== name) return;
      w.data.e = Object.assign({ name, sub: "body" }, r, { original: { content: r.content, status: String(r.status), headers: JSON.stringify(r.headers) } });
      drawEditor(w);
      if (!(opts && opts.keepFocus)) focusEditor(w);
    } catch (e) { A.toast(e.message, true); w.data.name = null; drawEditor(w); }
  }
  const focusEditor = (w) => { const ta = w.body.querySelector("#mlbody"); if (ta && !ta.readOnly) ta.focus({ preventScroll: true }); };

  function drawEditor(w) {
    const box = w.body.querySelector("[data-ml-ed]"), e = w.data.e;
    if (!e) { box.innerHTML = ui.empty("Pick a rule", "Its response — status, headers and body — opens here."); return; }
    const variants = e.variants.length ? e.variants : ["Default"];
    box.innerHTML = `
      <div class="rv-ml-head"><b class="rv-mono rv-ell-line" title="${esc(e.match)}">${esc(e.method || "Any")} ${esc(pretty(maps().find((r) => r.name === e.name) || { match: e.match }))}</b>
        <button type="button" class="rv-icon-btn" data-ml-del title="Delete this rule" aria-label="Delete rule ${esc(e.name)}">🗑</button></div>
      ${e.draft ? `<p class="rv-note">New rule from a call: edit the response, then <b>Save</b> to turn it on. Close without saving and it is discarded.</p>` : ""}
      <div class="rv-form"><label>Status <input type="number" id="mlst" min="100" max="999" value="${esc(e.status)}" style="width:84px"></label>
        <label>Variant <select id="mlvar">${variants.map((n) => `<option value="${esc(n)}"${n === (e.active || "Default") ? " selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
        <button type="button" class="rv-lnk" data-mlv="add">Add variant</button><button type="button" class="rv-lnk" data-mlv="rename">Rename</button><button type="button" class="rv-lnk" data-mlv="rm">Delete variant</button></div>
      ${ui.seg("mlsub", [["body", "Body"], ["headers", "Headers"]], e.sub)}
      <div data-mlpane="body"${e.sub === "body" ? "" : " hidden"}>
        ${e.clipped ? `<p class="rv-win-hint">Binary file (${A.fmtBytes(e.size)}): a read-only preview. Save keeps its bytes; status and headers can still change.</p>`
          : e.binary ? `<p class="rv-win-hint">Binary file (${A.fmtBytes(e.size)}) shown as text. Save keeps its bytes unless you edit the text.</p>` : ""}
        <textarea id="mlbody" class="rv-code rv-code-tall" spellcheck="false" aria-label="Response body" ${e.editable && !e.clipped ? "" : "readonly"}></textarea>
        <div class="rv-form"><button type="button" class="rv-btn" data-mlfmt ${e.clipped ? "disabled" : ""}>Format JSON</button><span class="rv-win-hint" data-mljs></span></div></div>
      <div data-mlpane="headers"${e.sub === "headers" ? "" : " hidden"}>${ui.kvHTML(e.headers, "mlhd")}<p class="rv-win-hint">Content-Type follows the file type when it is not set.</p></div>
      <div class="rv-form rv-ml-save"><button type="button" class="rv-btn p" data-mlsave ${e.editable ? "" : "disabled"} title="Save (${A.MOD}S)">Save</button>
        <span class="rv-win-hint" data-mldirty></span><span class="rv-spacer"></span>
        <span class="rv-win-hint rv-ell-line" title="${esc(e.file)}">${e.editable ? "The next matching call gets this." : "This rule reads a file outside Rivis: edit that file in your own editor."}</span></div>`;
    const ta = box.querySelector("#mlbody");
    ta.value = e.content;                         // through .value: a large body through innerHTML would freeze the page
    let t = 0;
    const js = box.querySelector("[data-mljs]");
    const check = () => {
      clearTimeout(t);
      const run = () => { const s = ui.jsonState(ta.value); js.textContent = s === "ok" ? "Valid JSON" : s === "bad" && /json/i.test(ctypeOf(w)) ? "Not valid JSON" : ""; js.className = "rv-win-hint" + (s === "bad" ? " bad" : ""); };
      if (ta.value.length < BIG) run(); else t = setTimeout(run, 400);
    };
    check();
    const dirty = () => { box.querySelector("[data-mldirty]").textContent = changed(w) ? "Modified" : ""; };
    ta.addEventListener("input", () => { check(); dirty(); });
    box.addEventListener("input", (ev) => { if (ev.target !== ta) dirty(); });
    ui.kvWire(box);
    box.querySelectorAll("[data-mlsub]").forEach((b) => (b.onclick = () => {
      e.sub = b.dataset.mlsub;
      box.querySelectorAll("[data-mlpane]").forEach((p) => (p.hidden = p.dataset.mlpane !== e.sub));
      box.querySelectorAll("[data-mlsub]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    }));
    box.querySelector("[data-mlfmt]").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2) + "\n"; check(); dirty(); } catch (x) { A.toast("The body is not JSON", true); } };
    box.querySelector("#mlvar").onchange = () => variant(w, "use", box.querySelector("#mlvar").value);
    box.querySelectorAll("[data-mlv]").forEach((b) => (b.onclick = async () => {
      const cur = e.active || "Default";
      if (b.dataset.mlv === "add") { const n = await prompt("Name the new variant", "It starts as a copy of the current response.", ""); if (n) variant(w, "add", n); }
      if (b.dataset.mlv === "rename") { const n = await prompt("Rename variant " + cur, "", cur); if (n && n !== cur) variant(w, "rename", cur, n); }
      if (b.dataset.mlv === "rm" && await A.ask("Delete variant " + cur + "?", "Its saved file is kept.", "Delete", true)) variant(w, "rm", cur);
    }));
    box.querySelector("[data-ml-del]").onclick = () => remove(w, e.name);
    box.querySelector("[data-mlsave]").onclick = () => save(w);
    box.onkeydown = (ev) => { if ((A.isMac ? ev.metaKey : ev.ctrlKey) && ev.key.toLowerCase() === "s") { ev.preventDefault(); save(w); } };
  }
  const ctypeOf = (w) => { const h = ui.kvRead(w.body, "mlhd").find(([k]) => k.toLowerCase() === "content-type"); return h ? h[1] : (/\.json$/i.test(w.data.e.file || "") ? "json" : ""); };

  function changed(w) {
    const e = w.data.e, ta = w.body.querySelector("#mlbody"), st = w.body.querySelector("#mlst");
    if (!e || !ta || !st) return false;
    return ta.value !== e.original.content || st.value !== e.original.status || JSON.stringify(ui.kvRead(w.body, "mlhd")) !== e.original.headers;
  }

  async function save(w) {
    const e = w.data.e;
    if (!e || !e.editable || w.data.saving) return;
    const ta = w.body.querySelector("#mlbody"), status = Number(w.body.querySelector("#mlst").value), headers = ui.kvRead(w.body, "mlhd");
    if (!(status >= 100 && status <= 999)) { A.toast("The status must be a number from 100 to 999", true); return; }
    if (/json/i.test(ctypeOf(w)) && ui.jsonState(ta.value) === "bad" && !await A.ask("This is not valid JSON", "Save it anyway? The app gets exactly this text.", "Save anyway")) return;
    const body = { name: e.name, status, headers };
    if (ta.value !== e.original.content) body.content = ta.value;      // an unchanged body is not sent again (large files)
    w.data.saving = true;
    try {
      await A.api("mockfile_put", body);
      e.draft = false;
      e.original = { content: ta.value, status: String(status), headers: JSON.stringify(headers) };
      e.content = ta.value; e.status = status; e.headers = headers;
      w.body.querySelector("[data-mldirty]").textContent = "";
      const note = w.body.querySelector(".rv-note"); if (note) note.remove();
      A.toast("Saved — the next matching call gets it"); A.refresh(); A.toolsChanged();
    } catch (x) { A.toast(x.message, true); }
    finally { w.data.saving = false; }
  }

  async function variant(w, action, v, newName) {
    const e = w.data.e;
    if (changed(w)) { A.toast("Save or undo your edits before changing variants", true); w.body.querySelector("#mlvar").value = e.active || "Default"; return; }
    try { await A.api("mockvariant", { name: e.name, action, variant: v, new_name: newName }); const n = e.name; w.data.e = null; w.data.name = null; await select(w, n); A.refresh(); }
    catch (x) { A.toast(x.message, true); w.body.querySelector("#mlvar").value = e.active || "Default"; }
  }

  async function remove(w, name) {
    if (!await A.ask("Delete Map Local " + name + "?", "Matching calls go to the real server again. The saved response file is kept.", "Delete", true)) return;
    const r = await ui.run("delete", { name });
    if (!r) return;
    A.toast(r.message || "Deleted " + name);
    if (w.data.name === name) { w.data.name = null; w.data.e = null; drawEditor(w); }
  }

  async function dropDraft(w) {
    const e = w.data.e;
    if (e && e.draft) { try { await A.api("delete", { name: e.name }); A.toast("Map Local " + e.name + " discarded (never saved)"); A.refresh(); } catch (x) { /* already gone */ } }
  }

  // small in-window forms: a new rule, a folder
  function sheet(w, html, onOk) {
    let s = w.el.querySelector(".rv-sheet");
    if (!s) { s = document.createElement("div"); s.className = "rv-sheet"; w.el.appendChild(s); }
    s.innerHTML = `<form class="rv-sheet-in">${html}<div class="rv-form"><span class="rv-spacer"></span><button type="button" class="rv-btn" data-sh-cancel>Cancel</button><button type="submit" class="rv-btn p">Add</button></div><p class="rv-win-hint bad" data-sh-err role="alert"></p></form>`;
    s.hidden = false;
    const f = s.querySelector("form");
    const close = () => { s.hidden = true; s.innerHTML = ""; };
    s.querySelector("[data-sh-cancel]").onclick = close;
    f.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); } });
    f.onsubmit = async (e) => { e.preventDefault(); try { if (await onOk(f)) close(); } catch (x) { s.querySelector("[data-sh-err]").textContent = x.message; } };
    const first = f.querySelector("input, select"); if (first) first.focus();
  }
  function newRule(w) {
    sheet(w, `<h4>New Map Local rule</h4>
      <div class="rv-form"><label class="grow">URL <input type="text" name="url" spellcheck="false" placeholder="https://api.example.com/v1/accounts/*" required></label></div>
      <div class="rv-form"><label>Method ${ui.methodSelect("mlnm", "", "Any")}</label><label>Status <input type="number" name="status" value="200" min="100" max="999" style="width:84px"></label>
        <span class="rv-win-hint">* matches anything, ? one character. A full URL with a query matches that query exactly.</span></div>`,
    async (f) => {
      const url = f.url.value.trim();
      if (!url) throw new Error("Enter the URL to answer");
      const parts = ui.splitUrl(url);
      const r = await A.api("maplocal_add", Object.assign(parts, { method: f.querySelector("#mlnm").value, status: f.status.value, literal_query: /\?[^#]*=/.test(url) }));
      A.toast(r.existing ? "Map Local " + r.name + " already exists — opened it" : "Map Local " + r.name + " added: edit its response");
      A.refresh(); A.toolsChanged();
      select(w, r.name);
      return true;
    });
  }
  function folder(w) {
    sheet(w, `<h4>Map a folder</h4><p class="rv-win-hint">Every call under the URL is answered from the file at the same path in the folder (like Proxyman's Map Local folder).</p>
      <div class="rv-form"><label class="grow">Name <input type="text" name="name" placeholder="neo-sit-mocks" required></label></div>
      <div class="rv-form"><label class="grow">URL prefix <input type="text" name="base" spellcheck="false" placeholder="https://api.example.com/v1/" required></label></div>
      <div class="rv-form"><label class="grow">Folder <input type="text" name="folder" spellcheck="false" placeholder="~/mocks/neo" required></label></div>`,
    async (f) => {
      await A.api("maplocal_folder_add", { name: f.name.value.trim(), base: f.base.value.trim(), folder: f.folder.value.trim() });
      A.toast("Map Local folder added"); A.refresh(); A.toolsChanged();
      return true;
    });
  }
  function prompt(title, text, value) {
    return new Promise((resolve) => {
      const d = A.$("dialog"), sc = A.$("scrim"), back = document.activeElement;
      d.innerHTML = `<h3>${esc(title)}</h3>${text ? `<p>${esc(text)}</p>` : ""}<form><input type="text" id="pv" style="width:100%;height:30px;margin-bottom:12px" value="${esc(value)}">
        <div class="rv-btns"><button type="button" class="rv-btn" id="pno">Cancel</button><button type="submit" class="rv-btn p">OK</button></div></form>`;
      d.hidden = sc.hidden = false;
      const done = (v) => { d.hidden = sc.hidden = true; if (back && back.focus) back.focus(); resolve(v); };
      d.querySelector("form").onsubmit = (e) => { e.preventDefault(); done(d.querySelector("#pv").value.trim() || null); };
      d.querySelector("#pno").onclick = () => done(null);
      d.onkeydown = (e) => { if (e.key === "Escape") { e.stopPropagation(); done(null); } };
      d.querySelector("#pv").select();
    });
  }

  // Map Local from a call (right-click, ⌥⌘L with a call selected in the list)
  window.RivisMapLocal = Object.freeze({
    async fromFlow(id) {
      try {
        const r = await A.api("mock", { flow_id: id, draft: true });   // a draft until its first Save, as in the classic panel
        A.refresh(); A.toolsChanged();
        T.open("map", { name: r.name });
        A.toast(r.existing ? "Opened the Map Local rule that already answers this call" : "Edit the response, then Save to turn it on");
      } catch (e) { A.toast(e.message, true); }
    },
  });
})();
