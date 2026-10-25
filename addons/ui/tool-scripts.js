/* Scripting: per-project scripts, their source, and the last run or syntax error. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;
  const methods = ["", "GET", "POST", "PUT", "PATCH", "DELETE"];
  const templates = [["header", "Request header"], ["json", "JSON response field"], ["mock", "Local mock"],
    ["latency", "Endpoint latency"], ["token", "Log token refresh"]];
  const scripts = () => (A.state() || {}).scripts || [];
  const status = () => (A.state() || {}).script_status || {};
  const sig = (st) => JSON.stringify([st.scripts, st.script_status]);
  const options = (items, selected) => items.map(([value, label]) =>
    `<option value="${esc(value)}"${value === selected ? " selected" : ""}>${esc(label)}</option>`).join("");
  const methodOptions = (selected) => options(methods.map((m) => [m, m || "Any method"]), selected || "");
  const errorHTML = (error) => error ? `<div class="rv-win-err" role="alert"><b>${esc(error.phase || "Script error")}</b>: ${esc(error.message || error)}`
    + `${error.time ? ` · ${esc(error.time)}` : ""}${error.traceback ? `<pre class="rv-mono">${esc(error.traceback)}</pre>` : ""}</div>` : "";

  T.register("scripts", {
    title: "Scripting", width: 900, height: 580,
    render(w) {
      w.data.sig = null;
      w.body.innerHTML = `<div class="rv-split2"><div class="rv-list2"><div class="rv-win-bar">
          <button type="button" class="rv-btn p" data-script-new>+ New</button></div>
          <div data-script-list></div></div><div data-script-editor></div></div>`;
      w.body.onclick = async (e) => {
        const add = e.target.closest("[data-script-new]");
        if (add) { if (await mayLeave(w)) newScript(w); return; }
        const del = e.target.closest("[data-script-del]");
        if (del) { await deleteScript(w, del.dataset.scriptDel); return; }
        const save = e.target.closest("[data-script-save]");
        if (save) { await saveScript(w); return; }
        const row = e.target.closest("[data-script-open]");
        if (row && !e.target.closest("input, button, select")) await selectScript(w, row.dataset.scriptOpen);
      };
      w.body.onkeydown = (e) => {
        const row = e.target.closest("[data-script-open]");
        if (row && e.target === row && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault(); selectScript(w, row.dataset.scriptOpen);
        }
        if ((A.isMac ? e.metaKey : e.ctrlKey) && e.key === "Enter" && w.data.edit) {
          e.preventDefault(); saveScript(w);
        }
      };
      w.body.onchange = async (e) => {
        const c = e.target.closest("[data-script-on]");
        if (c) {
          const enabled = c.checked;
          if (!await ui.run("script_toggle", { file: c.dataset.scriptOn, enabled }, enabled ? "Script on" : "Script off")) c.checked = !enabled;
          return;
        }
        const field = e.target.dataset.scriptField, ed = w.data.edit;
        if (field && ed) { ed[field] = e.target.value; ed.dirty = true; }
      };
      w.body.oninput = (e) => {
        const ed = w.data.edit;
        if (!ed || !e.target.closest("[data-script-editor]")) return;
        const field = e.target.dataset.scriptField;
        if (field) { ed[field] = e.target.value; ed.dirty = true; }
      };
      drawEditor(w);
    },
    onState(st, w) {
      if (!w) return;
      const s = sig(st);
      if (s === w.data.sig) return;
      w.data.sig = s;
      const rows = st.scripts || [], errors = (st.script_status || {}).errors || {};
      w.setSub(`${rows.length} script${rows.length === 1 ? "" : "s"} · ${rows.filter((x) => x.enabled !== false).length} on`);
      const list = w.body.querySelector("[data-script-list]");
      const active = document.activeElement;
      const focus = active && list.contains(active) ? { action: active.dataset.scriptOn ? "on" : active.dataset.scriptDel ? "del" : "open",
        file: active.dataset.scriptOn || active.dataset.scriptDel || active.dataset.scriptOpen } : null;
      list.innerHTML = rows.length ? rows.map((x) => `<div role="option" tabindex="0" data-script-open="${esc(x.file)}"
          aria-selected="${!!(w.data.edit && w.data.edit.file === x.file)}">
          <input type="checkbox" data-script-on="${esc(x.file)}" aria-label="${esc(x.name)} on"${x.enabled === false ? "" : " checked"}>
          <span class="rv-spacer"><b>${esc(x.name)}</b> <span class="rv-badge">${esc(x.lang)}</span>
            ${errors[x.file] ? `<span class="rv-badge warn" data-script-error-badge title="${esc(errors[x.file].message || errors[x.file])}">Error</span>` : ""}
            ${x.exists === false ? `<span class="rv-badge warn">File missing</span>` : ""}<br>
            <span class="rv-win-hint">${esc(x.method || "Any method")} · ${esc(x.match || ".")}</span></span>
          <button type="button" class="rv-icon-btn" data-script-del="${esc(x.file)}" aria-label="Delete ${esc(x.name)}">✕</button></div>`).join("")
        : ui.empty("No scripts yet", "Choose a template and create one. Enabled scripts run after rules, in filename order.");
      if (focus && focus.file) {
        const attr = focus.action === "on" ? "data-script-on" : focus.action === "del" ? "data-script-del" : "data-script-open";
        const el = list.querySelector(`[${attr}="${CSS.escape(focus.file)}"]`);
        if (el) el.focus({ preventScroll: true });
      }
      refreshScriptErrors(w, st);
      const node = w.body.querySelector("[data-script-node]");
      if (node) {
        const message = (st.script_status || {}).node_message;
        node.hidden = !message;
        node.textContent = message ? message + ". Python scripts still work." : "";
      }
      if (!w.data.initialized) {
        w.data.initialized = true;
        if (rows.length) loadScript(w, rows[0].file);
        else newScript(w);
      }
    },
    dirty: (w) => !!(w.data.edit && w.data.edit.dirty),
    closed(w) { w.data.edit = null; w.data.initialized = false; w.data.loading = null; },
  });

  function refreshScriptErrors(w, st) {
    const errors = (st.script_status || {}).errors || {};
    const msg = w.body.querySelector("[data-script-error]");
    if (msg && w.data.edit && w.data.edit.file) msg.innerHTML = errorHTML(errors[w.data.edit.file]);
    w.body.querySelectorAll("[data-script-open]").forEach((row) => {
      const file = row.dataset.scriptOpen, err = errors[file];
      let badge = row.querySelector("[data-script-error-badge]");
      if (err) {
        if (!badge) {
          badge = document.createElement("span");
          badge.className = "rv-badge warn";
          badge.dataset.scriptErrorBadge = "";
          row.querySelector(".rv-spacer b").after(badge);
        }
        badge.title = err.message || String(err);
        badge.textContent = "Error";
      } else if (badge) badge.remove();
    });
  }

  async function mayLeave(w) {
    return !(w.data.edit && w.data.edit.dirty) || await A.ask("Discard unsaved changes?", "The script edits in this window have not been saved.", "Discard", true);
  }
  async function selectScript(w, file) {
    if (w.data.edit && w.data.edit.file === file) return;
    if (await mayLeave(w)) loadScript(w, file);
  }
  async function loadScript(w, file) {
    const token = {}; w.data.loading = token;
    const pane = w.body.querySelector("[data-script-editor]");
    pane.innerHTML = `<p class="rv-win-hint">Loading script…</p>`;
    try {
      const r = await A.api("script_get", { file });
      if (w.data.loading !== token || !w.shown) return;
      w.data.edit = { kind: "existing", file, name: r.script.name, match: r.script.match || ".",
        method: r.script.method || "", content: r.content || "", dirty: false };
      drawEditor(w);
      w.body.querySelectorAll("[data-script-open]").forEach((x) => x.setAttribute("aria-selected", String(x.dataset.scriptOpen === file)));
      const row = w.body.querySelector(`[data-script-open="${CSS.escape(file)}"]`);
      if (row) row.focus({ preventScroll: true });
    } catch (e) { if (w.data.loading === token) { pane.innerHTML = `<p class="rv-win-err">${esc(e.message)}</p>`; A.toast(e.message, true); } }
  }
  function newScript(w) {
    w.data.loading = null;
    w.data.edit = { kind: "new", name: "", lang: "js", template: "header", match: ".", method: "", dirty: false };
    drawEditor(w);
    w.body.querySelector('[data-script-field="name"]').focus({ preventScroll: true });
  }
  function drawEditor(w) {
    const pane = w.body.querySelector("[data-script-editor]");
    const e = w.data.edit;
    if (!e) { pane.innerHTML = ui.empty("Choose a script", "Select one on the left to edit it."); return; }
    const st = status();
    pane.innerHTML = e.kind === "new" ? `<h4>New script</h4>
      <div class="rv-form"><label class="grow">Name <input type="text" data-script-field="name" value="${esc(e.name)}" placeholder="e.g. add-header" autocomplete="off"></label>
        <label>Language <select data-script-field="lang">${options([["js", "JavaScript"], ["py", "Python"]], e.lang)}</select></label></div>
      <div class="rv-form"><label>Template <select data-script-field="template">${options(templates, e.template)}</select></label>
        <label>Method <select data-script-field="method">${methodOptions(e.method)}</select></label></div>
      <div class="rv-form"><label class="grow">Run on URLs <input type="text" data-script-field="match" value="${esc(e.match)}" spellcheck="false"></label></div>
      <p class="rv-win-hint">The URL pattern is a regular expression; a dot matches every call. Scripts run after rules, with your user rights.</p>
      <div class="rv-form"><button type="button" class="rv-btn p" data-script-save>Create script</button></div>`
      : `<h4>${esc(e.name)} <span class="rv-badge">${esc(e.file)}</span></h4>
      <div class="rv-form"><label class="grow">Run on URLs <input type="text" data-script-field="match" value="${esc(e.match)}" spellcheck="false"></label>
        <label>Method <select data-script-field="method">${methodOptions(e.method)}</select></label></div>
      <p class="rv-win-hint">The URL pattern is a regular expression; a dot matches every call. Changes reload within one second.</p>
      <textarea class="rv-code" data-script-field="content" spellcheck="false" aria-label="Script source">${esc(e.content)}</textarea>
      <div class="rv-form"><button type="button" class="rv-btn p" data-script-save>Save</button>
        <button type="button" class="rv-btn d" data-script-del="${esc(e.file)}">Delete</button></div>
      <h4>Last run / errors</h4><div data-script-error>${errorHTML((st.errors || {})[e.file])}</div>`;
    if (st.node_message) pane.insertAdjacentHTML("afterbegin", `<p class="rv-win-err" data-script-node>${esc(st.node_message)}. Python scripts still work.</p>`);
    else pane.insertAdjacentHTML("afterbegin", `<p class="rv-win-err" data-script-node hidden></p>`);
  }
  async function saveScript(w) {
    const e = w.data.edit;
    if (!e) return;
    if (e.kind === "new") {
      if (!/^[A-Za-z0-9._-]+$/.test(e.name.trim())) { A.toast("Use letters, digits, dots, underscores or hyphens in the name", true); return; }
      const r = await ui.run("script_new", { name: e.name.trim(), lang: e.lang, template: e.template, match: e.match,
        method: e.method }, "Script created");
      if (r) { e.dirty = false; loadScript(w, r.file); }
      return;
    }
    const r = await ui.run("script_put", { file: e.file, match: e.match, method: e.method, content: e.content });
    if (r) {
      e.dirty = false;
      A.toast(r.syntax_error ? "Saved, but it has a syntax error — " + r.syntax_error : "Script saved — hot reloads within 1 s", !!r.syntax_error);
      if (r.syntax_error) {
        const msg = w.body.querySelector("[data-script-error]");
        if (msg) msg.innerHTML = errorHTML({ phase: "syntax", message: r.syntax_error });
      } else {
        const st = A.state();
        if (st) refreshScriptErrors(w, st);
      }
    }
  }
  async function deleteScript(w, file) {
    const item = scripts().find((x) => x.file === file);
    if (!item) return;
    if (w.data.edit && w.data.edit.file === file && !await mayLeave(w)) return;
    if (!await A.ask("Delete script '" + item.name + "' and its source file?", "This removes the script from this project.", "Delete", true)) return;
    if (await ui.run("script_delete", { file }, "Deleted " + file)) {
      if (w.data.edit && w.data.edit.file === file) { w.data.edit = null; drawEditor(w); }
    }
  }
})();
