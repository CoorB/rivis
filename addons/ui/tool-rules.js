/* Map Remote and the other rewrite rules (⌥⌘R; Block List ⌥⌘X): one window with a type filter, the rule list and
 * an editor, like Proxyman's Map Remote / Block List windows. Map Local and Breakpoint have their own windows.
 * Ops: add {rule}, update {name, rule, keys}, toggle {name, enabled}, delete {name}, rule_test {flow_id}.
 * State: rules, rules_error, skipped_rules, rule_warnings, rules_outside, rule_hits, rules_file. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;

  const TYPES = [["map_remote", "Map Remote"], ["block", "Block List"], ["respond", "Fixed reply"], ["status", "Force status"],
    ["json_patch", "Edit JSON"], ["delay", "Delay"], ["set_header", "Header"]];
  const KEYS = { respond: ["status", "body"], status: ["status"], json_patch: ["set"], delay: ["ms"], set_header: ["side", "header", "value"], map_remote: ["replace", "with"], block: [] };
  const typeName = (a) => (TYPES.find((t) => t[0] === a) || [])[1] || (a === "drop" ? "Block List" : a);
  const isOurs = (r) => r.action !== "map_local";
  const describe = (r) => {
    const a = r.action;
    if (a === "respond") return "answers " + r.status + " without calling the server";
    if (a === "status") return "changes the status to " + r.status;
    if (a === "delay") return "waits " + r.ms + " ms first";
    if (a === "json_patch") return "changes " + Object.keys(r.set || {}).join(", ") + " in the JSON reply";
    if (a === "set_header") return (r.value == null ? "removes the " : "sets the ") + r.header + " header on the " + (r.side === "response" ? "response" : "request");
    if (a === "map_remote") return "sends it to " + r.with;
    if (a === "block" || a === "drop") return "blocks the call (the app gets a network error)";
    return a;
  };
  const ago = (t) => { const d = Math.max(0, Date.now() / 1000 - t); return d < 5 ? "just now" : d < 60 ? Math.round(d) + " s ago" : d < 3600 ? Math.round(d / 60) + " min ago" : Math.round(d / 3600) + " h ago"; };

  T.register("rules", {
    title: "Map Remote & Rules", width: 940, height: 600,
    render(w, opts) {
      w.data.sig = null;
      if (opts && opts.type) w.data.type = opts.type;
      w.data.type = w.data.type || "map_remote";
      w.body.innerHTML = `<div data-r-warn></div>
        <div class="rv-win-bar">${ui.seg("rtype", [["all", "All"], ...TYPES], w.data.type)}<span class="rv-spacer"></span>
          <button type="button" class="rv-btn p" data-r-new>+ Add Rule</button></div>
        <div data-r-list></div><div class="rv-editor" data-r-ed hidden></div>
        <div class="rv-form rv-r-test"><button type="button" class="rv-btn" data-r-test>Test against the selected call</button><span class="rv-win-hint" data-r-testhint></span></div>
        <div data-r-testout aria-live="polite"></div>
        <p class="rv-win-hint" data-r-file></p>`;
      w.body.querySelectorAll("[data-rtype]").forEach((b) => (b.onclick = () => {
        w.data.type = b.dataset.rtype; w.data.sig = null;
        w.body.querySelectorAll("[data-rtype]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
        T.win("rules").def.onState(A.state(), w);
      }));
      w.body.querySelector("[data-r-new]").onclick = () => edit(w, null);
      w.body.querySelector("[data-r-test]").onclick = () => test(w);
      w.body.addEventListener("change", (e) => {
        const c = e.target.closest("[data-r-on]");
        if (c) ui.run("toggle", { name: c.dataset.rOn, enabled: c.checked }, c.checked ? "Rule on" : "Rule off");
      });
      w.body.addEventListener("click", async (e) => {
        const ed = e.target.closest("[data-r-edit]");
        if (ed) edit(w, rules().find((r) => r.name === ed.dataset.rEdit));
        const del = e.target.closest("[data-r-del]");
        if (del && await A.ask("Delete rule " + del.dataset.rDel + "?", "", "Delete", true)) {
          const r = await ui.run("delete", { name: del.dataset.rDel });
          if (r) A.toast(r.message || "Deleted " + del.dataset.rDel);
        }
      });
      if (opts && opts.new) edit(w, null, opts.new, opts.preset);
    },
    onState(st, w) {
      if (!w) return;
      const s = JSON.stringify([w.data.type, st.rules, st.rules_error, st.skipped_rules, st.rule_warnings, st.rules_outside, (st.rule_hits || {}).rules, !!A.selected()]);
      if (s === w.data.sig) return;
      w.data.sig = s;
      const all = (st.rules || []).filter(isOurs), shown = all.filter((r) => w.data.type === "all" || r.action === w.data.type || (w.data.type === "block" && r.action === "drop"));
      w.setSub(`${all.filter((r) => r.enabled !== false).length} of ${all.length} rules on`);
      const skipped = st.skipped_rules || [];
      w.body.querySelector("[data-r-warn]").innerHTML = (st.rules_error ? `<div class="rv-alert bad"><b>rules.json has an error:</b> ${esc(st.rules_error)}</div>` : "")
        + (skipped.length ? `<div class="rv-alert bad"><b>${skipped.length} rule(s) skipped</b>${skipped.map((r) => `<div>${esc(r.name)} — ${esc(r.error)}</div>`).join("")}</div>` : "");
      const hits = (st.rule_hits || {}).rules || {}, warn = st.rule_warnings || {}, outside = st.rules_outside || [];
      const list = w.body.querySelector("[data-r-list]");
      const had = document.activeElement && list.contains(document.activeElement) ? [...document.activeElement.attributes].find((a) => /^data-r-(on|edit|del)$/.test(a.name)) : null;
      const hadSel = had ? `[${had.name}="${CSS.escape(had.value)}"]` : null;
      list.innerHTML = shown.length ? `<table class="rv-rtable rv-rtable-rules"><thead><tr><th>On</th><th>Method</th><th>URL</th><th>Does</th><th></th></tr></thead><tbody>`
        + shown.map((r) => {
          const h = r.enabled !== false && hits[r.name];
          const hit = !h ? "" : h.count > 0 ? `<div class="rv-win-hint">matched ${h.count}× · last ${ago(h.last)}${h.noop ? ` · ${h.noop} without changing anything` : ""}</div>`
            : h.noop > 0 ? `<div class="rv-win-hint bad">matched ${h.noop}× but changed nothing — ${esc(h.noop_reason || "")}</div>`
            : h.calls_since >= 10 ? `<div class="rv-win-hint bad">On, but none of the ${h.calls_since} calls since then matched. Select a call it should change and Test.</div>` : "";
          return `<tr${r.enabled === false ? ' class="off"' : ""}><td><input type="checkbox" data-r-on="${esc(r.name)}" aria-label="${esc(r.name)} on" ${r.enabled === false ? "" : "checked"}></td>
            <td>${esc(r.method || "Any")}</td>
            <td class="rv-mono rv-ell" title="${esc(r.match)}"><b>${esc(r.name)}</b> <span class="rv-badge">${esc(typeName(r.action))}</span><div class="rv-ell-line">${esc(r.match)}</div></td>
            <td>${esc(describe(r))}${warn[r.name] ? `<div class="rv-win-hint bad">${esc(warn[r.name])}</div>` : ""}${hit}</td>
            <td class="rv-act">${outside.includes(r.name) ? `<span class="rv-badge warn" title="Reads a file outside the project: edit it in your own editor">external</span>` : `<button type="button" class="rv-lnk" data-r-edit="${esc(r.name)}">Edit</button>`}
              <button type="button" class="rv-icon-btn" data-r-del="${esc(r.name)}" aria-label="Delete rule ${esc(r.name)}">✕</button></td></tr>`;
        }).join("") + `</tbody></table>`
        : ui.empty(w.data.type === "all" ? "No rules yet" : "No " + typeName(w.data.type) + " rules", w.data.type === "map_remote"
          ? "Map Remote sends matching calls to another server, e.g. production → staging." : w.data.type === "block"
          ? "Block List makes matching calls fail, as if the network were down." : "Pick + Add Rule.");
      if (hadSel) { const el = list.querySelector(hadSel); if (el) el.focus({ preventScroll: true }); }
      const sel = A.selected();
      w.body.querySelector("[data-r-test]").disabled = !sel;
      w.body.querySelector("[data-r-testhint]").textContent = sel ? "" : "Select a call in the list first.";
      w.body.querySelector("[data-r-file]").textContent = st.rules_file ? "Saved in " + st.rules_file.replace(st.home || "\u0000", "~") : "";
    },
    dirty: (w) => !!(w.data.edit && w.data.edit.dirty),
  });
  const rules = () => (((A.state() || {}).rules) || []).filter(isOurs);

  function edit(w, it, presetType, preset) {
    const ed = w.body.querySelector("[data-r-ed]");
    const t = it ? (it.action === "drop" ? "block" : it.action) : (presetType || (w.data.type !== "all" ? w.data.type : "map_remote"));
    const v = it || preset || {};      // a preset comes from a call (right-click → Map Remote / Block)
    w.data.edit = { name: it ? it.name : null, dirty: false };
    const row = (label, inner, hint) => `<div class="rv-form"><span class="rv-flabel">${label}</span>${inner}${hint ? `<span class="rv-win-hint">${hint}</span>` : ""}</div>`;
    const txt = (id, val, ph) => `<input type="text" id="${id}" class="grow" spellcheck="false" value="${esc(val == null ? "" : val)}" placeholder="${esc(ph || "")}">`;
    let f = "";
    if (!it) f += row("Type", `<select id="rf-type">${TYPES.map(([id, l]) => `<option value="${id}"${id === t ? " selected" : ""}>${esc(l)}</option>`).join("")}</select>`);
    if (!it) f += row("Name", txt("rf-name", preset && preset.match ? suggestName(preset.match, t) : "", "letters, digits . _ -"));
    f += row("URL", txt("rf-match", v.match, t === "map_remote" ? "^https://api\\.example\\.com/" : "regex on the URL — . matches every call"), "a regex: . any character, .* anything");
    f += row("Method", ui.methodSelect("rf-method", v.method, "Any"));
    if (t === "map_remote") {
      f += row("Replace", txt("rf-replace", v.replace, "https://api.example.com/v1"), "the part of the URL to change (regex)");
      f += row("With", txt("rf-with", v.with, "https://staging.example.com/v1"));
    } else if (t === "respond") {
      f += row("Status", `<input type="number" id="rf-status" value="${esc(v.status == null ? 200 : v.status)}" style="width:84px">`);
      f += v.body_file ? `<p class="rv-win-hint">The body is read from ${esc(v.body_file)}.</p>`
        : row("Body", `<textarea id="rf-body" class="rv-code grow" rows="6" spellcheck="false" placeholder='{"ok": true}'>${esc(typeof v.body === "object" && v.body !== null ? JSON.stringify(v.body, null, 2) : v.body == null ? "" : v.body)}</textarea>`);
    } else if (t === "status") {
      f += row("Status", `<input type="number" id="rf-status" value="${esc(v.status == null ? 503 : v.status)}" style="width:84px">`);
    } else if (t === "json_patch") {
      f += row("Set fields", `<textarea id="rf-set" class="rv-code grow" rows="5" spellcheck="false" placeholder='{"user.name": "QA", "items[0].price": 1}'>${esc(it ? JSON.stringify(v.set, null, 2) : "")}</textarea>`, "path → new value, as JSON");
    } else if (t === "delay") {
      f += row("Delay", `<input type="number" id="rf-ms" min="0" value="${esc(v.ms == null ? 1000 : v.ms)}" style="width:100px"> ms`);
    } else if (t === "set_header") {
      f += row("On", `<select id="rf-side"><option value="request"${v.side !== "response" ? " selected" : ""}>the request</option><option value="response"${v.side === "response" ? " selected" : ""}>the response</option></select>`);
      f += row("Header", txt("rf-header", v.header, "X-QA"));
      f += row("Value", txt("rf-value", v.value, "") + `<label><input type="checkbox" id="rf-remove"${it && v.value == null ? " checked" : ""}> Remove it instead</label>`);
    }
    ed.hidden = false;
    ed.innerHTML = `<h4>${it ? "Edit " + esc(it.name) + " · " + esc(typeName(t)) : "New rule"}</h4>${f}
      <div class="rv-form"><span class="rv-spacer"></span><button type="button" class="rv-btn" data-r-cancel>Cancel</button><button type="button" class="rv-btn p" data-r-save>${it ? "Save" : "Add"}</button></div>
      <p class="rv-win-hint bad" data-r-err role="alert"></p>`;
    ed.oninput = () => { w.data.edit.dirty = true; };
    const typeSel = ed.querySelector("#rf-type");
    if (typeSel) typeSel.onchange = () => edit(w, null, typeSel.value, preset);
    const rm = ed.querySelector("#rf-remove");
    if (rm) { const sync = () => { ed.querySelector("#rf-value").disabled = rm.checked; }; rm.onchange = sync; sync(); }
    ed.querySelector("[data-r-cancel]").onclick = () => { ed.hidden = true; ed.innerHTML = ""; w.data.edit = null; };
    ed.querySelector("[data-r-save]").onclick = () => save(w, it, t);
    const first = ed.querySelector(it ? "#rf-match" : "#rf-name");
    if (first) first.focus();
    ed.scrollIntoView({ block: "nearest" });
  }

  // "^https://api\.x\.com/v1/accounts" → "remote-accounts" (the user can change it)
  function suggestName(match, t) {
    const seg = match.replace(/\\/g, "").split("/").filter(Boolean).pop() || "rule";
    const base = (t === "block" ? "block-" : t === "map_remote" ? "remote-" : "") + seg.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 30);
    const names = new Set(rules().map((r) => r.name));
    let n = base, i = 2;
    while (names.has(n)) n = base + "-" + i++;
    return n;
  }

  async function save(w, it, t) {
    const ed = w.body.querySelector("[data-r-ed]"), val = (id) => (ed.querySelector("#" + id) || {}).value || "", err = ed.querySelector("[data-r-err]");
    try {
      const rule = { match: val("rf-match").trim(), method: val("rf-method") };
      if (!rule.match) throw new Error("Enter the URL pattern (. matches every call)");
      if (t === "respond") {
        rule.status = Number(val("rf-status"));
        if (!it || !it.body_file) { const b = val("rf-body"); if (/^\s*[[{]/.test(b)) { try { rule.body = JSON.parse(b); } catch (x) { rule.body = b; } } else rule.body = b; }
      } else if (t === "status") rule.status = Number(val("rf-status"));
      else if (t === "json_patch") {
        let o; try { o = JSON.parse(val("rf-set")); } catch (x) { throw new Error('Set fields must be a JSON object, e.g. {"user.name": "QA"}'); }
        if (!o || typeof o !== "object" || Array.isArray(o) || !Object.keys(o).length) throw new Error("Set fields must be a JSON object with at least one path");
        rule.set = o;
      } else if (t === "delay") rule.ms = Number(val("rf-ms"));
      else if (t === "set_header") { rule.side = val("rf-side"); rule.header = val("rf-header").trim(); rule.value = ed.querySelector("#rf-remove").checked ? null : val("rf-value"); if (!rule.header) throw new Error("Enter the header name"); }
      else if (t === "map_remote") { rule.replace = val("rf-replace"); rule.with = val("rf-with"); if (!rule.replace || !rule.with) throw new Error("Enter both Replace and With"); }
      if ((t === "status" || t === "respond") && !(rule.status >= 100 && rule.status <= 999)) throw new Error("The status must be a number from 100 to 999");
      let r;
      if (it) r = await A.api("update", { name: it.name, rule, keys: ["match", "method", ...KEYS[t]] });
      else {
        const name = val("rf-name").trim();
        if (!name) throw new Error("Give the rule a name");
        r = await A.api("add", { rule: Object.assign({ name, enabled: true, action: t }, rule) });
      }
      A.toast(it ? "Rule " + it.name + " saved" : "Rule " + val("rf-name").trim() + " is on");
      void r;
      ed.hidden = true; ed.innerHTML = ""; w.data.edit = null;
      if (w.data.type !== "all" && w.data.type !== t) { w.data.type = t; T.open("rules", { type: t }); }
      A.refresh(); A.toolsChanged();
    } catch (x) { err.textContent = x.message; }
  }

  async function test(w) {
    const f = A.selected(), out = w.body.querySelector("[data-r-testout]");
    if (!f) return;
    try {
      const t = await A.api("rule_test", { flow_id: f.id });
      out.innerHTML = `<div class="rv-ruletest"><div class="rv-mono"><b>${esc(t.method)}</b> ${esc(t.url)}${t.sent_to ? " · sent to " + esc(t.sent_to) : ""}</div>`
        + (t.rules.length ? t.rules.map((x) => `<div class="${x.fires ? "fires" : x.inert ? "bad" : ""}">${x.fires ? "✓ <b>" + esc(x.name) + "</b> fires: " + esc(x.effect)
          : (x.inert ? "⚠ " : "· ") + "<b>" + esc(x.name) + "</b> does not fire: " + esc(x.reason)}</div>`).join("") : "<div>No rules.</div>") + `</div>`;
    } catch (e) { A.toast(e.message, true); }
  }
})();
