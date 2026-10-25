/* Devices, collections, sessions and call comparison. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;
  const stamp = (t) => t ? new Date(t * 1000).toLocaleString() : "";
  const focusKey = (w) => { const el = document.activeElement; if (!w.body.contains(el)) return null;
    return ["data-action", "data-item", "data-device"].filter((key) => el.hasAttribute(key)).map((key) => `[${key}="${CSS.escape(el.getAttribute(key))}"]`).join("") || null; };
  const restore = (w, key) => { if (key) { const el = w.body.querySelector(key); if (el) el.focus({ preventScroll: true }); } };
  const note = (s) => `<p class="rv-win-hint">${esc(s)}</p>`;
  async function exportHar(op, name, secret) {
    if (secret && !await A.ask("Export with secrets?", "This HAR will contain tokens, cookies and passwords in clear text. Keep it on this machine.", "Export with secrets", true)) return;
    const r = await ui.run(op, { name, include_secrets: secret }); if (!r) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(r.har, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = r.filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 2000);
    A.toast(r.redacted ? "HAR saved to Downloads (secrets redacted)" : "HAR saved to Downloads — contains secrets!", !r.redacted);
  }
  const harChoice = () => `<label><input type="checkbox" data-secret> Include secrets in the next HAR</label>${note("Exports hide tokens, cookies, API keys and passwords unless checked. The choice resets after export.")}`;
  const fileHar = async (file) => { try { return JSON.parse(await file.text()); } catch (e) { A.toast("Not a valid HAR (JSON) file", true); return null; } };
  function popupForm(w, title, value, label) {
    const box = document.createElement("form"); box.className = "rv-editor";
    box.innerHTML = `<label>${esc(title)} <input type="text" aria-label="${esc(title)}" value="${esc(value || "")}"></label> <button class="rv-btn p" type="submit">${esc(label || "Save")}</button> <button class="rv-btn" type="button">Cancel</button>`;
    w.body.prepend(box); const input = box.querySelector("input"); input.focus();
    return new Promise((resolve) => { const done = (v) => { box.remove(); resolve(v); }; box.onsubmit = (e) => { e.preventDefault(); done(input.value.trim()); }; box.querySelector("[type=button]").onclick = () => done(null); box.onkeydown = (e) => { if (e.key === "Escape") { e.stopPropagation(); done(null); } }; });
  }

  /* The device probe is separate from state. Keep the typed browser URL and local consent while it polls. */
  T.register("devices", {
    title: "Devices", width: 760, height: 610,
    render(w) { w.data.url = w.data.url || ""; w.data.sig = null; w.data.consent = null; drawDevices(w); probe(w); },
    closed(w) { clearTimeout(w.data.timer); w.data.timer = null; },
  });
  async function probe(w) {
    if (!w.shown) return;
    try { w.data.deviceState = await A.api("devices", {}); } catch (e) { w.data.deviceState = { error: e.message }; }
    if (!w.shown) return;
    const sig = JSON.stringify([w.data.deviceState, (A.state() || {}).lan, (A.state() || {}).untrusted]);
    if (sig !== w.data.sig && document.activeElement !== w.body.querySelector("[data-browser-url]")) { w.data.sig = sig; drawDevices(w); }
    clearTimeout(w.data.timer);
    const d = w.data.deviceState || {};
    w.data.timer = setTimeout(() => probe(w), d.pending ? 600 : d.job && d.job.running ? 1500 : 4000);
  }
  function drawDevices(w) {
    const d = w.data.deviceState;
    if (!d || d.pending) { w.body.innerHTML = note("Looking for simulators and emulators…"); return; }
    if (d.error) { w.body.innerHTML = `<p role="alert" class="rv-win-err">${esc(d.error)}</p>`; return; }
    const url = w.data.url;
    const key = focusKey(w), job = d.job || {}, bj = d.browser_job;
    if (w.data.starting && job.platform === w.data.starting.platform && job.target === w.data.starting.target && job.started * 1000 >= w.data.starting.at - 2000) w.data.starting = null;
    const busy = !!(job.running || w.data.starting);
    const row = (platform, x) => {
      const mine = job.platform === platform && (job.target === "all" || job.target === x.id);
      const starting = w.data.starting && w.data.starting.platform === platform && (w.data.starting.target === "all" || w.data.starting.target === x.id);
      const setting = !x.ready && (job.running && mine || starting);
      const failed = !setting && mine && job.rc != null && job.rc !== 0 && job.error;
      const detail = setting ? job.step || "Setting up…" : failed ? job.error : platform === "ios" ? x.ready ? "Trusts the Rivis certificate" : "Certificate not trusted yet"
        : !x.ca_ok ? x.play ? "Google Play image — certificate not installed yet" : "Certificate not installed yet" : !x.proxy_ok ? "Certificate OK — proxy not pointing at Rivis" : "Certificate and proxy set";
      const sys = platform === "android" && x.ca_ok && !setting ? `<div class="rv-win-hint">System store: ${x.system_ok ? "on" + (x.play ? " (until its next normal restart)" : "") : x.system_wanted ? "gone after a restart" + (x.play ? "" : " — coming back") : "off"}</div>`
        + (!x.system_ok && (!x.system_wanted || x.play) ? `<button type="button" class="rv-lnk" data-device="${esc(x.id)}" data-platform="android" data-name="${esc(x.name)}" data-system="1" data-play="${x.play ? 1 : 0}" ${busy ? "disabled" : ""}>${x.system_wanted ? "Add it again" : "Add to system store"}</button>` : "") : "";
      return `<div class="rv-form"><div class="grow"><b>${esc(x.name)}</b> <span class="rv-win-hint">${esc(x.os)}</span><div class="rv-win-hint" ${failed ? 'role="alert"' : ""}>${esc(detail)}</div>${sys}</div>
        ${x.ready ? `<span class="rv-badge on">Ready</span>` : `<button type="button" class="rv-btn p" data-device="${esc(x.id)}" data-platform="${platform}" data-name="${esc(x.name)}" data-play="${x.play && !x.ca_ok ? 1 : 0}" ${busy ? "disabled" : ""}>${setting ? "Setting up…" : "Set up"}</button>`}</div>`;
    };
    const section = (platform, title, list, absent) => `<h4>${title}</h4>` + (list === null ? note(absent) : list.length ? list.map((x) => row(platform, x)).join("")
      + (list.filter((x) => !x.ready).length > 1 ? `<button type="button" class="rv-btn" data-device="all" data-platform="${platform}" data-name="all" data-play="${list.some((x) => x.play && !x.ca_ok) ? 1 : 0}" ${busy ? "disabled" : ""}>Set up all</button>` : "")
      : note(platform === "ios" ? "No simulator is booted. Start one from Xcode or Simulator — it shows up here." : "No emulator is running. Start one from Android Studio's Device Manager — it shows up here."));
    w.setSub(`${(d.ios || []).length} simulators · ${(d.android || []).length} emulators${busy ? " · setting up" : ""}`);
    w.body.innerHTML = note("Set up each simulator or emulator once: its certificate, and for Android the proxy.")
      + (w.data.consent ? `<div class="rv-editor"><b>${w.data.consent.system ? "System store for" : "One-time setup for"} ${esc(w.data.consent.name)}</b>${note(d.magisk ? "Google Play images refuse adb root. Setup uses a temporary patched boot, then the emulator restarts once. The certificate lasts for that boot; use test emulators only." : w.data.consent.system ? "This copy has no temporary boot setup for the system store. Use a Google APIs emulator, or install a copy that includes it. Use test emulators only." : "Google Play images refuse adb root. Setup uses the emulator's Settings screens and may take a few minutes; leave the emulator alone until it finishes. Use test emulators only.")}
          <button type="button" class="rv-btn p" data-consent="yes">Continue</button> <button type="button" class="rv-btn" data-consent="no">Cancel</button></div>` : "")
      + (job.label ? `<h4>${job.running ? "Setting up" : job.rc === 0 ? "Done" : "Failed"} — ${esc(job.label)}</h4><pre class="rv-code" ${job.rc ? 'role="alert"' : ""}>${esc((job.lines || []).join("\n") || "starting…")}</pre>` : "")
      + section("ios", "iOS Simulators", d.ios, d.ios_error || "Xcode command-line tools are not installed (xcrun simctl).")
      + section("android", "Android emulators", d.android, "adb was not found. Install Android Studio SDK platform-tools to use emulators.")
      + note("Same setup from a terminal: rivis setup. Some apps trust only the system certificate store; certificate pinning can still prevent decryption.")
      + (((A.state() || {}).untrusted || []).length ? `<div class="rv-alert bad" role="alert">A device does not trust the certificate. Calls to ${esc((A.state().untrusted || [])[0].host)} may pass through without being recorded. <button type="button" class="rv-btn" data-retry>Decrypt again</button></div>` : "")
      + `<h4>Phones and tablets (Wi-Fi)</h4>` + lanHTML((A.state() || {}).lan)
      + `<h4>Web browser</h4>${note("Opens a separate browser profile pointed at Rivis. Your normal browser settings are not changed.")}`
      + ((d.browsers || []).length ? `<div class="rv-form"><input type="text" class="grow" data-browser-url aria-label="Web app URL" placeholder="Web app URL (optional)" value="${esc(url)}">`
        + d.browsers.map((b) => `<button type="button" class="rv-btn p" data-browser="${esc(b.id)}">Open ${esc(b.name)}</button>`).join("") + `</div>`
        + (bj ? `<pre class="rv-code" ${bj.rc ? 'role="alert"' : ""}>${esc((bj.running ? "Opening…\n" : bj.rc ? "Could not open: \n" : "") + (bj.lines || []).join("\n"))}</pre>` : "") + note("Same from a terminal: rivis browser [URL].")
        : note("No Chrome, Edge, Chromium or Brave found in Applications."));
    const input = w.body.querySelector("[data-browser-url]"); if (input) input.oninput = () => { w.data.url = input.value; };
    w.body.querySelectorAll("[data-device]").forEach((b) => b.onclick = () => {
      const data = { platform: b.dataset.platform, target: b.dataset.device, name: b.dataset.name, system: !!b.dataset.system };
      if (data.platform === "android" && b.dataset.play === "1") { w.data.consent = data; drawDevices(w); return; }
      setup(w, data, false);
    });
    w.body.querySelectorAll("[data-consent]").forEach((b) => b.onclick = () => { const data = w.data.consent; w.data.consent = null; if (b.dataset.consent === "yes") setup(w, data, true); else drawDevices(w); });
    w.body.querySelectorAll("[data-browser]").forEach((b) => b.onclick = async () => { const value = w.data.url.trim(); if (await ui.run("browser_open", { browser: b.dataset.browser, url: value }, "Opening browser…")) setTimeout(() => probe(w), 1500); });
    const retry = w.body.querySelector("[data-retry]"); if (retry) retry.onclick = () => ui.run("untrusted_retry", {}, "Decrypting again");
    wireLan(w);
    restore(w, key);
  }
  async function setup(w, data, consent) { w.data.starting = { ...data, at: Date.now() }; drawDevices(w); const r = await ui.run("device_setup", { ...data, consent }, "Setup started"); if (!r) w.data.starting = null; probe(w); }
  function lanHTML(lan) {
    lan = lan || { on: false };
    if (!lan.on) return note("Off. To capture a phone or tablet on this Wi-Fi, restart with rivis stop, then rivis start --lan. Each device must be allowed here.");
    const address = (lan.addresses || [])[0] || ":", at = address.lastIndexOf(":"), ip = address.slice(0, at), port = address.slice(at + 1);
    const qr = (lan.qr || [])[0];
    return `<div class="rv-form">${qr ? `<img class="rv-lanqr" alt="Phone setup code" src="${esc("data:image/svg+xml;charset=utf-8," + encodeURIComponent(qr))}">` : ""}<div class="grow rv-note">1. On the phone, scan the code or open ${esc((lan.setup_urls || [])[0] || "the setup URL")} for the certificate. 2. Set its Wi-Fi proxy to ${esc(ip)}:${esc(port)}. 3. Allow it below.${(lan.addresses || []).length > 1 ? ` Other addresses: ${esc(lan.addresses.slice(1).join(", "))}.` : ""}</div></div>`
      + (lan.pending || []).map((x) => `<div class="rv-form"><span class="grow">${esc(x.name)} · ${esc(x.ip)} · ${esc(x.count)} calls refused</span><button class="rv-btn p" data-lan="allow" data-ip="${esc(x.ip)}" data-name="${esc(x.name)}">Allow</button><button class="rv-btn" data-lan="dismiss" data-ip="${esc(x.ip)}">Ignore</button></div>`).join("")
      + `<h4>Allowed</h4>` + ((lan.devices || []).length ? lan.devices.map((x) => `<div class="rv-form"><span class="grow">${esc(x.name)} · ${esc(x.ip)}</span><button class="rv-btn" data-lan="rename" data-ip="${esc(x.ip)}" data-name="${esc(x.name)}">Rename</button><button class="rv-btn" data-lan="remove" data-ip="${esc(x.ip)}" data-name="${esc(x.name)}">Remove</button></div>`).join("") : note("None yet."));
  }
  function wireLan(w) { w.body.querySelectorAll("[data-lan]").forEach((b) => b.onclick = async () => {
    const ip = b.dataset.ip, name = b.dataset.name, kind = b.dataset.lan;
    if (kind === "allow") await ui.run("lan_allow", { ip, name }, "Allowed " + name);
    if (kind === "dismiss") await ui.run("lan_dismiss", { ip }, "Ignored");
    if (kind === "rename") { const next = await popupForm(w, "Name for " + ip, name, "Rename"); if (next) await ui.run("lan_allow", { ip, name: next }, "Renamed to " + next); }
    if (kind === "remove" && await A.ask("Remove " + name + "?", "Its calls are refused from now on.", "Remove", true)) await ui.run("lan_rm", { ip }, "Removed " + name);
    probe(w);
  }); }

  T.register("collections", {
    title: "Collections", width: 800, height: 610,
    render(w) { w.data.sig = null; w.data.open = w.data.open || null; drawCollections(w); },
    onState(st, w) { if (w && JSON.stringify(st.collections) !== w.data.sig && !w.body.querySelector("input:focus, textarea:focus")) { w.data.sig = JSON.stringify(st.collections); drawCollections(w); if (w.data.open) loadEntries(w); } },
    dirty(w) { return !!((w.data.editing && w.data.editing !== w.data.savedForm) || w.data.importFile); },
  });
  function drawCollections(w) {
    const st = A.state() || {}, c = st.collections || { items: [] }, key = focusKey(w), old = w.data.form || { name: "", match: "", strictMatch: "", importName: "" };
    w.setSub(`${(c.items || []).length} saved · ${c.recording ? "recording " + c.recording : "idle"}`);
    w.body.innerHTML = `<h4>Record</h4>` + (c.recording ? `<p>Recording into <b>${esc(c.recording)}</b>. Use the app, then stop.</p><button class="rv-btn" data-action="stop">Stop recording</button>`
      : `<div class="rv-form"><input type="text" class="grow" data-field="name" aria-label="Collection name" placeholder="Collection name" value="${esc(old.name)}"><button class="rv-btn p" data-action="record">Start recording</button></div>
      <label>Record calls matching <input type="text" data-field="match" aria-label="Record calls matching" value="${esc(old.match || c.record_match || "")}"></label>`)
      + `<h4>Replay</h4><div class="rv-form"><label><input type="checkbox" data-action="strict" ${c.strict ? "checked" : ""}> Strict replay</label></div>`
      + note(`Calls matching ${c.record_match || "."} that are absent from a replayed collection return 404 when strict replay is on.`)
      + `<div class="rv-form"><input type="text" class="grow" data-field="strictMatch" aria-label="Strict replay match" value="${esc(old.strictMatch || c.record_match || "")}"><button class="rv-btn" data-action="match">Save match</button></div>
      <h4>Collections (${(c.items || []).length})</h4>` + ((c.items || []).length ? c.items.map((x) => `<div class="rv-form"><label><input type="checkbox" data-item="${esc(x.name)}" data-action="replay" ${x.replay ? "checked" : ""} ${c.recording === x.name ? "disabled" : ""}> Replay</label>
        <span class="grow"><b>${esc(x.name)}</b> · ${esc(x.count)} calls · ${esc(stamp(x.created))}</span>
        <button class="rv-btn" data-item="${esc(x.name)}" data-action="entries">${w.data.open === x.name ? "Hide" : "Calls"}</button>
        <button class="rv-btn" data-item="${esc(x.name)}" data-action="har">HAR</button><button class="rv-btn" data-item="${esc(x.name)}" data-action="delete">Delete</button></div>
        ${w.data.open === x.name ? `<div class="rv-editor" data-entries>${w.data.entries ? entriesHTML(w.data.entries) : "Loading…"}</div>` : ""}`).join("") : ui.empty("No collections yet", "Name a journey, record it, then replay its responses."))
      + `<h4>Import</h4><div class="rv-form"><input type="file" data-import-file accept=".har,application/json" aria-label="HAR file">${w.data.importFile ? `<span class="rv-win-hint">${esc(w.data.importFile.name)}</span>` : ""}<input type="text" data-field="importName" aria-label="Collection name" placeholder="Name" value="${esc(old.importName)}"><button class="rv-btn" data-action="import">Import HAR</button></div>`
      + harChoice() + note(`Stored in ${st.project_state || "this project's private folder"}/collections.`);
    w.body.oninput = () => { w.data.form = Object.fromEntries([...w.body.querySelectorAll("[data-field]")].map((x) => [x.dataset.field, x.value])); w.data.editing = JSON.stringify(w.data.form); };
    w.body.querySelector("[data-import-file]").onchange = (e) => { w.data.importFile = e.target.files[0] || null; };
    if (!w.data.savedForm) w.data.savedForm = JSON.stringify(w.data.form || old);
    w.body.onclick = (e) => collAction(w, e.target.closest("[data-action]"));
    restore(w, key);
  }
  function entriesHTML(entries) { return entries.length ? entries.map((x) => `<div class="rv-form"><span class="grow rv-mono">${esc(x.method)} ${esc(x.host)}${esc(x.path)}${x.query ? "?" + esc(x.query) : ""} → ${esc(x.status)}</span><button class="rv-icon-btn" data-action="entry-delete" data-index="${esc(x.i)}" aria-label="Remove call">✕</button></div>`).join("") : note("Empty collection."); }
  async function collAction(w, b) {
    if (!b) return; const kind = b.dataset.action, c = ((A.state() || {}).collections || { items: [] }), name = b.dataset.item;
    if (kind === "record" && await ui.run("coll_record", { name: w.body.querySelector('[data-field="name"]').value, record_match: w.body.querySelector('[data-field="match"]').value }, "Recording started")) { w.data.form = null; w.data.editing = null; w.data.savedForm = null; }
    if (kind === "stop") await ui.run("coll_stop", {}, "Recording stopped");
    if (kind === "strict") await ui.run("coll_strict", { strict: b.checked }, b.checked ? "Strict replay on" : "Strict replay off");
    if (kind === "match" && await ui.run("coll_match", { record_match: w.body.querySelector('[data-field="strictMatch"]').value }, "Replay match saved")) { w.data.savedForm = JSON.stringify(w.data.form); w.data.editing = null; }
    if (kind === "replay") await ui.run("coll_replay", { name, enabled: b.checked }, b.checked ? "Replaying " + name : "Replay off");
    if (kind === "delete" && await A.ask("Delete collection " + name + "?", "Its recorded calls will be lost.", "Delete", true)) { if (w.data.open === name) w.data.open = null; await ui.run("coll_delete", { name }, "Deleted " + name); }
    if (kind === "entries") { w.data.open = w.data.open === name ? null : name; w.data.entries = null; drawCollections(w); if (w.data.open) await loadEntries(w); }
    if (kind === "entry-delete" && w.data.open) { await ui.run("coll_entry_delete", { name: w.data.open, i: b.dataset.index }, "Removed"); await loadEntries(w); }
    if (kind === "har") { await exportHar("coll_export", name, w.body.querySelector("[data-secret]").checked); w.body.querySelector("[data-secret]").checked = false; }
    if (kind === "import") {
      const file = w.body.querySelector("[data-import-file]").files[0] || w.data.importFile; if (!file) { A.toast("Choose a .har file first", true); return; }
      const har = await fileHar(file); if (!har) return;
      const entered = w.body.querySelector('[data-field="importName"]').value.trim();
      const newName = entered || file.name.replace(/\.har$|\.json$/i, "").replace(/[^A-Za-z0-9._-]/g, "-");
      const overwrite = c.items.some((x) => x.name === newName);
      if (overwrite && !await A.ask("Replace collection " + newName + "?", "Its recorded calls will be lost.", "Replace", true)) return;
      const r = await ui.run("coll_import", { name: newName, har, overwrite }); if (r) { w.data.importFile = null; w.data.editing = null; w.data.form = null; w.data.savedForm = null; A.toast(`Imported ${r.count} calls into ${newName}${r.skipped_count ? ` — left out ${r.skipped_count}` : ""}`); }
    }
  }
  async function loadEntries(w) { try { const name = w.data.open, r = await A.api("coll_entries", { name }); if (w.data.open === name) { w.data.entries = r.entries; const box = w.body.querySelector("[data-entries]"); if (box) box.innerHTML = entriesHTML(r.entries); } } catch (e) { A.toast(e.message, true); } }

  T.register("sessions", {
    title: "Sessions", width: 800, height: 590,
    render(w) { w.data.sig = null; w.data.form = w.data.form || { name: "", note: "", visible: false }; if (!w.data.savedForm) w.data.savedForm = JSON.stringify(w.data.form); drawSessions(w); },
    onState(st, w) { if (w && JSON.stringify(st.sessions) !== w.data.sig && !w.data.choiceOpen && !w.body.querySelector("input:focus, textarea:focus")) { w.data.sig = JSON.stringify(st.sessions); drawSessions(w); } },
    dirty(w) { return !!(w.data.form && JSON.stringify(w.data.form) !== w.data.savedForm); },
  });
  function drawSessions(w) {
    const st = A.state() || {}, ss = st.sessions || [], f = w.data.form || { name: "", note: "", visible: false }, key = focusKey(w);
    w.setSub(`${ss.length} saved`);
    w.body.innerHTML = `<h4>Save the current capture</h4><div class="rv-form"><input type="text" class="grow" data-sess-name aria-label="Session name" placeholder="Session name" value="${esc(f.name)}"></div>
      <div class="rv-form"><input type="text" class="grow" data-sess-note aria-label="Note" placeholder="Note (optional)" value="${esc(f.note)}"></div>
      <div class="rv-form"><label><input type="checkbox" data-sess-visible ${f.visible ? "checked" : ""}> Only calls matching the current search</label><button class="rv-btn p" data-action="save">Save session</button></div>
      <h4>Saved sessions (${ss.length})</h4>` + (ss.length ? ss.map((x) => `<div class="rv-form"><span class="grow"><b>${esc(x.name)}</b> · ${esc(x.count)} calls · ${esc(stamp(x.created))}<br>${esc((x.hosts || []).slice(0, 3).join(", "))}
      <button class="rv-lnk" data-action="note" data-item="${esc(x.name)}">${x.note ? esc(x.note) : "Add a note…"}</button></span>
      <button class="rv-btn" data-action="load" data-item="${esc(x.name)}">Open</button><button class="rv-btn" data-action="har" data-item="${esc(x.name)}">HAR</button><button class="rv-btn" data-action="delete" data-item="${esc(x.name)}">Delete</button></div>`).join("") : ui.empty("No saved sessions yet", "Name the capture above and save it. Open brings the calls back into the list."))
      + harChoice() + note(`Stored in ${st.project_state || "this project's private folder"}/sessions.`);
    w.body.oninput = () => { f.name = w.body.querySelector("[data-sess-name]").value; f.note = w.body.querySelector("[data-sess-note]").value; f.visible = w.body.querySelector("[data-sess-visible]").checked; };
    w.body.onchange = w.body.oninput;
    w.body.onclick = (e) => sessAction(w, e.target.closest("[data-action]"));
    restore(w, key);
  }
  async function sessAction(w, b) {
    if (!b) return; const kind = b.dataset.action, name = b.dataset.item, ss = (A.state() || {}).sessions || [], item = ss.find((x) => x.name === name), f = w.data.form;
    if (kind === "save") {
      const entered = w.body.querySelector("[data-sess-name]").value.trim(); if (!entered) { A.toast("Enter a session name", true); return; }
      const overwrite = ss.some((x) => x.name === entered);
      if (overwrite && !await A.ask("Replace session " + entered + "?", "The earlier capture will be lost.", "Replace", true)) return;
      if (await ui.run("sess_save", { name: entered, note: f.note, visible_only: f.visible, search_filter: f.visible ? A.currentFilter() : "", overwrite }, "Session saved")) { w.data.form = { name: "", note: "", visible: false }; w.data.savedForm = JSON.stringify(w.data.form); drawSessions(w); }
    }
    if (kind === "load" && item) {
      const mode = await loadChoice(w, item.name); if (!mode) return;
      const r = await ui.run("sess_load", { name, replace: mode === "replace" }); if (r) A.toast("Opened " + r.count + " calls");
    }
    if (kind === "delete" && item && await A.ask("Delete session " + name + "?", "The saved capture will be removed.", "Delete", true)) await ui.run("sess_delete", { name }, "Deleted");
    if (kind === "note" && item) { const value = await popupForm(w, "Note for " + name, item.note || "", "Save note"); if (value !== null) await ui.run("sess_note", { name, note: value }, "Note saved"); }
    if (kind === "har" && item) { await exportHar("sess_har", name, w.body.querySelector("[data-secret]").checked); w.body.querySelector("[data-secret]").checked = false; }
  }
  function loadChoice(w, name) {
    const box = document.createElement("div"); box.className = "rv-editor"; box.setAttribute("role", "dialog"); box.setAttribute("aria-label", "Open session");
    box.innerHTML = `<h4>Open session ${esc(name)}?</h4>${note("Add its calls to the list, or replace the calls currently in the list.")}
      <div class="rv-form"><button type="button" class="rv-btn p" data-choice="add">Add to the list</button><button type="button" class="rv-btn" data-choice="replace">Replace the list</button><button type="button" class="rv-btn" data-choice="cancel">Cancel</button></div>`;
    w.data.choiceOpen = true; w.body.prepend(box); box.querySelector("[data-choice=add]").focus();
    return new Promise((resolve) => { const done = (v) => { w.data.choiceOpen = false; box.remove(); resolve(v); }; box.querySelectorAll("[data-choice]").forEach((b) => b.onclick = () => done(b.dataset.choice === "cancel" ? null : b.dataset.choice)); box.onkeydown = (e) => { if (e.key === "Escape") { e.stopPropagation(); done(null); } }; });
  }

  T.register("compare", {
    title: "Compare", width: 860, height: 620,
    render(w, opts) { if (opts && opts.left && opts.left !== w.data.left) { w.data.left = opts.left; w.data.result = null; } else if (!w.data.left && A.selected()) w.data.left = A.selected().id; w.data.right = w.data.right || ""; drawCompare(w); },
    onState(st, w) { if (w) { const sig = A.recentFlows().map((f) => f.id).join("|"); if (sig !== w.data.sig && !w.body.querySelector("select:focus")) { w.data.sig = sig; drawCompare(w); } } },
  });
  function drawCompare(w) {
    const calls = A.recentFlows(), key = focusKey(w), label = (f) => f ? f.request.method + " " + A.urlOf(f) : "";
    for (const id of [w.data.left, w.data.right]) { const f = id && A.flow(id); if (f && f.type === "http" && !calls.some((x) => x.id === id)) calls.unshift(f); }
    const chosen = A.selected(), ids = new Set(calls.map((f) => f.id));
    const options = (value) => `<option value="">Choose a call…</option>` + calls.map((f) => `<option value="${esc(f.id)}" ${f.id === value ? "selected" : ""}>${esc(label(f))}</option>`).join("");
    w.setSub(w.data.left && w.data.right ? "Two calls selected" : "Choose two calls");
    w.body.innerHTML = `<p class="rv-win-hint">Choose two captured calls to compare their request and response.</p>
      <div class="rv-form"><label>A <select data-compare="left" aria-label="First call">${options(w.data.left)}</select></label>
      <label>B <select data-compare="right" aria-label="Second call">${options(w.data.right)}</select></label>
      <button class="rv-btn p" data-action="compare" ${w.data.left && w.data.right && w.data.left !== w.data.right && ids.has(w.data.left) && ids.has(w.data.right) ? "" : "disabled"}>Compare</button></div>
      <div class="rv-form"><button class="rv-lnk" data-action="selected">Use selected call as B</button>${chosen ? esc(label(chosen)) : "No call selected"}</div><div data-compare-result>${w.data.result ? resultHTML(w.data.result) : ""}</div>`;
    w.body.querySelectorAll("[data-compare]").forEach((s) => s.onchange = () => { w.data[s.dataset.compare] = s.value; w.data.result = null; drawCompare(w); });
    w.body.querySelector('[data-action="selected"]').onclick = () => { if (A.selected()) { w.data.right = A.selected().id; w.data.result = null; drawCompare(w); } };
    w.body.querySelector('[data-action="compare"]').onclick = async () => { const r = await ui.run("diff", { a: w.data.left, b: w.data.right }); if (r) { w.data.result = r; w.body.querySelector("[data-compare-result]").innerHTML = resultHTML(r); } };
    restore(w, key);
  }
  function resultHTML(r) {
    const label = (x) => x ? `${esc(x.method)} ${esc(x.url || x.label)}${x.status ? " → " + esc(x.status) : ""}` : "";
    const table = (rows, kind) => rows && rows.length ? `<table class="rv-rtable"><thead><tr><th>Field</th><th>A</th><th>B</th></tr></thead><tbody>`
      + rows.map(([k, a, b]) => kind === "text" ? `<tr><td>${k === "-" ? "Only A" : "Only B"}</td><td>${k === "-" ? esc(a) : ""}</td><td>${k === "+" ? esc(a) : ""}</td></tr>`
        : `<tr><td>${esc(k)}</td><td>${esc(a)}</td><td>${esc(b)}</td></tr>`).join("") + `</tbody></table>` : note("Identical.");
    return `<h4>Summary</h4><p>A: ${label(r.a)}<br>B: ${label(r.b)}</p><h4>Response body (${r.resp_body.rows.length} differences)</h4>${table(r.resp_body.rows, r.resp_body.kind)}
      <h4>Response headers</h4>${table(r.resp_headers)}<h4>Request body</h4>${table(r.req_body.rows, r.req_body.kind)}<h4>Request headers</h4>${table(r.req_headers)}`;
  }
})();
