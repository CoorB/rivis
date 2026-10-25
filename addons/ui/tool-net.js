/* Network: conditions, caching, TLS decryption, client certificates, and LAN devices. */
(() => {
  "use strict";
  const A = window.RivisApp, T = window.RivisTools;
  if (!A || !T) return;
  const { esc } = A, ui = T.ui;
  const manualKeys = [["latency_ms", "Latency (ms)"], ["jitter_ms", "Jitter (ms)"],
    ["down_kbps", "Download (kbps, 0 = unlimited)"], ["up_kbps", "Upload (kbps, 0 = unlimited)"],
    ["loss_pct", "Packet loss (%)"], ["response_delay_ms", "Extra response delay (ms)"]];
  const sig = (st) => JSON.stringify([st.throttle, st.throttle_match, st.loss, st.manual, st.profiles, st.no_cache,
    st.tls, st.client_certs, st.lan, st.project_only, st.show_dns, st.view_project, st.project,
    (A.selected() || {}).id]);
  const b64 = async (file) => {
    const bytes = new Uint8Array(await file.arrayBuffer()); let s = "";
    for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    return btoa(s);
  };
  const ago = (t) => { const s = Math.max(0, Math.round(Date.now() / 1000 - Number(t || 0))); return s < 60 ? s + " s ago" : Math.round(s / 60) + " min ago"; };
  const when = (t) => t ? new Date(Number(t) * 1000).toLocaleDateString() : "?";
  const focusKey = (el) => {
    if (!el || !el.dataset) return null;
    const attrs = ["netProfile", "netScope", "netManual", "netApply", "netNocache", "netTlsMode", "netTlsAdd", "netTlsAddbtn",
      "netTlsRm", "netTlsHost", "netCcHost", "netCcPass", "netCcFile", "netCcKey", "netCcAdd", "netCcRm", "netLanAllow",
      "netLanDismiss", "netLanName", "netLanRename", "netLanRm", "netProject", "netDns"];
    for (const key of attrs) if (Object.hasOwn(el.dataset, key)) {
      const attr = "data-" + key.replace(/[A-Z]/g, (x) => "-" + x.toLowerCase());
      return `[${attr}="${CSS.escape(el.dataset[key])}"]`;
    }
    return null;
  };
  T.register("net", {
    title: "Network", width: 820, height: 650,
    render(w) {
      w.data.sig = null;
      w.data.draft = w.data.draft || { manual: {}, tls: { allow: "", ignore: "" }, cc: { host: "", pass: "", file: null, key: null } };
      w.body.innerHTML = `<div data-net-content></div>`;
      w.body.oninput = (e) => {
        const d = w.data.draft;
        if (e.target.matches("[data-net-scope]")) d.scope = e.target.value;
        if (e.target.matches("[data-net-manual]")) d.manual[e.target.dataset.netManual] = e.target.value;
        if (e.target.matches("[data-net-tls-add]")) d.tls[e.target.dataset.netTlsAdd] = e.target.value;
        if (e.target.matches("[data-net-cc-host]")) d.cc.host = e.target.value;
        if (e.target.matches("[data-net-cc-pass]")) d.cc.pass = e.target.value;
        if (e.target.matches("[data-net-lan-name]")) d.lanNames = { ...(d.lanNames || {}), [e.target.dataset.netLanName]: e.target.value };
      };
      w.body.onchange = async (e) => {
        if (e.target.matches("[data-net-cc-file]")) { w.data.draft.cc.file = e.target.files[0] || null; return; }
        if (e.target.matches("[data-net-cc-key]")) { w.data.draft.cc.key = e.target.files[0] || null; return; }
        if (e.target.matches("[data-net-scope]")) {
          await ui.run("profile", { match: e.target.value }, "Applies to: " + (e.target.value || "all calls")); return;
        }
        if (e.target.matches("[data-net-profile]")) {
          const id = e.target.value;
          if (id !== "manual") await ui.run("profile", { id, match: w.body.querySelector("[data-net-scope]").value }, "Network: " + e.target.selectedOptions[0].textContent);
          else { w.data.draft.manualOpen = true; w.body.querySelector("[data-net-manual-box]").hidden = false; }
          return;
        }
        if (e.target.matches("[data-net-nocache]")) { await ui.run("nocache", { on: e.target.checked }, "No caching " + (e.target.checked ? "on" : "off")); return; }
        if (e.target.matches("[data-net-project]")) {
          const st = A.state() || {};
          await ui.run("view", { project: st.view_project, project_only: e.target.checked, show_dns: false }, "Call list updated"); return;
        }
        if (e.target.matches("[data-net-dns]")) {
          await ui.run("view", { project_only: false, show_dns: e.target.checked }, "Call list updated");
        }
      };
      w.body.onkeydown = (e) => {
        if (e.key === "Enter" && e.target.matches("[data-net-tls-add]")) { e.preventDefault(); addTls(w, e.target.dataset.netTlsAdd); }
        if (e.key === "Enter" && e.target.matches("[data-net-lan-name]")) { e.preventDefault(); renameLan(w, e.target.dataset.netLanName); }
      };
      w.body.onclick = async (e) => {
        const b = e.target.closest("button"); if (!b) return;
        if (b.matches("[data-net-apply]")) { await applyManual(w); return; }
        if (b.matches("[data-net-tls-mode]")) { await ui.run("tls_set", { mode: b.dataset.netTlsMode }, "TLS decryption updated"); return; }
        if (b.matches("[data-net-tls-addbtn]")) { await addTls(w, b.dataset.netTlsAddbtn); return; }
        if (b.matches("[data-net-tls-rm]")) {
          await ui.run("tls_update", { list: b.dataset.netTlsRm, action: "remove", pattern: b.dataset.pattern }, "Removed " + b.dataset.pattern); return;
        }
        if (b.matches("[data-net-tls-host]")) {
          const f = A.selected(); if (!f || !f.request) { A.toast("Select a web call first", true); return; }
          const r = await ui.run("tls_host", { flow_id: f.id, host: A.hostOf(f), decrypt: b.dataset.netTlsHost === "on" });
          if (r && r.message) A.toast(r.message);
          return;
        }
        if (b.matches("[data-net-cc-add]")) { await addCert(w); return; }
        if (b.matches("[data-net-settings]")) { A.$("tb-settings").click(); return; }
        if (b.matches("[data-net-cc-rm]")) {
          const host = b.dataset.netCcRm;
          if (await A.ask("Remove the client certificate of " + host + "?", "The next connection will no longer send it.", "Remove", true))
            await ui.run("client_cert_rm", { host }, "Removed the client certificate of " + host);
          return;
        }
        if (b.matches("[data-net-lan-allow]")) {
          const r = await ui.run("lan_allow", { ip: b.dataset.netLanAllow, name: b.dataset.name });
          if (r) A.toast("Allowed " + r.device.name + " (" + r.device.ip + ")");
          return;
        }
        if (b.matches("[data-net-lan-dismiss]")) { await ui.run("lan_dismiss", { ip: b.dataset.netLanDismiss }, "Ignored device"); return; }
        if (b.matches("[data-net-lan-rename]")) { await renameLan(w, b.dataset.netLanRename); return; }
        if (b.matches("[data-net-lan-rm]")) {
          if (await A.ask("Remove " + b.dataset.name + " (" + b.dataset.netLanRm + ")?", "Its calls are refused from now on.", "Remove", true))
            await ui.run("lan_rm", { ip: b.dataset.netLanRm }, "Removed " + b.dataset.name);
        }
      };
    },
    onState(st, w) {
      if (!w) return;
      const s = sig(st);
      if (s === w.data.sig) return;
      w.data.sig = s;
      const active = document.activeElement, focus = w.body.contains(active) ? focusKey(active) : null;
      const start = active && typeof active.selectionStart === "number" ? active.selectionStart : null;
      const end = active && typeof active.selectionEnd === "number" ? active.selectionEnd : null;
      draw(w, st);
      if (focus) {
        const el = w.body.querySelector(focus);
        if (el) { el.focus({ preventScroll: true }); if (start !== null && el.setSelectionRange) el.setSelectionRange(start, end); }
      }
    },
  });

  function draw(w, st) {
    const d = w.data.draft, profiles = st.profiles || [], current = st.throttle || "off";
    const chosen = profiles.find((p) => p.id === current);
    w.setSub("Throttle: " + (chosen ? chosen.name : current) + (Number(st.loss || 0) ? " · loss " + st.loss + "%" : ""));
    const manual = st.manual || {}, t = st.tls || { mode: "all", allow: [], ignore: [] }, cc = st.client_certs || [];
    const f = A.selected(), selectedHost = f && f.request ? A.hostOf(f) : "";
    const profileOptions = profiles.map((p) => `<option value="${esc(p.id)}"${p.id === current ? " selected" : ""}>${esc(p.name)}</option>`).join("");
    const manualHTML = manualKeys.map(([key, label]) => `<label>${esc(label)} <input type="number" min="0"${key === "loss_pct" ? ' max="100" step="0.5"' : ""}
      data-net-manual="${key}" value="${esc(Object.hasOwn(d.manual, key) ? d.manual[key] : manual[key] || 0)}"></label>`).join("");
    const tlsList = (which, label) => `<div class="rv-editor"><b>${label}</b>${t.mode === which ? ' <span class="rv-badge on">In use</span>' : ""}
      <div class="rv-form">${(t[which] || []).map((p) => `<span class="rv-badge">${esc(p)}
        <button type="button" class="rv-icon-btn" data-net-tls-rm="${which}" data-pattern="${esc(p)}" aria-label="Remove ${esc(p)}">✕</button></span>`).join("") || '<span class="rv-win-hint">None</span>'}</div>
      <div class="rv-form"><input type="text" class="grow" data-net-tls-add="${which}" value="${esc(d.tls[which])}" placeholder="*.example.test or api.example.test:8443" aria-label="Add ${esc(label.toLowerCase())}">
        <button type="button" class="rv-btn" data-net-tls-addbtn="${which}">Add</button></div></div>`;
    const lan = st.lan || {};
    const lanHTML = lan.on ? `<h4>Phones and tablets</h4>
      <p class="rv-win-hint">On the phone, open ${esc((lan.setup_urls || [])[0] || "the setup link")} for the certificate. Set its Wi-Fi proxy to ${esc((lan.addresses || [])[0] || "this Mac")}, then allow it here.</p>
      ${(lan.qr || [])[0] ? `<img width="148" height="148" alt="Phone setup QR code" src="data:image/svg+xml,${esc(encodeURIComponent(lan.qr[0]))}">` : ""}
      ${(lan.addresses || []).length > 1 ? `<p class="rv-win-hint">Other network addresses: ${lan.addresses.slice(1).map((x) => esc(x)).join(", ")}</p>` : ""}
      <h4>Waiting to be allowed</h4>${(lan.pending || []).length ? lan.pending.map((x) => `<div class="rv-editor"><div class="rv-form"><b>${esc(x.name)}</b> <code>${esc(x.ip)}</code>
        <span class="rv-spacer"></span><button type="button" class="rv-btn p" data-net-lan-allow="${esc(x.ip)}" data-name="${esc(x.name)}">Allow</button>
        <button type="button" class="rv-btn" data-net-lan-dismiss="${esc(x.ip)}">Ignore</button></div>
        <span class="rv-win-hint">${esc(x.count)} refused call${x.count === 1 ? "" : "s"} · last ${esc(ago(x.last))}${x.ua ? " · " + esc(String(x.ua).slice(0, 90)) : ""}</span></div>`).join("")
        : '<p class="rv-win-hint">No devices waiting.</p>'}
      <h4>Allowed</h4>${(lan.devices || []).length ? lan.devices.map((x) => `<div class="rv-editor"><div class="rv-form"><b>${esc(x.name)}</b> <code>${esc(x.ip)}</code>
        <input type="text" data-net-lan-name="${esc(x.ip)}" aria-label="New name for ${esc(x.ip)}" maxlength="40" value="${esc((d.lanNames || {})[x.ip] === undefined ? x.name : d.lanNames[x.ip])}">
        <button type="button" class="rv-btn" data-net-lan-rename="${esc(x.ip)}">Rename</button>
        <button type="button" class="rv-btn d" data-net-lan-rm="${esc(x.ip)}" data-name="${esc(x.name)}">Remove</button></div>
        <span class="rv-win-hint">Its calls appear under Source → Phone or tablet.</span></div>`).join("")
        : '<p class="rv-win-hint">No allowed devices.</p>'}` : "";
    w.body.querySelector("[data-net-content]").innerHTML = `
      <h4>Network conditions</h4><p class="rv-win-hint">Slow selected calls using a profile. A URL pattern limits which calls are affected.</p>
      <div class="rv-form"><label>Profile <select data-net-profile>${profileOptions}${chosen ? "" : `<option value="${esc(current)}" selected>${esc(current)} (from command line)</option>`}</select></label>
        <label class="grow">URL pattern <input type="text" data-net-scope spellcheck="false" value="${esc(d.scope === undefined ? st.throttle_match || "" : d.scope)}" placeholder="Empty = every call"></label></div>
      <p class="rv-win-hint">The URL pattern is a regular expression. ${Number(st.loss || 0) ? `Extra packet loss is active: ${esc(st.loss)}%. Choosing a profile clears it.` : ""}</p>
      <div class="rv-editor" data-net-manual-box${current === "manual" || d.manualOpen ? "" : " hidden"}><h4>Manual profile</h4>
        <div class="rv-form">${manualHTML}</div><button type="button" class="rv-btn p" data-net-apply>Apply manual profile</button></div>
      <h4>No Caching</h4><div class="rv-form"><label><input type="checkbox" data-net-nocache${st.no_cache ? " checked" : ""}> No Caching</label></div>
      <p class="rv-win-hint">Always fetch fresh content: removes conditional request headers and marks responses no-store. Map Local answers stay as they are.</p>
      <h4>TLS decryption</h4><p class="rv-win-hint">SSL Proxying: choose which hosts Rivis decrypts. Changes apply to new connections. ${esc(t.note || "")}</p>
      <div class="rv-seg" role="group" aria-label="TLS decryption mode">${[["all", "Every host"], ["allow", "Only listed hosts"], ["ignore", "All except listed"]]
        .map(([id, label]) => `<button type="button" data-net-tls-mode="${id}" aria-pressed="${t.mode === id}">${label}</button>`).join("")}</div>
      ${t.error ? `<p class="rv-win-err" role="alert">${esc(t.error)}</p>` : ""}
      ${tlsList("allow", "Hosts to decrypt")}${tlsList("ignore", "Hosts to leave alone")}
      ${selectedHost ? `<div class="rv-form"><span class="rv-win-hint">Selected call: ${esc(selectedHost)}</span>
        <button type="button" class="rv-btn" data-net-tls-host="on">Decrypt this host</button>
        <button type="button" class="rv-btn" data-net-tls-host="off">Stop decrypting this host</button></div>` : ""}
      <h4>Client certificates</h4><p class="rv-win-hint">For a server that asks the app for its own certificate (mutual TLS).</p>
      ${cc.length ? cc.map((x) => `<div class="rv-form"><b>${esc(x.host)}</b>${x.expired ? ' <span class="rv-badge warn">Expired</span>' : ""}
        <span class="rv-win-hint">${x.error ? "Unreadable: " + esc(x.error) : esc(x.subject) + " · expires " + esc(when(x.not_after))}</span>
        <span class="rv-spacer"></span><button type="button" class="rv-btn d" data-net-cc-rm="${esc(x.host)}">Remove</button></div>`).join("")
        : '<p class="rv-win-hint">None. Add one when a server reports a missing client certificate.</p>'}
      <div class="rv-editor"><div class="rv-form"><label class="grow">Host <input type="text" data-net-cc-host value="${esc(d.cc.host)}" placeholder="api.example.test or *.example.test" autocomplete="off"></label>
        <label>Certificate <input type="file" data-net-cc-file accept=".p12,.pfx,.pem,.crt,.cer"></label>${d.cc.file ? `<span class="rv-win-hint">${esc(d.cc.file.name)}</span>` : ""}</div>
        <div class="rv-form"><label>Password <input type="password" data-net-cc-pass value="${esc(d.cc.pass)}" autocomplete="new-password"></label>
          <label>Separate private key <input type="file" data-net-cc-key accept=".pem,.key"></label>${d.cc.key ? `<span class="rv-win-hint">${esc(d.cc.key.name)}</span>` : ""}</div>
        <div class="rv-form"><button type="button" class="rv-btn p" data-net-cc-add>Add client certificate</button>
          <span class="rv-win-hint">Stored unencrypted in this project's private folder; used from the next connection.</span></div></div>
      ${lanHTML}
      <h4>What the list shows</h4><div class="rv-form"><label><input type="checkbox" data-net-project${st.project_only ? " checked" : ""}> Only ${esc((st.project || {}).label || "project")} calls</label>
        <label><input type="checkbox" data-net-dns${st.show_dns ? " checked" : ""}> Show background lookups (DNS)</label></div>
      <div class="rv-form"><span class="rv-win-hint">These choices also appear in the Show menu. Theme is in Settings.</span>
        <button type="button" class="rv-btn" data-net-settings>Open Settings</button></div>`;
  }

  async function applyManual(w) {
    const manual = {};
    for (const input of w.body.querySelectorAll("[data-net-manual]")) {
      const n = Number(input.value || 0), cap = input.dataset.netManual === "loss_pct" ? 100
        : ["latency_ms", "jitter_ms", "response_delay_ms"].includes(input.dataset.netManual) ? 120000 : 1000000;
      if (!Number.isFinite(n) || n < 0 || n > cap) { A.toast(input.dataset.netManual.replaceAll("_", " ") + " must be from 0 to " + cap, true); input.focus(); return; }
      manual[input.dataset.netManual] = n;
    }
    if (await ui.run("profile", { id: "manual", manual, match: w.body.querySelector("[data-net-scope]").value }, "Network: manual profile"))
      w.data.draft.manualOpen = false;
  }
  async function addTls(w, which) {
    const input = w.body.querySelector(`[data-net-tls-add="${which}"]`), value = input.value.trim().toLowerCase();
    if (!value) { input.focus(); return; }
    if (await ui.run("tls_update", { list: which, action: "add", pattern: value }, "Added " + value)) {
      w.data.draft.tls[which] = ""; input.value = "";
    }
  }
  async function addCert(w) {
    const d = w.data.draft.cc, host = d.host.trim(), file = d.file, key = d.key;
    if (!host) { A.toast("Type the host the certificate is for", true); w.body.querySelector("[data-net-cc-host]").focus(); return; }
    if (!file) { A.toast("Choose the certificate file first", true); w.body.querySelector("[data-net-cc-file]").focus(); return; }
    if (((A.state() || {}).client_certs || []).some((x) => x.host === host.toLowerCase()) &&
      !await A.ask("Replace the client certificate of " + host + "?", "The next connection will use the new certificate.", "Replace")) return;
    try {
      const args = { host, file_b64: await b64(file), password: d.pass };
      if (key) args.key_b64 = await b64(key);
      const r = await ui.run("client_cert_add", args);
      if (r) {
        A.toast("Client certificate for " + r.cert.host + ": " + r.cert.subject + (r.cert.expired ? " (EXPIRED)" : ""));
        Object.assign(d, { host: "", pass: "", file: null, key: null });
        for (const key of ["host", "pass", "file", "key"]) w.body.querySelector(`[data-net-cc-${key}]`).value = "";
      }
    } catch (e) { A.toast(e.message, true); }
  }
  async function renameLan(w, ip) {
    const input = w.body.querySelector(`[data-net-lan-name="${CSS.escape(ip)}"]`), name = input.value.trim();
    if (!name || name.length > 40) { A.toast("Enter a name of up to 40 characters", true); input.focus(); return; }
    if (await ui.run("lan_allow", { ip, name }, "Renamed to " + name)) delete w.data.draft.lanNames[ip];
  }
})();
