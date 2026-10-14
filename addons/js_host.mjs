import vm from "node:vm";
import readline from "node:readline";

const scripts = new Map();
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

function safe(value) { return JSON.parse(JSON.stringify(value === undefined ? null : value)); }
function reply(id, value) {
  // The small preamble lets Python attribute and discard an over-limit JSON line
  // without stopping this host or failing unrelated calls.
  process.stdout.write(JSON.stringify({ id, responding: true }) + "\n");
  process.stdout.write(JSON.stringify({ id, ...value }) + "\n");
}

async function invoke(msg) {
  let entry = scripts.get(msg.name);
  if (!entry || entry.code !== msg.code) {
    const sandbox = Object.create(null);
    sandbox.globalThis = sandbox;
    const context = vm.createContext(sandbox, { name: `proxy-script:${msg.name}`, codeGeneration: { strings: false, wasm: false } });
    new vm.Script(`
      globalThis.__proxyState = Object.create(null);
      globalThis.__proxyLogs = [];
      globalThis.log = (...args) => globalThis.__proxyLogs.push(args.map(String).join(" "));
      globalThis.sleep = (ms) => Atomics.waitAsync(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, Number(ms) || 0)).value;
      globalThis.mock = (status=200, body="", headers={}) => ({__proxy_mock__:true,statusCode:status,body,headers});
    `).runInContext(context, { timeout: 2000 });
    // Helpers exist before user code loads, so user declarations intentionally win.
    new vm.Script(`"use strict";\n${msg.code}`, { filename: msg.name }).runInContext(context, { timeout: 2000 });
    entry = { code: msg.code, context, fresh: true };
    scripts.set(msg.name, entry);
  }
  const preferred = msg.hook === "on_request" ? ["onRequest", "on_request"] : ["onResponse", "on_response"];
  const functionName = preferred.find((name) => vm.runInContext(`typeof ${name} === "function"`, entry.context));
  entry.context.__proxyInputJson = JSON.stringify({ state: msg.context || {}, url: msg.url,
    request: msg.request, response: msg.response });
  entry.context.__proxyFresh = entry.fresh;
  new vm.Script(`
    globalThis.__proxyInput = JSON.parse(globalThis.__proxyInputJson);
    if (globalThis.__proxyFresh) Object.assign(globalThis.__proxyState, globalThis.__proxyInput.state);
    else {
      globalThis.__proxyState.flow_id = globalThis.__proxyInput.state.flow_id;
      globalThis.__proxyState.project = globalThis.__proxyInput.state.project;
    }
    globalThis.__proxyLogs.length = 0;
  `).runInContext(entry.context, { timeout: 2000 });
  entry.fresh = false;
  if (!functionName) {
    const raw = vm.runInContext(`JSON.stringify({context:globalThis.__proxyState,logs:globalThis.__proxyLogs,result:null})`, entry.context);
    return JSON.parse(raw);
  }
  const args = msg.hook === "on_request" ? "__proxyState,__proxyInput.url,__proxyInput.request"
                                         : "__proxyState,__proxyInput.url,__proxyInput.request,__proxyInput.response";
  const started = new vm.Script(`globalThis.__proxyResult = ${functionName}(${args})`)
    .runInContext(entry.context, { timeout: 2000 });
  let timer;
  const result = await Promise.race([
    Promise.resolve(started),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timed out after 2 s")), 2000); }),
  ]).finally(() => clearTimeout(timer));
  entry.context.__proxyResolved = result;
  const raw = vm.runInContext(`JSON.stringify({context:globalThis.__proxyState,logs:globalThis.__proxyLogs,result:globalThis.__proxyResolved})`, entry.context, { timeout: 2000 });
  return JSON.parse(raw);
}

rl.on("line", async (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
    // Python serialises calls to the same script. Different script contexts may
    // run concurrently, and every call's two-second budget begins here.
    process.stdout.write(JSON.stringify({ id: msg.id, started: true }) + "\n");
    const out = await invoke(msg);
    reply(msg.id, out);
  }
  catch (error) { reply(msg?.id, { error: String(error?.stack || error) }); }
});
