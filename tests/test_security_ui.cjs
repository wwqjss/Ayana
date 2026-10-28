/* Execute the production UI callbacks with controlled network ordering. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.resolve(__dirname, "../ayana/static/app.js"), "utf8");

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.children = []; this.listeners = {};
    this.className = ""; this.style = {}; this.dataset = {}; this.value = ""; this.checked = false; this._text = "";
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(" "), ...names])].join(" "); },
      remove: (...names) => { this.className = this.className.split(" ").filter((name) => !names.includes(name)).join(" "); },
      contains: (name) => this.className.split(" ").includes(name),
    };
  }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(_) { this._text = ""; this.children = []; }
  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  insertBefore(child, next) { child.parent = this; const i = this.children.indexOf(next); this.children.splice(i < 0 ? this.children.length : i, 0, child); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this); }
  get firstChild() { return this.children[0]; }
  get nextSibling() { return this.parent?.children[this.parent.children.indexOf(this) + 1]; }
  setAttribute(name, value) { if (name === "class") this.className = value; else if (name === "checked") this.checked = true; else this[name] = value; }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  async dispatch(type) { for (const listener of this.listeners[type] || []) await listener({ target: this, preventDefault() {} }); }
  async click() { if (!this.disabled) await this.dispatch("click"); }
  querySelectorAll(selector) {
    const result = [];
    const matches = (node) => selector.startsWith(".") ? node.classList.contains(selector.slice(1)) : node.tagName.toLowerCase() === selector;
    for (const child of this.children) { if (matches(child)) result.push(child); result.push(...child.querySelectorAll(selector)); }
    return result;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
const deferred = () => { let resolve, reject; const promise = new Promise((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

function environment(reply = () => ({ ok: true })) {
  const nodes = new Map(), calls = [], sockets = [], terminals = [], dialogs = [], promptReplies = [];
  for (const id of ["term-status", "term-title", "term-host-label", "term-modal", "term-container", "term-close", "term-disconnect", "term-reconnect", "modal", "modal-title", "modal-body", "agent-ceiling", "host-list", "ssh-creds", "perm-eff-cap", "perm-eff-asset", "perm-eff-object", "perm-eff-result", "perm-eff-lookup"]) {
    const node = new Element("div"); nodes.set(id, node);
  }
  const actions = new Element("div"); actions.className = "modal-actions";
  class Terminal {
    constructor() { this.cols = 80; this.rows = 24; this.output = []; terminals.push(this); }
    open() {}
    dispose() { this.disposed = true; }
    onData(callback) { this.data = callback; }
    onResize(callback) { this.resize = callback; }
    write(data) { this.output.push(data); }
  }
  class WebSocket {
    constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
    close() { this.readyState = 3; if (this.onclose) this.onclose(); }
    send(data) { this.sent.push(data); }
  }
  const context = vm.createContext({
    console, Promise, URL, TextEncoder, Uint8Array, location: { protocol: "https:", host: "ayana.test" },
    window: { Terminal }, WebSocket,
    document: {
      createElement: (tag) => new Element(tag),
      createTextNode: (text) => { const n = new Element("text"); n.textContent = text; return n; },
      querySelector: (selector) => { assert.equal(selector, "#modal .modal-actions"); return actions; },
    },
    $: (id) => nodes.get(id), on: (id, type, listener) => nodes.get(id)?.addEventListener(type, listener),
    api: async (url, options = {}) => { const call = { url, body: options.body ? JSON.parse(options.body) : null }; calls.push(call); return await reply(call); },
    prompt: () => promptReplies.shift(), confirm: () => true,
    showModal: (title, children) => { dialogs.push(title); nodes.get("modal-title").textContent = title; nodes.get("modal-body").innerHTML = ""; children.forEach((child) => nodes.get("modal-body").appendChild(child)); nodes.get("modal").classList.remove("hidden"); },
    humanFormError: (res, fallback) => res.hint || fallback,
    permissionCapabilityLabel: (capability) => capability,
    permissionObjectLabel: (_, object) => object,
    checkHostLabel: (asset) => asset === "control" ? "Control" : "Sora",
    populatePermissionObjects: () => {},
    badge: (text) => { const node = new Element("span"); node.textContent = text; return node; },
    setTabHash: () => {}, fmtTime: () => "", loopOutcome: () => ({}), renderLoopSteps: () => new Element("div"),
    fillSelect: () => {}, credLabel: (credential) => credential.name,
  });
  const cut = (start, end) => {
    const a = source.indexOf(start), b = source.indexOf(end, a);
    assert.ok(a >= 0 && b > a, start + " → " + end); return source.slice(a, b);
  };
  for (const [start, end] of [
    ["function el(", "async function api("],
    ["const effectivePermissionState", "function permissionCapabilityLabel("],
    ['on("perm-eff-cap", "change"', "function collectAdvancedPermission("],
    ["/* ---- Agent ceiling ---- */", "/* ---- modal ---- */"],
    ["async function openIncidentDetail(", "function openActionDetail("],
    ["async function renderConnections(", 'on("host-auth", "change"'],
  ]) vm.runInContext(cut(start, end), context);
  for (const [id, value] of [["perm-eff-cap", "service.restart"], ["perm-eff-asset", "control"], ["perm-eff-object", "*"]]) nodes.get(id).value = value;
  return { nodes, calls, sockets, terminals, dialogs, actions, promptReplies, run: (code) => vm.runInContext(code, context) };
}
const tests = [];
const test = (name, run) => tests.push({ name, run });
const checkSuccess = { ok: true };
const keyCheck = { ok: false, detail: "host_key_untrusted", host_key_info: { host: "control", fingerprint: "SHA256:test", key_line: "ssh-ed25519 test" } };
const socketAsset = (socket) => new URL(socket.url).searchParams.get("asset_id");

test("closing and reopening for another host ignores the old connection check", async () => {
  const control = deferred(), sora = deferred();
  const env = environment(({ url }) => url.includes("control") ? control.promise : sora.promise);
  const first = env.run('openTerminal("control")'); await env.nodes.get("term-close").click();
  const second = env.run('openTerminal("sora")'); sora.resolve(checkSuccess); await second;
  control.resolve(checkSuccess); await first;
  assert.deepEqual(env.sockets.map(socketAsset), ["sora"]);
  assert.equal(env.nodes.get("term-title").textContent, "终端 · sora");
  assert.equal(env.run("termState.assetId"), "sora");
});

test("closing a pending terminal prevents any late socket or host-key dialog", async () => {
  const check = deferred(); const env = environment(() => check.promise);
  const opening = env.run('openTerminal("control")'); await env.nodes.get("term-close").click();
  check.resolve(keyCheck); await opening;
  assert.equal(env.sockets.length, 0); assert.equal(env.dialogs.length, 0);
  assert.equal(env.run("termState.assetId"), "");
  await env.nodes.get("term-reconnect").click(); assert.equal(env.calls.length, 1);
});

test("changing hosts closes the old socket immediately and ignores every old callback", async () => {
  const next = deferred(); let count = 0;
  const env = environment(() => ++count === 1 ? checkSuccess : next.promise);
  await env.run('openTerminal("control")');
  const old = env.sockets[0], terminal = env.terminals[0]; old.readyState = 1;
  const callbacks = { open: old.onopen, message: old.onmessage, close: old.onclose, error: old.onerror };
  const switching = env.run('openTerminal("sora")');
  assert.equal(old.readyState, 3); assert.equal(terminal.disposed, true);
  old.readyState = 1; terminal.data("id\n"); terminal.resize({ cols: 100, rows: 30 });
  callbacks.open(); callbacks.message({ data: JSON.stringify({ type: "ready", host: "control" }) });
  callbacks.message({ data: new Uint8Array([1, 2]).buffer });
  callbacks.message({ data: JSON.stringify({ type: "error", host_key_info: keyCheck.host_key_info }) });
  callbacks.close(); callbacks.error();
  assert.equal(old.sent.length, 0); assert.equal(terminal.output.length, 0); assert.equal(env.dialogs.length, 0);
  assert.equal(env.nodes.get("term-status").textContent, "检查连接…");
  next.resolve(checkSuccess); await switching;
  assert.equal(socketAsset(env.sockets[1]), "sora");
  env.sockets[1].readyState = 1; env.terminals[1].data("id\n"); assert.equal(env.sockets[1].sent.length, 1);
});

test("opening the same host twice still discards the earlier request generation", async () => {
  const first = deferred(), second = deferred(); let count = 0;
  const env = environment(() => ++count === 1 ? first.promise : second.promise);
  const a = env.run('openTerminal("control")'), b = env.run('openTerminal("control")');
  second.resolve(checkSuccess); await b; first.resolve({ ok: false, hint: "old failure" }); await a;
  assert.equal(env.sockets.length, 1); assert.equal(env.nodes.get("term-status").textContent, "连接中…");
});

test("a late network failure from the old terminal cannot replace the current connection", async () => {
  const old = deferred(); const env = environment(({ url }) => url.includes("control") ? old.promise : checkSuccess);
  const first = env.run('openTerminal("control")'); await env.run('openTerminal("sora")');
  old.reject(new Error("old connection failed")); await first;
  assert.deepEqual(env.sockets.map(socketAsset), ["sora"]);
  assert.equal(env.nodes.get("term-status").textContent, "连接中…");
});

test("active socket input and status refer to the selected host", async () => {
  const env = environment(); await env.run('openTerminal("sora")');
  const socket = env.sockets[0], terminal = env.terminals[0]; socket.readyState = 1;
  socket.onmessage({ data: JSON.stringify({ type: "ready", remote_user: "admin", host: "sora", port: 22, auth_method: "key" }) });
  terminal.data("id\n"); terminal.resize({ cols: 100, rows: 40 });
  assert.equal(env.nodes.get("term-host-label").textContent, "admin@sora:22 · 密钥登录");
  assert.equal(env.nodes.get("term-status").textContent, "已连接");
  assert.equal(new TextDecoder().decode(socket.sent[0]), "id\n");
  assert.deepEqual(JSON.parse(socket.sent[1]), { type: "resize", cols: 100, rows: 40 });
});

test("disconnect invalidates pending checks and reconnect performs a new permission check", async () => {
  const check = deferred(); let count = 0;
  const env = environment(() => ++count === 1 ? check.promise : { ok: false, hint: "权限已撤销" });
  const opening = env.run('openTerminal("control")'); await env.nodes.get("term-disconnect").click();
  check.resolve(checkSuccess); await opening; assert.equal(env.sockets.length, 0);
  await env.nodes.get("term-reconnect").click(); await flush();
  assert.equal(env.calls.length, 2); assert.equal(env.sockets.length, 0);
  assert.equal(env.nodes.get("term-container").textContent, "权限已撤销");
});

test("trust completion after closing cannot reopen an old terminal", async () => {
  const trust = deferred(); const env = environment(({ url }) => url.includes("/trust") ? trust.promise : keyCheck);
  await env.run('openTerminal("control")');
  const trusting = env.actions.querySelectorAll("button").find((n) => n.textContent === "信任并连接").click();
  await env.nodes.get("term-close").click(); trust.resolve({ ok: true }); await trusting;
  assert.equal(env.calls.length, 2); assert.equal(env.sockets.length, 0); assert.equal(env.run("termState.visible"), false);
});

test("a trust dialog from another host cannot submit trust or reconnect", async () => {
  const env = environment(({ url }) => url.includes("control") ? keyCheck : checkSuccess);
  await env.run('openTerminal("control")');
  const oldTrust = env.actions.querySelectorAll("button").find((n) => n.textContent === "信任并连接");
  await env.run('openTerminal("sora")'); await oldTrust.click();
  assert.equal(env.calls.length, 2); assert.deepEqual(env.sockets.map(socketAsset), ["sora"]);
});

const proposalReply = { ok: true, incident: {}, summary: {}, disposition: { proposals: [{ action_id: "act1", capability: "service.restart", asset_id: "control", object_id: "nginx" }] } };
for (const label of ["批准并执行", "拒绝"]) {
  test(`canceling ${label} submits no approval decision`, async () => {
    const env = environment(() => proposalReply); await env.run('openIncidentDetail("inc1")');
    env.promptReplies.push(null);
    await env.nodes.get("modal-body").querySelectorAll("button").find((n) => n.textContent === label).click();
    assert.equal(env.calls.length, 1); assert.equal(env.nodes.get("modal").classList.contains("hidden"), false);
  });
}
test("confirming an empty approval reason still approves exactly once", async () => {
  const env = environment(({ body }) => body ? { ok: true } : proposalReply); await env.run('openIncidentDetail("inc1")');
  env.promptReplies.push("");
  await env.nodes.get("modal-body").querySelectorAll("button").find((n) => n.textContent === "批准并执行").click(); await flush();
  assert.deepEqual(env.calls.filter((call) => call.body).map((call) => call.body), [{ execute: true, reason: "" }]);
});

test("permission responses cannot overwrite the result for a newer host", async () => {
  const control = deferred(), sora = deferred();
  const env = environment(({ url }) => url.includes("control") ? control.promise : sora.promise);
  const oldLookup = env.nodes.get("perm-eff-lookup").click();
  env.nodes.get("perm-eff-asset").value = "sora"; await env.nodes.get("perm-eff-asset").dispatch("change");
  const lookup = env.nodes.get("perm-eff-lookup").click();
  sora.resolve({ ok: true, effective: { state: "deny", readable: "禁止" } }); await lookup;
  control.resolve({ ok: true, effective: { state: "auto", readable: "自动执行" } }); await oldLookup;
  assert.ok(env.nodes.get("perm-eff-result").textContent.includes("Sora"));
  assert.ok(env.nodes.get("perm-eff-result").textContent.includes("禁止"));
  assert.ok(!env.nodes.get("perm-eff-result").textContent.includes("自动执行"));
});

test("a network failure from the previous permission query cannot replace current results", async () => {
  const old = deferred(); const env = environment(({ url }) => url.includes("control") ? old.promise : { ok: true, effective: { state: "deny", readable: "禁止" } });
  const first = env.nodes.get("perm-eff-lookup").click();
  env.nodes.get("perm-eff-asset").value = "sora"; await env.nodes.get("perm-eff-asset").dispatch("change");
  await env.nodes.get("perm-eff-lookup").click(); old.reject(new Error("offline")); await first;
  assert.ok(env.nodes.get("perm-eff-result").textContent.includes("Sora"));
  assert.ok(!env.nodes.get("perm-eff-result").textContent.includes("连接中断"));
});

for (const [id, value] of [["perm-eff-cap", "service.logs"], ["perm-eff-asset", "sora"], ["perm-eff-object", "redis"]]) {
  test(`${id} changes immediately invalidate both displayed and pending results`, async () => {
    const pending = deferred(); let count = 0;
    const env = environment(() => ++count === 1 ? { ok: true, effective: { state: "auto", readable: "自动执行" } } : pending.promise);
    await env.nodes.get("perm-eff-lookup").click(); const lookup = env.nodes.get("perm-eff-lookup").click();
    const node = env.nodes.get(id), original = node.value;
    node.value = value; await node.dispatch("change"); node.value = original; await node.dispatch("change");
    assert.equal(env.nodes.get("perm-eff-result").textContent, "请选择目标后查询当前权限。");
    pending.resolve({ ok: true, effective: { state: "auto", readable: "自动执行" } }); await lookup;
    assert.equal(env.nodes.get("perm-eff-result").textContent, "请选择目标后查询当前权限。");
  });
}

const ceilingReply = { ok: true, agent_ceiling: [{ capability: "service.restart", allowed: true, allow_auto: true }] };
test("quick ceiling changes preserve both fields and serialize full-row writes", async () => {
  const firstSave = deferred(), oldRender = deferred(); let getCount = 0, postCount = 0;
  const env = environment(({ body }) => body ? ++postCount === 1 ? firstSave.promise : { ok: true } : ++getCount === 1 ? ceilingReply : oldRender.promise);
  await env.run("renderAgentCeiling()"); const oldLoad = env.run("renderAgentCeiling()");
  const [allowed, auto] = env.nodes.get("agent-ceiling").querySelectorAll("input");
  allowed.checked = false; const a = allowed.dispatch("change");
  auto.checked = false; const b = auto.dispatch("change"); await flush();
  assert.equal(env.calls.filter((call) => call.body).length, 1);
  oldRender.resolve(ceilingReply); await oldLoad;
  assert.equal(env.nodes.get("agent-ceiling").querySelectorAll("input")[0], allowed);
  firstSave.resolve({ ok: true }); await Promise.all([a, b]);
  assert.deepEqual(env.calls.filter((call) => call.body).map((call) => call.body), [
    { capability: "service.restart", allowed: false, allow_auto: true },
    { capability: "service.restart", allowed: false, allow_auto: false },
  ]);
  assert.equal(allowed.checked, false); assert.equal(auto.checked, false);
  assert.ok(env.nodes.get("agent-ceiling").textContent.includes("已保存"));
});

test("failed ceiling saves restore the confirmed state and explain the failure", async () => {
  const env = environment(({ body }) => body ? { ok: false, hint: "没有管理权限" } : ceilingReply);
  await env.run("renderAgentCeiling()"); const allowed = env.nodes.get("agent-ceiling").querySelectorAll("input")[0];
  allowed.checked = false; await allowed.dispatch("change");
  assert.equal(allowed.checked, true); assert.ok(env.nodes.get("agent-ceiling").textContent.includes("没有管理权限"));
  assert.equal(env.run("agentCeilingState.pending"), 0);
});

test("a network failure does not poison subsequent ceiling saves", async () => {
  let posts = 0; const env = environment(({ body }) => {
    if (!body) return ceilingReply;
    if (++posts === 1) throw new Error("offline");
    return { ok: true };
  });
  await env.run("renderAgentCeiling()"); const allowed = env.nodes.get("agent-ceiling").querySelectorAll("input")[0];
  allowed.checked = false; await allowed.dispatch("change"); assert.equal(allowed.checked, true);
  allowed.checked = false; await allowed.dispatch("change"); assert.equal(allowed.checked, false);
  assert.ok(env.nodes.get("agent-ceiling").textContent.includes("已保存"));
});

test("private-key rotation lets the server derive the new public key", async () => {
  const credential = { id: "cred1", name: "Key", kind: "key", public_key: "ssh-ed25519 OLD" };
  const env = environment(({ url }) => url === "/api/assets" ? { ok: true, assets: [] } : url === "/api/ssh/credentials" ? { ok: true, credentials: [credential] } : url === "/api/ssh/roles" ? { ok: true, roles: [] } : { ok: true });
  await env.run("renderConnections()");
  await env.nodes.get("ssh-creds").querySelectorAll("button").find((node) => node.textContent === "更新凭据").click();
  const editor = env.nodes.get("modal-body").querySelector("textarea");
  assert.ok(editor, "private-key editing must preserve PEM newlines");
  editor.value = "NEW PRIVATE KEY";
  assert.ok(!env.calls.some((call) => call.url.endsWith("/rotate")), "opening a credential editor must not rotate it");
  await env.nodes.get("modal-body").querySelector("form").dispatch("submit");
  const rotation = env.calls.find((call) => call.url.endsWith("/rotate"));
  assert.deepEqual(rotation.body, { id: "cred1", secret: "NEW PRIVATE KEY" });
});

(async () => {
  let failures = 0;
  for (const { name, run } of tests) {
    try { await run(); console.log("PASS " + name); }
    catch (error) { failures++; console.error("FAIL " + name); console.error(error); }
  }
  console.log(`${tests.length - failures}/${tests.length} security UI checks passed`);
  process.exitCode = failures ? 1 : 0;
})();
