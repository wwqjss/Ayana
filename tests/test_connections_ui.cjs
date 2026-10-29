/* Exercise real connection/NodeWatch callbacks against controlled DOM and API ordering. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

class Element {
  constructor(tag, registry) {
    this.tagName = tag.toUpperCase(); this.registry = registry; this.children = []; this.listeners = {};
    this.dataset = {}; this.className = ""; this.value = ""; this.disabled = false; this.open = false; this.attributes = {}; this._text = "";
    this.classList = {
      contains: (name) => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(" "); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter((name) => !names.includes(name)).join(" "); },
      toggle: (name, force) => { if (force === undefined) force = !this.classList.contains(name); if (force) this.classList.add(name); else this.classList.remove(name); },
    };
  }
  set textContent(value) { this._text = String(value); this.children.forEach((child) => { child.parentElement = null; }); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(_) { this.textContent = ""; }
  get innerHTML() { return this.textContent; }
  get isConnected() { return this.tagName === "BODY" || !!this.parentElement?.isConnected; }
  appendChild(child) { child.remove(); child.parentElement = this; this.children.push(child); if (this.tagName === "SELECT" && this.children.length === 1) this.value = child.value; return child; }
  remove() { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter((child) => child !== this); this.parentElement = null; }
  replaceWith(replacement) { const parent = this.parentElement; if (!parent) return; const i = parent.children.indexOf(this); parent.children[i] = replacement; replacement.parentElement = parent; this.parentElement = null; }
  setAttribute(name, value) { this.attributes[name] = String(value); if (name === "class") this.className = String(value); else this[name] = value; if (name === "id") this.registry.set(value, this); }
  getAttribute(name) { return this.attributes[name] ?? this[name] ?? null; }
  addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
  async dispatch(type) { for (const callback of this.listeners[type] || []) await callback({ target: this, preventDefault() {}, stopPropagation() {} }); }
  async click() { if (!this.disabled) await this.dispatch("click"); }
  querySelectorAll(selector) { return this.children.flatMap((child) => [ ...(selector.startsWith(".") ? child.classList.contains(selector.slice(1)) : child.tagName.toLowerCase() === selector) ? [child] : [], ...child.querySelectorAll(selector) ]); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  focus() { this.focused = true; }
  select() { this.selected = true; }
  scrollIntoView() { this.scrolled = true; }
}

const hosts = [{ id: "romi", display_name: "ROMI", enabled: true, objects: [], ssh_endpoints: [{ asset_id: "romi", role: "default", username: "ops", host: "10.0.0.14", port: 22, credential_id: "key1", host_key_trusted_at: 1, host_key_sha256: "SHA256:host" }] }];
const credentials = [{ id: "key1", name: "Romi key", kind: "private_key", public_key: "ssh-ed25519 PUBLIC", secret: "MUST NEVER APPEAR" }, { id: "pw1", name: "Password", kind: "password", secret: "MUST NEVER APPEAR" }];
const nodeStatus = { send: { enabled: true, node_id: "romi", target_url: "https://control.test/heartbeat", interval_sec: 15, last_send: { ok: true, at: 100 } }, recv: { enabled: false, allowed_nodes: [], timeout_sec: 180 }, peers: [{ node_id: "control", status: "online", last_seen_at: 101 }] };

function environment(reply, options = {}) {
  const nodes = new Map(), calls = [], opened = [], confirmations = [], events = {};
  const body = new Element("body", nodes);
  const create = (id, tag = "div") => { const node = new Element(tag, nodes); node.id = id; nodes.set(id, node); body.appendChild(node); return node; };
  ["host-list", "ssh-creds", "host-list-count", "ssh-creds-count", "connections-load-error", "host-add-panel", "credential-editor-panel", "connections-sub-hosts", "connections-sub-nodewatch", "notify-sub-channels", "notify-sub-messages", "notify-sub-outbox", "tab-connections", "tab-notify", "modal", "modal-body", "notify-list", "notify-editor-panel", "notify-channel-count", "nw-status-summary", "nw-status", "nw-err", "nw-recv-box", "nw-send-box", "nw-invite-box", "nw-fp", "nw-parse-box", "nw-p-url", "nw-p-node", "nw-p-fp"].forEach((id) => create(id));
  create("account-groups-list");
  ["host-cred", "host-role", "ssh-test-asset", "ssh-test-role", "nw-role", "ssh-cred-kind"].forEach((id) => create(id, "select"));
  ["ag-assign-group", "ag-assign-asset", "ag-assign-cred"].forEach((id) => create(id, "select"));
  ["host-id", "ssh-cred-name", "ssh-cred-secret", "nw-interval", "nw-node-id", "nw-url", "nw-invite", "nw-paste", "nw-p-fp-in"].forEach((id) => create(id, "input"));
  ["connections-add-open", "nw-refresh", "nw-gen", "nw-gen-keep", "nw-copy", "nw-parse", "nw-apply", "nw-save-interval"].forEach((id) => create(id, "button"));
  const connectionTabs = ["hosts", "nodewatch"].map((sub) => { const node = create("connection-" + sub, "button"); node.dataset.sub = sub; return node; });
  const notifyTabs = ["messages", "outbox"].map((sub) => { const node = create("notify-" + sub, "button"); node.dataset.sub = sub; return node; });
  const state = { tab: "connections", focus: "", connectionsSub: "hosts", notifySub: "messages", aibotStatus: {} };
  const location = { hash: "#connections" };
  const defaults = (url) => {
    if (url === "/api/assets") return { ok: true, assets: hosts };
    if (url === "/api/ssh/credentials") return { ok: true, credentials };
    if (url === "/api/ssh/roles") return { ok: true, roles: [{ name: "default", label: "默认" }, { name: "ops", label: "运维" }] };
    if (url === "/api/ssh/account-groups") return { ok: true, groups: [{ name: "default", label: "默认", members: hosts[0].ssh_endpoints }, { name: "ops", label: "运维", members: [] }] };
    if (url === "/api/node-watch/status") return { ok: true, status: nodeStatus };
    if (url === "/api/node-watch/invite/generate") return { ok: true, invite: "INVITE", fp: "fp" };
    if (url === "/api/node-watch/invite/parse") return { ok: true, url: "https://control.test", node_id: "romi", fp: "verified-separately" };
    if (url === "/api/notify/channels") return { ok: true, channels: [] };
    return { ok: true, interval_sec: 30 };
  };
  const context = vm.createContext({
    console, Promise, Date, Map, Set, Number, String, Array, state, location,
    history: { replaceState: (_, __, hash) => { location.hash = hash; } },
    queueMicrotask: (callback) => Promise.resolve().then(callback),
    window: { addEventListener() {}, renderAgentWorkbench: async () => {}, openAgentSettings: async () => { opened.push("agent"); } },
    document: { createElement: (tag) => new Element(tag, nodes), createTextNode: (text) => { const node = new Element("text", nodes); node.textContent = text; return node; }, getElementById: (id) => nodes.get(id),
      querySelectorAll: (selector) => selector === "#connections-subnav .subtab" ? connectionTabs : selector === "#notify-subnav .subtab" ? notifyTabs : selector === ".tab-panel" ? [nodes.get("tab-connections"), nodes.get("tab-notify")] : [], addEventListener: (type, callback) => { events[type] = callback; }, execCommand: () => options.copyResult === true },
    $: (id) => nodes.get(id), on: (id, type, callback) => nodes.get(id)?.addEventListener(type, callback),
    api: async (url, settings = {}) => { const request = { url, method: settings.method || "GET", body: settings.body ? JSON.parse(settings.body) : null }; calls.push(request); const result = reply?.(request, defaults); return result === undefined ? defaults(url) : await result; },
    refreshTab() {}, renderPromConfig() {}, syncChecksAsset() {}, renderChecks() {}, renderMonitor() {}, renderMessages() {}, initExtFormDom() {}, renderExtTransactions() {},
    openSettings: (section) => opened.push(section),
    confirm: (text) => { confirmations.push(text); return options.confirmResult !== false; },
    prompt: () => { throw new Error("Secrets must not use browser prompts"); },
    showModal: (title, children) => { const modal = nodes.get("modal-body"); modal.innerHTML = ""; children.forEach((child) => modal.appendChild(child)); nodes.get("modal").classList.remove("hidden"); },
    badge: (text, cls) => { const node = new Element("span", nodes); node.className = "badge " + cls; node.textContent = text; return node; },
    hostStatusBadge: () => { const node = new Element("span", nodes); node.textContent = "SSH 已信任"; return node; },
    credLabel: (credential) => credential.name, fmtTime: (time) => "时间 " + time,
  });
  const cut = (start, end) => { const a = source.indexOf(start), b = source.indexOf(end, a); assert.ok(a >= 0 && b > a, start); return source.slice(a, b); };
  for (const [start, end] of [["function el(", "async function api("], ["function currentTabFromHash(", "async function boot("], ["function fillSelect(", "async function refreshTab("], ["function renderAccountGroups(", 'on("host-auth", "change"'], ["function sshFormModal(", "const pcProgressByHost"], ["/* ---- 节点守望配对 ---- */", "/* ---- 外部事务 ---- */"], ["async function loadNotifyChannels(", "async function loadNotifyOutbox("]]) vm.runInContext(cut(start, end), context);
  return { nodes, calls, opened, confirmations, state, location, events, run: (code) => vm.runInContext(code, context) };
}

const tests = []; const test = (name, run) => tests.push({ name, run });
test("legacy NodeWatch and channel bookmarks reach their new homes", async () => {
  const env = environment(); env.location.hash = "#notify/nodewatch";
  assert.equal(env.run("currentTabFromHash().tab"), "connections");
  env.run('activateTab("notify", "nodewatch")'); assert.equal(env.location.hash, "#connections/nodewatch");
  env.run('activateTab("notify", "channels")'); await flush();
  assert.equal(env.state.notifySub, "messages"); assert.deepEqual(env.opened, ["notifications"]);
  assert.equal(env.location.hash, "#notify/messages");
});
test("legacy permission bookmarks open the unified Agent settings once", async () => {
  const env = environment(); env.location.hash = "#permissions/effective";
  assert.equal(env.run("currentTabFromHash().tab"), "agent");
  assert.equal(env.run("currentTabFromHash().focus"), "settings");
  env.run('activateTab("permissions", "effective")');
  assert.equal(env.state.tab, "agent"); assert.equal(env.location.hash, "#agent/settings");
  const start = source.indexOf("async function refreshTab() {"), end = source.indexOf("function syncChecksAsset()", start);
  env.run(source.slice(start, end));
  await env.run("refreshTab()"); await env.run("refreshTab()");
  assert.deepEqual(env.opened, ["agent"]); assert.equal(env.location.hash, "#agent");
  assert.equal(env.calls.length, 0);
});
test("retired permission UI has no navigation, rule editor, API calls, or permanent grants", () => {
  const html = fs.readFileSync(path.join(__dirname, "../ayana/static/index.html"), "utf8");
  assert.ok(!html.includes('data-tab="permissions"')); assert.ok(!html.includes('id="tab-permissions"'));
  for (const retired of ["/api/permissions", "/api/agent-ceiling", "allow_always", "永久允许执行", "matched_rule"]) assert.ok(!source.includes(retired), retired);
});
test("connection subviews update both visibility and bookmark without posting", () => {
  const env = environment(); env.run('setConnectionsSub("nodewatch")');
  assert.equal(env.nodes.get("connections-sub-hosts").classList.contains("hidden"), true);
  assert.equal(env.nodes.get("connections-sub-nodewatch").classList.contains("hidden"), false);
  assert.equal(env.location.hash, "#connections/nodewatch"); assert.equal(env.calls.length, 0);
});
test("host and credential details start closed and summary rows contain no action buttons or public keys", async () => {
  const env = environment(); await env.run("renderConnections()");
  const host = env.nodes.get("host-list").children[0], credential = env.nodes.get("ssh-creds").children[0];
  assert.equal(host.tagName, "DETAILS"); assert.equal(host.open, false); assert.equal(credential.open, false);
  assert.equal(host.querySelector("summary").querySelectorAll("button").length, 0);
  assert.ok(!credential.querySelector("summary").textContent.includes("ssh-ed25519"));
  assert.ok(!env.nodes.get("ssh-creds").textContent.includes("MUST NEVER APPEAR"));
  assert.ok(!env.calls.some((call) => call.method !== "GET"));
});
test("refresh retains expanded rows and selected role, credential and test host", async () => {
  const env = environment(); await env.run("renderConnections()");
  env.nodes.get("host-list").children[0].open = true; env.nodes.get("ssh-creds").children[1].open = true;
  env.nodes.get("host-role").value = "ops"; env.nodes.get("host-cred").value = "pw1"; env.nodes.get("ssh-test-asset").value = "romi";
  await env.run("renderConnections()");
  assert.equal(env.nodes.get("host-list").children[0].open, true); assert.equal(env.nodes.get("ssh-creds").children[1].open, true);
  assert.equal(env.nodes.get("host-role").value, "ops"); assert.equal(env.nodes.get("host-cred").value, "pw1"); assert.equal(env.nodes.get("ssh-test-asset").value, "romi");
});
test("failed loads retain previous lists and selector drafts with an explicit error", async () => {
  let fail = false; const env = environment(() => fail ? { ok: false } : undefined);
  await env.run("renderConnections()"); const previous = env.nodes.get("host-list").children[0];
  env.nodes.get("host-cred").value = "pw1"; env.nodes.get("host-role").value = "ops";
  fail = true; await env.run("renderConnections()");
  assert.equal(env.nodes.get("host-list").children[0], previous); assert.equal(env.nodes.get("ssh-creds").children.length, 2);
  assert.equal(env.nodes.get("host-cred").value, "pw1"); assert.equal(env.nodes.get("host-role").value, "ops");
  assert.ok(env.nodes.get("connections-load-error").textContent.includes("暂时无法加载"));
});
test("account groups show actual members and retain selections without restoring read/write groups", async () => {
  const env = environment(); await env.run("renderConnections()");
  assert.ok(env.nodes.get("account-groups-list").textContent.includes("ops@10.0.0.14:22"));
  const group = env.nodes.get("ag-assign-group");
  assert.deepEqual(group.children.map(option => option.value), ["default", "ops"]);
  assert.equal(env.nodes.get("ag-assign-cred").children[0].textContent, "沿用已有账号凭据");
  group.value = "ops"; env.nodes.get("ag-assign-cred").value = "key1";
  await env.run("renderConnections()");
  assert.equal(group.value, "ops"); assert.equal(env.nodes.get("ag-assign-cred").value, "key1");
  assert.equal(env.nodes.get("ag-assign-asset").children[0].disabled, false);
});
test("a failed account-group refresh retains the confirmed member list and draft", async () => {
  let failed = false;
  const env = environment(({url}) => failed && url === "/api/ssh/account-groups" ? {ok:false} : undefined);
  await env.run("renderConnections()");
  const confirmed = env.nodes.get("account-groups-list").children[0];
  env.nodes.get("ag-assign-group").value = "ops";
  env.nodes.get("ag-assign-cred").value = "key1";
  failed = true; await env.run("renderConnections()");
  assert.equal(env.nodes.get("account-groups-list").children[0], confirmed);
  assert.equal(env.nodes.get("ag-assign-group").value, "ops"); assert.equal(env.nodes.get("ag-assign-cred").value, "key1");
  assert.ok(env.nodes.get("connections-load-error").textContent.includes("账号组成员暂时无法加载"));
});
test("a late connections request cannot replace a newer result", async () => {
  const first = deferred(), second = deferred(); let requests = 0;
  const env = environment(({ url }) => url === "/api/assets" ? (++requests === 1 ? first.promise : second.promise) : undefined);
  const old = env.run("renderConnections()"); const next = env.run("renderConnections()");
  second.resolve({ ok: true, assets: [{ ...hosts[0], id: "new", display_name: "New" }] }); await next;
  first.resolve({ ok: true, assets: hosts }); await old;
  assert.ok(env.nodes.get("host-list").textContent.includes("New")); assert.ok(!env.nodes.get("host-list").textContent.includes("ROMI"));
});
test("password entries cannot deploy public keys and rotate only after explicit masked submission", async () => {
  const env = environment(); await env.run("renderConnections()");
  const row = env.nodes.get("ssh-creds").children[1]; assert.equal(row.querySelectorAll("button")[0].disabled, true);
  await row.querySelectorAll("button")[1].click();
  const editor = env.nodes.get("modal-body").querySelector("input"); assert.equal(editor.type, "password");
  assert.ok(!env.calls.some((call) => call.url.endsWith("/rotate")));
  editor.value = "  password with spaces  "; await env.nodes.get("modal-body").querySelector("form").dispatch("submit");
  assert.deepEqual(env.calls.find((call) => call.url.endsWith("/rotate")).body, { id: "pw1", secret: "  password with spaces  " });
});
test("private-key editing preserves PEM lines and leaves public-key derivation to the server", async () => {
  const env = environment(); env.run('openCredentialRotation({id:"key1",kind:"private_key",name:"Key"})');
  const editor = env.nodes.get("modal-body").querySelector("textarea"); editor.value = "-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----\n";
  await env.nodes.get("modal-body").querySelector("form").dispatch("submit");
  const body = env.calls.find((call) => call.url.endsWith("/rotate")).body;
  assert.equal(body.secret, "-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----\n"); assert.equal(Object.hasOwn(body, "public_key"), false);
});
test("credential save failure retains the draft, reports failure and suppresses duplicate submissions", async () => {
  const pending = deferred(); const env = environment(({ url }) => url.endsWith("/rotate") ? pending.promise : undefined);
  env.run('openCredentialRotation({id:"pw1",kind:"password",name:"Password"})');
  const form = env.nodes.get("modal-body").querySelector("form"), input = form.querySelector("input"); input.value = "keep me";
  const first = form.dispatch("submit"); await form.dispatch("submit"); assert.equal(env.calls.length, 1);
  pending.resolve({ ok: false, error: "权限不足" }); await first;
  assert.equal(input.value, "keep me"); assert.ok(form.textContent.includes("权限不足")); assert.equal(form.querySelector("button").disabled, false);
});
test("closing a credential editor prevents a retained callback from submitting its secret", async () => {
  const env = environment(); env.run('openCredentialRotation({id:"pw1",kind:"password",name:"Password"})');
  const form = env.nodes.get("modal-body").querySelector("form"); form.querySelector("input").value = "must not submit";
  env.nodes.get("modal").classList.add("hidden"); await form.dispatch("submit"); assert.equal(env.calls.length, 0);
});
test("credential import switches to a multiline key editor and clears incompatible secret drafts", async () => {
  const env = environment(); env.nodes.get("ssh-cred-secret").value = "private password";
  env.nodes.get("ssh-cred-kind").value = "private_key"; await env.nodes.get("ssh-cred-kind").dispatch("change");
  const key = env.nodes.get("ssh-cred-secret"); assert.equal(key.tagName, "TEXTAREA"); assert.equal(key.value, "");
  key.value = "PEM\nMULTILINE"; env.nodes.get("ssh-cred-kind").value = "password"; await env.nodes.get("ssh-cred-kind").dispatch("change");
  assert.equal(env.nodes.get("ssh-cred-secret").tagName, "INPUT"); assert.equal(env.nodes.get("ssh-cred-secret").type, "password"); assert.equal(env.nodes.get("ssh-cred-secret").value, "");
});
test("a partial credential load failure retains the known host authentication and current credential choice", async () => {
  let failed = false; const env = environment(({ url }) => failed && url === "/api/ssh/credentials" ? { ok: false } : undefined);
  await env.run("renderConnections()"); env.nodes.get("host-cred").value = "pw1"; failed = true; await env.run("renderConnections()");
  assert.ok(env.nodes.get("host-list").textContent.includes("认证：密钥")); assert.equal(env.nodes.get("host-cred").value, "pw1");
});
test("NodeWatch presents human statuses, preserves interval drafts and selects the configured direction", async () => {
  const env = environment(); await env.run("renderNodeWatch()");
  const summary = env.nodes.get("nw-status-summary").textContent;
  assert.ok(summary.includes("发送正常")); assert.ok(summary.includes("最近发送")); assert.ok(summary.includes("在线"));
  assert.equal(env.nodes.get("nw-role").value, "send"); assert.equal(env.nodes.get("nw-interval").value, "15");
  env.nodes.get("nw-interval").value = "45"; await env.nodes.get("nw-interval").dispatch("input");
  await env.run("renderNodeWatch()"); assert.equal(env.nodes.get("nw-interval").value, "45");
  assert.ok(!summary.includes('"send"')); assert.ok(env.nodes.get("nw-status").textContent.includes('"send"'));
});
test("normal invitation generation reuses the key and canceled rotation sends nothing", async () => {
  const env = environment(); await env.nodes.get("nw-gen-keep").click();
  assert.equal(env.calls.find((call) => call.url.endsWith("/generate")).body.rotate, false); assert.equal(env.confirmations.length, 0);
  const cancel = environment(undefined, { confirmResult: false }); await cancel.nodes.get("nw-gen").click(); assert.equal(cancel.calls.length, 0);
  assert.ok(cancel.confirmations[0].includes("配对失效"));
});
test("fingerprint confirmation is entered manually and stale parsed invitations cannot be displayed", async () => {
  const env = environment(); env.nodes.get("nw-paste").value = "INVITE"; env.nodes.get("nw-p-fp-in").value = "old";
  await env.nodes.get("nw-parse").click(); assert.equal(env.nodes.get("nw-p-fp-in").value, "");
  env.nodes.get("nw-paste").value = "DIFFERENT"; await env.nodes.get("nw-paste").dispatch("input"); assert.equal(env.nodes.get("nw-parse-box").classList.contains("hidden"), true);
  const pending = deferred(); const stale = environment(({ url }) => url.endsWith("/parse") ? pending.promise : undefined);
  stale.nodes.get("nw-parse-box").classList.add("hidden"); stale.nodes.get("nw-paste").value = "FIRST";
  const parsing = stale.nodes.get("nw-parse").click(); stale.nodes.get("nw-paste").value = "SECOND";
  pending.resolve({ ok: true, url: "wrong target", fp: "old" }); await parsing;
  assert.equal(stale.nodes.get("nw-parse-box").classList.contains("hidden"), true);
});
test("pairing requires the manually entered matching fingerprint before posting", async () => {
  const env = environment(); env.nodes.get("nw-paste").value = "INVITE"; await env.nodes.get("nw-parse").click();
  await env.nodes.get("nw-apply").click(); assert.ok(!env.calls.some((call) => call.url.endsWith("/apply")));
  env.nodes.get("nw-p-fp-in").value = "wrong"; await env.nodes.get("nw-apply").click(); assert.ok(!env.calls.some((call) => call.url.endsWith("/apply")));
  env.nodes.get("nw-p-fp-in").value = "verified-separately"; await env.nodes.get("nw-apply").click();
  assert.equal(env.calls.filter((call) => call.url.endsWith("/apply")).length, 1);
  assert.equal(env.calls.find((call) => call.url.endsWith("/apply")).body.fp, "verified-separately");
});
test("failed clipboard writes never report copied and successful status is not styled as an error", async () => {
  const env = environment(); await env.nodes.get("nw-copy").click(); assert.ok(env.nodes.get("nw-err").textContent.includes("手动复制"));
  const success = environment(undefined, { copyResult: true }); await success.nodes.get("nw-copy").click();
  assert.ok(success.nodes.get("nw-err").textContent.includes("已复制")); assert.equal(success.nodes.get("nw-err").classList.contains("error"), false);
});
test("channel loads honor section liveness and newest request on the same moved DOM node", async () => {
  const old = deferred(), next = deferred(); let sequence = 0;
  const env = environment(({ url }) => url === "/api/notify/channels" ? (++sequence === 1 ? old.promise : next.promise) : undefined);
  const first = env.run("loadNotifyChannels({active:()=>true})"), second = env.run("loadNotifyChannels({active:()=>true})");
  next.resolve({ ok: true, channels: [] }); await second;
  old.resolve({ ok: false, error: "stale error" }); await first;
  assert.ok(!env.nodes.get("notify-list").textContent.includes("stale error")); assert.equal(env.nodes.get("notify-editor-panel").open, true);
  const late = deferred(); const inactive = environment(({ url }) => url === "/api/notify/channels" ? late.promise : undefined);
  inactive.run("var stillActive=true"); const loading = inactive.run("loadNotifyChannels({active:()=>stillActive})"); inactive.run("stillActive=false");
  inactive.nodes.get("notify-list").textContent = "New generation"; late.resolve({ ok: false, error: "old failure" }); await loading;
  assert.equal(inactive.nodes.get("notify-list").textContent, "New generation");
});

(async () => {
  let failures = 0;
  for (const { name, run } of tests) { try { await run(); console.log("PASS " + name); } catch (error) { failures++; console.error("FAIL " + name); console.error(error); } }
  console.log(`${tests.length - failures}/${tests.length} connection UI checks passed`); process.exitCode = failures ? 1 : 0;
})();
