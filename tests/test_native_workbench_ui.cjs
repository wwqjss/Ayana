/* Run the real workbench callbacks against controlled API/PTY ordering. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../ayana/static/workbench.js"), "utf8");
const clipboardSource = fs.readFileSync(path.join(__dirname, "../ayana/static/terminal_clipboard.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../ayana/static/index.html"), "utf8");
const app = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 20; n++) await Promise.resolve(); };
class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.listeners = {}; this._text = "";
    this.className = ""; this.value = ""; this.checked = false; this.disabled = false; this.dataset={};this.style={};
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/), ...names])].join(" "); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(n => !names.includes(n)).join(" "); },
      toggle: (name, force) => { const on = force === undefined ? !this.classList.contains(name) : force; on ? this.classList.add(name) : this.classList.remove(name); return on; },
    };
  }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  set innerHTML(_) { this._text = ""; this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
  setAttribute(key, value) { this[key === "class" ? "className" : key] = value; }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  focus() { this.focused = true; }
  select() { this.selected = true; }
  setSelectionRange(start, end) { this.selectionRange = [start, end]; }
  async click() { if (this.disabled) return; if (this.onclick) await this.onclick(); for (const h of this.listeners.click || []) await h(); }
  querySelectorAll(selector) { return this.children.flatMap(c => [...(c.tagName.toLowerCase() === selector ? [c] : []), ...c.querySelectorAll(selector)]); }
}
const sessions = [
  { id: "sess_a", title: "automatic-a", origin: "auto", status: "open", created_at: 1 },
  { id: "sess_b", title: "manual-b", origin: "manual", status: "open", created_at: 2 },
];
function environment(reply) {
  const nodes = new Map(), calls = [], sockets = [], terminals = [], observers = [], timers = new Map(), timeouts = new Map(), events = new Map(), modals = [], alerts = [], prompts = [], clipboardWrites = [], legacyCopies = [];
  let copyAllowed = true;
  for (const match of html.matchAll(/\bid="(aw-[^"]+|agent-workbench)"/g)) nodes.set(match[1], new Element());
  class Terminal {
    constructor(options) {
      this.options = options; this.cols = 100; this.rows = 36; this.output = [];
      this.screenText = ""; this.pendingWrites = [];
      this.selectionText = ""; this.oscHandlers = new Map();
      this.parser = { registerOscHandler: (code, handler) => { this.oscHandlers.set(code, handler); return { dispose: () => this.oscHandlers.delete(code) }; } };
      const terminal = this;
      this.buffer = { active: { viewportY: 0, get length() { return terminal.rows; },
        getLine(index) { return { translateToString: () => terminal.screenText.split("\n")[index] || "" }; } } };
      terminals.push(this);
    }
    open(host) { this.host = host; }
    loadAddon(addon) { this.addon = addon; if (addon.activate) addon.activate(this); }
    onData(callback) { this.data = callback; }
    onResize(callback) { this.resizeHandler = callback; }
    onSelectionChange(callback) { this.selectionHandler = callback; }
    getSelection() { return this.selectionText; }
    hasSelection() { return !!this.selectionText; }
    write(data, done) {
      this.output.push(data);
      const commit = () => {
        const text = Buffer.from(data).toString("utf8");
        if (text.includes("\x1b[2J")) this.screenText = "";
        this.screenText += text.replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, "").replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
        if (done) done();
      };
      if (this.deferWrites) this.pendingWrites.push(commit); else commit();
    }
    completeWrites() { for (const done of this.pendingWrites.splice(0)) done(); }
    resize(cols, rows) {
      if (this.cols === cols && this.rows === rows) return;
      this.cols = cols; this.rows = rows;
      if (this.resizeHandler) this.resizeHandler({ cols, rows });
    }
    dispose() { this.disposed = true; }
    focus() { this.focused = true; }
  }
  class Socket {
    constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
    send(data) { this.sent.push(data); }
    close() { this.readyState = 3; if (this.onclose) this.onclose({ code: 1000 }); }
  }
  class Observer {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe(host) { this.host = host; }
    disconnect() { this.disconnected = true; }
  }
  let nextTimer = 0;
  const defaultReply = call => {
    if (call.url.includes("/sessions?")) return { ok: true, sessions };
    if (call.url.endsWith("/terminal/control")) return { ok: true };
    if (call.url.endsWith("/terminal")) return { ok: true, attached: true, binding: {} };
    const sid = call.url.split("/").pop();
    return { ok: true, session: { ...sessions.find(s => s.id === sid), remote_session_id: "ses_" + sid }, effective_permissions:{session_id:sid,access_mode:"readwrite",approval_mode:"manual",revision:1}, incidents: [], can_control: true, can_prepare: true };
  };
  const window = {
    isSecureContext: false, atob: text => Buffer.from(text, "base64").toString("binary"),
    navigator: { clipboard: { writeText: async text => { clipboardWrites.push(text); }, readText: () => { throw new Error("must_not_read_clipboard"); } } },
    Terminal, FitAddon: { FitAddon: class {
      activate(terminal) { this.terminal = terminal; }
      fit() { if (this.dimensions) this.terminal.resize(this.dimensions.cols, this.dimensions.rows); }
    } },
    api: async (url, options = {}) => { const call = { url, method: options.method || "GET", body: options.body ? JSON.parse(options.body) : null }; calls.push(call); return reply ? await reply(call, defaultReply) : defaultReply(call); },
    showModal: (title, children) => modals.push({ title, children }), closeModal: () => {},
    addEventListener: (name, callback) => { (events.get(name) || events.set(name, []).get(name)).push(callback); },
    matchMedia: () => ({ matches: false }),
  };
  const context = vm.createContext({
    console, window, WebSocket: Socket, ResizeObserver: Observer, ArrayBuffer, Uint8Array, URL, Date, TextEncoder, TextDecoder,
    document: { getElementById: id => nodes.get(id), createElement: tag => new Element(tag), createTextNode: text => { const e = new Element("text"); e.textContent = text; return e; }, execCommand: command => { assert.equal(command,"copy"); legacyCopies.push(nodes.get("aw-copy-text").value); return copyAllowed; } },
    location: { protocol: "https:", host: "ayana.test" }, requestAnimationFrame: callback => callback(),
    setInterval: callback => { const id = ++nextTimer; timers.set(id, callback); return id; }, clearInterval: id => timers.delete(id),
    setTimeout: callback => { const id = ++nextTimer; timeouts.set(id, callback); return id; }, clearTimeout: id => timeouts.delete(id),
    alert: message => alerts.push(message), confirm: () => true, prompt: () => prompts.shift() ?? "",
  });
  vm.runInContext(clipboardSource, context);
  vm.runInContext(source, context);
  const select = id => nodes.get("aw-session-list").children.find(c => c.tagName === "BUTTON" && c.textContent.includes(id === "sess_a" ? "automatic-a" : "manual-b")).click();
  const ready = (socket = sockets.at(-1)) => { socket.readyState = 1; socket.onmessage({ data: JSON.stringify({ type: "ready", connection_id: "connection-" + sockets.indexOf(socket), control: false }) }); };
  const output = (text, socket = sockets.at(-1)) => socket.onmessage({ data: new Uint8Array(Buffer.from(text)).buffer });
  const paint = (socket = sockets.at(-1)) => output("\x1b[HMiMo", socket);
  return { nodes, calls, sockets, terminals, observers, timers, timeouts, events, modals, alerts, prompts, select, ready, output, paint, window, clipboardWrites, legacyCopies, setCopyAllowed: value => { copyAllowed=value; }, run: code => vm.runInContext(code, context), defaultReply };
}
const tests = [];
const test = (name, run) => tests.push([name, run]);
function nested(root, predicate) {
  if (predicate(root)) return root;
  for (const child of root.children || []) { const found = nested(child, predicate); if (found) return found; }
  return null;
}
const modalNode = (env, id) => nested(env.modals.at(-1).children[0], node => node.id === id);
const modalButton = (env, text) => nested(env.modals.at(-1).children[0], node => node.tagName === "BUTTON" && node.textContent === text);
const pollCallback = env => [...env.timers.values()].find(callback => callback.constructor.name === "AsyncFunction");

test("the center has one native viewport and no parallel chat, composer or thinking strip", () => {
  const center = html.slice(html.indexOf('<section class="aw-center"'), html.indexOf('<aside class="aw-right"'));
  assert.equal((center.match(/id="aw-term-host"/g) || []).length, 1);
  for (const removed of ["aw-chat-scroll", "aw-composer", "aw-input", "aw-send", "aw-live-strip", "返回对话", "原生终端"]) assert.equal(center.includes(removed), false, removed);
  for (const removed of ["function renderMessages(", "function sendPrompt(", "function renderLiveStrip(", '"/api/agent/events']) assert.equal(source.includes(removed), false, removed);
});
test("selecting the automatic session attaches native TUI without submitting a task", async () => {
  const env = environment(); await env.window.renderAgentWorkbench();
  assert.equal(env.sockets.length, 1);
  assert.equal(new URL(env.sockets[0].url).searchParams.get("session_id"), "sess_a");
  assert.equal(env.calls.filter(c => c.url.endsWith("/terminal") && c.method === "POST").length, 1);
  assert.equal(env.calls.some(c => c.url.endsWith("/prompt") || c.url.includes("/events")), false);
});
test("transport-ready waits for real native bytes before claiming a rendered connection", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready();
  assert.equal(env.nodes.get("aw-term-status").textContent, "等待原生画面");
  assert.equal(env.nodes.get("aw-term-status").classList.contains("ready"), false);
  env.paint();
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察·读写");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"), true);
  assert.equal(env.terminals[0].output.length, 1);
});
test("clear-screen and capability queries never count as a visible native screen", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready();
  env.output("\x1b[2J\x1b[H\x1b[?2026$p\x1b[14t");
  assert.equal(env.nodes.get("aw-term-status").textContent, "等待原生画面");
  assert.equal(env.nodes.get("aw-term-status").classList.contains("ready"), false);
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"), false);
  for (const callback of [...env.timeouts.values()]) callback();
  assert.ok(env.nodes.get("aw-term-notice").textContent.includes("尚未收到原生画面"));
});
test("native screen becomes ready only after the terminal parser commits visible text", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready();
  const terminal = env.terminals[0]; terminal.deferWrites = true;
  env.paint();
  assert.equal(env.nodes.get("aw-term-status").textContent, "等待原生画面");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"), false);
  terminal.completeWrites();
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察·读写");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"), true);
  assert.equal(env.timeouts.size, 0);
});
test("a pending parser callback from the old terminal cannot mark a new selection ready", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready();
  const old = env.terminals[0]; old.deferWrites = true; env.paint();
  await env.select("sess_b"); env.ready();
  old.completeWrites();
  assert.equal(env.nodes.get("aw-term-status").textContent, "等待原生画面");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"), false);
  env.paint();
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察·读写");
});
test("fit, onResize and host observation send each distinct geometry once", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready();
  const socket = env.sockets[0], terminal = env.terminals[0]; socket.sent.length = 0;
  env.events.get("resize")[0](); env.observers[0].callback();
  assert.equal(socket.sent.length, 0);
  terminal.addon.dimensions = { cols: 156, rows: 58 };
  env.events.get("resize")[0](); env.observers[0].callback();
  assert.deepEqual(socket.sent.map(JSON.parse), [{ type: "resize", cols: 156, rows: 58 }]);
  terminal.addon.dimensions = { cols: 120, rows: 36 };
  env.observers[0].callback();
  assert.deepEqual(socket.sent.map(JSON.parse), [
    { type: "resize", cols: 156, rows: 58 }, { type: "resize", cols: 120, rows: 36 },
  ]);
});
test("native geometry requests enable only terminal report options", async () => {
  const env = environment(); await env.window.renderAgentWorkbench();
  const options = env.terminals[0].options.windowOptions;
  assert.deepEqual(Object.keys(options).sort(), ["getCellSizePixels", "getWinSizeChars", "getWinSizePixels"]);
  assert.ok(Object.values(options).every(value => value === true));
});
test("typing in observation never acquires control or replays keystrokes later", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  const socket = env.sockets[0], terminal = env.terminals[0]; socket.sent.length = 0;
  terminal.data("do-not-replay\r");
  assert.equal(socket.sent.length, 0);
  assert.equal(env.calls.some(c => c.url.endsWith("/terminal/control")), false);
  terminal.data("\x1b[1;1R");
  assert.deepEqual(socket.sent.map(JSON.parse), [{ type: "terminal_response", data: "\x1b[1;1R" }]);
  socket.sent.length = 0;
  await env.nodes.get("aw-term-acquire").click();
  assert.equal(terminal.options.disableStdin, false);
  terminal.data("native-input\r");
  const input = socket.sent.map(JSON.parse).filter(v => v.type === "input");
  assert.deepEqual(input, [{ type: "input", data: "native-input\r" }]);
});
test("failed preparation remains an honest error and creates no empty terminal", async () => {
  const env = environment((call, normal) => call.url.endsWith("/terminal") ? { ok: false, message: "runtime unavailable" } : normal(call));
  await env.window.renderAgentWorkbench();
  assert.equal(env.sockets.length, 0); assert.equal(env.terminals.length, 0);
  assert.ok(env.nodes.get("aw-term-notice").textContent.includes("runtime unavailable"));
  assert.equal(env.nodes.get("aw-term-status").classList.contains("ready"), false);
});
test("late preparation for an old selection cannot create a stale socket", async () => {
  const pending = deferred();
  const env = environment((call, normal) => call.url === "/api/agent/sessions/sess_a/terminal" ? pending.promise : normal(call));
  const first = env.window.renderAgentWorkbench(); await flush();
  await env.select("sess_b"); pending.resolve({ ok: true }); await first;
  assert.deepEqual(env.sockets.map(s => new URL(s.url).searchParams.get("session_id")), ["sess_b"]);
  assert.equal(env.nodes.get("aw-chat-title").textContent, "manual-b");
});
test("old socket output and keyboard callbacks cannot cross into another session", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  const old = env.sockets[0], terminal = env.terminals[0];
  const handlers = { message: old.onmessage, close: old.onclose, error: old.onerror };
  await env.select("sess_b"); env.ready(); env.paint();
  old.readyState = 1; terminal.data("old\r");
  handlers.message({ data: new Uint8Array([65]).buffer }); handlers.close({ code: 4403 }); handlers.error();
  assert.equal(terminal.disposed, true);
  assert.equal(env.terminals[1].output.length, 1);
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察·读写");
  assert.equal(old.sent.map(JSON.parse).filter(v => v.type === "input").length, 0);
});
test("late session details never overwrite a more recent selection", async () => {
  const pending = deferred();
  const env = environment((call, normal) => call.url === "/api/agent/sessions/sess_a" ? pending.promise : normal(call));
  const first = env.window.renderAgentWorkbench(); await flush();
  await env.select("sess_b");
  pending.resolve({ ok: true, session: sessions[0], incidents: [] }); await first;
  assert.equal(env.window.agentWorkbenchState.currentId, "sess_b");
  assert.equal(env.nodes.get("aw-chat-title").textContent, "manual-b");
  assert.equal(env.sockets.length, 1);
});
test("suspending a pending attach prevents a late socket and task submission", async () => {
  const pending = deferred();
  const env = environment((call, normal) => call.url.endsWith("/terminal") ? pending.promise : normal(call));
  const opening = env.window.renderAgentWorkbench(); await flush(); env.window.suspendAgentWorkbench();
  pending.resolve({ ok: true }); await opening;
  assert.equal(env.sockets.length, 0); assert.equal(env.timers.size, 0);
  assert.equal(env.calls.some(c => c.url.endsWith("/abort") || c.url.endsWith("/prompt")), false);
});
test("leaving the view disposes only browser attachments and does not abort or archive", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  env.window.suspendAgentWorkbench();
  assert.equal(env.sockets[0].readyState, 3); assert.equal(env.terminals[0].disposed, true);
  assert.equal(env.timers.size, 0); assert.equal(env.timeouts.size, 0);
  assert.equal(env.calls.some(c => c.url.endsWith("/abort") || c.url.endsWith("/archive")), false);
  await env.window.renderAgentWorkbench();
  assert.equal(env.sockets.length, 2);
  assert.equal(new URL(env.sockets[1].url).searchParams.get("session_id"), "sess_a");
});
test("reconnect attaches the same session without any prompt replay", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  env.sockets[0].onclose({ code: 1013 });
  await env.nodes.get("aw-term-reconnect").click();
  assert.equal(env.sockets.length, 2);
  assert.deepEqual(env.sockets.map(s => new URL(s.url).searchParams.get("session_id")), ["sess_a", "sess_a"]);
  assert.equal(env.calls.some(c => c.url.endsWith("/prompt")), false);
});
test("late control grant after switching cannot enable keyboard in the new session", async () => {
  const pending = deferred();
  const env = environment((call, normal) => call.url.endsWith("/terminal/control") ? pending.promise : normal(call));
  await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  const grant = env.nodes.get("aw-term-acquire").click();
  await env.select("sess_b"); env.ready(); env.paint();
  pending.resolve({ ok: true }); await grant;
  env.terminals[1].data("blocked-after-stale-grant\r");
  assert.equal(env.sockets[1].sent.map(JSON.parse).filter(item => item.type === "input").length, 0);
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察·读写");
});
test("archived history attaches read-only without silently reopening a session", async () => {
  const env = environment((call, normal) => {
    const result = normal(call);
    if (call.url === "/api/agent/sessions/sess_a") { result.session.status = "archived"; result.can_control = false; result.can_prepare = true; }
    return result;
  });
  await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  assert.equal(env.sockets.length, 1);
  assert.equal(env.nodes.get("aw-term-acquire").classList.contains("hidden"), true);
  assert.equal(env.nodes.get("aw-reopen").classList.contains("hidden"), false);
  assert.equal(env.calls.some(c => c.url.endsWith("/reopen")), false);
});
test("viewers inspect an existing binding without a mutation or control button", async () => {
  const env = environment((call, normal) => {
    const result = normal(call);
    if (call.url === "/api/agent/sessions/sess_a") { result.can_prepare = false; result.can_control = false; }
    return result;
  });
  await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  assert.equal(env.calls.find(c => c.url.endsWith("/terminal")).method, "GET");
  assert.equal(env.nodes.get("aw-term-acquire").classList.contains("hidden"), true);
});
test("repeated renders bind one set of listeners and retain one native connection", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  await env.window.renderAgentWorkbench(); await env.window.renderAgentWorkbench();
  assert.equal(env.sockets.length, 1); assert.equal(env.events.get("resize").length, 1);
  assert.equal(env.events.get("pagehide").length, 1);
  assert.equal([...env.timers.values()].length, 2);
});
test("native readiness with no bytes times out visibly without false success", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready();
  for (const callback of env.timeouts.values()) callback();
  assert.ok(env.nodes.get("aw-term-notice").textContent.includes("尚未收到原生画面"));
  assert.equal(env.nodes.get("aw-term-status").classList.contains("ready"), false);
});
test("new manual sessions collect only a title and start tasks inside the native input", async () => {
  const env = environment((call, normal) => call.url === "/api/agent/sessions" && call.method === "POST" ? { ok: true, session_id: "sess_b" } : normal(call));
  await env.window.renderAgentWorkbench();
  await env.nodes.get("aw-new-session").click();
  const modal = env.modals.at(-1), wrapper = modal.children[0];
  wrapper.querySelectorAll("input")[0].value = "manual native";
  await wrapper.querySelectorAll("button")[0].click();
  const created = env.calls.find(c => c.url === "/api/agent/sessions" && c.method === "POST");
  assert.deepEqual(created.body, { title: "manual native" });
  assert.equal(env.calls.some(c => c.url.endsWith("/prompt")), false);
  assert.equal(new URL(env.sockets.at(-1).url).searchParams.get("session_id"), "sess_b");
});
test("approval retains the exact action and OTP while duplicate clicks submit once", async () => {
  const pending = deferred();
  const env = environment((call, normal) => {
    if (call.url === "/api/actions/action-a/decision") return pending.promise;
    const result = normal(call);
    if (call.url === "/api/agent/sessions/sess_a") result.pending_actions = [{ id: "action-a", capability: "service.restart", object_id: "mysql" }];
    return result;
  });
  await env.window.renderAgentWorkbench();
  const approve = env.nodes.get("aw-pending").querySelectorAll("button").find(b => b.textContent === "批准并执行");
  env.prompts.push("123456");
  const first = approve.click(); await approve.click();
  const requests = env.calls.filter(c => c.url === "/api/actions/action-a/decision");
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].body, { decision: "execute_once", totp: "123456" });
  pending.resolve({ ok: true }); await first;
});
test("read-only viewers can inspect pending approvals without action buttons becoming active", async () => {
  const env = environment((call, normal) => {
    const result = normal(call);
    if (call.url === "/api/agent/sessions/sess_a") {
      result.can_prepare = result.can_control = false;
      result.pending_actions = [{ id: "action-a", capability: "service.restart" }];
    }
    return result;
  });
  await env.window.renderAgentWorkbench();
  const buttons = env.nodes.get("aw-pending").querySelectorAll("button");
  assert.equal(buttons.length, 2);
  assert.ok(buttons.every(b => b.disabled));
  await buttons[0].click();
  assert.equal(env.calls.some(c => c.url.includes("/api/actions/")), false);
});
test("control revocation immediately disables the original native keyboard", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  await env.nodes.get("aw-term-acquire").click();
  const socket = env.sockets[0]; socket.sent.length = 0;
  socket.onmessage({ data: JSON.stringify({ type: "control", control: false }) });
  env.terminals[0].data("blocked\r");
  assert.equal(socket.sent.length, 0);
});
test("observer device reports stay separate from encoded keys and clipboard commands", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  const socket = env.sockets[0], terminal = env.terminals[0]; socket.sent.length = 0;
  terminal.data("\x1b[?1;2c");
  terminal.data("\x1b[97u");
  terminal.data("\x1b]52;c;c2VjcmV0\x07");
  terminal.data("\x1b[1;1Rinspect\r");
  assert.deepEqual(socket.sent.map(JSON.parse), [{ type: "terminal_response", data: "\x1b[?1;2c" }]);
  assert.equal(env.calls.some(call => call.url.endsWith("/terminal/control")), false);
});
test("observers return only the native queried DECRPM modes and valid status values", async () => {
  const env = environment(); await env.window.renderAgentWorkbench(); env.ready(); env.paint();
  const socket = env.sockets[0], terminal = env.terminals[0]; socket.sent.length = 0;
  const reports = [];
  for (const mode of [1004, 1016, 2004, 2026, 2027, 2031]) {
    for (let status = 0; status <= 4; status++) {
      const data = `\x1b[?${mode};${status}$y`; reports.push({ type: "terminal_response", data }); terminal.data(data);
    }
  }
  for (const data of ["\x1b[?2025;1$y", "\x1b[?2026;5$y", "\x1b[2026;1$y", "\x1b[?2026;1$yinspect\r", "\x1b[97u"]) terminal.data(data);
  assert.deepEqual(socket.sent.map(JSON.parse), reports);
  assert.equal(env.calls.some(call => call.url.endsWith("/terminal/control")), false);
});
test("observer shows actual access with both permission controls disabled", async () => {
  const env=environment();await env.window.renderAgentWorkbench();env.ready();env.paint();
  assert.equal(env.nodes.get("aw-term-status").textContent,"观察·读写");
  assert.equal(env.nodes.get("aw-access-mode").disabled,true);
  assert.equal(env.nodes.get("aw-approval-mode").disabled,true);
  const before=env.calls.length;await env.nodes.get("aw-access-mode").click();assert.equal(env.calls.length,before);
});
test("takeover inherits and permission toggle waits for confirmed response", async () => {
  const pending=deferred();let env;
  env=environment(call=>call.url.endsWith("/permissions") ? pending.promise : env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();await env.nodes.get("aw-term-acquire").click();
  assert.equal(env.nodes.get("aw-term-status").textContent,"控制中·读写");
  const operation=env.nodes.get("aw-access-mode").click();await flush();
  assert.equal(env.nodes.get("aw-access-mode").textContent,"读写");
  assert.equal(env.nodes.get("aw-access-mode").disabled,true);
  const call=env.calls.find(c=>c.url.endsWith("/permissions"));
  assert.equal(call.body.access_mode,"readonly");
  pending.resolve({ok:true,effective_permissions:{session_id:"sess_a",access_mode:"readonly",approval_mode:"manual",revision:2}});await operation;
  assert.equal(env.nodes.get("aw-term-status").textContent,"控制中·只读");
});
test("permission failure keeps backend mode and exposes reason", async () => {
  let env;env=environment(call=>call.url.endsWith("/permissions") ? {ok:false,message:"控制权已过期",effective_permissions:{session_id:"sess_a",access_mode:"readwrite",approval_mode:"manual",revision:2}} : env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();await env.nodes.get("aw-term-acquire").click();await env.nodes.get("aw-access-mode").click();
  assert.equal(env.nodes.get("aw-access-mode").textContent,"读写");
  assert.equal(env.nodes.get("aw-task-feedback").textContent,"控制权已过期");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"),true);
});
test("late permission response cannot change another session", async () => {
  const pending=deferred();let env;env=environment(call=>call.url.endsWith("/permissions") ? pending.promise : env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();await env.nodes.get("aw-term-acquire").click();
  const operation=env.nodes.get("aw-access-mode").click();await flush();await env.select("sess_b");env.ready();env.paint();
  pending.resolve({ok:true,effective_permissions:{session_id:"sess_a",access_mode:"readonly",approval_mode:"automatic",revision:99}});await operation;
  assert.equal(env.nodes.get("aw-term-status").textContent,"观察·读写");assert.equal(env.nodes.get("aw-access-mode").disabled,true);
});
test("release and heartbeat adopt restored backend permissions", async () => {
  let env;env=environment(call=>call.url.endsWith("/terminal/control") && call.body.action==="release" ? {ok:true,effective_permissions:{session_id:"sess_a",access_mode:"readonly",approval_mode:"manual",revision:3}} : env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();await env.nodes.get("aw-term-acquire").click();await env.nodes.get("aw-term-release").click();
  assert.equal(env.nodes.get("aw-term-status").textContent,"观察·只读");assert.equal(env.nodes.get("aw-access-mode").disabled,true);
  env.sockets[0].onmessage({data:JSON.stringify({type:"control",control:false,effective_permissions:{session_id:"sess_a",access_mode:"readwrite",approval_mode:"automatic",revision:4}})});
  assert.equal(env.nodes.get("aw-term-status").textContent,"观察·读写");assert.equal(env.nodes.get("aw-approval-mode").value,"automatic");
});
test("backend task state is separate from open session and heartbeat does not erase a queue acknowledgment", async () => {
  const env=environment();await env.window.renderAgentWorkbench();env.ready();env.paint();
  assert.ok(env.nodes.get("aw-chat-meta").textContent.includes("会话开放"));
  assert.equal(env.nodes.get("aw-task-state").textContent,"空闲");
  const socket=env.sockets[0];
  socket.onmessage({data:JSON.stringify({type:"action_ack",state:"queued",queued:true,message:"已排队，当前任务继续执行。"})});
  socket.onmessage({data:JSON.stringify({type:"control",control:false})});
  assert.ok(env.nodes.get("aw-task-state").textContent.includes("排队"));
  assert.equal(env.nodes.get("aw-task-feedback").textContent,"已排队，当前任务继续执行。");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"),true);
});
test("a detail response started before an acknowledgment cannot replace its newer task state", async () => {
  const pending=deferred();let hold=false,env;
  env=environment(call=>hold && call.url==="/api/agent/sessions/sess_a" ? pending.promise : env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();hold=true;
  const operation=pollCallback(env)();await flush();
  env.sockets[0].onmessage({data:JSON.stringify({type:"action_ack",state:"queued",message:"新输入已确认排队"})});
  pending.resolve({...env.defaultReply({url:"/api/agent/sessions/sess_a"}),task_state:"idle",task_state_label:"空闲"});await operation;
  assert.equal(env.window.agentWorkbenchState.detail.task_state,"queued");
  assert.ok(env.nodes.get("aw-task-state").textContent.includes("排队"));
});
test("a rejected new input displays its reason without marking the active task failed", async () => {
  const env=environment();await env.window.renderAgentWorkbench();env.ready();env.paint();
  const socket=env.sockets[0];
  socket.onmessage({data:JSON.stringify({type:"action_ack",state:"running",message:"执行中"})});
  socket.onmessage({data:JSON.stringify({type:"action_ack",state:"error",ok:false,message:"控制权已过期，输入未接收"})});
  assert.equal(env.window.agentWorkbenchState.detail.task_state,"running");
  assert.equal(env.nodes.get("aw-task-feedback").textContent,"控制权已过期，输入未接收");
  assert.equal(env.nodes.get("aw-term-notice").classList.contains("hidden"),true);
});
test("pause and resume duty use distinct APIs without silently aborting the native task", async () => {
  let paused=false,env;
  env=environment(call=>{
    if(call.url.endsWith("/pause")){paused=true;return {ok:true,message:"暂停接单已确认"};}
    if(call.url.endsWith("/resume-duty")){paused=false;return {ok:true};}
    const reply=env.defaultReply(call);
    return call.url==="/api/agent/sessions/sess_a" ? {...reply,session:{...reply.session,paused_at:paused?1:0},task_state:paused?"paused":"running"} : reply;
  });
  await env.window.renderAgentWorkbench();await env.nodes.get("aw-pause-duty").click();
  assert.equal(env.calls.filter(call=>call.url.endsWith("/pause")).length,1);
  assert.equal(env.nodes.get("aw-pause-duty").classList.contains("hidden"),true);
  assert.equal(env.nodes.get("aw-resume-duty").classList.contains("hidden"),false);
  await env.nodes.get("aw-resume-duty").click();
  assert.equal(env.calls.filter(call=>call.url.endsWith("/resume-duty")).length,1);
  assert.equal(env.calls.some(call=>call.url.endsWith("/abort")),false);
});
test("recover requires current control and resumes via recovery API without submitting another prompt", async () => {
  let resumed=false,env;
  env=environment(call=>{
    if(call.url.endsWith("/recover")){resumed=true;return {ok:true,accepted:true};}
    const reply=env.defaultReply(call);
    return call.url==="/api/agent/sessions/sess_a" ? {...reply,can_recover:!resumed,task_state:resumed?"running":"interrupted"} : reply;
  });
  await env.window.renderAgentWorkbench();env.ready();env.paint();
  assert.equal(env.nodes.get("aw-recover-task").disabled,true);
  await env.nodes.get("aw-term-acquire").click();await env.nodes.get("aw-recover-task").click();
  const recovery=env.calls.find(call=>call.url.endsWith("/recover"));
  assert.deepEqual(recovery.body,{connection_id:"connection-0"});
  assert.equal(env.calls.some(call=>call.url.endsWith("/prompt")),false);
  assert.equal(env.window.agentWorkbenchState.detail.task_state,"running");
});
test("stop and delete remains visible until backend confirms completion and then handles its 404", async () => {
  let requested=false,gone=false,env;
  env=environment(call=>{
    if(call.method==="DELETE"){requested=true;return {ok:true,pending:true,message:"正在停止并删除"};}
    if(call.url.includes("/sessions?"))return {ok:true,sessions:gone?sessions.filter(s=>s.id!=="sess_a"):sessions};
    if(call.url==="/api/agent/sessions/sess_a"){
      if(gone)return {ok:false,error:"session_unavailable"};
      const reply=env.defaultReply(call);return {...reply,session:{...reply.session,delete_requested_at:requested?1:0},can_delete:false,can_request_delete:true,task_state:requested?"stopping":"running"};
    }
    return env.defaultReply(call);
  });
  await env.window.renderAgentWorkbench();env.ready();env.paint();
  await env.nodes.get("aw-delete-stop").click();
  assert.equal(env.calls.filter(call=>call.method==="DELETE").length,1);
  assert.deepEqual(env.calls.find(call=>call.method==="DELETE").body,{stop:true});
  assert.equal(env.window.agentWorkbenchState.currentId,"sess_a");assert.equal(env.window.agentWorkbenchState.sessions.length,2);
  gone=true;await pollCallback(env)();
  assert.equal(env.window.agentWorkbenchState.currentId,"sess_b");
  assert.equal(env.window.agentWorkbenchState.sessions.some(s=>s.id==="sess_a"),false);
  assert.equal(env.calls.some(call=>call.url.endsWith("/abort")),false);
});
test("safe delete sends stop false and removes only the confirmed session", async () => {
  let gone=false,env;
  env=environment(call=>{
    if(call.method==="DELETE"){gone=true;return {ok:true,pending:false};}
    if(call.url.includes("/sessions?"))return {ok:true,sessions:gone?sessions.filter(s=>s.id!=="sess_a"):sessions};
    return env.defaultReply(call);
  });
  await env.window.renderAgentWorkbench();await env.nodes.get("aw-delete-session").click();
  assert.deepEqual(env.calls.find(call=>call.method==="DELETE").body,{stop:false});
  assert.equal(env.window.agentWorkbenchState.currentId,"sess_b");assert.equal(env.calls.some(call=>call.url.endsWith("/abort")),false);
});
test("lifecycle rejection keeps the selected session and makes the backend reason visible", async () => {
  let env;env=environment(call=>call.url.endsWith("/pause")?{ok:false,error:"unknown_requires_review",message:"结果待核对，未暂停任务"}:env.defaultReply(call));
  await env.window.renderAgentWorkbench();await env.nodes.get("aw-pause-duty").click();
  assert.equal(env.window.agentWorkbenchState.currentId,"sess_a");
  assert.equal(env.nodes.get("aw-task-feedback").textContent,"结果待核对，未暂停任务");
  assert.equal(env.nodes.get("aw-pause-duty").disabled,false);
});
test("Agent settings separates permission and approval and shows actual role fallback accounts", async () => {
  let env;env=environment(call=>{
    if(call.url==="/api/agent/settings"){
      if(call.method==="POST")return {ok:true,settings:call.body};
      return {ok:true,settings:{auto_access_mode:"readonly",auto_approval_mode:"automatic",ssh_investigate_role:"read",ssh_execute_role:"write",archive_delay_sec:300},ssh_roles:[{name:"read",kind:"read"},{name:"write",kind:"write"},{name:"root-ops",kind:"write"}],ssh_endpoints:[{asset_id:"host",role:"write",username:"root",host:"host.example",enabled:true},{asset_id:"host",role:"root-ops",username:"operator",host:"host.example",enabled:true}]};
    }
    return env.defaultReply(call);
  });
  await env.window.renderAgentWorkbench();await env.nodes.get("aw-settings-btn").click();
  const wrap=env.modals.at(-1).children[0],access=modalNode(env,"agent-auto-access"),approval=modalNode(env,"agent-auto-approval");
  assert.equal(access.value,"readonly");assert.equal(approval.value,"automatic");
  assert.ok(wrap.textContent.includes("root@host.example · 回退至 write"));
  for(const id of ["agent-ssh-investigate","agent-ssh-execute"])assert.ok(modalNode(env,id).children.some(option=>option.value==="root-ops"));
  await access.children[1].click();await approval.children[0].click();
  modalNode(env,"agent-ssh-investigate").value="root-ops";modalNode(env,"agent-ssh-investigate").onchange();
  modalNode(env,"agent-ssh-execute").value="read";
  const preset=modalNode(env,"agent-archive-preset");preset.value="custom";preset.onchange();modalNode(env,"agent-archive-custom").value="217";
  await modalButton(env,"保存设置").click();
  const saved=env.calls.find(call=>call.url==="/api/agent/settings"&&call.method==="POST");
  assert.deepEqual(saved.body,{auto_access_mode:"readwrite",auto_approval_mode:"manual",archive_delay_sec:217,ssh_investigate_role:"root-ops",ssh_execute_role:"read"});
  assert.ok(wrap.textContent.includes("已保存并生效"));
});
test("settings cancellation does not save and invalid custom delay stays inline", async () => {
  let env;env=environment(call=>call.url==="/api/agent/settings"?{ok:true,settings:{archive_delay_sec:300},ssh_roles:[{name:"read"},{name:"write"}]}:env.defaultReply(call));
  await env.window.renderAgentWorkbench();await env.nodes.get("aw-settings-btn").click();
  const preset=modalNode(env,"agent-archive-preset");preset.value="custom";preset.onchange();modalNode(env,"agent-archive-custom").value="0";
  await modalButton(env,"保存设置").click();assert.ok(env.modals.at(-1).children[0].textContent.includes("30–3600"));
  await modalButton(env,"取消").click();
  assert.equal(env.calls.some(call=>call.url==="/api/agent/settings"&&call.method==="POST"),false);
});
test("settings prevents edits and duplicate saves while awaiting the backend and retains failed values", async () => {
  const pending=deferred();let env;env=environment(call=>call.url==="/api/agent/settings"?(call.method==="POST"?pending.promise:{ok:true,settings:{archive_delay_sec:300},ssh_roles:[{name:"read"},{name:"write"}]}):env.defaultReply(call));
  await env.window.renderAgentWorkbench();await env.nodes.get("aw-settings-btn").click();
  const save=modalButton(env,"保存设置"),operation=save.click();await flush();
  assert.equal(modalNode(env,"agent-ssh-investigate").disabled,true);assert.equal(modalNode(env,"agent-auto-access").children[0].disabled,true);
  await save.click();assert.equal(env.calls.filter(call=>call.url==="/api/agent/settings"&&call.method==="POST").length,1);
  pending.resolve({ok:false,error:"configured_ssh_endpoint_missing",message:"该角色端点尚未配置"});await operation;
  assert.ok(env.modals.at(-1).children[0].textContent.includes("该角色端点尚未配置"));assert.equal(save.disabled,false);
});
test("observer copy result fetch offers text but waits for a fresh local copy click on HTTP", async () => {
  let env;env=environment(call=>call.url.endsWith("/copy-text")?{ok:true,text:"真实回答正文",source:"latest_assistant"}:env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();await env.nodes.get("aw-copy-result").click();
  assert.equal(env.nodes.get("aw-copy-text").value,"真实回答正文");assert.equal(env.legacyCopies.length,0);assert.equal(env.clipboardWrites.length,0);
  await env.nodes.get("aw-copy-local").click();assert.deepEqual(env.legacyCopies,["真实回答正文"]);
  assert.ok(env.nodes.get("aw-task-feedback").textContent.includes("已复制到本机"));
  assert.equal(env.calls.some(call=>call.url.endsWith("/terminal/control")),false);
});
test("selected native text copies locally without a backend call or takeover", async () => {
  const env=environment();await env.window.renderAgentWorkbench();env.ready();env.paint();
  env.terminals[0].selectionText="所选输出";env.terminals[0].selectionHandler();
  assert.equal(env.nodes.get("aw-copy-result").textContent,"复制选中文本");
  await env.nodes.get("aw-copy-result").click();assert.deepEqual(env.legacyCopies,["所选输出"]);
  assert.equal(env.calls.some(call=>call.url.endsWith("/copy-text")||call.url.endsWith("/terminal/control")),false);
});
test("failed local clipboard write keeps selectable text and does not claim success", async () => {
  const env=environment();await env.window.renderAgentWorkbench();env.ready();env.paint();env.setCopyAllowed(false);
  env.terminals[0].selectionText="保留文本";await env.nodes.get("aw-copy-result").click();
  assert.equal(env.nodes.get("aw-copy-text").value,"保留文本");assert.equal(env.nodes.get("aw-copy-text").selected,true);
  assert.ok(env.nodes.get("aw-task-feedback").textContent.includes("未允许复制"));assert.equal(env.nodes.get("aw-copy-panel").classList.contains("hidden"),false);
});
test("a late copy response cannot populate a different session", async () => {
  const pending=deferred();let env;env=environment(call=>call.url.endsWith("/copy-text")?pending.promise:env.defaultReply(call));
  await env.window.renderAgentWorkbench();env.ready();env.paint();const operation=env.nodes.get("aw-copy-result").click();await flush();await env.select("sess_b");
  pending.resolve({ok:true,text:"old session text"});await operation;
  assert.equal(env.nodes.get("aw-copy-text").value,"");assert.equal(env.nodes.get("aw-copy-panel").classList.contains("hidden"),true);assert.equal(env.legacyCopies.length,0);
});
test("OSC52 is registered, rejects queries and ignores replay after reattachment", async () => {
  const env=environment();await env.window.renderAgentWorkbench();env.ready();env.paint();
  const terminal=env.terminals[0],handler=terminal.oscHandlers.get(52),payload="c;"+Buffer.from("copied native result").toString("base64");
  assert.equal(typeof handler,"function");handler(payload);assert.equal(env.nodes.get("aw-copy-text").value,"");
  await env.nodes.get("aw-term-acquire").click();terminal.data("x");handler("c;?");assert.equal(env.nodes.get("aw-copy-text").value,"");
  handler(payload);assert.equal(env.nodes.get("aw-copy-text").value,"copied native result");assert.equal(env.legacyCopies.length,0);
  await env.nodes.get("aw-term-disconnect").click();await env.nodes.get("aw-term-reconnect").click();env.ready();env.paint();
  env.terminals.at(-1).oscHandlers.get(52)(payload);handler(payload);
  assert.equal(env.nodes.get("aw-copy-text").value,"");assert.equal(env.nodes.get("aw-copy-panel").classList.contains("hidden"),true);
});
test("logout and navigation both invoke the workbench suspension hook", () => {
  const login = app.slice(app.indexOf("function showLogin()"), app.indexOf("function showLogin()") + 220);
  const navigate = app.slice(app.indexOf("function activateTab("), app.indexOf("function setMonitorSub("));
  assert.ok(login.includes("window.suspendAgentWorkbench()"));
  assert.ok(navigate.includes('tab !== "agent" && typeof window.suspendAgentWorkbench'));
});
(async () => {
  let passed = 0;
  for (const [name, run] of tests) { try { await run(); console.log("PASS " + name); passed++; } catch (error) { console.error("FAIL " + name); throw error; } }
  console.log(`${passed}/${tests.length} native workbench UI tests passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
