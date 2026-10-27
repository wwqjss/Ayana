/* Run the real workbench callbacks against controlled API/PTY ordering. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../ayana/static/workbench.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../ayana/static/index.html"), "utf8");
const app = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 20; n++) await Promise.resolve(); };
class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.listeners = {}; this._text = "";
    this.className = ""; this.value = ""; this.checked = false; this.disabled = false;
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
  async click() { if (this.disabled) return; if (this.onclick) await this.onclick(); for (const h of this.listeners.click || []) await h(); }
  querySelectorAll(selector) { return this.children.flatMap(c => [...(c.tagName.toLowerCase() === selector ? [c] : []), ...c.querySelectorAll(selector)]); }
}
const sessions = [
  { id: "sess_a", title: "automatic-a", origin: "auto", status: "open", created_at: 1 },
  { id: "sess_b", title: "manual-b", origin: "manual", status: "open", created_at: 2 },
];
function environment(reply) {
  const nodes = new Map(), calls = [], sockets = [], terminals = [], observers = [], timers = new Map(), timeouts = new Map(), events = new Map(), modals = [], alerts = [], prompts = [];
  for (const match of html.matchAll(/\bid="(aw-[^"]+|agent-workbench)"/g)) nodes.set(match[1], new Element());
  class Terminal {
    constructor(options) {
      this.options = options; this.cols = 100; this.rows = 36; this.output = [];
      this.screenText = ""; this.pendingWrites = [];
      const terminal = this;
      this.buffer = { active: { viewportY: 0, get length() { return terminal.rows; },
        getLine(index) { return { translateToString: () => terminal.screenText.split("\n")[index] || "" }; } } };
      terminals.push(this);
    }
    open(host) { this.host = host; }
    loadAddon(addon) { this.addon = addon; if (addon.activate) addon.activate(this); }
    onData(callback) { this.data = callback; }
    onResize(callback) { this.resizeHandler = callback; }
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
    return { ok: true, session: { ...sessions.find(s => s.id === sid), remote_session_id: "ses_" + sid }, incidents: [], can_control: true, can_prepare: true };
  };
  const window = {
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
    console, window, WebSocket: Socket, ResizeObserver: Observer, ArrayBuffer, Uint8Array, URL, Date,
    document: { getElementById: id => nodes.get(id), createElement: tag => new Element(tag), createTextNode: text => { const e = new Element("text"); e.textContent = text; return e; } },
    location: { protocol: "https:", host: "ayana.test" }, requestAnimationFrame: callback => callback(),
    setInterval: callback => { const id = ++nextTimer; timers.set(id, callback); return id; }, clearInterval: id => timers.delete(id),
    setTimeout: callback => { const id = ++nextTimer; timeouts.set(id, callback); return id; }, clearTimeout: id => timeouts.delete(id),
    alert: message => alerts.push(message), confirm: () => true, prompt: () => prompts.shift() ?? "",
  });
  vm.runInContext(source, context);
  const select = id => nodes.get("aw-session-list").children.find(c => c.tagName === "BUTTON" && c.textContent.includes(id === "sess_a" ? "automatic-a" : "manual-b")).click();
  const ready = (socket = sockets.at(-1)) => { socket.readyState = 1; socket.onmessage({ data: JSON.stringify({ type: "ready", connection_id: "connection-" + sockets.indexOf(socket), control: false }) }); };
  const output = (text, socket = sockets.at(-1)) => socket.onmessage({ data: new Uint8Array(Buffer.from(text)).buffer });
  const paint = (socket = sockets.at(-1)) => output("\x1b[HMiMo", socket);
  return { nodes, calls, sockets, terminals, observers, timers, timeouts, events, modals, alerts, prompts, select, ready, output, paint, window, run: code => vm.runInContext(code, context), defaultReply };
}
const tests = [];
const test = (name, run) => tests.push([name, run]);

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
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察");
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
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察");
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
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察");
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
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察");
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
  assert.equal(env.nodes.get("aw-term-status").textContent, "观察");
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
