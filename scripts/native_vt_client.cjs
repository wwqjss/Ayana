/* Real HTTP/WebSocket + real xterm parser integration for the unchanged
 * workbench. The DOM adapter is intentionally minimal; this is not a browser
 * visual acceptance test and it never submits prompts through an HTTP shortcut.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const { performance } = require("node:perf_hooks");
const WebSocket = require("ws");

const base = new URL(process.env.AYANA_VT_BASE || "http://127.0.0.1:16398");
const key = process.env.AYANA_VT_KEY || "";
if (base.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) || base.username || base.password || base.search || base.hash || base.pathname !== "/") throw new Error("probe_base_must_be_local_http");
if (!key || !process.env.AYANA_HEADLESS_MODULE) throw new Error("probe_capability_and_headless_module_required");
const { Terminal: HeadlessTerminal } = require(process.env.AYANA_HEADLESS_MODULE);
const sourcePath = path.resolve(__dirname, "../ayana/static/workbench.js");
const source = fs.readFileSync(sourcePath, "utf8");
const html = fs.readFileSync(path.resolve(__dirname, "../ayana/static/index.html"), "utf8");
const nodes = new Map(), terminals = [], sockets = new Set(), intervals = new Set(), timeouts = new Set(), modals = [], calls = [];
const queries = { window: {}, modes: {}, replies: 0 };
const report = {
  kind: "real-vt-workbench-integration", browser_visual_test: false,
  workbench_source_sha256: crypto.createHash("sha256").update(source).digest("hex"),
  executed_workbench_unmodified: true, direct_http_prompt_calls: 0,
  geometry_adapter: { cols: 144, rows: 47, cell_width: 8, cell_height: 16 },
};
const started = performance.now();
let phase = "initialize", activeModal = null, context, window;

class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.listeners = {};
    this.className = ""; this._text = ""; this.value = ""; this.checked = false; this.disabled = false; this.style = {};this.dataset={};
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/), ...names])].join(" "); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(name => !names.includes(name)).join(" "); },
      toggle: (name, force) => { const on = force === undefined ? !this.classList.contains(name) : force; on ? this.classList.add(name) : this.classList.remove(name); return on; },
    };
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(""); }
  set innerHTML(_) { this._text = ""; this.children = []; }
  appendChild(child) { child.parentElement = this; this.children.push(child); return child; }
  setAttribute(name, value) { this[name === "class" ? "className" : name] = value; }
  addEventListener(name, callback) { (this.listeners[name] ||= []).push(callback); }
  async click() { if (this.disabled) return; if (this.onclick) await this.onclick(); for (const callback of this.listeners.click || []) await callback(); }
  focus() {}
  querySelectorAll(tag) { return this.children.flatMap(child => [...(child.tagName.toLowerCase() === tag ? [child] : []), ...child.querySelectorAll(tag)]); }
}
for (const item of html.matchAll(/\bid="(aw-[^"]+|agent-workbench)"/g)) nodes.set(item[1], new Element());

class Terminal extends HeadlessTerminal {
  constructor(options) {
    super({ ...options, allowProposedApi: true, logLevel: "off" });
    this.probeDisposed = false; terminals.push(this);
    // Headless has no physical screen pixels. Implement only read-only geometry
    // reports; actual ANSI parsing, screen buffers and onData remain xterm's.
    this.parser.registerCsiHandler({ final: "t" }, params => {
      const code = params[0];
      if (![14, 16, 18].includes(code)) return false;
      queries.window[code] = (queries.window[code] || 0) + 1;
      const response = code === 14 ? `\x1b[4;${this.rows * 16};${this.cols * 8}t`
        : code === 16 ? "\x1b[6;16;8t" : `\x1b[8;${this.rows};${this.cols}t`;
      this.input(response, false); return true;
    });
    this.parser.registerCsiHandler({ prefix: "?", intermediates: "$", final: "p" }, params => {
      const mode = String(params[0]); queries.modes[mode] = (queries.modes[mode] || 0) + 1;
      return false; // Let the real xterm parser generate the DECRPM response.
    });
    this.onData(data => { if (data.startsWith("\x1b")) queries.replies++; });
  }
  open(host) { this.probeHost = host; }
  focus() {}
  dispose() { if (!this.probeDisposed) { this.probeDisposed = true; super.dispose(); } }
}
class FitAddon {
  activate(terminal) { this.terminal = terminal; }
  fit() { if (this.terminal) this.terminal.resize(144, 47); }
  dispose() {}
}
class Socket extends WebSocket {
  constructor(url) {
    super(url, { headers: { Origin: base.origin, "X-Probe-Key": key } });
    sockets.add(this); this.on("close", () => sockets.delete(this)); this.on("error", () => {});
  }
}
async function request(route, options = {}) {
  const response = await fetch(new URL(route, base), {
    ...options, headers: { "Content-Type": "application/json", "X-Probe-Key": key, ...(options.headers || {}) },
    signal: AbortSignal.timeout(10000),
  });
  calls.push({ path: route.split("?")[0], method: options.method || "GET", status: response.status });
  if (/\/(?:prompt|prompt_async)$/.test(route.split("?")[0])) throw new Error("direct_prompt_shortcut_forbidden");
  try { return await response.json(); } catch (_) { throw new Error("probe_api_invalid_json_" + response.status); }
}
window = {
  Terminal, FitAddon: { FitAddon }, api: request,
  showModal: (title, children) => { activeModal = { title, children }; modals.push(activeModal); },
  closeModal: () => { activeModal = null; },
  addEventListener: () => {}, matchMedia: () => ({ matches: false }),
  atob: value => Buffer.from(value, "base64").toString("binary"),
};
const trackedTimeout = (callback, delay) => {
  const timer = setTimeout(() => { timeouts.delete(timer); callback(); }, delay);
  timeouts.add(timer); return timer;
};
context = vm.createContext({
  window, console, WebSocket: Socket, ArrayBuffer, Uint8Array, URL, Date, TextEncoder, TextDecoder,
  document: { getElementById: id => nodes.get(id), createElement: tag => new Element(tag), createTextNode: text => { const node = new Element("#text"); node.textContent = text; return node; } },
  location: { protocol: base.protocol, host: base.host },
  ResizeObserver: class { observe() {} disconnect() {} },
  requestAnimationFrame: callback => trackedTimeout(callback, 0),
  setInterval: (callback, delay) => { const timer = setInterval(callback, delay); intervals.add(timer); return timer; },
  clearInterval: timer => { clearInterval(timer); intervals.delete(timer); },
  setTimeout: trackedTimeout, clearTimeout: timer => { clearTimeout(timer); timeouts.delete(timer); },
  alert: () => {}, confirm: () => false, prompt: () => null,
});
vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../ayana/static/terminal_clipboard.js"), "utf8"), context, { filename: "actual-terminal-clipboard.js" });
vm.runInContext(source, context, { filename: "actual-workbench.js" });

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
function assert(condition, code) { if (!condition) throw new Error(code); }
function terminal() { return terminals.at(-1); }
function screen() {
  const buffer = terminal()?.buffer.active;
  if (!buffer) return "";
  const lines = [];
  for (let i = 0; i < buffer.length; i++) lines.push(buffer.getLine(i)?.translateToString(true) || "");
  return lines.join("\n");
}
function occurrences(text, marker) { return text.split(marker).length - 1; }
async function waitUntil(check, milliseconds, code) {
  const deadline = performance.now() + milliseconds;
  while (performance.now() < deadline) { const value = await check(); if (value) return value; await sleep(100); }
  throw new Error(code);
}
function snapshot(state) {
  return { user_messages: state.user_messages, runtime_state: state.binding?.state,
    receipt_statuses: (state.receipts || []).map(item => item.status),
    remote_session_id: state.binding?.remote_session_id,
    engine_pid: state.binding?.engine_pid, pane_pid: state.binding?.pane_pid };
}
async function probeState(sid) { return request("/probe/state?sid=" + encodeURIComponent(sid)); }
async function takeControl() {
  await nodes.get("aw-term-acquire").click();
  assert(nodes.get("aw-term-status").textContent.includes("控制中"), "native_control_not_acquired");
}
async function sendAndWait(sid, marker, expectedUsers) {
  terminal().input("请只回复 " + marker + "，不要调用任何工具，不执行其他任务。", true);
  await sleep(250); terminal().input("\r", true);
  let latest;
  await waitUntil(async () => {
    latest = await probeState(sid);
    return occurrences(screen(), marker) >= 2 && latest.user_messages === expectedUsers
      && latest.binding?.state === "idle" && (latest.receipts || []).length > 0
      && latest.receipts.every(receipt => receipt.status === "completed");
  }, 45000, "native_reply_not_rendered_or_settled");
  return snapshot(latest);
}
async function run() {
  phase = "render_empty_workbench";
  await window.renderAgentWorkbench();
  assert(window.agentWorkbenchState.sessions.length === 0 && !window.agentWorkbenchState.currentId, "probe_actor_has_prior_sessions");
  phase = "click_new_session";
  await nodes.get("aw-new-session").click();
  assert(activeModal, "native_create_dialog_missing");
  const form = activeModal.children[0];
  form.querySelectorAll("input")[0].value = "真实 VT 普通新建验收 " + crypto.randomBytes(3).toString("hex");
  const coldStarted = performance.now();
  await form.querySelectorAll("button")[0].click();
  const sid = window.agentWorkbenchState.currentId;
  assert(sid, "ordinary_new_session_not_created"); report.session_id = sid;
  phase = "cold_native_welcome";
  await waitUntil(() => screen().includes("输入消息"), Math.max(1, 10000 - (performance.now() - coldStarted)), "cold_native_welcome_not_visible");
  report.cold_welcome_ms = Math.round(performance.now() - coldStarted);
  report.cold_welcome_visible = true;
  assert(nodes.get("aw-term-notice").classList.contains("hidden"), "native_screen_hidden_by_notice");
  const firstMarker = "VT_FIRST_" + crypto.randomBytes(6).toString("hex");
  phase = "first_takeover_input"; await takeControl();
  const firstStarted = performance.now();
  const first = await sendAndWait(sid, firstMarker, 1);
  report.first_response_ms = Math.round(performance.now() - firstStarted);
  report.first_visible = true; report.first_state = first;
  phase = "disconnect_and_reconnect";
  await nodes.get("aw-term-disconnect").click();
  const reconnectStarted = performance.now();
  await nodes.get("aw-term-reconnect").click();
  await waitUntil(() => occurrences(screen(), firstMarker) >= 2 && nodes.get("aw-term-notice").classList.contains("hidden"), 10000, "same_native_history_not_visible_after_reconnect");
  report.reconnect_history_ms = Math.round(performance.now() - reconnectStarted);
  const reconnected = snapshot(await probeState(sid));
  assert(reconnected.user_messages === 1, "reconnect_replayed_user_input");
  assert(reconnected.remote_session_id === first.remote_session_id, "reconnect_changed_native_session");
  assert(reconnected.engine_pid === first.engine_pid && reconnected.pane_pid === first.pane_pid, "reconnect_replaced_native_process");
  report.reconnect_same_engine = report.reconnect_same_pane = report.reconnect_without_replay = true;
  phase = "second_takeover_input"; await takeControl();
  const secondStarted = performance.now();
  const second = await sendAndWait(sid, "VT_SECOND_" + crypto.randomBytes(6).toString("hex"), 2);
  report.second_response_ms = Math.round(performance.now() - secondStarted);
  report.second_visible = true; report.second_state = second;
  report.two_distinct_user_turns = second.user_messages === 2;
  report.passed = true;
}
async function cleanup() {
  try { window.suspendAgentWorkbench(); } catch (_) {}
  for (const timer of intervals) clearInterval(timer);
  for (const timer of timeouts) clearTimeout(timer);
  for (const item of terminals) try { item.dispose(); } catch (_) {}
  await Promise.all([...sockets].map(socket => new Promise(resolve => {
    if (socket.readyState === WebSocket.CLOSED) return resolve();
    const timeout = setTimeout(() => { socket.terminate(); resolve(); }, 1500);
    socket.once("close", () => { clearTimeout(timeout); resolve(); }); socket.close();
  })));
}
(async () => {
  try { await run(); }
  catch (error) { report.passed = false; report.failure_phase = phase; report.error = error.message; report.notice = nodes.get("aw-term-notice")?.textContent; process.exitCode = 1; }
  finally {
    report.total_ms = Math.round(performance.now() - started); report.terminal_queries = queries;
    report.api_requests = calls; await cleanup(); process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  }
})().catch(() => { process.exitCode = 1; });
