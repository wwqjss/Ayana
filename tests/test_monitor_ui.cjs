/* DOM regressions for the shared resource view, independent sources, and request races. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { execFileSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "ayana/static/app.js"), "utf8");
const html = fs.readFileSync(path.join(root, "ayana/static/index.html"), "utf8");
const form = JSON.parse(execFileSync("python", ["-c", "import json; from ayana.formspec import get_form; print(json.dumps(get_form('checks')))"], { cwd: root, encoding: "utf8" }));

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.listeners = {};
    this.className = ""; this.style = {}; this._value = ""; this._text = ""; this.disabled = false;
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(" "), ...names])].join(" "); },
      remove: (...names) => { this.className = this.className.split(" ").filter((name) => !names.includes(name)).join(" "); },
      toggle: (name, force) => { if (force) this.classList.add(name); else this.classList.remove(name); },
      contains: (name) => this.className.split(" ").includes(name),
    };
  }
  set value(value) { const text = String(value); this._value = this.tagName === "SELECT" && !this.children.some((child) => child.value === text) ? "" : text; }
  get value() { return this._value; }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(_) { this._text = ""; this.children = []; this._value = ""; }
  appendChild(child) { child.parent = this; this.children.push(child); if (this.tagName === "SELECT" && this.children.length === 1) this._value = child.value; return child; }
  setAttribute(name, value) { if (name === "class") this.className = value; else if (name === "value") this._value = String(value); else this[name] = value; }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  async dispatch(type) { for (const listener of this.listeners[type] || []) await listener({ target: this }); }
  async click() { if (!this.disabled) await this.dispatch("click"); }
  closest(selector) { return this.tagName.toLowerCase() === selector ? this : this.parent ? this.parent.closest(selector) : null; }
  querySelectorAll(selector) {
    const result = [];
    const matches = (element) => selector.startsWith(".") ? element.className.split(" ").includes(selector.slice(1)) : element.tagName.toLowerCase() === selector;
    for (const child of this.children) { if (matches(child)) result.push(child); result.push(...child.querySelectorAll(selector)); }
    return result;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  scrollIntoView() {}
}

const hosts = [
  { asset_id: "control", display_name: "Control", state: "no_data", health: { state: "no_data", label: "暂无数据", cls: "dim" } },
  { asset_id: "sora", display_name: "Sora", state: "partial_no_data", health: { state: "partial_no_data", label: "部分未观测", cls: "warn" } },
];
const native = { source: "ayana", id: "control-containerd", asset_id: "control", name: "容器运行状态", kind: "service", params: { unit: "containerd" }, expect: {}, enabled: true, last_at: 123, last_state: "ok", interval_sec: 60, fail_threshold: 2, severity: "warning" };
const oldProbe = { source: "prometheus", id: "control-probe", name: "网站可用性", kind: "probe", state: "ok", last_at: 123, labels: { internal_label: "private-probe" } };
const emptyMetrics = { ok: true, asset: { id: "control" }, overview: { state: "no_data", metrics: {} }, history: { state: "no_data", metrics: {} } };
const metricsFor = (id, range = "1h") => ({ ok: true, asset: { id }, overview: { state: "ok", metrics: { observed: { key: "observed", state: "ok", value: 12 } } }, history: { state: "ok", metrics: { observed: { key: "observed", label: id + " " + range + " 当前指标", state: "ok", value: 12, points: [{ t: 1, v: 12 }, { t: 2, v: 13 }] } } } });
const businessFor = (id, items = id === "control" ? [oldProbe, native] : [{ source: "prometheus", id: "sora-youtube", name: "视频代理", kind: "proxy", state: "fail", last_at: 124 }]) => ({ ok: true, asset: { id, display_name: id === "control" ? "Control" : "Sora" }, items, errors: [] });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { for (let index = 0; index < 8; index++) await Promise.resolve(); };

function environment(customReply) {
  const nodes = new Map(), calls = [];
  const create = (id, tag = "div") => { const node = new Element(tag); node.id = id; nodes.set(id, node); return node; };
  for (const id of ["monitor-body", "monitor-hosts-strip", "monitor-business", "monitor-onboard", "monitor-install-box", "promconfig-ne", "chk-list", "chk-activity", "chk-assist-msg", "modal", "modal-title", "modal-body", "monitor-sub-metrics", "monitor-sub-checks", "monitor-sub-prom"]) create(id);
  for (const id of ["monitor-detect", "monitor-configure", "monitor-refresh", "monitor-auto", "chk-refresh", "chk-add"]) create(id, "button");
  for (const id of ["monitor-host", "pc-ne-asset", "monitor-range", "chk-asset"]) create(id, "select");
  create("pc-ne-register", "input");
  for (const sub of ["metrics", "checks", "prom"]) { const node = create("sub-" + sub, "button"); node.dataset.sub = sub; }
  const state = { tab: "monitor", monitorSub: "metrics", assets: [
    { id: "control", display_name: "Control", monitor_host: "10.0.0.1" },
    { id: "sora", display_name: "Sora", monitor_host: "10.0.0.2" },
  ] };
  const defaultReply = (url) => {
    if (url === "/api/monitor/hosts") return { ok: true, hosts };
    if (url.startsWith("/api/monitor/host/")) { const parsed = new URL(url, "http://local"); const id = parsed.pathname.split("/").at(-1); return id === "control" ? emptyMetrics : metricsFor(id, parsed.searchParams.get("range")); }
    if (url.startsWith("/api/monitor/business/")) return businessFor(url.split("/").at(-1));
    if (url.startsWith("/api/checks?")) return { ok: true, checks: [native] };
    if (url === "/api/checks/activity") return { ok: true, activity: [] };
    if (["/api/checks/run", "/api/checks/update", "/api/checks/delete"].includes(url)) return { ok: true };
    if (url === "/api/setup/monitor") return { ok: true, prometheus_ok: true };
    if (url === "/api/promconfig/node-exporter/detect") return { ok: true, running: true, binary: "/usr/bin/node_exporter", port_9100: true };
    if (url === "/api/promconfig/node-exporter/adopt") return { ok: true, scrape: { has_metrics: true }, address: "10.0.0.1:9100" };
    throw new Error("Unexpected API request " + url);
  };
  const context = vm.createContext({
    console, setTimeout: () => 0, clearInterval: () => {}, setInterval: () => 1,
    document: { createElement: (tag) => new Element(tag), createTextNode: (text) => { const node = new Element("text"); node.textContent = text; return node; }, getElementById: (id) => nodes.get(id), querySelectorAll: (selector) => selector === "#monitor-subnav .subtab" ? [nodes.get("sub-metrics"), nodes.get("sub-checks"), nodes.get("sub-prom")] : [] },
    $: (id) => nodes.get(id), on: (id, type, listener) => nodes.get(id)?.addEventListener(type, listener), state,
    api: async (url, options = {}) => { const request = { url, body: options.body ? JSON.parse(options.body) : null }; calls.push(request); const result = customReply && customReply(request, defaultReply); return result === undefined ? defaultReply(url) : await result; },
    badge: (label, cls) => { const node = new Element("span"); node.className = "badge " + cls; node.textContent = label; return node; },
    pcBadge: (label, cls) => { const node = new Element("span"); node.className = "badge " + cls; node.textContent = label; return node; },
    assistForms: { checks: form }, ensureAssistForm: async () => form, chkKindChanged: () => {},
    assistNote: (id, lines) => { if (nodes.get(id)) nodes.get(id).textContent = lines.join("\n"); },
    getSchemaDefault: (_, name) => form.fields.find((field) => field.name === name)?.default,
    fmtTime: (value) => "最近 " + value,
    showModal: (title, children) => { nodes.get("modal-title").textContent = title; nodes.get("modal-body").innerHTML = ""; children.forEach((child) => nodes.get("modal-body").appendChild(child)); nodes.get("modal").classList.remove("hidden"); },
  });
  const cut = (start, end) => { const from = source.indexOf(start); assert.ok(from >= 0, start); const to = source.indexOf(end, from); assert.ok(to > from, end); return source.slice(from, to); };
  for (const [start, end] of [
    ["function el(", "async function api("], ["function fillSelect(", "async function refreshTab("],
    ["function setMonitorSub(", "function setNotifySub("], ["function syncChecksAsset(", "/* ---- 统一健康状态"],
    ["const pcProgressByHost", "function showModal("], ["const monitorState", "/* ---- 通知渠道"],
    ["function pcFillRegisterAddr(", "async function renderPcNodeExporter("],
    ["function checkHostLabel(", "function chkKindChanged("], ["function humanFormError(", "async function assistConfigure("],
  ]) vm.runInContext(cut(start, end), context);
  return { nodes, calls, state, run: (code) => vm.runInContext(code, context) };
}

const tests = [];
const test = (name, run) => tests.push({ name, run });

test("the resource view contains inline onboarding and the shared business region", () => {
  assert.ok(!html.includes('data-sub="onboard"'));
  assert.ok(!html.includes('id="monitor-sub-onboard"'));
  const metrics = html.slice(html.indexOf('id="monitor-sub-metrics"'), html.indexOf('id="monitor-sub-checks"'));
  assert.ok(metrics.includes('id="monitor-onboard"')); assert.ok(metrics.includes('id="monitor-business"'));
  assert.ok(metrics.indexOf('id="monitor-body"') < metrics.indexOf('id="monitor-business"'));
  assert.equal((html.match(/id="monitor-detect"/g) || []).length, 1);
  assert.ok(html.includes('data-sub="checks"')); assert.ok(html.includes('data-sub="prom"'));
});

test("missing Node metrics never hide old Prometheus checks or the native containerd check", async () => {
  const env = environment(); await env.run("renderMonitor()");
  const business = env.nodes.get("monitor-business").textContent;
  assert.ok(business.includes("网站可用性")); assert.ok(business.includes("containerd"));
  assert.ok(business.includes("Prometheus")); assert.ok(business.includes("Ayana 原生"));
  assert.ok(business.includes("正常"));
  assert.equal(env.nodes.get("monitor-onboard").classList.contains("hidden"), false);
  assert.equal(env.nodes.get("pc-ne-asset").value, "control");
  assert.equal(env.nodes.get("pc-ne-register").value, "10.0.0.1:9100");
  assert.ok(env.nodes.get("monitor-hosts-strip").children[0].classList.contains("active"));
  const advanced = env.nodes.get("monitor-business").querySelector("details");
  assert.equal(advanced.open, undefined); assert.ok(advanced.textContent.includes("private-probe"));
  assert.ok(!env.calls.some((call) => call.body));
});

test("an entirely empty metric response omits the blank card grid while retaining onboarding and business checks", async () => {
  const metrics = Object.fromEntries(["cpu", "memory", "disk", "swap", "load1", "disk_read", "net_rx"].map((key) => [key, { key, value: null, state: "no_data", points: [] }]));
  const env = environment(({ url }) => {
    if (url.startsWith("/api/monitor/host/")) return { ...emptyMetrics, overview: { state: "no_data", metrics }, history: { state: "no_data", metrics } };
  });
  await env.run("renderMonitor()");
  assert.equal(env.nodes.get("monitor-body").querySelector(".metric-grid"), null);
  assert.equal(env.nodes.get("monitor-body").querySelector(".metric-card"), null);
  assert.ok(env.nodes.get("monitor-body").textContent.includes("暂无当前资源数据"));
  assert.equal(env.nodes.get("monitor-onboard").classList.contains("hidden"), false);
  assert.ok(env.nodes.get("monitor-business").textContent.includes("containerd"));
});

test("historical trends remain visible when the latest resource values are missing", async () => {
  const metrics = { cpu: { key: "cpu", label: "CPU 使用率", value: null, state: "no_data", points: [{ t: 1, v: 12 }, { t: 2, v: 13 }] }, memory: { key: "memory", value: null, state: "no_data", points: [] } };
  const env = environment(({ url }) => {
    if (url.startsWith("/api/monitor/host/")) return { ...emptyMetrics, history: { state: "no_data", metrics } };
  });
  await env.run("renderMonitor()");
  assert.ok(env.nodes.get("monitor-body").querySelector(".metric-grid"));
  assert.equal(env.nodes.get("monitor-body").querySelectorAll(".metric-card").length, 2);
  assert.ok(env.nodes.get("monitor-body").textContent.includes("以下为历史趋势"));
  assert.equal(env.nodes.get("monitor-onboard").classList.contains("hidden"), false);
  assert.ok(env.nodes.get("monitor-business").textContent.includes("containerd"));
});

test("partial current resource values retain useful and missing metric cards", async () => {
  const metrics = { cpu: { key: "cpu", label: "CPU 使用率", value: 12, unit: "%", state: "ok", points: [] }, memory: { key: "memory", value: null, state: "no_data", points: [] } };
  const env = environment(({ url }) => {
    if (url.startsWith("/api/monitor/host/")) return { ...emptyMetrics, history: { state: "partial_no_data", metrics } };
  });
  await env.run("renderMonitor()");
  assert.equal(env.nodes.get("monitor-body").querySelectorAll(".metric-card").length, 2);
  assert.ok(env.nodes.get("monitor-body").textContent.includes("12.0"));
  assert.equal(env.nodes.get("monitor-onboard").classList.contains("hidden"), true);
});

test("a single disabled Swap metric keeps its state and has no meaningless chart", () => {
  const env = environment();
  const metric = { key: "swap", label: "Swap 使用率", unit: "%", state: "not_enabled", value: null, points: [] };
  const group = env.run("buildMetricGroups(" + JSON.stringify({ swap: metric }) + ")[0]");
  assert.equal(group.head.state, "not_enabled");
  const card = env.run("metricCard(" + JSON.stringify(group.head) + ", " + JSON.stringify(group.seriesList) + ")");
  assert.ok(card.textContent.includes("未启用")); assert.ok(!card.textContent.includes("正常"));
  assert.equal(card.querySelector("canvas"), null);
});

test("a combined group with all members disabled keeps the disabled state", () => {
  const env = environment();
  const metrics = { net_rx: { key: "net_rx", state: "not_enabled", value: null, points: [] }, net_tx: { key: "net_tx", state: "not_enabled", value: null, points: [] } };
  const group = env.run("buildMetricGroups(" + JSON.stringify(metrics) + ")[0]");
  assert.equal(group.head.state, "not_enabled");
  const card = env.run("metricCard(" + JSON.stringify(group.head) + ", " + JSON.stringify(group.seriesList) + ")");
  assert.ok(card.textContent.includes("未启用")); assert.equal(card.querySelector("canvas"), null);
});

test("an enabled observed member makes a mixed group observed instead of disabled", () => {
  const env = environment();
  const metrics = { net_rx: { key: "net_rx", state: "not_enabled", value: null, points: [] }, net_tx: { key: "net_tx", state: "ok", value: 42, points: [{ t: 1, v: 42 }] } };
  const group = env.run("buildMetricGroups(" + JSON.stringify(metrics) + ")[0]");
  assert.equal(group.head.state, "ok");
  const card = env.run("metricCard(" + JSON.stringify(group.head) + ", " + JSON.stringify(group.seriesList) + ")");
  assert.ok(card.textContent.includes("正常")); assert.ok(!card.textContent.includes("未启用"));
  assert.ok(card.textContent.includes("42")); assert.ok(card.querySelector("canvas"));
});

test("metric and business failures are isolated and source errors retain readable checks", async () => {
  const env = environment(({ url }) => {
    if (url.startsWith("/api/monitor/host/")) return { ok: false, error: "denied" };
    if (url.startsWith("/api/monitor/business/")) return { ...businessFor("control", [native]), errors: [{ source: "prometheus", message: "当前账号没有读取这部分探测结果的权限。" }] };
  });
  await env.run("renderMonitor()");
  assert.ok(env.nodes.get("monitor-body").textContent.includes("没有此操作的权限"));
  assert.ok(env.nodes.get("monitor-business").textContent.includes("containerd"));
  assert.ok(env.nodes.get("monitor-business").textContent.includes("没有读取这部分探测结果"));
});

test("freshness and disabled states from the unified API override old successful results", async () => {
  const env = environment();
  const stale = { ...native, state: "stale", last_state: "ok" };
  const disabled = { ...native, id: "disabled", name: "已停用检查", state: "disabled", last_state: "ok" };
  env.run("renderMonitorBusiness(" + JSON.stringify(businessFor("control", [stale, disabled])) + ", 'control')");
  const rows = env.nodes.get("monitor-business").querySelectorAll("tr");
  assert.ok(rows[1].textContent.includes("样本过期")); assert.ok(!rows[1].textContent.includes("正常"));
  assert.ok(rows[2].textContent.includes("已停用")); assert.ok(!rows[2].textContent.includes("正常"));
});

test("host switches sync all resource sources and stale responses cannot replace the selected host", async () => {
  const oldMetrics = deferred(), oldBusiness = deferred();
  const env = environment(({ url }) => {
    if (url.startsWith("/api/monitor/host/control")) return oldMetrics.promise;
    if (url === "/api/monitor/business/control") return oldBusiness.promise;
  });
  const old = env.run("renderMonitor()"); await flush();
  await env.run("selectMonitorHost('sora')");
  assert.equal(env.nodes.get("pc-ne-asset").value, "sora");
  assert.equal(env.nodes.get("pc-ne-register").value, "10.0.0.2:9100");
  assert.equal(env.nodes.get("monitor-onboard").classList.contains("hidden"), true);
  oldMetrics.resolve({ ...metricsFor("control"), health: { state: "no_data", label: "暂无数据", cls: "dim" } });
  oldBusiness.resolve(businessFor("control")); await old;
  assert.equal(env.nodes.get("monitor-host").value, "sora");
  assert.ok(env.nodes.get("monitor-body").textContent.includes("sora 1h 当前指标"));
  assert.ok(!env.nodes.get("monitor-body").textContent.includes("control 1h 当前指标"));
  assert.ok(env.nodes.get("monitor-business").textContent.includes("视频代理"));
  assert.ok(!env.nodes.get("monitor-business").textContent.includes("containerd"));
  assert.equal(env.nodes.get("monitor-host").children[1].textContent, "Sora · 部分未观测");
});

test("old gray host summaries cannot overwrite a newer observed yellow summary", async () => {
  const oldHosts = deferred(); let summaries = 0;
  const observed = [{ ...hosts[0], state: "partial_no_data", health: { label: "部分未观测", cls: "warn" } }];
  const env = environment(({ url }) => {
    if (url === "/api/monitor/hosts") return ++summaries === 1 ? oldHosts.promise : { ok: true, hosts: observed };
    if (url.startsWith("/api/monitor/host/")) return metricsFor("control");
  });
  const old = env.run("renderMonitor()"); await flush(); await env.run("renderMonitor()");
  oldHosts.resolve({ ok: true, hosts }); await old;
  assert.ok(env.nodes.get("monitor-host").textContent.includes("部分未观测"));
  assert.ok(!env.nodes.get("monitor-host").textContent.includes("暂无数据"));
  assert.ok(env.nodes.get("monitor-hosts-strip").children[0].querySelector("span").classList.contains("warn"));
});

test("current detail health refreshes only the selected host dropdown and dot", async () => {
  const env = environment(({ url }) => {
    if (url.startsWith("/api/monitor/host/control")) return { ...metricsFor("control"), health: { state: "ok", cls: "ok", label: "正常" } };
  });
  await env.run("renderMonitor()");
  assert.equal(env.nodes.get("monitor-host").value, "control");
  assert.equal(env.nodes.get("monitor-host").children[0].textContent, "Control · 正常");
  assert.equal(env.nodes.get("monitor-host").children[1].textContent, "Sora · 部分未观测");
  const chips = env.nodes.get("monitor-hosts-strip").children;
  assert.ok(chips[0].querySelector("span").classList.contains("ok"));
  assert.ok(chips[1].querySelector("span").classList.contains("warn"));
  assert.equal(env.run("monitorState.hosts[0].state"), "ok");
  assert.equal(env.run("monitorState.hosts[1].state"), "partial_no_data");
});

test("range changes bind metric requests and ignore old historical results", async () => {
  const previous = deferred();
  const env = environment(({ url }) => { if (url.endsWith("range=1h")) return previous.promise; });
  const old = env.run("selectMonitorHost('sora')"); await flush();
  env.run("monitorState.range = '6h'"); await env.run("renderMonitor()");
  previous.resolve(metricsFor("sora", "1h")); await old;
  assert.ok(env.nodes.get("monitor-body").textContent.includes("sora 6h 当前指标"));
  assert.ok(!env.nodes.get("monitor-body").textContent.includes("sora 1h 当前指标"));
});

test("native maintenance is explicit and refreshes the unified resources after success", async () => {
  let stopped = false;
  const env = environment(({ url, body }) => {
    if (url === "/api/checks/update") { assert.deepEqual(body, { id: native.id, enabled: false }); stopped = true; return { ok: true }; }
    if (url === "/api/monitor/business/control") return businessFor("control", [{ ...native, enabled: !stopped }]);
  });
  await env.run("renderMonitor()");
  assert.ok(!env.calls.some((call) => call.body));
  await env.nodes.get("monitor-business").querySelectorAll("button").find((button) => button.textContent === "停用").click();
  assert.equal(env.calls.filter((call) => call.url === "/api/checks/update").length, 1);
  assert.ok(env.nodes.get("monitor-business").textContent.includes("已停用"));
  assert.ok(env.nodes.get("monitor-business").textContent.includes("启用"));
});

test("completed check creation returns to its host resource summary", async () => {
  const env = environment(); env.state.monitorSub = "checks";
  await env.run("refreshResourceAfterCheck('control', true)");
  assert.equal(env.state.monitorSub, "metrics"); assert.equal(env.nodes.get("monitor-host").value, "control");
  assert.ok(env.nodes.get("monitor-business").textContent.includes("containerd"));
});

test("switching hosts during onboarding cannot move the old host progress into the new host", async () => {
  const detection = deferred();
  const env = environment(({ url }) => { if (url === "/api/promconfig/node-exporter/detect") return detection.promise; });
  env.state.tab = "overview";
  env.run("monitorState.host = 'control'; syncMonitorOnboarding('control', true)");
  const running = env.run("pcRunAdoptFlow('control')"); await flush();
  env.run("monitorState.host = 'sora'; syncMonitorOnboarding('sora', true)");
  detection.resolve({ ok: true, running: true, binary: "node_exporter", port_9100: true }); await running;
  assert.equal(env.nodes.get("monitor-install-box").dataset.hostKey, "sora");
  assert.equal(env.nodes.get("monitor-install-box").textContent, "");
  assert.equal(env.run("pcRunningByHost.control"), false);
  assert.equal(env.run("pcProgressByHost.control[3].status"), "ok");
  assert.equal(env.nodes.get("pc-ne-register").value, "10.0.0.2:9100");
});

test("failed onboarding resets its running state and permits a retry", async () => {
  const env = environment(({ url }) => { if (url === "/api/promconfig/node-exporter/detect") return { ok: false, error: "connection_failed" }; });
  env.state.tab = "overview";
  env.run("monitorState.host = 'control'; syncMonitorOnboarding('control', true)");
  await env.run("pcRunAdoptFlow('control')");
  assert.equal(env.run("pcRunningByHost.control"), false);
  assert.equal(env.nodes.get("monitor-install-box").dataset.running, "0");
  assert.equal(env.nodes.get("monitor-detect").disabled, false);
  await env.run("pcRunAdoptFlow('control')");
  assert.equal(env.calls.filter((call) => call.url === "/api/promconfig/node-exporter/detect").length, 2);
});

test("unavailable Prometheus stops onboarding before detection or changes and permits a retry", async () => {
  let ready = false;
  const env = environment(({ url }) => {
    if (url === "/api/setup/monitor") return { ok: true, prometheus_ok: ready, prometheus_hint: "请先连接 Prometheus" };
  });
  env.state.tab = "overview";
  env.run("monitorState.host = 'control'; syncMonitorOnboarding('control', true)");
  await env.run("pcRunAdoptFlow('control')");
  assert.equal(env.run("pcProgressByHost.control[0].status"), "fail");
  assert.ok(env.nodes.get("monitor-install-box").textContent.includes("请先连接 Prometheus"));
  assert.equal(env.run("pcRunningByHost.control"), false);
  assert.equal(env.nodes.get("monitor-detect").disabled, false);
  assert.ok(!env.calls.some((call) => call.url.startsWith("/api/promconfig/node-exporter/")));
  ready = true;
  await env.run("pcRunAdoptFlow('control')");
  assert.equal(env.run("pcProgressByHost.control[3].status"), "ok");
  assert.equal(env.calls.filter((call) => call.url === "/api/promconfig/node-exporter/detect").length, 1);
});

(async () => {
  let failures = 0;
  for (const item of tests) { try { await item.run(); console.log("PASS " + item.name); } catch (error) { failures++; console.error("FAIL " + item.name, error); } }
  console.log(`${tests.length - failures}/${tests.length} monitoring UI checks passed`); process.exitCode = failures ? 1 : 0;
})();
