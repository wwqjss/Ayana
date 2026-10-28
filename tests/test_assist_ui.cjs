/* DOM-level regression checks for form drafts and confirmation boundaries. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { execFileSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "ayana/static/app.js"), "utf8");
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
  set value(value) {
    const text = String(value);
    this._value = this.tagName === "SELECT" && !this.children.some((child) => child.value === text) ? "" : text;
  }
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

function environment() {
  const nodes = new Map();
  const create = (id, tag = "input", options = []) => {
    const node = new Element(tag); node.id = id; nodes.set(id, node);
    const label = new Element("label"); label.appendChild(node);
    for (const value of options) { const option = new Element("option"); option.value = value; node.appendChild(option); }
    return node;
  };
  for (const field of form.fields) create(field.control, field.type === "enum" || field.source === "assets" ? "select" : "input", field.values || (field.source === "assets" ? ["", "romi", "sora"] : []));
  for (const prefix of ["chk"]) {
    for (const suffix of ["assist-input", "assist-go", "assist-msg", "assist-followup"]) create(prefix + "-" + suffix, suffix === "assist-go" ? "button" : suffix.includes("input") ? "input" : "div");
    const debug = create(prefix + "-assist-debug", "details"); debug.appendChild(new Element("pre"));
  }
  for (const id of ["chk-summary", "chk-params-port", "chk-params-service", "chk-params-command", "modal", "modal-body", "modal-title"]) create(id, "div");
  create("chk-add", "button");
  const calls = [], replies = [];
  const context = vm.createContext({
    console, setTimeout: () => 0,
    document: { createElement: (tag) => new Element(tag), createTextNode: (text) => { const node = new Element("text"); node.textContent = text; return node; } },
    $: (id) => nodes.get(id),
    on: (id, type, listener) => nodes.get(id)?.addEventListener(type, listener),
    state: { assets: [{ id: "romi", display_name: "Romi", objects: [{ id: "romi-nginx", name: "网站服务", unit: "nginx" }, { id: "romi-redis", name: "缓存服务", unit: "redis" }] }, { id: "sora", display_name: "Sora", objects: [] }] },
    api: async (url, options = {}) => {
      calls.push({ url, body: options.body ? JSON.parse(options.body) : null });
      const reply = replies.shift();
      assert.ok(reply !== undefined, "Unexpected API request " + url);
      return typeof reply === "function" ? await reply() : reply;
    },
    showModal: (title, children) => { nodes.get("modal-title").textContent = title; nodes.get("modal-body").innerHTML = ""; children.forEach((child) => nodes.get("modal-body").appendChild(child)); nodes.get("modal").classList.remove("hidden"); },
    chkKindChanged: () => {}, renderChecks: () => {},
    fmtTime: () => "已执行时间",
  });
  const cut = (start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
  vm.runInContext(cut("function el(", "async function api("), context);
  vm.runInContext(cut("function confirmFormAction(", 'on("kb-search"'), context);
  vm.runInContext(cut("function checkHostLabel", "async function renderChecks"), context);
  vm.runInContext(cut("function chkKindChanged", "/* ---- 自然语言辅助配置"), context);
  vm.runInContext(cut("/* ---- 自然语言辅助配置", 'on("monitor-detect"'), context);
  vm.runInContext(cut("function checkPayloadSummary", "/* ---- init ---- */"), context);
  return { nodes, calls, replies, run: (code) => vm.runInContext(code, context) };
}

const validFields = { asset_id: "romi", kind: "service", name: "Romi 网站运行状态", "params.unit": "nginx", interval_sec: 60, fail_threshold: 2, severity: "warning" };
const payload = { asset_id: "romi", kind: "service", name: "Romi 网站运行状态", params: { unit: "nginx" }, expect: {}, interval_sec: 60, fail_threshold: 2, severity: "warning" };
const tests = [];
function test(name, run) { tests.push({ name, run }); }
async function ready(env) { env.replies.push({ ok: true, form }); await env.run("ensureAssistForm('checks')"); }
const setFields = (env, fields = validFields) => env.run("applyCheckFields(" + JSON.stringify(fields) + ")");

test("a new partial draft clears stale fields, including empty strings", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.nodes.get("chk-cmd").value = "old command";
  setFields(env, { asset_id: "sora", kind: "port", "params.port": 443, name: "" });
  assert.equal(env.nodes.get("chk-unit").value, "");
  assert.equal(env.nodes.get("chk-cmd").value, "");
  assert.equal(env.nodes.get("chk-name").value, "");
  assert.equal(env.nodes.get("chk-threshold").value, "");
});

test("quoted command text is sent unchanged to schema validation", async () => {
  const env = environment(); await ready(env);
  setFields(env, { ...validFields, kind: "command", "params.cmd": 'printf "hello world"', "expect.mode": "contains", "expect.value": "hello world" });
  env.replies.push({ ok: false, issues: [{ label: "命令", message: "此主机未授权该命令。" }] });
  await env.run("prepareCheckSubmit()");
  assert.equal(env.calls.at(-1).body.fields["params.cmd"], 'printf "hello world"');
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
});

test("changing check kind clears old target and only submits applicable fields", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.nodes.get("chk-kind").value = "port";
  await env.nodes.get("chk-kind").dispatch("change");
  env.nodes.get("chk-port").value = "443";
  assert.equal(env.nodes.get("chk-unit").value, "");
  const fields = JSON.parse(env.run("JSON.stringify(collectCheckFields())"));
  assert.equal(fields["params.port"], 443);
  assert.equal(fields["params.proto"], "tcp");
  assert.ok(!Object.hasOwn(fields, "params.unit"));
  assert.ok(!Object.hasOwn(fields, "params.cmd"));
  assert.ok(!Object.hasOwn(fields, "expect.mode"));
});

test("changing command expectation clears stale matching text", async () => {
  const env = environment(); await ready(env);
  setFields(env, { ...validFields, kind: "command", "params.cmd": 'curl -I https://example.com', "expect.mode": "contains", "expect.value": "HTTP" });
  env.nodes.get("chk-expect").value = "exit0";
  await env.nodes.get("chk-expect").dispatch("change");
  assert.equal(env.nodes.get("chk-expect-val").value, "");
  const fields = JSON.parse(env.run("JSON.stringify(collectCheckFields())"));
  assert.ok(!Object.hasOwn(fields, "expect.value"));
});

test("canceling the create preview performs no writes", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.replies.push({ ok: true, payload }); await env.run("prepareCheckSubmit()");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
  await env.nodes.get("modal-body").querySelectorAll("button")[0].click();
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
});

test("explicit confirmation posts the exact server validated payload once", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.replies.push({ ok: true, payload }, { ok: true }); await env.run("prepareCheckSubmit()");
  const button = env.nodes.get("modal-body").querySelectorAll("button")[1];
  await button.click(); await button.click();
  const writes = env.calls.filter((call) => call.url === "/api/checks");
  assert.equal(writes.length, 1); assert.deepEqual(writes[0].body, payload);
});

test("editing after validation blocks creation until a fresh preview", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.replies.push({ ok: true, payload }); await env.run("prepareCheckSubmit()");
  env.nodes.get("chk-unit").value = "redis";
  await env.nodes.get("modal-body").querySelectorAll("button")[1].click();
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
  assert.ok(env.nodes.get("modal-body").textContent.includes("表单已修改"));
});

test("failed create explains the reason without displaying bad_name", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.replies.push({ ok: true, payload }, { ok: false, error: "bad_name" }); await env.run("prepareCheckSubmit()");
  await env.nodes.get("modal-body").querySelectorAll("button")[1].click();
  assert.ok(env.nodes.get("modal-body").textContent.includes("检查名称"));
  assert.ok(!env.nodes.get("modal-body").textContent.includes("bad_name"));
});

test("an in flight model response cannot overwrite a manual edit", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.nodes.get("chk-assist-input").value = "监控网站";
  let release; env.replies.push(() => new Promise((resolve) => { release = resolve; }));
  const request = env.run("runAssist('checks')"); await Promise.resolve(); await Promise.resolve();
  assert.equal(env.nodes.get("chk-assist-go").disabled, true);
  env.nodes.get("chk-unit").value = "redis"; await env.nodes.get("chk-unit").dispatch("input");
  release({ ok: true, fields: validFields, missing: [] }); await request;
  assert.equal(env.nodes.get("chk-unit").value, "redis");
  assert.ok(env.nodes.get("chk-assist-msg").textContent.includes("没有覆盖"));
});

test("an outdated description response is discarded", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.nodes.get("chk-assist-input").value = "监控网站";
  let release; env.replies.push(() => new Promise((resolve) => { release = resolve; }));
  const request = env.run("runAssist('checks')"); await Promise.resolve(); await Promise.resolve();
  env.nodes.get("chk-assist-input").value = "改为查看缓存"; await env.nodes.get("chk-assist-input").dispatch("input");
  release({ ok: true, fields: { ...validFields, "params.unit": "apache" }, missing: [] }); await request;
  assert.equal(env.nodes.get("chk-unit").value, "nginx");
});

test("followups retain original intent, previous draft, and targeted answers", async () => {
  const env = environment(); await ready(env);
  env.nodes.get("chk-assist-input").value = "监控我的应用";
  env.replies.push({ ok: true, fields: { asset_id: "romi" }, missing: [{ key: "kind", label: "检查方式", question: "希望查看服务状态还是端口监听？", options: [{ value: "service", label: "服务状态", description: "判断服务是否运行。" }] }] });
  await env.run("runAssist('checks')");
  assert.ok(env.nodes.get("chk-assist-followup").textContent.includes("判断服务是否运行"));
  env.replies.push({ ok: true, fields: validFields, missing: [] });
  await env.run("runAssist('checks', {continuation:true,answers:[{field:'kind',text:'service'}]})");
  const body = env.calls.at(-1).body;
  assert.equal(body.text, "监控我的应用"); assert.equal(body.context.draft.original_text, body.text);
  assert.equal(body.context.draft.fields.asset_id, "romi"); assert.deepEqual(body.context.answers, [{ field: "kind", text: "service" }]);
});

const componentQuestion = {
  field: "clarification.target_component", key: "clarification.target_component", mode: "answer", label: "检查对象",
  question: "希望观察排队任务处理器，还是定时任务调度器？",
  options: [
    { value: "我想观察处理排队任务的组件", label: "排队任务处理器", description: "处理已经进入队列的工作。", mode: "answer" },
    { value: "我想观察按时间启动任务的组件", label: "定时任务调度器", description: "到指定时间后安排新的任务。", mode: "answer" },
  ],
};
const semanticDraft = {
  ok: true, status: "needs_input", ready_to_submit: false, fields: { asset_id: "romi", kind: "service" },
  payload: null, missing: [componentQuestion], defaulted: ["interval_sec"],
};

test("conceptual candidates only continue the conversation before filling a real target", async () => {
  const env = environment(); await ready(env);
  env.nodes.get("chk-assist-input").value = "监控我的后台应用";
  env.replies.push({ ...semanticDraft, confirm_question: "请确认未明确的服务名。" });
  await env.run("runAssist('checks')");
  const followup = env.nodes.get("chk-assist-followup");
  const candidate = followup.querySelector("select");
  assert.ok(followup.textContent.includes("处理已经进入队列的工作"));
  assert.ok(followup.textContent.includes("也可以自己说明"));
  assert.ok(!followup.textContent.includes("确认这个理解"));
  assert.ok(env.nodes.get("chk-assist-msg").textContent.includes("尚未完成配置"));
  assert.ok(!/间隔秒|核对摘要并提交|已准备/.test(env.nodes.get("chk-assist-msg").textContent));
  candidate.value = componentQuestion.options[0].value; await candidate.dispatch("change");
  assert.equal(env.nodes.get("chk-unit").value, "");
  await env.run("prepareCheckSubmit()");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks/validate"));
  env.replies.push({ ok: true, status: "ready", fields: { ...validFields, "params.unit": "report-worker" }, missing: [] });
  await followup.querySelector("button").click();
  const request = env.calls.at(-1).body;
  assert.equal(request.text, "监控我的后台应用");
  assert.deepEqual(request.context.answers, [{ field: componentQuestion.field, text: componentQuestion.options[0].value }]);
  assert.ok(!Object.hasOwn(request.context.draft.fields, componentQuestion.field));
  assert.equal(request.context.draft.fields["params.unit"], "");
  assert.equal(env.nodes.get("chk-unit").value, "report-worker");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks" || call.url === "/api/checks/validate"));
});

test("a custom semantic answer replaces a candidate and failed continuation cannot fill or save", async () => {
  const env = environment(); await ready(env);
  env.nodes.get("chk-assist-input").value = "监控我的应用";
  env.replies.push(semanticDraft); await env.run("runAssist('checks')");
  const followup = env.nodes.get("chk-assist-followup");
  const candidate = followup.querySelector("select"), custom = followup.querySelector("input");
  candidate.value = componentQuestion.options[0].value; await candidate.dispatch("change");
  custom.value = "都不是，我指的是在另一台主机上接收报表请求的应用";
  await custom.dispatch("input");
  assert.equal(candidate.value, "");
  env.replies.push({ ok: false, status: "failed", error: "invalid_model_fields", fields: validFields,
    issues: [{ field: "asset_id", message: "所选主机不存在，请重新选择主机。" }] });
  await followup.querySelector("button").click();
  assert.deepEqual(env.calls.at(-1).body.context.answers, [{ field: componentQuestion.field, text: custom.value }]);
  assert.equal(env.nodes.get("chk-unit").value, "");
  assert.equal(env.run("assistState.checks.response.status"), "needs_input");
  assert.ok(env.nodes.get("chk-assist-msg").textContent.includes("所选主机不存在"));
  assert.equal(custom.value, "都不是，我指的是在另一台主机上接收报表请求的应用");
  await env.run("prepareCheckSubmit()");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks" || call.url === "/api/checks/validate"));
});

test("answer-mode options on actual fields cannot be assigned or bypassed through a manual field edit", async () => {
  const env = environment(); await ready(env);
  env.nodes.get("chk-assist-input").value = "我不知道后台组件叫什么";
  const question = { field: "params.unit", label: "服务名", question: "这个组件主要负责什么？",
    options: [{ value: "我说的是处理后台任务的组件", label: "处理后台任务", mode: "answer" }] };
  env.replies.push({ ...semanticDraft, missing: [question] }); await env.run("runAssist('checks')");
  const followup = env.nodes.get("chk-assist-followup"), candidate = followup.querySelector("select");
  candidate.value = question.options[0].value; await candidate.dispatch("change");
  assert.equal(env.nodes.get("chk-unit").value, "");
  env.nodes.get("chk-unit").value = "nginx"; await env.nodes.get("chk-unit").dispatch("input");
  await env.run("prepareCheckSubmit()");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks/validate"));
  env.replies.push({ ok: true, status: "ready", fields: validFields, missing: [] });
  await followup.querySelector("button").click();
  assert.deepEqual(env.calls.at(-1).body.context.answers, [{ field: "params.unit", text: question.options[0].value }]);
  assert.equal(env.calls.at(-1).body.context.draft.fields["params.unit"], "nginx");
  assert.equal(env.nodes.get("chk-unit").value, "nginx");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
});

test("semantic questions without candidates accept text and reject an unanswered continuation", async () => {
  const env = environment(); await ready(env);
  env.nodes.get("chk-assist-input").value = "观察服务是否正常工作";
  env.replies.push({ ...semanticDraft, missing: [{ field: "clarification.success_criterion", mode: "answer", label: "成功标准", question: "你希望用什么现象判断它工作正常？" }] });
  await env.run("runAssist('checks')");
  const followup = env.nodes.get("chk-assist-followup"), input = followup.querySelector("input");
  await followup.querySelector("button").click();
  assert.equal(env.calls.filter((call) => call.url === "/api/assist/configure").length, 1);
  assert.ok(env.nodes.get("chk-assist-msg").textContent.includes("请先回答"));
  input.value = "这次先看它有没有运行，之后再加任务完成情况";
  env.replies.push({ ok: true, status: "ready", fields: validFields, missing: [] });
  await followup.querySelector("button").click();
  assert.deepEqual(env.calls.at(-1).body.context.answers, [{ field: "clarification.success_criterion", text: input.value }]);
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
});

test("a new semantic question invalidates a previously open creation preview", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.replies.push({ ok: true, payload }); await env.run("prepareCheckSubmit()");
  const confirm = env.nodes.get("modal-body").querySelectorAll("button")[1];
  env.nodes.get("chk-assist-input").value = "再确认一下我说的组件";
  env.replies.push({ ...semanticDraft, fields: validFields }); await env.run("runAssist('checks')");
  await confirm.click();
  assert.ok(env.nodes.get("modal-body").textContent.includes("表单已修改"));
  assert.ok(!env.calls.some((call) => call.url === "/api/checks"));
});

test("normal messages use labels while raw diagnostics stay collapsed", async () => {
  const env = environment(); await ready(env);
  env.run("renderAssistResult('checks', " + JSON.stringify({ fields: validFields, defaulted: ["interval_sec"], inferred_detail: [{ field: "params.unit", reason: "根据应用描述推断，需要核对。" }], missing: [], diagnostics: { raw: "model internals" } }) + ")");
  const text = env.nodes.get("chk-assist-msg").textContent;
  assert.ok(text.includes("服务名")); assert.ok(text.includes("间隔秒"));
  assert.ok(!text.includes("params.unit")); assert.ok(!text.includes("interval_sec"));
  assert.equal(env.nodes.get("chk-assist-debug").open, undefined);
  assert.ok(env.nodes.get("chk-assist-debug").textContent.includes("model internals"));
});

test("failed AI validation explains actual fields without applying a failed draft", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.run("assistState.checks.response = {ok:true,status:'ready',fields:" + JSON.stringify(validFields) + "}");
  env.nodes.get("chk-assist-input").value = "监控应用的运行情况";
  env.replies.push({
    ok: false, error: "invalid_model_fields", status: "failed",
    message: "AI 生成的配置未通过表单校验，请重试或根据提示手动填写。",
    fields: { ...validFields, "params.unit": "wrong-service", name: "不可用草稿" },
    issues: [
      { field: "params.unit", label: "params.unit", code: "bad_format", message: "服务名格式不符合目标主机的要求，请确认实际服务名。" },
      { field: "kind", code: "bad_choice", message: "请选择表单提供的检查方式。" },
    ], diagnostics: { raw: "private model output" },
  });
  await env.run("runAssist('checks')");
  const message = env.nodes.get("chk-assist-msg").textContent;
  assert.ok(message.includes("服务名：服务名格式不符合目标主机的要求"));
  assert.ok(message.includes("检查类型：请选择表单提供的检查方式"));
  assert.ok(!/params\.unit|invalid_model_fields|bad_format|private model output|已准备/.test(message));
  assert.equal(env.nodes.get("chk-unit").value, "nginx");
  assert.equal(env.nodes.get("chk-name").value, validFields.name);
  assert.equal(env.run("assistState.checks.response"), null);
  assert.equal(env.nodes.get("chk-assist-go").disabled, false);
  assert.equal(env.nodes.get("chk-assist-debug").open, undefined);
  assert.ok(env.nodes.get("chk-assist-debug").textContent.includes("private model output"));
  assert.ok(!env.calls.some((call) => call.url === "/api/checks" || call.url === "/api/checks/validate"));
});

test("failure explanations deduplicate and bound details with a readable code fallback", async () => {
  const env = environment(); await ready(env);
  const issues = [
    { field: "name", code: "bad_name", message: "bad_name" },
    { field: "name", code: "bad_name", message: "bad_name" },
    ...Array.from({ length: 7 }, (_, index) => ({ field: "unknown_field_" + index, label: "unknown_field_" + index, message: "请核对内容 " + index + "。" + "说明".repeat(200) })),
  ];
  const lines = JSON.parse(env.run("JSON.stringify(assistFailureLines('checks', " + JSON.stringify({ ok: false, error: "invalid_model_fields", issues }) + "))"));
  assert.equal(lines.length, 7);
  assert.ok(lines[1].includes("检查名称不符合要求"));
  assert.ok(lines.at(-1).includes("还有 3 项需要核对"));
  assert.ok(lines.every((line) => line.length <= 300));
  assert.ok(!/bad_name|unknown_field_/.test(lines.join("")));
});

test("unsupported new intent clears stale ready draft and cannot create it", async () => {
  const env = environment(); await ready(env); setFields(env);
  env.nodes.get("chk-assist-input").value = "请直接添加不支持的监控方式";
  env.replies.push({ ok: true, status: "unsupported", fields: {}, missing: [], unsupported: { reason: "系统不支持这种探测方式。", alternatives: ["可检查已存在的服务状态。"] } });
  await env.run("runAssist('checks')");
  assert.equal(env.nodes.get("chk-kind").value, "");
  assert.equal(env.nodes.get("chk-unit").value, "");
  await env.run("prepareCheckSubmit()");
  assert.ok(!env.calls.some((call) => call.url === "/api/checks/validate" || call.url === "/api/checks"));
});

test("retired permission assistant cannot issue requests", async () => {
  const env = environment();
  await env.run("runAssist('permissions')");
  assert.equal(env.calls.length, 0);
});

test("saved check labels stay readable and execution details stay advanced", async () => {
  const env = environment(); await ready(env);
  assert.equal(env.run("checkHostLabel('romi')"), "Romi");
  assert.equal(env.run("checkFieldValueLabel('severity','warning')"), "警告");
  const type = env.run("checkTypeLabel(" + JSON.stringify(payload) + ")");
  assert.ok(type.includes("服务运行状态")); assert.ok(type.includes("nginx")); assert.ok(!type.includes("service"));
  assert.equal(env.run("checkStateLabel({enabled:true,last_state:'unknown'})"), "等待首次检查");
  assert.equal(env.run("checkStateLabel({enabled:true,last_state:'ok',last_at:123})"), "正常");
  const recent = env.run("checkRecentResult({last_at:123,last_detail:'state=active want=active'})");
  assert.equal(recent.children[0].textContent, "已执行时间");
  const advanced = recent.querySelector("details");
  assert.equal(advanced.open, undefined); assert.equal(advanced.querySelector("summary").textContent, "高级：执行详情");
  assert.equal(advanced.querySelector("pre").textContent, "state=active want=active");
});

(async () => {
  let failures = 0;
  for (const item of tests) {
    try { await item.run(); console.log("PASS " + item.name); }
    catch (error) { failures += 1; console.error("FAIL " + item.name, error); }
  }
  console.log(`${tests.length - failures}/${tests.length} UI regression checks passed`);
  process.exitCode = failures ? 1 : 0;
})();
