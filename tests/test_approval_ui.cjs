/* Exercise incident approval buttons with the production UI callbacks. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const harness = fs.readFileSync(path.join(__dirname, "test_security_ui.cjs"), "utf8").split("const tests = [];")[0];
const environment = vm.runInNewContext(harness + "\nenvironment;", { require, __dirname, console, URL, TextEncoder, Uint8Array });
const detail = { ok: true, incident: { status: "open", actions: [{ id: "act1", state: "proposed", capability: "service.restart", object_id: "frps" }] } };
const setup = (reply) => {
  const env = environment(reply);
  env.run('const ZH_CAP = {"service.restart":"重启服务"}; const zh = (value) => value;');
  return env;
};
const buttons = (env) => env.nodes.get("modal-body").querySelectorAll("button");
const find = (env, label) => buttons(env).find((button) => button.textContent === label);

(async () => {
  let passed = 0;
  for (const [label, decision] of [["执行一次", "execute_once"], ["不执行", "reject"]]) {
    const env = setup(({ body }) => body ? { ok: true } : detail);
    await env.run('openIncidentDetail("inc1")');
    env.promptReplies.push("", "");
    await find(env, label).click();
    const posted = env.calls.filter((call) => call.body);
    assert.equal(posted.length, 1);
    assert.equal(posted[0].url, "/api/actions/act1/decision");
    assert.equal(posted[0].body.decision, decision);
    assert.equal(env.calls.filter((call) => !call.body).length, 2);
    console.log(`PASS ${label} targets one explicit action and refreshes incident state`); passed++;
  }

  {
    const env = setup(() => detail);
    await env.run('openIncidentDetail("inc1")');
    assert.equal(find(env, "永久允许执行"), undefined);
    assert.deepEqual(Array.from(buttons(env)).slice(0, 2).map((button) => button.textContent), ["执行一次", "不执行"]);
    console.log("PASS only per-operation approval choices are offered"); passed++;
  }
  {
    const env = setup(() => ({ ...detail, disposition: { authority: { access_mode: "readonly", approval_mode: "automatic" } } }));
    await env.run('openIncidentDetail("inc1")');
    assert.ok(env.nodes.get("modal-body").textContent.includes("当前 Agent 会话：只读 · 自动执行"));
    assert.ok(!env.nodes.get("modal-body").textContent.includes("命中规则"));
    console.log("PASS incident context displays the actual session permission instead of legacy rules"); passed++;
  }

  for (const responses of [[null], ["", null]]) {
    const env = setup(() => detail); await env.run('openIncidentDetail("inc1")');
    env.promptReplies.push(...responses);
    await find(env, "执行一次").click();
    assert.equal(env.calls.length, 1);
    console.log("PASS canceled authorization or TOTP prompt submits no decision"); passed++;
  }

  {
    let finish;
    const waiting = new Promise((resolve) => { finish = resolve; });
    const env = setup(({ body }) => body ? waiting : detail);
    await env.run('openIncidentDetail("inc1")');
    env.promptReplies.push("", "");
    const first = find(env, "执行一次").click();
    assert.equal(find(env, "不执行").disabled, true);
    await find(env, "不执行").click();
    assert.equal(env.calls.filter((call) => call.body).length, 1);
    finish({ ok: true }); await first;
    console.log("PASS concurrent choices cannot create a second in-flight decision"); passed++;
  }

  {
    const env = setup(() => ({ ok: true, incident: { actions: [{ id: "act1", state: "cancelled" }] } }));
    await env.run('openIncidentDetail("inc1")');
    assert.equal(find(env, "执行一次"), undefined);
    assert.equal(find(env, "永久允许执行"), undefined);
    console.log("PASS completed or canceled actions offer no authorization buttons"); passed++;
  }
  {
    const approved = { ok: true, incident: { actions: [{ id: "act1", state: "approved" }] } };
    const env = setup(({ body }) => body ? { ok: true } : approved);
    await env.run('openIncidentDetail("inc1")');
    assert.equal(find(env, "执行一次"), undefined);
    env.promptReplies.push("", "123456");
    await find(env, "继续执行").click();
    assert.equal(env.calls[1].url, "/api/actions/act1/execute");
    assert.equal(env.calls[1].body.totp, "123456");
    assert.equal(Object.keys(env.calls[1].body).length, 1);
    console.log("PASS an approved but undispatched action can resume through the execution gate"); passed++;
  }
  console.log(`${passed}/${passed} approval UI checks passed`);
})().catch((error) => { console.error(error); process.exitCode = 1; });
