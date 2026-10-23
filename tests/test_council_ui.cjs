/* Exercise the production council UI and independent role configuration. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const harness = fs.readFileSync(path.join(__dirname, "test_security_ui.cjs"), "utf8").split("const tests = [];")[0];
const environment = vm.runInNewContext(harness + "\nenvironment;", { require, __dirname, console, URL, TextEncoder, Uint8Array });
const source = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const settingsStart = source.indexOf("async function openAutonomySettings(");
const settingsEnd = source.indexOf("/* ---- 全局设置", settingsStart);
const setup = (reply, admin = true) => {
  const env = environment(reply);
  env.run(`const state = {user:{is_admin:${admin}}};`);
  env.run(source.slice(settingsStart, settingsEnd));
  return env;
};
const content = (env) => env.nodes.get("modal-body").textContent;
const buttons = (env) => env.nodes.get("modal-body").querySelectorAll("button");
const find = (env, label) => buttons(env).find((button) => button.textContent === label);
const labels = (env, label) => env.nodes.get("modal-body").querySelectorAll("label").filter((node) => node.textContent.startsWith(label)).map((node) => node.querySelector("input"));
const config = { enabled: false, budget_cny: 100, roles: Object.fromEntries(["planner", "reviewer_kimi", "reviewer_deepseek"].map((role) => [role, {base_url:"https://api.example.com/v1",model:role,key_configured:true,account_verified:false}])) };
const plans = [{id:"plan1",version:1,generation:2,goal_id:"goal1",asset_id:"nerv",object_id:"frps",state:"vetoed",plan:{repair_goal:"恢复 frps",rationale:"服务不活跃",steps:[{capability:"service.start",params:{unit:"frps"}}]},reviews:[{role:"reviewer_kimi",approve:true,reason:"证据充分"},{role:"reviewer_deepseek",approve:false,reason:"缺少端口证据",missing_evidence:["端口占用"],suggested_revision:"先查端口"}],ballot:{decision:"vetoed",reason:"委员否决"}}];
const detail = (council) => ({ok:true,incident:{},council});
const tests = [];
const test = (name, run) => tests.push([name, run]);

test("incident shows independent full reviews, veto reasons and immutable plan history", async () => {
  const env = setup(() => detail({phase:"reviewing",plans}));
  await env.run('openIncidentDetail("inc1")');
  assert.ok(content(env).includes("接奏 → 调查 → 拟旨 → 会审"));
  for (const expected of ["门下省 A · Kimi：同意", "门下省 B · DeepSeek：否决", "缺少端口证据", "缺失证据：端口占用", "修改建议：先查端口", "投票箱：封驳", "不可变方案版本"]) assert.ok(content(env).includes(expected), expected);
  assert.equal(buttons(env).some((button) => /执行|批准/.test(button.textContent)), false);
});

test("missing reviewer opinion cannot display ballot approval", async () => {
  const env = setup(() => detail({phase:"reviewing",plans:[{...plans[0],reviews:[plans[0].reviews[0]],ballot:null}]}));
  await env.run('openIncidentDetail("inc1")');
  assert.ok(content(env).includes("门下省 B · DeepSeek：等待审议"));
  assert.equal(content(env).includes("投票箱：准奏"), false);
});

test("draft blocked by policy is visible without implying execution authority", async () => {
  const env = setup(() => detail({phase:"manual",draft:{rationale:"等待明确权限",steps:[{capability:"service.reload"}]}}));
  await env.run('openIncidentDetail("inc1")');
  assert.ok(content(env).includes("当前拟案 · 尚不代表获得执行授权"));
  assert.ok(content(env).includes("等待明确权限"));
  assert.equal(content(env).includes("投票箱：准奏"),false);
});

test("old generation manual barrier cannot offer a current adjudication button", async () => {
  const env = setup(() => detail({current_generation:2,manual_required:false,
    goals:[{id:"old-goal",generation:1,manual_required:true}]}));
  await env.run('openIncidentDetail("inc1")');
  assert.equal(find(env,"允许此目标重新拟案"),undefined);
});

test("reviewed council Actions never expose ordinary manual approval or resume buttons", async () => {
  for (const state of ["proposed", "approved"]) {
    const env = setup(() => ({ok:true,incident:{actions:[{id:"action1",state,mode:"reviewed",council_grant_id:"grant1",capability:"service.start"}]},council:{plans}}));
    env.run('const ZH_CAP = {}; const zh = (value) => value;');
    await env.run('openIncidentDetail("inc1")');
    for (const label of ["执行一次", "永久允许执行", "继续执行", "不执行"]) assert.equal(find(env,label),undefined);
  }
});

test("unconfigured service and unavailable service do not invent recovery success", async () => {
  for (const council of [{enabled:false,status:"disabled"},{status:"unavailable",error:"offline"}]) {
    const env = setup(() => detail(council)); await env.run('openIncidentDetail("inc1")');
    assert.ok(/尚未启用|暂时不可用/.test(content(env)));
    assert.equal(content(env).includes("投票箱：准奏"), false);
  }
});

test("unknown usage stays unknown rather than showing zero as complete cost", async () => {
  const env = setup(() => detail({usage:{overall:{cost_cny:0,complete:false,input_tokens:20,output_tokens:4}}}));
  await env.run('openIncidentDetail("inc1")');
  assert.ok(content(env).includes("本事件模型费用：未知 · 输入 Token：20 · 输出 Token：4"));
});

test("read-only users see manual adjudication without a write button", async () => {
  const env = setup(() => detail({manual_required:true,goals:[{id:"goal1",manual_required:true,repair_goal:"恢复frps",consecutive_vetoes:3}]}), false);
  await env.run('openIncidentDetail("inc1")');
  assert.ok(content(env).includes("等待人工裁决"));
  assert.equal(find(env,"允许此目标重新拟案"), undefined);
});

test("manual decision targets one exact goal and sends no approve or execution flags", async () => {
  const council = {manual_required:true,goals:[{id:"goal1",manual_required:true}]};
  const env = setup(({body}) => body ? {ok:true} : detail(council));
  await env.run('openIncidentDetail("inc1")'); env.promptReplies.push("123456");
  await find(env,"允许此目标重新拟案").click();
  const writes = env.calls.filter((call) => call.body);
  assert.equal(writes.length,1);
  assert.equal(writes[0].url,"/api/incidents/inc1/council/review");
  assert.equal(JSON.stringify(writes[0].body),' {"goal_id":"goal1","totp":"123456"}'.trim());
});

test("canceling manual TOTP prompt sends no write request", async () => {
  const env = setup(() => detail({manual_required:true,goals:[{id:"goal1",manual_required:true}]}));
  await env.run('openIncidentDetail("inc1")'); env.promptReplies.push(null);
  await find(env,"允许此目标重新拟案").click();
  assert.equal(env.calls.filter((call) => call.body).length,0);
});

test("manual failure stays visible and allows retry without claiming adjudication success", async () => {
  const env = setup(({body}) => body ? {ok:false,error:"goal_generation_stale"} : detail({manual_required:true,goals:[{id:"goal1",manual_required:true}]}));
  await env.run('openIncidentDetail("inc1")'); env.promptReplies.push("");
  await find(env,"允许此目标重新拟案").click();
  assert.ok(content(env).includes("goal_generation_stale"));
  assert.equal(find(env,"允许此目标重新拟案").disabled,false);
});

test("role settings expose no saved key value and distinguish unverified accounts", async () => {
  const env = setup(({url}) => url.endsWith("/usage") ? {ok:true,usage:{}} : {ok:true,config});
  await env.run("openAutonomySettings()");
  assert.equal(labels(env,"独立 API Key").length,3);
  assert.ok(labels(env,"独立 API Key").every((input) => input.value === ""));
  assert.equal(content(env).split("该账户与模型尚未验证").length - 1,3);
  assert.ok(content(env).includes("不能填入 MiMo Token Plan Key"));
});

test("save keeps independent role keys write-only, unknown prices null, and clears entered keys", async () => {
  const env = setup(({url,body}) => body ? {ok:true,config} : url.endsWith("/usage") ? {ok:true,usage:{}} : {ok:true,config});
  await env.run("openAutonomySettings()");
  labels(env,"独立 API Key")[0].value = "new-planner-secret";
  labels(env,"清除此角色")[1].checked = true;
  env.promptReplies.push(""); await find(env,"保存 Agent 配置").click();
  const posted = env.calls.find((call) => call.body);
  assert.equal(posted.url,"/api/autonomy/providers");
  assert.equal(posted.body.roles.planner.api_key,"new-planner-secret");
  assert.equal(posted.body.roles.reviewer_kimi.clear_api_key,true);
  assert.equal(posted.body.roles.reviewer_deepseek.api_key,undefined);
  assert.equal(posted.body.roles.planner.input_cny_per_million,null);
  assert.equal(labels(env,"独立 API Key")[0].value,"");
});

test("account verification probes only the explicit saved role and reports a rejected model", async () => {
  const env = setup(({url,body}) => body ? {ok:false,error:"model_not_available",result:{ok:false}} : url.endsWith("/usage") ? {ok:true,usage:{}} : {ok:true,config});
  await env.run("openAutonomySettings()"); env.promptReplies.push("123456");
  await buttons(env).filter((button) => button.textContent === "核验已保存的账户与模型")[1].click();
  const posted = env.calls.find((call) => call.body);
  assert.equal(posted.url,"/api/autonomy/providers/verify");
  assert.equal(posted.body.role,"reviewer_kimi");
  assert.equal(Object.hasOwn(posted.body,"api_key"),false);
  assert.ok(content(env).includes("该账户的模型列表不包含此模型"));
  assert.equal(content(env).includes("已核验：已保存的账户支持该模型"),false);
});

test("budget limits and unknown costs use registry totals without claiming actual account charges", async () => {
  const usage = {overall:{cost_cny:1,complete:false},budget:{budget_cny:100,remaining_cny:75,warning:true,exhausted:true,account_balance_cny:null}};
  const env = setup(({url}) => url.endsWith("/usage") ? {ok:true,usage} : {ok:true,config});
  await env.run("openAutonomySettings()");
  assert.ok(content(env).includes("已统计费用：未知"));
  assert.ok(content(env).includes("可用预算：¥75.0000"));
  assert.ok(content(env).includes("账户余额：未知"));
  assert.ok(content(env).includes("模型调用已熔断"));
});

(async () => {
  for (const [name, run] of tests) { await run(); console.log("PASS " + name); }
  console.log(`${tests.length}/${tests.length} council UI checks passed`);
})().catch((error) => { console.error(error); process.exitCode = 1; });
