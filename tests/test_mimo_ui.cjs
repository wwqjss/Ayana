/* Execute the real MiMo settings callbacks with isolated, controlled API replies. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const harness = fs.readFileSync(path.join(__dirname, "test_security_ui.cjs"), "utf8").split("const tests = [];")[0];
const environment = vm.runInNewContext(harness + "\nenvironment;", {require, __dirname, console, URL, TextEncoder, Uint8Array});
const source = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const start = source.indexOf("async function openMimoAdmin("), end = source.indexOf("/* ---- 全局设置", start);
const cli = {ok:true,exists:true,version:"test"};
const config = (available = false, model = "owner/model-a") => ({
  ok:true,available,model:"selected/" + model,
  providers:[{name:"other",baseURL:"https://wrong.example.test/v1",key_set:true},{name:"selected",baseURL:"https://selected.example.test/v1",key_set:available}],
  verification:{verified:available,provider_id:"selected",model,base_url:"https://selected.example.test/v1"},
});
const deferred = () => {let resolve, reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};};
const make = (reply, admin = true) => {
  const env=environment(reply);
  env.run(`const state={user:{is_admin:${admin}}};`);
  env.run(source.slice(start,end));
  return env;
};
const open = async (env) => {await env.run("openMimoAdmin()");return env;};
const text = env => env.nodes.get("modal-body").textContent;
const inputs = env => env.nodes.get("modal-body").querySelectorAll("input");
const input = (env,id) => inputs(env).find(item=>item.id===id);
const button = (env,label) => env.nodes.get("modal-body").querySelectorAll("button").find(item=>item.textContent===label);
const posts = env => env.calls.filter(call=>call.body);
const defaultReply = call => call.url.endsWith("/status") ? cli : config();
const tests=[];
const test=(name,run)=>tests.push([name,run]);

test("selected provider supplies endpoint and full model ID, and saved keys stay blank", async()=>{
  const env=await open(make(call=>call.url.endsWith("/status")?cli:config(true)));
  assert.equal(input(env,"mimo-base-url").value,"https://selected.example.test/v1");
  assert.equal(input(env,"mimo-model").value,"owner/model-a");
  assert.equal(input(env,"mimo-api-key").value,"");
  assert.equal(input(env,"mimo-api-key").type,"password");
  assert.ok(text(env).includes("已保存配置：MiMoCode 可用"));
});

test("nonadministrators receive no provider mutation controls", async()=>{
  const env=await open(make(defaultReply,false));
  assert.equal(inputs(env).length,0);
  for(const label of ["测试连接","保存并验证","清除已保存密钥","启动","停止"])assert.equal(button(env,label),undefined);
});

test("double test and save clicks issue one request while verification is pending", async()=>{
  const pending=deferred();
  const env=await open(make(call=>call.url.endsWith("/test")?pending.promise:defaultReply(call)));
  input(env,"mimo-api-key").value="dummy-input-key";
  const first=button(env,"测试连接").click();
  await button(env,"测试连接").click();
  await button(env,"保存并验证").click();
  assert.equal(posts(env).length,1);
  assert.equal(posts(env)[0].body.provider_id,"selected");
  assert.equal(button(env,"测试连接").disabled,true);
  pending.resolve({ok:true,result:"success"});await first;
  assert.equal(button(env,"测试连接").disabled,false);
});

test("draft test success does not mark the saved configuration available", async()=>{
  const env=await open(make(call=>call.url.endsWith("/test")?{ok:true,result:"success"}:defaultReply(call)));
  await button(env,"测试连接").click();
  assert.ok(text(env).includes("当前输入连接成功"));
  assert.ok(text(env).includes("已保存配置尚未通过连接验证"));
  assert.equal(text(env).includes("已保存配置：MiMoCode 可用"),false);
});

test("failed saved-key retest refreshes the formerly available status", async()=>{
  let saved=config(true);
  const env=await open(make(call=>{
    if(call.url.endsWith("/test")){saved=config(false);return{ok:false,result:"auth_failed",message:"认证失败"};}
    return call.url.endsWith("/status")?cli:saved;
  }));
  await button(env,"测试连接").click();
  assert.equal(text(env).includes("已保存配置：MiMoCode 可用"),false);
  assert.ok(text(env).includes("认证失败"));
});

test("editing a field invalidates a pending test response", async()=>{
  const pending=deferred();
  const env=await open(make(call=>call.url.endsWith("/test")?pending.promise:defaultReply(call)));
  const operation=button(env,"测试连接").click();
  input(env,"mimo-model").value="different-model";await input(env,"mimo-model").dispatch("input");
  pending.resolve({ok:true,result:"success"});await operation;
  assert.ok(text(env).includes("当前输入已变化"));
  assert.equal(text(env).includes("当前输入连接成功"),false);
});

test("save verifies once, refreshes saved status, and clears only the submitted key", async()=>{
  let saved=config(false);
  const pending=deferred();
  const env=await open(make(call=>{
    if(call.body&&call.url==="/api/mimo/provider"){saved=config(true);return pending.promise;}
    return call.url.endsWith("/status")?cli:saved;
  }));
  input(env,"mimo-api-key").value="dummy-submitted-key";
  const operation=button(env,"保存并验证").click();
  await button(env,"保存并验证").click();
  assert.equal(posts(env).length,1);
  assert.equal(posts(env)[0].body.test,true);
  pending.resolve({ok:true,saved:true,verified:true});await operation;
  assert.equal(input(env,"mimo-api-key").value,"");
  assert.ok(text(env).includes("已保存配置：MiMoCode 可用"));
  assert.ok(text(env).includes("配置已保存，连接验证通过"));
  assert.equal(text(env).includes("dummy-submitted-key"),false);
});

test("late save completion does not clear a newly edited key", async()=>{
  const pending=deferred();
  const env=await open(make(call=>call.body&&call.url==="/api/mimo/provider"?pending.promise:defaultReply(call)));
  input(env,"mimo-api-key").value="old-dummy-key";
  const operation=button(env,"保存并验证").click();
  input(env,"mimo-api-key").value="new-dummy-key";await input(env,"mimo-api-key").dispatch("input");
  pending.resolve({ok:true,saved:true,verified:true});await operation;
  assert.equal(input(env,"mimo-api-key").value,"new-dummy-key");
  assert.ok(text(env).includes("当前输入已变化"));
});

test("network rejection exits progress and reenables configuration controls", async()=>{
  const env=await open(make(call=>call.url.endsWith("/test")?Promise.reject(new Error("network")):defaultReply(call)));
  await button(env,"测试连接").click();
  assert.ok(text(env).includes("请求未完成，请重试"));
  assert.equal(text(env).includes("正在真实调用模型…"),false);
  assert.equal(button(env,"测试连接").disabled,false);
  assert.equal(button(env,"保存并验证").disabled,false);
});

test("failed status refresh does not retain a stale available badge", async()=>{
  let refresh=false;
  const env=await open(make(call=>{
    if(call.url.endsWith("/test")){refresh=true;return{ok:true,result:"success"};}
    if(call.url==="/api/mimo/provider"&&refresh)return Promise.reject(new Error("offline"));
    return call.url.endsWith("/status")?cli:config(true);
  }));
  await button(env,"测试连接").click();
  assert.equal(text(env).includes("已保存配置：MiMoCode 可用"),false);
  assert.ok(text(env).includes("保存状态暂时无法确认"));
});

test("canceling key clearance sends no mutation", async()=>{
  const env=await open(make(defaultReply));env.run("confirm=()=>false;");
  await button(env,"清除已保存密钥").click();
  assert.equal(posts(env).length,0);
});

test("clearing the selected provider refreshes availability and the saved-key label", async()=>{
  let saved=config(true);
  const env=await open(make(call=>{
    if(call.url.endsWith("/clear")){saved=config(false);return{ok:true,verified:false};}
    return call.url.endsWith("/status")?cli:saved;
  }));
  input(env,"mimo-api-key").value="dummy-unsaved-key";
  await button(env,"清除已保存密钥").click();
  assert.equal(posts(env)[0].body.provider_id,"selected");
  assert.equal(input(env,"mimo-api-key").value,"");
  assert.ok(text(env).includes("已清除密钥"));
  assert.equal(text(env).includes("已保存配置：MiMoCode 可用"),false);
  assert.equal(text(env).includes("API Key（已保存"),false);
});

test("failed clear stays an error and does not claim the key was removed", async()=>{
  const env=await open(make(call=>call.url.endsWith("/clear")?{ok:false,message:"配置未能保存"}:defaultReply(call)));
  await button(env,"清除已保存密钥").click();
  assert.ok(text(env).includes("配置未能保存"));
  assert.equal(text(env).includes("已清除密钥，验证状态已重置"),false);
});

test("initial network failure produces a readable settings error", async()=>{
  const env=await open(make(()=>Promise.reject(new Error("offline"))));
  assert.ok(text(env).includes("配置加载未完成，请重试"));
});

test("a late settings load cannot replace a newer opening", async()=>{
  const old=deferred();let loads=0;
  const env=make(call=>call.url.endsWith("/status")?cli:++loads===1?old.promise:config(false,"new-model"));
  const first=env.run("openMimoAdmin()");
  await env.run("openMimoAdmin()");
  old.resolve(config(true,"old-model"));await first;
  assert.equal(input(env,"mimo-model").value,"new-model");
});

test("a response after another modal opens cannot alter that modal", async()=>{
  const pending=deferred();
  const env=await open(make(call=>call.url.endsWith("/test")?pending.promise:defaultReply(call)));
  const operation=button(env,"测试连接").click();
  env.run('showModal("Other",[el("p",{text:"other content"})]);');
  pending.resolve({ok:true,result:"success"});await operation;
  assert.equal(text(env),"other content");
});

test("process and usage network failures stay visible instead of rejecting callbacks", async()=>{
  const env=await open(make(call=>call.url.endsWith("/start")||call.url.endsWith("/stats")?Promise.reject(new Error("offline")):defaultReply(call)));
  await button(env,"启动").click();assert.ok(text(env).includes("请求未完成，请重试"));
  await button(env,"刷新用量").click();assert.ok(text(env).includes("用量加载未完成，请重试"));
});

(async()=>{for(const [name,run] of tests){await run();console.log("PASS "+name);}console.log(`${tests.length}/${tests.length} MiMo settings UI checks passed`);})().catch(error=>{console.error(error);process.exitCode=1;});
