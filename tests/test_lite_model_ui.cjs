/* Exercise the real lightweight model form; no live model requests. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const harness = fs.readFileSync(path.join(__dirname, "test_security_ui.cjs"), "utf8").split("const tests = [];")[0];
const environment = vm.runInNewContext(harness + "\nenvironment;", {require, __dirname, console, URL, TextEncoder, Uint8Array});
const app = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const source = app.slice(app.indexOf("async function openLiteAgentSettings("), app.indexOf("/* ---- 全局设置", app.indexOf("async function openLiteAgentSettings(")));
const saved = {ok:true, agent_mode:"lite", llm_base_url:"https://models.example.test/v1", llm_model:"test-model", llm_api_key_set:true};
const make = reply => {const env=environment(reply || (()=>saved));env.run('const state={agentMode:"lite",user:{is_admin:true}};');env.run(source);return env;};
const open = async env => {await env.run("openMimoAdmin()");return env;};
const root = env => env.nodes.get("modal-body");
const input = (env,id) => root(env).querySelectorAll("input").find(node=>node.id===id);
const button = (env,text) => root(env).querySelectorAll("button").find(node=>node.textContent===text);
const tests=[];
const test=(name,run)=>tests.push([name,run]);

test("lite model settings load no MiMo endpoints and never refill an existing secret",async()=>{
  const env=await open(make());
  assert.deepEqual(Array.from(env.calls,call=>call.url),["/api/settings/global"]);
  assert.equal(input(env,"lite-api-key").value,"");
  assert.equal(input(env,"lite-api-key").type,"password");
  assert.ok(root(env).textContent.includes("不需要 MiMoCode"));
  for(const label of ["启动","停止","刷新用量","清除已保存密钥"])assert.equal(button(env,label),undefined);
});

test("lite test explicitly probes without saving and save uses the existing global settings",async()=>{
  const env=await open(make(call=>call.body?{ok:true}:saved));
  input(env,"lite-api-key").value="test-new-key";
  await button(env,"测试连接").click();
  assert.equal(env.calls.at(-1).url,"/api/settings/model/test");
  assert.equal(input(env,"lite-api-key").value,"test-new-key");
  assert.ok(root(env).textContent.includes("尚未保存"));
  await button(env,"保存模型配置").click();
  assert.equal(env.calls.at(-1).url,"/api/settings/global");
  assert.equal(env.calls.at(-1).body.llm_api_key,"test-new-key");
  assert.equal(input(env,"lite-api-key").value,"");
  assert.ok(root(env).textContent.includes("下次后台任务"));
});

test("lite configuration prevents duplicate submissions and retains failed input",async()=>{
  let resolve;const pending=new Promise(yes=>{resolve=yes;});
  const env=await open(make(call=>call.body?pending:saved));
  input(env,"lite-api-key").value="test-retain-key";
  const first=button(env,"保存模型配置").click();
  await button(env,"测试连接").click();
  assert.equal(env.calls.filter(call=>call.body).length,1);
  assert.equal(input(env,"lite-base-url").disabled,true);
  resolve({ok:false,message:"validation failed"});await first;
  assert.equal(input(env,"lite-api-key").value,"test-retain-key");
  assert.equal(input(env,"lite-base-url").disabled,false);
  assert.ok(root(env).textContent.includes("validation failed"));
});

(async()=>{for(const [name,run] of tests){await run();console.log("PASS "+name);}console.log(`${tests.length}/${tests.length} lite model UI tests passed`);})().catch(error=>{console.error(error);process.exitCode=1;});
