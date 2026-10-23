/* Optional channel administrators: selection, manual IDs, clear and save failure. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const harness = fs.readFileSync(path.join(__dirname, "test_security_ui.cjs"), "utf8").split("const tests = [];")[0];
const environment = vm.runInNewContext(harness + "\nenvironment;", { require, __dirname, console, URL, TextEncoder, Uint8Array });
const source = fs.readFileSync(path.join(__dirname, "../ayana/static/app.js"), "utf8");
const start = source.indexOf("async function openAibotAdmins(");
const end = source.indexOf("async function loadNotifyChannels(", start);
const setup = (reply) => {
  const env = environment(reply);
  env.run(source.slice(start, end) + "\nasync function loadNotifyChannels() {};");
  return env;
};
const inputs = (env) => env.nodes.get("modal-body").querySelectorAll("input");
const save = (env) => env.nodes.get("modal-body").querySelectorAll("button").find((button) => button.textContent === "保存管理员");

(async () => {
  const empty = setup(({ body }) => body ? { ok: true } : { ok: true, users: ["alice"], selected: [] });
  await empty.run('openAibotAdmins({id:"channel1",name:"一号"})');
  assert.equal(inputs(empty)[0].checked, false);
  await save(empty).click();
  assert.equal(empty.calls[1].body.admin_user_ids.length, 0);
  console.log("PASS observed users are never automatically selected as administrators");

  const selected = setup(({ body }) => body ? { ok: true } : { ok: true, users: ["alice", "bob"], selected: ["alice"] });
  await selected.run('openAibotAdmins({id:"channel2",name:"二号"})');
  inputs(selected).at(-1).value = "carol,alice";
  await save(selected).click();
  assert.equal(selected.calls[1].url, "/api/notify/aibot/admins");
  assert.equal(selected.calls[1].body.id, "channel2");
  assert.equal(JSON.stringify(selected.calls[1].body.admin_user_ids), '["alice","carol"]');
  console.log("PASS selected and manual IDs save only to the requested channel");

  const clear = setup(({ body }) => body ? { ok: true } : { ok: true, users: [], selected: ["alice"] });
  await clear.run('openAibotAdmins({id:"channel3",name:"三号"})');
  inputs(clear)[0].checked = false;
  await save(clear).click();
  assert.equal(clear.calls[1].body.admin_user_ids.length, 0);
  console.log("PASS all saved administrators can be explicitly removed");

  const denied = setup(({ body }) => body ? { ok: false, detail: "没有保存权限" } : { ok: true, users: [], selected: [] });
  await denied.run('openAibotAdmins({id:"channel4",name:"四号"})');
  await save(denied).click();
  assert.equal(denied.nodes.get("modal").classList.contains("hidden"), false);
  assert.equal(save(denied).disabled, false);
  assert.ok(denied.nodes.get("modal-body").textContent.includes("没有保存权限"));
  console.log("PASS failed saves remain visible and can be retried");
  console.log("4/4 channel administrator UI checks passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
