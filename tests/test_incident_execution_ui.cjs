/* Current host.exec facts and recovery evidence stay separate from retired dispatcher history. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname,"../ayana/static/app.js"),"utf8");
class Element {
  constructor(tag) { this.tagName=tag.toUpperCase();this.children=[];this._text=""; }
  set textContent(value) { this._text=String(value);this.children=[]; }
  get textContent() { return this._text+this.children.map(child=>child.textContent).join(""); }
  appendChild(child) { this.children.push(child);return child; }
  setAttribute(key,value) { this[key]=value; }
  addEventListener() {}
}
const context=vm.createContext({
  document:{createElement:tag=>new Element(tag),createTextNode:text=>{const node=new Element("text");node.textContent=text;return node;}},
  badge:(text,cls)=>{const node=new Element("span");node.textContent=text;node.className=cls;return node;},
  fmtTime:value=>"time "+value,zh:value=>value,ZH_CAP:{},
});
for(const [start,end] of [["function el(","async function api("],["function loopOutcome(","async function renderIncidents("]]) {
  const a=source.indexOf(start),b=source.indexOf(end,a);assert.ok(a>=0&&b>a);vm.runInContext(source.slice(a,b),context);
}
function view(incident) { context.incident=incident;return vm.runInContext("renderLoopSteps(loopOutcome(incident),incident)",context); }
function outcome(incident) { context.incident=incident;return vm.runInContext("loopOutcome(incident)",context); }
const evidence={confirmed:true,generation:2,recorded_at:20,evidence:{verdict:"green",generation:2,checks:[{contract:"check.service",check_id:"nginx",sample_at:19,verdict:"green"}]}};
const base={id:"inc",title:"Nginx",asset_id:"romi",object_id:"nginx",generation:2,status:"resolved",outcome:"recovered"};
const tests=[];const test=(name,run)=>tests.push({name,run});
test("resolved without a current recovery proof never claims recovered",()=>{
  assert.equal(outcome(base).recovered,false);
  assert.equal(outcome({...base,outcome:"",recovery:evidence}).recovered,false);
  assert.equal(outcome({...base,recovery:{...evidence,generation:1}}).recovered,false);
  assert.ok(view(base).textContent.includes("恢复证据待核对"));
});
test("current host execution and recovery evidence replace obsolete no-action claims",()=>{
  const rendered=view({...base,recovery:evidence,host_exec:{generation:2,operations:[{id:"write",generation:2,status:"done",command:"systemctl start nginx",account_group:"ops",account:"operator"}]}}).textContent;
  assert.ok(rendered.includes("systemctl start nginx"));assert.ok(rendered.includes("ops"));
  assert.ok(rendered.includes("nginx"));assert.ok(rendered.includes("第 2 代"));
  assert.equal(rendered.includes("尚未处置"),false);assert.equal(rendered.includes("已恢复"),true);
});
test("retired need-human history cannot override current recovery or native interruption",()=>{
  const incident={...base,recovery:evidence,need_human:1,need_human_reason:"old blocker",
    native_task:{task_state:"interrupted",task_state_label:"任务已中断，等待恢复"},
    legacy_loop:{retired:true,active:false,snapshot:{generation:1,status:"need_human",stop_reason:"unsupported_verification_profile"}}};
  const result=outcome(incident);assert.equal(result.needHuman,false);assert.equal(result.recovered,true);
  const rendered=view(incident).textContent;
  assert.ok(rendered.includes("任务已中断"));assert.ok(rendered.includes("已恢复"));
  assert.ok(rendered.includes("已退役"));assert.ok(rendered.includes("unsupported_verification_profile"));
});
test("unscoped or old-generation operation records cannot appear as current execution",()=>{
  const rendered=view({...base,status:"open",outcome:"",host_exec:{generation:2,operations:[{generation:1,command:"old-command"},{command:"unscoped-command"}]}}).textContent;
  assert.equal(rendered.includes("old-command"),false);assert.equal(rendered.includes("unscoped-command"),false);
  assert.ok(rendered.includes("暂无本代执行记录"));
});
let failures=0;for(const item of tests){try{item.run();console.log("PASS "+item.name);}catch(error){failures++;console.error("FAIL "+item.name,error);}}
console.log(`${tests.length-failures}/${tests.length} incident execution UI checks passed`);process.exitCode=failures?1:0;
