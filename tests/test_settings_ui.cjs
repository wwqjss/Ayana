/* Run the real settings callbacks with isolated DOM and controlled API replies. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "ayana/static/settings.js"), "utf8");
const app = fs.readFileSync(path.join(root, "ayana/static/app.js"), "utf8");
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 24; i++) await Promise.resolve(); };

function environment(reply, options = {}) {
  const calls = [], confirmations = [], opened = [], modelCalls = [], documentEvents = new Map();
  let currentDocument;
  class Element {
    constructor(tag) {
      this.tagName = tag.toUpperCase(); this.children = []; this.parentElement = null;
      this.attributes = {}; this.listeners = {}; this.dataset = {}; this.style = {};
      this.className = ""; this.value = ""; this.checked = false; this.disabled = false;
      this.hidden = false; this._text = ""; this.scrollTop = 0;
      this.classList = {
        contains: name => this.className.split(/\s+/).includes(name),
        add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(" "); },
        remove: (...names) => { this.className = this.className.split(/\s+/).filter(name => !names.includes(name)).join(" "); },
        toggle: (name, force) => { const enabled = force === undefined ? !this.classList.contains(name) : force; if (enabled) this.classList.add(name); else this.classList.remove(name); return enabled; },
      };
    }
    set textContent(value) { if(this.tagName==="TEXTAREA")this.value=String(value); this._text = String(value); this.children.forEach(child => { child.parentElement = null; }); this.children = []; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(""); }
    set innerHTML(value) { this.textContent = ""; assert.equal(value, "", "settings harness expects dynamic content to use DOM nodes"); }
    get innerHTML() { return this.textContent; }
    get parentNode() { return this.parentElement; }
    get firstChild() { return this.children[0] || null; }
    get firstElementChild() { return this.firstChild; }
    get lastElementChild() { return this.children.at(-1) || null; }
    get nextSibling() { return this.parentElement?.children[this.parentElement.children.indexOf(this) + 1] || null; }
    get isConnected() { return currentDocument.body.contains(this); }
    get offsetParent() { return this.classList.contains("hidden") ? null : this.parentElement; }
    appendChild(child) { if (child.parentElement) child.remove(); child.parentElement = this; this.children.push(child); if(this.tagName==="SELECT" && this.children.length===1)this.value=child.value; return child; }
    append(...children) { children.forEach(child => this.appendChild(typeof child === "string" ? currentDocument.createTextNode(child) : child)); }
    prepend(...children) { children.reverse().forEach(child => this.insertBefore(child, this.firstChild)); }
    insertBefore(child, next) { if (child.parentElement) child.remove(); child.parentElement = this; const index = this.children.indexOf(next); this.children.splice(index < 0 ? this.children.length : index, 0, child); return child; }
    replaceChildren(...children) { this.textContent = ""; this.append(...children); }
    remove() { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(child => child !== this); this.parentElement = null; }
    contains(node) { return this === node || this.children.some(child => child.contains(node)); }
    setAttribute(name, value) {
      value = String(value); this.attributes[name] = value;
      if (name === "class") this.className = value;
      else if (name === "style") this.style.cssText = value;
      else if (name.startsWith("data-")) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, ch) => ch.toUpperCase())] = value;
      else if (name === "disabled") this.disabled = true;
      else this[name] = value;
    }
    getAttribute(name) { if (name === "class") return this.className; return this.attributes[name] ?? this[name] ?? null; }
    removeAttribute(name) { delete this.attributes[name]; if (name === "disabled") this.disabled = false; else delete this[name]; }
    hasAttribute(name) { return Object.hasOwn(this.attributes, name); }
    addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
    removeEventListener(type, callback) { this.listeners[type] = (this.listeners[type] || []).filter(item => item !== callback); }
    async dispatch(type, fields = {}) {
      const event = { type, target: this, currentTarget: this, preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; }, ...fields };
      const bubbles=["click","input","change","keydown","submit"].includes(type),route=[this];
      if(bubbles)for(let ancestor=this.parentElement;ancestor;ancestor=ancestor.parentElement)route.push(ancestor);
      for(const node of route){event.currentTarget=node;for(const callback of [...(node.listeners[type]||[])])await callback(event);if(event.stopped)break;}
      if(bubbles && !event.stopped)for(const callback of documentEvents.get(type)||[]){event.currentTarget=currentDocument;await callback(event);if(event.stopped)break;}
      return event;
    }
    async click() { if (!this.disabled) return this.dispatch("click"); }
    focus() { currentDocument.activeElement = this; }
    select() { this.selected = true; }
    scrollIntoView() {}
    getClientRects() { return this.closest(".hidden") ? [] : [{}]; }
    matches(selector) {
      selector = selector.trim(); if (!selector || selector === "*") return true;
      if (selector.includes(",")) return selector.split(",").some(part => this.matches(part));
      if (selector.includes(":not([disabled])")) { if (this.disabled) return false; selector = selector.replace(":not([disabled])", ""); }
      const attributes = [...selector.matchAll(/\[([^\]=]+)(?:=["']?([^\]"']*)["']?)?\]/g)];
      for (const [, name, expected] of attributes) {
        const actual = this.getAttribute(name); if (actual === null || actual === undefined) return false;
        if (expected !== undefined && String(actual) !== expected) return false;
      }
      selector = selector.replace(/\[[^\]]+\]/g, "");
      const ident = selector.match(/#([\w-]+)/); if (ident && this.id !== ident[1]) return false;
      const classes = [...selector.matchAll(/\.([\w-]+)/g)].map(match => match[1]);
      if (classes.some(name => !this.classList.contains(name))) return false;
      const tag = selector.match(/^[a-z][\w-]*/i); return !tag || this.tagName.toLowerCase() === tag[0].toLowerCase();
    }
    closest(selector) { return this.matches(selector) ? this : this.parentElement?.closest(selector) || null; }
    querySelectorAll(selector) {
      const alternatives = selector.split(",").map(part => part.trim());
      const result = [];
      const visit = node => {
        for (const child of node.children) {
          if (alternatives.some(part => {
            const pieces = part.replace(/\s*>\s*/g," > ").split(/\s+/); if (!child.matches(pieces.pop())) return false;
            let ancestor = child.parentElement;
            while (pieces.length) { let required = pieces.pop(); if(required===">") { required=pieces.pop(); if(!ancestor || !ancestor.matches(required))return false; } else { while (ancestor && !ancestor.matches(required)) ancestor = ancestor.parentElement; if(!ancestor)return false; } ancestor = ancestor.parentElement; }
            return true;
          })) result.push(child);
          visit(child);
        }
      };
      visit(this); return result;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  }
  const document = currentDocument = {
    body: new Element("body"), documentElement: new Element("html"), activeElement: null,
    createElement: tag => new Element(tag),
    createTextNode: text => { const node = new Element("text"); node.textContent = text; return node; },
    getElementById: id => document.body.querySelector("#" + id),
    querySelector: selector => document.body.querySelector(selector),
    querySelectorAll: selector => document.body.querySelectorAll(selector),
    addEventListener: (type, callback) => { if (!documentEvents.has(type)) documentEvents.set(type, []); documentEvents.get(type).push(callback); },
    removeEventListener: (type, callback) => documentEvents.set(type, (documentEvents.get(type) || []).filter(item => item !== callback)),
  };
  const add = (parent, tag, id, cls = "") => { const node = new Element(tag); node.id = id; node.className = cls; parent.appendChild(node); return node; };
  const account = add(document.body, "div", "account-container", "user-box");
  const accountButton = add(account, "button", "account-menu-btn"); add(accountButton, "span", "username");
  const accountMenu = add(account, "div", "account-menu", "hidden");
  for (const id of ["account-profile-btn", "chg-pw-btn", "totp-btn", "settings-btn", "logout-btn"]) add(accountMenu, "button", id).setAttribute("role","menuitem");
  const dialog = add(document.body, "div", "settings-dialog", "settings-dialog hidden");
  const window = add(dialog, "div", "settings-window");
  add(window, "h2", "settings-title").textContent = "设置";
  add(window, "nav", "settings-nav");
  add(window, "h2", "settings-section-title");
  add(window, "button", "settings-close");
  add(window, "div", "settings-content");
  add(window, "footer", "settings-actions");
  const modal = add(document.body, "div", "modal", "hidden");
  const modalCard=add(modal,"div","modal-card","modal-card");
  add(modalCard,"h3","modal-title"); add(modalCard,"div","modal-body");
  const modalActions=add(modalCard,"div","modal-actions","modal-actions");add(modalActions,"button","modal-close");
  add(document.body, "section", "main-view");
  add(document.body, "section", "login-view", "hidden"); add(document.body, "p", "login-error");
  const notifications = add(document.body, "div", "notify-sub-channels");
  const storage=add(document.body,"div","settings-storage","hidden");
  const notificationContent=add(storage,"div","settings-notification-content");
  add(notificationContent,"input","notify-name");add(notificationContent,"input","notify-hook-url").setAttribute("type","url");
  const notificationSecret=add(notificationContent,"input","notify-hook-token");notificationSecret.setAttribute("type","password");
  add(notificationContent,"div","notify-list");
  add(notifications,"button","notify-settings-open");
  const user = { username: "admin", user_id: 1, is_admin: true, totp_enabled: false, ...options.user };
  const globalReply = { ok:true,llm_base_url:"https://helper.example.test/v1",llm_model:"helper-model",llm_api_key_set:true,prometheus_url:"http://127.0.0.1:9090",alertmanager_url:"http://127.0.0.1:9093",prometheus_ok:true };
  const defaults = call => {
    if (call.url === "/api/me") return {ok:true,user,csrf_token:ctx.state.csrf};
    if (call.url === "/api/mimo/status") return {ok:true,exists:true,version:"0.1.15",unit:{configured:false}};
    if (call.url === "/api/mimo/provider") return {ok:true,available:true,model:"selected/current-model",providers:[{name:"selected",baseURL:"https://selected.example.test/v1",key_set:true}],verification:{verified:true,provider_id:"selected",model:"current-model",base_url:"https://selected.example.test/v1"}};
    if (call.url === "/api/settings/global") return globalReply;
    if (call.url.includes("/prompts")) return {ok:true,effect:"next_call",message:"下一次调用生效",items:[{key:"investigation",label:"调查提示词",current:{id:1,version:1,text:"Investigate carefully.",active:true},versions:[{id:1,version:1,text:"Investigate carefully.",active:true}]},{key:"decision",label:"处置提示词",current:{id:2,version:2,text:"Decide carefully.",active:true},versions:[]},{key:"constraints",label:"运维软约束",current:{id:3,version:3,text:"Stop when evidence is missing.",active:true},versions:[]}]};
    if (call.url.includes("/skills")) return {ok:true,items:[],roots:[],message:"发现不等于加载"};
    if (call.url.includes("/about")) return {ok:true,ayana_version:"0.8.0",project_url:"https://github.com/wwqjss/Ayana",mimocode_version:"0.1.15"};
    return {ok:true};
  };
  const ctx = {
    console, Promise, URL, TextEncoder, Uint8Array, Event: class { constructor(type, fields = {}) { this.type=type; Object.assign(this, fields); } },
    document, HTMLElement: Element, navigator: { clipboard:{ writeText:async value => { opened.push(["clipboard",value]); } } },
    location: { protocol:"https:",host:"ayana.test",hash:"" },
    setTimeout, clearTimeout, requestAnimationFrame: callback => callback(),
    confirm: text => { confirmations.push(text); return options.confirm ? options.confirm(text) : true; },
    api: async (url, options = {}) => { const call = {url,method:options.method || "GET",body:options.body ? JSON.parse(options.body) : null}; calls.push(call); const selected=reply ? reply(call) : undefined; return await (selected === undefined ? defaults(call) : selected); },
    $: id => document.getElementById(id), on:(id,type,callback)=>document.getElementById(id)?.addEventListener(type,callback),
    fmtTime: value => value ? "test time" : "—", VERSION:"0.8.0",
    state:{user,csrf:"csrf-first",tab:"overview"},
    openMimoAdmin:async (host, context) => { modelCalls.push({host,context}); if (host) { host.replaceChildren(); host.appendChild(new Element("p")); host.firstChild.textContent="MiMoCode connection form"; } },
    showLogin:() => { ctx.state.user=null; document.getElementById("login-view").classList.remove("hidden"); document.getElementById("main-view").classList.add("hidden"); },
    showPasswordChange:() => { opened.push(["password-page"]); },
    openAutonomySettings:()=>{opened.push(["legacy-history"]);},
    renderNotify:async()=>{},loadNotifyChannels:async()=>{},loadNotifyKinds:async()=>{},loadAibotStatus:async()=>{},fillNotifyMethods:()=>{},toggleNotifyKind:()=>{},
    __modelCall:(host,context)=>modelCalls.push({host,context}),
  };
  ctx.window={addEventListener:document.addEventListener,removeEventListener:document.removeEventListener,open:(...args)=>opened.push(args),QR:{encode:()=>"dummy-qr",toSvg:()=>""}};
  const context=vm.createContext(ctx);
  const elStart=app.indexOf("function el("),elEnd=app.indexOf("async function api(",elStart);
  vm.runInContext(app.slice(elStart,elEnd),context);
  const modalStart=app.indexOf("function showModal("),modalEnd=app.indexOf('on("modal-close"',modalStart);
  vm.runInContext(app.slice(modalStart,modalEnd),context);
  const modelStart=app.indexOf("async function openMimoAdmin("),modelEnd=app.indexOf("/* ---- 旧自治历史",modelStart);
  vm.runInContext(app.slice(modelStart,modelEnd),context);
  vm.runInContext("const realMimoAdmin=openMimoAdmin;openMimoAdmin=async(...args)=>{__modelCall(...args);return realMimoAdmin(...args);};",context);
  vm.runInContext(source,context);
  for(const id of ["settings-btn","chg-pw-btn"]) {
    const prefix='on("'+id+'", "click",';const start=app.indexOf(prefix);const end=app.indexOf("\n",start);
    if(start>=0)vm.runInContext(app.slice(start,end),context);
  }
  const logoutStart=app.indexOf('on("logout-btn", "click"'),logoutEnd=app.indexOf("/* ---- 双重验证",logoutStart);
  vm.runInContext(app.slice(logoutStart,logoutEnd),context);
  return {document,calls,confirmations,opened,modelCalls,context,run:code=>vm.runInContext(code,context),
          node:id=>document.getElementById(id),
          async documentEvent(type,target,fields={}) { const event={type,target,preventDefault(){this.defaultPrevented=true;},stopPropagation(){this.stopped=true;},...fields};for(const callback of documentEvents.get(type)||[])await callback(event);return event; },
          button(label,within="settings-content") { return document.getElementById(within)?.querySelectorAll("button").find(button=>button.textContent===label); },
          input(id,value) { const input=document.getElementById(id);assert.ok(input,"missing input "+id);input.value=value;return input.dispatch("input"); }};
}
const tests=[];
const test=(name,run)=>tests.push({name,run});

test("account menu opens by click and closes on outside click", async () => {
  const env=environment();
  await env.node("account-menu-btn").click();
  assert.equal(env.node("account-menu").classList.contains("hidden"),false);
  await env.documentEvent("click",env.document.body);
  assert.equal(env.node("account-menu").classList.contains("hidden"),true);
});

test("account menu supports Escape without opening settings", async () => {
  const env=environment();await env.node("account-menu-btn").click();
  await env.documentEvent("keydown",env.node("account-menu-btn"),{key:"Escape"});
  assert.equal(env.node("account-menu").classList.contains("hidden"),true);
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),true);
});

test("settings opens directly on the model form and stays in one window", async () => {
  const env=environment();await env.run("openSettings('model')");
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),false);
  assert.equal(env.node("settings-section-title").textContent,"模型");
  assert.equal(env.modelCalls.length,1);
  assert.equal(env.node("modal").classList.contains("hidden"),true);
  await env.run("openSettings('model')");
  assert.equal(env.document.querySelectorAll("#settings-dialog").length,1);
  assert.equal(env.document.querySelectorAll("#settings-section-title").length,1);
});

test("nonadministrators cannot open model or system controls", async () => {
  const env=environment(undefined,{user:{is_admin:false}});await env.run("openSettings('model')");
  assert.equal(env.modelCalls.length,0);
  const nav=env.node("settings-nav").textContent;
  assert.ok(nav.includes("个人资料"));
  assert.ok(nav.includes("双重验证"));
  for(const caption of ["模型","提示词","技能","系统连接"])assert.ok(!nav.includes(caption),caption);
  assert.equal(env.calls.filter(call=>call.url.includes("/mimo/provider")).length,0);
});

test("canceling a dirty section change preserves the current form", async () => {
  const env=environment();await env.run("openSettings('profile')");
  env.run("settingsState.dirty=true");
  await env.run("renderSettingsSection('about')");
  assert.equal(env.run("settingsState.page"),"profile");
  assert.equal(env.node("modal").classList.contains("hidden"),false);
  await env.button("继续编辑","modal-actions").click();
  assert.equal(env.run("settingsState.dirty"),true);
});

test("canceling dirty close keeps settings open and does not discard state", async () => {
  const env=environment();await env.run("openSettings('profile')");
  env.run("settingsState.dirty=true");await env.run("closeSettings()");
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),false);
  assert.equal(env.run("settingsState.dirty"),true);
  await env.button("继续编辑","modal-actions").click();
});

test("confirming dirty close clears settings content and returns focus", async () => {
  const env=environment();await env.run("openSettings('profile')");
  env.run("settingsState.dirty=true");await env.run("closeSettings()");
  await env.button("放弃修改","modal-actions").click();await flush();
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),true);
  assert.equal(env.node("settings-content").children.length,0);
  assert.equal(env.run("settingsState.dirty"),false);
});

test("a busy operation blocks section changes and ordinary close", async () => {
  const env=environment();await env.run("openSettings('profile')");
  env.run("settingsState.busy=true");
  await env.run("renderSettingsSection('about')");await env.run("closeSettings()");
  assert.equal(env.run("settingsState.page"),"profile");
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),false);
});

test("forced close can clean up an expired or logged-out session", async () => {
  const env=environment();await env.run("openSettings('profile')");
  env.run("settingsState.dirty=true;settingsState.busy=true");await env.run("closeSettings(true)");
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),true);
});

test("shared modal removes old footer actions before showing unrelated content", async () => {
  const env=environment();
  const start=app.indexOf("function showModal("),end=app.indexOf('on("modal-close"',start);
  assert.ok(start>=0 && end>start);
  vm.runInContext(app.slice(start,end),env.context);
  const footer=env.node("modal-actions");
  for(let i=0;i<3;i++) {
    const save=env.document.createElement("button");save.textContent="保存";footer.appendChild(save);
    env.run('showModal("Other",[el("p",{text:"New content"})])');
    assert.deepEqual(footer.children.map(node=>node.id),["modal-close"]);
  }
});

test("the actual model form uses the embedded host and never fills a saved secret", async () => {
  const env=environment();await env.run("openSettings('model')");
  assert.equal(env.node("mimo-model").value,"current-model");
  assert.equal(env.node("mimo-base-url").value,"https://selected.example.test/v1");
  assert.equal(env.node("mimo-api-key").value,"");
  assert.equal(env.node("mimo-api-key").type,"password");
  assert.equal(env.button("保存并验证","settings-actions")?.textContent,"保存并验证");
  assert.equal(env.node("modal").classList.contains("hidden"),true);
});

test("a late skills response cannot overwrite a different settings page", async () => {
  const pending=deferred();const env=environment(call=>call.url==="/api/settings/skills"?pending.promise:undefined);
  const old=env.run("openSettings('skills')");await flush();
  await env.run("renderSettingsSection('profile')");
  pending.resolve({ok:true,items:[{name:"obsolete skill",loaded:true}],roots:[]});await old;
  assert.equal(env.run("settingsState.page"),"profile");
  assert.ok(!env.node("settings-content").textContent.includes("obsolete skill"));
  assert.ok(env.node("profile-current-password"));
});

test("a late model config response cannot reopen a closed settings window", async () => {
  const pending=deferred();const env=environment(call=>call.url==="/api/mimo/provider"?pending.promise:undefined);
  const old=env.run("openSettings('model')");await flush();await env.run("closeSettings(true)");
  pending.resolve({ok:true,available:true,providers:[],verification:{}});await old;
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),true);
  assert.equal(env.node("settings-content").children.length,0);
  assert.equal(env.node("settings-actions").children.length,0);
});

test("changing a password preserves whitespace and logs out only after success", async () => {
  const env=environment(call=>call.url==="/api/password"?{ok:true}:undefined);await env.run("openSettings('profile')");
  await env.input("profile-current-password","  current password  ");
  await env.input("profile-new-password","  new password  ");await env.input("profile-confirm-password","  new password  ");
  await env.button("修改密码","settings-actions").click();
  const sent=env.calls.find(call=>call.url==="/api/password");
  assert.equal(sent.body.old_password,"  current password  ");assert.equal(sent.body.new_password,"  new password  ");
  assert.equal(env.run("state.user"),null);assert.equal(env.run("state.csrf"),"");
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),true);
  assert.equal(env.node("login-view").classList.contains("hidden"),false);
});

test("failed password changes keep the form and remain dirty", async () => {
  const env=environment(call=>call.url==="/api/password"?{ok:false,message:"当前密码错误"}:undefined);await env.run("openSettings('profile')");
  await env.input("profile-current-password","wrong password");await env.input("profile-new-password","new-password-123");await env.input("profile-confirm-password","new-password-123");
  await env.button("修改密码","settings-actions").click();
  assert.equal(env.run("state.user.username"),"admin");assert.equal(env.run("settingsState.dirty"),true);
  assert.equal(env.run("settingsState.busy"),false);assert.ok(env.node("settings-feedback").textContent.includes("当前密码错误"));
});

test("password validation prevents a short or mismatched password request", async () => {
  const env=environment();await env.run("openSettings('profile')");
  await env.input("profile-current-password","old");await env.input("profile-new-password","short");await env.input("profile-confirm-password","short");
  await env.button("修改密码","settings-actions").click();
  await env.input("profile-new-password","new-password-123");await env.input("profile-confirm-password","different-password");
  await env.button("修改密码","settings-actions").click();
  assert.equal(env.calls.filter(call=>call.url==="/api/password").length,0);
});

test("duplicate password clicks dispatch once and block navigation until completion", async () => {
  const pending=deferred();const env=environment(call=>call.url==="/api/password"?pending.promise:undefined);await env.run("openSettings('profile')");
  await env.input("profile-current-password","current-password");await env.input("profile-new-password","new-password-123");await env.input("profile-confirm-password","new-password-123");
  const save=env.button("修改密码","settings-actions"),first=save.click();await flush();await save.click();
  await env.run("renderSettingsSection('about')");await env.run("closeSettings()");
  assert.equal(env.run("settingsState.page"),"profile");assert.equal(env.run("settingsState.busy"),true);
  assert.equal(env.calls.filter(call=>call.url==="/api/password").length,1);
  pending.resolve({ok:false,message:"try later"});await first;
  assert.equal(env.run("settingsState.busy"),false);
});

test("first-login password requirements cannot be bypassed via settings", async () => {
  const env=environment(undefined,{user:{must_change_password:true}});await env.run("openSettings('model')");
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),true);
  assert.equal(env.modelCalls.length,0);assert.deepEqual(env.opened,[["password-page"]]);
});

test("OTP confirmation rotates CSRF and recovery codes are removed on exit", async () => {
  const env=environment(call=>call.url==="/api/totp/setup"?{ok:true,secret:"DUMMY-OTP-SECRET",otpauth:"otpauth://totp/dummy"}:call.url==="/api/totp/confirm"?{ok:true,csrf_token:"rotated-csrf",recovery_codes:["DUMMY-RECOVERY-ONE","DUMMY-RECOVERY-TWO"]}:undefined);
  await env.run("openSettings('security')");await env.button("绑定认证器","settings-actions").click();
  assert.ok(env.node("security-confirm-code"));
  await env.input("security-confirm-code","123456");await env.button("确认启用","settings-actions").click();
  assert.equal(env.run("state.csrf"),"rotated-csrf");assert.equal(env.run("state.user.totp_enabled"),true);
  assert.ok(env.node("security-recovery-codes").textContent.includes("DUMMY-RECOVERY-ONE"));
  assert.ok(!env.node("settings-content").textContent.includes("DUMMY-OTP-SECRET"));
  assert.equal(env.run("settingsState.dirty"),true);
  const acknowledged=env.node("security-recovery-saved");acknowledged.checked=true;await acknowledged.dispatch("change");
  await env.run("renderSettingsSection('profile')");
  assert.equal(env.node("security-recovery-codes"),null);
  await env.run("renderSettingsSection('security')");assert.ok(!env.node("settings-content").textContent.includes("DUMMY-RECOVERY-ONE"));
});

test("disabling OTP preserves password whitespace and adopts the new CSRF", async () => {
  const env=environment(call=>call.url==="/api/totp/disable"?{ok:true,csrf_token:"disabled-csrf"}:undefined,{user:{totp_enabled:true}});
  await env.run("openSettings('security')");await env.input("security-password","  actual password  ");await env.input("security-otp","654321");
  await env.button("关闭双重验证","settings-actions").click();
  const sent=env.calls.find(call=>call.url==="/api/totp/disable");assert.equal(sent.body.password,"  actual password  ");assert.equal(sent.body.totp,"654321");
  assert.equal(env.run("state.user.totp_enabled"),false);assert.equal(env.run("state.csrf"),"disabled-csrf");
  assert.equal(env.node("security-password").value,"");assert.equal(env.node("security-otp").value,"");
});

test("unknown skill loading state is never presented as successfully loaded", async () => {
  const env=environment(call=>call.url==="/api/settings/skills"?{ok:true,message:"实际目录发现",items:[{name:"unknown-skill",description:"test",loaded:null,status:"discovered",source:"MiMoCode",path:"/test/skill/SKILL.md"}],roots:[]}:undefined);
  await env.run("openSettings('skills')");
  const body=env.node("settings-content").textContent;assert.ok(body.includes("unknown-skill"));assert.ok(body.includes("加载状态待确认"));assert.ok(!body.includes("已确认加载"));
  assert.equal(env.calls.filter(call=>call.method!=="GET").length,0);
});

test("update checks only query the server and never install or open external content automatically", async () => {
  const env=environment(call=>call.url==="/api/settings/updates/check"?{ok:true,result:"available",update_available:true,message:"发现新版本",latest_version:"v0.9.0"}:undefined);
  await env.run("openSettings('about')");assert.equal(env.calls.filter(call=>call.url.includes("updates/check")).length,0);
  await env.button("检查更新","settings-actions").click();
  const mutations=env.calls.filter(call=>call.method!=="GET");assert.equal(mutations.length,1);assert.equal(mutations[0].url,"/api/settings/updates/check");
  assert.deepEqual(mutations[0].body,{});assert.equal(env.opened.length,0);assert.ok(env.node("settings-update-result").textContent.includes("发现新版本"));
});

test("an untrusted project URL cannot become an external project link", async () => {
  const env=environment(call=>call.url==="/api/settings/about"?{ok:true,ayana_version:"0.8.0",mimocode_version:"0.1.15",project_url:"javascript:alert('bad')"}:undefined);
  await env.run("openSettings('about')");
  const links=env.node("settings-content").querySelectorAll("a");assert.equal(links.length,1);assert.equal(links[0].href,"https://github.com/wwqjss/Ayana");
  assert.equal(links[0].rel,"noopener noreferrer");
});

test("prompt types show their own current content and dirty switching requires consent", async () => {
  const env=environment();await env.run("openSettings('prompts')");
  assert.equal(env.node("settings-prompt-text").value,"Investigate carefully.");
  await env.input("settings-prompt-text","unsaved investigation draft");
  await env.button("处置提示词").click();
  assert.equal(env.run("settingsState.promptKey"),"investigation");
  assert.equal(env.node("modal").classList.contains("hidden"),false);
  await env.button("继续编辑","modal-actions").click();
  assert.equal(env.node("settings-prompt-text").value,"unsaved investigation draft");
  await env.button("处置提示词").click();await env.button("放弃修改","modal-actions").click();await flush();
  assert.equal(env.run("settingsState.promptKey"),"decision");assert.equal(env.node("settings-prompt-text").value,"Decide carefully.");
  assert.equal(env.calls.filter(call=>call.method!=="GET").length,0);
});

test("saving a prompt preserves its exact text and only modifies the selected prompt", async () => {
  const env=environment();await env.run("openSettings('prompts')");await env.button("处置提示词").click();await flush();
  const text="  A deliberate plan.\nKeep indentation.  ";await env.input("settings-prompt-text",text);await env.input("settings-prompt-note","test change");
  await env.button("保存并生效","settings-actions").click();
  const sent=env.calls.filter(call=>call.method!=="GET");assert.equal(sent.length,1);assert.equal(sent[0].url,"/api/settings/prompts");
  assert.equal(sent[0].body.key,"decision");assert.equal(sent[0].body.text,text);assert.equal(sent[0].body.change_note,"test change");
  assert.equal(env.run("settingsState.dirty"),false);assert.ok(env.node("settings-feedback").textContent.includes("下一次"));
});

test("restoring a prompt uses the selected version and retains the selected prompt type", async () => {
  const env=environment();await env.run("openSettings('prompts')");await env.button("运维软约束").click();await flush();
  env.node("settings-prompt-version").value="0";await env.button("恢复此版本").click();
  const sent=env.calls.find(call=>call.url==="/api/settings/prompts/restore");assert.ok(sent);
  assert.equal(sent.body.key,"constraints");assert.equal(sent.body.version_id,0);
  assert.equal(env.run("settingsState.promptKey"),"constraints");assert.equal(env.run("settingsState.dirty"),false);
});

test("failed prompt saves keep the draft and selected version visible", async () => {
  const env=environment(call=>call.url==="/api/settings/prompts" && call.body?{ok:false,message:"保存失败，请重试"}:undefined);
  await env.run("openSettings('prompts')");await env.input("settings-prompt-text","keep this important draft");
  await env.button("保存并生效","settings-actions").click();
  assert.equal(env.node("settings-prompt-text").value,"keep this important draft");assert.equal(env.run("settingsState.dirty"),true);
  assert.equal(env.run("settingsState.busy"),false);assert.ok(env.node("settings-feedback").textContent.includes("保存失败"));
});

test("saving the auxiliary model does not discard an unsaved autonomous-model draft", async () => {
  const env=environment();await env.run("openSettings('model')");
  await env.input("mimo-model","unsaved-autonomous-model");await env.input("settings-assist-model","new-helper-model");
  await env.button("保存辅助配置").click();
  assert.equal(env.run("settingsState.dirty"),true);assert.equal(env.node("mimo-model").value,"unsaved-autonomous-model");
  assert.equal(env.calls.filter(call=>call.url==="/api/mimo/provider" && call.body).length,0);
  const sent=env.calls.find(call=>call.url==="/api/settings/global" && call.body);assert.equal(sent.body.llm_model,"new-helper-model");
});

test("saving the autonomous model does not discard an unsaved auxiliary-model draft", async () => {
  const env=environment(call=>call.url==="/api/mimo/provider" && call.body?{ok:true,saved:true,verified:true}:undefined);await env.run("openSettings('model')");
  await env.input("mimo-model","new-autonomous-model");await env.input("settings-assist-model","unsaved-helper-model");
  await env.button("保存并验证","settings-actions").click();
  assert.equal(env.run("settingsState.dirty"),true);assert.equal(env.node("settings-assist-model").value,"unsaved-helper-model");
  assert.equal(env.calls.filter(call=>call.url==="/api/settings/global" && call.body).length,0);
  const sent=env.calls.find(call=>call.url==="/api/mimo/provider" && call.body);assert.equal(sent.body.model,"new-autonomous-model");assert.equal(sent.body.test,true);
});

test("notification configuration moves the original nodes and returns them without duplicate IDs", async () => {
  const env=environment(),original=env.node("settings-notification-content"),name=env.node("notify-name");
  let edits=0;name.addEventListener("input",()=>edits++);name.value="draft channel name";
  await env.run("openSettings('connections')");
  const details=env.node("settings-content").querySelectorAll("details").find(node=>node.querySelector("summary")?.textContent==="通知渠道");
  details.open=true;await details.dispatch("toggle");
  assert.ok(env.node("settings-content").contains(original));assert.equal(env.node("notify-name"),name);
  await name.dispatch("input");assert.equal(edits,1);assert.equal(env.run("settingsState.dirty"),true);
  await env.input("notify-hook-token","dummy-private-notification-token");
  await env.input("notify-hook-url","https://hooks.example.test/send?key=dummy-query-secret");
  await env.run("renderSettingsSection('about')");
  await env.button("继续编辑","modal-actions").click();assert.ok(env.node("settings-content").contains(original));
  assert.equal(name.value,"draft channel name");assert.equal(env.node("notify-hook-token").value,"dummy-private-notification-token");
  await env.run("renderSettingsSection('about')");await env.button("放弃修改","modal-actions").click();await flush();
  assert.equal(original.parentElement,env.node("settings-storage"));assert.equal(name.value,"");
  assert.equal(env.node("notify-hook-token").value,"");assert.equal(env.node("notify-hook-url").value,"");
  assert.equal(env.document.querySelectorAll("#settings-notification-content").length,1);
  assert.equal(env.document.querySelectorAll("#notify-name").length,1);
  assert.equal(env.calls.filter(call=>call.url.includes("/notify/") && call.method!=="GET").length,0);
});

test("repeated section changes do not accumulate save buttons or duplicate section titles", async () => {
  const env=environment();await env.run("openSettings('profile')");
  for(const page of ["connections","about","prompts","model","profile","model"]){
    await env.run(`renderSettingsSection('${page}')`);
    assert.equal(env.document.querySelectorAll("#settings-section-title").length,1);
    assert.equal(env.document.querySelectorAll("#settings-actions").length,1);
    const primary=env.node("settings-actions").querySelectorAll("button.primary");assert.ok(primary.length<=1,page);
  }
  assert.equal(env.node("settings-actions").querySelectorAll("button").filter(button=>button.textContent==="保存并验证").length,1);
});

test("canceling dirty logout retains the session and no logout request is sent", async () => {
  const env=environment();await env.run("openSettings('profile')");await env.input("profile-current-password","unsaved input");
  await env.node("logout-btn").click();
  assert.equal(env.node("settings-dialog").classList.contains("hidden"),false);assert.equal(env.calls.filter(call=>call.url==="/api/logout").length,0);
  await env.button("继续编辑","modal-actions").click();assert.equal(env.run("state.user.username"),"admin");
  await env.node("logout-btn").click();await env.button("放弃修改","modal-actions").click();await flush();
  assert.equal(env.calls.filter(call=>call.url==="/api/logout").length,1);assert.equal(env.run("state.user"),null);
});

test("a busy operation blocks logout as well as closing settings", async () => {
  const env=environment();await env.run("openSettings('profile')");env.run("settingsState.busy=true");
  await env.node("logout-btn").click();assert.equal(env.calls.filter(call=>call.url==="/api/logout").length,0);
  assert.equal(env.run("state.user.username"),"admin");assert.equal(env.node("settings-dialog").classList.contains("hidden"),false);
});

test("monitor save explicitly blocks while a separate notification draft is unsaved", async () => {
  const env=environment();await env.run("openSettings('connections')");
  const details=env.node("settings-content").querySelectorAll("details").find(node=>node.querySelector("summary")?.textContent==="通知渠道");
  details.open=true;await details.dispatch("toggle");await env.input("notify-name","not saved channel");await env.input("notify-hook-token","dummy-notification-secret");
  await env.input("settings-prometheus-url","http://127.0.0.1:9191");await env.button("保存连接","settings-actions").click();
  assert.equal(env.node("notify-name").value,"not saved channel");assert.equal(env.node("notify-hook-token").value,"dummy-notification-secret");
  assert.equal(env.run("settingsState.dirty"),true);
  assert.equal(env.calls.filter(call=>call.body).length,0);
  assert.ok(env.node("settings-feedback").textContent.includes("通知渠道还有未保存"));
  env.run("settingsNotificationSaved()");
  await env.button("保存连接","settings-actions").click();
  const sent=env.calls.filter(call=>call.body);assert.equal(sent.length,1);assert.equal(sent[0].url,"/api/settings/global");
  assert.equal(sent[0].body.prometheus_url,"http://127.0.0.1:9191");assert.equal(env.run("settingsState.dirty"),false);
});

test("notification save hooks prevent concurrent submits and preserve unsaved monitor fields", async () => {
  const env=environment();await env.run("openSettings('connections')");
  const details=env.node("settings-content").querySelectorAll("details").find(node=>node.querySelector("summary")?.textContent==="通知渠道");
  details.open=true;await details.dispatch("toggle");await env.input("notify-name","channel");await env.input("settings-prometheus-url","http://127.0.0.1:9191");
  assert.equal(env.run("settingsNotificationSaving(true)"),true);assert.equal(env.run("settingsState.busy"),true);
  assert.equal(env.run("settingsNotificationSaving(true)"),false);
  env.run("settingsNotificationSaved();settingsNotificationSaving(false)");
  assert.equal(env.run("settingsState.busy"),false);assert.equal(env.run("settingsState.dirty"),true);
  assert.equal(env.node("settings-prometheus-url").value,"http://127.0.0.1:9191");
  assert.equal(env.calls.filter(call=>call.method!=="GET").length,0);
});

(async()=>{
  let passed=0;
  for(const {name,run} of tests){try {await run();passed+=1;console.log("PASS "+name);} catch(error) { console.error("FAIL "+name);console.error(error); }}
  console.log(`${passed}/${tests.length} settings UI checks passed`);
  if(passed!==tests.length)process.exitCode=1;
})().catch(error=>{console.error(error);process.exitCode=1;});
