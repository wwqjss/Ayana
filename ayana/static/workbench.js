/* One native MiMoCode workspace; Ayana renders business state only. */
(function () {
  const appApi = typeof window.api === "function" ? window.api.bind(window) : null;
  const appEl = typeof window.el === "function" ? window.el : null;
  const appShowModal = typeof window.showModal === "function" ? window.showModal : null;
  const appCloseModal = typeof window.closeModal === "function" ? window.closeModal : null;
  const state = {
    sessions: [], currentId: "", detail: null, settings: null, permissions: null, groupBusy: false,
    sshGroups: [], groupOptionsVersion: 0, groupEventVersion: 0,
    active: false, generation: 0, mount: 0, pollTimer: null, polling: false,
    collapsedLeft: false, collapsedRight: false, settingsGeneration: 0, lifecycleBusy: false, taskEventVersion: 0,
  };
  const term = {
    ws: null, xterm: null, fit: null, observer: null, connectionId: "",
    control: false, ready: false, rendered: false, connecting: false,
    sessionId: "", attempt: 0, pingTimer: null, paintTimer: null,
    resizeCols: 0, resizeRows: 0, clipboard: null, clipboardHandler: null,
  };
  const $ = (id) => document.getElementById(id);
  function el(tag, attrs = {}, children = []) {
    if (appEl) return appEl(tag, attrs, children);
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
      else if (value !== null && value !== undefined) node.setAttribute(key, value);
    });
    children.forEach((child) => node.appendChild(typeof child === "string" ? document.createTextNode(child) : child));
    return node;
  }
  async function api(path, options = {}) {
    if (appApi) return appApi(path, options);
    const response = await fetch(path, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...options });
    try { return await response.json(); } catch (_) { return { ok: false, error: "bad_response" }; }
  }
  function fmtTime(timestamp) {
    if (!timestamp) return "";
    const date = new Date(Number(timestamp) * 1000);
    return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("zh-CN", { hour12: false });
  }
  const current = (sid, generation) => state.active && state.currentId === sid && state.generation === generation;
  const sessionPath = (sid) => "/api/agent/sessions/" + encodeURIComponent(sid);
  const manageable = () => !!state.detail && (state.detail.can_prepare === true || state.detail.can_control === true || (state.detail.can_prepare === undefined && state.detail.can_control === undefined));
  const openSession = () => state.detail && state.detail.session && state.detail.session.status === "open";

  function groupLabel(name) {
    const group = state.sshGroups.find((item) => item.name === name);
    return group && group.label || (name === "default" ? "默认" : name) || "待确认";
  }
  function globalGroup() {
    if (state.permissions && state.permissions.ssh_account_group_source === "global") return state.permissions.ssh_account_group;
    return state.settings && state.settings.ssh_default_group || "default";
  }
  function sessionGroupOverride() {
    const authority = state.permissions;
    if (authority && authority.ssh_account_group_source) return authority.ssh_account_group_source === "session" ? authority.ssh_account_group : "";
    return state.detail && state.detail.session && state.detail.session.ssh_account_group || "";
  }
  function adoptGroupOptions(reply) {
    if (reply.settings) state.settings = reply.settings;
    if (Array.isArray(reply.ssh_roles)) state.sshGroups = reply.ssh_roles.map((group) => typeof group === "string" ? { name: group } : group).filter((group) => group && group.name);
  }
  async function loadAccountGroups() {
    const mount = state.mount, version = ++state.groupOptionsVersion;
    try {
      const reply = await api("/api/agent/settings");
      if (!state.active || state.mount !== mount || version !== state.groupOptionsVersion || !reply || !reply.ok) return;
      adoptGroupOptions(reply); updateTermUi();
    } catch (_) { /* Keep the last confirmed account groups on a transient failure. */ }
  }
  function renderGroupSelector() {
    const select = $("aw-account-group");
    if (!select) return;
    const selected = sessionGroupOverride();
    const choices = [{ name: "", label: `跟随默认（${groupLabel(globalGroup())}）` }, ...state.sshGroups];
    if (selected && !choices.some((group) => group.name === selected)) choices.push({ name: selected, label: selected + "（未配置）", enabled: false });
    const signature = JSON.stringify(choices.map((group) => [group.name, group.label, group.enabled]));
    if (select.dataset.options !== signature) {
      select.innerHTML = "";
      choices.forEach((group) => select.appendChild(el("option", { value: group.name, text: group.label || group.name, disabled: group.enabled === false ? "disabled" : null })));
      select.dataset.options = signature;
    }
    select.value = selected;
    const detail = state.detail || {}, session = detail.session || {};
    select.disabled = !(manageable() && detail.can_control !== false && openSession() && !session.delete_requested_at && state.permissions && !state.groupBusy && state.sshGroups.length);
  }

  function notice(text = "", failure = false) {
    const box = $("aw-term-notice");
    if (!box) return;
    box.textContent = text;
    box.classList.toggle("hidden", !text);
    box.classList.toggle("error", failure);
  }
  function taskFeedback(text = "", failure = false) {
    const node = $("aw-task-feedback");
    if (!node) return;
    node.textContent = text; node.classList.toggle("hidden", !text); node.classList.toggle("error", failure);
  }
  function taskState() {
    const detail = state.detail || {}, session = detail.session || {};
    if (session.deleted_at) return "deleted";
    if (session.delete_requested_at) return detail.task_state || "deleting";
    if (session.status === "archived") return "archived";
    return detail.task_state || (session.paused_at ? "paused" : detail.runtime && detail.runtime.state) || "idle";
  }
  function taskLabel() {
    const names = {idle:"空闲",running:"任务执行中",busy:"任务执行中",queued:"输入已排队",interrupted:"任务已中断",paused:"值班已暂停",unknown:"执行结果待核对",stopping:"正在停止",deleting:"正在停止并删除",archived:"已归档",deleted:"已删除"};
    return state.detail && state.detail.task_state_label || names[taskState()] || "状态待确认";
  }
  function renderSessionList() {
    const root = $("aw-session-list");
    if (!root) return;
    root.innerHTML = "";
    const groups = [
      ["自动值班", state.sessions.filter((item) => item.status === "open" && item.origin === "auto")],
      ["手动会话", state.sessions.filter((item) => item.status === "open" && item.origin === "manual")],
      ["历史", state.sessions.filter((item) => item.status !== "open" || !["auto", "manual"].includes(item.origin))],
    ];
    if (!state.sessions.length) root.appendChild(el("div", { class: "aw-muted", text: "暂无会话" }));
    groups.forEach(([label, items]) => {
      if (!items.length) return;
      root.appendChild(el("div", { class: "aw-group-label", text: label }));
      items.forEach((item) => {
        const button = el("button", {
          type: "button", class: "aw-session-item" + (item.id === state.currentId ? " active" : ""),
          onclick: () => selectSession(item.id),
          "aria-current": item.id === state.currentId ? "true" : "false",
        }, [
          el("div", { class: "aw-session-title", text: item.title || item.id }),
          el("div", { class: "aw-session-meta", text: `${fmtTime(item.updated_at || item.created_at)} · ${item.incident_count || 0} 个工单` }),
        ]);
        if (item.delete_requested_at) button.appendChild(el("div", { class: "aw-session-badge warn", text: item.task_state_label || "等待停止并删除" }));
        else if (item.paused_at) button.appendChild(el("div", { class: "aw-session-badge warn", text: "值班已暂停" }));
        else if (item.archive_due_at > 0) button.appendChild(el("div", { class: "aw-session-badge warn", text: "归档缓冲中" }));
        else if (item.status === "archived") button.appendChild(el("div", { class: "aw-session-badge", text: "已归档" }));
        root.appendChild(button);
      });
    });
  }
  function renderHeader() {
    const session = state.detail && state.detail.session;
    const title = $("aw-chat-title"), meta = $("aw-chat-meta");
    if (title) title.textContent = session ? session.title || session.id : "MiMoCode 工作台";
    if (meta) meta.textContent = session ? [session.origin === "auto" ? "自动值班" : "手动会话", session.status === "open" ? "会话开放" : "已归档", session.archive_due_at > 0 ? "归档缓冲中" : ""].filter(Boolean).join(" · ") : "";
    updateTermUi();
  }
  function renderRight() {
    const d = state.detail;
    const prog = $("aw-progress");
    const incs = $("aw-incidents");
    const res = $("aw-results");
    if (!prog) return;
    if (!d) {
      prog.textContent = "—";
      if (incs) incs.innerHTML = "";
      if (res) res.innerHTML = "";
      return;
    }
    const incidents = d.incidents || [];
    const openN = incidents.filter((i) => i.status === "open").length;
    prog.textContent = `${taskLabel()} · ` + (incidents.length ? `关联 ${incidents.length} 个工单 · 未关闭 ${openN}` : "无关联工单");
    if (incs) {
      incs.innerHTML = "";
      if (!incidents.length) incs.appendChild(el("div", { class: "aw-muted", text: "暂无" }));
      incidents.forEach((i) => {
        const row = el("div", { class: "aw-inc-row" }, [
          el("div", { class: "aw-inc-title", text: i.title || i.incident_id }),
          el("div", { class: "aw-inc-meta", text: `${i.severity || ""} · ${i.status || ""} · ${i.asset_id || ""}${i.need_human ? " · 需人工" : ""}` }),
        ]);
        if (i.need_human && i.status === "open") {
          row.appendChild(el("button", {
            type: "button", class: "btn primary small", text: "恢复自治",
            onclick: () => resumeAutonomy(i),
          }));
        }
        incs.appendChild(row);
      });
    }
    if (res) {
      res.innerHTML = "";
      const results = d.pending_write_results || [];
      const evs = (d.events || []).filter((e) =>
        ["tool_call", "tool_result", "action_proposed", "session_archived"].includes(e.type)
      );
      if (!results.length && !evs.length) res.appendChild(el("div", { class: "aw-muted", text: "暂无" }));
      results.forEach((w) => {
        const row = el("div", { class: "aw-pend-card" }, [
          el("div", { class: "aw-pend-title", text: `写结果待核销${w.target ? " @ " + w.target : ""}` }),
          el("div", { class: "aw-pend-meta", text: `${w.incident_id || ""} · ${fmtTime(w.created_at)} · ${w.result || w.status}` }),
          el("div", { class: "aw-pend-actions" }, [
            el("button", {
              type: "button", class: "btn primary small", text: "已执行",
              onclick: () => adjudicateResult(w, "executed"),
            }),
            el("button", {
              type: "button", class: "btn ghost small", text: "未执行",
              onclick: () => adjudicateResult(w, "not_executed"),
            }),
            el("button", {
              type: "button", class: "btn ghost small", text: "仍未知",
              onclick: () => adjudicateResult(w, "still_unknown"),
            }),
          ]),
        ]);
        res.appendChild(row);
      });
      res.querySelectorAll("button").forEach((button) => { button.disabled = !manageable(); });
      evs.slice(-8).forEach((e) => {
        res.appendChild(el("div", { class: "aw-res-row", text: `${fmtTime(e.created_at)} ${e.title || e.type}` }));
      });
    }
  }
  function resumeAutonomy(inc) {
    const key = "resume:" + inc.incident_id;
    if (pendingDecisions.has(key)) return;
    if (!confirm("确认人工处理完成后恢复自治？将重置本轮失败计数并重新调查规划，历史审计保留。")) return;
    return decide("/api/incidents/" + encodeURIComponent(inc.incident_id) + "/resume", {}, key);
  }
  function adjudicateResult(w, outcome) {
    const key = "wop:" + w.id;
    if (pendingDecisions.has(key)) return;
    const names = { executed: "已执行", not_executed: "未执行", still_unknown: "仍未知" };
    const reason = prompt(`核销写结果（${names[outcome]}）：请填写核对依据。`, outcome === "executed" ? "已在目标主机确认生效" : outcome === "not_executed" ? "已确认未执行" : "暂无法确认");
    if (reason === null) return;
    return decide("/api/agent/write-ops/" + encodeURIComponent(w.id) + "/adjudicate", { outcome, reason }, key);
  }


  const pendingDecisions = new Set();
  async function decide(path, body, key) {
    if (pendingDecisions.has(key)) return;
    pendingDecisions.add(key);
    const sid = state.currentId, generation = state.generation;
    try {
      const result = await api(path, { method: "POST", body: JSON.stringify(body) });
      if (!result || !result.ok) alert(result && (result.message || result.error) || "操作未完成，请查看当前状态。");
      if (current(sid, generation)) await loadDetail(sid, generation);
    } catch (_) { alert("请求未完成，请刷新核对操作状态。不要重复提交未确认的执行请求。"); }
    finally { pendingDecisions.delete(key); }
  }
  async function loadSessions() {
    const mount = state.mount;
    const result = await api("/api/agent/sessions?limit=100");
    if (!state.active || state.mount !== mount) return false;
    if (!result || !result.ok) return false;
    state.sessions = (result.sessions || []).filter((session) => !session.deleted_at);
    if (result.settings) state.settings = result.settings;
    renderSessionList();
    return true;
  }
  async function loadDetail(sid, generation = state.generation) {
    if (!sid) return false;
    const taskEventVersion = state.taskEventVersion;
    const groupEventVersion = state.groupEventVersion;
    const result = await api(sessionPath(sid));
    if (!current(sid, generation)) return false;
    if (!result || !result.ok) {
      if (state.detail && state.detail.session && state.detail.session.delete_requested_at
          && result && ["session_unavailable", "not_found", "session_deleted"].includes(result.error)) {
        await chooseAfterDeletion(sid, generation); return false;
      }
      notice(result && (result.message || result.error) || "无法读取会话。", true);
      return false;
    }
    if (result.session && result.session.deleted_at) { await chooseAfterDeletion(sid, generation); return false; }
    if (taskEventVersion !== state.taskEventVersion && state.detail) {
      result.task_state = state.detail.task_state;
      result.task_state_label = state.detail.task_state_label;
    }
    if (groupEventVersion !== state.groupEventVersion && state.permissions) {
      result.effective_permissions = state.permissions;
      if (result.session) result.session.ssh_account_group = sessionGroupOverride();
    }
    state.detail = result;
    if (result.can_control === false) term.control = false;
    adoptPermissions(result.effective_permissions);
    if (!term.ready && !term.connecting) {
      try {
        const viewport = await api(sessionPath(sid) + "/terminal");
        if (current(sid, generation)) state.viewport = viewport && viewport.ok ? viewport : null;
      } catch (_) { if (current(sid, generation)) state.viewport = null; }
      renderTerminalIdle();
    }
    renderHeader(); renderRight(); renderSessionList();
    return true;
  }
  async function selectSession(sid) {
    const generation = ++state.generation;
    disconnectTerminal();
    state.currentId = sid;
    state.permissions = null; state.groupBusy = false;
    state.detail = null; state.viewport = null;
    state.taskEventVersion = 0; state.groupEventVersion = 0; state.lifecycleBusy = false;
    taskFeedback("");
    renderHeader(); renderRight(); renderSessionList();
    notice("正在读取会话…");
    try {
      if (await loadDetail(sid, generation)) {
        renderTerminalIdle();
        notice("点击「连接会话」接入 MiMoCode。");
      }
    } catch (_) {
      if (current(sid, generation)) notice("会话暂不可达，请重试。", true);
    }
  }
  function createSession() {
    if (!appShowModal) { notice("会话创建面板暂不可用。", true); return; }
    const input = el("input", { type: "text", maxlength: "120", placeholder: "会话标题（可留空）", "aria-label": "会话标题" });
    const error = el("p", { class: "aw-muted", role: "status" });
    const save = el("button", { type: "button", class: "btn primary", text: "创建会话", onclick: async () => {
      if (save.disabled) return;
      save.disabled = true;
      const mount = state.mount;
      try {
        const result = await api("/api/agent/sessions", { method: "POST", body: JSON.stringify({ title: input.value.trim() }) });
        if (!state.active || mount !== state.mount) return;
        if (!result || !result.ok) { error.textContent = result && (result.message || result.error) || "创建失败"; return; }
        if (appCloseModal) appCloseModal();
        await loadSessions();
        if (state.active && mount === state.mount) await selectSession(result.session_id);
      } catch (_) { error.textContent = "创建请求未完成，请核对左侧会话列表。"; }
      finally { save.disabled = false; }
    } });
    appShowModal("新建手动会话", [el("div", { class: "form-col" }, [input, el("p", { class: "aw-muted", text: "创建后点击「连接会话」进入 MiMoCode，在原生输入框中开始任务。" }), error, save])]);
  }
  async function abortCurrent() {
    const sid = state.currentId, generation = state.generation;
    if (!sid || !confirm("停止当前 MiMo 任务？断开页面无需停止任务。")) return;
    try {
      const result = await api(sessionPath(sid) + "/abort", { method: "POST", body: "{}" });
      if (!current(sid, generation)) return;
      if (!result || !result.ok) taskFeedback(result && (result.message || result.error) || "停止请求未确认。", true);
      else taskFeedback("已发送停止请求，正在核对任务状态。");
      await loadDetail(sid, generation);
    } catch (_) { if (current(sid, generation)) taskFeedback("停止请求未确认，请检查任务状态。", true); }
  }
  async function archiveCurrent() {
    const sid = state.currentId, generation = state.generation;
    if (!sid || !confirm("归档当前会话？仍有运行任务或待核对写结果时将保留会话。")) return;
    const result = await api(sessionPath(sid) + "/archive", { method: "POST", body: "{}" });
    if (!current(sid, generation)) return;
    if (!result || !result.ok) taskFeedback(result && (result.message || result.error) || "当前会话暂不能归档。", true);
    await loadSessions(); await loadDetail(sid, generation);
  }
  async function reopenCurrent() {
    const sid = state.currentId, generation = state.generation;
    if (!sid || !confirm("将此历史会话续接为手动会话？自动值班会话继续独立运行。")) return;
    const result = await api(sessionPath(sid) + "/reopen", { method: "POST", body: "{}" });
    if (!current(sid, generation)) return;
    if (!result || !result.ok) { taskFeedback(result && (result.message || result.error) || "续接失败。", true); return; }
    await loadSessions();
    if (current(sid, generation)) await selectSession(sid);
  }
  async function chooseAfterDeletion(sid, generation) {
    if (!current(sid, generation)) return;
    disconnectTerminal();
    const nextGeneration = ++state.generation;
    state.currentId = ""; state.detail = null; state.permissions = null; state.lifecycleBusy = false;
    taskFeedback(""); renderHeader(); renderRight();
    await loadSessions();
    if (!state.active || state.generation !== nextGeneration || state.currentId) return;
    state.sessions = state.sessions.filter((item) => item.id !== sid);
    renderSessionList();
    const next = state.sessions.find((item) => item.origin === "auto" && item.status === "open") || state.sessions[0];
    if (next) await selectSession(next.id);
    else notice("会话已从列表移除。可以新建会话开始任务。");
  }
  async function lifecycleAction(action) {
    const sid = state.currentId, generation = state.generation;
    if (!sid || state.lifecycleBusy || !manageable()) return;
    const prompts = {
      pause: "暂停此会话的自动值班接单？当前任务的执行状态会单独显示。",
      "resume-duty": "恢复此会话的自动值班接单？这不会自动重放未知操作。",
      recover: "继续当前中断任务？将沿用原生会话和权限，未知写操作不会自动重放。",
      delete: "删除此会话并从列表移除？关联工单和审计历史会保留。",
      "delete-stop": "停止当前任务并删除此会话？结果尚未确认时会保留会话，关联工单和审计历史不删除。",
    };
    if (!confirm(prompts[action])) return;
    state.lifecycleBusy = true; updateTermUi();
    try {
      const deleting = action === "delete" || action === "delete-stop";
      const response = await api(sessionPath(sid) + (deleting ? "" : "/" + action), {
        method: deleting ? "DELETE" : "POST", body: JSON.stringify(deleting ? { stop: action === "delete-stop" } : action === "recover" ? { connection_id: term.connectionId } : {}),
      });
      if (!current(sid, generation)) return;
      if (!response || !response.ok) {
        const reason = response && (response.message || response.error);
        taskFeedback(reason || "操作未完成，请核对当前任务状态。", true);
        await loadDetail(sid, generation); return;
      }
      ++state.taskEventVersion;
      if (deleting && !response.pending) { await chooseAfterDeletion(sid, generation); return; }
      if (deleting && response.pending && state.detail && state.detail.session) state.detail.session.delete_requested_at = state.detail.session.delete_requested_at || Date.now() / 1000;
      const messages = {pause:"暂停值班请求已确认。", "resume-duty":"已恢复值班接单。", recover:"恢复请求已接受，正在核对原生任务状态。", delete:"删除正在等待安全确认。", "delete-stop":"正在停止并删除；确认完成前会话仍会保留。"};
      taskFeedback(response.message || messages[action]);
      await loadSessions();
      if (current(sid, generation)) await loadDetail(sid, generation);
    } catch (_) { if (current(sid, generation)) taskFeedback("请求结果未确认，请核对状态，勿重复提交。", true); }
    finally { if (current(sid, generation)) { state.lifecycleBusy = false; updateTermUi(); } }
  }
  async function openAgentSettings() {
    const generation = ++state.settingsGeneration, mount = state.mount;
    let reply;
    try { reply = await api("/api/agent/settings"); }
    catch (_) { taskFeedback("无法读取 Agent 设置，请重试。", true); return; }
    if (!state.active || mount !== state.mount || generation !== state.settingsGeneration) return;
    if (!reply || !reply.ok) { taskFeedback(reply && (reply.message || reply.error) || "无法读取 Agent 设置。", true); return; }
    adoptGroupOptions(reply); updateTermUi();
    if (!appShowModal) { taskFeedback("设置面板暂不可用。", true); return; }
    const settings = reply.settings || {}, endpoints = reply.ssh_endpoints || [];
    const wrap = el("div", { class: "aw-agent-settings" });
    const feedback = el("p", { class: "settings-footer-note", role: "status", "aria-live": "polite", text: "修改尚未保存" });
    const dirty = () => { feedback.textContent = "修改尚未保存"; feedback.classList.remove("error"); };
    function section(title, description) {
      const card = el("section", { class: "settings-card" }, [el("h3", { text: title }), el("p", { class: "settings-description", text: description })]);
      wrap.appendChild(card); return card;
    }
    function field(label, control, help = "") {
      return el("label", { class: "settings-field" }, [el("span", { text: label }), control, ...(help ? [el("small", { text: help })] : [])]);
    }
    const sshCard = section("默认账号组", "会话和后台检查统一使用此组。单个会话可在顶部另选账号组，从下一次执行生效。账号能执行哪些命令，由服务器账号及 sudo 决定；缺少该组账号时会提示配置，不会换用其他组。");
    const manageHint = el("p", { class: "muted small" }, [
      el("span", { text: "要新建账号组或把 SSH 账号挂进组，请到 " }),
      el("button", { type: "button", class: "btn link", text: "连接 → 账号组", onclick: () => {
        if (appCloseModal) appCloseModal();
        const btn = document.querySelector('nav [data-tab="connections"]');
        if (btn) btn.click();
        queueMicrotask(() => {
          const panel = document.getElementById("account-groups-panel");
          if (panel) { panel.open = true; panel.scrollIntoView({ block: "nearest" }); }
        });
      } }),
      el("span", { text: "。" }),
    ]);
    sshCard.appendChild(manageHint);
    const roles = state.sshGroups.slice();
    function rolePicker(id, label, selected) {
      const select = el("select", { id, "aria-label": label });
      const choices = roles.slice();
      if (!choices.some((role) => role.name === selected)) choices.push({ name: selected, missing: true });
      choices.forEach((role) => select.appendChild(el("option", { value: role.name, disabled: role.enabled === false ? "disabled" : null, text: (role.label || role.name) + (role.missing ? "（待配置）" : role.enabled === false ? "（已停用）" : "") + (role.description ? " · " + role.description : "") })));
      select.value = selected;
      const accounts = el("div", { class: "aw-account-list", "aria-live": "polite" });
      function renderAccounts() {
        accounts.innerHTML = "";
        const assets = [...new Set(endpoints.map((endpoint) => endpoint.asset_id))];
        if (!assets.length) accounts.appendChild(el("span", { class: "aw-muted", text: "暂无 SSH 端点，请在「连接」中配置。" }));
        assets.forEach((asset) => {
          const enabled = endpoints.filter((endpoint) => endpoint.enabled && endpoint.asset_id === asset);
          const endpoint = enabled.find((candidate) => candidate.role === select.value);
          const text = endpoint ? `${endpoint.username || "未设置账户"}@${endpoint.host || "未设置地址"}${endpoint.port ? ":" + endpoint.port : ""}` : "未加入此账号组";
          accounts.appendChild(el("div", { class: "aw-account-row" }, [el("span", { class: "aw-account-asset", text: asset || "资产", title: asset }), el(endpoint ? "code" : "span", { class: endpoint ? "aw-account-address" : "aw-account-missing", text, title: text })]));
        });
      }
      select.onchange = () => { renderAccounts(); dirty(); };
      renderAccounts();
      sshCard.appendChild(field(label, select)); sshCard.appendChild(accounts);
      return select;
    }
    const defaultGroup = rolePicker("agent-ssh-default", "默认账号组", settings.ssh_default_group || "default");
    const archiveCard = section("会话归档", "自动值班关联工单全部关闭后开始缓冲；新告警会取消倒计时。手动会话独立管理。");
    const presets = [["60", "1 分钟"], ["300", "5 分钟"], ["900", "15 分钟"], ["1800", "30 分钟"], ["custom", "自定义"]];
    const delayValue = String(settings.archive_delay_sec || 300);
    const delayPreset = el("select", { id: "agent-archive-preset", "aria-label": "归档缓冲" }, presets.map(([value, text]) => el("option", { value, text })));
    delayPreset.value = presets.some(([value]) => value === delayValue) ? delayValue : "custom";
    const customDelay = el("input", { id: "agent-archive-custom", type: "number", min: "30", max: "3600", step: "1", value: delayValue, "aria-label": "自定义归档秒数" });
    const customField = field("自定义秒数", customDelay, "支持 30–3600 秒。");
    function showCustom() { customField.classList.toggle("hidden", delayPreset.value !== "custom"); }
    delayPreset.onchange = () => { showCustom(); dirty(); }; customDelay.oninput = dirty;
    archiveCard.appendChild(field("归档缓冲", delayPreset)); archiveCard.appendChild(customField); showCustom();
    let busy = false;
    const cancel = el("button", { type: "button", class: "btn", text: "取消", onclick: () => {
      if (busy) return; ++state.settingsGeneration; if (appCloseModal) appCloseModal();
    } });
    const save = el("button", { type: "button", class: "btn primary", text: "保存设置", onclick: async () => {
      if (busy) return;
      const seconds = Number(delayPreset.value === "custom" ? customDelay.value : delayPreset.value);
      if (!Number.isInteger(seconds) || seconds < 30 || seconds > 3600) {
        feedback.textContent = "归档缓冲需要是 30–3600 秒的整数。"; feedback.classList.add("error"); return;
      }
      busy = true;
      for (const tag of ["button", "input", "select"]) wrap.querySelectorAll(tag).forEach((node) => { node.disabled = true; });
      wrap.setAttribute("aria-busy", "true"); save.textContent = "保存中…";
      feedback.textContent = "正在保存…"; feedback.classList.remove("error");
      const stillCurrent = () => state.active && state.settingsGeneration === generation && wrap.isConnected !== false;
      try {
        const result = await api("/api/agent/settings", { method: "POST", body: JSON.stringify({
          archive_delay_sec: seconds,
          ssh_default_group: defaultGroup.value,
        }) });
        if (!stillCurrent()) return;
        if (!result || !result.ok) { feedback.textContent = result && (result.message || result.error) || "保存失败，请重试。"; feedback.classList.add("error"); return; }
        state.settings = result.settings || state.settings;
        updateTermUi();
        feedback.textContent = "已保存并生效"; cancel.textContent = "关闭";
        if (state.currentId) await loadDetail(state.currentId);
      } catch (_) { if (stillCurrent()) { feedback.textContent = "保存结果未确认，请重新读取设置后核对。"; feedback.classList.add("error"); } }
      finally {
        busy = false;
        if (stillCurrent()) {
          for (const tag of ["button", "input", "select"]) wrap.querySelectorAll(tag).forEach((node) => { node.disabled = false; });
          wrap.setAttribute("aria-busy", "false"); save.textContent = "保存设置";
        }
      }
    } });
    wrap.appendChild(el("div", { class: "settings-actions aw-settings-actions" }, [feedback, cancel, save]));
    appShowModal("Agent 设置", [wrap]);
  }


  function adoptPermissions(value) {
    if (!value || value.session_id !== state.currentId || typeof value.ssh_account_group !== "string") return;
    if (state.permissions && value.revision < state.permissions.revision) return;
    state.permissions = value;
    if (value.controller_active === false) term.control = false;
  }
  function clipboardBridge() {
    if (term.clipboard) return term.clipboard;
    if (!window.AyanaTerminalClipboard) { taskFeedback("复制组件未加载，请刷新页面。", true); return null; }
    const sid = state.currentId, generation = state.generation, attempt = term.attempt;
    term.clipboard = window.AyanaTerminalClipboard.create({
      document, navigator: window.navigator,
      isCurrent: () => current(sid, generation) && term.attempt === attempt,
      preview: () => $("aw-copy-text"),
      onOffer: (text, visible) => {
        const panel = $("aw-copy-panel"), preview = $("aw-copy-text");
        if (preview) preview.value = text;
        if (panel) panel.classList.toggle("hidden", !visible);
      },
      onStatus: (text, failure) => {
        const status = $("aw-copy-status");
        if (status) { status.textContent = text; status.classList.toggle("error", failure); }
        taskFeedback(text, failure);
      },
    });
    return term.clipboard;
  }
  async function copyResult() {
    const sid = state.currentId, generation = state.generation, attempt = term.attempt;
    if (!sid || !state.detail) return;
    const bridge = clipboardBridge();
    if (!bridge) return;
    const selected = term.xterm && typeof term.xterm.getSelection === "function" ? term.xterm.getSelection() : "";
    if (selected) {
      if (bridge.offer(selected)) await bridge.copyPending();
      return;
    }
    const button = $("aw-copy-result");
    if (button && button.disabled) return;
    if (button) button.disabled = true;
    try {
      const reply = await api(sessionPath(sid) + "/copy-text");
      if (!current(sid, generation) || term.attempt !== attempt) return;
      if (!reply || !reply.ok || typeof reply.text !== "string" || !reply.text) {
        taskFeedback(reply && (reply.message || reply.error) || "当前没有可复制的回答，可先在终端选中文本。", true); return;
      }
      // HTTP fetch has crossed the gesture boundary. Offer text and require a
      // fresh click instead of pretending a remote copy updated this device.
      bridge.offer(reply.text);
    } catch (_) { if (current(sid, generation) && term.attempt === attempt) taskFeedback("无法读取复制内容，请重试或选择终端文本。", true); }
    finally { if (current(sid, generation) && term.attempt === attempt) updateTermUi(); }
  }
  async function copyLocal() {
    const bridge = term.clipboard, sid = state.currentId, generation = state.generation;
    const button = $("aw-copy-local");
    if (!bridge || button && button.disabled) return;
    if (button) button.disabled = true;
    try { await bridge.copyPending(); }
    finally { if (button && current(sid, generation) && term.clipboard === bridge) button.disabled = false; }
  }
  async function changeAccountGroup(group) {
    const sid=state.currentId, generation=state.generation;
    if (!manageable() || !openSession() || state.groupBusy || !state.permissions || state.detail.can_control === false) { updateTermUi(); return; }
    state.groupBusy=true; updateTermUi();
    try {
      const result=await api(sessionPath(sid)+"/account-group", {method:"POST",body:JSON.stringify({group})});
      if (!current(sid,generation)) return;
      adoptPermissions(result && result.effective_permissions);
      if (!result || !result.ok) taskFeedback(result && (result.message || result.error) || "账号组切换未生效。",true);
      else {
        ++state.groupEventVersion;
        if (state.detail && state.detail.session) state.detail.session.ssh_account_group = typeof result.group === "string" ? result.group : group;
        taskFeedback("当前会话账号组已更新，下次执行生效。");
      }
    } catch (_) { if(current(sid,generation)) taskFeedback("账号组切换尚未确认，请核对当前状态。",true); }
    finally { if(current(sid,generation)) {state.groupBusy=false;updateTermUi();} }
  }
  function updateTermUi() {
    const status = $("aw-term-status");
    if (status) {
      const group = state.permissions ? groupLabel(state.permissions.ssh_account_group) : "账号组待确认";
      status.textContent = term.connecting ? "接入中" : term.ready && term.rendered ? (term.control ? "接管" : "观察")+" · "+group : term.ready ? "等待原生画面" : (state.viewport && state.viewport.released_at ? "已释放，可连接" : "未接入");
      status.classList.toggle("ready", term.ready && term.rendered);
      status.classList.toggle("control", term.control);
    }
    const toggle = (id, visible) => { const node = $(id); if (node) node.classList.toggle("hidden", !visible); };
    const admin = manageable(), open = openSession();
    const detail = state.detail || {}, session = detail.session || {}, task = taskState();
    const taskBadge = $("aw-task-state");
    if (taskBadge) { taskBadge.textContent = state.detail ? taskLabel() : ""; taskBadge.dataset.state = task; }
    const copy = $("aw-copy-result");
    if (copy) { copy.disabled = !state.currentId || !state.detail; copy.textContent = term.xterm && typeof term.xterm.hasSelection === "function" && term.xterm.hasSelection() ? "复制选中文本" : "复制结果"; }
    const canControl = admin && detail.can_control !== false && !session.delete_requested_at;
    renderGroupSelector();
    toggle("aw-term-acquire", term.ready && term.rendered && !term.control && canControl && open);
    toggle("aw-term-release", term.ready && term.control);
    toggle("aw-term-reconnect", !!state.currentId && !term.connecting && !term.ready);
    toggle("aw-term-disconnect", term.ready || term.connecting);
    toggle("aw-term-stop", !!state.currentId && admin && open);
    toggle("aw-archive", !!state.currentId && admin && open);
    toggle("aw-reopen", !!state.detail && admin && !open);
    toggle("aw-pause-duty", !!state.detail && admin && open && session.origin === "auto" && !session.paused_at && !session.delete_requested_at);
    toggle("aw-resume-duty", !!state.detail && admin && open && session.origin === "auto" && !!session.paused_at && !session.delete_requested_at);
    toggle("aw-recover-task", !!state.detail && admin && open && detail.can_recover === true && !session.delete_requested_at);
    toggle("aw-delete-session", !!state.detail && admin && detail.can_delete !== false && !session.delete_requested_at);
    toggle("aw-delete-stop", !!state.detail && admin && detail.can_request_delete !== false && detail.can_delete === false && !session.delete_requested_at);
    for (const id of ["aw-pause-duty", "aw-resume-duty", "aw-delete-session", "aw-delete-stop", "aw-recover-task"]) {
      const button = $(id); if (button) button.disabled = state.lifecycleBusy || id === "aw-recover-task" && !term.control;
    }
  }
  function sendTerminalSize(socket, cols, rows) {
    if (!state.active || !term.ready || term.ws !== socket || !socket || socket.readyState !== 1) return;
    if (!Number.isFinite(cols) || !Number.isFinite(rows)) return;
    cols = Math.max(20, Math.min(400, Math.floor(cols)));
    rows = Math.max(5, Math.min(200, Math.floor(rows)));
    if (term.resizeCols === cols && term.resizeRows === rows) return;
    term.resizeCols = cols; term.resizeRows = rows;
    socket.send(JSON.stringify({ type: "resize", cols, rows }));
  }
  function fitTerminal() {
    if (!term.xterm || !state.active) return;
    try { if (term.fit) term.fit.fit(); } catch (_) {}
    const socket = term.ws;
    if (socket && socket.readyState === 1 && term.ready) {
      sendTerminalSize(socket, term.xterm.cols, term.xterm.rows);
    }
  }
  function disconnectTerminal() {
    ++term.attempt;
    if (term.pingTimer) clearInterval(term.pingTimer);
    if (term.paintTimer) clearTimeout(term.paintTimer);
    term.pingTimer = term.paintTimer = null;
    if (term.observer) term.observer.disconnect();
    term.observer = null;
    if (term.clipboardHandler) term.clipboardHandler.dispose();
    term.clipboardHandler = null;
    if (term.clipboard) term.clipboard.dispose();
    term.clipboard = null;
    const copyPanel = $("aw-copy-panel"), copyText = $("aw-copy-text");
    if (copyPanel) copyPanel.classList.add("hidden");
    if (copyText) copyText.value = "";
    if (term.ws) {
      term.ws.onopen = term.ws.onmessage = term.ws.onclose = term.ws.onerror = null;
      term.ws.close();
    }
    term.ws = null;
    if (term.xterm) term.xterm.dispose();
    term.xterm = term.fit = null;
    const host = $("aw-term-host");
    if (host) host.innerHTML = "";
    term.connectionId = "";
    term.sessionId = "";
    term.resizeCols = term.resizeRows = 0;
    term.control = term.ready = term.rendered = term.connecting = false;
    updateTermUi();
  }
  function renderTerminalIdle() {
    const host = $("aw-term-host");
    if (!host || term.ready || term.connecting) return;
    host.innerHTML = "";
    const viewport = state.viewport;
    if (viewport && viewport.last_capture) {
      const pre = document.createElement("pre");
      pre.className = "aw-term-snapshot";
      pre.textContent = viewport.last_capture;
      host.appendChild(pre);
    }
    updateTermUi();
  }
  async function connectTerminal(sid = state.currentId, generation = state.generation) {
    if (!sid || !current(sid, generation)) return;
    disconnectTerminal();
    const attempt = term.attempt;
    const valid = () => current(sid, generation) && term.attempt === attempt;
    term.sessionId = sid; term.connecting = true;
    notice("正在接入该会话的 MiMoCode…"); updateTermUi();
    let prepared;
    try {
      prepared = await api(sessionPath(sid) + "/terminal", state.detail && state.detail.can_prepare === false ? {} : { method: "POST", body: "{}" });
    } catch (_) {
      if (valid()) { term.connecting = false; notice("原生运行服务暂不可达，任务和历史已保留。", true); updateTermUi(); }
      return;
    }
    if (!valid()) return;
    if (!prepared || !prepared.ok) {
      term.connecting = false;
      notice(prepared && (prepared.message || prepared.error) || "无法接入原生会话。任务和历史已保留。", true);
      updateTermUi(); return;
    }
    const Terminal = window.Terminal || window.xterm && window.xterm.Terminal;
    const Fit = window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon);
    if (!Terminal) { term.connecting = false; notice("原生界面组件未加载，请刷新页面。", true); updateTermUi(); return; }
    let terminal, socket;
    try {
    terminal = new Terminal({
      cursorBlink: true, fontSize: 13, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      theme: { background: "#0a0a0a", foreground: "#d5d5d5", cursor: "#ff8547" },
      // Keep device replies active; user instructions are gated below and
      // independently by the server's exclusive controller lease.
      scrollback: 2000, disableStdin: false, convertEol: false,
      windowOptions: { getWinSizePixels: true, getCellSizePixels: true, getWinSizeChars: true },
    });
    term.xterm = terminal;
    if (Fit) { term.fit = new Fit(); terminal.loadAddon(term.fit); }
    terminal.open($("aw-term-host"));
    const clipboard = clipboardBridge();
    if (clipboard && terminal.parser && typeof terminal.parser.registerOscHandler === "function") {
      term.clipboardHandler = terminal.parser.registerOscHandler(52, (data) => clipboard.receiveOsc52(data));
    }
    if (typeof terminal.onSelectionChange === "function") terminal.onSelectionChange(() => { if (valid()) updateTermUi(); });
    socket = new WebSocket(`${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/agent-terminal?session_id=${encodeURIComponent(sid)}`);
    term.ws = socket; socket.binaryType = "arraybuffer";
    } catch (_) {
      disconnectTerminal(); notice("无法创建原生视图，请刷新后重试。", true); return;
    }
    terminal.onData((data) => {
      if (!valid() || term.ws !== socket || !term.ready || socket.readyState !== 1) return;
      const reply = /^(?:\x1b\[(?:[?>]?[0-9;]*c|[0-9]+;[0-9]+R|[0-9;]+t|\?[0-9]+u|\?(?:1004|1016|2004|2026|2027|2031);[0-4]\$y)|\x1b\](?:10|11);rgb:[0-9a-f/]+(?:\x07|\x1b\\))$/i;
      if (data.length <= 256 && reply.test(data)) {
        socket.send(JSON.stringify({ type: "terminal_response", data }));
        return;
      }
      if (!term.control || state.detail && (state.detail.can_control === false || state.detail.session && state.detail.session.delete_requested_at)) return;
      if (term.clipboard) term.clipboard.arm();
      socket.send(JSON.stringify({ type: "input", data }));
    });
    terminal.onResize(({ cols, rows }) => {
      if (valid()) sendTerminalSize(socket, cols, rows);
    });
    const frame = () => valid() && term.ws === socket;
    socket.onmessage = (event) => {
      if (!frame()) return;
      if (typeof event.data === "string") {
        let message;
        try { message = JSON.parse(event.data); } catch (_) { return; }
        if (message.type === "ready") {
          adoptPermissions(message.effective_permissions || message.binding && message.binding.effective_permissions);
          term.connectionId = message.connection_id || "";
          term.control = !!message.control;
          term.ready = true; term.connecting = false;
          notice(term.rendered ? "" : "已附着，正在等待 MiMoCode 原生画面…");
          updateTermUi(); fitTerminal();
          term.paintTimer = setTimeout(() => {
            if (frame() && !term.rendered) notice("尚未收到原生画面，请重新接入。后台任务未停止。", true);
          }, 12000);
        } else if (message.type === "control") {
          adoptPermissions(message.effective_permissions);
          term.control = !!message.control; updateTermUi();
        } else if (message.type === "error") {
          taskFeedback(message.message || message.error || "原生连接异常，请核对任务状态。", true);
        } else if (message.type === "action_ack" || message.type === "task_state") {
          ++state.taskEventVersion;
          if (state.detail && message.state !== "error" && (message.state || message.task_state)) {
            state.detail.task_state = message.state || message.task_state;
            if (message.task_state_label) state.detail.task_state_label = message.task_state_label;
            else delete state.detail.task_state_label;
          }
          if (message.type === "action_ack" || message.message) taskFeedback(message.message || (message.queued ? "输入已排队，将在当前任务之后处理。" : "任务状态已更新。"), !!message.error || message.state === "error" || message.ok === false);
          renderHeader();
        }
        return;
      }
      if (event.data instanceof ArrayBuffer && event.data.byteLength) {
        terminal.write(new Uint8Array(event.data), () => {
          if (!frame() || term.xterm !== terminal) return;
          const buffer = terminal.buffer && terminal.buffer.active;
          if (buffer && typeof buffer.getLine === "function") {
            const start = Math.max(0, buffer.viewportY || 0);
            const end = Math.min(buffer.length, start + terminal.rows);
            for (let index = start; index < end; index++) {
              const line = buffer.getLine(index);
              if (line && /\S/.test(line.translateToString(true))) {
                term.rendered = true;
                break;
              }
            }
          }
          if (term.ready && term.rendered) {
            if (term.paintTimer) clearTimeout(term.paintTimer);
            term.paintTimer = null;
            notice("");
          }
          updateTermUi();
        });
      }
    };
    socket.onclose = (event) => {
      if (!frame()) return;
      term.ready = term.control = term.connecting = false;
      if (term.pingTimer) clearInterval(term.pingTimer);
      term.pingTimer = null;
      if (term.paintTimer) clearTimeout(term.paintTimer);
      term.paintTimer = null;
      notice(event && event.code === 4403 ? "会话权限已变更，连接已关闭。" : "当前视图已断开，后台任务继续执行。重新接入可回到同一会话。", true);
      updateTermUi();
    };
    socket.onerror = () => { if (frame()) notice("原生视图连接异常，请重新接入。", true); };
    term.pingTimer = setInterval(() => {
      if (frame() && socket.readyState === 1) socket.send(JSON.stringify({ type: "ping" }));
    }, 15000);
    if (typeof ResizeObserver === "function") {
      term.observer = new ResizeObserver(() => { if (frame()) fitTerminal(); });
      term.observer.observe($("aw-term-host"));
    }
    requestAnimationFrame(() => { if (frame()) fitTerminal(); });
    updateTermUi();
  }
  async function acquireControl() {
    const sid = state.currentId, generation = state.generation;
    const connectionId = term.connectionId, attempt = term.attempt;
    if (!term.ready || !term.rendered || !connectionId || !manageable() || !openSession()) return;
    const button = $("aw-term-acquire");
    if (button && button.disabled) return;
    if (button) button.disabled = true;
    try {
      const result = await api(sessionPath(sid) + "/terminal/control", { method: "POST", body: JSON.stringify({ action: "acquire", connection_id: connectionId }) });
      if (!current(sid, generation) || term.attempt !== attempt || term.connectionId !== connectionId) return;
      if (!result || !result.ok) { taskFeedback(result && (result.message || result.error) || "无法取得控制权，可能已由其他窗口持有。", true); return; }
      adoptPermissions(result.effective_permissions);
      term.control = true; updateTermUi(); notice("");
      if (term.xterm) term.xterm.focus();
      fitTerminal();
    } catch (_) { if (current(sid, generation) && term.attempt === attempt) taskFeedback("控制权请求未完成，请重新核对。", true); }
    finally { if (button) button.disabled = false; }
  }
  async function releaseControl() {
    const sid = state.currentId, generation = state.generation, attempt = term.attempt;
    const connectionId = term.connectionId;
    term.control = false; updateTermUi();
    if (!sid || !connectionId) return;
    try {
      const result = await api(sessionPath(sid) + "/terminal/control", { method: "POST", body: JSON.stringify({ action: "release", connection_id: connectionId }) });
      if(current(sid,generation) && term.attempt===attempt) {adoptPermissions(result && result.effective_permissions);updateTermUi();}
      if (current(sid, generation) && term.attempt === attempt && (!result || !result.ok)) taskFeedback("释放请求未确认，键盘已在当前页面停用。", true);
    } catch (_) { if (current(sid, generation) && term.attempt === attempt) taskFeedback("释放请求未确认，键盘已在当前页面停用。", true); }
  }
  function stopPoll() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  function startPoll() {
    if (state.pollTimer) return;
    state.pollTimer = setInterval(async () => {
      if (!state.active || state.polling) return;
      state.polling = true;
      const sid = state.currentId, generation = state.generation;
      try { await loadSessions(); if (current(sid, generation)) await loadDetail(sid, generation); }
      catch (_) { /* A business-state refresh never replaces native output. */ }
      finally { state.polling = false; }
    }, 10000);
  }
  function toggleColumn(side) {
    if (side === "right" && window.matchMedia && window.matchMedia("(max-width: 800px)").matches) {
      $("agent-workbench").classList.toggle("right-mobile-open");
      return;
    }
    const property = side === "left" ? "collapsedLeft" : "collapsedRight";
    state[property] = !state[property];
    $("aw-" + side).classList.toggle("collapsed", state[property]);
    $("agent-workbench").classList.toggle(side + "-collapsed", state[property]);
    requestAnimationFrame(fitTerminal);
  }
  let bound = false;
  function bind() {
    if (bound) return;
    bound = true;
    const handlers = {
      "aw-new-session": createSession, "aw-settings-btn": openAgentSettings,
      "aw-term-reconnect": () => connectTerminal(), "aw-term-acquire": acquireControl,
      "aw-term-release": releaseControl, "aw-term-stop": abortCurrent,
      "aw-term-disconnect": () => { disconnectTerminal(); renderTerminalIdle(); notice("已离开当前视图，后台任务继续执行。"); },
      "aw-archive": archiveCurrent, "aw-reopen": reopenCurrent,
      "aw-pause-duty": () => lifecycleAction("pause"), "aw-resume-duty": () => lifecycleAction("resume-duty"),
      "aw-recover-task": () => lifecycleAction("recover"), "aw-delete-session": () => lifecycleAction("delete"),
      "aw-delete-stop": () => lifecycleAction("delete-stop"), "aw-copy-result": copyResult, "aw-copy-local": copyLocal,
      "aw-copy-dismiss": () => { if (term.clipboard) term.clipboard.clear(); },
      "aw-toggle-left": () => toggleColumn("left"), "aw-toggle-right": () => toggleColumn("right"),
    };
    Object.entries(handlers).forEach(([id, callback]) => { const node = $(id); if (node) node.onclick = callback; });
    const group=$("aw-account-group");
    if(group)group.onchange=()=>changeAccountGroup(group.value);
    window.addEventListener("resize", fitTerminal);
    window.addEventListener("pagehide", suspendAgentWorkbench);
  }
  async function renderAgentWorkbench() {
    bind();
    if (!state.active) { state.active = true; ++state.mount; }
    const mount = state.mount;
    try {
      await Promise.all([loadSessions(), loadAccountGroups()]);
      if (!state.active || state.mount !== mount) return;
      const selected = state.sessions.find((item) => item.id === state.currentId);
      const next = selected || state.sessions.find((item) => item.status === "open" && item.origin === "auto") || state.sessions[0];
      if (!next) { notice("选择或新建会话后，点击「连接会话」进入 MiMoCode。"); renderHeader(); }
      else if (state.currentId !== next.id || !term.sessionId) await selectSession(next.id);
      else await loadDetail(next.id);
      if (state.active && state.mount === mount) startPoll();
    } catch (_) { if (state.active && state.mount === mount) notice("工作台暂不可达，请刷新重试。", true); }
  }
  function suspendAgentWorkbench() {
    state.active = false; ++state.mount; ++state.generation;
    stopPoll(); disconnectTerminal();
  }
  window.openAgentSettings = openAgentSettings;
  window.renderAgentWorkbench = renderAgentWorkbench;
  window.suspendAgentWorkbench = suspendAgentWorkbench;
  window.agentWorkbenchState = state;
})();
