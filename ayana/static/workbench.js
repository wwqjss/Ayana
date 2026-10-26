/* One native MiMoCode workspace; Ayana renders business state only. */
(function () {
  const appApi = typeof window.api === "function" ? window.api.bind(window) : null;
  const appEl = typeof window.el === "function" ? window.el : null;
  const appShowModal = typeof window.showModal === "function" ? window.showModal : null;
  const appCloseModal = typeof window.closeModal === "function" ? window.closeModal : null;
  const state = {
    sessions: [], currentId: "", detail: null, settings: null,
    active: false, generation: 0, mount: 0, pollTimer: null, polling: false,
    collapsedLeft: false, collapsedRight: false,
  };
  const term = {
    ws: null, xterm: null, fit: null, observer: null, connectionId: "",
    control: false, ready: false, rendered: false, connecting: false,
    sessionId: "", attempt: 0, pingTimer: null, paintTimer: null,
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

  function notice(text = "", failure = false) {
    const box = $("aw-term-notice");
    if (!box) return;
    box.textContent = text;
    box.classList.toggle("hidden", !text);
    box.classList.toggle("error", failure);
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
        if (item.archive_due_at > 0) button.appendChild(el("div", { class: "aw-session-badge warn", text: "归档缓冲中" }));
        else if (item.status === "archived") button.appendChild(el("div", { class: "aw-session-badge", text: "已归档" }));
        root.appendChild(button);
      });
    });
  }
  function renderHeader() {
    const session = state.detail && state.detail.session;
    const title = $("aw-chat-title"), meta = $("aw-chat-meta");
    if (title) title.textContent = session ? session.title || session.id : "MiMoCode 工作台";
    if (meta) meta.textContent = session ? [session.origin === "auto" ? "自动值班" : "手动会话", session.status === "open" ? "进行中" : "已归档", session.archive_due_at > 0 ? "归档缓冲中" : ""].filter(Boolean).join(" · ") : "";
    updateTermUi();
  }
  function renderRight() {
    const d = state.detail;
    const prog = $("aw-progress");
    const incs = $("aw-incidents");
    const pend = $("aw-pending");
    const res = $("aw-results");
    if (!prog) return;
    if (!d) {
      prog.textContent = "—";
      if (incs) incs.innerHTML = "";
      if (pend) pend.innerHTML = "";
      if (res) res.innerHTML = "";
      return;
    }
    const incidents = d.incidents || [];
    const openN = incidents.filter((i) => i.status === "open").length;
    prog.textContent = incidents.length
      ? `关联 ${incidents.length} 个工单 · 进行中 ${openN}`
      : "无关联工单";
    if (incs) {
      incs.innerHTML = "";
      if (!incidents.length) incs.appendChild(el("div", { class: "aw-muted", text: "暂无" }));
      incidents.forEach((i) => {
        incs.appendChild(el("div", { class: "aw-inc-row" }, [
          el("div", { class: "aw-inc-title", text: i.title || i.incident_id }),
          el("div", { class: "aw-inc-meta", text: `${i.severity || ""} · ${i.status || ""} · ${i.asset_id || ""}` }),
        ]));
      });
    }
    if (pend) {
      pend.innerHTML = "";
      const writes = d.pending_writes || [];
      const actions = d.pending_actions || [];
      if (!writes.length && !actions.length) {
        pend.appendChild(el("div", { class: "aw-muted", text: "无待审批" }));
      }
      writes.forEach((w) => {
        const params = w.params || {};
        const row = el("div", { class: "aw-pend-card" }, [
          el("div", { class: "aw-pend-title", text: params.command || w.action_key || "写操作" }),
          el("div", { class: "aw-pend-meta", text: `${w.target || ""} · ${w.incident_id || ""}` }),
          el("div", { class: "aw-pend-actions" }, [
            el("button", {
              type: "button", class: "btn primary small", text: "批准",
              onclick: () => approveWrite(w),
            }),
            el("button", {
              type: "button", class: "btn ghost small", text: "拒绝",
              onclick: () => rejectWrite(w),
            }),
          ]),
        ]);
        pend.appendChild(row);
      });
      actions.forEach((a) => {
        const row = el("div", { class: "aw-pend-card" }, [
          el("div", { class: "aw-pend-title", text: `${a.capability || ""} @ ${a.object_id || ""}` }),
          el("div", { class: "aw-pend-meta", text: a.reason || a.incident_id || "" }),
          el("div", { class: "aw-pend-actions" }, [
            el("button", {
              type: "button", class: "btn primary small", text: "批准并执行",
              onclick: () => approveAction(a),
            }),
            el("button", {
              type: "button", class: "btn ghost small", text: "拒绝",
              onclick: () => rejectAction(a),
            }),
          ]),
        ]);
        pend.appendChild(row);
      });
      pend.querySelectorAll("button").forEach((button) => { button.disabled = !manageable() || !openSession(); });
    }
    if (res) {
      res.innerHTML = "";
      const evs = (d.events || []).filter((e) =>
        ["tool_call", "tool_result", "action_proposed", "session_archived"].includes(e.type)
      );
      if (!evs.length) res.appendChild(el("div", { class: "aw-muted", text: "暂无" }));
      evs.slice(-8).forEach((e) => {
        res.appendChild(el("div", { class: "aw-res-row", text: `${fmtTime(e.created_at)} ${e.title || e.type}` }));
      });
    }
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
  function approveWrite(write) {
    if (pendingDecisions.has("write:" + write.action_key)) return;
    if (!confirm("批准该操作？执行仍受 Ayana 权限与审计约束。")) return;
    return decide("/api/agent/pending-writes/approve", { incident_id: write.incident_id, action_key: write.action_key }, "write:" + write.action_key);
  }
  function rejectWrite(write) {
    return decide("/api/agent/pending-writes/reject", { incident_id: write.incident_id, action_key: write.action_key, reason: "human_rejected" }, "write:" + write.action_key);
  }
  function approveAction(action) {
    if (pendingDecisions.has("action:" + action.id)) return;
    const totp = prompt("动态验证码（若账号已启用 2FA，否则留空）:", "");
    if (totp === null) return;
    return decide("/api/actions/" + encodeURIComponent(action.id) + "/decision", { decision: "execute_once", totp }, "action:" + action.id);
  }
  function rejectAction(action) {
    return decide("/api/actions/" + encodeURIComponent(action.id) + "/reject", { reason: "human_rejected" }, "action:" + action.id);
  }
  async function loadSessions() {
    const mount = state.mount;
    const result = await api("/api/agent/sessions?limit=100");
    if (!state.active || state.mount !== mount) return false;
    if (!result || !result.ok) return false;
    state.sessions = result.sessions || [];
    if (result.settings) state.settings = result.settings;
    renderSessionList();
    return true;
  }
  async function loadDetail(sid, generation = state.generation) {
    if (!sid) return false;
    const result = await api(sessionPath(sid));
    if (!current(sid, generation)) return false;
    if (!result || !result.ok) {
      notice(result && (result.message || result.error) || "无法读取会话。", true);
      return false;
    }
    state.detail = result;
    renderHeader(); renderRight(); renderSessionList();
    return true;
  }
  async function selectSession(sid) {
    const generation = ++state.generation;
    disconnectTerminal();
    state.currentId = sid;
    state.detail = null;
    renderHeader(); renderRight(); renderSessionList();
    notice("正在读取会话…");
    try {
      if (await loadDetail(sid, generation)) await connectTerminal(sid, generation);
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
    appShowModal("新建手动会话", [el("div", { class: "form-col" }, [input, el("p", { class: "aw-muted", text: "创建后直接进入 MiMoCode，在原生输入框中开始任务。" }), error, save])]);
  }
  async function abortCurrent() {
    const sid = state.currentId, generation = state.generation;
    if (!sid || !confirm("停止当前 MiMo 任务？断开页面无需停止任务。")) return;
    try {
      const result = await api(sessionPath(sid) + "/abort", { method: "POST", body: "{}" });
      if (!current(sid, generation)) return;
      if (!result || !result.ok) notice(result && (result.message || result.error) || "停止请求未确认。", true);
      else notice("已发送停止请求，正在核对任务状态。");
      await loadDetail(sid, generation);
    } catch (_) { if (current(sid, generation)) notice("停止请求未确认，请检查任务状态。", true); }
  }
  async function archiveCurrent() {
    const sid = state.currentId, generation = state.generation;
    if (!sid || !confirm("归档当前会话？仍有运行任务或待审批时将保留会话。")) return;
    const result = await api(sessionPath(sid) + "/archive", { method: "POST", body: "{}" });
    if (!current(sid, generation)) return;
    if (!result || !result.ok) notice(result && (result.message || result.error) || "当前会话暂不能归档。", true);
    await loadSessions(); await loadDetail(sid, generation);
  }
  async function reopenCurrent() {
    const sid = state.currentId, generation = state.generation;
    if (!sid || !confirm("将此历史会话续接为手动会话？自动值班会话继续独立运行。")) return;
    const result = await api(sessionPath(sid) + "/reopen", { method: "POST", body: "{}" });
    if (!current(sid, generation)) return;
    if (!result || !result.ok) { notice(result && (result.message || result.error) || "续接失败。", true); return; }
    await loadSessions();
    if (current(sid, generation)) await selectSession(sid);
  }
  async function openAgentSettings() {
    const r = await api("/api/agent/settings");
    const settings = (r && r.settings) || {};
    const wrap = el("div", { class: "form-col" });
    const approval = el("input", { type: "checkbox", id: "agent-require-approval" });
    approval.checked = settings.require_human_approval !== false;
    wrap.appendChild(el("label", { class: "form-row" }, [
      approval,
      el("span", { text: "需要人工审批（写操作等待批准后执行）" }),
    ]));
    const delay = el("input", { type: "number", min: "30", max: "3600", value: String(settings.archive_delay_sec || 300) });
    wrap.appendChild(el("label", { class: "form-row" }, [
      el("span", { text: "归档倒计时（秒）" }),
      delay,
    ]));
    const invRole = el("input", { type: "text", value: settings.ssh_investigate_role || "read", placeholder: "read" });
    const exeRole = el("input", { type: "text", value: settings.ssh_execute_role || "write", placeholder: "write" });
    wrap.appendChild(el("label", { class: "form-row" }, [el("span", { text: "调查 SSH 角色" }), invRole]));
    wrap.appendChild(el("label", { class: "form-row" }, [el("span", { text: "执行 SSH 角色" }), exeRole]));

    const eps = (r && r.ssh_endpoints) || [];
    const epBox = el("div", { class: "aw-muted" });
    epBox.textContent = eps.length
      ? "当前 SSH 端点：" + eps.map((e) => `${e.asset_id}/${e.role}=${e.username}`).join("，")
      : "未配置 SSH 端点（请在「连接」页配置）";
    wrap.appendChild(epBox);

    const save = el("button", {
      type: "button",
      class: "btn primary",
      text: "保存设置",
      onclick: async () => {
        const body = {
          require_human_approval: approval.checked,
          archive_delay_sec: Number(delay.value) || 300,
          ssh_investigate_role: invRole.value || "read",
          ssh_execute_role: exeRole.value || "write",
        };
        const res = await api("/api/agent/settings", { method: "POST", body: JSON.stringify(body) });
        if (!res.ok) alert(res.message || res.error || "保存失败");
        else if (appCloseModal) appCloseModal();
        else if (appShowModal) appShowModal("已保存", [el("p", { text: "Agent 设置已更新" })]);
      },
    });
    wrap.appendChild(save);
    if (appShowModal) {
      appShowModal("Agent 设置", [wrap]);
    } else {
      alert("设置面板不可用");
    }
  }


  function updateTermUi() {
    const status = $("aw-term-status");
    if (status) {
      status.textContent = term.connecting ? "接入中" : term.ready && term.rendered ? term.control ? "控制中" : "观察" : term.ready ? "等待原生画面" : "未接入";
      status.classList.toggle("ready", term.ready && term.rendered);
      status.classList.toggle("control", term.control);
    }
    const toggle = (id, visible) => { const node = $(id); if (node) node.classList.toggle("hidden", !visible); };
    const admin = manageable(), open = openSession();
    toggle("aw-term-acquire", term.ready && !term.control && admin && open);
    toggle("aw-term-release", term.ready && term.control);
    toggle("aw-term-reconnect", !!state.currentId && !term.connecting && !term.ready);
    toggle("aw-term-disconnect", term.ready || term.connecting);
    toggle("aw-term-stop", !!state.currentId && admin && open);
    toggle("aw-archive", !!state.currentId && admin && open);
    toggle("aw-reopen", !!state.detail && admin && !open);
  }
  function fitTerminal() {
    if (!term.xterm || !state.active) return;
    try { if (term.fit) term.fit.fit(); } catch (_) {}
    const socket = term.ws;
    if (socket && socket.readyState === 1 && term.ready) {
      socket.send(JSON.stringify({ type: "resize", cols: Math.max(40, term.xterm.cols || 80), rows: Math.max(12, term.xterm.rows || 24) }));
    }
  }
  function disconnectTerminal() {
    ++term.attempt;
    if (term.pingTimer) clearInterval(term.pingTimer);
    if (term.paintTimer) clearTimeout(term.paintTimer);
    term.pingTimer = term.paintTimer = null;
    if (term.observer) term.observer.disconnect();
    term.observer = null;
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
    term.control = term.ready = term.rendered = term.connecting = false;
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
    });
    term.xterm = terminal;
    if (Fit) { term.fit = new Fit(); terminal.loadAddon(term.fit); }
    terminal.open($("aw-term-host"));
    socket = new WebSocket(`${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/agent-terminal?session_id=${encodeURIComponent(sid)}`);
    term.ws = socket; socket.binaryType = "arraybuffer";
    } catch (_) {
      disconnectTerminal(); notice("无法创建原生视图，请刷新后重试。", true); return;
    }
    terminal.onData((data) => {
      if (!valid() || term.ws !== socket || !term.ready || socket.readyState !== 1) return;
      const reply = /^(?:\x1b\[(?:[?>]?[0-9;]*c|[0-9]+;[0-9]+R|[0-9;]+t|\?[0-9]+u)|\x1b\](?:10|11);rgb:[0-9a-f/]+(?:\x07|\x1b\\))$/i;
      if (data.length <= 256 && reply.test(data)) {
        socket.send(JSON.stringify({ type: "terminal_response", data }));
        return;
      }
      if (!term.control) return;
      socket.send(JSON.stringify({ type: "input", data }));
    });
    terminal.onResize(({ cols, rows }) => {
      if (valid() && term.ws === socket && term.ready && socket.readyState === 1) socket.send(JSON.stringify({ type: "resize", cols, rows }));
    });
    const frame = () => valid() && term.ws === socket;
    socket.onmessage = (event) => {
      if (!frame()) return;
      if (typeof event.data === "string") {
        let message;
        try { message = JSON.parse(event.data); } catch (_) { return; }
        if (message.type === "ready") {
          term.connectionId = message.connection_id || "";
          term.control = !!message.control;
          term.ready = true; term.connecting = false;
          notice(term.rendered ? "" : "已附着，正在等待 MiMoCode 原生画面…");
          updateTermUi(); fitTerminal();
          term.paintTimer = setTimeout(() => {
            if (frame() && !term.rendered) notice("尚未收到原生画面，请重新接入。后台任务未停止。", true);
          }, 12000);
        } else if (message.type === "control") {
          term.control = !!message.control; updateTermUi();
        } else if (message.type === "error") {
          notice(message.message || message.error || "原生连接异常，请核对任务状态。", true);
        }
        return;
      }
      if (event.data instanceof ArrayBuffer && event.data.byteLength) {
        term.rendered = true;
        terminal.write(new Uint8Array(event.data));
        if (term.ready) notice("");
        updateTermUi();
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
    if (!term.ready || !connectionId || !manageable() || !openSession()) return;
    const button = $("aw-term-acquire");
    if (button && button.disabled) return;
    if (button) button.disabled = true;
    try {
      const result = await api(sessionPath(sid) + "/terminal/control", { method: "POST", body: JSON.stringify({ action: "acquire", connection_id: connectionId }) });
      if (!current(sid, generation) || term.attempt !== attempt || term.connectionId !== connectionId) return;
      if (!result || !result.ok) { notice(result && (result.message || result.error) || "无法取得控制权，可能已由其他窗口持有。", true); return; }
      term.control = true; updateTermUi(); notice("");
      if (term.xterm) term.xterm.focus();
      fitTerminal();
    } catch (_) { if (current(sid, generation) && term.attempt === attempt) notice("控制权请求未完成，请重新核对。", true); }
    finally { if (button) button.disabled = false; }
  }
  async function releaseControl() {
    const sid = state.currentId, generation = state.generation, attempt = term.attempt;
    const connectionId = term.connectionId;
    term.control = false; updateTermUi();
    if (!sid || !connectionId) return;
    try {
      const result = await api(sessionPath(sid) + "/terminal/control", { method: "POST", body: JSON.stringify({ action: "release", connection_id: connectionId }) });
      if (current(sid, generation) && term.attempt === attempt && (!result || !result.ok)) notice("释放请求未确认，键盘已在当前页面停用。", true);
    } catch (_) { if (current(sid, generation) && term.attempt === attempt) notice("释放请求未确认，键盘已在当前页面停用。", true); }
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
      "aw-term-disconnect": () => { disconnectTerminal(); notice("已离开当前视图，后台任务继续执行。"); },
      "aw-archive": archiveCurrent, "aw-reopen": reopenCurrent,
      "aw-toggle-left": () => toggleColumn("left"), "aw-toggle-right": () => toggleColumn("right"),
    };
    Object.entries(handlers).forEach(([id, callback]) => { const node = $(id); if (node) node.onclick = callback; });
    window.addEventListener("resize", fitTerminal);
    window.addEventListener("pagehide", suspendAgentWorkbench);
  }
  async function renderAgentWorkbench() {
    bind();
    if (!state.active) { state.active = true; ++state.mount; }
    const mount = state.mount;
    try {
      await loadSessions();
      if (!state.active || state.mount !== mount) return;
      const selected = state.sessions.find((item) => item.id === state.currentId);
      const next = selected || state.sessions.find((item) => item.status === "open" && item.origin === "auto") || state.sessions[0];
      if (!next) { notice("选择或新建会话，直接进入 MiMoCode。"); renderHeader(); }
      else if (state.currentId !== next.id || !term.sessionId) await selectSession(next.id);
      else await loadDetail(next.id);
      if (state.active && state.mount === mount) startPoll();
    } catch (_) { if (state.active && state.mount === mount) notice("工作台暂不可达，请刷新重试。", true); }
  }
  function suspendAgentWorkbench() {
    state.active = false; ++state.mount; ++state.generation;
    stopPoll(); disconnectTerminal();
  }
  window.renderAgentWorkbench = renderAgentWorkbench;
  window.suspendAgentWorkbench = suspendAgentWorkbench;
  window.agentWorkbenchState = state;
})();
