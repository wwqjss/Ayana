/* Agent 工作台：三栏会话 / 对话 / 任务信息。使用 app.js 全局 api/el/showModal。 */
(function () {
  const appApi = (typeof window.api === "function") ? window.api.bind(window) : null;
  const appEl = (typeof window.el === "function") ? window.el : null;
  const appShowModal = (typeof window.showModal === "function") ? window.showModal : null;
  const appCloseModal = (typeof window.closeModal === "function") ? window.closeModal : null;

  const state = {
    sessions: [],
    currentId: "",
    detail: null,
    settings: null,
    pollTimer: null,
    lastEventId: 0,
    collapsedLeft: false,
    collapsedRight: false,
    // 实时流
    liveTimer: null,
    liveSince: 0,
    busy: false,
    busySince: 0,
    thinkingTimer: null,
    liveTexts: {},      // partId -> {text, kind, tool, done}
    liveOrder: [],
  };

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, attrs = {}, children = []) {
    if (appEl) return appEl(tag, attrs, children);
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else if (v !== undefined && v !== null) n.setAttribute(k, v);
    });
    (children || []).forEach((c) => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
    return n;
  }

  async function api(path, opts = {}) {
    if (appApi) return appApi(path, opts);
    const res = await fetch(path, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    try {
      return await res.json();
    } catch {
      return { ok: false, error: "bad_json" };
    }
  }

  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(Number(ts) * 1000);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString("zh-CN", { hour12: false });
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---- 左栏：会话列表 ----
  function renderSessionList() {
    const root = $("aw-session-list");
    if (!root) return;
    root.innerHTML = "";
    if (!state.sessions.length) {
      root.appendChild(el("div", { class: "aw-muted", text: "暂无会话" }));
      return;
    }
    const groups = [
      { key: "auto-open", label: "自动值班", items: [] },
      { key: "manual-open", label: "手动会话", items: [] },
      { key: "history", label: "历史", items: [] },
    ];
    state.sessions.forEach((s) => {
      if (s.status === "open" && s.origin === "auto") groups[0].items.push(s);
      else if (s.status === "open" && s.origin === "manual") groups[1].items.push(s);
      else groups[2].items.push(s);
    });
    groups.forEach((g) => {
      if (!g.items.length) return;
      root.appendChild(el("div", { class: "aw-group-label", text: g.label }));
      g.items.forEach((s) => {
        const active = s.id === state.currentId;
        const item = el("button", {
          type: "button",
          class: "aw-session-item" + (active ? " active" : ""),
          onclick: () => selectSession(s.id),
        }, [
          el("div", { class: "aw-session-title", text: s.title || s.id }),
          el("div", { class: "aw-session-meta", text: `${fmtTime(s.updated_at || s.created_at)} · ${s.incident_count || 0} 个工单` }),
        ]);
        if (s.archive_due_at > 0) {
          item.appendChild(el("div", { class: "aw-session-badge warn", text: "即将归档" }));
        } else if (s.status === "archived") {
          item.appendChild(el("div", { class: "aw-session-badge", text: "已归档" }));
        }
        root.appendChild(item);
      });
    });
  }

  // ---- 中栏：对话流 ----
  function renderMessages() {
    const root = $("aw-chat-scroll");
    if (!root) return;
    const d = state.detail;
    if (!d || !d.session) {
      root.innerHTML = '<div class="aw-chat-empty muted">左侧选择会话，或点击「+ 新建会话」开始运维任务。</div>';
      return;
    }
    const keepScroll = root.scrollTop;
    const nearBottom = root.scrollHeight - root.scrollTop - root.clientHeight < 80;
    root.innerHTML = "";
    const msgs = d.messages || [];
    if (!msgs.length) {
      root.appendChild(el("div", { class: "aw-chat-empty muted", text: "会话已创建，等待 Agent 响应…" }));
    }
    msgs.forEach((m) => {
      root.appendChild(renderMessage(m));
    });
    (d.events || []).forEach((ev) => {
      if (ev.type === "session_created" || ev.type === "incident_joined" || ev.type === "archive_scheduled") {
        root.appendChild(el("div", { class: "aw-sys-event", text: ev.title || ev.type }));
      }
    });
    if (nearBottom) root.scrollTop = root.scrollHeight;
    else root.scrollTop = keepScroll;
  }

  function renderMessage(m) {
    const role = m.role || "assistant";
    const kind = m.kind || "text";
    const cls = role === "user" ? "user" : role === "system" ? "system error" : "assistant";
    const wrap = el("div", { class: "aw-msg " + cls + " kind-" + kind });
    const roleLabel = role === "user" ? "你" : role === "system" ? "系统" : "Agent";
    wrap.appendChild(el("div", { class: "aw-msg-role", text: roleLabel }));
    if (m.title) wrap.appendChild(el("div", { class: "aw-msg-title", text: m.title }));
    const body = el("div", { class: "aw-msg-body" });
    const text = m.body || "";
    if (kind === "error" || role === "system") {
      body.appendChild(el("div", { class: "aw-msg-text", text: text || "（无输出）" }));
    } else if (text.length > 600) {
      const pre = el("pre", { class: "aw-log collapsed", text: text.slice(0, 600) + "…" });
      const btn = el("button", {
        type: "button",
        class: "btn ghost small",
        text: "展开完整日志",
        onclick: () => {
          pre.classList.toggle("collapsed");
          pre.textContent = pre.classList.contains("collapsed") ? text.slice(0, 600) + "…" : text;
          btn.textContent = pre.classList.contains("collapsed") ? "展开完整日志" : "折叠";
        },
      });
      body.appendChild(pre);
      body.appendChild(btn);
    } else if (kind === "mimo_result" || kind === "tool") {
      body.appendChild(el("pre", { class: "aw-log", text: text || "（无输出）" }));
    } else {
      body.appendChild(el("div", { class: "aw-msg-text", text: text }));
    }
    wrap.appendChild(body);
    wrap.appendChild(el("div", { class: "aw-msg-time", text: fmtTime(m.created_at) }));
    return wrap;
  }

  function renderHeader() {
    const d = state.detail;
    const title = $("aw-chat-title");
    const meta = $("aw-chat-meta");
    if (!title || !meta) return;
    if (!d || !d.session) {
      title.textContent = "选择或创建会话";
      meta.textContent = "";
      return;
    }
    const s = d.session;
    title.textContent = s.title || s.id;
    const bits = [
      s.origin === "auto" ? "自动值班" : "手动",
      s.status === "open" ? "进行中" : "已归档",
      fmtTime(s.created_at),
    ];
    if (s.archive_due_at > 0) bits.push("归档倒计时中");
    meta.textContent = bits.join(" · ");
  }

  // ---- 右栏 ----
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

  async function approveWrite(w) {
    const r = await api("/api/agent/pending-writes/approve", {
      method: "POST",
      body: JSON.stringify({ incident_id: w.incident_id, action_key: w.action_key }),
    });
    if (!r.ok) alert(r.message || r.error || "批准失败");
    await loadDetail(state.currentId);
  }

  async function rejectWrite(w) {
    const r = await api("/api/agent/pending-writes/reject", {
      method: "POST",
      body: JSON.stringify({ incident_id: w.incident_id, action_key: w.action_key, reason: "human_rejected" }),
    });
    if (!r.ok) alert(r.message || r.error || "拒绝失败");
    await loadDetail(state.currentId);
  }

  async function approveAction(a) {
    const r = await api(`/api/actions/${a.id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision: "execute_once" }),
    });
    if (!r.ok) alert(r.message || r.error || "批准失败");
    await loadDetail(state.currentId);
  }

  async function rejectAction(a) {
    const r = await api(`/api/actions/${a.id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason: "human_rejected" }),
    });
    if (!r.ok) alert(r.message || r.error || "拒绝失败");
    await loadDetail(state.currentId);
  }

  // ---- 数据加载 ----
  async function loadSessions() {
    const r = await api("/api/agent/sessions?limit=50");
    if (r && r.ok) {
      state.sessions = r.sessions || [];
      if (r.settings) state.settings = r.settings;
    }
    renderSessionList();
  }

  async function loadDetail(sid) {
    if (!sid) return;
    const r = await api("/api/agent/sessions/" + encodeURIComponent(sid));
    if (!r || !r.ok) return;
    state.detail = r;
    state.currentId = sid;
    renderHeader();
    renderMessages();
    renderRight();
    renderSessionList();
  }

  async function selectSession(sid) {
    if (term.sessionId && sid !== term.sessionId) {
      disconnectTerminal();
      if (term.visible) showTerminalPanel(false);
    }
    state.currentId = sid;
    state.lastEventId = 0;
    state.liveTexts = {};
    state.liveOrder = [];
    state.liveSince = Date.now() / 1000;
    renderSessionList();
    await loadDetail(sid);
  }

  async function createSession() {
    const title = prompt("会话标题（可留空）", "") || "";
    const promptText = prompt("初始任务描述（可留空，稍后在对话中输入）", "") || "";
    const r = await api("/api/agent/sessions", {
      method: "POST",
      body: JSON.stringify({ title, prompt: promptText }),
    });
    if (!r || !r.ok) {
      alert(r && (r.message || r.error) || "创建失败");
      return;
    }
    await loadSessions();
    await selectSession(r.session_id);
  }

  async function sendPrompt() {
    const input = $("aw-input");
    if (!input || !state.currentId) return;
    const text = input.value.trim();
    if (!text) return;
    const sid = state.currentId;
    input.value = "";
    // 乐观展示
    const scroll = $("aw-chat-scroll");
    if (scroll) {
      scroll.appendChild(el("div", { class: "aw-msg user pending" }, [
        el("div", { class: "aw-msg-role", text: "你" }),
        el("div", { class: "aw-msg-text", text }),
        el("div", { class: "aw-msg-time", text: "已发送" }),
      ]));
      scroll.scrollTop = scroll.scrollHeight;
    }
    // 不阻塞输入框；按钮变停止
    setBusy(true);
    try {
      const r = await api(`/api/agent/sessions/${encodeURIComponent(sid)}/prompt`, {
        method: "POST",
        body: JSON.stringify({ prompt: text }),
      });
      if (!r || !r.ok) {
        const msg = (r && (r.message || r.error)) || "发送失败";
        if (scroll) {
          scroll.appendChild(el("div", { class: "aw-msg system error" }, [
            el("div", { class: "aw-msg-role", text: "系统" }),
            el("div", { class: "aw-msg-title", text: "发送失败" }),
            el("div", { class: "aw-msg-text", text: msg }),
          ]));
          scroll.scrollTop = scroll.scrollHeight;
        }
        setBusy(false);
      } else {
        state.liveSince = Date.now();
        startLive();
        await loadDetail(sid);
      }
    } catch (e) {
      if (scroll) {
        scroll.appendChild(el("div", { class: "aw-msg system error" }, [
          el("div", { class: "aw-msg-role", text: "系统" }),
          el("div", { class: "aw-msg-text", text: "网络错误：" + (e && e.message ? e.message : e) }),
        ]));
      }
      setBusy(false);
    }
  }

  function setBusy(on) {
    state.busy = !!on;
    const btn = $("aw-send");
    if (!btn) return;
    if (on) {
      state.busySince = Date.now();
      btn.textContent = "停止";
      btn.classList.add("danger");
      btn.onclick = abortCurrent;
    } else {
      btn.textContent = "发送";
      btn.classList.remove("danger");
      btn.onclick = sendPrompt;
      if (state.thinkingTimer) clearInterval(state.thinkingTimer);
      state.thinkingTimer = null;
    }
  }

  async function abortCurrent() {
    if (!state.currentId) return;
    try {
      await api(`/api/agent/sessions/${encodeURIComponent(state.currentId)}/abort`, {
        method: "POST",
        body: JSON.stringify({}),
      });
    } catch (e) { /* ignore */ }
    setBusy(false);
    renderStatusLine("已停止");
    await loadDetail(state.currentId);
  }

  function renderStatusLine(text) {
    let bar = $("aw-status-bar");
    const head = $("aw-chat-head");
    if (!head) return;
    if (!bar) {
      bar = el("div", { id: "aw-status-bar", class: "aw-status-bar" });
      head.appendChild(bar);
    }
    if (!text) {
      bar.classList.add("hidden");
      bar.textContent = "";
      return;
    }
    bar.classList.remove("hidden");
    bar.textContent = text;
  }

  function startLive() {
    stopLive();
    state.liveSince = state.liveSince || Date.now();
    // 计时器：正在思考 Ns
    state.thinkingTimer = setInterval(() => {
      if (!state.busy) return;
      const sec = Math.round((Date.now() - state.busySince) / 1000);
      const last = state.liveOrder.length ? state.liveOrder[state.liveOrder.length - 1] : null;
      const hint = last && last.tool ? `正在执行 ${last.tool}` : "正在思考";
      renderStatusLine(`${hint}  ${sec}s`);
    }, 1000);
    renderStatusLine("正在思考  0s");
    state.liveTimer = setInterval(pullLiveEvents, 1000);
    pullLiveEvents();
  }

  function stopLive() {
    if (state.liveTimer) clearInterval(state.liveTimer);
    state.liveTimer = null;
    if (state.thinkingTimer) clearInterval(state.thinkingTimer);
    state.thinkingTimer = null;
  }

  async function pullLiveEvents() {
    try {
      const r = await api(`/api/agent/events?after=${encodeURIComponent(state.liveSince || 0)}`);
      if (!r || !r.ok) return;
      state.liveSince = r.server_time || Date.now() / 1000;
      const evs = r.events || [];
      let touched = false;
      evs.forEach((ev) => {
        if (ev.kind === "status") {
          if (ev.status === "busy") {
            if (!state.busy) setBusy(true);
          } else if (ev.status && ev.status !== "busy") {
            setBusy(false);
            renderStatusLine(ev.status === "idle" ? "" : ev.status);
            touched = true;
          }
        } else if (ev.kind === "delta" && ev.delta) {
          const p = state.liveTexts[ev.part_id] || { text: "", kind: "text", tool: "" };
          p.text += ev.delta;
          state.liveTexts[ev.part_id] = p;
          if (!state.liveOrder.find((x) => x.id === ev.part_id)) {
            state.liveOrder.push({ id: ev.part_id, kind: p.kind, tool: p.tool, msg: ev.message_id });
          }
          renderLiveStream();
          touched = true;
        } else if (ev.kind === "part") {
          const p = state.liveTexts[ev.part_id] || {};
          p.kind = ev.part_type || p.kind || "text";
          p.tool = ev.tool || p.tool || "";
          if (ev.text) p.text = ev.text;
          p.done = !!(ev.state && String(ev.state).indexOf("end") >= 0) || p.kind === "step-finish";
          state.liveTexts[ev.part_id] = p;
          if (!state.liveOrder.find((x) => x.id === ev.part_id)) {
            state.liveOrder.push({ id: ev.part_id, kind: p.kind, tool: p.tool, msg: ev.message_id });
          }
          renderLiveStream();
          touched = true;
        }
      });
      if (touched && state.busy) {
        const scroll = $("aw-chat-scroll");
        if (scroll) scroll.scrollTop = scroll.scrollHeight;
      }
      // 无事件且超过 5 分钟则解除 busy，防卡死
      if (state.busy && Date.now() - state.busySince > 5 * 60 * 1000) {
        setBusy(false);
        renderStatusLine("超时未完成，可重试");
      }
    } catch (e) { /* poll ignore */ }
  }

  function renderLiveStream() {
    let box = $("aw-live-stream");
    const scroll = $("aw-chat-scroll");
    if (!scroll) return;
    if (!box) {
      box = el("div", { id: "aw-live-stream", class: "aw-live-stream" });
      scroll.appendChild(box);
    }
    box.innerHTML = "";
    state.liveOrder.slice(-6).forEach((item) => {
      const p = state.liveTexts[item.id] || {};
      const kind = p.kind || item.kind || "text";
      const card = el("div", { class: "aw-live-card k-" + kind });
      if (kind === "step-start") {
        card.appendChild(el("div", { class: "aw-live-title", text: "· 开始一步" }));
      } else if (kind === "step-finish") {
        card.appendChild(el("div", { class: "aw-live-title", text: "· 完成一步" }));
      } else if (kind === "reasoning") {
        card.appendChild(el("div", { class: "aw-live-title", text: "思考" }));
        card.appendChild(el("div", { class: "aw-live-text", text: (p.text || "").slice(0, 500) || "…" }));
      } else if (kind === "tool" || kind === "tool-call" || kind === "tool_use") {
        card.appendChild(el("div", { class: "aw-live-title", text: "工具 " + (p.tool || "") }));
        const pre = el("pre", { class: "aw-log collapsed", text: (p.text || "").slice(0, 400) || "…" });
        card.appendChild(pre);
      } else {
        card.appendChild(el("div", { class: "aw-live-title", text: "Agent" }));
        card.appendChild(el("div", { class: "aw-live-text", text: p.text || "…" }));
      }
      box.appendChild(card);
    });
    scroll.scrollTop = scroll.scrollHeight;
  }

  async function archiveCurrent() {
    if (!state.currentId) return;
    if (!confirm("归档该会话？历史仍可查看。")) return;
    const r = await api(`/api/agent/sessions/${encodeURIComponent(state.currentId)}/archive`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    if (!r || !r.ok) alert((r && (r.message || r.error)) || "归档失败");
    await loadSessions();
    await loadDetail(state.currentId);
  }

  // ---- Agent 设置 ----
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

  // ---- 轮询实时更新 ----
  function startPoll() {
    stopPoll();
    state.pollTimer = setInterval(async () => {
      if (state.currentId) await loadDetail(state.currentId);
      await loadSessions();
    }, 15000);
    startLive();
  }

  function stopPoll() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
    stopLive();
  }

  // ---- 布局 ----
  function toggleLeft() {
    state.collapsedLeft = !state.collapsedLeft;
    const left = $("aw-left");
    const wb = $("agent-workbench");
    if (left) left.classList.toggle("collapsed", state.collapsedLeft);
    if (wb) wb.classList.toggle("left-collapsed", state.collapsedLeft);
  }

  function toggleRight() {
    state.collapsedRight = !state.collapsedRight;
    const right = $("aw-right");
    const wb = $("agent-workbench");
    if (right) right.classList.toggle("collapsed", state.collapsedRight);
    if (wb) wb.classList.toggle("right-collapsed", state.collapsedRight);
  }

  function bind() {
    const nb = $("aw-new-session");
    if (nb) nb.onclick = createSession;
    const sb = $("aw-send");
    if (sb) sb.onclick = sendPrompt;
    const input = $("aw-input");
    if (input) {
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
          e.preventDefault();
          sendPrompt();
        }
      });
    }
    const st = $("aw-settings-btn");
    if (st) st.onclick = openAgentSettings;
    const tl = $("aw-toggle-left");
    if (tl) tl.onclick = toggleLeft;
    const tr = $("aw-toggle-right");
    if (tr) tr.onclick = toggleRight;
    const head = $("aw-chat-head");
    if (head) {
      head.addEventListener("dblclick", () => {
        if (state.currentId && confirm("归档当前会话？")) archiveCurrent();
      });
    }
    const tb = $("aw-term-btn");
    if (tb) tb.onclick = toggleTerminal;
    window.addEventListener("resize", () => {
      if (term.visible) fitTerminal();
    });
    const acq = $("aw-term-acquire");
    if (acq) acq.onclick = acquireControl;
    const rel = $("aw-term-release");
    if (rel) rel.onclick = releaseControl;
    const reconn = $("aw-term-reconnect");
    if (reconn) reconn.onclick = () => connectTerminal();
  }

  async function renderAgentWorkbench() {
    bind();
    await loadSessions();
    if (!state.currentId && state.sessions.length) {
      const open = state.sessions.find((s) => s.status === "open") || state.sessions[0];
      if (open) await selectSession(open.id);
    } else if (state.currentId) {
      await loadDetail(state.currentId);
    }
    startPoll();
  }


  // ---- 原生 TUI 终端（观察默认 / 控制权显式接管）----
  const term = {
    ws: null,
    xterm: null,
    fit: null,
    connectionId: "",
    control: false,
    ready: false,
    visible: false,
    pingTimer: null,
    sessionId: "",
    onDataBound: false,
    onResizeBound: false,
  };

  function ensureXterm() {
    const T = window.Terminal || (window.xterm && window.xterm.Terminal);
    const Fit = window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon);
    if (!T) {
      renderStatusLine('xterm.js 未加载，终端不可用。请强刷页面后重试。');
      return null;
    }
    if (!term.xterm) {
      term.xterm = new T({
        cursorBlink: true,
        fontSize: 12,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        theme: { background: "#0b0d11", foreground: "#c9d1d9", cursor: "#6cb6ff" },
        scrollback: 5000,
        convertEol: true,
        disableStdin: true,
      });
      if (Fit) {
        term.fit = new Fit();
        term.xterm.loadAddon(term.fit);
      }
    }
    return term.xterm;
  }

  function fitTerminal() {
    if (!term.fit || !term.xterm) return;
    try {
      term.fit.fit();
    } catch (e) { /* ignore */ }
    if (term.xterm && term.ws && term.ws.readyState === 1 && term.control) {
      try {
        term.ws.send(JSON.stringify({ type: "resize", cols: term.xterm.cols, rows: term.xterm.rows }));
      } catch (e) { /* ignore */ }
    }
  }

  function showTerminalPanel(show) {
    const panel = $("aw-terminal");
    const chat = $("aw-chat-scroll");
    const composer = $("aw-composer");
    const center = $("aw-center");
    if (!panel) return;
    term.visible = !!show;
    panel.classList.toggle("hidden", !show);
    if (center) center.classList.toggle("terminal-mode", !!show);
    if (chat) chat.classList.toggle("hidden", show);
    if (composer) composer.classList.toggle("hidden", show);
    const btn = $("aw-term-btn");
    if (btn) btn.textContent = show ? "返回对话" : "原生终端";
    if (show) {
      const t = ensureXterm();
      const host = $("aw-term-host");
      if (t && host && !t.element) t.open(host);
      // layout settles after flex show; fit twice to avoid a short first frame
      requestAnimationFrame(() => {
        fitTerminal();
        setTimeout(fitTerminal, 60);
      });
    }
    updateTermUi();
  }

  function updateTermUi() {
    const status = $("aw-term-status");
    if (status) {
      const bits = [];
      if (!term.visible) bits.push("终端未打开");
      else if (term.ready) bits.push("已接入");
      else bits.push("未接入");
      bits.push(term.control ? "控制中" : "观察");
      status.textContent = bits.join(" · ");
      status.classList.toggle("control", !!term.control);
      status.classList.toggle("ready", !!term.ready);
    }
    const acq = $("aw-term-acquire");
    const rel = $("aw-term-release");
    const reconn = $("aw-term-reconnect");
    if (acq) acq.classList.toggle("hidden", !(term.visible && term.ready && !term.control));
    if (rel) rel.classList.toggle("hidden", !(term.visible && term.control));
    if (reconn) reconn.classList.toggle("hidden", !(term.visible && !term.ready));
  }

  function disconnectTerminal() {
    if (term.pingTimer) {
      clearInterval(term.pingTimer);
      term.pingTimer = null;
    }
    if (term.ws) {
      try { term.ws.onclose = null; term.ws.onmessage = null; term.ws.close(); } catch (e) {}
      term.ws = null;
    }
    term.ready = false;
    term.control = false;
    term.connectionId = "";
    updateTermUi();
  }

  function termWriteLine(msg) {
    const t = term.xterm;
    if (t) {
      try { t.writeln("\r\n[" + msg + "]"); } catch (e) {}
    }
  }

  function bindTermIo() {
    const t = ensureXterm();
    if (!t) return;
    if (!term.onDataBound) {
      term.onDataBound = true;
      t.onData((data) => {
        if (!term.ws || term.ws.readyState !== 1) return;
        if (!term.control) return;
        term.ws.send(JSON.stringify({ type: "input", data }));
      });
    }
    if (!term.onResizeBound) {
      term.onResizeBound = true;
      t.onResize(({ cols, rows }) => {
        if (!term.ws || term.ws.readyState !== 1 || !term.control) return;
        try { term.ws.send(JSON.stringify({ type: "resize", cols, rows })); } catch (e) {}
      });
    }
    if (t.options) t.options.disableStdin = !term.control;
  }

  async function connectTerminal() {
    const sid = state.currentId;
    if (!sid) return;
    term.sessionId = sid;
    disconnectTerminal();
    const t = ensureXterm();
    if (t) {
      try { t.clear(); } catch (e) {}
    }
    let prep;
    try {
      prep = await api(`/api/agent/sessions/${encodeURIComponent(sid)}/terminal`, {
        method: "POST",
        body: JSON.stringify({}),
      });
    } catch (e) {
      termWriteLine("原生运行服务不可达：" + (e && e.message ? e.message : e));
      updateTermUi();
      return;
    }
    if (!prep || !prep.ok) {
      const msg = (prep && (prep.message || prep.error)) || "原生运行服务暂不可用，任务和历史记录已保留。";
      termWriteLine(msg);
      renderStatusLine("接入失败: " + msg);
      updateTermUi();
      return;
    }
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/ws/agent-terminal?session_id=${encodeURIComponent(sid)}`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      termWriteLine("无法建立终端连接");
      updateTermUi();
      return;
    }
    term.ws = ws;
    ws.binaryType = "arraybuffer";
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "ready") {
            term.connectionId = msg.connection_id || "";
            term.control = !!msg.control;
            term.ready = true;
            bindTermIo();
            updateTermUi();
            fitTerminal();
            setTimeout(fitTerminal, 80);
            return;
          }
          if (msg.type === "control") {
            term.control = !!msg.control;
            if (term.xterm && term.xterm.options) term.xterm.options.disableStdin = !term.control;
            updateTermUi();
            return;
          }
        } catch (e) { /* ignore */ }
        return;
      }
      if (term.xterm && ev.data instanceof ArrayBuffer) {
        term.xterm.write(new Uint8Array(ev.data));
      }
    };
    ws.onclose = (ev) => {
      term.ready = false;
      term.control = false;
      const code = ev && ev.code ? ev.code : 0;
      if (code === 1013) termWriteLine("视图连接已断开，后台任务继续执行。点击「重新接入」回到同一任务。");
      else if (code === 4403) termWriteLine("会话权限已变更，连接已关闭。");
      else if (term.visible) termWriteLine("连接已关闭。任务仍在运行，可重新接入。");
      updateTermUi();
    };
    ws.onerror = () => {};
    term.pingTimer = setInterval(() => {
      if (term.ws && term.ws.readyState === 1) {
        try { term.ws.send(JSON.stringify({ type: "ping" })); } catch (e) {}
      }
    }, 15000);
    updateTermUi();
  }

  async function openNativeTerminal() {
    const sid = state.currentId;
    if (!sid) {
      alert("请先选择会话");
      return;
    }
    const d = state.detail;
    const session = d && d.session;
    if (session && session.status !== "open") {
      if (!session.remote_session_id) {
        alert("该历史会话没有原生会话绑定，可在右侧查看关联记录。");
        return;
      }
      if (!confirm("会话已归档。续接为手动会话后才能接入终端，是否继续？")) return;
      const r = await api(`/api/agent/sessions/${encodeURIComponent(sid)}/reopen`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      if (!r || !r.ok) {
        alert((r && (r.message || r.error)) || "续接失败");
        return;
      }
      await loadSessions();
      await loadDetail(sid);
    }
    showTerminalPanel(true);
    await connectTerminal();
  }

  async function acquireControl() {
    if (!term.connectionId || !state.currentId) return;
    const r = await api(`/api/agent/sessions/${encodeURIComponent(state.currentId)}/terminal/control`, {
      method: "POST",
      body: JSON.stringify({ action: "acquire", connection_id: term.connectionId }),
    });
    if (!r || !r.ok) {
      alert((r && (r.message || r.error)) || "无法取得控制权，可能已由其他窗口持有。");
      return;
    }
    term.control = true;
    if (term.xterm && term.xterm.options) term.xterm.options.disableStdin = false;
    updateTermUi();
    if (term.xterm) term.xterm.focus();
  }

  async function releaseControl() {
    if (!term.connectionId || !state.currentId) return;
    try {
      await api(`/api/agent/sessions/${encodeURIComponent(state.currentId)}/terminal/control`, {
        method: "POST",
        body: JSON.stringify({ action: "release", connection_id: term.connectionId }),
      });
    } catch (e) { /* ignore */ }
    term.control = false;
    if (term.xterm && term.xterm.options) term.xterm.options.disableStdin = true;
    updateTermUi();
  }

  function toggleTerminal() {
    if (term.visible) {
      disconnectTerminal();
      showTerminalPanel(false);
    } else {
      openNativeTerminal();
    }
  }

  window.renderAgentWorkbench = renderAgentWorkbench;
  window.agentWorkbenchState = state;
})();
