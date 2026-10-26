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
    state.currentId = sid;
    state.lastEventId = 0;
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
    // 乐观展示用户消息
    const scroll = $("aw-chat-scroll");
    if (scroll) {
      const pending = el("div", { class: "aw-msg user pending" }, [
        el("div", { class: "aw-msg-role", text: "你" }),
        el("div", { class: "aw-msg-text", text }),
        el("div", { class: "aw-msg-time", text: "发送中…" }),
      ]);
      scroll.appendChild(pending);
      scroll.scrollTop = scroll.scrollHeight;
    }
    // 发送中禁用
    const btn = $("aw-send");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "发送中…";
    }
    try {
      const r = await api(`/api/agent/sessions/${encodeURIComponent(sid)}/prompt`, {
        method: "POST",
        body: JSON.stringify({ prompt: text }),
      });
      if (!r || !r.ok) {
        const msg = (r && (r.message || r.error)) || "发送失败";
        // 内联错误气泡
        if (scroll) {
          const errBox = el("div", { class: "aw-msg system error" }, [
            el("div", { class: "aw-msg-role", text: "系统" }),
            el("div", { class: "aw-msg-title", text: "发送失败" }),
            el("div", { class: "aw-msg-text", text: msg }),
          ]);
          scroll.appendChild(errBox);
          scroll.scrollTop = scroll.scrollHeight;
        }
      }
      // 无论成败都刷新，以拉取已落库的消息/错误
      await loadDetail(sid);
      await loadSessions();
    } catch (e) {
      if (scroll) {
        scroll.appendChild(el("div", { class: "aw-msg system error" }, [
          el("div", { class: "aw-msg-role", text: "系统" }),
          el("div", { class: "aw-msg-text", text: "网络错误：" + (e && e.message ? e.message : e) }),
        ]));
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "发送";
      }
    }
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
    }, 8000);
  }

  function stopPoll() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
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

  window.renderAgentWorkbench = renderAgentWorkbench;
  window.agentWorkbenchState = state;
})();
