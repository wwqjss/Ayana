/* Ayana Web 控制台 */
const state = {
  csrf: "",
  user: null,
  tab: "overview",
  assets: [],
  caps: [],
};

function $(id) { return document.getElementById(id); }
function el(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) n.setAttribute(k, v);
  });
  (children || []).forEach((c) => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return n;
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
  const res = await fetch(path, {
    credentials: "same-origin",
    headers,
    ...opts,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { data = { ok: false, error: "bad_response" }; }
  return data;
}

function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return d.toLocaleString("zh-CN", { hour12: false });
}

function badge(text, cls) {
  return el("span", { class: "badge " + (cls || "dim"), text });
}

/* ---- login ---- */
function showLogin() {
  $("login-view").classList.remove("hidden");
  $("main-view").classList.add("hidden");
}

function showMain() {
  $("login-view").classList.add("hidden");
  $("main-view").classList.remove("hidden");
  $("username").textContent = state.user && state.user.username || "";
  $("ver").textContent = state.version || "";
  refreshTab();
}

$("use-recovery").addEventListener("click", (e) => {
  e.preventDefault();
  $("recovery-field").classList.toggle("hidden");
  $("totp-field").classList.toggle("hidden");
});

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {
    username: fd.get("username"),
    password: fd.get("password"),
    totp: fd.get("totp") || "",
    recovery_code: fd.get("recovery_code") || "",
  };
  const res = await api("/api/login", { method: "POST", body: JSON.stringify(body) });
  if (!res.ok) {
    $("login-error").textContent = res.message || res.error || "登录失败";
    return;
  }
  state.csrf = res.csrf_token;
  await boot();
});

$("logout-btn").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST", body: "{}" });
  state.csrf = "";
  state.user = null;
  showLogin();
});

$("totp-btn").addEventListener("click", async () => {
  const setupPassword = prompt("如需更换 2FA，请输入当前密码（首次绑定可留空）") || "";
  const setupOtp = prompt("如已有 2FA，请输入当前动态码（首次绑定可留空）") || "";
  const setup = await api("/api/totp/setup", {
    method: "POST",
    body: JSON.stringify({ password: setupPassword, totp: setupOtp }),
  });
  if (!setup.ok) {
    alert(setup.message || setup.error || "TOTP 初始化失败");
    return;
  }
  showModal("绑定 TOTP", [
    el("p", { class: "muted small", text: "使用 Microsoft Authenticator 等扫码或手动输入：" }),
    el("pre", { text: setup.otpauth }),
    el("p", { class: "muted small", text: "Secret: " + setup.secret }),
    el("label", { text: "当前密码（首次绑定可留空；更换必填）" }, [
      el("input", { id: "totp-setup-password", type: "password", style: "width:100%;margin-top:8px;padding:8px" }),
    ]),
    el("label", { text: "输入 6 位验证码确认" }, [
      el("input", { id: "totp-confirm-code", maxlength: "6", style: "width:140px;margin-top:8px;padding:8px" }),
    ]),
    el("label", { text: "当前密码（更换 2FA 时必填）" }, [
      el("input", { id: "totp-confirm-password", type: "password", style: "width:100%;margin-top:8px;padding:8px" }),
    ]),
    el("div", { id: "totp-result" }),
    el("button", {
      class: "btn primary", text: "确认启用",
      onclick: async () => {
        const code = $("totp-confirm-code").value.trim();
        const password = ($("totp-confirm-password") && $("totp-confirm-password").value) || "";
        const res = await api("/api/totp/confirm", {
          method: "POST",
          body: JSON.stringify({ code, password }),
        });
        if (!res.ok) {
          $("totp-result").textContent = res.message || res.error || "失败";
          return;
        }
        // 服务端已换发 CSRF / 新会话
        if (res.csrf_token) state.csrf = res.csrf_token;
        $("modal-body").innerHTML = "";
        $("modal-body").appendChild(el("p", { text: "已启用 2FA。请保存恢复码（仅显示一次）：" }));
        $("modal-body").appendChild(el("pre", { text: (res.recovery_codes || []).join("\n") }));
      },
    }),
  ]);
});

/* ---- tabs ---- */
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.tab = btn.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    $("tab-" + state.tab).classList.remove("hidden");
    refreshTab();
  });
});

async function boot() {
  const me = await api("/api/me");
  if (!me.ok) { showLogin(); return; }
  state.user = me.user;
  state.csrf = me.csrf_token || state.csrf;
  state.version = "v0.2.0";
  await loadMeta();
  showMain();
}

async function loadMeta() {
  const assets = await api("/api/assets");
  if (assets.ok) state.assets = assets.assets || [];
  const caps = await api("/api/capabilities");
  if (caps.ok) state.caps = caps.capabilities || [];
  fillSelects();
}

function fillSelects() {
  const assetOpts = state.assets.map((a) => ({ v: a.id, t: a.id + " / " + a.display_name }));
  const capOpts = state.caps.map((c) => ({ v: c.name, t: c.name + " (" + c.kind + ")" }));
  fillSelect("act-asset", assetOpts);
  fillSelect("perm-asset", [{ v: "*", t: "*(全部)" }, ...assetOpts]);
  fillSelect("act-cap", capOpts.filter((c) => c.t.includes("write") || true));
  fillSelect("perm-cap", capOpts);
}

function fillSelect(id, opts) {
  const s = $(id);
  if (!s) return;
  s.innerHTML = "";
  (opts || []).forEach((o) => {
    const op = document.createElement("option");
    op.value = o.v;
    op.textContent = o.t;
    s.appendChild(op);
  });
}

async function refreshTab() {
  if (state.tab === "overview") await renderOverview();
  if (state.tab === "assets") await renderAssets();
  if (state.tab === "incidents") await renderIncidents();
  if (state.tab === "actions") await renderActions();
  if (state.tab === "permissions") await renderPermissions();
  if (state.tab === "audit") await renderAudit();
}

async function renderOverview() {
  const res = await api("/api/overview");
  if (!res.ok) return;
  const g = $("overview-grid");
  g.innerHTML = "";
  $("quiet-banner").classList.toggle("hidden", !res.quiet);
  $("human-banner").classList.toggle("hidden", !(res.need_human || []).length);

  g.appendChild(tile("资产", String((res.assets || []).length), "已登记对象"));
  g.appendChild(tile("活动事件", String((res.open_incidents || []).length), "open incidents"));
  g.appendChild(tile("需人工", String((res.need_human || []).length), (res.need_human || []).map((i) => i.id).join(", ")));
  g.appendChild(tile("最近操作", String((res.recent_actions || []).length), (res.recent_actions || []).slice(0, 2).map((a) => a.state).join(", ")));

  (res.assets || []).forEach((a) => {
    g.appendChild(tile(a.id, a.display_name, `read=${a.read_alias} write=${a.write_alias}`, a.expected_host_id ? "ok" : "warn", a.expected_host_id ? "host_id 已登记" : "host_id 未核实"));
  });
}

function tile(label, value, sub, badgeCls, badgeText) {
  const t = el("div", { class: "tile" }, [
    el("div", { class: "label", text: label }),
    el("div", { class: "value", text: value }),
  ]);
  if (sub) t.appendChild(el("div", { class: "sub", text: sub }));
  if (badgeText) t.appendChild(badge(badgeText, badgeCls));
  return t;
}

async function renderAssets() {
  const res = await api("/api/assets");
  if (!res.ok) return;
  const root = $("assets-list");
  root.innerHTML = "";
  (res.assets || []).forEach((a) => {
    const card = el("div", { class: "card" });
    card.appendChild(el("h2", { text: `${a.id} · ${a.display_name}` }));
    card.appendChild(el("p", {
      class: "muted small",
      text: `read=${a.read_alias} write=${a.write_alias} host_id=${a.expected_host_id || "未登记"} prom=${a.prom_asset || "-"}`,
    }));
    const objs = a.objects || [];
    if (objs.length) {
      const table = el("table");
      table.appendChild(el("tr", {}, [
        el("th", { text: "kind" }), el("th", { text: "name" }), el("th", { text: "unit/container" }), el("th", { text: "auto" }),
      ]));
      objs.forEach((o) => {
        table.appendChild(el("tr", {}, [
          el("td", { text: o.kind }), el("td", { text: o.name }),
          el("td", { text: o.unit || o.container || (o.port ? o.port + "/" + o.protocol : "-") }),
          el("td", { text: o.auto_recover ? "是" : "否" }),
        ]));
      });
      card.appendChild(table);
    }
    const actions = el("div", { class: "row-actions", style: "margin-top:12px" }, [
      el("button", {
        class: "btn", text: "只读调查",
        onclick: async () => {
          const r = await api(`/api/assets/${a.id}/investigate`, {
            method: "POST",
            body: JSON.stringify({ capability: "asset.summary" }),
          });
          showModal("调查结果", [el("pre", { text: JSON.stringify(r, null, 2) })]);
        },
      }),
      el("button", {
        class: "btn", text: "探测状态",
        onclick: async () => {
          const r = await api(`/api/prom/probe?asset=${encodeURIComponent(a.id)}`);
          showModal("Prometheus probe", [el("pre", { text: JSON.stringify(r, null, 2) })]);
        },
      }),
    ]);
    card.appendChild(actions);
    root.appendChild(card);
  });
}

async function renderIncidents() {
  const res = await api("/api/incidents");
  const root = $("incidents-list");
  root.innerHTML = "";
  if (!res.ok) return;
  const list = res.incidents || [];
  if (!list.length) {
    root.appendChild(el("div", { class: "card muted", text: "无 Incident" }));
    return;
  }
  list.forEach((i) => {
    const card = el("div", { class: "card" });
    card.appendChild(el("h2", { text: i.title }));
    card.appendChild(el("p", {
      class: "muted small",
      text: `${i.id} · ${i.status} · ${i.stage}` + (i.need_human ? " · 需人工: " + (i.need_human_reason || "") : ""),
    }));
    card.appendChild(el("div", { class: "row-actions" }, [
      el("button", {
        class: "btn small", text: "详情",
        onclick: async () => {
          const d = await api("/api/incidents/" + i.id);
          showModal(i.id, [el("pre", { text: JSON.stringify(d.incident || d, null, 2) })]);
        },
      }),
    ]));
    root.appendChild(card);
  });
}

async function renderActions() {
  const res = await api("/api/actions");
  const root = $("actions-list");
  root.innerHTML = "";
  if (!res.ok) return;
  const list = res.actions || [];
  if (!list.length) {
    root.appendChild(el("div", { class: "card muted", text: "无操作记录" }));
    return;
  }
  list.forEach((a) => {
    const card = el("div", { class: "card" });
    const st = a.state;
    const cls = st === "success" ? "ok" : st === "failure" || st === "unknown" ? "bad" : st === "proposed" ? "warn" : "dim";
    card.appendChild(el("h2", {}, [
      document.createTextNode(a.capability + " "),
      badge(st, cls),
    ]));
    card.appendChild(el("p", {
      class: "muted small",
      text: `${a.id} · ${a.asset_id}/${a.object_id} · ${a.reason || ""}`,
    }));
    const row = el("div", { class: "row-actions" });
    if (st === "proposed") {
      row.appendChild(el("button", {
        class: "btn primary small", text: "批准",
        onclick: async () => {
          await api(`/api/actions/${a.id}/approve`, { method: "POST", body: "{}" });
          refreshTab();
        },
      }));
      row.appendChild(el("button", {
        class: "btn danger small", text: "取消",
        onclick: async () => {
          await api(`/api/actions/${a.id}/cancel`, { method: "POST", body: "{}" });
          refreshTab();
        },
      }));
    }
    if (st === "approved") {
      row.appendChild(el("button", {
        class: "btn primary small", text: "执行",
        onclick: async () => {
          const r = await api(`/api/actions/${a.id}/execute`, { method: "POST", body: "{}" });
          showModal("执行结果", [el("pre", { text: JSON.stringify(r, null, 2) })]);
          refreshTab();
        },
      }));
    }
    row.appendChild(el("button", {
      class: "btn small", text: "详情",
      onclick: async () => {
        // 用 list 中的数据
        showModal(a.id, [el("pre", { text: JSON.stringify(a, null, 2) })]);
      },
    }));
    card.appendChild(row);
    root.appendChild(card);
  });
}

$("act-propose").addEventListener("click", async () => {
  const body = {
    asset_id: $("act-asset").value,
    object_id: $("act-object").value,
    capability: $("act-cap").value,
    reason: $("act-reason").value,
    params: {},
  };
  const res = await api("/api/actions", { method: "POST", body: JSON.stringify(body) });
  showModal(res.ok ? "提案已创建" : "提案失败", [el("pre", { text: JSON.stringify(res, null, 2) })]);
  refreshTab();
});

async function renderPermissions() {
  const res = await api("/api/permissions");
  const root = $("perm-list");
  root.innerHTML = "";
  if (!res.ok) return;
  root.appendChild(el("div", { class: "card" }, [
    el("h2", { text: "说明" }),
    el("p", { class: "muted small", text: res.note || "" }),
    el("p", { class: "muted small", text: "能力目录固定注册；不能通过 Web 上传任意执行模板。" }),
  ]));
  const table = el("table");
  table.appendChild(el("tr", {}, [
    el("th", { text: "id" }), el("th", { text: "主体" }), el("th", { text: "能力" }),
    el("th", { text: "资产" }), el("th", { text: "对象" }), el("th", { text: "允许" }),
    el("th", { text: "批准" }), el("th", { text: "自动" }), el("th", { text: "" }),
  ]));
  (res.permissions || []).forEach((p) => {
    table.appendChild(el("tr", {}, [
      el("td", { text: String(p.id) }),
      el("td", { text: p.subject_type + ":" + p.subject_id }),
      el("td", { text: p.capability }),
      el("td", { text: p.asset_id }),
      el("td", { text: p.object_id }),
      el("td", {}, [badge(p.allow ? "是" : "否", p.allow ? "ok" : "bad")]),
      el("td", { text: p.require_approval ? "是" : "否" }),
      el("td", { text: p.auto_allowed ? "是" : "否" }),
      el("td", {}, [
        el("button", {
          class: "btn danger small", text: "删除",
          onclick: async () => {
            await api("/api/permissions/delete", { method: "POST", body: JSON.stringify({ id: p.id }) });
            refreshTab();
          },
        }),
      ]),
    ]));
  });
  root.appendChild(table);
}

$("perm-save").addEventListener("click", async () => {
  const body = {
    subject_type: $("perm-subject-type").value,
    subject_id: $("perm-subject-id").value,
    capability: $("perm-cap").value,
    asset_id: $("perm-asset").value,
    object_id: $("perm-object").value || "*",
    allow: $("perm-allow").checked,
    require_approval: $("perm-approval").checked,
    auto_allowed: $("perm-auto").checked,
  };
  const res = await api("/api/permissions", { method: "POST", body: JSON.stringify(body) });
  showModal(res.ok ? "已保存" : "失败", [el("pre", { text: JSON.stringify(res, null, 2) })]);
  refreshTab();
});

async function renderAudit() {
  const res = await api("/api/audit?limit=80");
  const root = $("audit-list");
  root.innerHTML = "";
  if (!res.ok) return;
  const table = el("table");
  table.appendChild(el("tr", {}, [
    el("th", { text: "时间" }), el("th", { text: "主体" }), el("th", { text: "条目" }), el("th", { text: "资产/对象" }),
  ]));
  (res.audit || []).forEach((a) => {
    table.appendChild(el("tr", {}, [
      el("td", { text: fmtTime(a.at) }),
      el("td", { text: a.actor_type + ":" + a.actor_id }),
      el("td", { text: a.entry }),
      el("td", { text: (a.asset_id || "-") + "/" + (a.object_id || "-") }),
    ]));
  });
  root.appendChild(table);
}

/* ---- modal ---- */
function showModal(title, children) {
  $("modal-title").textContent = title;
  const body = $("modal-body");
  body.innerHTML = "";
  (children || []).forEach((c) => body.appendChild(c));
  $("modal").classList.remove("hidden");
}
$("modal-close").addEventListener("click", () => $("modal").classList.add("hidden"));

/* ---- init ---- */
boot();
