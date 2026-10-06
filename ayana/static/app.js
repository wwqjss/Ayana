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

/* ---- i18n maps ---- */
const ZH = {
  // status
  open: "处理中",
  resolved: "已解决",
  closed: "已关闭",
  // stage
  pending: "待调查",
  investigating: "调查中",
  awaiting_approval: "待批准",
  executing: "执行中",
  verifying: "验证中",
  watching: "观察中",
  done: "完成",
  need_human: "需人工",
  // action state
  proposed: "已提案",
  approved: "已批准",
  dispatched: "已派发",
  success: "成功",
  failure: "失败",
  unknown: "结果未知",
  cancelled: "已取消",
  expired: "已过期",
  // alert names
  TargetDown: "探测目标不可达",
  PrometheusJobMissing: "采集目标丢失",
  PrometheusNotConnectedToAlertmanager: "Prometheus 未连接告警",
  DiskUsageHigh: "磁盘使用率过高",
  MemoryLow: "可用内存不足",
};

function zh(s) {
  return ZH[s] || s;
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
  const { tab, focus } = currentTabFromHash();
  activateTab(tab, focus);
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
    el("p", { class: "muted small", text: "用 Microsoft Authenticator / 谷歌验证器扫码：" }),
    el("div", {
      id: "totp-qr",
      style: "background:#fff;padding:12px;border-radius:8px;display:inline-block;margin:8px 0",
    }),
    el("p", { class: "muted small", text: "扫码不可用时，手动输入 Secret：" }),
    el("pre", { id: "totp-secret", text: setup.secret, style: "user-select:all" }),
    el("p", { class: "muted small", text: "otpauth：" }),
    el("pre", { text: setup.otpauth, style: "user-select:all;font-size:10px;max-height:80px" }),
    el("label", { text: "输入 6 位验证码确认" }, [
      el("input", { id: "totp-confirm-code", maxlength: "6", style: "width:140px;margin-top:8px;padding:8px" }),
    ]),
    el("label", { text: "当前密码（首次绑定可留空；更换必填）" }, [
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
        if (res.csrf_token) state.csrf = res.csrf_token;
        $("modal-body").innerHTML = "";
        $("modal-body").appendChild(el("p", { text: "已启用 2FA。请保存恢复码（仅显示一次）：" }));
        $("modal-body").appendChild(el("pre", { text: (res.recovery_codes || []).join("\n") }));
      },
    }),
  ]);
  // 渲染 QR
  try {
    const qr = window.QR.encode(setup.otpauth, 4);
    $("totp-qr").innerHTML = window.QR.toSvg(qr, 4);
  } catch (e) {
    $("totp-qr").innerHTML = '<span class="muted small">二维码生成失败，请用 Secret 手动添加</span>';
  }
});

/* ---- tabs ---- */
function currentTabFromHash() {
  const h = (location.hash || "").replace(/^#/, "");
  const assetM = h.match(/^assets\/(.+)$/);
  if (assetM) return { tab: "overview", focus: assetM[1], assetView: true };
  const m = h.match(/^(overview|incidents|actions|permissions|audit)(?:\/(.+))?$/);
  return m ? { tab: m[1], focus: m[2] || "", assetView: false } : { tab: "overview", focus: "", assetView: false };
}

function setTabHash(tab, focus, assetView) {
  if (assetView && focus) {
    const h = `#assets/${focus}`;
    if (location.hash !== h) history.replaceState(null, "", h);
    return;
  }
  const h = focus ? `#${tab}/${focus}` : `#${tab}`;
  if (location.hash !== h) history.replaceState(null, "", h);
}

function activateTab(tab, focus, assetView) {
  const valid = ["overview", "incidents", "actions", "permissions", "audit"];
  if (!valid.includes(tab)) tab = "overview";
  state.tab = tab;
  state.focus = focus || "";
  state.assetView = !!assetView;
  document.querySelectorAll(".tab").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tab);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
  const panel = $("tab-" + tab);
  if (panel) panel.classList.remove("hidden");
  setTabHash(tab, state.focus, state.assetView);
  refreshTab();
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    activateTab(btn.dataset.tab, "");
  });
});

window.addEventListener("hashchange", () => {
  const { tab, focus, assetView } = currentTabFromHash();
  if (tab !== state.tab || (focus || "") !== (state.focus || "") || !!state.assetView !== !!assetView) {
    activateTab(tab, focus, assetView);
  }
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
  fillSelect("act-cap", capOpts);
  fillSelect("perm-cap", capOpts);
  refreshObjectSelect();
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

function refreshObjectSelect() {
  const assetId = $("act-asset").value;
  const asset = state.assets.find((a) => a.id === assetId);
  const objs = (asset && asset.objects) || [];
  const sel = $("act-object");
  const prev = sel.value;
  sel.innerHTML = "";
  objs.forEach((o) => {
    const op = document.createElement("option");
    op.value = o.name;
    op.textContent = `${o.name} (${o.kind})`;
    sel.appendChild(op);
  });
  if (prev && objs.some((o) => o.name === prev)) sel.value = prev;
  refreshCapabilitySelect();
}

function refreshCapabilitySelect() {
  const assetId = $("act-asset").value;
  const asset = state.assets.find((a) => a.id === assetId);
  const objName = $("act-object").value;
  const obj = ((asset && asset.objects) || []).find((o) => o.name === objName);
  const kind = obj ? obj.kind : "";
  // 对象类型 → 可用能力
  const KIND_CAPS = {
    service: ["asset.summary", "service.status", "service.logs", "service.restart", "service.start", "service.stop"],
    container: ["asset.summary", "service.status", "service.logs", "container.restart"],
    port: ["port.listen", "asset.summary"],
    probe: ["probe.status"],
    filesystem: ["disk.usage", "asset.summary"],
    "": ["asset.summary", "disk.usage", "memory.available", "load.current"],
  };
  const allowed = new Set(KIND_CAPS[kind] || KIND_CAPS[""]);
  const sel = $("act-cap");
  const prev = sel.value;
  sel.innerHTML = "";
  state.caps
    .filter((c) => allowed.has(c.name))
    .forEach((c) => {
      const op = document.createElement("option");
      op.value = c.name;
      const kindLabel = c.kind === "write" ? "写" : "读";
      const desc = c.description || "";
      op.textContent = `${c.name} (${kindLabel})` + (desc ? ` — ${desc}` : "");
      sel.appendChild(op);
    });
  if (prev && Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
}

$("act-asset").addEventListener("change", refreshObjectSelect);
$("act-object").addEventListener("change", refreshCapabilitySelect);

async function refreshTab() {
  if (state.tab === "overview") await renderOverview();
  if (state.tab === "assets") await renderAssets();
  if (state.tab === "incidents") await renderIncidents();
  if (state.tab === "actions") await renderActions();
  if (state.tab === "permissions") await renderPermissions();
  if (state.tab === "audit") await renderAudit();
}

/* ---- 统一健康状态 ---- */
function computeAssetHealth(asset, openIncs) {
  const openCount = openIncs.filter((i) => i.asset_id === asset.id).length;
  const hasProbe = (asset.objects || []).some((o) => o.kind === "probe" || o.external_probe);
  return {
    openCount,
    hasProbe,
    health: openCount > 0 ? "异常" : "正常",
    healthCls: openCount > 0 ? "bad" : "ok",
    coverage: hasProbe ? "已覆盖" : "未覆盖外部探测",
    coverageCls: hasProbe ? "ok" : "warn",
  };
}

function computeObjectStatus(obj, assetId, incByObj) {
  const keys = [
    `${assetId}/${obj.id}`,
    `${assetId}/${obj.name}`,
    `${assetId}/${assetId}:${obj.kind}:${obj.name}`,
  ];
  const hit = keys.map((k) => incByObj[k]).find(Boolean);
  return hit ? { label: "异常", cls: "bad", inc: hit } : { label: "正常", cls: "ok", inc: null };
}

function buildIncIndex(openIncs) {
  const idx = {};
  openIncs.forEach((i) => {
    const keys = [
      `${i.asset_id}/${i.object_id}`,
      `${i.asset_id}/${i.asset_id}:service:${i.object_id}`,
      `${i.asset_id}/${i.asset_id}:container:${i.object_id}`,
      `${i.asset_id}/${i.asset_id}:port:${i.object_id}`,
      `${i.asset_id}/${i.asset_id}:probe:${i.object_id}`,
    ];
    keys.forEach((k) => { idx[k] = i; });
  });
  return idx;
}

async function renderOverview() {
  const res = await api("/api/overview");
  if (!res.ok) return;
  const g = $("overview-grid");
  g.innerHTML = "";
  $("quiet-banner").classList.toggle("hidden", !res.quiet);
  $("human-banner").classList.toggle("hidden", !(res.need_human || []).length);
  $("human-banner").onclick = () => activateTab("incidents", "");

  if ((res.need_human || []).length) {
    const list = el("div", { class: "card", style: "margin-bottom:12px" });
    list.appendChild(el("h2", { text: "需要人工处理" }));
    res.need_human.forEach((i) => {
      const row = el("div", {
        style: "display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--line);cursor:pointer",
        onclick: () => openIncidentDetail(i.id),
      }, [
        el("div", {}, [
          el("div", { text: zh(i.title || ""), style: "font-size:14px" }),
          el("div", { class: "muted small", text: `${i.id} · ${zh(i.need_human_reason || "")}` }),
        ]),
        el("button", { class: "btn small", text: "查看" }),
      ]);
      list.appendChild(row);
    });
    g.appendChild(list);
  }

  g.appendChild(tile("活动事件", String((res.open_incidents || []).length), "处理中的异常", (res.open_incidents || []).length ? "warn" : "ok", (res.open_incidents || []).length ? "有异常" : "正常"));
  g.appendChild(tile("需人工", String((res.need_human || []).length), (res.need_human || []).map((i) => i.id).join(", ") || "无需人工", (res.need_human || []).length ? "bad" : "ok", (res.need_human || []).length ? "有" : "无"));
  g.appendChild(tile("最近操作", String((res.recent_actions || []).length), (res.recent_actions || []).slice(0, 2).map((a) => zh(a.state)).join(", ") || "-"));

  const openIncs = res.open_incidents || [];
  const incByObj = buildIncIndex(openIncs);

  // 资产长条列表
  const list = el("div", { style: "margin-top:16px" });
  list.appendChild(el("h2", { text: "监控状态", style: "margin-bottom:8px;font-size:14px" }));
  (res.assets || []).forEach((a) => {
    const h = computeAssetHealth(a, openIncs);
    const expanded = state.focus === a.id;
    // 长条行
    const row = el("div", {
      style: `background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:6px;overflow:hidden`,
    });
    const head = el("div", {
      style: "display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer",
      onclick: () => {
        const newFocus = expanded ? "" : a.id;
        activateTab("overview", newFocus, false);
      },
    }, [
      el("span", { text: expanded ? "▾" : "▸", style: "width:16px;color:var(--dim)" }),
      el("span", { text: `${a.id} · ${a.display_name}`, style: "font-weight:500;flex:1" }),
      badge(h.health, h.healthCls),
      badge(h.coverage, h.coverageCls),
      el("button", {
        class: "btn small", text: "详情",
        onclick: (e) => {
          e.stopPropagation();
          activateTab("overview", a.id, true);
        },
      }),
    ]);
    row.appendChild(head);

    // 展开区：对象表 + 操作
    if (expanded) {
      const body = el("div", {
        style: "padding:0 16px 16px;border-top:1px solid var(--line)",
      });
      body.appendChild(el("p", {
        class: "muted small",
        text: `read=${a.read_alias} write=${a.write_alias} host_id=${a.expected_host_id || "未登记"}`,
        style: "margin:12px 0",
      }));
      const objs = a.objects || [];
      if (objs.length) {
        const table = el("table");
        table.appendChild(el("tr", {}, [
          el("th", { text: "对象" }), el("th", { text: "类型" }), el("th", { text: "配置" }), el("th", { text: "状态" }),
        ]));
        objs.forEach((o) => {
          const st = computeObjectStatus(o, a.id, incByObj);
          const cfg = o.unit || o.container || (o.port ? `${o.port}/${o.protocol}` : (o.external_probe || "-"));
          table.appendChild(el("tr", {}, [
            el("td", { text: o.name }),
            el("td", { class: "muted small", text: o.kind }),
            el("td", { class: "muted small", text: cfg }),
            el("td", {}, [badge(st.label, st.cls)]),
          ]));
        });
        body.appendChild(table);
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
            showModal("Prometheus 探测", [el("pre", { text: JSON.stringify(r, null, 2) })]);
          },
        }),
      ]);
      body.appendChild(actions);
      row.appendChild(body);
    }
    list.appendChild(row);
  });
  g.appendChild(list);
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
  const incRes = await api("/api/incidents?status=open");
  const openIncs = (incRes && incRes.ok && incRes.incidents) || [];
  const incByObj = buildIncIndex(openIncs);
  const focusId = state.focus;

  if (!focusId) {
    activateTab("overview", "", false);
    return;
  }

  const a = (res.assets || []).find((x) => x.id === focusId);
  root.appendChild(el("div", { style: "margin-bottom:12px" }, [
    el("button", {
      class: "btn", text: "< 返回总览",
      onclick: () => activateTab("overview", "", false),
    }),
  ]));
  if (!a) {
    root.appendChild(el("div", { class: "card muted", text: `未找到资产 ${focusId}` }));
    return;
  }

  const h = computeAssetHealth(a, openIncs);
    const card = el("div", { class: "card" });
    const head = el("div", { style: "display:flex;justify-content:space-between;align-items:center" });
    head.appendChild(el("h2", { text: `${a.id} · ${a.display_name}` }));
    const badges = el("div", { style: "display:flex;gap:8px" }, [
      badge(h.health, h.healthCls),
      badge(h.coverage, h.coverageCls),
    ]);
    head.appendChild(badges);
    card.appendChild(head);
    card.appendChild(el("p", {
      class: "muted small",
      text: `read=${a.read_alias} write=${a.write_alias} host_id=${a.expected_host_id || "未登记"}`,
    }));

    const objs = a.objects || [];
    if (objs.length) {
      const table = el("table");
      table.appendChild(el("tr", {}, [
        el("th", { text: "对象" }), el("th", { text: "类型" }), el("th", { text: "配置" }), el("th", { text: "状态" }),
      ]));
      objs.forEach((o) => {
        const st = computeObjectStatus(o, a.id, incByObj);
        const cfg = o.unit || o.container || (o.port ? `${o.port}/${o.protocol}` : (o.external_probe || "-"));
        table.appendChild(el("tr", {}, [
          el("td", { text: o.name }),
          el("td", { class: "muted small", text: o.kind }),
          el("td", { class: "muted small", text: cfg }),
          el("td", {}, [badge(st.label, st.cls)]),
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
          showModal("Prometheus 探测", [el("pre", { text: JSON.stringify(r, null, 2) })]);
        },
      }),
    ]);
    card.appendChild(actions);
    root.appendChild(card);
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
    // 标题里的告警名翻成中文
    const title = (i.title || "").replace(/TargetDown|PrometheusJobMissing|DiskUsageHigh|MemoryLow/g, (m) => zh(m));
    card.appendChild(el("h2", { text: title }));
    card.appendChild(el("p", {
      class: "muted small",
      text: `${i.id} · ${zh(i.status)} · ${zh(i.stage)}`
        + (i.need_human ? " · 需人工: " + (i.need_human_reason || "") : ""),
    }));
    card.appendChild(el("p", {
      class: "muted small",
      text: `发现 ${fmtTime(i.created_at)} · 更新 ${fmtTime(i.updated_at)}`
        + (i.resolved_at ? ` · 解决 ${fmtTime(i.resolved_at)}` : ""),
    }));
    card.appendChild(el("div", { class: "row-actions" }, [
      el("button", {
        class: "btn small", text: "详情",
        onclick: () => openIncidentDetail(i.id),
      }),
    ]));
    root.appendChild(card);
  });
  if (state.focus) openIncidentDetail(state.focus);
}

async function openIncidentDetail(incId) {
  setTabHash("incidents", incId);
  const d = await api("/api/incidents/" + incId);
  if (!d.ok) return;
  const inc = d.incident || {};
  const sum = d.summary || {};
  const body = el("div");

  // 标题
  body.appendChild(el("h2", { text: sum.title || inc.title || "" }));
  body.appendChild(el("p", {
    class: "muted small",
    text: `状态: ${sum.status_zh || ""} · 阶段: ${sum.stage_zh || ""}`,
  }));

  // 为什么需要人工
  if (sum.why_human) {
    const box = el("div", {
      style: "background:rgba(229,192,123,.12);border-radius:8px;padding:12px;margin:12px 0",
    });
    box.appendChild(el("div", { text: "为什么需要你", style: "font-weight:600;margin-bottom:4px" }));
    box.appendChild(el("div", { text: sum.why_human }));
    if (sum.suggestion) box.appendChild(el("div", { class: "muted small", text: sum.suggestion, style: "margin-top:6px" }));
    body.appendChild(box);
  } else if (sum.suggestion) {
    body.appendChild(el("p", { class: "muted small", text: sum.suggestion }));
  }

  // 时间线
  if ((sum.timeline || []).length) {
    body.appendChild(el("h3", { text: "时间线", style: "margin:16px 0 8px;font-size:14px" }));
    (sum.timeline || []).forEach((t) => {
      body.appendChild(el("div", {
        class: "muted small",
        text: `${fmtTime(t.time)}  ${t.label}`,
        style: "padding:3px 0",
      }));
    });
  }

  // 最近操作
  if (sum.last_action) {
    body.appendChild(el("p", {
      class: "muted small",
      text: `最近操作: ${sum.last_action.capability_zh || ""} · ${sum.last_action.state_zh || ""}`,
      style: "margin-top:12px",
    }));
  }

  // 操作按钮
  const actions = el("div", { class: "row-actions", style: "margin-top:16px" });
  if (inc.status === "open" || inc.status === "resolved") {
    actions.appendChild(el("button", {
      class: "btn danger", text: "手动关闭",
      onclick: async () => {
        const reason = prompt("关闭原因:", "问题已解决");
        if (!reason) return;
        await api(`/api/incidents/${incId}/close`, { method: "POST", body: JSON.stringify({ reason }) });
        $("modal").classList.add("hidden");
        refreshTab();
      },
    }));
  }
  actions.appendChild(el("button", {
    class: "btn", text: "原始数据",
    onclick: () => {
      $("modal-body").innerHTML = "";
      $("modal-body").appendChild(el("pre", { text: JSON.stringify(inc, null, 2) }));
      $("modal-body").appendChild(el("div", { class: "modal-actions" }, [
        el("button", { class: "btn", text: "关闭", onclick: () => $("modal").classList.add("hidden") }),
      ]));
    },
  }));
  body.appendChild(actions);

  showModal("", [body]);
  $("modal-title").textContent = "事件详情";
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
      badge(zh(st), cls),
    ]));
    card.appendChild(el("p", {
      class: "muted small",
      text: `${a.id} · ${a.asset_id}/${a.object_id} · ${a.reason || ""}`,
    }));
    card.appendChild(el("p", {
      class: "muted small",
      text: `发起 ${fmtTime(a.created_at)}`
        + (a.approved_at ? ` · 批准 ${fmtTime(a.approved_at)}` : "")
        + (a.finished_at ? ` · 结束 ${fmtTime(a.finished_at)}` : "")
        + (a.approver_id ? ` · 批准人 ${a.approver_id}` : ""),
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
      onclick: () => openActionDetail(a),
    }));
    card.appendChild(row);
    root.appendChild(card);
  });
  if (state.focus) {
    const hit = (res.actions || []).find((x) => x.id === state.focus);
    if (hit) openActionDetail(hit);
  }
}

function openActionDetail(a) {
  setTabHash("actions", a.id);
  showModal(a.id, [el("pre", { text: JSON.stringify(a, null, 2) })]);
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
  if (res.ok) {
    showModal("提案已创建", [
      el("pre", { text: JSON.stringify(res, null, 2) }),
      el("p", { class: "muted small", text: "请在下方列表批准后执行。" }),
    ]);
  } else {
    const err = res.error || "";
    let hint = res.message || err;
    if (err.includes("denied_by_policy") || err.includes("denied")) {
      hint = `权限不足：${body.capability} @ ${body.asset_id}/${body.object_id}\n`
        + `请到「权限」页为你的账号添加该能力（勾选允许）。`;
    } else if (err.includes("object_locked")) {
      hint = "该对象有进行中/结果未知的操作，请先处理完。";
    } else if (err.includes("object_not_registered")) {
      const assetId = body.asset_id;
      const asset = state.assets.find((a) => a.id === assetId);
      const names = ((asset && asset.objects) || []).map((o) => o.name).join(", ") || "无";
      hint = `对象未登记：「${body.object_id}」\n`
        + `资产 ${assetId} 下可选对象：${names}`;
    }
    showModal("提案失败", [el("pre", { text: hint })]);
  }
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
  const root = $("audit-list");
  root.innerHTML = "";

  // 筛选栏
  const bar = el("div", { class: "card" });
  bar.appendChild(el("h2", { text: "审计日志" }));
  const row = el("div", { class: "form-row" });
  const kw = el("input", { id: "audit-kw", placeholder: "搜索关键词…" });
  const from = el("input", { id: "audit-from", type: "datetime-local" });
  const to = el("input", { id: "audit-to", type: "datetime-local" });
  const btn = el("button", { class: "btn primary", text: "搜索", onclick: () => doSearch() });
  const btnReset = el("button", { class: "btn", text: "重置", onclick: () => {
    kw.value = ""; from.value = ""; to.value = ""; doSearch();
  }});
  row.appendChild(el("label", { text: "关键词" }, [kw]));
  row.appendChild(el("label", { text: "从" }, [from]));
  row.appendChild(el("label", { text: "到" }, [to]));
  row.appendChild(btn);
  row.appendChild(btnReset);
  bar.appendChild(row);
  root.appendChild(bar);

  const resultDiv = el("div");
  root.appendChild(resultDiv);

  async function doSearch() {
    const params = new URLSearchParams();
    if (kw.value) params.set("q", kw.value);
    if (from.value) params.set("from", String(new Date(from.value).getTime() / 1000));
    if (to.value) params.set("to", String(new Date(to.value).getTime() / 1000));
    params.set("limit", "200");
    const res = await api(`/api/audit?${params}`);
    resultDiv.innerHTML = "";
    if (!res.ok) return;
    const list = res.audit || [];
    if (!list.length) {
      resultDiv.appendChild(el("div", { class: "card muted", text: "无匹配记录" }));
      return;
    }
    const table = el("table");
    table.appendChild(el("tr", {}, [
      el("th", { text: "时间" }), el("th", { text: "主体" }), el("th", { text: "条目" }), el("th", { text: "资产/对象" }), el("th", { text: "详情" }),
    ]));
    list.forEach((a) => {
      const detail = (() => {
        try {
          const d = JSON.parse(a.detail_json || "{}");
          return Object.entries(d).map(([k, v]) => `${k}=${v}`).join(" ").slice(0, 80);
        } catch { return ""; }
      })();
      table.appendChild(el("tr", {}, [
        el("td", { text: fmtTime(a.at) }),
        el("td", { text: a.actor_type + ":" + a.actor_id }),
        el("td", { text: a.entry }),
        el("td", { text: (a.asset_id || "-") + "/" + (a.object_id || "-") }),
        el("td", { class: "muted small", text: detail }),
      ]));
    });
    resultDiv.appendChild(table);
  }
  doSearch();
}

/* ---- modal ---- */
function showModal(title, children) {
  $("modal-title").textContent = title;
  const body = $("modal-body");
  body.innerHTML = "";
  (children || []).forEach((c) => body.appendChild(c));
  $("modal").classList.remove("hidden");
}
$("modal-close").addEventListener("click", () => {
  $("modal").classList.add("hidden");
  setTabHash(state.tab, "");
});

/* ---- init ---- */
boot();
