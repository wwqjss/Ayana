/* Ayana Web 控制台 */
const state = {
  csrf: "",
  user: null,
  tab: "overview",
  assets: [],
  caps: [],
  knowledge: [],
};

function $(id) { return document.getElementById(id); }
function on(id, ev, fn) {
  const n = $(id);
  if (n) n.addEventListener(ev, fn);
  return n;
}

/** 极简 Markdown 渲染（标题/列表/粗体/行内代码/代码块/段落），带标题 id 供 TOC 锚点 */
function renderMarkdown(md) {
  const box = el("div", { class: "md-body" });
  const lines = (md || "").split(/\r?\n/);
  let ul = null;
  let pre = null;
  const flushUl = () => { ul = null; };
  const flushPre = () => { pre = null; };
  lines.forEach((line) => {
    if (pre !== null) {
      if (line.trim().startsWith("```")) { flushPre(); return; }
      pre.textContent += (pre.textContent ? "\n" : "") + line;
      return;
    }
    const t = line.trim();
    if (t.startsWith("```")) {
      flushUl();
      pre = el("pre", {});
      pre.appendChild(el("code", { text: "" }));
      // keep code text in pre
      box.appendChild(pre);
      return;
    }
    if (!t) { flushUl(); return; }
    const hm = t.match(/^(#{1,4})\s+(.*)$/);
    if (hm) {
      flushUl();
      const level = hm[1].length;
      const text = hm[2].replace(/`([^`]+)`/g, "$1");
      const id = "h-" + text.replace(/[^\w一-龥]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
      const tag = level === 1 ? "h2" : level === 2 ? "h3" : level === 3 ? "h4" : "div";
      const node = el(tag, {
        text,
        id,
        style:
          level === 1
            ? "font-size:18px;margin:18px 0 10px"
            : level === 2
              ? "font-size:15px;margin:16px 0 8px"
              : "font-size:13px;font-weight:600;margin:12px 0 6px",
      });
      node.dataset.level = String(level);
      box.appendChild(node);
      return;
    }
    const m = t.match(/^[-*]\s+(.*)$/);
    if (m) {
      if (!ul) {
        ul = el("ul", { style: "margin:6px 0 10px 20px;color:var(--dim);font-size:13px;line-height:1.55" });
        box.appendChild(ul);
      }
      ul.appendChild(el("li", { text: m[1].replace(/`([^`]+)`/g, "$1").replace(/\*\*([^*]+)\*\*/g, "$1") }));
      return;
    }
    if (/^\d+\.\s+/.test(t)) {
      if (!ul) {
        ul = el("ol", { style: "margin:6px 0 10px 20px;color:var(--dim);font-size:13px;line-height:1.55" });
        box.appendChild(ul);
      }
      ul.appendChild(el("li", { text: t.replace(/^\d+\.\s+/, "").replace(/`([^`]+)`/g, "$1") }));
      return;
    }
    flushUl();
    // 箭头/关系行保持 monospace 观感
    if (t.includes("→") || t.startsWith("- ")) {
      box.appendChild(el("p", {
        text: t.replace(/`([^`]+)`/g, "$1"),
        class: "muted",
        style: "font-size:13px;line-height:1.6;margin:3px 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace",
      }));
      return;
    }
    box.appendChild(el("p", {
      text: t.replace(/`([^`]+)`/g, "$1").replace(/\*\*([^*]+)\*\*/g, "$1"),
      class: "",
      style: "font-size:13.5px;line-height:1.7;margin:8px 0;color:var(--ink)",
    }));
  });
  return box;
}

function collectToc(md) {
  const toc = [];
  (md || "").split(/\r?\n/).forEach((line) => {
    const m = line.trim().match(/^(#{1,4})\s+(.*)$/);
    if (!m) return;
    const level = m[1].length;
    const text = m[2].replace(/`([^`]+)`/g, "$1");
    const id = "h-" + text.replace(/[^\w一-龥]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
    if (level >= 1 && level <= 3) toc.push({ level, text, id });
  });
  return toc;
}
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
const ZH_CAP = {
  "service.restart": "重启服务",
  "service.start": "启动服务",
  "service.stop": "停止服务",
  "container.restart": "重启容器",
  "asset.summary": "资产摘要",
  "service.status": "服务状态",
  "service.logs": "服务日志",
  "port.listen": "端口监听",
  "disk.usage": "磁盘使用",
  "memory.available": "内存可用",
  "load.current": "负载",
  "probe.status": "探测状态",
};

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

on("use-recovery", "click", (e) => {
  e.preventDefault();
  $("recovery-field").classList.toggle("hidden");
  $("totp-field").classList.toggle("hidden");
});

on("login-form", "submit", async (e) => {
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

on("logout-btn", "click", async () => {
  await api("/api/logout", { method: "POST", body: "{}" });
  state.csrf = "";
  state.user = null;
  showLogin();
});

on("totp-btn", "click", async () => {
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
  const m = h.match(/^(overview|incidents|knowledge|permissions|audit)(?:\/(.+))?$/);
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
  const valid = ["overview", "incidents", "knowledge", "permissions", "audit"];
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
window.addEventListener("popstate", () => {
  const { tab, focus, assetView } = currentTabFromHash();
  activateTab(tab, focus, assetView);
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
  fillSelect("perm-asset", [{ v: "*", t: "*(全部)" }, ...assetOpts]);
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
  if (state.tab === "knowledge") await renderKnowledge();
  if (state.tab === "permissions") await renderPermissions();
  if (state.tab === "audit") await renderAudit();
}

/* ---- 统一健康状态 ---- */
function computeAssetHealth(asset, openIncs) {
  const openCount = openIncs.filter((i) => i.asset_id === asset.id).length;
  const hasProbe = (asset.objects || []).some((o) =>
    o.kind === "probe" || o.external_probe || o.name.includes("probe")
  );
  // 用真实探测数据
  const probe = asset.probe || {};
  const hysteria = asset.hysteria_proxy || {};
  let health = "正常", healthCls = "ok";
  if (openCount > 0) {
    health = `${openCount} 个异常`;
    healthCls = "bad";
  } else if (probe.state === "fail" || hysteria.state === "fail") {
    health = "探测失败";
    healthCls = "bad";
  } else if (probe.state === "ok" || hysteria.state === "ok") {
    health = "正常";
    healthCls = "ok";
  }
  return {
    openCount,
    hasProbe,
    health,
    healthCls,
    coverage: hasProbe ? "已覆盖" : "无探测项",
    coverageCls: hasProbe ? "ok" : "warn",
    probeState: probe.state,
    hysteriaState: hysteria.state,
    hysteriaTargets: hysteria.targets || [],
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

/** 标准对象行：登记对象 + 外部探测（google/youtube 等）统一成表格行 */
function buildMonitorRows(asset, incByObj) {
  const rows = [];
  (asset.objects || []).forEach((o) => {
    const st = computeObjectStatus(o, asset.id, incByObj);
    const cfg = o.unit || o.container || (o.port ? `${o.port}/${o.protocol}` : (o.external_probe || "-"));
    rows.push({
      name: o.name,
      kind: o.kind,
      cfg,
      label: st.label,
      cls: st.cls,
      inc: st.inc,
    });
  });
  // hysteria 代理探测 → 标准行（不使用 badge、不单列「外部探测」）
  const hysteria = asset.hysteria_proxy || {};
  (hysteria.targets || []).forEach((t) => {
    const ok = t.value === 1;
    rows.push({
      name: t.target,
      kind: "probe",
      cfg: "hysteria_proxy",
      label: ok ? "正常" : "异常",
      cls: ok ? "ok" : "bad",
      inc: null,
    });
  });
  // 黑盒 probe 汇总（未对应登记对象且有明确状态时补一行）
  const probe = asset.probe || {};
  const hasProbeObj = (asset.objects || []).some(
    (o) => o.kind === "probe" || o.external_probe
  );
  if (!hasProbeObj && (probe.state === "ok" || probe.state === "fail")) {
    const ok = probe.state === "ok";
    rows.push({
      name: "blackbox",
      kind: "probe",
      cfg: "probe_success",
      label: ok ? "正常" : "异常",
      cls: ok ? "ok" : "bad",
      inc: null,
    });
  }
  return rows;
}

function renderMonitorTable(asset, incByObj) {
  const rows = buildMonitorRows(asset, incByObj);
  if (!rows.length) return null;
  const table = el("table");
  table.appendChild(el("tr", {}, [
    el("th", { text: "对象" }), el("th", { text: "类型" }),
    el("th", { text: "配置" }), el("th", { text: "状态" }),
  ]));
  rows.forEach((r) => {
    table.appendChild(el("tr", {}, [
      el("td", { text: r.name }),
      el("td", { class: "muted small", text: r.kind }),
      el("td", { class: "muted small", text: r.cfg }),
      el("td", {}, [badge(r.label, r.cls)]),
    ]));
  });
  return table;
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
  g.style.display = "block";
  $("quiet-banner").classList.toggle("hidden", !res.quiet);
  $("human-banner").classList.toggle("hidden", !(res.need_human || []).length);
  $("human-banner").onclick = () => activateTab("incidents", "");

  // 需人工列表
  if ((res.need_human || []).length) {
    const list = el("div", { class: "card", style: "margin-bottom:16px" });
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

  // 紧凑统计条
  const stats = el("div", {
    style: "display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap",
  });
  const mkStat = (label, value, cls) => {
    return el("div", {
      style: "flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px",
    }, [
      el("span", { class: `badge ${cls}`, text: value, style: "font-size:18px;min-width:32px;text-align:center" }),
      el("span", { text: label, style: "font-size:13px;color:var(--dim)" }),
    ]);
  };
  const openN = (res.open_incidents || []).length;
  const humanN = (res.need_human || []).length;
  const actN = (res.recent_actions || []).length;
  stats.appendChild(mkStat("活动事件", String(openN), openN ? "warn" : "ok"));
  stats.appendChild(mkStat("需人工", String(humanN), humanN ? "bad" : "ok"));
  stats.appendChild(mkStat("最近操作", String(actN), "dim"));
  g.appendChild(stats);

  // 资产长条
  const openIncs = res.open_incidents || [];
  const incByObj = buildIncIndex(openIncs);
  const list = el("div", {});
  list.appendChild(el("h2", { text: "监控状态", style: "margin-bottom:8px;font-size:14px" }));

  (res.assets || []).forEach((a) => {
    const h = computeAssetHealth(a, openIncs);
    const expanded = state.focus === a.id;
    const row = el("div", {
      style: "background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:6px;overflow:hidden",
    });
    const head = el("div", {
      style: "display:flex;align-items:center;gap:10px;padding:10px 16px;cursor:pointer",
      onclick: () => {
        const newFocus = expanded ? "" : a.id;
        activateTab("overview", newFocus, false);
      },
    }, [
      el("span", { text: expanded ? "▾" : "▸", style: "width:16px;color:var(--dim);flex-shrink:0" }),
      el("span", { text: `${a.id} · ${a.display_name}`, style: "font-weight:500;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" }),
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

    if (expanded) {
      const body = el("div", {
        style: "padding:0 16px 16px;border-top:1px solid var(--line)",
      });
      body.appendChild(el("p", {
        class: "muted small",
        text: `read=${a.read_alias} write=${a.write_alias} host_id=${a.expected_host_id || "未登记"}`,
        style: "margin:12px 0",
      }));

      // 对象表：登记对象 + 外部探测统一为标准行
      const table = renderMonitorTable(a, incByObj);
      if (table) body.appendChild(table);

      body.appendChild(el("div", { class: "row-actions", style: "margin-top:12px" }, [
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
      ]));
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

    const table = renderMonitorTable(a, incByObj);
    if (table) card.appendChild(table);

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

/** 故障闭环摘要：问题 → 处置 → 验证 → 恢复 */
function loopOutcome(inc) {
  const actions = inc.actions || [];
  const vers = (inc.verifications || []).concat(
    ...actions.map((a) => a.verifications || [])
  );
  // 去重
  const seen = new Set();
  const allVers = vers.filter((v) => {
    if (!v || seen.has(v.id)) return false;
    seen.add(v.id);
    return true;
  });
  const lastVer = allVers[allVers.length - 1];
  const lastAct = actions[actions.length - 1];
  let recovered = false;
  let recoverLabel = "处理中";
  let recoverCls = "warn";
  if (inc.status === "resolved" || inc.status === "closed") {
    recovered = true;
    recoverLabel = inc.status === "closed" ? "已关闭" : "已恢复";
    recoverCls = "ok";
  } else if (inc.need_human) {
    recoverLabel = "需人工";
    recoverCls = "bad";
  } else if (lastVer && lastVer.status === "failed") {
    recoverLabel = "验证未通过";
    recoverCls = "bad";
  }
  return {
    problem: inc.title || "",
    assetObject: `${inc.asset_id || "?"}/${inc.object_id || "?"}`,
    invCount: (inc.investigations || []).length,
    invLast: (inc.investigations || []).slice(-1)[0] || null,
    actions,
    lastAct,
    verifications: allVers,
    lastVer,
    recovered,
    recoverLabel,
    recoverCls,
    needHuman: !!inc.need_human,
    needReason: inc.need_human_reason || "",
  };
}

function renderLoopSteps(loop, sum) {
  const wrap = el("div", {
    style: "display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-top:12px",
  });
  const step = (title, text, cls) => {
    const c = el("div", {
      style: "background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:10px;padding:10px 12px",
    }, [
      el("div", { class: "muted small", text: title, style: "margin-bottom:4px" }),
      el("div", { text: text || "—", style: "font-size:13px;line-height:1.4" }),
    ]);
    if (cls) c.appendChild(el("div", { style: "margin-top:6px" }, [badge(cls.label, cls.cls)]));
    return c;
  };

  const inv = loop.invLast;
  const act = loop.lastAct;
  const ver = loop.lastVer;
  wrap.appendChild(step(
    "出现了什么问题",
    `${loop.problem} · ${loop.assetObject}`,
    null
  ));
  wrap.appendChild(step(
    "做了什么处置",
    act
      ? `${ZH_CAP[act.capability] || act.capability} · ${act.object_id || ""}`
        + (act.reason ? `\n${act.reason}` : "")
      : (loop.invCount ? `仅调查 ${loop.invCount} 次，未处置` : "尚未处置"),
    act ? { label: zh(act.state), cls: act.state === "success" ? "ok" : act.state === "failure" || act.state === "unknown" ? "bad" : "warn" } : null
  ));
  wrap.appendChild(step(
    "验证结果",
    ver
      ? `${zh(ver.status)}${ver.note ? " · " + ver.note : ""}`
      : (act && act.state === "success" ? "待验证" : "—"),
    ver ? { label: zh(ver.status === "passed" ? "验证通过" : ver.status === "failed" ? "验证未通过" : ver.status), cls: ver.status === "passed" ? "ok" : ver.status === "failed" ? "bad" : "dim" } : null
  ));
  wrap.appendChild(step(
    "是否恢复",
    loop.needHuman ? (loop.needReason || "需人工介入") : (loop.recovered ? "已恢复" : "处理中"),
    { label: loop.recoverLabel, cls: loop.recoverCls }
  ));
  return wrap;
}

async function renderIncidents() {
  const res = await api("/api/loops");
  const root = $("incidents-list");
  root.innerHTML = "";
  if (!res.ok) return;
  const list = res.loops || [];
  if (!list.length) {
    root.appendChild(el("div", { class: "card muted", text: "无故障闭环" }));
    return;
  }
  list.forEach((inc) => {
    const loop = loopOutcome(inc);
    const card = el("div", { class: "card" });
    const title = (inc.title || "").replace(
      /TargetDown|PrometheusJobMissing|DiskUsageHigh|MemoryLow/g,
      (m) => zh(m)
    );
    card.appendChild(el("h2", {
      text: title,
      style: "font-size:15px;margin-bottom:6px",
    }));
    card.appendChild(el("p", {
      class: "muted small",
      text: `${inc.id} · ${zh(inc.status)} · ${zh(inc.stage)}`
        + ` · 发现 ${fmtTime(inc.created_at)}`
        + (inc.resolved_at ? ` · 解决 ${fmtTime(inc.resolved_at)}` : ""),
    }));
    card.appendChild(renderLoopSteps(loop, inc));
    card.appendChild(el("div", { class: "row-actions", style: "margin-top:12px" }, [
      el("button", {
        class: "btn small", text: "闭环详情",
        onclick: () => openIncidentDetail(inc.id),
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

  // 故障闭环：问题 → 处置 → 验证 → 恢复
  const loop = loopOutcome(inc);
  body.appendChild(el("h3", { text: "故障闭环", style: "margin:16px 0 8px;font-size:14px" }));
  body.appendChild(renderLoopSteps(loop, inc));

  // 关联操作（含验证）
  const relatedActions = inc.actions || [];
  if (relatedActions.length) {
    body.appendChild(el("h3", { text: "关联操作", style: "margin:16px 0 8px;font-size:14px" }));
    relatedActions.forEach((a) => {
      const st = a.state;
      const cls = st === "success" ? "ok" : st === "failure" || st === "unknown" ? "bad" : "warn";
      const cap = ZH_CAP && ZH_CAP[a.capability] || a.capability;
      const vers = a.verifications || [];
      const vtxt = vers.length
        ? vers.map((v) => `验证 ${zh(v.status)}${v.note ? " · " + v.note : ""}`).join("；")
        : "";
      const row = el("div", {
        style: "padding:8px 0;border-bottom:1px solid var(--line);cursor:pointer",
        onclick: () => openActionDetail(a),
      }, [
        el("div", {
          style: "display:flex;justify-content:space-between;align-items:center;gap:8px",
        }, [
          el("div", {}, [
            el("div", { text: `${cap} · ${a.object_id || ""}`, style: "font-size:13px" }),
            el("div", {
              class: "muted small",
              text: `${a.id} · ${a.reason || ""}${vtxt ? " · " + vtxt : ""}`,
            }),
          ]),
          badge(zh(st), cls),
        ]),
      ]);
      body.appendChild(row);
    });
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

function openActionDetail(a) {
  const kids = [
    el("p", {
      class: "muted small",
      text: `${a.asset_id}/${a.object_id} · ${ZH_CAP[a.capability] || a.capability} · ${zh(a.state)}`,
    }),
  ];
  if (a.reason) kids.push(el("p", { class: "muted small", text: a.reason }));
  const vers = a.verifications || [];
  if (vers.length) {
    kids.push(el("h3", { text: "验证", style: "font-size:13px;margin:10px 0 4px" }));
    vers.forEach((v) => {
      kids.push(el("div", {
        class: "muted small",
        text: `${fmtTime(v.started_at)} · ${zh(v.status)}${v.note ? " · " + v.note : ""}`,
      }));
    });
  }
  if (a.incident_id) {
    kids.push(el("p", {
      class: "muted small",
      text: `关联事件 ${a.incident_id}`,
      style: "margin-top:8px",
    }));
  }
  kids.push(el("pre", { text: JSON.stringify(a, null, 2), style: "margin-top:10px;max-height:280px;overflow:auto" }));
  showModal(a.id, kids);
}

/* ---- 权限：三态 UI ↔ policy 字段映射（不改数据模型）----
   禁止       → allow=0, require_approval=1, auto_allowed=0
   需要我确认 → allow=1, require_approval=1, auto_allowed=0
   自动执行   → allow=1, require_approval=0, auto_allowed=1
*/
const PERM_CAP_LABEL = {
  "asset.summary": "查看状态",
  "service.status": "查看服务状态",
  "service.logs": "查看日志",
  "service.restart": "重启服务",
  "service.start": "启动服务",
  "service.stop": "停止服务",
  "container.restart": "重启容器",
  "port.listen": "查看端口",
  "disk.usage": "磁盘使用",
  "memory.available": "内存可用",
  "load.current": "系统负载",
  "probe.status": "外部探测",
};

const PERM_STATE_META = {
  deny: { key: "deny", label: "禁止", cls: "on-deny" },
  confirm: { key: "confirm", label: "需要我确认", cls: "on-confirm" },
  auto: { key: "auto", label: "Ayana 可以自动执行", cls: "on-auto" },
};

function permFlagsToState(p) {
  if (!p || !p.allow) return "deny";
  if (p.auto_allowed) return "auto";
  if (p.require_approval) return "confirm";
  // allow=1, 无需批准, 非 auto：按「自动执行」展示但不改写，直到用户主动切换
  return "auto";
}

function permStateToFlags(state) {
  if (state === "deny") return { allow: false, require_approval: true, auto_allowed: false };
  if (state === "confirm") return { allow: true, require_approval: true, auto_allowed: false };
  return { allow: true, require_approval: false, auto_allowed: true };
}

/** 在 agent 规则里找最具体的一条（对象 > * > 空） */
function findAgentRule(perms, assetId, objectId, capability) {
  const rows = perms.filter(
    (p) =>
      p.subject_type === "auto_rule" &&
      p.subject_id === "agent" &&
      p.capability === capability &&
      (p.asset_id === assetId || p.asset_id === "*" || p.asset_id === "")
  );
  const byObj = rows.filter((p) => p.object_id === objectId);
  if (byObj.length) return byObj[0];
  const star = rows.filter((p) => p.object_id === "*" || p.object_id === "");
  if (star.length) return star[0];
  return null;
}

function kindCaps(kind) {
  const KIND_CAPS = {
    service: ["asset.summary", "service.status", "service.logs", "service.restart", "service.start", "service.stop"],
    container: ["asset.summary", "service.status", "service.logs", "container.restart"],
    port: ["port.listen", "asset.summary"],
    probe: ["probe.status"],
    filesystem: ["disk.usage", "asset.summary"],
    "": ["asset.summary", "disk.usage", "memory.available", "load.current"],
  };
  return KIND_CAPS[kind] || KIND_CAPS[""];
}

function renderSeg(current, onPick) {
  const seg = el("div", { class: "seg" });
  ["deny", "confirm", "auto"].forEach((k) => {
    const meta = PERM_STATE_META[k];
    const b = el("button", {
      type: "button",
      text: meta.label,
      class: current === k ? meta.cls : "",
      onclick: () => onPick(k),
    });
    seg.appendChild(b);
  });
  return seg;
}

async function saveAgentPerm(assetId, objectId, capability, state) {
  const flags = permStateToFlags(state);
  const res = await api("/api/permissions", {
    method: "POST",
    body: JSON.stringify({
      subject_type: "auto_rule",
      subject_id: "agent",
      capability,
      asset_id: assetId,
      object_id: objectId,
      ...flags,
    }),
  });
  if (!res.ok) {
    showModal("保存失败", [el("pre", { text: res.message || res.error || "unknown" })]);
    return false;
  }
  return true;
}

on("kb-search", "click", () => {
  setTabHash("knowledge", "");
  renderKnowledge();
});

function openKnowledgeDoc(id) {
  // pushState 保留历史，浏览器/按钮可回退
  history.pushState(null, "", "#knowledge/" + id);
  state.tab = "knowledge";
  state.focus = id;
  renderKnowledge();
}

async function renderKnowledge() {
  const root = $("knowledge-list");
  if (!root) return;
  root.innerHTML = "";
  const filters = document.querySelector("#tab-knowledge > .card");
  const docId = state.focus || "";
  if (filters) filters.classList.toggle("hidden", !!docId);
  if (docId) {
    await renderKnowledgeDoc(docId, root);
    return;
  }
  await renderKnowledgeList(root);
}

async function renderKnowledgeList(root) {
  const q = ($("kb-q") && $("kb-q").value) || "";
  const typ = ($("kb-type") && $("kb-type").value) || "";
  const st = ($("kb-status") && $("kb-status").value) || "";
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (typ) params.set("type", typ);
  if (st) params.set("status", st);
  const res = await api("/api/knowledge?" + params.toString());
  if (!res.ok) {
    root.appendChild(el("div", { class: "card muted", text: "加载失败" }));
    return;
  }
  const list = res.knowledge || [];
  if (!list.length) {
    root.appendChild(el("div", { class: "card muted", text: "无匹配知识" }));
    return;
  }
  list.forEach((k) => {
    const card = el("div", { class: "card kb-list-item" });
    card.onclick = () => openKnowledgeDoc(k.id);
    card.appendChild(el("h2", { text: k.title, style: "font-size:15px;margin-bottom:6px" }));
    const meta = el("div", { class: "muted small", style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center" });
    meta.appendChild(badge(k.type, k.type === "issue" ? "warn" : k.type === "procedure" ? "dim" : "ok"));
    meta.appendChild(badge(k.status, k.status === "active" ? "ok" : k.status === "deprecated" ? "bad" : "dim"));
    meta.appendChild(el("span", { text: "id: " + k.id }));
    card.appendChild(meta);
    if ((k.objects || []).length) {
      card.appendChild(el("div", {
        class: "muted small",
        text: "涉及: " + k.objects.join(" · "),
        style: "margin-top:6px",
      }));
    }
    if ((k.tags || []).length) {
      card.appendChild(el("div", { class: "muted small", text: "标签: " + k.tags.join(" · ") }));
    }
    card.appendChild(el("div", { class: "row-actions", style: "margin-top:10px" }, [
      el("button", { class: "btn small primary", text: "阅读文档", onclick: (e) => { e.stopPropagation(); openKnowledgeDoc(k.id); } }),
    ]));
    root.appendChild(card);
  });
}

async function renderKnowledgeDoc(docId, root) {
  const res = await api("/api/knowledge?id=" + encodeURIComponent(docId));
  if (!res.ok) {
    root.appendChild(el("div", { class: "card muted", text: "未找到文档" }));
    return;
  }
  const k = res.knowledge;
  const layout = el("div", { class: "kb-layout" });

  // 侧栏：返回 + 本页目录 + 全部文档
  const side = el("div", { class: "kb-side" });
  side.appendChild(el("div", {
    class: "side-title",
  }, [
    el("a", {
      text: "← 全部知识",
      onclick: () => {
        history.pushState(null, "", "#knowledge");
        state.focus = "";
        renderKnowledge();
      },
      style: "font-weight:600",
    }),
  ]));
  const toc = collectToc(k.body || "");
  if (toc.length) {
    side.appendChild(el("div", { class: "side-title", text: "本页目录" }));
    toc.forEach((t) => {
      side.appendChild(el("a", {
        text: t.text,
        class: t.level === 1 ? "" : t.level === 2 ? "l2" : "l3",
        onclick: () => {
          const n = document.getElementById(t.id);
          if (n) n.scrollIntoView({ behavior: "smooth", block: "start" });
        },
      }));
    });
  }

  // 主栏：文档正文
  const main = el("div", { class: "kb-main" });
  main.appendChild(el("div", { class: "crumb" }, [
    el("a", {
      text: "知识库",
      onclick: () => {
        history.pushState(null, "", "#knowledge");
        state.focus = "";
        renderKnowledge();
      },
    }),
    document.createTextNode(" / " + (k.title || k.id)),
  ]));
  main.appendChild(el("h1", { class: "doc-title", text: k.title || k.id }));
  const meta = el("div", { class: "doc-meta" });
  meta.appendChild(badge(k.type, k.type === "issue" ? "warn" : k.type === "procedure" ? "dim" : "ok"));
  meta.appendChild(badge(k.status, k.status === "active" ? "ok" : k.status === "deprecated" ? "bad" : "dim"));
  meta.appendChild(el("span", { class: "muted small", text: "id: " + k.id }));
  if ((k.objects || []).length) {
    meta.appendChild(el("span", { class: "muted small", text: "涉及: " + k.objects.join(" · ") }));
  }
  if ((k.tags || []).length) {
    meta.appendChild(el("span", { class: "muted small", text: "标签: " + k.tags.join(" · ") }));
  }
  main.appendChild(meta);
  main.appendChild(renderMarkdown(k.body || ""));

  layout.appendChild(side);
  layout.appendChild(main);
  root.appendChild(layout);
}

async function renderPermissions() {
  const [pRes, aRes] = await Promise.all([api("/api/permissions"), api("/api/assets")]);
  const root = $("perm-agent");
  const adv = $("perm-list");
  root.innerHTML = "";
  if (adv) adv.innerHTML = "";
  if (!pRes.ok) return;
  const perms = pRes.permissions || [];
  const assets = (aRes && aRes.ok && aRes.assets) || state.assets || [];

  // ---- 默认：Agent × 资产/对象 × 能力 ----
  if (!assets.length) {
    root.appendChild(el("div", { class: "muted small", text: "无资产" }));
  }
  assets.forEach((a) => {
    const wrap = el("div", { class: "perm-asset" });
    wrap.appendChild(el("h3", {
      text: `${a.id} · ${a.display_name}`,
      style: "font-size:14px;margin:4px 0 2px",
    }));
    const objs = (a.objects || []).length
      ? a.objects
      : [{ id: "*", name: "(全部对象)", kind: "" }];
    objs.forEach((o) => {
      const box = el("div", { class: "perm-obj" });
      box.appendChild(el("h3", { text: o.name }));
      box.appendChild(el("div", {
        class: "sub",
        text: `${o.kind || "asset"}${o.unit ? " · " + o.unit : ""}${o.container ? " · " + o.container : ""}${o.port ? " · " + o.port + "/" + (o.protocol || "") : ""}`,
      }));
      const objectId = o.id || o.name || "*";
      kindCaps(o.kind || "").forEach((cap) => {
        const rule = findAgentRule(perms, a.id, objectId, cap);
        const stateKey = permFlagsToState(rule);
        const row = el("div", { class: "perm-row" });
        row.appendChild(el("div", {
          class: "cap-name",
          text: PERM_CAP_LABEL[cap] || cap,
        }));
        row.appendChild(renderSeg(stateKey, async (next) => {
          const ok = await saveAgentPerm(a.id, objectId, cap, next);
          if (ok) {
            const btns = row.querySelector(".seg");
            if (btns) {
              btns.querySelectorAll("button").forEach((b) => {
                b.className = "";
              });
              const meta = PERM_STATE_META[next];
              const idx = ["deny", "confirm", "auto"].indexOf(next);
              const target = btns.querySelectorAll("button")[idx];
              if (target) target.className = meta.cls;
            }
          }
        }));
        box.appendChild(row);
      });
      wrap.appendChild(box);
    });
    root.appendChild(wrap);
  });

  // ---- 高级：原始规则表 ----
  if (!adv) return;
  adv.appendChild(el("p", {
    class: "muted small",
    text: pRes.note || "主机侧 commands.json / forced-command / sudoers 为独立最终安全上限。",
  }));
  const table = el("table");
  table.appendChild(el("tr", {}, [
    el("th", { text: "id" }), el("th", { text: "主体" }), el("th", { text: "能力" }),
    el("th", { text: "资产" }), el("th", { text: "对象" }), el("th", { text: "允许" }),
    el("th", { text: "批准" }), el("th", { text: "自动" }), el("th", { text: "" }),
  ]));
  perms.forEach((p) => {
    table.appendChild(el("tr", {}, [
      el("td", { text: String(p.id) }),
      el("td", { text: p.subject_type + ":" + p.subject_id }),
      el("td", { text: (PERM_CAP_LABEL[p.capability] || p.capability) + " (" + p.capability + ")" }),
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
  adv.appendChild(table);
}

on("perm-save", "click", async () => {
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
on("modal-close", "click", () => {
  $("modal").classList.add("hidden");
  setTabHash(state.tab, "");
});

/* ---- init ---- */
boot();
