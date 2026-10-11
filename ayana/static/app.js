/* Ayana Web 控制台 */
const state = {
  csrf: "",
  user: null,
  tab: "overview",
  monitorSub: "metrics",
  notifySub: "channels",
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
  const m = h.match(/^(overview|incidents|monitor|checks|promconfig|messages|connections|notify|knowledge|permissions|audit)(?:\/(.+))?$/);
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
  // 旧 hash 兼容：promconfig → 资源-Prometheus，messages → 通知-消息记录
  if (tab === "promconfig") {
    tab = "monitor";
    queueMicrotask(() => setMonitorSub("prom"));
  } else if (tab === "messages") {
    tab = "notify";
    queueMicrotask(() => setNotifySub("messages"));
  }
  const valid = ["overview", "incidents", "monitor", "checks", "connections", "notify", "knowledge", "permissions", "audit"];
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

function setMonitorSub(sub) {
  if (!sub) return;
  state.monitorSub = sub;
  document.querySelectorAll("#monitor-subnav .subtab").forEach((b) => {
    b.classList.toggle("active", b.dataset.sub === sub);
  });
  ["metrics", "onboard", "prom"].forEach((k) => {
    const el = document.getElementById("monitor-sub-" + k);
    if (el) el.classList.toggle("hidden", k !== sub);
  });
}

function setNotifySub(sub) {
  if (!sub) return;
  state.notifySub = sub;
  document.querySelectorAll("#notify-subnav .subtab").forEach((b) => {
    b.classList.toggle("active", b.dataset.sub === sub);
  });
  ["channels", "messages", "outbox"].forEach((k) => {
    const el = document.getElementById("notify-sub-" + k);
    if (el) el.classList.toggle("hidden", k !== sub);
  });
}

document.addEventListener("click", (e) => {
  const t = e.target.closest(".subtab");
  if (!t) return;
  const nav = t.closest("#monitor-subnav") || t.closest("#notify-subnav");
  if (!nav) return;
  if (nav.id === "monitor-subnav") setMonitorSub(t.dataset.sub);
  else setNotifySub(t.dataset.sub);
  if (nav.id === "monitor-subnav" && t.dataset.sub === "prom") renderPromConfig();
  if (nav.id === "notify-subnav" && t.dataset.sub === "messages") renderMessages();
  if (nav.id === "notify-subnav" && t.dataset.sub === "outbox") {
    const b = $("notify-outbox-refresh");
    if (b) b.click();
  }
});

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
  // 版本取服务端 health，不硬编码
  try {
    const h = await fetch("/health").then(r => r.json());
    state.version = "v" + (h.version || "unknown");
  } catch { state.version = "v?"; }
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
  if (state.tab === "monitor") {
    if (state.monitorSub === "prom") await renderPromConfig();
    else if (state.monitorSub !== "onboard") await renderMonitor();
  }
  if (state.tab === "checks") await renderChecks();
  if (state.tab === "connections") await renderConnections();
  if (state.tab === "notify") {
    if (state.notifySub === "messages") await renderMessages();
    else await renderNotify();
  }
  if (state.tab === "knowledge") await renderKnowledge();
  if (state.tab === "permissions") await renderPermissions();
  if (state.tab === "audit") await renderAudit();
}

/* ---- 统一健康状态 ---- */
function computeAssetHealth(asset, openIncs) {
  // 优先 host_health_dot（小圆点统一语义），其次 backend health
  const dot = asset.health_dot || {};
  const h = asset.health || {};
  const openCount = openIncs.filter((i) => i.asset_id === asset.id).length;
  const map = {
    healthy: { health: "正常", healthCls: "ok" },
    unhealthy: { health: "异常", healthCls: "bad" },
    degraded: { health: "降级", healthCls: "warn" },
    stale: { health: "观测过期", healthCls: "warn" },
    unknown: { health: "观测不全", healthCls: "warn" },
  };
  const m = map[h.state] || map.unknown;
  return {
    openCount,
    hasProbe: (h.coverage || "").startsWith("required"),
    health: dot.label || h.label || m.health,
    healthCls: dot.cls || m.healthCls,
    coverage: h.coverage || "无探测项",
    coverageCls: h.state === "healthy" ? "ok" : "warn",
    probeState: dot.state || h.state,
    hysteriaState: "",
    hysteriaTargets: [],
  };
}

function computeObjectStatus(obj, assetId, incByObj) {
  // 无 required check / 无观测 → 未观测，不得「正常」
  const keys = [
    `${assetId}/${obj.id}`,
    `${assetId}/${obj.name}`,
    `${assetId}/${assetId}:${obj.kind}:${obj.name}`,
  ];
  const hit = keys.map((k) => incByObj[k]).find(Boolean);
  if (hit) return { label: "异常", cls: "bad", inc: hit };
  return { label: "未观测", cls: "warn", inc: null };
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
  if (state._overviewLoading) return;
  state._overviewLoading = true;
  try {
    const res = await api("/api/overview");
    if (!res.ok) return;
    const g = $("overview-grid");
    g.innerHTML = "";
    g.style.display = "block";
    $("quiet-banner").classList.toggle("hidden", !res.quiet);
    $("human-banner").classList.toggle("hidden", !(res.need_human || []).length);
    $("human-banner").onclick = () => activateTab("incidents", "");

    // 系统健康度（唯一分数 + MAGI 分项拆解）
    const hr = res.health_ratio || {};
    g.appendChild(buildHealthRatioCard(hr));

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
    const pending = res.pending_actions || 0;
    const src = res.sources || {};
    const promBad = src.prometheus_unhealthy || 0;
    stats.appendChild(mkStat("活动事件", String(openN), openN ? "warn" : "ok"));
    stats.appendChild(mkStat("需人工", String(humanN), humanN ? "bad" : "ok"));
    stats.appendChild(mkStat("待批准/执行", String(pending), pending ? "warn" : "ok"));
    stats.appendChild(mkStat("Prom 异常目标", String(promBad), promBad ? "bad" : "ok"));
    g.appendChild(stats);

    // 只列异常主机摘要（正常主机进「资源」）
    const openIncs = res.open_incidents || [];
    const badHosts = (res.assets || []).filter((a) => {
      const st = (a.health && a.health.state) || "";
      const ds = (a.health_dot && a.health_dot.state) || "";
      return st === "unhealthy" || st === "degraded" || st === "stale"
        || ds === "bad" || ds === "warn" || ds === "collect_error";
    });
    const hostCard = el("div", { class: "card" });
    hostCard.appendChild(el("h2", { text: "需要关注的主机" }));
    if (!badHosts.length) {
      hostCard.appendChild(el("p", {
        class: "muted small",
        text: "当前没有异常主机。完整监控与指标请到「资源」。",
      }));
    } else {
      badHosts.forEach((a) => {
        const h = computeAssetHealth(a, openIncs);
        const row = el("div", {
          style: "display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--line);cursor:pointer",
          onclick: () => {
            activateTab("monitor", "");
            monitorState.host = a.id;
            renderMonitor();
          },
        }, [
          el("div", {}, [
            el("div", { text: `${a.id} · ${a.display_name}`, style: "font-size:14px" }),
            el("div", { class: "muted small", text: h.coverage || "" }),
          ]),
          badge(h.health, h.healthCls),
        ]);
        hostCard.appendChild(row);
      });
    }
    g.appendChild(hostCard);
  } finally {
    state._overviewLoading = false;
  }
}

/** 系统健康度卡片：唯一分数 + MAGI 三行分项拆解（非独立评分） */
function buildHealthRatioCard(hr) {
  const card = el("div", { class: "card health-ratio-card" });
  const ratio = hr.ratio;
  const label = hr.label || "—";
  const colorCls = hr.color || "dim";
  const healthy = hr.healthy ?? 0;
  const total = hr.total ?? 0;
  const hasRatio = ratio != null && total > 0;

  // 角标装饰（克制的指挥台细线）
  card.appendChild(el("div", { class: "hr-corner tl" }));
  card.appendChild(el("div", { class: "hr-corner tr" }));
  card.appendChild(el("div", { class: "hr-corner bl" }));
  card.appendChild(el("div", { class: "hr-corner br" }));

  const head = el("div", { class: "hr-head" }, [
    el("div", { class: "hr-title", text: "系统健康度" }),
    el("div", { class: "hr-sub", text: "SYSTEM HEALTH INDEX" }),
  ]);
  card.appendChild(head);

  const body = el("div", { class: "hr-body" });
  const valBox = el("div", { class: "hr-val-box" });
  const val = el("div", { class: "hr-val " + colorCls, text: label });
  valBox.appendChild(val);
  valBox.appendChild(el("div", {
    class: "hr-count",
    text: hasRatio ? `健康 ${healthy} / 总计 ${total}` : "暂无监控项",
  }));
  body.appendChild(valBox);

  // 主进度条：唯一分数
  const barBox = el("div", { class: "hr-bar-box" });
  const bar = el("div", { class: "hr-bar" });
  const pct = hasRatio ? Math.max(0, Math.min(100, ratio)) : 0;
  const fill = el("div", {
    class: "hr-bar-fill " + colorCls,
    style: `width:${hasRatio ? pct : 0}%`,
  });
  bar.appendChild(fill);
  barBox.appendChild(bar);
  if (hasRatio) {
    barBox.appendChild(el("div", {
      class: "hr-bar-tip",
      text: `${healthy} 项健康 · 共 ${total} 项监控`,
    }));
  }
  body.appendChild(barBox);
  card.appendChild(body);

  // MAGI 三行：分项解释，加总 = 主分数
  const magi = el("div", { class: "hr-magi" });
  magi.appendChild(el("div", {
    class: "hr-magi-title",
    text: "系统同步率 · SYSTEM SYNC RATIO",
  }));
  (hr.sources || []).forEach((s) => {
    const empty = !s.total;
    const spct = empty ? 0 : Math.round((s.healthy * 100) / s.total);
    const row = el("div", { class: "hr-magi-row" + (empty ? " na" : "") });
    row.appendChild(el("div", { class: "hr-magi-code", text: s.code }));
    row.appendChild(el("div", { class: "hr-magi-label", text: s.label }));
    const mini = el("div", { class: "hr-mini" });
    mini.appendChild(el("div", {
      class: "hr-mini-fill " + (empty ? "dim" : s.state === "ok" ? "ok" : s.state === "warn" ? "warn" : s.state === "bad" ? "bad" : "dim"),
      style: `width:${empty ? 0 : Math.max(spct, s.healthy > 0 ? 8 : 0)}%`,
    }));
    row.appendChild(mini);
    row.appendChild(el("div", {
      class: "hr-magi-frac",
      text: empty ? "—" : `${s.healthy}/${s.total}`,
    }));
    magi.appendChild(row);
  });
  card.appendChild(magi);
  return card;
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
  const seen = new Set();
  const allVers = vers.filter((v) => {
    if (!v || seen.has(v.id)) return false;
    seen.add(v.id);
    return true;
  });
  const lastVer = allVers[allVers.length - 1];
  const lastAct = actions[actions.length - 1];
  // P0-04：outcome 来自服务端；closed ≠ recovered
  const outcome = inc.outcome || "";
  let recovered = outcome === "recovered";
  let recoverLabel = "处理中";
  let recoverCls = "warn";
  if (inc.status === "closed") {
    recovered = false;
    recoverLabel = "已关闭（未证实恢复）";
    recoverCls = "dim";
  } else if (outcome === "recovered" || inc.status === "resolved") {
    recovered = true;
    recoverLabel = "已恢复";
    recoverCls = "ok";
  } else if (outcome === "closed_unverified") {
    recoverLabel = "已关闭（未证实恢复）";
    recoverCls = "dim";
  } else if (inc.need_human) {
    recoverLabel = "需人工";
    recoverCls = "bad";
  } else if (outcome === "unrecovered") {
    recoverLabel = "未恢复";
    recoverCls = "bad";
  } else if (outcome === "unknown") {
    recoverLabel = "结论未知";
    recoverCls = "warn";
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
    outcome,
    generation: inc.generation || 1,
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
  const disp = d.disposition || {};
  const body = el("div");

  // 标题
  body.appendChild(el("h2", { text: sum.title || inc.title || "" }));
  body.appendChild(el("p", {
    class: "muted small",
    text: `状态: ${sum.status_zh || ""} · 阶段: ${sum.stage_zh || ""}`
      + ` · 发现 ${fmtTime(inc.created_at)}`
      + (inc.resolved_at ? ` · 解决 ${fmtTime(inc.resolved_at)}` : ""),
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

  // 处置上下文（P1-01：证据 / 理由 / 权限 / 验证 / 批准拒绝）
  if ((disp.proposals || []).length || disp.evidence_summary) {
    body.appendChild(el("h3", { text: "处置上下文", style: "margin:16px 0 8px;font-size:14px" }));
    if (disp.evidence_summary) {
      const evBox = el("div", {
        style: "background:rgba(120,160,255,.08);border-radius:8px;padding:10px;margin:8px 0",
      });
      evBox.appendChild(el("div", { text: "调查证据摘要", style: "font-weight:600;margin-bottom:4px" }));
      evBox.appendChild(el("div", { class: "muted small", text: disp.evidence_summary }));
      body.appendChild(evBox);
    }
    (disp.proposals || []).forEach((p) => {
      const box = el("div", {
        style: "border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0",
      });
      box.appendChild(el("div", {
        text: `${p.capability_zh || p.capability} · ${p.asset_id}/${p.object_id}`,
        style: "font-weight:600",
      }));
      [
        `理由: ${p.reason || "-"}`,
        `runbook/template: ${p.runbook_id || p.template_id || "-"}${p.runbook_rev ? " rev " + p.runbook_rev : ""}`,
        `权限结论: ${p.readable || p.decision || "-"}${p.decision_reason ? " · " + p.decision_reason : ""}`,
        `验证目标: ${p.verification_target || "按 profile 独立判定"}`,
        `模式: ${p.mode || "manual"} · 提案 ${p.action_id}`,
        p.approval_deadline ? `批准期限: ${fmtTime(p.approval_deadline)}` : "",
      ].filter(Boolean).forEach((t) => box.appendChild(el("div", { class: "muted small", text: t })));
      box.appendChild(el("div", { class: "row-actions", style: "margin-top:10px" }, [
        el("button", {
          class: "btn", text: "批准并执行",
          onclick: async () => {
            const reason = prompt("批准原因（可空）:", "") || "";
            await api(`/api/actions/${p.action_id}/approve`, {
              method: "POST",
              body: JSON.stringify({ execute: true, reason }),
            });
            $("modal").classList.add("hidden");
            openIncidentDetail(incId);
          },
        }),
        el("button", {
          class: "btn danger", text: "拒绝",
          onclick: async () => {
            const reason = prompt("拒绝原因:", "") || "";
            if (reason === null) return;
            await api(`/api/actions/${p.action_id}/reject`, {
              method: "POST",
              body: JSON.stringify({ reason }),
            });
            $("modal").classList.add("hidden");
            openIncidentDetail(incId);
          },
        }),
      ]));
      body.appendChild(box);
    });
    if (disp.policy) {
      body.appendChild(el("div", {
        class: "muted small",
        text: `当前权限求值: ${disp.policy.readable || disp.policy.decision || ""}`
          + (disp.policy.matched_rule ? ` · 命中规则 #${disp.policy.matched_rule.id}` : "")
          + (disp.policy.reason ? ` · ${disp.policy.reason}` : ""),
        style: "margin:6px 0",
      }));
    }
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
  if (!p) return "deny";
  // 优先使用服务端 effective decision，前端不重算优先级
  if (p.decision === "forbidden") return "deny";
  if (p.decision === "approval_required") return "confirm";
  if (p.decision === "automatic") return "auto";
  if (!p.allow) return "deny";
  if (p.auto_allowed && !p.require_approval) return "auto";
  return "confirm";
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
  renderAgentCeiling();
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
        if (rule && rule.readable) {
          row.appendChild(el("div", {
            class: "muted small",
            text: `服务端结论: ${rule.readable}${rule.decision ? " · " + rule.decision : ""}`,
            style: "font-size:11px;opacity:.75",
          }));
        }
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

/* ---- SSH connections / credentials ---- */
function credLabel(c) {
  return `${c.id.slice(0, 12)} · ${c.kind} · ${c.name || "(未命名)"}`;
}

function hostStatusBadge(ep) {
  if (!ep) return el("span", { class: "badge dim", text: "未配置 SSH" });
  const trusted = !!ep.host_key_trusted_at && !!ep.host_key_sha256;
  return el("span", {
    class: "badge " + (trusted ? "ok" : "warn"),
    text: trusted ? "SSH 已信任" : "SSH 待信任",
  });
}

async function testHostChannel(assetId, role) {
  const out = await api(`/api/assets/${assetId}/test`, {
    method: "POST",
    body: JSON.stringify({ role: role || "write" }),
  });
  return showChannelResult(assetId, out, role);
}

function showChannelResult(assetId, out, role) {
  const ch = out.channel === "ssh" ? "原生 SSH" : "无通道";
  const kids = [];

  if (out.detail === "host_key_untrusted" && out.host_key_info) {
    const info = out.host_key_info;
    kids.push(el("p", {
      text: "首次连接，需要确认主机指纹",
      style: "font-size:16px;font-weight:600",
    }));
    kids.push(el("p", {
      class: "muted",
      text: `主机 ${info.host}:${info.port}　算法 ${info.key_type || "unknown"}`,
    }));
    kids.push(el("p", {
      style: "font-family:ui-monospace,Menlo,monospace;font-size:13px;margin:12px 0;padding:10px;background:rgba(255,255,255,.05);border-radius:8px",
      text: info.fingerprint || "(无法获取指纹)",
    }));
    kids.push(el("p", {
      class: "muted small",
      text: "请与服务器上的指纹核对（ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub）。",
    }));
    showModal(`信任主机 · ${assetId}`, kids);
    // 追加按钮到 modal actions
    const actions = document.querySelector(".modal-actions");
    actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
    const cancel = el("button", {
      class: "btn btn-trust", text: "取消",
      onclick: () => {
        $("modal").classList.add("hidden");
        actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
      },
    });
    const trust = el("button", {
      class: "btn primary btn-trust", text: "信任并连接",
      onclick: async () => {
        trust.disabled = true;
        trust.textContent = "信任中…";
        const t = await api("/api/ssh/endpoints/trust", {
          method: "POST",
          body: JSON.stringify({
            asset_id: assetId,
            role: role || "write",
            host_key_sha256: info.fingerprint,
            host_key_line: info.key_line || "",
          }),
        });
        if (!t.ok) {
          trust.textContent = "信任失败";
          trust.disabled = false;
          kids.push(el("p", { class: "error", text: t.error || "trust failed" }));
          return;
        }
        trust.textContent = "已信任，继续连接…";
        const again = await api(`/api/assets/${assetId}/test`, {
          method: "POST",
          body: JSON.stringify({ role: role || "write" }),
        });
        actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
        showChannelResult(assetId, again, role);
        renderConnections();
      },
    });
    actions.insertBefore(trust, actions.firstChild);
    actions.insertBefore(cancel, trust.nextSibling);
    return out;
  }

  if (out.detail === "host_key_changed") {
    const info = out.host_key_info || {};
    kids.push(el("p", {
      text: "主机密钥已变更，已阻止连接",
      style: "font-size:16px;font-weight:600;color:var(--bad)",
    }));
    kids.push(el("p", {
      class: "muted",
      text: `${info.host || assetId}:${info.port || ""} 的指纹与之前记录不一致，不会自动覆盖。`,
    }));
    kids.push(el("p", { class: "small", text: "已保存的指纹：" }));
    kids.push(el("p", {
      style: "font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--warn)",
      text: info.stored_fingerprint || "-",
    }));
    kids.push(el("p", { class: "small", text: "当前指纹：" }));
    kids.push(el("p", {
      style: "font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--bad)",
      text: info.current_fingerprint || "-",
    }));
    kids.push(el("p", {
      class: "muted small",
      text: "若确认服务器重装/更换，请在服务器核对指纹后再手动选择信任新指纹。",
    }));
    showModal(`安全警告 · ${assetId}`, kids);
    const actions = document.querySelector(".modal-actions");
    actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
    const retrust = el("button", {
      class: "btn danger btn-trust", text: "确认换机，信任新指纹",
      onclick: async () => {
        if (!confirm("确认服务器身份无误？将用新指纹覆盖旧记录。")) return;
        const scan = out.host_key_scan || {};
        const t = await api("/api/ssh/endpoints/trust", {
          method: "POST",
          body: JSON.stringify({
            asset_id: assetId,
            role: role || "write",
            host_key_sha256: info.current_fingerprint || scan.fingerprint,
            host_key_line: scan.key_line || "",
          }),
        });
        actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
        if (!t.ok) {
          kids.push(el("p", { class: "error", text: t.error || "trust failed" }));
          return;
        }
        const again = await api(`/api/assets/${assetId}/test`, {
          method: "POST",
          body: JSON.stringify({ role: role || "write" }),
        });
        showChannelResult(assetId, again, role);
        renderConnections();
      },
    });
    actions.insertBefore(retrust, actions.firstChild);
    return out;
  }

  // 常规结果
  const verdict = out.ok ? "通" : "不通";
  const color = out.ok ? "var(--ok)" : "var(--bad)";
  kids.push(el("p", {
    text: `结果：${ch} ${verdict}`,
    style: `font-size:16px;font-weight:600;color:${color}`,
  }));
  kids.push(el("p", { text: out.hint || "", class: "muted" }));
  if (out.has_credential !== undefined) {
    const authText = out.auth_method === "key" ? "密钥登录"
      : out.auth_method === "password" ? "密码登录"
      : out.has_credential ? "已绑定凭据" : "未配置密码或密钥";
    kids.push(el("p", { class: "small", text: `当前认证方式：${authText}` }));
  }
  const statusMap = {
    ssh_ok: "SSH 认证与连接正常",
    ssh_failed: "SSH 连接或认证失败",
    ssh_error: "SSH 测试出现异常",
    endpoint_without_credential: "未配置密码或密钥",
    host_key_untrusted: "主机指纹尚未信任",
    host_key_changed: "主机密钥变更",
    ssh_not_configured: "未配置 SSH",
    none: "没有可用通道",
  };
  kids.push(el("p", {
    class: "small muted",
    text: `状态：${statusMap[out.detail] || out.detail || "-"}`,
  }));
  if (out.probe_cmds && out.probe_cmds.length) {
    out.probe_cmds.forEach((r) => {
      kids.push(el("p", {
        class: "small",
        text: `${r.ok ? "✓" : "✗"} ${r.cmd} → ${r.stdout || r.stderr || r.returncode}`,
      }));
    });
  }
  if (out.raw && out.raw.output) {
    kids.push(el("details", {}, [
      el("summary", { class: "small muted", text: "技术细节" }),
      el("pre", {
        class: "small",
        style: "white-space:pre-wrap;color:var(--dim)",
        text: String(out.raw.output).slice(0, 400),
      }),
    ]));
  }
  showModal(`连接测试 · ${assetId}`, kids);
  return out;
}

async function renderConnections() {
  const [assetRes, credRes, roleRes] = await Promise.all([
    api("/api/assets"),
    api("/api/ssh/credentials").catch(() => ({ ok: false })),
    api("/api/ssh/roles").catch(() => ({ ok: false })),
  ]);
  const hosts = (assetRes && assetRes.ok && assetRes.assets) || [];
  const creds = (credRes && credRes.ok && credRes.credentials) || [];
  const roles = (roleRes && roleRes.ok && roleRes.roles) || [
    { name: "write", kind: "write", label: "可执行" },
    { name: "read", kind: "read", label: "只读" },
  ];

  fillSelect("host-cred", [{ v: "", t: "（无）" }, ...creds.map((c) => ({ v: c.id, t: credLabel(c) }))]);
  fillSelect("host-role", roles.map((r) => ({
    v: r.name,
    t: `${r.name} · ${r.label || r.kind}`,
  })));
  fillSelect("ssh-test-asset", hosts.map((a) => ({ v: a.id, t: a.id + " / " + (a.display_name || "") })));
  fillSelect("ssh-test-role", roles.map((r) => ({ v: r.name, t: `${r.name} (${r.kind})` })));

  // ---- host list ----
  const box = $("host-list");
  box.innerHTML = "";
  if (!hosts.length) {
    box.appendChild(el("p", { class: "muted small", text: "还没有主机。在上方「添加主机」填写连接信息。" }));
  } else {
    hosts.forEach((a) => {
      const eps = a.ssh_endpoints || [];
      const writeEp = eps.find((e) => e.role === "write") || eps[0];
      const card = el("div", {
        style: "border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:10px",
      });
      const head = el("div", {
        style: "display:flex;align-items:center;gap:10px;flex-wrap:wrap",
      }, [
        el("span", { text: a.id, style: "font-weight:600;font-size:15px" }),
        el("span", { text: a.display_name || "", class: "muted small" }),
        hostStatusBadge(writeEp),
        el("span", {
          class: "badge " + (a.enabled ? "ok" : "bad"),
          text: a.enabled ? "启用" : "停用",
        }),
        el("div", { style: "flex:1" }),
        el("button", {
          class: "btn small", text: "测试",
          onclick: async () => {
            await testHostChannel(a.id, writeEp ? writeEp.role : "write");
            renderConnections();
          },
        }),
        el("button", {
          class: "btn small", text: a.enabled ? "停用" : "启用",
          onclick: async () => {
            await api(`/api/assets/${a.id}/update`, {
              method: "POST",
              body: JSON.stringify({ enabled: !a.enabled }),
            });
            renderConnections();
          },
        }),
        el("button", {
          class: "btn danger small", text: "删除",
          onclick: async () => {
            if (!confirm(`删除主机 ${a.id}？会一并删除其对象与 SSH 端点。`)) return;
            const r = await api(`/api/assets/${a.id}`, { method: "DELETE" });
            if (!r.ok) showModal("删除失败", [el("pre", { text: JSON.stringify(r, null, 2) })]);
            renderConnections();
          },
        }),
      ]);
      card.appendChild(head);

      const body = el("div", { style: "margin-top:10px;display:flex;flex-direction:column;gap:8px" });
      if (writeEp) {
        const credId = writeEp.credential_id || "";
        const cred = creds.find((c) => c.id === credId);
        const authLabel = cred
          ? (cred.kind === "private_key" ? "认证：密钥" : "认证：密码")
          : "认证：未配置";
        const authCls = cred ? (cred.kind === "private_key" ? "ok" : "warn") : "bad";
        body.appendChild(el("div", {
          class: "muted small",
          text: `SSH ${writeEp.role} · ${writeEp.username}@${writeEp.host}:${writeEp.port} · 指纹 ${writeEp.host_key_sha256 ? writeEp.host_key_sha256.slice(0, 24) + "…" : "未信任"}`,
        }));
        body.appendChild(el("div", { style: "margin:4px 0 8px" }, [
          el("span", { class: "badge " + authCls, text: authLabel }),
          cred ? el("span", {
            class: "muted small",
            style: "margin-left:8px",
            text: `凭据 ${cred.name || cred.id.slice(0, 10)}`,
          }) : el("span", { class: "muted small", style: "margin-left:8px", text: "请配置密码或密钥" }),
        ]));
        const actions = el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, [
          el("button", {
            class: "btn small", text: "打开终端",
            onclick: () => openTerminal(a.id, writeEp),
          }),
          el("button", {
            class: "btn small", text: "信任 host key",
            onclick: async () => {
              const r = await api(`/api/assets/${writeEp.asset_id}/test`, {
                method: "POST",
                body: JSON.stringify({ role: writeEp.role }),
              });
              if (r.detail === "host_key_untrusted" && r.host_key_info) {
                showChannelResult(writeEp.asset_id, r, writeEp.role);
              } else if (r.detail === "host_key_changed") {
                showChannelResult(writeEp.asset_id, r, writeEp.role);
              } else if (r.host_key_trusted) {
                showModal("提示", [el("p", { text: "主机指纹已信任，无需重复操作。" })]);
              } else {
                showChannelResult(writeEp.asset_id, r, writeEp.role);
              }
            },
          }),
          el("button", {
            class: "btn small primary", text: (writeEp.host_key_trusted_at && writeEp.host_key_sha256) ? "改用密钥登录" : "信任并更换密钥",
            onclick: async () => {
              const go = confirm(
                "将改用密钥登录：\n1. 生成密钥对\n2. 用当前密码部署公钥\n3. 验证密钥登录\n\n确定切换？\n（点「取消」不做任何改动）"
              );
              if (!go) return;
              showModal("改用密钥登录", [el("p", { text: "正在处理，请稍候…" })]);
              // 若未信任指纹，先走信任流程
              const pre = await api(`/api/assets/${writeEp.asset_id}/test`, {
                method: "POST",
                body: JSON.stringify({ role: writeEp.role }),
              });
              if (pre.detail === "host_key_untrusted" || pre.detail === "host_key_changed") {
                showChannelResult(writeEp.asset_id, pre, writeEp.role);
                return;
              }
              // 先不删密码；验证通过后再问
              const r = await api("/api/ssh/switch-to-key", {
                method: "POST",
                body: JSON.stringify({
                  asset_id: writeEp.asset_id,
                  role: writeEp.role,
                  delete_password: false,
                  trust_host_key: true,
                }),
              });
              const kids = [];
              kids.push(el("p", {
                text: r.hint || (r.ok ? "切换完成" : "切换未完成"),
                style: `font-size:14px;color:${r.ok ? "var(--ok)" : "var(--bad)"}`,
              }));
              const stepMap = {
                use_password_credential: "使用当前密码凭据",
                generated_key: "已生成密钥对",
                deployed_pubkey: "部署公钥",
                key_verify: "密钥登录验证",
                switched_to_key_confirmed: "确认切换为密钥",
                password_kept: "密码凭据已保留",
                deleted_password: "已删除密码凭据",
              };
              (r.steps || []).forEach((s) => {
                const [name] = s.split(":");
                kids.push(el("p", {
                  class: "small muted",
                  text: `· ${stepMap[name] || name}${s.includes("ok=False") ? " — 失败" : s.includes("ok=True") ? " — 成功" : ""}`,
                }));
              });
              if (r.verify && r.verify.error) {
                kids.push(el("p", { class: "error small", text: "验证错误：" + r.verify.error }));
              }
              if (r.error) kids.push(el("p", { class: "error small", text: r.error }));
              if (r.ok && r.public_key) {
                kids.push(el("p", { class: "muted small", text: "已安装的公钥：" }));
                kids.push(el("pre", { class: "small", text: r.public_key }));
                if (!r.deleted_password) {
                  kids.push(el("button", {
                    class: "btn small danger", text: "删除密码凭据",
                    style: "margin-top:10px",
                    onclick: async () => {
                      if (!confirm("确定删除该主机的密码凭据？删除后只能用密钥登录。")) return;
                      const list = await api("/api/ssh/credentials");
                      const pw = (list.credentials || []).filter((c) => c.kind === "password");
                      if (!pw.length) {
                        showModal("提示", [el("p", { text: "凭据库中没有密码凭据。" })]);
                        return;
                      }
                      const names = pw.map((c, i) => `${i + 1}. ${c.name || c.id}`).join("\n");
                      const pick = prompt(`删除哪一个密码凭据？输入序号：\n${names}`, "1");
                      const idx = parseInt(pick || "0", 10) - 1;
                      if (idx < 0 || idx >= pw.length) return;
                      const del = await api("/api/ssh/credentials", {
                        method: "DELETE",
                        body: JSON.stringify({ id: pw[idx].id }),
                      });
                      showModal(del.ok ? "已删除" : "删除失败", [
                        el("p", { text: del.ok ? "密码凭据已删除，当前为密钥登录。" : (del.error || "") }),
                      ]);
                      renderConnections();
                    },
                  }));
                }
              }
              showModal("改用密钥登录", kids);
              renderConnections();
            },
          }),
          el("button", {
            class: "btn small", text: "改连接信息",
            onclick: () => {
              sshFormModal("改连接信息 · " + a.id, [
                { name: "host", label: "地址 (IP/域名)", value: writeEp.host, required: true },
                { name: "username", label: "用户", value: writeEp.username || "root", required: true },
                { name: "port", label: "端口", value: String(writeEp.port || 22), type: "number" },
                { name: "password", label: "新密码（留空=不改凭据）", type: "password", help: "填了会更新原密码凭据，不是新建一条" },
                { name: "private_key", label: "新私钥 PEM（留空=不改）", type: "textarea" },
                { name: "clear_credential", label: "清空凭据（填 yes 才清空）", placeholder: "yes / 空" },
              ], async (d) => {
                const body = {
                  host: d.host,
                  username: d.username,
                  port: Number(d.port || 22),
                  role: writeEp.role,
                  password: d.password || "",
                  private_key: d.private_key || "",
                  clear_credential: d.clear_credential.toLowerCase() === "yes",
                };
                return api(`/api/assets/${a.id}/update`, { method: "POST", body: JSON.stringify(body) });
              });
            },
          }),
        ]);
        body.appendChild(actions);
      } else {
        body.appendChild(el("div", {
          class: "muted small",
          text: "未配置 SSH（需要地址 + 密码或密钥）。需配置 SSH 才能远程连接与执行。",
        }));
        body.appendChild(el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, [
          el("button", {
            class: "btn small primary", text: "配置 SSH（填密码/密钥）",
            onclick: () => {
              sshFormModal("配置 SSH · " + a.id, [
                { name: "host", label: "地址 (IP/域名)", required: true, placeholder: "192.0.2.10" },
                { name: "username", label: "用户", value: "root", required: true },
                { name: "port", label: "端口", value: "22", type: "number" },
                { name: "password", label: "SSH 密码（与私钥二选一）", type: "password" },
                { name: "private_key", label: "私钥 PEM（密码留空时用）", type: "textarea" },
              ], async (d) => {
                return api(`/api/assets/${a.id}/update`, {
                  method: "POST",
                  body: JSON.stringify({
                    host: d.host,
                    username: d.username || "root",
                    port: Number(d.port || 22),
                    role: "write",
                    password: d.password || "",
                    private_key: d.private_key || "",
                  }),
                });
              });
            },
          }),
          el("button", {
            class: "btn small", text: "测试连接",
            onclick: () => testHostChannel(a.id, "write"),
          }),
        ]));
      }
      // objects summary
      const objs = (a.objects || []).map((o) => o.name).slice(0, 8);
      if (objs.length) {
        body.appendChild(el("div", { class: "muted small", text: "对象: " + objs.join(" · ") }));
      }
      card.appendChild(body);
      box.appendChild(card);
    });
  }

  // ---- credentials list ----
  const cbox = $("ssh-creds");
  cbox.innerHTML = "";
  if (!creds.length) {
    cbox.appendChild(el("p", { class: "muted small", text: "凭据库为空。可导入密码/私钥，或生成密钥对。" }));
  } else {
    const table = el("table");
    table.appendChild(el("tr", {}, [
      el("th", { text: "ID" }), el("th", { text: "名称" }), el("th", { text: "类型" }),
      el("th", { text: "公钥" }), el("th", { text: "操作" }),
    ]));
    creds.forEach((c) => {
      const pub = c.public_key || "";
      table.appendChild(el("tr", {}, [
        el("td", { class: "muted small", text: c.id.slice(0, 14) }),
        el("td", { text: c.name || "-" }),
        el("td", { text: c.kind }),
        el("td", {
          class: "muted small",
          text: pub ? (pub.slice(0, 28) + "…") : "—",
          title: pub,
        }),
        el("td", {}, [
          el("button", {
            class: "btn small", text: "部署公钥",
            onclick: async () => {
              if (!pub) { showModal("提示", [el("p", { text: "该凭据没有公钥" })]); return; }
              const host = prompt("目标主机地址:", "127.0.0.1");
              if (!host) return;
              const user = prompt("SSH 用户:", "root");
              if (!user) return;
              const port = prompt("端口:", "22") || "22";
              const r = await api("/api/ssh/credentials/deploy-pubkey", {
                method: "POST",
                body: JSON.stringify({
                  host, port: Number(port), username: user,
                  public_key: pub, credential_id: c.id,
                }),
              });
              showModal("部署公钥结果", [el("pre", { text: JSON.stringify(r, null, 2) })]);
            },
          }),
          " ",
          el("button", {
            class: "btn small", text: "轮换",
            onclick: async () => {
              const secret = prompt("输入新的密码或私钥（不显示）:");
              if (!secret) return;
              const r = await api("/api/ssh/credentials/rotate", {
                method: "POST",
                body: JSON.stringify({ id: c.id, secret, public_key: c.public_key || "" }),
              });
              showModal("轮换结果", [el("pre", { text: JSON.stringify(r, null, 2) })]);
              renderConnections();
            },
          }),
        ]),
      ]));
    });
    cbox.appendChild(table);
  }
}

on("host-auth", "change", () => {
  const m = $("host-auth").value;
  $("host-auth-password-wrap").classList.toggle("hidden", m !== "password");
  $("host-auth-key-wrap").classList.toggle("hidden", m !== "key");
  $("host-auth-cred-wrap").classList.toggle("hidden", m !== "cred");
});

on("role-add-btn", "click", () => {
  $("role-add-form").classList.remove("hidden");
});
on("role-cancel-btn", "click", () => {
  $("role-add-form").classList.add("hidden");
});
on("role-save-btn", "click", async () => {
  const body = {
    name: $("role-name").value.trim(),
    label: $("role-label").value.trim(),
    kind: $("role-kind").value,
  };
  if (!body.name) return;
  const r = await api("/api/ssh/roles", { method: "POST", body: JSON.stringify(body) });
  if (!r.ok) {
    showModal("添加角色失败", [el("pre", { text: JSON.stringify(r, null, 2) })]);
    return;
  }
  $("role-name").value = "";
  $("role-label").value = "";
  $("role-add-form").classList.add("hidden");
  renderConnections();
});

on("host-add-btn", "click", async () => {
  const msg = $("host-add-msg");
  const authMode = $("host-auth").value;
  const body = {
    id: $("host-id").value.trim(),
    display_name: $("host-name").value.trim(),
    host: $("host-addr").value.trim(),
    port: Number($("host-port").value || 22),
    username: $("host-user").value.trim() || "root",
    role: $("host-role").value,
    credential_id: "",
  };
  if (authMode === "password") {
    body.password = $("host-password").value;
  } else if (authMode === "key") {
    body.private_key = $("host-private-key").value;
  } else if (authMode === "cred") {
    body.credential_id = $("host-cred").value || "";
  }
  if (!body.id || !body.host) {
    msg.textContent = "请填写主机 ID 和地址";
    return;
  }
  if (authMode === "password" && !body.password) {
    msg.textContent = "请填写 SSH 密码（或切换认证方式）";
    return;
  }
  if (authMode === "key" && !body.private_key) {
    msg.textContent = "请粘贴私钥（或切换认证方式）";
    return;
  }
  msg.textContent = "添加中…";
  const r = await api("/api/assets", { method: "POST", body: JSON.stringify(body) });
  if (r.ok) {
    msg.textContent = `已添加主机 ${r.asset_id}` + (r.credential_id ? "（已保存凭据）" : "");
    $("host-id").value = "";
    $("host-name").value = "";
    $("host-addr").value = "";
    $("host-user").value = "";
    $("host-password").value = "";
    $("host-private-key").value = "";
  } else {
    msg.textContent = "失败: " + (r.error || "unknown");
  }
  renderConnections();
  loadMeta();
});

on("ssh-cred-save", "click", async () => {
  const body = {
    name: $("ssh-cred-name").value.trim(),
    kind: $("ssh-cred-kind").value,
    secret: $("ssh-cred-secret").value,
    public_key: "",
  };
  if (!body.secret) { showModal("提示", [el("p", { text: "请输入密码或私钥" })]); return; }
  const r = await api("/api/ssh/credentials", { method: "POST", body: JSON.stringify(body) });
  $("ssh-cred-secret").value = "";
  showModal("凭据导入", [el("pre", { text: JSON.stringify({ ok: r.ok, id: r.credential && r.credential.id, kind: r.credential && r.credential.kind, error: r.error }, null, 2) })]);
  renderConnections();
});

on("ssh-cred-gen", "click", async () => {
  const name = $("ssh-cred-name").value.trim() || "ayana";
  const r = await api("/api/ssh/credentials/generate", { method: "POST", body: JSON.stringify({ name }) });
  if (r.ok && r.credential && r.credential.public_key) {
    showModal("密钥对已生成", [
      el("p", { text: "私钥已加密入库。请把下面公钥部署到目标服务器：" }),
      el("pre", { text: r.credential.public_key }),
    ]);
  } else {
    showModal("生成失败", [el("pre", { text: JSON.stringify(r, null, 2) })]);
  }
  renderConnections();
});

on("ssh-test-btn", "click", async () => {
  const out = $("ssh-test-out");
  out.textContent = "测试中…";
  const assetId = $("ssh-test-asset").value;
  const role = $("ssh-test-role").value;
  const r = await testHostChannel(assetId, role);
  out.textContent = `${r.ok ? "通" : "不通"} · ${r.channel} · ${r.hint || r.detail || ""}`;
});

/* ---- Agent ceiling ---- */
async function renderAgentCeiling() {
  const res = await api("/api/agent-ceiling");
  const box = $("agent-ceiling");
  if (!box) return;
  box.innerHTML = "";
  if (!res.ok) {
    box.appendChild(el("p", { class: "muted small", text: "无法加载 Agent ceiling" }));
    return;
  }
  const rows = res.agent_ceiling || [];
  const table = el("table");
  table.appendChild(el("tr", {}, [
    el("th", { text: "能力" }), el("th", { text: "允许 Agent" }),
    el("th", { text: "允许自动" }), el("th", { text: "来源" }), el("th", { text: "操作" }),
  ]));
  rows.forEach((r) => {
    const tr = el("tr", {}, [
      el("td", { text: r.capability }),
      el("td", {}, [
        el("input", {
          type: "checkbox",
          ...(r.allowed ? { checked: "checked" } : {}),
          onchange: async (e) => {
            await api("/api/agent-ceiling", {
              method: "POST",
              body: JSON.stringify({
                capability: r.capability,
                allowed: e.target.checked,
                allow_auto: r.allow_auto,
              }),
            });
            renderAgentCeiling();
          },
        }),
      ]),
      el("td", {}, [
        el("input", {
          type: "checkbox",
          ...(r.allow_auto ? { checked: "checked" } : {}),
          onchange: async (e) => {
            await api("/api/agent-ceiling", {
              method: "POST",
              body: JSON.stringify({
                capability: r.capability,
                allowed: r.allowed,
                allow_auto: e.target.checked,
              }),
            });
            renderAgentCeiling();
          },
        }),
      ]),
      el("td", { class: "muted small", text: r.configured ? "用户配置" : "目录默认" }),
      el("td", { class: "muted small", text: r.updated_by || "" }),
    ]);
    table.appendChild(tr);
  });
  box.appendChild(table);
}

/* ---- Web SSH Terminal (xterm.js) ---- */
const termState = {
  term: null,
  fit: null,
  ws: null,
  assetId: "",
  open: false,
};

function setTermStatus(text, cls) {
  const n = $("term-status");
  if (!n) return;
  n.textContent = text;
  n.className = "badge " + (cls || "dim");
}

function destroyTerminal() {
  try {
    if (termState.ws) {
      termState.ws.onclose = null;
      termState.ws.close();
    }
  } catch (_) {}
  termState.ws = null;
  try {
    if (termState.term) termState.term.dispose();
  } catch (_) {}
  termState.term = null;
  termState.fit = null;
  termState.open = false;
  setTermStatus("未连接", "dim");
}

function ensureXterm() {
  const T = window.Terminal || (window.xterm && window.xterm.Terminal);
  const Fit = window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon);
  if (!T) {
    showModal("无法打开终端", [el("p", { text: "xterm.js 未加载，请强制刷新页面。" })]);
    return null;
  }
  destroyTerminal();
  const term = new T({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
    theme: {
      background: "#0c0c0c",
      foreground: "#e8eaed",
      cursor: "#6cb6ff",
      selectionBackground: "rgba(108,182,255,.35)",
    },
  });
  const container = $("term-container");
  container.innerHTML = "";
  term.open(container);
  let fit = null;
  if (Fit) {
    fit = new Fit();
    try {
      term.loadAddon(fit);
      fit.fit();
    } catch (_) {}
  }
  termState.term = term;
  termState.fit = fit;
  return term;
}

async function openTerminal(assetId, ep) {
  termState.assetId = assetId;
  $("term-title").textContent = `终端 · ${assetId}`;
  $("term-host-label").textContent = ep
    ? `${ep.username || ""}@${ep.host || ""}:${ep.port || 22}`
    : "";
  $("term-modal").classList.remove("hidden");
  setTermStatus("检查连接…", "warn");

  // 先检查权限 / host key
  const chk = await api(`/api/terminal/check?asset_id=${encodeURIComponent(assetId)}`);
  if (chk.detail === "host_key_untrusted" && chk.host_key_info) {
    setTermStatus("待信任指纹", "warn");
    showHostKeyDialog(assetId, chk, () => openTerminal(assetId, ep));
    return;
  }
  if (chk.detail === "host_key_changed") {
    setTermStatus("主机密钥变更", "bad");
    showHostKeyDialog(assetId, chk, () => openTerminal(assetId, ep));
    return;
  }
  if (!chk.ok) {
    setTermStatus("无法打开", "bad");
    $("term-container").innerHTML = "";
    $("term-container").appendChild(el("div", {
      class: "muted",
      style: "padding:20px",
      text: chk.hint || chk.error || "无法打开终端",
    }));
    return;
  }
  connectTerminal(assetId);
}

function showHostKeyDialog(assetId, chk, onDone) {
  const info = chk.host_key_info || {};
  const changed = chk.detail === "host_key_changed";
  const kids = [];
  kids.push(el("p", {
    text: changed ? "主机密钥已变更，已阻止连接" : "首次连接，需要确认主机指纹",
    style: `font-size:16px;font-weight:600;color:${changed ? "var(--bad)" : "var(--ink)"}`,
  }));
  kids.push(el("p", {
    class: "muted",
    text: `主机 ${info.host || ""}:${info.port || ""}`,
  }));
  if (changed) {
    kids.push(el("p", { class: "small", text: "已保存：" }));
    kids.push(el("p", { class: "small", style: "font-family:monospace;color:var(--warn)", text: info.stored_fingerprint || "-" }));
    kids.push(el("p", { class: "small", text: "当前：" }));
    kids.push(el("p", { class: "small", style: "font-family:monospace;color:var(--bad)", text: info.current_fingerprint || "-" }));
    kids.push(el("p", { class: "muted small", text: "不会自动覆盖。确认服务器身份后再信任新指纹。" }));
  } else {
    kids.push(el("p", {
      style: "font-family:ui-monospace,Menlo,monospace;font-size:13px;margin:12px 0;padding:10px;background:rgba(255,255,255,.05);border-radius:8px",
      text: info.fingerprint || "(无法获取指纹)",
    }));
  }
  showModal(changed ? "安全警告" : "信任主机", kids);
  const actions = document.querySelector("#modal .modal-actions");
  actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
  const cancel = el("button", {
    class: "btn btn-trust", text: "取消",
    onclick: () => {
      $("modal").classList.add("hidden");
      actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
    },
  });
  const trust = el("button", {
    class: "btn primary btn-trust",
    text: changed ? "确认换机，信任新指纹" : "信任并连接",
    onclick: async () => {
      if (changed && !confirm("确认服务器身份无误？将覆盖旧指纹。")) return;
      trust.disabled = true;
      const t = await api("/api/ssh/endpoints/trust", {
        method: "POST",
        body: JSON.stringify({
          asset_id: assetId,
          role: "write",
          host_key_sha256: (changed ? info.current_fingerprint : info.fingerprint) || "",
          host_key_line: info.key_line || "",
        }),
      });
      actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
      $("modal").classList.add("hidden");
      if (!t.ok) {
        showModal("信任失败", [el("p", { text: t.error || "trust failed" })]);
        return;
      }
      if (onDone) onDone();
    },
  });
  actions.insertBefore(trust, actions.firstChild);
  actions.insertBefore(cancel, trust.nextSibling);
}

function connectTerminal(assetId) {
  const term = ensureXterm();
  if (!term) return;
  setTermStatus("连接中…", "warn");
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${location.host}/ws/terminal?asset_id=${encodeURIComponent(assetId)}&cols=${term.cols}&rows=${term.rows}`;
  const ws = new WebSocket(url);
  ws.binaryType = "arraybuffer";
  termState.ws = ws;
  termState.open = true;

  term.onData((data) => {
    if (ws.readyState === 1) ws.send(new TextEncoder().encode(data));
  });
  term.onResize(({ cols, rows }) => {
    if (ws.readyState === 1) ws.send(JSON.stringify({ type: "resize", cols, rows }));
  });

  ws.onopen = () => setTermStatus("等待会话…", "warn");
  ws.onmessage = (ev) => {
    if (typeof ev.data === "string") {
      let msg = null;
      try { msg = JSON.parse(ev.data); } catch (_) { return; }
      if (msg.type === "ready") {
        setTermStatus("已连接", "ok");
        $("term-host-label").textContent =
          `${msg.remote_user || ""}@${msg.host || ""}:${msg.port || ""} · ` +
          (msg.auth_method === "key" ? "密钥登录" : "密码登录");
      } else if (msg.type === "error") {
        setTermStatus("连接失败", "bad");
        term.write(`\r\n\x1b[31m[${msg.hint || msg.error || "错误"}]\x1b[0m\r\n`);
        if (msg.host_key_info) {
          showHostKeyDialog(assetId, msg, () => connectTerminal(assetId));
        }
      } else if (msg.type === "closed") {
        setTermStatus("已断开", "dim");
        term.write(`\r\n\x1b[33m[连接已断开：${msg.reason || ""}]\x1b[0m\r\n`);
      }
    } else {
      term.write(new Uint8Array(ev.data));
    }
  };
  ws.onclose = () => {
    setTermStatus("已断开", "dim");
  };
  ws.onerror = () => {
    setTermStatus("连接错误", "bad");
  };
}

on("term-close", "click", () => {
  $("term-modal").classList.add("hidden");
  destroyTerminal();
});
on("term-disconnect", "click", () => {
  if (termState.ws && termState.ws.readyState === 1) {
    try { termState.ws.send(JSON.stringify({ type: "close" })); } catch (_) {}
    termState.ws.close();
  }
  destroyTerminal();
});
on("term-reconnect", "click", () => {
  if (termState.assetId) connectTerminal(termState.assetId);
});

/* ---- modal ---- */

function sshFormModal(title, fields, onSubmit) {
  // fields: [{name,label,type,value,placeholder,required,help}]
  const wrap = el("div", {});
  const inputs = {};
  fields.forEach((f) => {
    const id = "sf_" + f.name;
    const input =
      f.type === "password"
        ? el("input", { id, type: "password", placeholder: f.placeholder || "", autocomplete: "new-password" })
        : f.type === "textarea"
          ? el("textarea", { id, placeholder: f.placeholder || "", rows: 4 })
          : el("input", {
              id,
              type: f.type || "text",
              placeholder: f.placeholder || "",
              value: f.value == null ? "" : String(f.value),
            });
    if (f.value != null && f.type !== "password" && f.type !== "textarea") input.value = String(f.value);
    inputs[f.name] = input;
    const lab = el("label", { style: "display:block;margin:8px 0 4px;font-size:12px;color:var(--dim)" }, [
      document.createTextNode(f.label + (f.required ? " *" : "")),
    ]);
    wrap.appendChild(lab);
    wrap.appendChild(input);
    if (f.help) {
      wrap.appendChild(el("div", { class: "muted small", style: "margin:2px 0 6px", text: f.help }));
    }
  });
  const err = el("p", { class: "error small", style: "margin-top:8px" });
  const okBtn = el("button", {
    class: "btn primary",
    text: "确定",
    onclick: async () => {
      err.textContent = "";
      const data = {};
      for (const k of Object.keys(inputs)) {
        data[k] = (inputs[k].value || "").trim();
      }
      okBtn.disabled = true;
      try {
        const r = await onSubmit(data);
        if (r && r.ok === false) {
          err.textContent = (r.error || "失败") + (r.detail ? ": " + r.detail : "");
          okBtn.disabled = false;
          return;
        }
        closeModal();
        renderConnections();
      } catch (e) {
        err.textContent = String(e);
        okBtn.disabled = false;
      }
    },
  });
  const cancelBtn = el("button", { class: "btn ghost", text: "取消", onclick: () => closeModal() });
  wrap.appendChild(el("div", { style: "margin-top:14px;display:flex;gap:8px" }, [okBtn, cancelBtn]));
  wrap.appendChild(err);
  showModal(title, [wrap]);
}

function closeModal() { const m = document.getElementById("modal"); if (m) m.classList.add("hidden"); }


const pcProgressByHost = {};
const pcRunningByHost = {};

function pcProgressRender(box, steps) {
  // steps: [{key, label, status: pending|running|ok|fail|skip, detail}]
  box.innerHTML = "";
  const bar = el("div", {
    style: "height:8px;border-radius:6px;background:rgba(255,255,255,.08);margin:8px 0 12px;overflow:hidden",
  });
  const done = steps.filter((s) => s.status === "ok" || s.status === "skip").length;
  const total = Math.max(steps.length, 1);
  const pct = Math.round((done / total) * 100);
  bar.appendChild(el("div", {
    style: `height:100%;width:${pct}%;background:linear-gradient(90deg,#3d86e0,#3dd68c);transition:width .35s`,
  }));
  box.appendChild(bar);
  steps.forEach((s) => {
    const icon =
      s.status === "ok" ? "✓" :
      s.status === "fail" ? "✗" :
      s.status === "running" ? "…" :
      s.status === "skip" ? "−" : "·";
    const color =
      s.status === "ok" ? "var(--ok)" :
      s.status === "fail" ? "var(--bad)" :
      s.status === "running" ? "var(--warn)" : "var(--dim)";
    const row = el("div", {
      style: "display:flex;gap:10px;align-items:flex-start;padding:4px 0;font-size:13px",
    }, [
      el("span", { style: `width:18px;color:${color};font-weight:700`, text: icon }),
      el("div", {}, [
        el("div", { style: `color:${s.status === "pending" ? "var(--dim)" : "var(--ink)"}`, text: s.label }),
        s.detail ? el("div", { class: "muted small", style: "margin-top:2px", text: s.detail }) : null,
      ].filter(Boolean)),
    ]);
    box.appendChild(row);
  });
}

async function pcRunAdoptFlow(asset) {
  const box = $("monitor-install-box");
  if (!box) return;
  pcRunningByHost[asset] = true;
  box.dataset.running = "1";
  const steps = [
    { key: "detect", label: "1. 检测主机（Docker / 二进制 / 9100）", status: "pending" },
    { key: "install", label: "2. 安装 / 启动采集器", status: "pending" },
    { key: "register", label: "3. 注册到 Prometheus", status: "pending" },
    { key: "verify", label: "4. 验证是否采到指标", status: "pending" },
  ];
  const render = () => { pcProgressByHost[asset] = steps.map((s) => Object.assign({}, s)); pcProgressRender(box, steps); };
  render();

  // 1 detect
  steps[0].status = "running";
  render();
  const det = await api("/api/promconfig/node-exporter/detect", {
    method: "POST",
    body: JSON.stringify({ asset_id: asset }),
  });
  if (!det.ok) {
    steps[0].status = "fail";
    steps[0].detail = String(det.error || "检测失败");
    render();
    return;
  }
  steps[0].status = "ok";
  steps[0].detail =
    "Docker=" + (det.docker ? "有" : "无") +
    " · 二进制=" + (det.binary || "无") +
    " · 9100=" + (det.port_9100 ? "在听" : "无") +
    " · 推荐=" + (det.recommend || "-");
  render();

  // 2 install（已运行则跳过）
  if (det.running || (det.port_9100 && det.binary)) {
    steps[1].status = "skip";
    steps[1].detail = "已在运行，跳过安装";
    render();
  } else if (det.recommend === "docker" || det.recommend === "binary") {
    steps[1].status = "running";
    steps[1].detail = det.recommend === "docker" ? "正在用 Docker 启动…" : "正在分发二进制并写 systemd…";
    render();
    const ir = await api("/api/promconfig/node-exporter/install", {
      method: "POST",
      body: JSON.stringify({ asset_id: asset, method: det.recommend }),
    });
    if (!ir.ok) {
      steps[1].status = "fail";
      steps[1].detail = String((ir.error || "") + " " + (ir.detail || ""));
      render();
      return;
    }
    steps[1].status = "ok";
    steps[1].detail = (ir.steps || []).map((s) => s.step).join(" → ") || "安装完成";
    render();
  } else {
    steps[1].status = "fail";
    steps[1].detail = "无法安装：无 Docker 且无二进制/安装包";
    render();
    return;
  }

  // 3 register
  steps[2].status = "running";
  steps[2].detail = "写入 file_sd 并热重载…";
  render();
  const ar = await api("/api/promconfig/node-exporter/adopt", {
    method: "POST",
    body: JSON.stringify({ asset_id: asset }),
  });
  if (!ar.ok && ar.error !== "no_metrics") {
    steps[2].status = "fail";
    steps[2].detail = String(ar.hint || ar.error || "注册失败");
    render();
    return;
  }
  steps[2].status = "ok";
  steps[2].detail = "地址 " + (ar.address || "-");
  render();

  // 4 verify
  steps[3].status = "running";
  steps[3].detail = "查询 up 指标…";
  render();
  const sc = ar.scrape || {};
  if (ar.ok && sc.has_metrics) {
    steps[3].status = "ok";
    steps[3].detail = "指标正常";
  } else {
    steps[3].status = "fail";
    steps[3].detail =
      (sc.hint || ar.hint || "未采到指标") +
      (sc.error ? " · " + sc.error : "");
  }
  render();
  pcRunningByHost[asset] = false;
  if (box) box.dataset.running = "0";
  if (typeof renderMonitor === "function") renderMonitor();
}

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
  document.querySelectorAll(".modal-actions .btn-trust").forEach((b) => b.remove());
});

/* ---- 主机监控 ---- */
const monitorState = {
  host: "",
  range: "1h",
  hosts: [],
  autoTimer: null,
};

function metricStateBadge(st) {
  const map = {
    ok: ["正常", "ok"],
    warn: ["偏高", "warn"],
    bad: ["异常", "bad"],
    not_enabled: ["未启用", "dim"],
    no_data: ["暂无数据", "dim"],
    collect_error: ["采集失败", "bad"],
  };
  const [t, c] = map[st] || [st, "dim"];
  return badge(t, c);
}

function fmtMetricVal(m) {
  if (!m || m.value === null || m.value === undefined) return "—";
  if (m.state === "not_enabled") return "—";
  const v = m.value;
  if (m.unit === "%") return v.toFixed(1);
  if (m.unit === "B/s") {
    const units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let x = Math.abs(v), i = 0;
    while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
    return x.toFixed(i === 0 ? 0 : 1);
  }
  if (m.key && String(m.key).startsWith("load")) return v.toFixed(2);
  return Number(v).toFixed(1);
}

function fmtMetricUnit(m) {
  if (!m || m.state === "not_enabled") return "";
  if (!m || m.value === null || m.value === undefined) return m && m.unit ? m.unit : "";
  const v = m.value;
  if (m.unit === "B/s") {
    const units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let x = Math.abs(v), i = 0;
    while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
    return units[i];
  }
  return m.unit || "";
}

function drawSpark(canvas, seriesList) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 220, h = canvas.clientHeight || 56;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const all = (seriesList || []).flatMap((s) => s.points || []);
  if (all.length < 2) {
    ctx.strokeStyle = "rgba(255,255,255,.12)";
    ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();
    return;
  }
  const vs = all.map((p) => p.v);
  let min = Math.min(...vs), max = Math.max(...vs);
  if (max - min < 1e-9) { max = min + 1; }
  const pad = 10;
  const x0 = Math.min(...all.map((p) => p.t)), x1 = Math.max(...all.map((p) => p.t));
  // 轴刻度（左右 min/max）
  ctx.fillStyle = "rgba(255,255,255,.35)";
  ctx.font = "9px sans-serif";
  ctx.fillText(fmtNum(max), 2, 9);
  ctx.fillText(fmtNum(min), 2, h - 2);
  // 时间刻度
  const tLabel = (t) => {
    const d = new Date(t * 1000);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  };
  ctx.fillText(tLabel(x0), 2, h - 2);
  ctx.fillText(tLabel(x1), w - 34, h - 2);
  // 网格
  ctx.strokeStyle = "rgba(255,255,255,.06)";
  ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();

  (seriesList || []).forEach((s) => {
    const points = s.points || [];
    if (points.length < 2) return;
    const color = s.color || "#6cb6ff";
    ctx.beginPath();
    points.forEach((p, i) => {
      const x = ((p.t - x0) / Math.max(x1 - x0, 1e-9)) * (w - 10) + 4;
      const y = h - pad - ((p.v - min) / (max - min)) * (h - pad * 2);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.stroke();
    ctx.lineTo(w - 6, h - 2); ctx.lineTo(4, h - 2); ctx.closePath();
    ctx.fillStyle = color + "18"; ctx.fill();
  });
}

function fmtNum(v) {
  if (v == null || v !== v) return "-";
  const x = Math.abs(v);
  if (x >= 1e9) return (v / 1e9).toFixed(1) + "G";
  if (x >= 1e6) return (v / 1e6).toFixed(1) + "M";
  if (x >= 1e3) return (v / 1e3).toFixed(1) + "k";
  if (x >= 100) return v.toFixed(0);
  if (x >= 10) return v.toFixed(1);
  return v.toFixed(2);
}

function metricCard(m, seriesList) {
  // seriesList: [{key,label,points,color,value,state}] 可选多序列
  const card = el("div", { class: "metric-card" });
  const title = m.label || m.key;
  const top = el("div", { class: "top" }, [
    el("div", { class: "name", text: title }),
    metricStateBadge(m.state),
  ]);
  card.appendChild(top);
  const valWrap = el("div", { class: "val" });
  if (seriesList && seriesList.length > 1) {
    seriesList.forEach((s, i) => {
      if (i) valWrap.appendChild(el("span", { class: "unit", text: "  ·  " }));
      const unit = s.unit || "";
      valWrap.appendChild(el("span", {
        text: `${s.label || s.key} ${fmtNum(s.value)}`,
        style: "font-size:13px",
      }));
      if (unit) valWrap.appendChild(el("span", { class: "unit", text: " " + unit }));
    });
  } else {
    valWrap.appendChild(document.createTextNode(fmtMetricVal(m)));
    valWrap.appendChild(el("span", { class: "unit", text: " " + fmtMetricUnit(m) }));
  }
  card.appendChild(valWrap);
  if (m.state === "not_enabled") {
    return card;
  }
  // 图例
  if (seriesList && seriesList.length > 1) {
    const legend = el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;margin:2px 0 4px" });
    seriesList.forEach((s) => {
      legend.appendChild(el("span", {
        style: `font-size:10px;color:var(--dim)`,
        text: "● " + (s.label || s.key),
      }));
      legend.lastChild.style.color = s.color || "#6cb6ff";
    });
    card.appendChild(legend);
  }
  const canvas = el("canvas", {});
  canvas.style.width = "100%";
  canvas.style.height = "56px";
  card.appendChild(canvas);
  const list = seriesList && seriesList.length
    ? seriesList
    : [{
        points: m.points || [],
        color: m.state === "bad" ? "#f07178" : m.state === "warn" ? "#e5c07b" : "#6cb6ff",
      }];
  setTimeout(() => drawSpark(canvas, list), 0);
  return card;
}

/** 合并指标卡片：Load 1/5/15、Disk R/W、Net Rx/Tx；无数据沉底 */
function buildMetricGroups(metrics) {
  const groups = [];
  const used = new Set();
  const put = (key, seriesKeys, label) => {
    const ms = seriesKeys.map((k) => metrics[k]).filter(Boolean);
    if (!ms.length) return;
    seriesKeys.forEach((k) => used.add(k));
    const states = ms.map((m) => m.state);
    const rank = { collect_error: 5, bad: 4, warn: 3, no_data: 2, ok: 1, not_enabled: 0, partial_no_data: 2 };
    const worst = states.reduce((a, b) => (rank[b] || 0) > (rank[a] || 0) ? b : a, "ok");
    const palette = ["#6cb6ff", "#e5c07b", "#3dd68c", "#c4b5fd"];
    const seriesList = ms.map((m, i) => ({
      key: m.key,
      label: (m.label || m.key).replace(/^.*[·\s]/, ""),
      points: m.points || [],
      color: palette[i % palette.length],
      value: m.value,
      unit: m.unit || "",
      state: m.state,
    }));
    const head = {
      key,
      label,
      state: worst,
      value: ms[0].value,
      unit: ms[0].unit || "",
      points: ms[0].points || [],
    };
    groups.push({ head, seriesList, rank: rank[worst] || 0, hasData: ms.some((m) => (m.points || []).length) });
  };
  put("cpu", ["cpu"], "CPU 使用率");
  put("memory", ["memory"], "内存使用率");
  put("disk", ["disk"], "磁盘使用率(最大)");
  put("swap", ["swap"], "Swap 使用率");
  put("load", ["load1", "load5", "load15"], "负载 1/5/15");
  put("disk_io", ["disk_read", "disk_write"], "磁盘 读/写");
  put("net", ["net_rx", "net_tx"], "网络 收/发");
  // 其余未归组
  Object.keys(metrics).forEach((k) => {
    if (used.has(k) || !metrics[k]) return;
    groups.push({ head: metrics[k], seriesList: null, rank: 0, hasData: (metrics[k].points || []).length > 0 });
  });
  // 排序：异常 > 警告 > 正常有数据 > 无数据/未启用
  groups.sort((a, b) => {
    const aEmpty = !a.hasData || a.head.state === "no_data" || a.head.state === "not_enabled";
    const bEmpty = !b.hasData || b.head.state === "no_data" || b.head.state === "not_enabled";
    if (aEmpty !== bEmpty) return aEmpty ? 1 : -1;
    return (b.rank || 0) - (a.rank || 0);
  });
  return groups;
}

async function renderMonitor() {
  const body = $("monitor-body");
  const strip = $("monitor-hosts-strip");
  if (!body) return;
  // 切主机/重绘时清掉检测结果，避免旧主机按钮串台
  const ibox = $("monitor-install-box");
  if (ibox) {
    const host = monitorState.host || "";
    ibox.dataset.hostKey = host;
    // 恢复该主机自己的进度，不丢别人的
    if (pcProgressByHost[host] && pcProgressByHost[host].length) {
      pcProgressRender(ibox, pcProgressByHost[host]);
    } else if (!pcRunningByHost[host]) {
      ibox.innerHTML = "";
    }
  }
  body.innerHTML = '<p class="muted small">加载中…</p>';
  const hostsRes = await api("/api/monitor/hosts");
  monitorState.hosts = (hostsRes.ok && hostsRes.hosts) || [];
  // strip
  strip.innerHTML = "";
  monitorState.hosts.forEach((h) => {
    const hh = h.health || {};
    const cls = hh.cls || (h.state === "collect_error" ? "err" : h.state === "no_data" ? "dim" : h.state);
    const chip = el("div", {
      class: "monitor-chip" + (h.asset_id === monitorState.host ? " active" : ""),
      onclick: () => {
        monitorState.host = h.asset_id;
        const sel = $("monitor-host");
        if (sel) sel.value = h.asset_id;
        renderMonitor();
      },
    }, [
      el("span", { class: "dot " + cls, text: "" }),
      el("span", { text: h.display_name || h.asset_id }),
    ]);
    strip.appendChild(chip);
  });
  fillSelect("monitor-host", monitorState.hosts.map((h) => {
    const hh = h.health || {};
    return {
      v: h.asset_id,
      t: (h.display_name || h.asset_id) + " · " + (hh.label || "暂无数据"),
    };
  }));
  if (!monitorState.host && monitorState.hosts.length) {
    monitorState.host = monitorState.hosts[0].asset_id;
  }
  const sel = $("monitor-host");
  if (sel) sel.value = monitorState.host || "";
  if (!monitorState.host) {
    body.innerHTML = '<p class="muted small">没有主机资产</p>';
    return;
  }
  const res = await api(`/api/monitor/host/${encodeURIComponent(monitorState.host)}?range=${monitorState.range}`);
  if (!res.ok) {
    body.innerHTML = "";
    body.appendChild(el("p", { class: "error", text: res.error || "加载失败" }));
    return;
  }
  body.innerHTML = "";
  const hist = res.history || {};
  const ov = res.overview || {};
  const bannerState = hist.state || ov.state;
  if (bannerState === "collect_error") {
    body.appendChild(el("div", { class: "banner warn", text: "采集失败：" + (hist.error || ov.error || "Prometheus 不可用") }));
  } else if (bannerState === "no_data") {
    body.appendChild(el("div", { class: "banner warn", text: "暂无数据：该主机可能未接入 Node Exporter，或标签 asset 未对齐。" }));
  }
  const metrics = hist.metrics || {};
  const groups = buildMetricGroups(metrics);
  const grid = el("div", { class: "metric-grid" });
  groups.forEach((g) => {
    grid.appendChild(metricCard(g.head, g.seriesList));
  });
  body.appendChild(grid);
  body.appendChild(el("p", {
    class: "muted small",
    text: `时间范围 ${monitorState.range} · 数据源 Prometheus / Node Exporter · 不在 Ayana 落时序`,
  }));
}

function stopMonitorAuto() {
  if (monitorState.autoTimer) {
    clearInterval(monitorState.autoTimer);
    monitorState.autoTimer = null;
    const b = $("monitor-auto");
    if (b) b.textContent = "自动 30s";
  }
}

on("monitor-refresh", "click", () => renderMonitor());
on("monitor-auto", "click", () => {
  if (monitorState.autoTimer) { stopMonitorAuto(); return; }
  monitorState.autoTimer = setInterval(() => {
    if (state.tab === "monitor") renderMonitor();
  }, 30000);
  const b = $("monitor-auto");
  if (b) b.textContent = "停止自动";
});
on("monitor-host", "change", (e) => {
  monitorState.host = e.target.value;
  renderMonitor();
});
on("monitor-range", "change", (e) => {
  monitorState.range = e.target.value;
  renderMonitor();
});

/* ---- 通知渠道 ---- */
const notifyKindGuides = {};
let notifyPlatforms = [];

function renderNotifyGuide(kind) {
  const root = $("notify-guide");
  if (!root) return;
  const g = notifyKindGuides[kind];
  root.innerHTML = "";
  if (!g) {
    root.classList.add("hidden");
    return;
  }
  root.classList.remove("hidden");
  const head = el("h3", {}, [
    el("span", { text: g.title || "" }),
    el("span", { class: "guide-tag", text: "接入说明" }),
  ]);
  root.appendChild(head);
  if (g.summary) root.appendChild(el("p", { class: "summary", text: g.summary }));
  if (g.steps && g.steps.length) {
    const ol = el("ol", {});
    g.steps.forEach((s) => ol.appendChild(el("li", { text: s })));
    root.appendChild(ol);
  }
  if (g.notes && g.notes.length) {
    const notes = el("div", { class: "notes" }, [el("strong", { text: "注意" })]);
    const ul = el("ul", {});
    g.notes.forEach((n) => ul.appendChild(el("li", { text: n })));
    notes.appendChild(ul);
    root.appendChild(notes);
  }
  if (g.docs && g.docs.length) {
    const docs = el("div", { class: "docs" });
    docs.appendChild(document.createTextNode("官方文档："));
    g.docs.forEach((d) => {
      const a = el("a", { href: d.url, target: "_blank", rel: "noopener noreferrer", text: d.title || d.url });
      docs.appendChild(a);
    });
    root.appendChild(docs);
  }
}

async function loadNotifyKinds() {
  if (Object.keys(notifyKindGuides).length && notifyPlatforms.length) return;
  try {
    const [kres, pres] = await Promise.all([
      api("/api/notify/kinds"),
      api("/api/notify/platforms"),
    ]);
    if (kres.ok && kres.kinds) {
      kres.kinds.forEach((k) => { notifyKindGuides[k.kind] = k; });
    }
    if (pres.ok && pres.platforms) {
      notifyPlatforms = pres.platforms;
    }
  } catch (_) { /* 指引加载失败不阻塞配置 */ }
}

function currentNotifyKind() {
  return ($("notify-method") || {}).value || "qq";
}

function fillNotifyMethods() {
  const pid = ($("notify-platform") || {}).value || "qq";
  const plat = notifyPlatforms.find((p) => p.id === pid);
  const methods = (plat && plat.methods) || [];
  const sel = $("notify-method");
  if (!sel) return;
  sel.innerHTML = "";
  methods.forEach((m) => {
    const op = document.createElement("option");
    op.value = m.kind;
    op.textContent = m.label;
    sel.appendChild(op);
  });
  if (methods.length) sel.value = methods[0].kind;
}

function toggleNotifyKind() {
  const kind = currentNotifyKind();
  const show = (id, on) => {
    const n = $(id);
    if (n) n.classList.toggle("hidden", !on);
  };
  show("notify-qq-wrap", kind === "qq");
  show("notify-wecom-wrap", kind === "wecom");
  show("notify-aibot-wrap", kind === "wecom_aibot");
  show("notify-hook-wrap", kind === "webhook");
  renderNotifyGuide(kind);
}

async function renderNotify() {
  await loadNotifyKinds();
  fillNotifyMethods();
  toggleNotifyKind();
  await loadNotifyChannels();
  await loadNotifyOutbox();
  await loadAibotStatus();
}

async function loadAibotStatus() {
  try {
    const res = await api("/api/notify/aibot/status");
    if (res.ok) state.aibotStatus = res.status || {};
  } catch (_) {
    state.aibotStatus = {};
  }
}

/** 已发现的推送目标：勾选保存 + 手动添加 */
async function openAibotTargets(ch) {
  const res = await api("/api/notify/aibot/targets?channel_id=" + encodeURIComponent(ch.id));
  const discovered = (res.ok && res.targets) || [];
  const selected = new Set((res.ok && res.selected) || ((ch.config && ch.config.targets) || []));
  const wrap = el("div", {});
  wrap.appendChild(el("p", {
    class: "muted small",
    text: "连接成功后，在企业微信群内 @机器人 发送一条消息，该群会出现在下面。勾选后点保存；也可手动补充 chatid/userid。",
  }));
  const list = el("div", { style: "max-height:280px;overflow:auto;margin:10px 0" });
  const manual = el("input", {
    placeholder: "手动添加：chatid 或 userid，逗号分隔",
    style: "width:100%;margin:8px 0;padding:8px;border-radius:8px;border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--ink)",
  });
  const boxes = [];
  function addRow(tid, label, checked) {
    const row = el("label", {
      style: "display:flex;align-items:center;gap:8px;padding:6px 4px;cursor:pointer",
    });
    const cb = el("input", { type: "checkbox" });
    cb.checked = !!checked;
    boxes.push({ tid, cb });
    row.appendChild(cb);
    row.appendChild(el("span", { text: label, style: "font-size:13px" }));
    list.appendChild(row);
  }
  if (!discovered.length) {
    list.appendChild(el("p", {
      class: "muted small",
      text: "暂未发现会话。请确认长连接已认证，并在群里 @机器人 发一条消息。",
    }));
  }
  discovered.forEach((t) => {
    const label = `[${t.kind_label || t.chattype || "?"}] ${t.target_id}` +
      (t.userid && t.chattype === "group" ? ` · 最近 ${t.userid}` : "");
    addRow(t.target_id, label, selected.has(t.target_id));
  });
  // 已保存但不在发现列表里的
  selected.forEach((tid) => {
    if (!discovered.some((t) => t.target_id === tid)) {
      addRow(tid, `[已保存] ${tid}`, true);
    }
  });
  wrap.appendChild(list);
  wrap.appendChild(manual);
  wrap.appendChild(el("p", {
    class: "muted small",
    id: "aibot-targets-msg",
    text: `当前已选 ${selected.size} 个目标`,
  }));
  showModal("推送目标 · " + ch.name, [wrap]);
  const actions = $("modal") && $("modal").querySelector(".modal-actions");
  if (!actions) return;
  actions.querySelectorAll(".btn-trust").forEach((b) => b.remove());
  const saveBtn = el("button", { class: "btn primary btn-trust", text: "保存目标" });
  saveBtn.addEventListener("click", async () => {
    const picked = boxes.filter((x) => x.cb.checked).map((x) => x.tid);
    const extra = (manual.value || "").split(/[\s,;，；]+/).filter(Boolean);
    const all = [...new Set([...picked, ...extra])];
    const r = await api("/api/notify/aibot/targets", {
      method: "POST",
      body: JSON.stringify({ id: ch.id, targets: all }),
    });
    const msg = document.getElementById("aibot-targets-msg");
    if (msg) msg.textContent = r.ok ? `已保存 ${all.length} 个目标` : (r.error || "保存失败");
    if (r.ok) {
      loadNotifyChannels();
      setTimeout(() => {
        $("modal").classList.add("hidden");
        setTabHash(state.tab, "");
      }, 600);
    }
  });
  actions.insertBefore(saveBtn, actions.firstChild);
}

async function loadNotifyChannels() {
  const root = $("notify-list");
  if (!root) return;
  root.innerHTML = '<p class="muted small">加载中…</p>';
  const res = await api("/api/notify/channels");
  if (!res.ok) {
    root.innerHTML = "";
    root.appendChild(el("p", { class: "error", text: res.error || "加载失败" }));
    return;
  }
  root.innerHTML = "";
  const chans = res.channels || [];
  if (!chans.length) {
    root.appendChild(el("p", { class: "muted small", text: "还没有渠道。至少保留 QQ 或添加 Webhook。" }));
    return;
  }
  chans.forEach((ch) => {
    const row = el("div", { class: "notify-row" });
    row.appendChild(el("button", {
      class: "switch " + (ch.enabled ? "on" : ""),
      title: ch.enabled ? "点击停用" : "点击启用",
      onclick: async () => {
        const r = await api("/api/notify/channels/enabled", {
          method: "POST",
          body: JSON.stringify({ id: ch.id, enabled: !ch.enabled }),
        });
        if (r.ok) loadNotifyChannels();
        else alert(r.error || "操作失败");
      },
    }));
    row.appendChild(el("div", { class: "name", text: ch.name }));
    const metaBits = [ch.kind_label || ch.kind];
    if (ch.kind === "qq" && ch.config && ch.config.target) metaBits.push(ch.config.target);
    if (ch.kind === "wecom") {
      const masked = (ch.config && (ch.config.webhook_masked || ch.config.url)) || "";
      metaBits.push(masked || "（未配置 Webhook）");
    }
    if (ch.kind === "wecom_aibot") {
      const c = ch.config || {};
      metaBits.push(c.bot_id_masked || "BotID ****");
      const tgts = c.targets || [];
      metaBits.push(tgts.length ? "推送目标 " + tgts.length + " 个" : "推送目标未配置（可自动发现）");
      const st = (state.aibotStatus || {})[ch.id];
      if (st) {
        metaBits.push(st.authenticated ? "长连接已认证" : (st.connected ? "已连接未认证" : "未连接 " + (st.state || "")));
        if (st.error) metaBits.push("错误: " + st.error);
      }
    }
    if (ch.kind === "webhook" && ch.config && ch.config.url) metaBits.push(ch.config.url);
    if (ch.has_secret) metaBits.push("含加密凭据");
    if (ch.last_test_at) {
      metaBits.push(ch.last_test_ok ? "测试通过" : "测试失败: " + (ch.last_test_error || ""));
    }
    row.appendChild(el("div", { class: "meta", text: metaBits.join(" · ") }));
    const ops = el("div", { class: "ops" });
    ops.appendChild(el("button", {
      class: "btn small",
      text: "发送测试",
      onclick: async () => {
        const r = await api("/api/notify/channels/test", {
          method: "POST",
          body: JSON.stringify({ id: ch.id }),
        });
        const box = $("notify-msg");
        if (r.ok && r.result) {
          const res = r.result.results || [{ target: "", ok: r.result.ok, error: r.result.error }];
          if (r.result.need_targets) {
            if (box) box.textContent = r.result.error || "未配置推送目标";
            openAibotTargets(ch);
          } else {
            const parts = res.map((x) => (x.ok ? "✓" : "✗") + (x.target || "默认") + (x.error ? " " + x.error : ""));
            if (box) box.textContent = (r.result.ok ? "测试消息已发送 " : "测试未全部成功 ") + parts.join(" | ");
          }
        } else {
          if (box) box.textContent = r.error || "测试失败";
        }
        loadNotifyChannels();
      },
    }));
    if (ch.kind === "qq") {
      ops.appendChild(el("button", {
        class: "btn small",
        text: "改目标",
        onclick: () => {
          const t = prompt("QQ 目标（user:123 / group:456）", (ch.config && ch.config.target) || "");
          if (t === null) return;
          api("/api/notify/channels/update", {
            method: "POST",
            body: JSON.stringify({ id: ch.id, config: { target: t.trim() } }),
          }).then((r) => {
            if (r.ok) loadNotifyChannels();
            else alert(r.detail || r.error || "保存失败");
          });
        },
      }));
    }
    if (ch.kind === "wecom") {
      ops.appendChild(el("button", {
        class: "btn small",
        text: "改 Webhook",
        onclick: () => {
          const url = prompt(
            "企业微信 Webhook 地址（完整 URL，含 key）\n留空取消；输入 - 清除现有地址",
            ""
          );
          if (url === null || url === "") return;
          const body = { id: ch.id, config: {} };
          if (url === "-") body.clear_secret = true;
          else body.config = { url: url.trim() };
          api("/api/notify/channels/update", { method: "POST", body: JSON.stringify(body) })
            .then((r) => {
              if (r.ok) loadNotifyChannels();
              else alert(r.detail || r.error || "保存失败");
            });
        },
      }));
      ops.appendChild(el("button", {
        class: "btn small ghost",
        text: "接入说明",
        onclick: () => renderNotifyGuide("wecom"),
      }));
    }
    if (ch.kind === "wecom_aibot") {
      ops.appendChild(el("button", {
        class: "btn small primary",
        text: "推送目标",
        onclick: () => openAibotTargets(ch),
      }));
      ops.appendChild(el("button", {
        class: "btn small",
        text: "接入说明",
        onclick: () => renderNotifyGuide("wecom_aibot"),
      }));
    }
    if (ch.kind === "webhook") {
      ops.appendChild(el("button", {
        class: "btn small",
        text: "编辑",
        onclick: () => {
          const url = prompt("Webhook URL", (ch.config && ch.config.url) || "");
          if (url === null) return;
          const token = prompt("密钥 Token（留空则不修改；输入 - 清除）", "");
          if (token === null) return;
          const body = { id: ch.id, config: { url: url.trim() } };
          if (token === "-") body.clear_secret = true;
          else if (token.trim()) body.secret = { token: token.trim() };
          api("/api/notify/channels/update", { method: "POST", body: JSON.stringify(body) })
            .then((r) => {
              if (r.ok) loadNotifyChannels();
              else alert(r.detail || r.error || "保存失败");
            });
        },
      }));
    }
    ops.appendChild(el("button", {
      class: "btn small danger",
      text: "删除",
      onclick: async () => {
        if (!confirm("删除渠道「" + ch.name + "」？")) return;
        const r = await api("/api/notify/channels/delete", {
          method: "POST",
          body: JSON.stringify({ id: ch.id }),
        });
        if (r.ok) loadNotifyChannels();
        else alert(r.error || "删除失败");
      },
    }));
    row.appendChild(ops);
    root.appendChild(row);
  });
}

async function loadNotifyOutbox() {
  const root = $("notify-outbox");
  if (!root) return;
  const st = ($("notify-outbox-state") || {}).value || "";
  root.innerHTML = '<p class="muted small">加载中…</p>';
  const res = await api("/api/notify/outbox?state=" + encodeURIComponent(st) + "&limit=50");
  if (!res.ok) {
    root.innerHTML = "";
    root.appendChild(el("p", { class: "error", text: res.error || "加载失败" }));
    return;
  }
  const rows = res.outbox || [];
  root.innerHTML = "";
  if (!rows.length) {
    root.appendChild(el("p", { class: "muted small", text: "暂无记录" }));
    return;
  }
  const table = el("table", {});
  table.appendChild(el("tr", {}, [
    el("th", { text: "时间" }),
    el("th", { text: "渠道" }),
    el("th", { text: "状态" }),
    el("th", { text: "内容" }),
    el("th", { text: "错误" }),
    el("th", { text: "" }),
  ]));
  rows.forEach((r) => {
    const stMap = { pending: ["待发送", "warn"], sent: ["已发送", "ok"], failed: ["失败", "bad"] };
    const [stTxt, stCls] = stMap[r.state] || [r.state, "dim"];
    const chLabel = r.channel_id ? (r.channel + (r.target ? " → " + r.target : "")) : (r.channel || "qq");
    const tr = el("tr", {}, [
      el("td", { class: "small muted", text: fmtTime(r.created_at) }),
      el("td", { class: "small", text: chLabel }),
      el("td", {}, [badge(stTxt, stCls)]),
      el("td", { class: "small", text: String(r.body || "").slice(0, 80) }),
      el("td", { class: "small muted", text: r.last_error || "" }),
      el("td", {}, r.state === "failed" ? [el("button", {
        class: "btn small",
        text: "重试",
        onclick: async () => {
          const rr = await api("/api/notifications/retry", {
            method: "POST",
            body: JSON.stringify({ id: r.id }),
          });
          if (rr.ok) loadNotifyOutbox();
        },
      })] : []),
    ]);
    table.appendChild(tr);
  });
  root.appendChild(table);
}

on("notify-platform", "change", () => {
  fillNotifyMethods();
  toggleNotifyKind();
});
on("notify-method", "change", toggleNotifyKind);

function notifyMsg(t) {
  const box = $("notify-msg");
  if (box) box.textContent = t || "";
}

async function notifyCreate(payload) {
  const r = await api("/api/notify/channels", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  notifyMsg(r.ok ? "已添加，可点「发送测试」验证" : (r.detail || r.error || "添加失败"));
  if (r.ok) {
    ($("notify-name") || {}).value = "";
    loadNotifyChannels();
  }
  return r;
}

on("notify-add-btn", "click", async () => {
  const name = (($("notify-name") || {}).value || "").trim();
  if (!name) return notifyMsg("请填写名称");
  const target = (($("notify-qq-target") || {}).value || "").trim();
  await notifyCreate({
    name, kind: "qq", config: { target }, secret: {}, enabled: true,
  });
  ($("notify-qq-target") || {}).value = "";
});

on("notify-add-btn-wecom", "click", async () => {
  const name = (($("notify-name") || {}).value || "").trim();
  if (!name) return notifyMsg("请填写名称");
  const url = (($("notify-wecom-url") || {}).value || "").trim();
  if (!url) {
    notifyMsg("请填写企业微信 Webhook 地址（见下方接入说明）");
    renderNotifyGuide("wecom");
    return;
  }
  await notifyCreate({
    name, kind: "wecom",
    config: { url }, secret: { webhook_url: url }, enabled: true,
  });
  ($("notify-wecom-url") || {}).value = "";
});

on("notify-add-btn-aibot", "click", async () => {
  const name = (($("notify-name") || {}).value || "").trim();
  if (!name) return notifyMsg("请填写名称");
  const botId = (($("notify-aibot-botid") || {}).value || "").trim();
  const secret = (($("notify-aibot-secret") || {}).value || "").trim();
  const wsUrl = (($("notify-aibot-wsurl") || {}).value || "").trim();
  const targetsRaw = (($("notify-aibot-targets") || {}).value || "").trim();
  const targets = targetsRaw.split(/[\s,;，；]+/).filter(Boolean);
  if (!botId || !secret) {
    notifyMsg("请填写 Bot ID 与 Secret");
    renderNotifyGuide("wecom_aibot");
    return;
  }
  // 推送目标可为空：连接后从群消息自动发现
  await notifyCreate({
    name, kind: "wecom_aibot",
    config: { bot_id: botId, targets, ws_url: wsUrl },
    secret: { bot_id: botId, secret },
    enabled: true,
  });
  ($("notify-aibot-botid") || {}).value = "";
  ($("notify-aibot-secret") || {}).value = "";
  ($("notify-aibot-targets") || {}).value = "";
});

on("notify-add-btn-hook", "click", async () => {
  const name = (($("notify-name") || {}).value || "").trim();
  if (!name) return notifyMsg("请填写名称");
  const url = (($("notify-hook-url") || {}).value || "").trim();
  if (!url) return notifyMsg("请填写 URL");
  const secret = {};
  const token = (($("notify-hook-token") || {}).value || "").trim();
  if (token) secret.token = token;
  const config = { url, method: "POST", content_type: "application/json" };
  const hdr = (($("notify-hook-headers") || {}).value || "").trim();
  if (hdr) {
    try { config.headers = JSON.parse(hdr); }
    catch (e) { return notifyMsg("自定义头不是合法 JSON"); }
  }
  await notifyCreate({ name, kind: "webhook", config, secret, enabled: true });
  ($("notify-hook-url") || {}).value = "";
  ($("notify-hook-token") || {}).value = "";
  ($("notify-hook-headers") || {}).value = "";
});
on("notify-outbox-refresh", "click", () => loadNotifyOutbox());
on("notify-outbox-state", "change", () => loadNotifyOutbox());
on("notify-outbox-retry", "click", async () => {
  const r = await api("/api/notifications/retry", { method: "POST", body: JSON.stringify({}) });
  const msg = $("notify-msg");
  if (msg) msg.textContent = r.ok ? `已重试 ${r.retried} 条` : (r.error || "重试失败");
  loadNotifyOutbox();
});

/* ---- 消息记录 ---- */
const msgState = { offset: 0, limit: 50, total: 0 };

function msgDirBadge(d) {
  return d === "in" ? badge("入站", "dim") : badge("出站", "ok");
}

function msgStateBadge(s) {
  const map = {
    received: ["已接收", "dim"],
    processed: ["已处理", "ok"],
    ignored: ["已忽略", "dim"],
    failed: ["处理/发送失败", "bad"],
    pending: ["待发送", "warn"],
    sent: ["发送成功", "ok"],
    unknown: ["结果未知", "warn"],
  };
  const [t, c] = map[s] || [s, "dim"];
  return badge(t, c);
}

function msgLocalToTs(v) {
  if (!v) return null;
  const t = new Date(v).getTime();
  return isNaN(t) ? null : t / 1000;
}

async function renderMessages() {
  const root = $("msg-list");
  if (!root) return;
  root.innerHTML = '<p class="muted small">加载中…</p>';
  const params = new URLSearchParams();
  const platform = ($("msg-platform") || {}).value || "";
  const direction = ($("msg-direction") || {}).value || "";
  const st = ($("msg-state") || {}).value || "";
  const q = (($("msg-q") || {}).value || "").trim();
  const start = msgLocalToTs(($("msg-start") || {}).value);
  const end = msgLocalToTs(($("msg-end") || {}).value);
  if (platform) params.set("platform", platform);
  if (direction) params.set("direction", direction);
  if (st) params.set("state", st);
  if (q) params.set("q", q);
  if (start) params.set("start", String(start));
  if (end) params.set("end", String(end));
  params.set("limit", String(msgState.limit));
  params.set("offset", String(msgState.offset));
  const res = await api("/api/messages?" + params.toString());
  if (!res.ok) {
    root.innerHTML = "";
    root.appendChild(el("p", { class: "error", text: res.error || "加载失败" }));
    return;
  }
  msgState.total = res.total || 0;
  const items = res.items || [];
  root.innerHTML = "";
  if (!items.length) {
    root.appendChild(el("p", { class: "muted small", text: "没有符合条件的消息" }));
  } else {
    const table = el("table", {});
    table.appendChild(el("tr", {}, [
      el("th", { text: "时间" }),
      el("th", { text: "平台" }),
      el("th", { text: "渠道" }),
      el("th", { text: "方向" }),
      el("th", { text: "发送者" }),
      el("th", { text: "目标" }),
      el("th", { text: "内容" }),
      el("th", { text: "状态" }),
    ]));
    items.forEach((m) => {
      const tr = el("tr", {
        style: "cursor:pointer",
        onclick: () => openMessageDetail(m),
      }, [
        el("td", { class: "small muted", text: fmtTime(m.at) }),
        el("td", { class: "small", text: m.platform || "-" }),
        el("td", { class: "small", text: m.channel_name || m.channel_kind || m.channel_id || "-" }),
        el("td", {}, [msgDirBadge(m.direction)]),
        el("td", { class: "small", text: m.sender || "-" }),
        el("td", { class: "small", text: m.target || "-" }),
        el("td", { class: "small", text: String(m.body || "").slice(0, 60) + (String(m.body || "").length > 60 ? "…" : "") }),
        el("td", {}, [msgStateBadge(m.state)]),
      ]);
      table.appendChild(tr);
    });
    root.appendChild(table);
  }
  const page = $("msg-page");
  if (page) {
    const from = msgState.total ? msgState.offset + 1 : 0;
    const to = Math.min(msgState.offset + msgState.limit, msgState.total);
    page.textContent = `${from}-${to} / ${msgState.total}`;
  }
}

function openMessageDetail(m) {
  const box = el("div", {});
  const kv = (k, v) => el("p", {
    class: "small",
    style: "margin:4px 0",
  }, [el("strong", { text: k + "： " }), document.createTextNode(String(v == null ? "" : v))]);
  box.appendChild(kv("时间", fmtTime(m.at)));
  box.appendChild(kv("平台", m.platform || "-"));
  box.appendChild(kv("渠道", (m.channel_name || "") + (m.channel_id ? " (" + m.channel_id + ")" : "")));
  box.appendChild(kv("方向", m.direction === "in" ? "入站" : "出站"));
  box.appendChild(kv("发送者", m.sender || "-"));
  box.appendChild(kv("接收目标", m.target || "-"));
  box.appendChild(kv("状态", m.state || "-"));
  if (m.error) box.appendChild(kv("失败原因", m.error));
  if (m.direction === "in") {
    box.appendChild(kv("是否回复", m.replied ? "是" : "否"));
    if (m.reply_log_id) box.appendChild(kv("回复消息 ID", m.reply_log_id));
  }
  box.appendChild(el("pre", {
    style: "margin-top:10px;padding:10px;background:rgba(255,255,255,.05);border-radius:8px;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto;font-size:12px",
    text: m.body || "（空）",
  }));
  if (m.detail && Object.keys(m.detail).length) {
    box.appendChild(el("p", {
      class: "muted small",
      style: "margin-top:8px",
      text: "详情: " + JSON.stringify(m.detail),
    }));
  }
  if (m.outbox_id) box.appendChild(kv("Outbox ID", m.outbox_id));
  showModal("消息详情 · " + (m.id || "").slice(0, 16), [box]);
  // 拉取关联回复
  if (m.id) {
    api("/api/messages/" + encodeURIComponent(m.id)).then((r) => {
      if (!r.ok || !r.related || !r.related.length) return;
      const rel = el("div", { style: "margin-top:12px" });
      rel.appendChild(el("p", { class: "muted small", text: "关联回复：" }));
      r.related.forEach((x) => {
        rel.appendChild(el("p", {
          class: "small",
          style: "margin:4px 0;padding:6px 8px;background:rgba(255,255,255,.04);border-radius:6px",
          text: `${fmtTime(x.at)} [${x.state}] ${String(x.body || "").slice(0, 120)}`,
        }));
      });
      $("modal-body").appendChild(rel);
    });
  }
}

on("msg-search", "click", () => {
  msgState.offset = 0;
  renderMessages();
});
on("msg-prev", "click", () => {
  msgState.offset = Math.max(0, msgState.offset - msgState.limit);
  renderMessages();
});
on("msg-next", "click", () => {
  if (msgState.offset + msgState.limit < msgState.total) {
    msgState.offset += msgState.limit;
    renderMessages();
  }
});
on("msg-q", "keydown", (e) => {
  if (e.key === "Enter") {
    msgState.offset = 0;
    renderMessages();
  }
});

/* ---- Prometheus 配置管理 ---- */
const pcState = { overview: null, config: null, targets: null, rules: null };

function pcBadge(text, cls) {
  return el("span", { class: "badge " + (cls || "dim"), text: String(text || "") });
}

function pcSetStatus(msg, cls) {
  const n = $("promconfig-status");
  if (!n) return;
  n.textContent = msg || "";
  n.className = "muted small" + (cls ? " " + cls : "");
}

async function renderPromConfig() {
  pcSetStatus("加载中…");
  const [ov, cfg, tg, rules] = await Promise.all([
    api("/api/promconfig/overview").catch((e) => ({ ok: false, error: String(e) })),
    api("/api/promconfig/config").catch((e) => ({ ok: false, error: String(e) })),
    api("/api/promconfig/targets").catch((e) => ({ ok: false, error: String(e) })),
    api("/api/promconfig/rules").catch((e) => ({ ok: false, error: String(e) })),
  ]);
  pcState.overview = ov;
  pcState.config = cfg;
  pcState.targets = tg;
  pcState.rules = rules;

  const raw = $("promconfig-raw");
  if (raw) raw.textContent = (cfg && cfg.raw) || (cfg && cfg.error ? String(cfg.error) : "（无配置）");

  renderPcTargets();
  renderPcRules();
  await renderPcNodeExporter();
  const live = (ov && ov.live) || {};
  const msg = ov && ov.ok
    ? `目标 ${live.targets_total || 0} · 正常 ${live.targets_up || 0}` + (live.targets_down ? ` · 异常 ${live.targets_down}` : "")
    : "加载失败";
  pcSetStatus(msg, ov && ov.ok ? "" : "error");
}

function pcAddr(x) {
  if (x == null) return "-";
  if (typeof x === "string") return x;
  if (typeof x === "object") {
    if (x.address) return pcAddr(x.address);
    // YAML 误解析成 map 的 host:port / url：拼回可读形式
    const keys = Object.keys(x);
    if (keys.length === 1) {
      const k = keys[0];
      const v = x[k];
      if (/^https?$/.test(k) && typeof v === "string") return k + ":" + v;
      return k + ":" + v;
    }
    return keys.map((k) => k + "=" + x[k]).join(",");
  }
  return String(x);
}

function pcShortErr(s) {
  if (!s) return "";
  return String(s).replace(/^Get\s+"/, "").replace(/":.*/, "").slice(0, 48);
}

function renderPcTargets() {
  const box = $("promconfig-targets");
  if (!box) return;
  box.innerHTML = "";
  const t = pcState.targets;
  if (!t || !t.ok) {
    box.appendChild(el("p", { class: "error", text: "加载失败: " + ((t && t.error) || "") }));
    return;
  }
  const liveKey = new Map();
  (t.live_targets || []).forEach((lt) => {
    const addr =
      (lt.labels && (lt.labels.instance || lt.labels.address)) ||
      (lt.scrapeUrl || "").replace(/^https?:\/\//, "").replace(/\/metrics$/, "");
    liveKey.set(pcAddr(addr), lt);
  });
  const rows = [];
  (t.file_sd_targets || []).forEach((row) => rows.push({ ...row, managed: true, via: "托管" }));
  (t.config_targets || []).forEach((row) => {
    if (row.via === "file_sd_configs") return;
    rows.push({ ...row, managed: false, via: row.job || "配置" });
  });
  if (!rows.length) {
    box.appendChild(el("p", { class: "muted small", text: "暂无目标。填地址点「添加」。" }));
    return;
  }
  rows.forEach((row) => {
    const addr = pcAddr(row.address);
    const lt = liveKey.get(addr);
    const up = lt && lt.health === "up";
    const name = (row.labels && (row.labels.name || row.labels.asset || row.labels.service)) || row.via || "";
    const line = el("div", {
      style: "display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.06)",
    }, [
      el("span", { class: "badge " + (up ? "ok" : lt ? "bad" : "dim"), text: up ? "正常" : lt ? "异常" : "—" }),
      el("strong", { class: "small", text: addr }),
      el("span", { class: "muted small", text: name }),
      el("span", { class: "muted small", style: "margin-left:auto", text: lt ? pcShortErr(lt.lastError) : "" }),
    ]);
    if (row.managed) {
      line.appendChild(el("button", {
        class: "btn ghost small",
        text: "移除",
        onclick: async () => {
          if (!confirm("移除 " + addr + "？")) return;
          const r = await api("/api/promconfig/targets/delete", {
            method: "POST",
            body: JSON.stringify({ address: addr, file: row.file }),
          });
          if (!r.ok) alert("失败: " + (r.error || r.detail || ""));
          renderPromConfig();
        },
      }));
    } else {
      line.appendChild(el("span", { class: "muted small", text: "配置内" }));
    }
    box.appendChild(line);
  });
}

function renderPcRules() {
  const box = $("promconfig-rules");
  const tplBox = $("promconfig-templates");
  if (!box || !tplBox) return;
  box.innerHTML = "";
  tplBox.innerHTML = "";
  const r = pcState.rules;
  if (!r || !r.ok) {
    box.appendChild(el("p", { class: "error", text: "加载失败: " + ((r && r.error) || "") }));
    return;
  }
  // 模板：一行一条，开关 + 阈值
  const thrHint = {
    cpu_high: "80",
    mem_high: "85",
    disk_high: "85",
    load_high: "2",
    host_down: "",
  };
  (r.templates || []).forEach((tp) => {
    const needThr = tp.id !== "host_down";
    const thr = el("input", {
      placeholder: thrHint[tp.id] || "阈值",
      style: "width:72px",
      title: needThr ? "不填用默认" : "无需阈值",
    });
    if (!needThr) thr.classList.add("hidden");
    const on = el("button", {
      class: "btn primary small",
      text: "启用",
      onclick: async () => {
        const body = { template_id: tp.id, enabled: true };
        if (needThr && thr.value) body.threshold = Number(thr.value);
        const res = await api("/api/promconfig/rules/template", { method: "POST", body: JSON.stringify(body) });
        if (!res.ok) alert("失败: " + (res.error || res.detail || ""));
        renderPromConfig();
      },
    });
    const off = el("button", {
      class: "btn ghost small",
      text: "停用",
      onclick: async () => {
        await api("/api/promconfig/rules/template", {
          method: "POST",
          body: JSON.stringify({ template_id: tp.id, enabled: false }),
        });
        renderPromConfig();
      },
    });
    tplBox.appendChild(el("div", {
      style: "display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.06)",
    }, [
      el("div", { style: "min-width:140px" }, [
        el("strong", { class: "small", text: tp.name }),
      ]),
      el("span", { class: "muted small", style: "flex:1", text: tp.description }),
      el("span", {
        class: "badge " + (tp.default_severity === "critical" ? "bad" : "dim"),
        text: tp.default_severity,
      }),
      thr,
      on,
      off,
    ]));
  });

  // 已启用规则（折叠里）：中文化常见名
  const zhName = {
    NodeHostDown: "主机离线",
    NodeCpuHigh: "CPU 过高",
    NodeMemoryHigh: "内存过高",
    NodeDiskHigh: "磁盘过高",
    NodeLoadHigh: "负载过高",
    TargetDown: "探测失败",
    PrometheusJobMissing: "采集丢失",
    PrometheusNotConnectedToAlertmanager: "未连 Alertmanager",
    DiskUsageHigh: "磁盘过高",
    MemoryLow: "内存不足",
  };
  let n = 0;
  (r.files || []).forEach((f) => {
    (f.groups || []).forEach((g) => {
      (g.rules || []).forEach((rule) => {
        n++;
        const sev = (rule.labels && rule.labels.severity) || "";
        const label = zhName[rule.alert] || rule.alert || rule.record || "-";
        const line = el("div", {
          style: "display:flex;align-items:center;gap:10px;padding:8px 0",
        }, [
          pcBadge(sev || "on", sev === "critical" ? "bad" : sev === "warning" ? "warn" : "ok"),
          el("strong", { class: "small", text: label }),
          el("span", { class: "muted small", text: rule.alert || "" }),
          el("span", { class: "muted small", style: "margin-left:auto", text: rule.for ? "持续 " + rule.for : "" }),
        ]);
        if (f.managed_by && rule.simple_editable) {
          line.appendChild(el("button", {
            class: "btn ghost small",
            text: "停用",
            onclick: async () => {
              await api("/api/promconfig/rules/update", {
                method: "POST",
                body: JSON.stringify({ file_path: f.path, alert: rule.alert, enabled: false }),
              });
              renderPromConfig();
            },
          }));
        }
        box.appendChild(line);
      });
    });
  });
  const cnt = $("pc-rules-count");
  if (cnt) cnt.textContent = String(n);
}

function pcFillRegisterAddr() {
  const sel = $("pc-ne-asset");
  const inp = $("pc-ne-register");
  if (!sel || !inp) return;
  const a = (state.assets || []).find((x) => x.id === sel.value);
  const host = (a && (a.monitor_host || a.host)) || "";
  // 换主机就覆盖地址，避免沿用上一台的 IP
  const addressHost = host.includes(":") && !host.startsWith("[") ? "[" + host + "]" : host;
  inp.value = host ? addressHost + ":9100" : "";
}

on("pc-ne-asset", "change", pcFillRegisterAddr);

async function renderPcNodeExporter() {
  const box = $("promconfig-ne");
  const sel = $("pc-ne-asset");
  if (!box) return;
  if (sel && state.assets) {
    fillSelect("pc-ne-asset", state.assets.map((a) => ({
      v: a.id,
      t: a.id + (a.monitor_host ? " · " + a.monitor_host : ""),
    })));
    pcFillRegisterAddr();
  }
  box.innerHTML = "";
}

on("promconfig-refresh", "click", () => renderPromConfig());
on("promconfig-validate", "click", async () => {
  if (!confirm("执行 promtool 校验并热重载 Prometheus？")) return;
  pcSetStatus("校验中…");
  const r = await api("/api/promconfig/validate", { method: "POST", body: "{}" });
  if (r.ok) {
    pcSetStatus("校验通过并已热重载");
    alert("校验通过，已热重载");
  } else {
    pcSetStatus("校验/重载失败", "error");
    alert("失败: " + (r.error || "") + " " + JSON.stringify(r.detail || r));
  }
  renderPromConfig();
});
on("promconfig-rollback", "click", async () => {
  const path = prompt("要回滚的配置路径（如 prometheus.yml / file_sd/ayana-nodes.json / rules/ayana-node-alerts.yml）");
  if (!path) return;
  const r = await api("/api/promconfig/rollback", {
    method: "POST",
    body: JSON.stringify({ path }),
  });
  if (!r.ok) alert("回滚失败: " + (r.error || r.detail || ""));
  else alert("已回滚 " + path);
  renderPromConfig();
});
on("pc-target-add", "click", async () => {
  const address = ($("pc-target-addr") || {}).value || "";
  const asset = ($("pc-target-asset") || {}).value || "";
  const labels = {};
  if (asset) labels.asset = asset;
  const r = await api("/api/promconfig/targets", {
    method: "POST",
    body: JSON.stringify({ address, labels }),
  });
  if (!r.ok) alert("添加失败: " + (r.error || r.detail || ""));
  const a = $("pc-target-addr");
  if (a) a.value = "";
  renderPromConfig();
});
on("pc-ne-check", "click", async () => {
  const asset = ($("pc-ne-asset") || {}).value;
  const r = await api("/api/promconfig/node-exporter?asset_id=" + encodeURIComponent(asset || ""));
  const box = $("promconfig-ne");
  if (!box) return;
  if (!r.ok) {
    box.innerHTML = "";
    box.appendChild(el("p", { class: "error", text: String(r.error || "检查失败") }));
    return;
  }
  const s = r.status || {};
  box.innerHTML = "";
  box.appendChild(el("p", {
    class: "small",
    text: `安装=${s.installed ? "是" : "否"} · 运行=${s.active ? "是" : "否"} · 9100监听=${s.port_9100 ? "是" : "否"} · ${s.load_state || ""}`,
  }));
  if (s.error_active || s.error_port) {
    box.appendChild(el("p", { class: "muted small", text: (s.error_active || "") + " " + (s.error_port || "") }));
  }
});
async function pcNodeAction(action) {
  const asset = ($("pc-ne-asset") || {}).value;
  if (action === "stop" && !confirm("停止 " + asset + " 的采集器？")) return;
  const r = await api("/api/promconfig/node-exporter", {
    method: "POST",
    body: JSON.stringify({ asset_id: asset, action, listen_address: "127.0.0.1:9100" }),
  });
  const box = $("promconfig-ne");
  if (!box) return;
  box.innerHTML = "";
  if (!r.ok) {
    box.appendChild(el("p", { class: "error", text: String((r.error || "") + " " + (r.detail || "")) }));
    return;
  }
  const s = r.status || r;
  box.appendChild(el("p", {
    class: "small",
    text: `${asset}: ${s.active || s.running ? "运行中" : "未运行"}${s.mode ? " · " + s.mode : ""}`,
  }));
}
on("pc-ne-start", "click", () => pcNodeAction("start"));
on("pc-ne-stop", "click", () => pcNodeAction("stop"));
on("pc-ne-register-btn", "click", async () => {
  const asset = ($("pc-ne-asset") || {}).value;
  const address = (($("pc-ne-register") || {}).value || "").trim();
  const box = $("promconfig-ne");
  if (box) box.innerHTML = '<p class="muted small">接入中，可能需要 1-2 分钟…</p>';
  const r = await api("/api/promconfig/node-exporter/adopt", {
    method: "POST",
    body: JSON.stringify({ asset_id: asset, address }),
  });
  if (!r.ok) {
    if (box) {
      box.innerHTML = "";
      box.appendChild(el("p", { class: "error", text: String((r.error || "") + " " + (r.detail || "")) }));
    }
    return;
  }
  if (box) {
    box.innerHTML = "";
    box.appendChild(el("p", {
      class: "small",
      style: "color:var(--ok)",
      text: "已接入 " + r.asset_id + " → " + r.address,
    }));
    (r.steps || []).forEach((s) => {
      box.appendChild(el("p", {
        class: "muted small",
        text: "· " + s.step + ": " + (s.ok ? "成功" : "失败"),
      }));
    });
  }
  renderPromConfig();
});

/* ---- 业务检查 ---- */
async function renderChecks() {
  fillSelect("chk-asset", (state.assets || []).map((a) => ({ v: a.id, t: a.id + " / " + a.display_name })));
  const list = $("chk-list");
  const act = $("chk-activity");
  if (!list) return;
  list.innerHTML = '<p class="muted small">加载中…</p>';
  const [cRes, aRes] = await Promise.all([
    api("/api/checks").catch(() => ({ ok: false })),
    api("/api/checks/activity").catch(() => ({ ok: false })),
  ]);
  list.innerHTML = "";
  if (!cRes.ok) {
    list.appendChild(el("p", { class: "error", text: "加载失败: " + (cRes.error || "") }));
    return;
  }
  const rows = cRes.checks || [];
  if (!rows.length) {
    list.appendChild(el("p", { class: "muted small", text: "还没有检查。选主机和类型，点「添加检查」。" }));
  } else {
    const table = el("table", { class: "table" });
    table.appendChild(el("tr", {}, [
      el("th", { text: "主机" }),
      el("th", { text: "名称" }),
      el("th", { text: "类型" }),
      el("th", { text: "状态" }),
      el("th", { text: "最近" }),
      el("th", { text: "操作" }),
    ]));
    rows.forEach((c) => {
      const st = c.last_state === "ok" ? "ok" : c.last_state === "fail" ? "bad" : "dim";
      table.appendChild(el("tr", {}, [
        el("td", { class: "small", text: c.asset_id }),
        el("td", { class: "small", text: c.name }),
        el("td", { class: "small", text: c.kind + (c.kind === "port" ? " :" + (c.params.port || "") : c.kind === "service" ? " " + (c.params.unit || "") : "") }),
        el("td", {}, [pcBadge(c.enabled ? c.last_state : "停用", st)]),
        el("td", { class: "small", text: c.last_detail || (c.last_at ? fmtTime(c.last_at) : "—") }),
        el("td", {}, [
          el("button", {
            class: "btn ghost small",
            text: "立即测",
            onclick: async () => {
              const r = await api("/api/checks/run", { method: "POST", body: JSON.stringify({ id: c.id }) });
              if (!r.ok) alert("失败: " + (r.error || r.detail || ""));
              renderChecks();
            },
          }),
          el("button", {
            class: "btn ghost small",
            text: c.enabled ? "停用" : "启用",
            onclick: async () => {
              await api("/api/checks/update", {
                method: "POST",
                body: JSON.stringify({ id: c.id, enabled: !c.enabled }),
              });
              renderChecks();
            },
          }),
          el("button", {
            class: "btn ghost small",
            text: "删除",
            onclick: async () => {
              if (!confirm("删除检查 " + c.name + "？")) return;
              await api("/api/checks/delete", { method: "POST", body: JSON.stringify({ id: c.id }) });
              renderChecks();
            },
          }),
        ]),
      ]));
    });
    list.appendChild(table);
  }
  if (act) {
    act.innerHTML = "";
    const items = (aRes && aRes.activity) || [];
    if (!items.length) act.appendChild(el("p", { class: "muted small", text: "暂无动态" }));
    items.slice(0, 20).forEach((x) => {
      act.appendChild(el("p", {
        class: "small",
        style: "margin:4px 0",
        text: `${fmtTime(x.at)} [${x.state}] ${x.asset_id}/${x.name}: ${x.detail || ""}`,
      }));
    });
  }
}

function chkKindChanged() {
  const k = ($("chk-kind") || {}).value;
  const p = $("chk-params-port"), s = $("chk-params-service"), c = $("chk-params-command");
  if (p) p.classList.toggle("hidden", k !== "port");
  if (s) s.classList.toggle("hidden", k !== "service");
  if (c) c.classList.toggle("hidden", k !== "command");
}
on("chk-kind", "change", chkKindChanged);
on("chk-refresh", "click", () => renderChecks());

on("monitor-detect", "click", () => {
  const asset = monitorState.host || (($("monitor-host") || {}).value || "") || (($("pc-ne-asset") || {}).value || "");
  if (!asset) {
    const box = $("monitor-install-box");
    if (box) box.innerHTML = '<p class="muted small">先选一台主机</p>';
    return;
  }
  pcRunAdoptFlow(asset);
});

on("overview-goto-monitor", "click", () => activateTab("monitor", ""));
on("overview-goto-incidents", "click", () => activateTab("incidents", ""));
on("overview-goto-notify", "click", () => activateTab("notify", ""));

on("chk-add", "click", async () => {
  const kind = ($("chk-kind") || {}).value;
  const body = {
    asset_id: ($("chk-asset") || {}).value,
    kind,
    name: ($("chk-name") || {}).value,
    interval_sec: Number(($("chk-interval") || {}).value || 60),
    fail_threshold: Number(($("chk-threshold") || {}).value || 2),
    severity: ($("chk-severity") || {}).value,
    params: {},
    expect: {},
  };
  if (kind === "port") {
    body.params = {
      port: Number(($("chk-port") || {}).value),
      protocol: ($("chk-proto") || {}).value || "tcp",
    };
    if (!body.name) body.name = "port-" + body.params.port;
  } else if (kind === "service") {
    body.params = { unit: ($("chk-unit") || {}).value };
    if (!body.name) body.name = body.params.unit;
  } else {
    const raw = ($("chk-cmd") || {}).value || "";
    body.params = { argv: raw.trim().split(/\s+/).filter(Boolean) };
    const ev = ($("chk-expect") || {}).value;
    const evv = ($("chk-expect-val") || {}).value;
    if (ev === "contains") body.expect = { output_contains: evv };
    else if (ev === "not_contains") body.expect = { output_not_contains: evv };
    else body.expect = { exit_code: 0 };
    if (!body.name) body.name = "cmd";
  }
  const r = await api("/api/checks", { method: "POST", body: JSON.stringify(body) });
  if (!r.ok) alert("添加失败: " + (r.error || r.detail || ""));
  renderChecks();
});

/* ---- init ---- */
boot();
