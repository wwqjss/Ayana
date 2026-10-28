/* Unified settings center: one shell, explicit scope and live server state. */
const settingsState = {
  opened: false, page: "model", generation: 0, dirty: false, busy: false,
  returnFocus: null, promptKey: "investigation", dirtyMessage: "", notificationScope: null,
};
const settingsSections = [
  { key: "model", label: "模型", icon: "◈", admin: true },
  { key: "profile", label: "个人资料", icon: "○" },
  { key: "security", label: "双重验证", icon: "◇" },
  { key: "prompts", label: "提示词", icon: "≡", admin: true },
  { key: "skills", label: "技能", icon: "▦", admin: true },
  { key: "connections", label: "监控接入", icon: "⌁", admin: true },
  { key: "notifications", label: "通知渠道", icon: "◉", admin: true },
  { key: "about", label: "关于", icon: "ⓘ" },
];

function closeAccountMenu(restoreFocus = false) {
  const menu = $("account-menu"), button = $("account-menu-btn");
  if (menu) menu.classList.add("hidden");
  if (button) { button.setAttribute("aria-expanded", "false"); if (restoreFocus) button.focus(); }
}
function accountMenuItems() { return Array.from(($("account-menu") || document).querySelectorAll('[role="menuitem"]')); }
on("account-menu-btn", "click", () => {
  const menu = $("account-menu"), button = $("account-menu-btn");
  const opening = menu.classList.contains("hidden");
  menu.classList.toggle("hidden", !opening);
  button.setAttribute("aria-expanded", String(opening));
});
on("account-menu-btn", "keydown", (event) => {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  event.preventDefault();
  $("account-menu").classList.remove("hidden");
  $("account-menu-btn").setAttribute("aria-expanded", "true");
  const items = accountMenuItems(); (event.key === "ArrowUp" ? items[items.length - 1] : items[0])?.focus();
});
on("account-menu", "keydown", (event) => {
  const items = accountMenuItems(), index = items.indexOf(document.activeElement);
  if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
    event.preventDefault();
    const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
    items[next]?.focus();
  }
  if (event.key === "Escape") { event.preventDefault(); closeAccountMenu(true); }
});
document.addEventListener("click", (event) => {
  const menu = $("account-menu"), button = $("account-menu-btn");
  if (menu && !menu.contains(event.target) && button && !button.contains(event.target)) closeAccountMenu();
});

function settingsDescription(text) { return el("p", { class: "settings-description", text }); }
function settingsCard(title, description = "") {
  const card = el("section", { class: "settings-card" });
  if (title) card.appendChild(el("h3", { text: title }));
  if (description) card.appendChild(settingsDescription(description));
  return card;
}
function settingsField(label, input, help = "") {
  return el("label", { class: "settings-field" }, [el("span", { text: label }), input, ...(help ? [el("small", { text: help })] : [])]);
}
function settingsInput(id, type = "text", value = "", extra = {}) { return el("input", { id, type, value, ...extra }); }
function settingsFeedback(text, error = false) {
  const node = $("settings-feedback");
  if (node) { node.className = error ? "settings-feedback error" : "settings-feedback settings-footer-note"; node.textContent = text; }
}
function settingsDirty(value, message = "") {
  settingsState.dirty = Boolean(value); settingsState.dirtyMessage = message;
  const node = $("settings-section-title"); if (node) node.dataset.dirty = String(Boolean(value));
}
function settingsBusy(value) {
  settingsState.busy = Boolean(value);
  document.querySelectorAll("#settings-nav button").forEach((button) => { button.disabled = settingsState.busy; });
  $("settings-dialog")?.setAttribute("aria-busy", String(settingsState.busy));
}
function settingsAskDiscard(continuation) {
  showModal("放弃未保存的修改？", [settingsDescription(settingsState.dirtyMessage || "当前修改尚未保存，离开后将丢失。")]);
  const actions = $("modal").querySelector(".modal-card > .modal-actions");
  const cancel = el("button", { class: "btn", type: "button", text: "继续编辑", onclick: () => { $("modal").classList.add("hidden"); $("settings-content").focus(); } });
  const discard = el("button", { class: "btn settings-danger", type: "button", text: "放弃修改", onclick: () => {
    $("modal").classList.add("hidden"); settingsDirty(false); continuation();
  } });
  const close = $("modal-close"); if (close) close.classList.add("hidden");
  actions.appendChild(cancel); actions.appendChild(discard); cancel.focus();
}
function settingsCanLeave(continuation) {
  if (settingsState.busy) { settingsFeedback("操作正在进行，请等待结果。", true); return false; }
  if (settingsState.dirty) { settingsAskDiscard(continuation); return false; }
  return true;
}
function returnSettingsNotifications() {
  if (settingsState.notificationScope) settingsState.notificationScope.cleanup();
  settingsState.notificationScope = null;
  const content = $("settings-notification-content"), storage = $("settings-storage");
  if (content && storage && content.parentNode !== storage) {
    content.querySelectorAll("input, textarea").forEach((input) => {
      if (["checkbox", "radio"].includes(input.type)) input.checked = Boolean(input.defaultChecked);
      else input.value = input.defaultValue || "";
    });
    storage.appendChild(content);
  }
}
function settingsClearSensitive() {
  const content = $("settings-content");
  if (content) content.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; });
  returnSettingsNotifications();
}
function closeSettings(force = false) {
  if (!settingsState.opened) return true;
  if (!force && !settingsCanLeave(() => closeSettings(true))) return false;
  settingsClearSensitive();
  settingsState.opened = false; settingsState.generation += 1;
  settingsDirty(false); settingsBusy(false);
  $("settings-dialog").classList.add("hidden");
  $("settings-content").innerHTML = ""; $("settings-actions").innerHTML = "";
  document.body.classList.remove("settings-page-open");
  if ($("main-view")) $("main-view").inert = false;
  if (settingsState.returnFocus?.isConnected) settingsState.returnFocus.focus();
  return true;
}
async function openSettings(section = "model") {
  closeAccountMenu();
  if (!state.user) return;
  if (state.user.must_change_password) { showPasswordChange(true); return; }
  const allowed = settingsSections.filter((item) => !item.admin || state.user.is_admin);
  if (!allowed.some((item) => item.key === section)) section = "profile";
  if (settingsState.opened) return renderSettingsSection(section);
  settingsState.returnFocus = document.activeElement;
  settingsState.opened = true;
  $("settings-dialog").classList.remove("hidden");
  document.body.classList.add("settings-page-open");
  const navigation = $("settings-nav"); navigation.innerHTML = "";
  allowed.forEach((item) => navigation.appendChild(el("button", {
    id: "settings-nav-" + item.key, type: "button", class: "settings-nav-item", "data-section": item.key,
    onclick: () => renderSettingsSection(item.key),
  }, [el("span", { class: "settings-nav-icon", text: item.icon, "aria-hidden": "true" }), el("span", { text: item.label })])));
  $("settings-close").focus();
  if ($("main-view")) $("main-view").inert = true;
  return renderSettingsSection(section, true);
}
async function renderSettingsSection(section, confirmed = false) {
  const item = settingsSections.find((entry) => entry.key === section);
  if (!settingsState.opened || !item || (item.admin && !state.user?.is_admin)) return;
  if (!confirmed && !settingsCanLeave(() => renderSettingsSection(section, true))) return;
  settingsClearSensitive();
  const generation = ++settingsState.generation;
  settingsState.page = section; settingsDirty(false); settingsBusy(false);
  const content = $("settings-content"), footer = $("settings-actions");
  content.innerHTML = ""; footer.innerHTML = "";
  $("settings-section-title").textContent = item.label;
  document.querySelectorAll("#settings-nav button").forEach((button) => {
    const selected = button.dataset.section === section;
    button.classList.toggle("active", selected); button.setAttribute("aria-current", selected ? "page" : "false");
    if (selected && typeof button.scrollIntoView === "function") button.scrollIntoView({ block: "nearest", inline: "nearest" });
  });
  const feedback = el("p", { id: "settings-feedback", class: "settings-feedback settings-footer-note", "aria-live": "polite" });
  const actions = el("div", { class: "settings-toolbar" });
  footer.appendChild(feedback); footer.appendChild(actions);
  const active = () => settingsState.opened && settingsState.generation === generation && settingsState.page === section;
  const context = {
    active, actions, root: content,
    setDirty: (value, message = "") => { if (active()) settingsDirty(value, message); },
    setBusy: (value) => { if (active()) settingsBusy(value); },
    feedback: (text, error = false) => { if (active()) settingsFeedback(text, error); },
    button: (text, callback, primary = false) => {
      const button = el("button", { class: primary ? "btn primary" : "btn", type: "button", text, onclick: async () => {
        if (!active() || settingsState.busy) return;
        button.disabled = true;
        try { await callback(button); } catch (_) { if (active()) settingsFeedback("请求未完成，请重试。", true); }
        finally { if (active()) button.disabled = false; }
      } });
      actions.appendChild(button); return button;
    },
  };
  content.appendChild(settingsDescription("正在加载…"));
  try {
    const renderers = { model: settingsModel, profile: settingsProfile, security: settingsSecurity, prompts: settingsPrompts, skills: settingsSkills, connections: settingsConnections, notifications: settingsNotifications, about: settingsAbout };
    await renderers[section](context);
  } catch (_) {
    if (active()) { content.innerHTML = ""; content.appendChild(settingsDescription("内容暂时无法加载，请重试。")); settingsFeedback("加载失败，请检查连接或重新登录。", true); }
  }
  if (active()) { content.scrollTop = 0; }
}
on("settings-close", "click", () => closeSettings());
on("settings-dialog", "click", (event) => { if (event.target === $("settings-dialog")) closeSettings(); });
on("notify-settings-open", "click", () => openSettings("notifications"));
window.addEventListener("beforeunload", (event) => {
  if (settingsState.opened && (settingsState.dirty || settingsState.busy)) { event.preventDefault(); event.returnValue = ""; }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && settingsState.opened) {
    if (!$("modal").classList.contains("hidden")) return;
    event.preventDefault(); closeSettings(); return;
  }
  if (event.key === "Escape") closeAccountMenu(true);
  if (event.key !== "Tab" || !settingsState.opened) return;
  const overlay = !$("modal").classList.contains("hidden") ? $("modal") : $("settings-dialog");
  const focusable = Array.from(overlay.querySelectorAll('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]')).filter((node) => node.getClientRects().length > 0 && !node.closest(".hidden"));
  if (!focusable.length) { event.preventDefault(); return; }
  const first = focusable[0], last = focusable[focusable.length - 1];
  if (event.shiftKey && (document.activeElement === first || !overlay.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && (document.activeElement === last || !overlay.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
});

async function settingsModel(context) {
  context.root.innerHTML = "";
  context.root.appendChild(settingsDescription("MiMoCode 用于事件调查与自治决策。这里显示当前生效的模型连接，密钥不会回填。"));
  const host = el("div", { id: "settings-model-host", class: "settings-section" }); context.root.appendChild(host);
  let primaryDirty = false, auxiliaryDirty = false;
  const markDirty = () => context.setDirty(primaryDirty || auxiliaryDirty);
  await openMimoAdmin(host, { ...context, setDirty: (value) => { primaryDirty = Boolean(value); markDirty(); } });
  if (!context.active()) return;
  const details = el("details", { class: "settings-detail" });
  details.appendChild(el("summary", { text: "表单辅助模型（可选）" }));
  details.appendChild(settingsDescription("用于“帮我填表”等辅助操作，与上方自治模型分别保存。修改这里不会切换自治调查模型。"));
  context.root.appendChild(details);
  const reply = await api("/api/settings/global"); if (!context.active() || !reply?.ok) return;
  const base = settingsInput("settings-assist-base", "url", reply.llm_base_url || "");
  const model = settingsInput("settings-assist-model", "text", reply.llm_model || "");
  const key = settingsInput("settings-assist-key", "password", "", { autocomplete: "new-password", placeholder: reply.llm_api_key_set ? "已保存，留空保留" : "API Key" });
  [base, model, key].forEach((input) => input.addEventListener("input", () => { auxiliaryDirty = true; markDirty(); }));
  details.appendChild(settingsField("接口地址", base)); details.appendChild(settingsField("模型", model)); details.appendChild(settingsField("API Key", key));
  const message = el("p", { class: "settings-description", "aria-live": "polite" });
  details.appendChild(el("button", { class: "btn", type: "button", text: "保存辅助配置", onclick: async () => {
    if (!context.active() || settingsState.busy) return;
    context.setBusy(true);
    try {
      const payload = { llm_base_url: base.value.trim(), llm_model: model.value.trim() }; if (key.value.trim()) payload.llm_api_key = key.value.trim();
      const result = await api("/api/settings/global", { method: "POST", body: JSON.stringify(payload) });
      if (!context.active()) return;
      message.textContent = result?.ok ? "辅助模型配置已保存；自治模型未变更。" : result?.message || "保存失败。";
      if (result?.ok) { key.value = ""; auxiliaryDirty = false; markDirty(); }
    } catch (_) { if (context.active()) message.textContent = "保存未完成，请重试。"; }
    finally { context.setBusy(false); }
  } }));
  details.appendChild(message);
  context.root.appendChild(el("details", { class: "settings-detail" }, [
    el("summary", { text: "Agent 工具连接" }),
    settingsDescription("Ayana 在模型会话启动时自动连接 MCP，并绑定当前事件数据库。每个会话按自身权限使用工具，无需在监控接入中另行配置。"),
  ]));
}

async function settingsProfile(context) {
  const reply = await api("/api/me"); if (!context.active()) return;
  if (!reply?.ok) throw new Error("auth_required");
  state.user = reply.user; if (reply.csrf_token) state.csrf = reply.csrf_token;
  context.root.innerHTML = "";
  const account = settingsCard("账号信息");
  account.appendChild(el("div", { class: "settings-row" }, [el("span", { text: "用户名" }), el("strong", { text: state.user.username || "" })]));
  account.appendChild(el("div", { class: "settings-row" }, [el("span", { text: "角色" }), el("span", { class: "settings-badge", text: state.user.is_admin ? "管理员" : "成员" })]));
  context.root.appendChild(account);
  const card = settingsCard("修改密码", "密码至少 10 位。修改成功后需要使用新密码重新登录。"), form = el("form", { class: "form-col" });
  const current = settingsInput("profile-current-password", "password", "", { autocomplete: "current-password", required: true });
  const password = settingsInput("profile-new-password", "password", "", { autocomplete: "new-password", minlength: 10, required: true });
  const confirm = settingsInput("profile-confirm-password", "password", "", { autocomplete: "new-password", minlength: 10, required: true });
  form.appendChild(settingsField("当前密码", current)); form.appendChild(settingsField("新密码", password)); form.appendChild(settingsField("确认新密码", confirm));
  [current, password, confirm].forEach((input) => input.addEventListener("input", () => context.setDirty(true)));
  card.appendChild(form); context.root.appendChild(card);
  const save = async () => {
    if (settingsState.busy || !context.active()) return;
    if (!current.value) { context.feedback("请输入当前密码。", true); return; }
    if (password.value.length < 10) { context.feedback("新密码至少 10 位。", true); return; }
    if (password.value !== confirm.value) { context.feedback("两次输入的新密码不一致。", true); return; }
    context.setBusy(true);
    try {
      const result = await api("/api/password", { method: "POST", body: JSON.stringify({ old_password: current.value, new_password: password.value, confirm_password: confirm.value }) });
      if (!context.active()) return;
      if (!result?.ok) { context.feedback(result?.message || "修改密码失败。", true); return; }
      current.value = password.value = confirm.value = "";
      closeSettings(true); state.user = null; state.csrf = ""; state.pendingLogin = null; showLogin();
      if ($("login-error")) $("login-error").textContent = "密码已修改，请使用新密码登录。";
    } finally { context.setBusy(false); }
  };
  form.addEventListener("submit", (event) => { event.preventDefault(); save().catch(() => context.feedback("请求未完成，请重试。", true)); });
  context.button("修改密码", save, true);
}

async function settingsSecurity(context) {
  const reply = await api("/api/me"); if (!context.active()) return;
  if (!reply?.ok) throw new Error("auth_required");
  state.user = reply.user; if (reply.csrf_token) state.csrf = reply.csrf_token;
  context.root.innerHTML = "";
  let enabled = Boolean(state.user.totp_enabled);
  const card = settingsCard("认证器验证", "使用认证器 App 扫描二维码，登录时输入每 30 秒更新的六位动态验证码（TOTP）。"), badgeNode = el("span", { class: "settings-badge", text: enabled ? "已启用" : "未启用" });
  card.appendChild(badgeNode);
  const password = settingsInput("security-password", "password", "", { autocomplete: "current-password" });
  const otp = settingsInput("security-otp", "text", "", { autocomplete: "one-time-code", inputmode: "numeric", maxlength: 6, placeholder: "6 位动态码" });
  card.appendChild(settingsField("当前密码", password, enabled ? "更换或关闭验证时必填。" : "首次绑定可留空。"));
  card.appendChild(settingsField("当前动态码", otp, "已启用双重验证时填写。"));
  [password, otp].forEach((input) => input.addEventListener("input", () => context.setDirty(true)));
  const setupArea = el("div", { id: "security-setup", class: "settings-section" });
  context.root.appendChild(card); context.root.appendChild(setupArea);
  const start = async () => {
    context.setBusy(true);
    try {
      const result = await api("/api/totp/setup", { method: "POST", body: JSON.stringify({ password: password.value, totp: otp.value.trim() }) });
      if (!context.active()) return;
      if (!result?.ok) { context.feedback(result?.message || "绑定未完成，请检查密码和验证码。", true); return; }
      setupArea.innerHTML = "";
      const setup = settingsCard("绑定认证器", "用认证器 App 扫码，随后输入新认证器生成的六位验证码。尚未确认前不会启用。"), qr = el("div", { class: "settings-qr" });
      try { qr.innerHTML = window.QR.toSvg(window.QR.encode(result.otpauth, 4), 4); }
      catch (_) { qr.textContent = "二维码暂时无法显示，可使用下方密钥手动添加。"; }
      setup.appendChild(qr);
      const secret = el("details", { class: "settings-detail" }, [el("summary", { text: "手动添加密钥" }), el("code", { text: result.secret || "" })]); setup.appendChild(secret);
      const code = settingsInput("security-confirm-code", "text", "", { inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code", placeholder: "新认证器的验证码" });
      setup.appendChild(settingsField("确认验证码", code));
      const confirm = el("button", { class: "btn primary", type: "button", text: "确认启用", onclick: async () => {
        if (!context.active() || settingsState.busy) return;
        if (!/^\d{6}$/.test(code.value.trim())) { context.feedback("请输入六位验证码。", true); return; }
        context.setBusy(true); confirm.disabled = true;
        try {
          const verified = await api("/api/totp/confirm", { method: "POST", body: JSON.stringify({ code: code.value.trim(), password: password.value }) });
          if (!context.active()) return;
          if (!verified?.ok) { context.feedback(verified?.message || "验证码未通过。", true); return; }
          if (verified.csrf_token) state.csrf = verified.csrf_token;
          enabled = true; state.user.totp_enabled = true; badgeNode.textContent = "已启用";
          password.value = otp.value = code.value = ""; setupArea.innerHTML = "";
          const recovery = settingsCard("保存恢复码", "认证器丢失时可使用恢复码登录，每个恢复码只能使用一次。恢复码仅显示这一次。"), codes = el("pre", { id: "security-recovery-codes", class: "settings-detail", text: (verified.recovery_codes || []).join("\n") });
          recovery.appendChild(codes);
          const acknowledged = settingsInput("security-recovery-saved", "checkbox");
          acknowledged.addEventListener("change", () => context.setDirty(!acknowledged.checked, "恢复码仅显示一次。请保存后再离开。"));
          recovery.appendChild(el("label", { class: "chk" }, [acknowledged, document.createTextNode("我已妥善保存恢复码")]));
          setupArea.appendChild(recovery); context.actions.innerHTML = ""; context.setDirty(true, "恢复码仅显示一次。请保存后再离开。");
          context.feedback("双重验证已启用，请保存恢复码。");
        } catch (_) { context.feedback("请求未完成，请重试。", true); }
        finally { context.setBusy(false); if (context.active()) confirm.disabled = false; }
      } });
      context.actions.innerHTML = ""; context.actions.appendChild(confirm); setupArea.appendChild(setup);
      context.setDirty(true, "认证器绑定尚未确认，离开后需重新开始绑定。"); context.feedback("请用新认证器完成确认。");
    } finally { context.setBusy(false); }
  };
  context.button(enabled ? "更换认证器" : "绑定认证器", start, true);
  if (enabled) {
    const disable = context.button("关闭双重验证", async () => {
      context.setBusy(true);
      try {
        const result = await api("/api/totp/disable", { method: "POST", body: JSON.stringify({ password: password.value, totp: otp.value.trim() }) });
        if (!context.active()) return;
        if (!result?.ok) { context.feedback(result?.message || "关闭失败，请检查密码和验证码。", true); return; }
        if (result.csrf_token) state.csrf = result.csrf_token;
        state.user.totp_enabled = false; password.value = otp.value = ""; context.setDirty(false);
        await renderSettingsSection("security", true); settingsFeedback("双重验证已关闭。");
      } finally { context.setBusy(false); }
    }); disable.classList.add("settings-danger");
  }
}

async function settingsPrompts(context) {
  const reply = await api("/api/settings/prompts"); if (!context.active()) return;
  if (!reply?.ok) throw new Error("prompts_unavailable");
  const items = reply.items || [], currentItem = items.find((item) => item.key === settingsState.promptKey) || items[0];
  context.root.innerHTML = "";
  context.root.appendChild(settingsDescription("编辑调查、处置提示词与运维软约束。保存后供下一次模型调用使用，当前已开始的调用保持原内容。执行权限与只读保护由系统独立控制。"));
  if (!currentItem) { context.root.appendChild(settingsDescription("暂无可编辑提示词。")); return; }
  settingsState.promptKey = currentItem.key;
  const tabs = el("div", { class: "settings-tabs", "aria-label": "提示词类型" });
  items.forEach((item) => tabs.appendChild(el("button", { class: "btn" + (item.key === currentItem.key ? " settings-selected" : ""), type: "button", text: item.label, onclick: () => {
    if (!settingsCanLeave(() => { settingsState.promptKey = item.key; renderSettingsSection("prompts", true); })) return;
    settingsState.promptKey = item.key; renderSettingsSection("prompts", true);
  } })));
  context.root.appendChild(tabs);
  const card = settingsCard(currentItem.label), current = currentItem.current || {};
  card.appendChild(el("p", { class: "settings-description", text: current.is_default || !current.id ? "当前使用系统默认版本" : `当前版本 v${current.version} · ${current.created_by || "管理员"}` }));
  const text = el("textarea", { id: "settings-prompt-text", class: "settings-prompt-editor", rows: 14, spellcheck: "false", text: current.text || "" }), note = settingsInput("settings-prompt-note", "text", "", { maxlength: 300, placeholder: "本次调整的用途" });
  [text, note].forEach((input) => input.addEventListener("input", () => context.setDirty(true)));
  card.appendChild(settingsField("内容", text)); card.appendChild(settingsField("变更说明", note)); context.root.appendChild(card);
  context.button("保存并生效", async () => {
    if (!text.value.trim()) { context.feedback("提示词内容不能为空。", true); return; }
    context.setBusy(true);
    try {
      const saved = await api("/api/settings/prompts", { method: "POST", body: JSON.stringify({ key: currentItem.key, text: text.value, change_note: note.value.trim() }) });
      if (!context.active()) return;
      if (!saved?.ok) { context.feedback(saved?.message || "保存失败。", true); return; }
      context.setDirty(false); await renderSettingsSection("prompts", true); settingsFeedback("已保存，下一次模型调用使用新版本。");
    } finally { context.setBusy(false); }
  }, true);
  const versions = settingsCard("历史版本", "恢复会创建新的生效版本，保留原有历史。"), select = el("select", { id: "settings-prompt-version" });
  select.appendChild(el("option", { value: "0", text: "系统默认版本" }));
  (currentItem.versions || []).forEach((version) => select.appendChild(el("option", { value: String(version.id), text: `v${version.version}${version.active ? " · 当前生效" : ""} · ${version.change_note || version.created_by || "历史版本"}` })));
  versions.appendChild(settingsField("恢复至", select));
  versions.appendChild(el("button", { class: "btn", type: "button", text: "恢复此版本", onclick: async () => {
    if (settingsState.busy || !context.active()) return;
    const restore = async () => {
      context.setBusy(true);
      try {
        const restored = await api("/api/settings/prompts/restore", { method: "POST", body: JSON.stringify({ key: currentItem.key, version_id: Number(select.value || 0) }) });
        if (!context.active()) return;
        if (!restored?.ok) { context.feedback(restored?.message || "恢复失败。", true); return; }
        context.setDirty(false); await renderSettingsSection("prompts", true); settingsFeedback("已恢复，下一次模型调用生效。");
      } catch (_) { context.feedback("恢复未完成，请重试。", true); }
      finally { context.setBusy(false); }
    };
    if (settingsCanLeave(restore)) await restore();
  } }));
  context.root.appendChild(versions);
}

async function settingsSkills(context) {
  const reply = await api("/api/settings/skills"); if (!context.active()) return;
  if (!reply?.ok) throw new Error("skills_unavailable");
  context.root.innerHTML = "";
  context.root.appendChild(settingsDescription(reply.message || "展示 MiMoCode 服务账户和当前运行目录中实际发现的技能。"));
  const items = reply.items || [], summary = settingsCard("技能列表", `已发现 ${items.length} 项。发现状态与实际会话加载状态分别展示。`);
  if (!items.length) summary.appendChild(el("div", { class: "settings-empty", text: "当前扫描位置未发现技能。" }));
  items.forEach((item) => {
    const card = el("article", { class: "settings-skill" });
    card.appendChild(el("h4", { text: item.name || item.id || "未命名技能" }));
    if (item.description) card.appendChild(settingsDescription(item.description));
    card.appendChild(el("span", { class: "settings-badge", text: item.loaded === true ? "已确认加载" : item.loaded === false ? "未加载" : "已发现 · 加载状态待确认" }));
    card.appendChild(el("details", { class: "settings-detail" }, [el("summary", { text: "来源与位置" }), el("p", { text: item.source || "MiMoCode" }), el("code", { text: item.path || "" })]));
    summary.appendChild(card);
  });
  context.root.appendChild(summary);
  const roots = el("details", { class: "settings-detail" }, [el("summary", { text: "查看扫描位置" })]);
  (reply.roots || []).forEach((root) => roots.appendChild(el("p", { class: "settings-description", text: `${root.source || ""} · ${root.exists ? "存在" : "未创建"} · ${root.path || ""}` })));
  context.root.appendChild(roots);
  context.button("刷新列表", () => renderSettingsSection("skills", true));
}

async function settingsConnections(context) {
  const reply = await api("/api/settings/global"); if (!context.active()) return;
  if (!reply?.ok) throw new Error("connections_unavailable");
  context.root.innerHTML = "";
  context.root.appendChild(settingsDescription("配置 Prometheus 与 Alertmanager，接入指标和告警。通知发送目标请在左侧「通知渠道」中管理。"));
  const card = settingsCard("监控接入"), prom = settingsInput("settings-prometheus-url", "url", reply.prometheus_url || ""), am = settingsInput("settings-alertmanager-url", "url", reply.alertmanager_url || "");
  card.appendChild(settingsField("Prometheus 地址", prom)); card.appendChild(settingsField("Alertmanager 地址", am));
  card.appendChild(el("p", { class: "settings-status", text: reply.prometheus_ok ? "Prometheus 连接正常" : reply.prometheus_error || "Prometheus 暂未连接，请检查服务状态和地址。" }));
  [prom, am].forEach((input) => input.addEventListener("input", () => context.setDirty(true)));
  context.root.appendChild(card);
  context.button("保存监控接入", async () => {
    context.setBusy(true);
    prom.disabled = true; am.disabled = true;
    try {
      const saved = await api("/api/settings/global", { method: "POST", body: JSON.stringify({ prometheus_url: prom.value.trim(), alertmanager_url: am.value.trim() }) });
      if (!context.active()) return;
      if (!saved?.ok) { context.feedback(saved?.message || "保存失败。", true); return; }
      context.setDirty(false);
      const refreshed = renderSettingsSection("connections", true), refreshedGeneration = settingsState.generation;
      await refreshed;
      if (settingsState.opened && settingsState.page === "connections" && settingsState.generation === refreshedGeneration) settingsFeedback("监控接入已保存。");
    } finally { prom.disabled = false; am.disabled = false; context.setBusy(false); }
  }, true);
  context.button("检测已保存地址", () => renderSettingsSection("connections"));
}

async function settingsNotifications(context) {
  context.root.innerHTML = "";
  context.root.appendChild(settingsDescription("管理告警与消息的发送目标。每个渠道分别保存；发送测试会向已配置的目标实际发送消息。"));
  const host = el("div", { class: "settings-notification-host" }); context.root.appendChild(host);
  host.appendChild(settingsDescription("正在加载通知渠道…"));
  const node = $("settings-notification-content");
  if (!node) throw new Error("notification_manager_unavailable");
  context.button("刷新渠道", () => renderSettingsSection("notifications"));
  try {
    if (typeof loadNotifyKinds === "function") await loadNotifyKinds();
    if (!context.active()) return;
    if (typeof fillNotifyMethods === "function") fillNotifyMethods();
    if (typeof toggleNotifyKind === "function") toggleNotifyKind();
    host.innerHTML = ""; host.appendChild(node);
    const edited = () => context.setDirty(true, "通知渠道还有未保存的输入，离开后草稿会被清除。");
    node.addEventListener("input", edited); node.addEventListener("change", edited);
    settingsState.notificationScope = {
      active: context.active, busy: context.setBusy,
      saved: () => context.setDirty(false),
      cleanup: () => { node.removeEventListener("input", edited); node.removeEventListener("change", edited); },
    };
    if (typeof loadAibotStatus === "function") await loadAibotStatus();
    if (!context.active()) return;
    if (typeof loadNotifyChannels === "function") await loadNotifyChannels({ active: context.active });
  } catch (_) {
    if (!context.active()) return;
    if (!host.contains(node)) {
      host.innerHTML = ""; host.appendChild(settingsDescription("通知渠道暂时无法加载，请刷新重试。"));
    }
    context.feedback("通知渠道暂时无法加载，请刷新重试。", true);
  }
}

async function settingsAbout(context) {
  const reply = await api("/api/settings/about"); if (!context.active()) return;
  if (!reply?.ok) throw new Error("about_unavailable");
  context.root.innerHTML = "";
  const card = settingsCard("Ayana", "事件驱动的运维工作台" );
  [["Ayana 版本", reply.ayana_version], ["MiMoCode 版本", reply.mimocode_version || "未检测到"]].forEach(([label, value]) => card.appendChild(el("div", { class: "settings-row" }, [el("span", { text: label }), el("strong", { text: value || "未知" })])));
  const project = reply.project_url === "https://github.com/wwqjss/Ayana" ? reply.project_url : "https://github.com/wwqjss/Ayana";
  card.appendChild(el("div", { class: "settings-row" }, [el("span", { text: "项目地址" }), el("a", { href: project, target: "_blank", rel: "noopener noreferrer", text: "GitHub · Ayana ↗" })]));
  const status = el("p", { id: "settings-update-result", class: "settings-description", "aria-live": "polite", text: "检查更新会查询项目发布版本。" }); card.appendChild(status);
  context.root.appendChild(card);
  if (state.user?.is_admin) context.button("检查更新", async () => {
    context.setBusy(true); status.textContent = "正在检查更新…";
    try {
      const checked = await api("/api/settings/updates/check", { method: "POST", body: "{}" }); if (!context.active()) return;
      status.textContent = checked?.message || (checked?.ok ? checked.update_available ? "发现新版本。" : "检查完成。" : "暂时无法检查更新，请稍后重试。");
      const release = checked?.release_url || checked?.url;
      if (checked?.ok && typeof release === "string" && release.startsWith("https://github.com/wwqjss/Ayana/releases/")) card.appendChild(el("a", { href: release, target: "_blank", rel: "noopener noreferrer", text: "查看更新说明 ↗" }));
    } finally { context.setBusy(false); }
  });
  if (state.user?.is_admin) {
    const history = el("details", { class: "settings-detail" }, [el("summary", { text: "旧自治历史" }), settingsDescription("旧 Council 已退役，历史费用记录仍可追溯。")]);
    const body = el("div"); history.appendChild(body); context.root.appendChild(history);
    history.addEventListener("toggle", async () => {
      if (!history.open || !context.active() || body.dataset.loaded) return;
      try {
        const usage = await api("/api/autonomy/usage"); if (!context.active()) return;
        body.textContent = usage?.ok ? JSON.stringify(usage.usage || {}, null, 2) : "历史记录暂时无法读取。";
        body.className = "settings-detail"; body.dataset.loaded = "true";
      } catch (_) { if (context.active()) body.textContent = "历史记录暂时无法读取。"; }
    });
  }
}

function settingsNotificationSaving(value) {
  const scope = settingsState.notificationScope;
  if (!scope || !scope.active()) return true;
  if (value && settingsState.busy) return false;
  scope.busy(value); return true;
}
function settingsNotificationSaved() {
  const scope = settingsState.notificationScope;
  if (scope && scope.active()) scope.saved();
}
