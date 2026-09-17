const state = { token: localStorage.getItem("recovery_token") || "", accounts: [], tasks: [], reauthSession: null, profiles: [], activeProfileId: null, sync: { status: "never" }, lastUpdatedAt: null, busyActions: new Set() };
const $ = (selector) => document.querySelector(selector);
const DASHBOARD_REFRESH_MS = 10000;
let dashboardRefreshTimer = null;
let dashboardLoadInFlight = null;

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  let payload = {};
  try { payload = await response.json(); } catch (_) { payload = {}; }
  if (response.status === 401) { logout(); throw new Error("登录已过期"); }
  if (!response.ok) throw new Error(payload.detail || payload.message || "请求失败");
  return payload;
}

function setLoggedIn(value) {
  $("#login-view").classList.toggle("hidden", value);
  $("#app-view").classList.toggle("hidden", !value);
  if (value) startDashboardRefresh();
  else stopDashboardRefresh();
}

function logout() {
  state.token = "";
  localStorage.removeItem("recovery_token");
  setLoggedIn(false);
}

function startDashboardRefresh() {
  if (dashboardRefreshTimer) return;
  dashboardRefreshTimer = window.setInterval(async () => {
    if (!state.token || document.hidden) return;
    try {
      await loadAll();
    } catch (_) {
      $("#service-status").textContent = "连接失败";
    }
  }, DASHBOARD_REFRESH_MS);
}

function stopDashboardRefresh() {
  if (!dashboardRefreshTimer) return;
  window.clearInterval(dashboardRefreshTimer);
  dashboardRefreshTimer = null;
}

function stateBadge(value) {
  const text = { healthy: "正常", auth_failed: "认证失败", recovering: "恢复中", reauth_required: "等待授权", manual_required: "待授权", automation_blocked: "备注不完整", succeeded: "成功", failed: "失败", skipped: "已跳过", queued: "排队中", running: "执行中", retry_wait: "等待重试", observed: "已观察", unknown: "未知" }[value] || value || "未知";
  return `<span class="state ${escapeHtml(value || "unknown")}">${escapeHtml(text)}</span>`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderSync(sync) {
  state.sync = sync || { status: "never" };
  const labels = { never: "等待首次同步", queued: "扫描已排队", running: "正在同步账号", success: "同步正常", failed: "同步失败", busy: "已有扫描进行中" };
  let label = labels[state.sync.status] || "同步状态未知";
  if (state.sync.status === "success" && Number.isFinite(state.sync.found)) {
    label = `同步正常 · ${state.sync.found} 个账号`;
    if (state.sync.removed) label += ` · 隐藏 ${state.sync.removed} 个已删除账号`;
  }
  if (state.sync.status === "failed" && state.sync.reason) label += ` · ${state.sync.reason}`;
  $("#sync-status").textContent = label;
  $("#last-updated").textContent = state.lastUpdatedAt ? `页面更新 ${formatDate(state.lastUpdatedAt)}` : "页面更新时间 -";
}

function renderSettings(data) {
  state.profiles = data.profiles || [];
  state.activeProfileId = data.active_profile_id || null;
  renderProfiles();
  const groups = data.groups || [];
  $("#settings-groups").innerHTML = groups.map((group) => `<section class="settings-group">
    <div class="settings-group-heading"><h4>${escapeHtml(group.label)}</h4><span class="settings-group-count">${group.fields.length} 项</span></div>
    <div class="settings-fields">${(group.fields || []).map((field) => {
      const source = field.source === "dashboard" ? "Dashboard 覆盖" : ".env / 默认值";
      const sourceText = field.secret
        ? (field.configured ? "已配置，留空保持不变" : "未配置")
        : source;
      let control = "";
      if (field.type === "boolean") {
        const selectedTrue = field.value ? "selected" : "";
        const selectedFalse = field.value ? "" : "selected";
        control = `<select data-setting="${escapeHtml(field.key)}" data-type="boolean"><option value="true" ${selectedTrue}>启用</option><option value="false" ${selectedFalse}>停用</option></select>`;
      } else {
        const type = field.type === "secret" ? "password" : (field.type === "number" || field.type === "integer" ? "number" : "text");
        const step = field.step ? ` step="${escapeHtml(field.step)}"` : (field.type === "integer" ? ' step="1"' : "");
        const min = field.min !== undefined ? ` min="${escapeHtml(field.min)}"` : "";
        const max = field.max !== undefined ? ` max="${escapeHtml(field.max)}"` : "";
        const placeholder = field.secret && field.configured ? " placeholder=\"已配置，留空保持不变\"" : "";
        const value = field.secret ? "" : escapeHtml(field.value ?? "");
        control = `<input data-setting="${escapeHtml(field.key)}" data-type="${escapeHtml(field.type)}" type="${type}" value="${value}"${step}${min}${max}${placeholder} />`;
      }
      return `<div class="settings-field"><div class="setting-label">${escapeHtml(field.label)}</div>${control}<div class="setting-source"><span class="source-dot ${field.source === "dashboard" ? "dashboard" : "default"}"></span>${escapeHtml(sourceText)}</div></div>`;
    }).join("")}</div>
  </section>`).join("");
}

function renderProfiles() {
  const select = $("#profile-select");
  const selected = select.value;
  select.innerHTML = `<option value="">选择配置存档</option>${state.profiles.map((profile) => `<option value="${escapeHtml(profile.id)}" ${profile.id === state.activeProfileId ? "selected" : ""}>${profile.active ? "当前 · " : ""}${escapeHtml(profile.name)}</option>`).join("")}`;
  if (state.profiles.some((profile) => profile.id === selected)) select.value = selected;
  const profile = state.profiles.find((item) => item.id === select.value);
  $("#activate-profile").disabled = !profile || profile.id === state.activeProfileId;
  $("#delete-profile").disabled = !profile;
}

async function loadSettings() {
  const data = await api("/api/v1/settings");
  renderSettings(data);
  $("#settings-status").textContent = `配置版本 ${data.revision}`;
}

function collectSettings() {
  const values = {};
  document.querySelectorAll("[data-setting]").forEach((element) => {
    const key = element.dataset.setting;
    const type = element.dataset.type;
    if (type === "secret") {
      if (element.value.trim()) values[key] = element.value;
    } else if (type === "boolean") {
      values[key] = element.value === "true";
    } else if (type === "integer") {
      values[key] = Number.parseInt(element.value, 10);
    } else if (type === "number") {
      values[key] = Number.parseFloat(element.value);
    } else {
      values[key] = element.value;
    }
  });
  return values;
}

async function loadAll() {
  if (dashboardLoadInFlight) return dashboardLoadInFlight;
  dashboardLoadInFlight = (async () => {
    const [dashboard, accounts, tasks] = await Promise.all([api("/api/v1/dashboard"), api("/api/v1/accounts"), api("/api/v1/tasks?limit=80")]);
    state.accounts = accounts.items || [];
    state.tasks = tasks.items || [];
    renderMetrics(dashboard.summary || {});
    state.lastUpdatedAt = new Date().toISOString();
    renderSync(dashboard.sync || {});
    renderAccounts();
    renderTasks();
    $("#service-status").textContent = "已连接";
  })();
  try {
    return await dashboardLoadInFlight;
  } finally {
    dashboardLoadInFlight = null;
  }
}

function renderMetrics(summary) {
  const items = [["账号总数", summary.accounts || 0], ["401 / 待授权", summary.auth_failures || 0], ["恢复中", summary.recovering || 0], ["近 30 天成功", summary.success || 0], ["失败任务", summary.failed || 0]];
  $("#metrics").innerHTML = items.map(([label, value]) => `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value">${value}</div></div>`).join("");
}

function renderAccounts() {
  const filter = $("#account-filter").value;
  const search = $("#account-search").value.trim().toLowerCase();
  const items = state.accounts.filter((item) => {
    if (filter && item.status !== filter) return false;
    if (!search) return true;
    return [item.email, item.username, item.sub2api_account_id].some((value) => String(value ?? "").toLowerCase().includes(search));
  });
  $("#accounts-empty").classList.toggle("hidden", items.length > 0);
  $("#accounts-empty").textContent = state.accounts.length && !items.length ? "没有匹配账号。" : "还没有同步到 OpenAI OAuth 账号。";
  $("#accounts-body").innerHTML = items.map((account) => `<tr>
    <td><div class="account-name">${escapeHtml(account.email || account.username || "未命名账号")}</div><div class="account-sub">${escapeHtml(account.failure_reason || account.plan_type || "OpenAI OAuth")}</div></td>
    <td><code>${escapeHtml(account.sub2api_account_id)}</code></td>
    <td>${stateBadge(account.status)}</td>
    <td><span class="account-sub">${account.has_access_token ? "AT" : "-"} / ${account.has_refresh_token ? "RT" : "-"}</span></td>
    <td>${escapeHtml(formatDate(account.last_401_at))}</td>
    <td><div class="row-actions">${actionButton("recover", account.sub2api_account_id, "恢复")}${actionButton("reauth", account.sub2api_account_id, "重新授权")}${actionButton("test", account.sub2api_account_id, "检查状态")}</div></td>
  </tr>`).join("");
}

function renderTasks() {
  const search = $("#task-search").value.trim().toLowerCase();
  const items = state.tasks.filter((task) => !search || [task.id, task.email, task.username, task.sub2api_account_id, task.status, task.stage].some((value) => String(value ?? "").toLowerCase().includes(search)));
  $("#tasks-empty").classList.toggle("hidden", items.length > 0);
  $("#tasks-empty").textContent = state.tasks.length && !items.length ? "没有匹配任务。" : "暂无恢复任务。";
  $("#tasks-body").innerHTML = items.map((task) => `<tr>
    <td><code>${escapeHtml(task.id.slice(0, 8))}</code></td><td>${escapeHtml(task.email || task.username || task.sub2api_account_id)}</td><td>${escapeHtml(task.stage)}</td><td>${stateBadge(task.status)}</td><td>${escapeHtml(formatDate(task.created_at))}</td>
    <td><div class="row-actions">${actionButton("detail", task.id, "日志")}${["failed", "manual_required"].includes(task.status) ? actionButton("retry-task", task.id, "重试") : ""}</div></td>
  </tr>`).join("");
}

function actionButton(action, id, label) {
  const key = `${action}:${id}`;
  const busy = state.busyActions.has(key);
  return `<button class="mini-button" data-action="${escapeHtml(action)}" data-id="${escapeHtml(id)}"${busy ? " disabled" : ""}>${busy ? "处理中..." : label}</button>`;
}

async function handleAction(action, id) {
  const key = `${action}:${id}`;
  if (state.busyActions.has(key)) return;
  state.busyActions.add(key);
  renderAccounts();
  renderTasks();
  try {
    if (action === "recover") { await api(`/api/v1/accounts/${id}/recover`, { method: "POST" }); await loadAll(); }
    if (action === "test") { const result = await api(`/api/v1/accounts/${id}/status`, { method: "POST" }); alert(result.reason); await loadAll(); }
    if (action === "reauth") await openReauth(id);
    if (action === "detail") await openTask(id);
    if (action === "retry-task") { await api(`/api/v1/tasks/${id}/retry`, { method: "POST" }); await loadAll(); }
  } catch (error) { alert(error.message); }
  finally { state.busyActions.delete(key); renderAccounts(); renderTasks(); }
}

async function openReauth(accountId) {
  const session = await api(`/api/v1/accounts/${accountId}/reauthorize`, { method: "POST", body: JSON.stringify({ launch_browser: false }) });
  state.reauthSession = session;
  $("#auth-link").href = session.auth_url;
  $("#auth-link").textContent = session.auth_url;
  $("#callback-url").value = "";
  $("#reauth-status").textContent = `任务 ${session.task_id.slice(0, 8)} 已建立，授权链接有效至 ${formatDate(session.expires_at)}。`;
  $("#reauth-dialog").showModal();
}

async function completeReauth() {
  if (!state.reauthSession) return;
  const callbackUrl = $("#callback-url").value.trim();
  if (!callbackUrl) { $("#reauth-status").textContent = "请粘贴浏览器回调地址。"; return; }
  try {
    await api(`/api/v1/oauth/sessions/${state.reauthSession.id}/complete`, { method: "POST", body: JSON.stringify({ callback_url: callbackUrl }) });
    $("#reauth-status").textContent = "授权已接收，恢复任务已重新排队。";
    await loadAll();
  } catch (error) { $("#reauth-status").textContent = error.message; }
}

async function openTask(taskId) {
  try {
    const task = await api(`/api/v1/tasks/${taskId}`);
    $("#task-title").textContent = `任务 ${task.id.slice(0, 8)}`;
    $("#task-meta").innerHTML = `<span>账号 ${escapeHtml(task.sub2api_account_id)}</span><span>阶段 ${escapeHtml(task.stage)}</span><span>状态 ${escapeHtml(task.status)}</span><span>错误 ${escapeHtml(task.error_reason || "-")}</span>`;
    $("#task-logs").innerHTML = (task.logs || []).map((log) => `<div class="log-line"><div class="log-top">${escapeHtml(formatDate(log.created_at))} · ${escapeHtml(log.stage)}</div><div class="log-message">${escapeHtml(log.message)}</div></div>`).join("") || `<div class="empty">暂无日志</div>`;
    $("#task-dialog").showModal();
  } catch (error) { alert(error.message); }
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    const result = await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username: $("#login-username").value, password: $("#login-password").value }) });
    state.token = result.access_token;
    localStorage.setItem("recovery_token", state.token);
    setLoggedIn(true);
    await loadAll();
  } catch (error) { $("#login-error").textContent = error.message; }
});

$("#logout-button").addEventListener("click", logout);
$("#refresh-button").addEventListener("click", async () => {
  const button = $("#refresh-button");
  button.disabled = true;
  button.textContent = "更新中...";
  try { await loadAll(); } catch (error) { alert(error.message); }
  finally { button.disabled = false; button.textContent = "刷新"; }
});
$("#settings-button").addEventListener("click", async () => {
  $("#settings-section").classList.remove("hidden");
  try { await loadSettings(); $("#settings-section").scrollIntoView({ behavior: "smooth", block: "start" }); } catch (error) { alert(error.message); }
});
$("#close-settings").addEventListener("click", () => $("#settings-section").classList.add("hidden"));
$("#settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#settings-status").textContent = "保存中...";
  try {
    const result = await api("/api/v1/settings", { method: "PUT", body: JSON.stringify({ values: collectSettings() }) });
    renderSettings(result);
    $("#settings-status").textContent = `已保存，配置版本 ${result.revision}`;
  } catch (error) { $("#settings-status").textContent = error.message; }
});
$("#profile-select").addEventListener("change", renderProfiles);
$("#save-profile").addEventListener("click", () => {
  $("#profile-name").value = "";
  $("#profile-dialog-status").textContent = "";
  $("#profile-dialog").showModal();
  $("#profile-name").focus();
});
$("#cancel-profile").addEventListener("click", () => $("#profile-dialog").close("cancel"));
$("#profile-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = $("#profile-name").value.trim();
  if (!name) { $("#profile-dialog-status").textContent = "请输入存档名称。"; return; }
  try {
    const result = await api("/api/v1/settings/profiles", { method: "POST", body: JSON.stringify({ name }) });
    $("#profile-dialog").close();
    renderSettings(result);
    $("#profile-status").textContent = `已保存存档“${name}”`;
  } catch (error) { $("#profile-dialog-status").textContent = error.message; }
});
$("#activate-profile").addEventListener("click", async () => {
  const profileId = $("#profile-select").value;
  const profile = state.profiles.find((item) => item.id === profileId);
  if (!profile || !window.confirm(`切换到配置存档“${profile.name}”？`)) return;
  try {
    const result = await api(`/api/v1/settings/profiles/${encodeURIComponent(profileId)}/activate`, { method: "POST" });
    renderSettings(result);
    $("#profile-status").textContent = `已切换到“${profile.name}”`;
  } catch (error) { $("#profile-status").textContent = error.message; }
});
$("#delete-profile").addEventListener("click", async () => {
  const profileId = $("#profile-select").value;
  const profile = state.profiles.find((item) => item.id === profileId);
  if (!profile || !window.confirm(`删除配置存档“${profile.name}”？`)) return;
  try {
    const result = await api(`/api/v1/settings/profiles/${encodeURIComponent(profileId)}`, { method: "DELETE" });
    renderSettings(result);
    $("#profile-status").textContent = `已删除“${profile.name}”`;
  } catch (error) { $("#profile-status").textContent = error.message; }
});
$("#reset-settings").addEventListener("click", async () => {
  if (!window.confirm("清除 Dashboard 覆盖值并恢复 .env / 默认配置？")) return;
  try {
    const result = await api("/api/v1/settings", { method: "DELETE" });
    renderSettings(result);
    $("#settings-status").textContent = `已恢复，配置版本 ${result.revision}`;
  } catch (error) { $("#settings-status").textContent = error.message; }
});
$("#scan-button").addEventListener("click", async () => {
  const button = $("#scan-button");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "扫描中...";
  try {
    await api("/api/v1/scan", { method: "POST" });
    $("#service-status").textContent = "扫描已排队";
    await loadAll();
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline && ["queued", "running"].includes(state.sync.status)) {
      await new Promise((resolve) => window.setTimeout(resolve, 1000));
      await loadAll();
    }
    $("#service-status").textContent = state.sync.status === "failed" ? "扫描失败" : (state.sync.status === "success" ? "扫描完成" : (state.sync.status === "busy" ? "已有扫描进行中" : "扫描仍在后台运行"));
  } catch (error) { alert(error.message); }
  finally { button.disabled = false; button.textContent = "立即扫描"; }
});
$("#account-search").addEventListener("input", renderAccounts);
$("#account-filter").addEventListener("change", renderAccounts);
$("#task-search").addEventListener("input", renderTasks);
$("#accounts-body").addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) handleAction(button.dataset.action, button.dataset.id); });
$("#tasks-body").addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) handleAction(button.dataset.action, button.dataset.id); });
$("#complete-auth").addEventListener("click", completeReauth);
$("#launch-browser").addEventListener("click", async () => { if (!state.reauthSession) return; try { await api(`/api/v1/accounts/${state.reauthSession.sub2api_account_id}/reauthorize`, { method: "POST", body: JSON.stringify({ launch_browser: true, session_id: state.reauthSession.id }) }); $("#reauth-status").textContent = "浏览器已启动，请完成验证。"; } catch (error) { $("#reauth-status").textContent = error.message; } });
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.token) loadAll().catch(() => { $("#service-status").textContent = "连接失败"; });
});

if (state.token) { setLoggedIn(true); loadAll().catch(() => logout()); } else { setLoggedIn(false); }
