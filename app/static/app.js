const state = { token: localStorage.getItem("recovery_token") || "", accounts: [], tasks: [], reauthSession: null, profiles: [], activeProfileId: null, sync: { status: "never" }, lastUpdatedAt: null, busyActions: new Set() };
const $ = (selector) => document.querySelector(selector);
const DASHBOARD_REFRESH_MS = 10000;
const TASK_DETAIL_REFRESH_MS = 2000;
const TERMINAL_TASK_STATUSES = new Set(["succeeded", "failed", "skipped"]);
let dashboardRefreshTimer = null;
let dashboardLoadInFlight = null;
let taskDialogRefreshTimer = null;
let activeTaskId = "";

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
  stopTaskDialogRefresh();
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
  const text = { healthy: "正常", auth_failed: "认证失败", recovering: "恢复中", reauth_required: "等待授权", manual_required: "待授权", automation_blocked: "备注不完整", account_error: "账号异常", succeeded: "成功", failed: "失败", skipped: "已跳过", queued: "排队中", running: "执行中", retry_wait: "等待重试", observed: "需关注", unknown: "未知" }[value] || value || "未知";
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

const STAGE_LABELS = {
  scan: "扫描发现",
  probe: "状态检查",
  sync: "同步凭据",
  native_refresh: "原生刷新",
  refresh_token: "令牌刷新",
  automatic_reauthorization: "自动重新授权",
  reauthorization: "重新授权",
  apply_credentials: "写回凭据",
  status_check: "恢复后验证",
  recover_state: "恢复账号状态",
  retry_wait: "等待重试",
  automation_blocked: "自动化条件",
  succeeded: "已完成",
  recovery: "恢复处理",
};

const STATUS_LABELS = { queued: "排队中", running: "执行中", manual_required: "等待授权", succeeded: "成功", failed: "失败", skipped: "已跳过", retry_wait: "等待重试" };
const LOG_LEVEL_LABELS = { INFO: "记录", ERROR: "错误", WARNING: "警告" };
const TECHNICAL_LABELS = {
  status_code: "HTTP 状态码",
  error_code: "上游错误码",
  classification: "系统分类",
  operation: "执行操作",
  retryable: "可否重试",
  reauthorization_required: "需要重新授权",
  automation_stage: "自动化阶段",
  exception_type: "异常类型",
  backoff_seconds: "重试等待（秒）",
  raw_reason: "原始原因",
};

function stageLabel(value) {
  return STAGE_LABELS[value] || value || "处理过程";
}

function statusLabel(value) {
  return STATUS_LABELS[value] || value || "未知";
}

function humanizeLogMessage(log) {
  const message = String(log.message || "");
  const exact = {
    "Fetching the selected account's encrypted credential export": "正在读取所选账号的加密凭据。",
    "Requesting Sub2API native OAuth refresh": "正在尝试 Sub2API 原生刷新。",
    "Native refresh failed; trying local refresh": "原生刷新未成功，正在尝试本地刷新。",
    "Native refresh did not pass account status check": "原生刷新返回了结果，但账号状态检查未通过。",
    "Refreshing the OAuth token with rotation-safe handling": "正在刷新 OAuth 令牌。",
    "Applying OAuth credentials to the original Sub2API account": "正在把新凭据写回原账号。",
    "Clearing Sub2API error state and restoring schedulability": "正在清理错误状态并恢复账号可用性。",
    "Automated OAuth callback completed": "自动授权回调已完成。",
    "Starting automated OAuth browser recovery": "正在启动浏览器自动授权。",
    "OAuth authorization completed; queued credential application": "OAuth 授权已完成，凭据写回任务已排队。",
    "Account note does not contain complete automation credentials": "账号备注缺少自动登录所需信息，自动恢复已暂停。",
    "Refresh token is not usable; administrator action is required": "刷新令牌不可用，需要重新授权。",
  };
  if (exact[message]) return exact[message];
  if (message.startsWith("Account recovered successfully using ")) {
    return `账号恢复成功，使用方式：${message.slice("Account recovered successfully using ".length)}。`;
  }
  if (message.startsWith("Automatic reauthorization will retry")) return "遇到临时问题，已安排自动重新授权重试。";
  if (message.startsWith("Recovery will retry")) return "遇到临时问题，任务将按退避策略自动重试。";
  if (message.startsWith("Detected an OAuth authentication failure")) return "发现 OAuth 认证失败，已创建恢复任务。";
  if (message.startsWith("Account test detected an OAuth authentication failure")) return "状态检查发现 OAuth 认证失败，已创建恢复任务。";
  if (log.level === "ERROR") {
    const summaries = {
      native_refresh: "原生刷新未完成，系统正在尝试其他恢复方式。",
      refresh_token: "OAuth 令牌刷新未完成。",
      apply_credentials: "新凭据写回原账号未完成。",
      status_check: "恢复后的账号状态检查未通过。",
      recover_state: "账号状态恢复未完成。",
      automatic_reauthorization: "自动重新授权未完成。",
      reauthorization: "重新授权未完成。",
    };
    return summaries[log.stage] || "该步骤未完成，请查看技术详情。";
  }
  return message || "已记录一个处理事件。";
}

function taskErrorSummary(task) {
  if (!task.error_reason) return "-";
  if (task.status === "retry_wait") return "遇到临时问题，等待自动重试。";
  if (task.status === "manual_required" || task.stage === "reauthorization") return "需要重新授权。";
  if (task.status === "failed") return "任务未完成，请查看下方日志中的技术详情。";
  return "处理中，请查看下方日志。";
}

function technicalValue(key, value) {
  if (["retryable", "reauthorization_required", "success"].includes(key)) return value ? "是" : "否";
  return String(value);
}

function renderTechnicalDetails(log) {
  if (!log.detail || typeof log.detail !== "object") return "";
  const entries = Object.entries(log.detail).filter(([key, value]) => TECHNICAL_LABELS[key] && value !== null && value !== undefined && value !== "");
  if (!entries.length) return "";
  return `<details class="log-technical"><summary>查看技术详情</summary><dl>${entries.map(([key, value]) => `<div><dt>${escapeHtml(TECHNICAL_LABELS[key])}</dt><dd><code>${escapeHtml(technicalValue(key, value))}</code></dd></div>`).join("")}</dl></details>`;
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
  const grouped = new Map();
  state.tasks.forEach((task) => {
    const key = String(task.sub2api_account_id ?? task.email ?? task.username ?? task.id);
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, { task, count: 1 });
      return;
    }
    existing.count += 1;
    if (new Date(task.created_at).getTime() > new Date(existing.task.created_at).getTime()) existing.task = task;
  });
  const items = [...grouped.values()].filter(({ task }) => !search || [task.id, task.email, task.username, task.sub2api_account_id, task.status, task.stage, statusLabel(task.status), stageLabel(task.stage)].some((value) => String(value ?? "").toLowerCase().includes(search)));
  $("#tasks-empty").classList.toggle("hidden", items.length > 0);
  $("#tasks-empty").textContent = state.tasks.length && !items.length ? "没有匹配任务。" : "暂无恢复任务。";
  $("#tasks-body").innerHTML = items.map(({ task, count }) => `<tr>
    <td><code>${escapeHtml(task.id.slice(0, 8))}</code><div class="task-history">该账号 ${count} 次记录</div></td><td>${escapeHtml(task.email || task.username || task.sub2api_account_id)}</td><td>${escapeHtml(stageLabel(task.stage))}</td><td>${stateBadge(task.status)}</td><td>${escapeHtml(formatDate(task.created_at))}</td>
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

function renderTaskDetail(task) {
  $("#task-title").textContent = `任务 ${task.id.slice(0, 8)}`;
  $("#task-meta").innerHTML = `<span><strong>账号</strong>${escapeHtml(task.sub2api_account_id)}</span><span><strong>阶段</strong>${escapeHtml(stageLabel(task.stage))}</span><span><strong>状态</strong>${escapeHtml(statusLabel(task.status))}</span><span class="task-error"><strong>处理结果</strong>${escapeHtml(taskErrorSummary(task))}</span>`;
  const logs = $("#task-logs");
  const stickToBottom = logs.scrollHeight - logs.scrollTop - logs.clientHeight < 32;
  logs.innerHTML = (task.logs || []).map((log) => `<article class="log-line ${String(log.level || "").toLowerCase() === "error" ? "log-error" : ""}"><div class="log-top"><span class="log-stage">${escapeHtml(stageLabel(log.stage))}</span><span>${escapeHtml(formatDate(log.created_at))}</span><span>${escapeHtml(LOG_LEVEL_LABELS[log.level] || log.level || "记录")}</span></div><div class="log-message">${escapeHtml(humanizeLogMessage(log))}</div>${renderTechnicalDetails(log)}</article>`).join("") || `<div class="empty">暂无日志</div>`;
  if (stickToBottom) logs.scrollTop = logs.scrollHeight;
  $("#task-dialog-status").textContent = TERMINAL_TASK_STATUSES.has(task.status) ? "" : "自动更新中 · 每 2 秒检查";
}

function stopTaskDialogRefresh() {
  if (!taskDialogRefreshTimer) return;
  window.clearInterval(taskDialogRefreshTimer);
  taskDialogRefreshTimer = null;
}

function startTaskDialogRefresh(task) {
  stopTaskDialogRefresh();
  if (!activeTaskId || TERMINAL_TASK_STATUSES.has(task.status)) return;
  taskDialogRefreshTimer = window.setInterval(async () => {
    if (document.hidden || !state.token || !activeTaskId) return;
    try {
      const latest = await api(`/api/v1/tasks/${activeTaskId}`);
      renderTaskDetail(latest);
      if (TERMINAL_TASK_STATUSES.has(latest.status)) stopTaskDialogRefresh();
    } catch (_) {
      $("#task-dialog-status").textContent = "日志暂时无法更新";
    }
  }, TASK_DETAIL_REFRESH_MS);
}

async function openTask(taskId) {
  stopTaskDialogRefresh();
  activeTaskId = taskId;
  try {
    const task = await api(`/api/v1/tasks/${taskId}`);
    renderTaskDetail(task);
    $("#task-dialog").showModal();
    startTaskDialogRefresh(task);
  } catch (error) {
    activeTaskId = "";
    alert(error.message);
  }
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
$("#task-dialog").addEventListener("close", () => { activeTaskId = ""; stopTaskDialogRefresh(); });
$("#complete-auth").addEventListener("click", completeReauth);
$("#launch-browser").addEventListener("click", async () => { if (!state.reauthSession) return; try { await api(`/api/v1/accounts/${state.reauthSession.sub2api_account_id}/reauthorize`, { method: "POST", body: JSON.stringify({ launch_browser: true, session_id: state.reauthSession.id }) }); $("#reauth-status").textContent = "浏览器已启动，请完成验证。"; } catch (error) { $("#reauth-status").textContent = error.message; } });
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.token) {
    loadAll().catch(() => { $("#service-status").textContent = "连接失败"; });
    if (activeTaskId && $("#task-dialog").open) {
      api(`/api/v1/tasks/${activeTaskId}`).then(renderTaskDetail).catch(() => { $("#task-dialog-status").textContent = "日志暂时无法更新"; });
    }
  }
});

if (state.token) { setLoggedIn(true); loadAll().catch(() => logout()); } else { setLoggedIn(false); }
