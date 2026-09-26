const savedTheme = localStorage.getItem("recovery_theme") === "dark" ? "dark" : "light";
document.documentElement.dataset.theme = savedTheme;
const state = { token: localStorage.getItem("recovery_token") || "", accounts: [], tasks: [], reauthSession: null, materialsAccountId: "", accountEnrollmentId: localStorage.getItem("recovery_account_enrollment") || "", accountEnrollmentTimer: null, profiles: [], activeProfileId: null, sync: { status: "never" }, lastUpdatedAt: null, busyActions: new Set(), accountSort: { key: "id", direction: "asc" }, selectedAccountId: "", selectedTask: null, activeView: localStorage.getItem("recovery_view") || "console" };
const $ = (selector) => document.querySelector(selector);
const DASHBOARD_REFRESH_MS = 10000;
const TASK_DETAIL_REFRESH_MS = 2000;
const TERMINAL_TASK_STATUSES = new Set(["succeeded", "failed", "skipped"]);
const RECOVERY_FLOW = [
  { key: "detect", label: "确认认证异常", stages: ["scan", "probe"], description: "读取 Sub2API 返回的账号状态，确认是否需要恢复。" },
  { key: "credentials", label: "读取账号材料", stages: ["sync"], description: "读取备注和加密凭据，敏感值不会显示在页面。" },
  { key: "native_refresh", label: "尝试原生刷新", stages: ["native_refresh"], description: "优先调用 Sub2API 原生 OAuth 刷新。" },
  { key: "refresh_token", label: "刷新 OAuth 令牌", stages: ["refresh_token"], description: "原生刷新未完成时，使用本地刷新令牌继续恢复。" },
  { key: "browser", label: "执行 OAuth 浏览器流程", stages: ["browser", "automatic_reauthorization", "automation_blocked", "security_challenge", "cloudflare_challenge", "oauth_flow", "email", "openai_password", "email_code", "totp", "account_disabled"], description: "按真实页面要求处理账号登录、邮箱验证码和验证器代码。" },
  { key: "callback", label: "接收回调并建立会话", stages: ["callback", "token_exchange", "reauthorization"], description: "校验 OAuth 回调和 PKCE 后交换会话令牌。" },
  { key: "apply", label: "写回原账号凭据", stages: ["apply_credentials"], description: "将新 OAuth 凭据写回原 Sub2API 账号 ID。" },
  { key: "verify", label: "恢复并验证状态", stages: ["status_check", "recover_state", "succeeded"], description: "清理错误状态，恢复可调度性并再次检查账号。" },
];
let dashboardRefreshTimer = null;
let dashboardLoadInFlight = null;
let taskDialogRefreshTimer = null;
let selectedTaskRefreshTimer = null;
let selectedTaskRequest = 0;
let activeTaskId = "";

function renderThemeControl(theme) {
  const dark = theme === "dark";
  const toggle = $("#theme-toggle");
  toggle.setAttribute("aria-pressed", String(dark));
  toggle.setAttribute("aria-label", dark ? "切换日间模式" : "切换夜间模式");
  toggle.title = dark ? "切换日间模式" : "切换夜间模式";
  $("#theme-icon").textContent = dark ? "☀" : "☾";
  $("#theme-label").textContent = dark ? "日间" : "夜间";
}

function setTheme(theme) {
  const nextTheme = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = nextTheme;
  localStorage.setItem("recovery_theme", nextTheme);
  renderThemeControl(nextTheme);
}

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
  if (value) {
    startDashboardRefresh();
    if (state.accountEnrollmentId) startAccountEnrollmentPolling();
  } else {
    stopDashboardRefresh();
    stopAccountEnrollmentPolling();
  }
}

function logout() {
  state.token = "";
  localStorage.removeItem("recovery_token");
  stopTaskDialogRefresh();
  stopSelectedTaskRefresh();
  stopAccountEnrollmentPolling();
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
  const text = { healthy: "正常", auth_failed: "认证失败", recovering: "恢复中", reauth_required: "等待授权", manual_required: "待授权", automation_blocked: "材料不足", account_error: "账号异常", account_disabled: "账号已删除或停用", succeeded: "成功", failed: "失败", skipped: "已跳过", queued: "排队中", running: "执行中", retry_wait: "等待重试", observed: "需关注", unknown: "未知" }[value] || value || "未知";
  return `<span class="state ${escapeHtml(value || "unknown")}">${escapeHtml(text)}</span>`;
}

function materialStatusText(account) {
  const count = Number(account.automation_configured_count || 0);
  const total = Number(account.automation_total || 4);
  if (!account.automation_materials_checked) return "未检查";
  if (account.automation_complete) return `${count}/${total} 完整`;
  if (account.automation_ready) return `${count}/${total} 可尝试`;
  return `${count}/${total} 缺少必填`;
}

function materialStatus(account) {
  if (!account.automation_materials_checked) {
    return '<span class="material-status unverified" title="尚未读取账号备注或录入自动登录材料">未检查</span>';
  }
  const kind = account.automation_complete ? "complete" : (account.automation_ready ? "partial" : "missing");
  const missing = (account.automation_missing || []).join("、");
  const title = missing ? `缺少：${missing}` : "四项自动登录材料已配置";
  return `<span class="material-status ${kind}" title="${escapeHtml(title)}">${escapeHtml(materialStatusText(account))}</span>`;
}

function accountStatusLabel(value) {
  return { healthy: "正常", auth_failed: "认证失败", recovering: "恢复中", reauth_required: "等待授权", manual_required: "待授权", automation_blocked: "材料不足", account_error: "账号异常", account_disabled: "账号已删除或停用", observed: "需关注", unknown: "未知" }[value] || value || "未知";
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
  browser: "启动浏览器",
  security_challenge: "安全挑战",
  cloudflare_challenge: "安全挑战",
  email: "提交账号邮箱",
  openai_password: "提交 OpenAI 密码",
  email_code: "获取邮箱验证码",
  totp: "提交验证器代码",
  account_disabled: "OpenAI 账号已删除或停用",
  credentials: "准备自动登录材料",
  oauth_flow: "OAuth 页面交互",
  callback: "接收 OAuth 回调",
  token_exchange: "交换 OAuth 会话",
  identity_check: "确认账号身份",
  duplicate_check: "检查账号重复",
  create_account: "创建 Sub2API 账号",
  completed: "已完成",
  starting: "准备开始",
  recovered_after_restart: "服务重启后重新排队",
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
const ACCOUNT_SORT_LABELS = { account: "账号", id: "Sub2API ID", status: "状态", materials: "自动登录材料", credentials: "凭据", last_401: "最近 401" };
const ACCOUNT_STATUS_ORDER = { account_disabled: 0, account_error: 1, auth_failed: 2, reauth_required: 3, automation_blocked: 4, recovering: 5, observed: 6, healthy: 7, unknown: 99 };
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

function accountSortValue(account, key) {
  if (key === "account") return String(account.email || account.username || "").trim().toLowerCase() || null;
  if (key === "id") {
    const value = Number(account.sub2api_account_id);
    return Number.isFinite(value) ? value : null;
  }
  if (key === "status") return ACCOUNT_STATUS_ORDER[account.status] ?? 99;
  if (key === "materials") return Number(account.automation_configured_count || 0);
  if (key === "credentials") return (account.has_access_token ? 2 : 0) + (account.has_refresh_token ? 1 : 0);
  if (key === "last_401") {
    if (!account.last_401_at) return null;
    const value = new Date(account.last_401_at).getTime();
    return Number.isFinite(value) ? value : null;
  }
  return null;
}

function compareAccountValues(left, right, key, direction = "asc") {
  const a = accountSortValue(left, key);
  const b = accountSortValue(right, key);
  const aMissing = a === null || a === "";
  const bMissing = b === null || b === "";
  if (aMissing || bMissing) {
    if (aMissing && bMissing) return 0;
    return aMissing ? 1 : -1;
  }
  const result = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b), "zh-CN");
  return direction === "desc" ? -result : result;
}

function accountSortHeader(key, label) {
  const active = state.accountSort.key === key;
  const direction = active ? state.accountSort.direction : "asc";
  const indicator = active ? (direction === "asc" ? "↑" : "↓") : "↕";
  const sortLabel = active ? `${label}，当前${direction === "asc" ? "升序" : "降序"}` : `按${label}排序`;
  return `<th aria-sort="${active ? (direction === "asc" ? "ascending" : "descending") : "none"}"><button class="table-sort" type="button" data-account-sort="${key}" aria-label="${sortLabel}" aria-pressed="${active}">${label}<span class="sort-indicator" aria-hidden="true">${indicator}</span></button></th>`;
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
    "Opening the OpenAI authorization page": "正在打开 OpenAI 授权页面。",
    "OpenAI authorization page loaded": "OpenAI 授权页面已打开。",
    "Submitting the account email": "正在提交账号邮箱。",
    "Submitting the OpenAI account password": "正在提交 OpenAI 账号密码。",
    "Waiting for the email verification code": "正在等待邮箱验证码。",
    "Reading the verification code from the mailbox": "正在读取邮箱验证码。",
    "IMAP did not return a code; trying Outlook webmail": "IMAP 未返回验证码，正在尝试网页邮箱。",
    "Email verification code received and submitted": "已取得邮箱验证码并提交。",
    "Generating and submitting the authenticator code": "正在生成并提交验证器代码。",
    "Submitting the OAuth consent or continue step": "正在提交 OAuth 同意或继续步骤。",
    "Waiting for the OAuth callback": "正在等待 OAuth 回调。",
    "OAuth callback received": "已收到 OAuth 回调。",
    "OAuth callback received; exchanging the authorization code": "已收到 OAuth 回调，正在交换授权码。",
    "Waiting for the OpenAI security challenge": "登录页要求安全验证，正在等待验证完成。",
    "Security challenge cleared": "安全验证已完成，继续登录。",
    "OAuth security challenge did not clear before timeout": "安全验证未能在等待时间内完成。",
    "OAuth page requires a security challenge that automation cannot complete": "登录页出现当前自动流程无法完成的安全验证。",
    "OAuth session received and encrypted credentials stored": "已建立 OAuth 会话并加密保存凭据。",
    "OAuth authorization completed; queued credential application": "OAuth 授权已完成，凭据写回任务已排队。",
    "Account note does not contain complete automation credentials": "账号备注缺少自动登录所需信息，自动恢复已暂停。",
    "2FA secret is not configured for this account": "该账号没有配置 2FA 密钥，流程在 2FA 步骤停止。",
    "email mailbox password is not configured for this account": "该账号没有配置邮箱密码，流程在邮箱验证码步骤停止。",
    "Refresh token is not usable; administrator action is required": "刷新令牌不可用，需要重新授权。",
    "Your refresh token has been invalidated. Please try signing in again.": "刷新令牌已失效，需要重新登录 OpenAI。",
  };
  if (exact[message]) return exact[message];
  if (message.startsWith("Account recovered successfully using ")) {
    return `账号恢复成功，使用方式：${message.slice("Account recovered successfully using ".length)}。`;
  }
  if (message.startsWith("Automatic authorization requires: ")) {
    return `自动授权未启动，缺少：${message.slice("Automatic authorization requires: ".length)}。`;
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
      browser: "浏览器自动化未完成。",
      email: "账号邮箱未通过。",
      openai_password: "OpenAI 密码未通过。",
      email_code: "邮箱验证码未获取。",
      totp: "验证器代码未通过。",
      security_challenge: "安全验证未完成。",
      cloudflare_challenge: "安全验证未完成。",
      callback: "OAuth 回调未收到。",
      token_exchange: "OAuth 会话交换未完成。",
    };
    return summaries[log.stage] || "该步骤未完成，请查看技术详情。";
  }
  return message || "已记录一个处理事件。";
}

function humanizeEnrollmentMessage(message, stage = "") {
  const value = String(message || "");
  if (value.startsWith("mailbox code retrieval failed:")) return `无法读取邮箱验证码：${value.slice("mailbox code retrieval failed:".length).trim()}`;
  if (value === "OpenAI password was rejected") return "OpenAI 密码被拒绝，请核对填写的密码。";
  if (value === "account email was rejected") return "登录邮箱被拒绝，请核对填写的邮箱。";
  if (value === "email mailbox password is not configured for this account") return "登录流程要求邮箱验证码，但没有填写邮箱密码。";
  if (value === "2FA secret is not configured for this account") return "登录流程要求 2FA 验证，但没有填写 2FA 密钥。";
  return humanizeLogMessage({ message: value, stage, level: "INFO" });
}

function taskErrorSummary(task) {
  if (!task.error_reason) return "-";
  if (task.status === "retry_wait") return "遇到临时问题，等待自动重试。";
  if (task.status === "manual_required" || task.stage === "reauthorization") return "需要重新授权。";
  if (task.status === "skipped" && task.stage === "automation_blocked") return "自动恢复未执行：缺少启动自动授权所需材料。";
  if (task.status === "skipped") return "任务已跳过：" + task.error_reason;
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
  const syncStatus = $("#sync-status");
  if (syncStatus) syncStatus.textContent = label;
  $("#sidebar-sync").textContent = label;
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
    ensureSelectedAccount();
    renderMetrics(dashboard.summary || {});
    state.lastUpdatedAt = new Date().toISOString();
    renderSync(dashboard.sync || {});
    renderConsole();
    renderAccounts();
    renderTasks();
    const latestSelectedTask = latestTaskForAccount(state.selectedAccountId);
    const selectedTaskChanged = latestSelectedTask && (!state.selectedTask || String(state.selectedTask.id) !== String(latestSelectedTask.id));
    const selectedTaskRemoved = !latestSelectedTask && state.selectedTask;
    if (selectedTaskChanged || selectedTaskRemoved) await loadSelectedTask();
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

function accountName(account) {
  return account.email || account.username || "未命名账号";
}

function accountPriority(account) {
  const priority = { account_disabled: 0, account_error: 1, auth_failed: 2, reauth_required: 3, automation_blocked: 4, recovering: 5, observed: 6, healthy: 7, unknown: 99 };
  return priority[account.status] ?? 99;
}

function ensureSelectedAccount() {
  if (state.accounts.some((account) => String(account.sub2api_account_id) === String(state.selectedAccountId))) return;
  const candidates = [...state.accounts].sort((left, right) => accountPriority(left) - accountPriority(right) || Number(left.sub2api_account_id) - Number(right.sub2api_account_id));
  state.selectedAccountId = candidates.length ? String(candidates[0].sub2api_account_id) : "";
}

function latestTaskForAccount(accountId) {
  return state.tasks
    .filter((task) => String(task.sub2api_account_id) === String(accountId))
    .sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime())[0] || null;
}

function renderConsoleAccounts() {
  const search = $("#console-account-search").value.trim().toLowerCase();
  const filter = $("#console-account-filter").value;
  const items = state.accounts
    .filter((account) => {
      if (filter && account.status !== filter) return false;
      if (!search) return true;
      return [account.email, account.username, account.sub2api_account_id].some((value) => String(value ?? "").toLowerCase().includes(search));
    })
    .sort((left, right) => accountPriority(left) - accountPriority(right) || Number(left.sub2api_account_id) - Number(right.sub2api_account_id));
  $("#console-account-count").textContent = `${items.length}/${state.accounts.length}`;
  $("#console-accounts-empty").classList.toggle("hidden", items.length > 0);
  const list = $("#console-account-list");
  const scrollTop = list.scrollTop;
  list.innerHTML = items.map((account) => {
    const accountId = String(account.sub2api_account_id);
    const selected = accountId === String(state.selectedAccountId);
    const task = latestTaskForAccount(accountId);
    const secondary = account.failure_reason || account.plan_type || "OpenAI OAuth";
    return `<button class="console-account ${selected ? "selected" : ""}" type="button" data-select-account="${escapeHtml(accountId)}" aria-pressed="${selected}"><span class="console-account-copy"><strong>${escapeHtml(accountName(account))}</strong><span>${escapeHtml(secondary)}</span></span><span class="console-account-side"><span class="console-account-side-top"><code>#${escapeHtml(accountId)}</code>${task ? `<small>${escapeHtml(stageLabel(task.stage))}</small>` : ""}</span><span class="console-account-side-bottom">${materialStatus(account)}${stateBadge(account.status)}</span></span></button>`;
  }).join("");
  list.scrollTop = scrollTop;
}

function timelineStageIndex(task) {
  if (!task) return -1;
  const direct = RECOVERY_FLOW.findIndex((step) => step.stages.includes(task.stage));
  if (direct >= 0) return direct;
  if (task.stage === "reauthorization") return RECOVERY_FLOW.findIndex((step) => step.key === "browser");
  const logs = task.logs || [];
  for (let index = logs.length - 1; index >= 0; index -= 1) {
    const logIndex = RECOVERY_FLOW.findIndex((step) => step.stages.includes(logs[index].stage));
    if (logIndex >= 0) return logIndex;
  }
  return ["queued", "running", "retry_wait"].includes(task.status) ? 0 : -1;
}

function timelineStepStatus(step, index, task) {
  if (!task) return "pending";
  const relevantLogs = (task.logs || []).filter((log) => step.stages.includes(log.stage));
  if (relevantLogs.some((log) => log.stage === "automation_blocked")) return "blocked";
  const error = relevantLogs.some((log) => String(log.level || "").toUpperCase() === "ERROR");
  if (error) return "error";
  const currentIndex = timelineStageIndex(task);
  if (currentIndex === index) {
    if (task.status === "succeeded") return "done";
    if (task.status === "failed") return "error";
    if (task.status === "skipped") return "skipped";
    return "running";
  }
  if (currentIndex > index) return relevantLogs.length ? "done" : "skipped";
  if (task.status === "succeeded") return relevantLogs.length ? "done" : "skipped";
  return "pending";
}

function timelineStepDescription(step, status, task) {
  const logs = (task?.logs || []).filter((log) => step.stages.includes(log.stage));
  const latest = logs[logs.length - 1];
  if (latest) return humanizeLogMessage(latest);
  if (status === "skipped") return "该路径未执行，前置步骤已决定使用其他恢复方式。";
  if (status === "error") return taskErrorSummary(task);
  if (status === "running" && task?.status === "manual_required") return "等待管理员完成授权。";
  return step.description;
}

function renderRecoveryTimeline(task) {
  const markers = { done: "✓", running: "…", pending: "", skipped: "–", error: "!", blocked: "!" };
  $("#recovery-timeline").innerHTML = RECOVERY_FLOW.map((step, index) => {
    const status = timelineStepStatus(step, index, task);
    const statusLabelText = { done: "已完成", running: task?.status === "manual_required" && index === timelineStageIndex(task) ? "等待授权" : "处理中", pending: "待执行", skipped: "未需要", error: "出错", blocked: "已阻止" }[status];
    return `<li class="timeline-step ${status}"><span class="timeline-marker" aria-hidden="true">${markers[status]}</span><div class="timeline-copy"><div class="timeline-title"><strong>${escapeHtml(step.label)}</strong><span>${statusLabelText}</span></div><p>${escapeHtml(timelineStepDescription(step, status, task))}</p></div></li>`;
  }).join("");
}

function renderRecoveryLogPreview(task) {
  const logs = (task?.logs || []).slice(-5).reverse();
  if (!logs.length) {
    $("#recovery-log-preview").innerHTML = `<div class="preview-empty">${task ? "任务已建立，等待第一条处理记录。" : "该账号还没有恢复记录。"}</div>`;
    return;
  }
  $("#recovery-log-preview").innerHTML = logs.map((log) => `<article class="preview-log ${String(log.level || "").toLowerCase() === "error" ? "log-error" : ""}"><div class="log-top"><span class="log-stage">${escapeHtml(stageLabel(log.stage))}</span><span>${escapeHtml(formatDate(log.created_at))}</span></div><div class="log-message">${escapeHtml(humanizeLogMessage(log))}</div>${renderTechnicalDetails(log)}</article>`).join("");
}

function renderRecoveryInspector() {
  const account = state.accounts.find((item) => String(item.sub2api_account_id) === String(state.selectedAccountId));
  const inspector = $("#recovery-inspector");
  const empty = $("#recovery-empty");
  if (!account) {
    inspector.classList.add("hidden");
    empty.classList.remove("hidden");
    $("#open-selected-logs").disabled = true;
    $("#recovery-alert").className = "inspector-alert hidden";
    $("#recovery-alert").textContent = "";
    return;
  }
  inspector.classList.remove("hidden");
  empty.classList.add("hidden");
  const task = state.selectedTask && String(state.selectedTask.sub2api_account_id) === String(account.sub2api_account_id) ? state.selectedTask : latestTaskForAccount(account.sub2api_account_id);
  $("#recovery-account-name").textContent = accountName(account);
  $("#recovery-account-meta").textContent = `Sub2API ID ${account.sub2api_account_id} · ${account.plan_type || "OpenAI OAuth"}`;
  $("#recovery-account-material").innerHTML = materialStatus(account);
  $("#recovery-account-state").innerHTML = stateBadge(account.status);
  const accountDisabled = account.status === "account_disabled" || task?.stage === "account_disabled";
  const automationBlocked = account.status === "automation_blocked" || task?.stage === "automation_blocked";
  const waitingAuthorization = account.status === "reauth_required" || task?.status === "manual_required" || task?.stage === "reauthorization";
  $("#recovery-actions").innerHTML = `${actionButton("materials", account.sub2api_account_id, "编辑材料")}${actionButton("recover", account.sub2api_account_id, accountDisabled ? "手动重试" : (automationBlocked ? "重新尝试" : "开始恢复"))}${actionButton("test", account.sub2api_account_id, "检查状态")}${waitingAuthorization ? actionButton("reauth", account.sub2api_account_id, "重新授权") : ""}${task ? actionButton("detail", task.id, "查看完整日志") : ""}`;
  $("#recovery-status-text").textContent = accountDisabled ? "OpenAI 账号已删除或停用" : (automationBlocked ? "自动恢复已阻止" : (waitingAuthorization ? "等待重新授权" : (task ? (task.status === "manual_required" ? "等待授权" : statusLabel(task.status)) : "暂无恢复任务")));
  $("#recovery-live-text").textContent = task && !TERMINAL_TASK_STATUSES.has(task.status) ? "自动更新中 · 每 2 秒" : (task?.error_reason ? taskErrorSummary(task) : "");
  const alert = $("#recovery-alert");
  if (accountDisabled) {
    const reason = task?.error_reason || account.failure_reason || "OpenAI 返回 account_deactivated。";
    alert.className = "inspector-alert blocked";
    alert.innerHTML = `<strong>OpenAI 账号已删除或停用</strong><span>${escapeHtml(`${humanizeLogMessage({ message: reason })} 自动扫描不会重复尝试；确认账号已恢复后，可手动检查状态或重试恢复。`)}</span>`;
  } else if (automationBlocked) {
    const missing = account.automation_missing || [];
    const missingText = missing.length ? `缺少：${missing.join("、")}。` : "没有读取到完整的自动登录材料。";
    const refreshInvalidated = task?.logs?.some((log) => log.message === "Your refresh token has been invalidated. Please try signing in again." || log.detail?.error_code === "refresh_token_invalidated");
    const refreshText = refreshInvalidated ? "旧 OAuth 刷新令牌已失效，浏览器流程尚未启动。" : "";
    alert.className = "inspector-alert blocked";
    alert.innerHTML = `<strong>自动恢复未执行</strong><span>${escapeHtml(`${refreshText}${missingText}请在“编辑材料”中补齐，或更新 Sub2API 账号备注后，再点击“重新尝试”。`)}</span>`;
  } else if (waitingAuthorization) {
    const reason = task?.error_reason || account.failure_reason || "刷新令牌已失效，需要重新登录 OpenAI。";
    alert.className = "inspector-alert waiting";
    alert.innerHTML = `<strong>需要重新授权</strong><span>${escapeHtml(humanizeLogMessage({ message: reason }))}</span>`;
  } else {
    alert.className = "inspector-alert hidden";
    alert.textContent = "";
  }
  $("#open-selected-logs").disabled = !task;
  renderRecoveryTimeline(task);
  renderRecoveryLogPreview(task);
}

function showView(view) {
  const views = { console: "#view-console", accounts: "#view-accounts", logs: "#view-logs", settings: "#settings-section" };
  const target = views[view] ? view : "console";
  state.activeView = target;
  localStorage.setItem("recovery_view", target);
  Object.entries(views).forEach(([name, selector]) => $(selector).classList.toggle("hidden", name !== target));
  document.querySelectorAll("[data-view-target]").forEach((button) => button.classList.toggle("active", button.dataset.viewTarget === target));
  if (target === "console") renderConsole();
  if (target === "accounts") renderAccounts();
  if (target === "logs") renderTasks();
}

function renderConsole() {
  renderConsoleAccounts();
  renderRecoveryInspector();
}

function stopSelectedTaskRefresh() {
  if (!selectedTaskRefreshTimer) return;
  window.clearInterval(selectedTaskRefreshTimer);
  selectedTaskRefreshTimer = null;
}

function startSelectedTaskRefresh(task) {
  stopSelectedTaskRefresh();
  if (!task || TERMINAL_TASK_STATUSES.has(task.status)) return;
  selectedTaskRefreshTimer = window.setInterval(async () => {
    if (document.hidden || !state.token || !state.selectedAccountId) return;
    const summary = latestTaskForAccount(state.selectedAccountId);
    if (!summary) return;
    try {
      const latest = await api(`/api/v1/tasks/${summary.id}`);
      if (String(latest.sub2api_account_id) !== String(state.selectedAccountId)) return;
      state.selectedTask = latest;
      renderConsole();
      if (TERMINAL_TASK_STATUSES.has(latest.status)) stopSelectedTaskRefresh();
    } catch (_) {
      $("#recovery-live-text").textContent = "详情暂时无法更新";
    }
  }, TASK_DETAIL_REFRESH_MS);
}

async function loadSelectedTask() {
  const requestId = ++selectedTaskRequest;
  stopSelectedTaskRefresh();
  const accountId = state.selectedAccountId;
  const summary = latestTaskForAccount(accountId);
  if (!summary) {
    state.selectedTask = null;
    renderRecoveryInspector();
    return;
  }
  try {
    const task = await api(`/api/v1/tasks/${summary.id}`);
    if (requestId !== selectedTaskRequest || String(state.selectedAccountId) !== String(accountId)) return;
    state.selectedTask = task;
    renderRecoveryInspector();
    startSelectedTaskRefresh(task);
  } catch (_) {
    if (requestId === selectedTaskRequest) $("#recovery-live-text").textContent = "恢复详情暂时无法加载";
  }
}

function selectAccount(accountId) {
  if (!state.accounts.some((account) => String(account.sub2api_account_id) === String(accountId))) return;
  state.selectedAccountId = String(accountId);
  renderConsole();
  loadSelectedTask();
}

function renderAccounts() {
  const filter = $("#account-filter").value;
  const search = $("#account-search").value.trim().toLowerCase();
  const items = state.accounts.filter((item) => {
    if (filter && item.status !== filter) return false;
    if (!search) return true;
    return [item.email, item.username, item.sub2api_account_id].some((value) => String(value ?? "").toLowerCase().includes(search));
  }).sort((left, right) => compareAccountValues(left, right, state.accountSort.key, state.accountSort.direction) || compareAccountValues(left, right, "id"));
  $("#accounts-head").innerHTML = [
    accountSortHeader("account", ACCOUNT_SORT_LABELS.account),
    accountSortHeader("id", ACCOUNT_SORT_LABELS.id),
    accountSortHeader("status", ACCOUNT_SORT_LABELS.status),
    accountSortHeader("materials", ACCOUNT_SORT_LABELS.materials),
    accountSortHeader("credentials", ACCOUNT_SORT_LABELS.credentials),
    accountSortHeader("last_401", ACCOUNT_SORT_LABELS.last_401),
    "<th>操作</th>",
  ].join("");
  $("#accounts-empty").classList.toggle("hidden", items.length > 0);
  $("#accounts-empty").textContent = state.accounts.length && !items.length ? "没有匹配账号。" : "还没有同步到 OpenAI OAuth 账号。";
  $("#accounts-body").innerHTML = items.map((account) => `<tr>
    <td><div class="account-name">${escapeHtml(account.email || account.username || "未命名账号")}</div><div class="account-sub">${escapeHtml(account.failure_reason || account.plan_type || "OpenAI OAuth")}</div></td>
    <td><code>${escapeHtml(account.sub2api_account_id)}</code></td>
    <td>${stateBadge(account.status)}</td>
    <td>${materialStatus(account)}</td>
    <td><span class="account-sub">${account.has_access_token ? "AT" : "-"} / ${account.has_refresh_token ? "RT" : "-"}</span></td>
    <td>${escapeHtml(formatDate(account.last_401_at))}</td>
    <td><div class="row-actions">${actionButton("materials", account.sub2api_account_id, "材料")}${actionButton("recover", account.sub2api_account_id, "恢复")}${actionButton("reauth", account.sub2api_account_id, "重新授权")}${actionButton("test", account.sub2api_account_id, "检查状态")}</div></td>
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
  if (["recover", "test", "reauth", "materials"].includes(action)) {
    state.selectedAccountId = String(id);
    if (action !== "materials") state.selectedTask = null;
  }
  renderConsole();
  renderAccounts();
  renderTasks();
  try {
    if (action === "recover") { await api(`/api/v1/accounts/${id}/recover`, { method: "POST" }); await loadAll(); }
    if (action === "test") { const result = await api(`/api/v1/accounts/${id}/status`, { method: "POST" }); alert(result.reason); await loadAll(); }
    if (action === "reauth") await openReauth(id);
    if (action === "materials") openMaterials(id);
    if (action === "detail") await openTask(id);
    if (action === "retry-task") { await api(`/api/v1/tasks/${id}/retry`, { method: "POST" }); await loadAll(); }
  } catch (error) { alert(error.message); }
  finally { state.busyActions.delete(key); renderConsole(); renderAccounts(); renderTasks(); }
}

function openMaterials(accountId) {
  const account = state.accounts.find((item) => String(item.sub2api_account_id) === String(accountId));
  if (!account) return;
  state.materialsAccountId = String(accountId);
  $("#materials-account-name").textContent = accountName(account);
  $("#materials-account-meta").textContent = `Sub2API ID ${account.sub2api_account_id} · 当前 ${materialStatusText(account)}`;
  $("#material-email").value = account.email || "";
  $("#material-email-password").value = "";
  $("#material-openai-password").value = "";
  $("#material-totp-secret").value = "";
  $("#materials-dialog-status").textContent = "空白字段保持已有值不变。保存后会在本服务内加密保存。";
  $("#materials-dialog").showModal();
}

async function saveMaterials() {
  const accountId = state.materialsAccountId;
  if (!accountId) return;
  const values = {
    email: $("#material-email").value.trim(),
    email_password: $("#material-email-password").value,
    openai_password: $("#material-openai-password").value,
    totp_secret: $("#material-totp-secret").value,
  };
  if (!Object.values(values).some((value) => value.trim())) {
    $("#materials-dialog-status").textContent = "至少填写一项材料。";
    return;
  }
  const submit = $("#save-materials");
  submit.disabled = true;
  $("#materials-dialog-status").textContent = "保存中...";
  try {
    const account = await api(`/api/v1/accounts/${encodeURIComponent(accountId)}/materials`, { method: "PUT", body: JSON.stringify(values) });
    const index = state.accounts.findIndex((item) => String(item.sub2api_account_id) === accountId);
    if (index >= 0) state.accounts[index] = account;
    $("#materials-dialog").close();
    state.materialsAccountId = "";
    renderConsole();
    renderAccounts();
    renderTasks();
  } catch (error) {
    $("#materials-dialog-status").textContent = error.message;
  } finally {
    submit.disabled = false;
  }
}

function resetAccountEnrollmentForm() {
  state.accountEnrollmentId = "";
  localStorage.removeItem("recovery_account_enrollment");
  stopAccountEnrollmentPolling();
  $("#account-enrollment-form").reset();
  $("#enrollment-fields").classList.remove("hidden");
  $("#enrollment-progress").classList.add("hidden");
  $("#submit-enrollment").classList.remove("hidden");
  $("#new-enrollment").classList.add("hidden");
  $("#enrollment-form-error").textContent = "";
}

function openAccountEnrollment() {
  $("#account-enrollment-dialog").showModal();
  if (state.accountEnrollmentId) {
    $("#enrollment-fields").classList.add("hidden");
    $("#enrollment-progress").classList.remove("hidden");
    refreshAccountEnrollment();
    startAccountEnrollmentPolling();
  } else {
    $("#enrollment-fields").classList.remove("hidden");
    $("#enrollment-progress").classList.add("hidden");
    $("#enrollment-form-error").textContent = "";
  }
}

function renderAccountEnrollment(enrollment) {
  $("#enrollment-progress").classList.remove("hidden");
  $("#enrollment-fields").classList.add("hidden");
  const statusLabels = { queued: "排队中", running: "执行中", succeeded: "成功", failed: "失败", skipped: "未创建" };
  const badge = $("#enrollment-status-badge");
  badge.className = `state ${enrollment.status || "unknown"}`;
  badge.textContent = statusLabels[enrollment.status] || enrollment.status || "未知";
  $("#enrollment-stage").textContent = stageLabel(enrollment.stage);
  let message = humanizeEnrollmentMessage(enrollment.message, enrollment.stage);
  if (enrollment.sub2api_account_id) message += `（Sub2API ID ${enrollment.sub2api_account_id}）`;
  $("#enrollment-message").textContent = message;
  $("#enrollment-logs").innerHTML = (enrollment.logs || []).map((log) => `<li class="enrollment-log ${String(log.level).toLowerCase() === "error" ? "error" : ""}"><div class="log-top"><span class="log-stage">${escapeHtml(stageLabel(log.stage))}</span><span>${escapeHtml(formatDate(log.created_at))}</span></div><div class="enrollment-log-message">${escapeHtml(humanizeEnrollmentMessage(log.message, log.stage))}</div></li>`).join("");
  const terminal = ["succeeded", "failed", "skipped"].includes(enrollment.status);
  $("#submit-enrollment").classList.add("hidden");
  $("#submit-enrollment").disabled = false;
  $("#new-enrollment").classList.toggle("hidden", !terminal);
}

async function refreshAccountEnrollment() {
  if (!state.accountEnrollmentId || !state.token) return;
  try {
    const enrollment = await api(`/api/v1/account-enrollments/${encodeURIComponent(state.accountEnrollmentId)}`);
    renderAccountEnrollment(enrollment);
    if (["succeeded", "failed", "skipped"].includes(enrollment.status)) {
      stopAccountEnrollmentPolling();
      if (enrollment.status === "succeeded") await loadAll();
    }
  } catch (error) {
    $("#enrollment-message").textContent = error.message;
  }
}

function startAccountEnrollmentPolling() {
  if (!state.accountEnrollmentId || state.accountEnrollmentTimer) return;
  refreshAccountEnrollment();
  state.accountEnrollmentTimer = window.setInterval(refreshAccountEnrollment, 2000);
}

function stopAccountEnrollmentPolling() {
  if (!state.accountEnrollmentTimer) return;
  window.clearInterval(state.accountEnrollmentTimer);
  state.accountEnrollmentTimer = null;
}

async function submitAccountEnrollment(event) {
  event.preventDefault();
  const submit = $("#submit-enrollment");
  submit.disabled = true;
  $("#enrollment-form-error").textContent = "";
  const values = {
    email: $("#enrollment-email").value.trim(),
    name: $("#enrollment-name").value.trim(),
    email_password: $("#enrollment-email-password").value,
    openai_password: $("#enrollment-openai-password").value,
    totp_secret: $("#enrollment-totp-secret").value,
  };
  try {
    const enrollment = await api("/api/v1/account-enrollments", { method: "POST", body: JSON.stringify(values) });
    state.accountEnrollmentId = enrollment.id;
    localStorage.setItem("recovery_account_enrollment", enrollment.id);
    $("#enrollment-email-password").value = "";
    $("#enrollment-openai-password").value = "";
    $("#enrollment-totp-secret").value = "";
    renderAccountEnrollment(enrollment);
    startAccountEnrollmentPolling();
  } catch (error) {
    $("#enrollment-form-error").textContent = error.message;
    submit.disabled = false;
  }
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
$("#theme-toggle").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
document.querySelectorAll("[data-view-target]").forEach((button) => button.addEventListener("click", async () => {
  const view = button.dataset.viewTarget;
  showView(view);
  if (view === "settings") {
    try { await loadSettings(); } catch (error) { alert(error.message); }
  }
}));
$("#refresh-button").addEventListener("click", async () => {
  const button = $("#refresh-button");
  button.disabled = true;
  button.textContent = "更新中...";
  try { await loadAll(); } catch (error) { alert(error.message); }
  finally { button.disabled = false; button.textContent = "刷新"; }
});
$("#close-settings").addEventListener("click", () => showView("console"));
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
$("#console-account-search").addEventListener("input", renderConsole);
$("#console-account-filter").addEventListener("change", renderConsole);
$("#console-account-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-select-account]");
  if (button) selectAccount(button.dataset.selectAccount);
});
$("#recovery-actions").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (button) handleAction(button.dataset.action, button.dataset.id);
});
$("#open-selected-logs").addEventListener("click", async () => {
  const task = state.selectedTask || latestTaskForAccount(state.selectedAccountId);
  if (!task) return;
  showView("logs");
  await openTask(task.id);
});
$("#account-search").addEventListener("input", renderAccounts);
$("#account-filter").addEventListener("change", renderAccounts);
$("#accounts-head").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-account-sort]");
  if (!button) return;
  const key = button.dataset.accountSort;
  if (state.accountSort.key === key) state.accountSort.direction = state.accountSort.direction === "asc" ? "desc" : "asc";
  else state.accountSort = { key, direction: "asc" };
  renderAccounts();
});
$("#task-search").addEventListener("input", renderTasks);
$("#accounts-body").addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) handleAction(button.dataset.action, button.dataset.id); });
$("#tasks-body").addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) handleAction(button.dataset.action, button.dataset.id); });
$("#task-dialog").addEventListener("close", () => { activeTaskId = ""; stopTaskDialogRefresh(); });
$("#complete-auth").addEventListener("click", completeReauth);
$("#new-account-button").addEventListener("click", openAccountEnrollment);
$("#account-enrollment-form").addEventListener("submit", submitAccountEnrollment);
$("#new-enrollment").addEventListener("click", resetAccountEnrollmentForm);
$("#close-enrollment").addEventListener("click", () => $("#account-enrollment-dialog").close("cancel"));
$("#close-enrollment-icon").addEventListener("click", () => $("#account-enrollment-dialog").close("cancel"));
$("#launch-browser").addEventListener("click", async () => { if (!state.reauthSession) return; try { await api(`/api/v1/accounts/${state.reauthSession.sub2api_account_id}/reauthorize`, { method: "POST", body: JSON.stringify({ launch_browser: true, session_id: state.reauthSession.id }) }); $("#reauth-status").textContent = "浏览器已启动，请完成验证。"; } catch (error) { $("#reauth-status").textContent = error.message; } });
$("#cancel-materials").addEventListener("click", () => { state.materialsAccountId = ""; $("#materials-dialog").close("cancel"); });
$("#materials-form").addEventListener("submit", async (event) => { event.preventDefault(); await saveMaterials(); });
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.token) {
    loadAll().catch(() => { $("#service-status").textContent = "连接失败"; });
    if (activeTaskId && $("#task-dialog").open) {
      api(`/api/v1/tasks/${activeTaskId}`).then(renderTaskDetail).catch(() => { $("#task-dialog-status").textContent = "日志暂时无法更新"; });
    }
  }
});

renderThemeControl(savedTheme);
if (state.token) { setLoggedIn(true); showView(state.activeView); loadAll().catch(() => logout()); } else { setLoggedIn(false); showView("console"); }
