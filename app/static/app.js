const savedTheme = localStorage.getItem("recovery_theme") === "dark" ? "dark" : "light";
document.documentElement.dataset.theme = savedTheme;
const state = { token: localStorage.getItem("recovery_token") || "", accounts: [], tasks: [], mailboxes: [], mailboxSecrets: new Map(), editingMailboxId: "", reauthSession: null, materialsAccountId: "", accountEnrollmentId: localStorage.getItem("recovery_account_enrollment") || "", accountEnrollmentTimer: null, profiles: [], activeProfileId: null, sync: { status: "never" }, lastUpdatedAt: null, busyActions: new Set(), selectedDisabledAccountIds: new Set(), accountSort: { key: "id", direction: "asc" }, selectedAccountId: "", selectedTask: null, recoveryPreviewSignature: "", activeView: localStorage.getItem("recovery_view") || "console" };
const $ = (selector) => document.querySelector(selector);
const DASHBOARD_REFRESH_MS = 10000;
const TASK_DETAIL_REFRESH_MS = 2000;
const TERMINAL_TASK_STATUSES = new Set(["succeeded", "failed", "skipped"]);
const DIRECT_OAUTH_401_MESSAGE = "Sub2API confirmed 401; skipping native and refresh-token attempts and starting a new OAuth flow";
const RECOVERY_FLOW = [
  { key: "detect", label: "确认认证异常", stages: ["scan", "probe"], description: "读取 Sub2API 返回的账号状态，确认是否需要恢复。" },
  { key: "credentials", label: "读取账号材料", stages: ["sync"], description: "读取备注和加密凭据，敏感值不会显示在页面。" },
  { key: "native_refresh", label: "尝试原生刷新", stages: ["native_refresh"], description: "优先调用 Sub2API 原生 OAuth 刷新。" },
  { key: "refresh_token", label: "刷新 OAuth 令牌", stages: ["refresh_token"], description: "原生刷新未完成时，使用本地刷新令牌继续恢复。" },
  { key: "browser", label: "执行 OAuth 浏览器流程", stages: ["browser", "automatic_reauthorization", "automation_blocked", "security_challenge", "cloudflare_challenge", "oauth_flow", "email", "openai_password", "email_code", "totp", "account_disabled"], description: "按真实页面要求处理账号登录、邮箱验证码和验证器代码。" },
  { key: "callback", label: "接收回调并建立会话", stages: ["callback", "token_exchange", "reauthorization"], description: "校验 OAuth 回调和 PKCE 后交换会话令牌。" },
  { key: "identity_change", label: "处理账号身份变化", stages: ["identity_change", "account_replaced"], description: "OAuth 身份发生变化，保留原账号并创建或复用新的 Sub2API 账号。" },
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
  const { _networkRetry, ...requestOptions } = options;
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  let response;
  try {
    response = await fetch(path, { ...requestOptions, headers });
  } catch (error) {
    if (!_networkRetry) {
      await new Promise((resolve) => window.setTimeout(resolve, 350));
      return api(path, { ...requestOptions, _networkRetry: true });
    }
    throw new Error("服务连接失败，请确认服务仍在运行后重试。", { cause: error });
  }
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
  const text = { healthy: "正常", auth_failed: "认证失败", recovering: "恢复中", reauth_required: "等待授权", manual_required: "待授权", automation_blocked: "材料不足", account_error: "账号异常", account_disabled: "账号已删除或停用", account_replaced: "已创建新账号", rate_limited: "限额中", succeeded: "成功", failed: "失败", skipped: "已跳过", queued: "排队中", running: "执行中", retry_wait: "等待重试", observed: "需关注", unknown: "未知" }[value] || value || "未知";
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
  return { healthy: "正常", auth_failed: "认证失败", recovering: "恢复中", retry_wait: "等待重试", reauth_required: "等待授权", manual_required: "待授权", automation_blocked: "材料不足", account_error: "账号异常", account_disabled: "账号已删除或停用", account_replaced: "已创建新账号", rate_limited: "限额中", observed: "需关注", unknown: "未知" }[value] || value || "未知";
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatCompactDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
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
  identity_change: "账号身份变化",
  credentials: "准备自动登录材料",
  oauth_flow: "OAuth 页面交互",
  callback: "接收 OAuth 回调",
  token_exchange: "交换 OAuth 会话",
  identity_check: "确认账号身份",
  duplicate_check: "检查账号重复",
  create_account: "创建 Sub2API 账号",
  account_deleted: "人工删除 Sub2API 账号",
  completed: "已完成",
  account_replaced: "已创建新账号",
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
const ACCOUNT_STATUS_ORDER = { account_disabled: 0, account_error: 1, auth_failed: 2, reauth_required: 3, automation_blocked: 4, recovering: 5, retry_wait: 6, account_replaced: 7, rate_limited: 8, observed: 9, healthy: 10, unknown: 99 };
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
  screenshot_error: "页面截图保存失败",
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
  if (key === "status") return ACCOUNT_STATUS_ORDER[accountStatusForUi(account)] ?? 99;
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
    [DIRECT_OAUTH_401_MESSAGE]: "Sub2API 已确认 OAuth 401，跳过原生刷新和 refresh token，直接开始 OAuth 重新授权。",
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
  if (message.startsWith("OAuth identity changed; created replacement Sub2API account")) return `账号身份已变化，已创建新 Sub2API 账号：${message.slice("OAuth identity changed; created replacement Sub2API account".length).trim()}。`;
  if (message === "OAuth identity changed; creating a new Sub2API account") return "检测到 OpenAI 账号身份变化，正在创建新的 Sub2API 账号。";
  if (message === "Replacement OAuth identity already exists; reusing that Sub2API account") return "新的 OAuth 身份已存在，正在复用对应的 Sub2API 账号。";
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
      account_disabled: "检测到账号停用错误页，请查看页面截图核实。",
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

function renderTaskEvidence(log, taskId) {
  const evidenceId = log.detail?.evidence_id;
  if (!evidenceId) return "";
  return `<div class="log-evidence"><button class="mini-button" type="button" data-task-evidence="${escapeHtml(taskId)}" data-evidence-id="${escapeHtml(evidenceId)}">查看页面截图</button></div>`;
}

function renderInlineTaskEvidence(log, taskId) {
  const evidenceId = log.detail?.evidence_id;
  if (!evidenceId) return "";
  return `<div class="log-evidence inline-log-evidence" data-inline-task-evidence="${escapeHtml(taskId)}" data-evidence-id="${escapeHtml(evidenceId)}"><span class="evidence-loading">正在加载页面截图...</span><img hidden alt="OpenAI 账号停用错误页面截图" /></div>`;
}

function releaseTaskEvidencePreviews(root = document) {
  root.querySelectorAll(".log-evidence[data-preview-url]").forEach((container) => {
    URL.revokeObjectURL(container.dataset.previewUrl);
    delete container.dataset.previewUrl;
  });
}

async function loadInlineTaskEvidencePreviews(root) {
  const containers = [...root.querySelectorAll("[data-inline-task-evidence]")];
  await Promise.all(containers.map(async (container) => {
    try {
      const path = `/api/v1/tasks/${encodeURIComponent(container.dataset.inlineTaskEvidence)}/evidence/${encodeURIComponent(container.dataset.evidenceId)}`;
      const response = await fetch(path, { headers: { Authorization: `Bearer ${state.token}` } });
      if (response.status === 401) { logout(); throw new Error("登录已过期"); }
      if (!response.ok) throw new Error("页面截图暂时无法加载");
      const imageUrl = URL.createObjectURL(await response.blob());
      if (!container.isConnected) {
        URL.revokeObjectURL(imageUrl);
        return;
      }
      container.dataset.previewUrl = imageUrl;
      const image = container.querySelector("img");
      image.src = imageUrl;
      image.hidden = false;
      container.querySelector(".evidence-loading")?.remove();
    } catch (error) {
      if (container.isConnected) container.textContent = `页面截图加载失败：${error.message}`;
    }
  }));
}

async function toggleTaskEvidence(button) {
  const container = button.closest(".log-evidence");
  if (container.dataset.previewUrl) {
    URL.revokeObjectURL(container.dataset.previewUrl);
    delete container.dataset.previewUrl;
    container.querySelector("img")?.remove();
    button.textContent = "查看页面截图";
    return;
  }
  button.disabled = true;
  try {
    const path = `/api/v1/tasks/${encodeURIComponent(button.dataset.taskEvidence)}/evidence/${encodeURIComponent(button.dataset.evidenceId)}`;
    const response = await fetch(path, { headers: { Authorization: `Bearer ${state.token}` } });
    if (response.status === 401) { logout(); throw new Error("登录已过期"); }
    if (!response.ok) throw new Error("截图暂时无法加载");
    const imageUrl = URL.createObjectURL(await response.blob());
    const image = document.createElement("img");
    image.src = imageUrl;
    image.alt = "OpenAI 账号停用错误页面截图";
    container.dataset.previewUrl = imageUrl;
    container.append(image);
    button.textContent = "隐藏截图";
  } catch (error) {
    button.textContent = error.message;
  } finally {
    button.disabled = false;
  }
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
    const [dashboard, accounts, tasks, mailboxes] = await Promise.all([api("/api/v1/dashboard"), api("/api/v1/accounts"), api("/api/v1/tasks?limit=80"), api("/api/v1/mailboxes")]);
    state.accounts = accounts.items || [];
    state.tasks = tasks.items || [];
    state.mailboxes = mailboxes.items || [];
    for (const accountId of state.selectedDisabledAccountIds) {
      const account = state.accounts.find((item) => String(item.sub2api_account_id) === accountId);
      if (!account || !isDeletionEligible(account)) state.selectedDisabledAccountIds.delete(accountId);
    }
    ensureSelectedAccount();
    renderMetrics(dashboard.summary || {});
    state.lastUpdatedAt = new Date().toISOString();
    renderSync(dashboard.sync || {});
    renderConsole();
    renderAccounts();
    renderMailboxes();
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
  const items = [
    ["账号总数", summary.accounts || 0],
    ["401 / 待授权", summary.auth_failures || 0],
    ["执行中", summary.running_tasks || 0],
    ["等待重试", summary.retry_wait_tasks || 0, summary.next_retry_at ? `最早 ${formatCompactDate(summary.next_retry_at)}` : "暂无待重试任务"],
    ["近 30 天成功", summary.success || 0],
    ["失败任务", summary.failed || 0],
  ];
  $("#metrics").innerHTML = items.map(([label, value, detail]) => `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value">${value}</div>${detail ? `<div class="metric-detail">${escapeHtml(detail)}</div>` : ""}</div>`).join("");
}

function accountName(account) {
  return account.email || account.username || "未命名账号";
}

function accountPriority(account) {
  const priority = { account_disabled: 0, account_error: 1, auth_failed: 2, reauth_required: 3, automation_blocked: 4, recovering: 5, retry_wait: 6, account_replaced: 7, rate_limited: 8, observed: 9, healthy: 10, unknown: 99 };
  return priority[accountStatusForUi(account)] ?? 99;
}

function ensureSelectedAccount() {
  if (state.accounts.some((account) => isVisibleAccount(account) && String(account.sub2api_account_id) === String(state.selectedAccountId))) return;
  const candidates = state.accounts.filter(isVisibleAccount).sort((left, right) => accountPriority(left) - accountPriority(right) || Number(left.sub2api_account_id) - Number(right.sub2api_account_id));
  state.selectedAccountId = candidates.length ? String(candidates[0].sub2api_account_id) : "";
}

function latestTaskForAccount(accountId) {
  return state.tasks
    .filter((task) => String(task.sub2api_account_id) === String(accountId))
    .sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime())[0] || null;
}

function accountStatusForUi(account) {
  const task = latestTaskForAccount(account.sub2api_account_id);
  return task?.status === "queued" && task.stage === "retry_wait" ? "retry_wait" : account.status;
}

function isVisibleAccount(account) {
  return accountStatusForUi(account) !== "rate_limited";
}

function isDeletionEligible(account) {
  const task = latestTaskForAccount(account.sub2api_account_id);
  return account.status === "account_disabled" && task?.status === "failed" && task.stage === "account_disabled" && Boolean(task.has_evidence);
}

function updateDisabledAccountSelectionControls(visibleEligible = []) {
  const count = state.selectedDisabledAccountIds.size;
  const button = $("#delete-disabled-selected");
  button.disabled = count === 0;
  button.textContent = `删除已选停用账号（${count}）`;
  const selectAll = $("#select-all-disabled");
  const selectedVisible = visibleEligible.filter((account) => state.selectedDisabledAccountIds.has(String(account.sub2api_account_id))).length;
  selectAll.disabled = visibleEligible.length === 0;
  selectAll.checked = visibleEligible.length > 0 && selectedVisible === visibleEligible.length;
  selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleEligible.length;
}

function renderConsoleAccounts() {
  const search = $("#console-account-search").value.trim().toLowerCase();
  const filter = $("#console-account-filter").value;
  const visibleAccounts = state.accounts.filter(isVisibleAccount);
  const items = visibleAccounts
    .filter((account) => {
      if (filter && accountStatusForUi(account) !== filter) return false;
      if (!search) return true;
      return [account.email, account.username, account.sub2api_account_id].some((value) => String(value ?? "").toLowerCase().includes(search));
    })
    .sort((left, right) => accountPriority(left) - accountPriority(right) || Number(left.sub2api_account_id) - Number(right.sub2api_account_id));
  $("#console-account-count").textContent = `${items.length}/${visibleAccounts.length}`;
  $("#console-accounts-empty").classList.toggle("hidden", items.length > 0);
  const list = $("#console-account-list");
  const scrollTop = list.scrollTop;
  list.innerHTML = items.map((account) => {
    const accountId = String(account.sub2api_account_id);
    const selected = accountId === String(state.selectedAccountId);
    const task = latestTaskForAccount(accountId);
    const retryWaiting = accountStatusForUi(account) === "retry_wait";
    const secondary = account.failure_reason || account.plan_type || "OpenAI OAuth";
    return `<button class="console-account ${selected ? "selected" : ""}" type="button" data-select-account="${escapeHtml(accountId)}" aria-pressed="${selected}"><span class="console-account-copy"><strong>${escapeHtml(accountName(account))}</strong><span>${escapeHtml(secondary)}</span></span><span class="console-account-side"><span class="console-account-side-top"><code>#${escapeHtml(accountId)}</code>${task ? `<small>${escapeHtml(stageLabel(task.stage))}</small>` : ""}</span><span class="console-account-side-bottom">${materialStatus(account)}${stateBadge(retryWaiting ? "retry_wait" : account.status)}${retryWaiting ? `<small class="console-account-retry-at">预计 ${escapeHtml(formatCompactDate(task.available_at))}</small>` : ""}</span></span></button>`;
  }).join("");
  list.scrollTop = scrollTop;
}

function recoveryTimelineForTask(task) {
  const account = state.accounts.find((item) => String(item.sub2api_account_id) === String(task?.sub2api_account_id));
  const directOAuth401 = task?.logs?.some((log) => log.message === DIRECT_OAUTH_401_MESSAGE)
    || task?.failure_class === "401_AUTH_FAILURE"
    || account?.failure_class === "401_AUTH_FAILURE";
  return directOAuth401
    ? RECOVERY_FLOW.filter((step) => !["detect", "credentials", "native_refresh", "refresh_token"].includes(step.key))
    : RECOVERY_FLOW;
}

function timelineStageIndex(task) {
  if (!task) return -1;
  const flow = recoveryTimelineForTask(task);
  const direct = flow.findIndex((step) => step.stages.includes(task.stage));
  if (direct >= 0) return direct;
  if (task.stage === "reauthorization") return flow.findIndex((step) => step.key === "browser");
  const logs = task.logs || [];
  for (let index = logs.length - 1; index >= 0; index -= 1) {
    const logIndex = flow.findIndex((step) => step.stages.includes(logs[index].stage));
    if (logIndex >= 0) return logIndex;
  }
  return ["queued", "running", "retry_wait"].includes(task.status) ? 0 : -1;
}

function timelineStepStatus(step, index, task) {
  if (!task) return "pending";
  const currentIndex = timelineStageIndex(task);
  if (task.status === "queued" && task.stage === "retry_wait" && currentIndex === index) return "waiting";
  const relevantLogs = (task.logs || []).filter((log) => step.stages.includes(log.stage));
  if (relevantLogs.some((log) => log.stage === "automation_blocked")) return "blocked";
  const error = relevantLogs.some((log) => String(log.level || "").toUpperCase() === "ERROR");
  if (error) return "error";
  if (currentIndex === index) {
    if (task.status === "succeeded") return "done";
    if (task.status === "failed") return "error";
    if (task.status === "skipped") return "skipped";
    if (task.status === "queued" && task.stage === "retry_wait") return "waiting";
    return "running";
  }
  if (currentIndex > index) return relevantLogs.length ? "done" : "skipped";
  if (task.status === "succeeded") return relevantLogs.length ? "done" : "skipped";
  return "pending";
}

function timelineStepDescription(step, status, task) {
  if (status === "waiting") return `最近一次尝试遇到临时问题，预计 ${formatDate(task.available_at)} 自动重试。`;
  const logs = (task?.logs || []).filter((log) => step.stages.includes(log.stage));
  const latest = logs[logs.length - 1];
  if (latest) return humanizeLogMessage(latest);
  if (status === "skipped") return "该路径未执行，前置步骤已决定使用其他恢复方式。";
  if (status === "error") return taskErrorSummary(task);
  if (status === "running" && task?.status === "manual_required") return "等待管理员完成授权。";
  return step.description;
}

function renderRecoveryTimeline(task) {
  const markers = { done: "✓", running: "…", waiting: "↻", pending: "", skipped: "–", error: "!", blocked: "!" };
  $("#recovery-timeline").innerHTML = recoveryTimelineForTask(task).map((step, index) => {
    const status = timelineStepStatus(step, index, task);
    const statusLabelText = { done: "已完成", running: task?.status === "manual_required" && index === timelineStageIndex(task) ? "等待授权" : "处理中", waiting: "等待重试", pending: "待执行", skipped: "未需要", error: "出错", blocked: "已阻止" }[status];
    return `<li class="timeline-step ${status}"><span class="timeline-marker" aria-hidden="true">${markers[status]}</span><div class="timeline-copy"><div class="timeline-title"><strong>${escapeHtml(step.label)}</strong><span>${statusLabelText}</span></div><p>${escapeHtml(timelineStepDescription(step, status, task))}</p></div></li>`;
  }).join("");
}

function renderRecoveryLogPreview(task) {
  const logs = (task?.logs || []).slice(-5).reverse();
  const preview = $("#recovery-log-preview");
  const signature = JSON.stringify({
    id: task?.id || "",
    status: task?.status || "",
    stage: task?.stage || "",
    error: task?.error_reason || "",
    logs: logs.map((log) => ({
      id: log.id,
      stage: log.stage,
      level: log.level,
      message: log.message,
      created_at: log.created_at,
      evidence_id: log.detail?.evidence_id || "",
      screenshot_error: log.detail?.screenshot_error || "",
    })),
  });
  if (signature === state.recoveryPreviewSignature) return;
  state.recoveryPreviewSignature = signature;
  releaseTaskEvidencePreviews(preview);
  if (!logs.length) {
    preview.innerHTML = `<div class="preview-empty">${task ? "任务已建立，等待第一条处理记录。" : "该账号还没有恢复记录。"}</div>`;
    return;
  }
  preview.innerHTML = logs.map((log) => `<article class="preview-log ${String(log.level || "").toLowerCase() === "error" ? "log-error" : ""}"><div class="log-top"><span class="log-stage">${escapeHtml(stageLabel(log.stage))}</span><span>${escapeHtml(formatDate(log.created_at))}</span></div><div class="log-message">${escapeHtml(humanizeLogMessage(log))}</div>${renderInlineTaskEvidence(log, task.id)}${renderTechnicalDetails(log)}</article>`).join("");
  void loadInlineTaskEvidencePreviews(preview);
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
  const accountReplaced = account.status === "account_replaced" || task?.stage === "account_replaced";
  const automationBlocked = account.status === "automation_blocked" || task?.stage === "automation_blocked";
  const waitingAuthorization = account.status === "reauth_required" || task?.status === "manual_required" || task?.stage === "reauthorization";
  const rateLimited = account.status === "rate_limited";
  const standardActions = rateLimited
    ? `${actionButton("materials", account.sub2api_account_id, "编辑材料")}${actionButton("test", account.sub2api_account_id, "检查状态")}`
    : `${actionButton("materials", account.sub2api_account_id, "编辑材料")}${actionButton("recover", account.sub2api_account_id, accountDisabled ? "手动重试" : (automationBlocked ? "重新尝试" : "开始恢复"))}${actionButton("test", account.sub2api_account_id, "检查状态")}${waitingAuthorization ? actionButton("reauth", account.sub2api_account_id, "重新授权") : ""}`;
  $("#recovery-actions").innerHTML = `${accountReplaced ? "" : standardActions}${task ? actionButton("detail", task.id, "查看完整日志") : ""}`;
  const retryWaiting = task?.status === "queued" && task.stage === "retry_wait";
  $("#recovery-status-text").textContent = accountDisabled ? "OpenAI 账号已删除或停用" : (accountReplaced ? "身份已变化，已创建新账号" : (rateLimited ? "上游使用额度已达到限制，等待额度恢复" : (automationBlocked ? "自动恢复已阻止" : (waitingAuthorization ? "等待重新授权" : (retryWaiting ? "等待重试" : (task ? (task.status === "manual_required" ? "等待授权" : statusLabel(task.status)) : "暂无恢复任务"))))));
  $("#recovery-live-text").textContent = retryWaiting ? `预计 ${formatDate(task.available_at)} 重试` : (task && !TERMINAL_TASK_STATUSES.has(task.status) ? "自动更新中 · 每 2 秒" : (task?.error_reason ? taskErrorSummary(task) : ""));
  const alert = $("#recovery-alert");
  if (accountDisabled) {
    const reason = task?.error_reason || account.failure_reason || "OpenAI 返回 account_deactivated。";
    const disabledLog = task?.logs?.find((log) => log.stage === "account_disabled");
    const screenshotStatus = disabledLog?.detail?.evidence_id
      ? "已保存错误页面截图，可在完整日志中预览。"
      : (disabledLog?.detail?.screenshot_error ? "页面截图未能保存；可在日志技术详情中查看原因。" : "当前任务没有可预览的页面截图。");
    alert.className = "inspector-alert blocked";
    alert.innerHTML = `<strong>OpenAI 账号已删除或停用</strong><span>${escapeHtml(`${humanizeLogMessage({ message: reason })} ${screenshotStatus} 自动扫描不会重复尝试；确认账号已恢复后，可手动检查状态或重试恢复。`)}</span>`;
  } else if (accountReplaced) {
    const replacementLog = task?.logs?.find((log) => log.stage === "account_replaced");
    alert.className = "inspector-alert waiting";
    alert.innerHTML = `<strong>OpenAI 身份已变化</strong><span>${escapeHtml(replacementLog ? humanizeLogMessage(replacementLog) : "已保留原账号，并创建新的 Sub2API 账号。")}</span>`;
  } else if (automationBlocked) {
    const missing = account.automation_missing || [];
    const missingText = missing.length ? `缺少：${missing.join("、")}。` : "没有读取到完整的自动登录材料。";
    const refreshInvalidated = task?.logs?.some((log) => log.message === "Your refresh token has been invalidated. Please try signing in again." || log.detail?.error_code === "refresh_token_invalidated");
    const refreshText = refreshInvalidated ? "旧 OAuth 刷新令牌已失效，浏览器流程尚未启动。" : "";
    alert.className = "inspector-alert blocked";
    alert.innerHTML = `<strong>自动恢复未执行</strong><span>${escapeHtml(`${refreshText}${missingText}请在“编辑材料”中补齐，或更新 Sub2API 账号备注后，再点击“重新尝试”。`)}</span>`;
  } else if (retryWaiting) {
    const reason = task.error_reason ? humanizeLogMessage({ message: task.error_reason }) : "遇到可重试的临时问题。";
    alert.className = "inspector-alert waiting";
    alert.innerHTML = `<strong>任务正在等待自动重试</strong><span>${escapeHtml(`${reason} 下次尝试：${formatDate(task.available_at)}。`)}</span>`;
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
  const views = { console: "#view-console", accounts: "#view-accounts", mailboxes: "#view-mailboxes", logs: "#view-logs", settings: "#settings-section" };
  const target = views[view] ? view : "console";
  state.activeView = target;
  localStorage.setItem("recovery_view", target);
  Object.entries(views).forEach(([name, selector]) => $(selector).classList.toggle("hidden", name !== target));
  document.querySelectorAll("[data-view-target]").forEach((button) => button.classList.toggle("active", button.dataset.viewTarget === target));
  if (target === "console") renderConsole();
  if (target === "accounts") renderAccounts();
  if (target === "mailboxes") renderMailboxes();
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
      const taskIndex = state.tasks.findIndex((item) => String(item.id) === String(latest.id));
      if (taskIndex >= 0) state.tasks[taskIndex] = { ...state.tasks[taskIndex], status: latest.status, stage: latest.stage, available_at: latest.available_at };
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
  const items = state.accounts.filter(isVisibleAccount).filter((item) => {
    if (filter && accountStatusForUi(item) !== filter) return false;
    if (!search) return true;
    return [item.email, item.username, item.sub2api_account_id].some((value) => String(value ?? "").toLowerCase().includes(search));
  }).sort((left, right) => compareAccountValues(left, right, state.accountSort.key, state.accountSort.direction) || compareAccountValues(left, right, "id"));
  const visibleEligible = items.filter(isDeletionEligible);
  $("#accounts-head").innerHTML = [
    '<th class="selection-column"><input id="select-all-disabled" type="checkbox" aria-label="全选当前显示的已确认停用账号" /></th>',
    accountSortHeader("account", ACCOUNT_SORT_LABELS.account),
    accountSortHeader("id", ACCOUNT_SORT_LABELS.id),
    accountSortHeader("status", ACCOUNT_SORT_LABELS.status),
    accountSortHeader("materials", ACCOUNT_SORT_LABELS.materials),
    accountSortHeader("credentials", ACCOUNT_SORT_LABELS.credentials),
    accountSortHeader("last_401", ACCOUNT_SORT_LABELS.last_401),
    "<th>操作</th>",
  ].join("");
  $("#accounts-empty").classList.toggle("hidden", items.length > 0);
  $("#accounts-empty").textContent = state.accounts.some(isVisibleAccount) && !items.length ? "没有匹配账号。" : "当前没有需要显示的账号。";
  $("#accounts-body").innerHTML = items.map((account) => {
    const eligible = isDeletionEligible(account);
    const accountId = String(account.sub2api_account_id);
    const latestTask = latestTaskForAccount(accountId);
    const needsScreenshotReview = account.status === "account_disabled" && latestTask?.stage === "account_disabled" && !latestTask.has_evidence;
    const recoveryAction = account.status === "rate_limited" ? "" : actionButton("recover", account.sub2api_account_id, needsScreenshotReview ? "重新核验" : "恢复");
    return `<tr>
    <td class="selection-column">${eligible ? `<input type="checkbox" data-delete-disabled-account="${escapeHtml(accountId)}" aria-label="选择已确认停用账号 ${escapeHtml(accountId)}" ${state.selectedDisabledAccountIds.has(accountId) ? "checked" : ""} />` : ""}</td>
    <td><div class="account-name">${escapeHtml(account.email || account.username || "未命名账号")}</div><div class="account-sub">${escapeHtml(account.failure_reason || account.plan_type || "OpenAI OAuth")}</div></td>
    <td><code>${escapeHtml(account.sub2api_account_id)}</code></td>
    <td>${stateBadge(accountStatusForUi(account))}${needsScreenshotReview ? '<div class="account-sub evidence-needed">需重新核验截图</div>' : ""}</td>
    <td>${materialStatus(account)}</td>
    <td><span class="account-sub">${account.has_access_token ? "AT" : "-"} / ${account.has_refresh_token ? "RT" : "-"}</span></td>
    <td>${escapeHtml(formatDate(account.last_401_at))}</td>
    <td><div class="row-actions">${actionButton("materials", account.sub2api_account_id, "材料")}${recoveryAction}${account.status === "rate_limited" ? "" : actionButton("reauth", account.sub2api_account_id, "重新授权")}${actionButton("test", account.sub2api_account_id, "检查状态")}${latestTask?.stage === "account_disabled" ? actionButton("detail", latestTask.id, "诊断日志") : ""}</div></td>
  </tr>`;
  }).join("");
  updateDisabledAccountSelectionControls(visibleEligible);
}

function mailboxSourceLabel(mailbox) {
  if (!mailbox.source_account_id) return "手动添加";
  if (mailbox.source_account_status === "account_deleted" || mailbox.source_account_present === 0) {
    return `账号 #${mailbox.source_account_id} 已删除`;
  }
  return `Sub2API #${mailbox.source_account_id}`;
}

function mailboxEyeIcon(revealed) {
  if (revealed) {
    return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  }
  return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-4.558 5.568"></path><path d="M14.084 14.084a3 3 0 0 1-4.168-4.168"></path><path d="M17.479 17.479A10.75 10.75 0 0 1 2.062 12.348a1 1 0 0 1 0-.696A10.75 10.75 0 0 1 5.58 6.42"></path><line x1="2" x2="22" y1="2" y2="22"></line></svg>`;
}

function renderMailboxes() {
  const search = $("#mailbox-search").value.trim().toLowerCase();
  const items = state.mailboxes.filter((mailbox) => Boolean(mailbox.has_password) && (!search || String(mailbox.email || "").toLowerCase().includes(search)));
  $("#mailboxes-empty").classList.toggle("hidden", items.length > 0);
  $("#mailboxes-body").innerHTML = items.map((mailbox) => {
    const id = String(mailbox.id);
    const secret = state.mailboxSecrets.get(id);
    const hasPassword = Boolean(mailbox.has_password);
    const status = hasPassword ? "可用" : "待补密码";
    const passwordValue = secret
      ? `<button class="mailbox-password-value" type="button" data-mailbox-action="copy" data-id="${escapeHtml(id)}" title="点击复制密码">${escapeHtml(secret.password || "（空密码）")}</button>`
      : `<code>••••••••••</code>`;
    const passwordAction = hasPassword
      ? `<button class="mailbox-visibility" type="button" data-mailbox-action="reveal" data-id="${escapeHtml(id)}" aria-label="${secret ? "隐藏密码" : "显示密码"}" title="${secret ? "隐藏密码" : "显示密码"}">${mailboxEyeIcon(Boolean(secret))}</button>`
      : "";
    return `<tr>
      <td><div class="account-name">${escapeHtml(mailbox.email)}</div></td>
      <td><div class="mailbox-password">${hasPassword ? passwordValue : "<code>未保存</code>"}${passwordAction}</div></td>
      <td><span class="account-sub">${escapeHtml(mailboxSourceLabel(mailbox))}</span></td>
      <td><span class="mailbox-state ${hasPassword ? "ready" : "missing"}">${status}</span></td>
      <td>${escapeHtml(formatDate(mailbox.updated_at))}</td>
      <td><div class="row-actions"><button class="mini-button" type="button" data-mailbox-action="edit" data-id="${escapeHtml(id)}">编辑</button><button class="mini-button danger-text" type="button" data-mailbox-action="delete" data-id="${escapeHtml(id)}">删除</button></div></td>
    </tr>`;
  }).join("");
}

function openMailboxDialog(mailboxId = "") {
  state.editingMailboxId = mailboxId;
  const mailbox = state.mailboxes.find((item) => String(item.id) === String(mailboxId));
  $("#mailbox-dialog-title").textContent = mailbox ? "编辑邮箱" : "新增邮箱";
  $("#mailbox-email").value = mailbox?.email || "";
  $("#mailbox-password").value = "";
  $("#mailbox-dialog-status").textContent = "";
  $("#mailbox-dialog").showModal();
  $("#mailbox-email").focus();
}

async function loadMailboxSecret(mailboxId) {
  const secret = await api(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/secret`);
  state.mailboxSecrets.set(String(mailboxId), secret);
  renderMailboxes();
  return secret;
}

async function copyMailboxSecret(mailboxId) {
  const secret = state.mailboxSecrets.get(String(mailboxId)) || await loadMailboxSecret(mailboxId);
  const value = secret.password;
  try {
    await navigator.clipboard.writeText(value);
  } catch (_) {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
}

async function handleMailboxAction(action, mailboxId) {
  const mailbox = state.mailboxes.find((item) => String(item.id) === String(mailboxId));
  if (!mailbox) return;
  try {
    if (action === "reveal") {
      if (state.mailboxSecrets.has(String(mailboxId))) state.mailboxSecrets.delete(String(mailboxId));
      else await loadMailboxSecret(mailboxId);
      renderMailboxes();
    } else if (action === "copy") {
      await copyMailboxSecret(mailboxId);
      $("#service-status").textContent = "密码已复制";
    } else if (action === "edit") {
      openMailboxDialog(mailboxId);
    } else if (action === "delete") {
      if (!window.confirm(`删除邮箱 ${mailbox.email}？此操作不会影响 Sub2API 账号。`)) return;
      await api(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}`, { method: "DELETE" });
      state.mailboxSecrets.delete(String(mailboxId));
      await loadAll();
    }
  } catch (error) {
    alert(error.message);
  }
}

async function deleteSelectedDisabledAccounts() {
  const accountIds = [...state.selectedDisabledAccountIds].map(Number);
  if (!accountIds.length) return;
  const summary = accountIds.map((id) => {
    const account = state.accounts.find((item) => Number(item.sub2api_account_id) === id);
    return `${account?.email || account?.username || "账号"} (#${id})`;
  }).join("\n");
  const confirmed = window.confirm(
    `即将从 Sub2API 删除以下 ${accountIds.length} 个已确认停用账号：\n\n${summary}\n\n本地登录凭据会清除，恢复日志和页面截图会保留。此操作不可由本项目撤销。确定继续？`,
  );
  if (!confirmed) return;
  $("#delete-disabled-selected").disabled = true;
  $("#account-delete-status").textContent = "正在删除所选 Sub2API 账号…";
  try {
    const result = await api("/api/v1/accounts/disabled", {
      method: "DELETE",
      body: JSON.stringify({ account_ids: accountIds, confirmation: "DELETE" }),
    });
    state.selectedDisabledAccountIds.clear();
    const failed = result.failed || [];
    const deleted = result.deleted || [];
    $("#account-delete-status").textContent = failed.length
      ? `已删除 ${deleted.length} 个，${failed.length} 个未删除：${failed.map((item) => `#${item.account_id} ${item.reason}`).join("；")}`
      : `已删除 ${deleted.length} 个 Sub2API 账号；本地恢复日志和截图已保留。`;
    await loadAll();
  } catch (error) {
    $("#account-delete-status").textContent = `删除未完成：${error.message}`;
  } finally {
    updateDisabledAccountSelectionControls();
  }
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
    <td><span class="task-id">${escapeHtml(task.id.slice(0, 8))}</span><div class="task-history">该账号 ${count} 次记录</div></td><td>${escapeHtml(task.email || task.username || task.sub2api_account_id)}</td><td>${escapeHtml(stageLabel(task.stage))}</td><td>${stateBadge(task.status)}</td><td>${escapeHtml(formatDate(task.created_at))}</td>
    <td><div class="row-actions">${actionButton("detail", task.id, "日志")}${["failed", "manual_required"].includes(task.status) && task.account_status !== "account_deleted" ? actionButton("retry-task", task.id, "重试") : ""}</div></td>
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
  releaseTaskEvidencePreviews(logs);
  logs.innerHTML = (task.logs || []).map((log) => `<article class="log-line ${String(log.level || "").toLowerCase() === "error" ? "log-error" : ""}"><div class="log-top"><span class="log-stage">${escapeHtml(stageLabel(log.stage))}</span><span>${escapeHtml(formatDate(log.created_at))}</span><span>${escapeHtml(LOG_LEVEL_LABELS[log.level] || log.level || "记录")}</span></div><div class="log-message">${escapeHtml(humanizeLogMessage(log))}</div>${renderTechnicalDetails(log)}${renderTaskEvidence(log, task.id)}</article>`).join("") || `<div class="empty">暂无日志</div>`;
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
    alert(error.message || "日志暂时无法读取，请稍后重试。");
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
$("#mailbox-search").addEventListener("input", renderMailboxes);
$("#new-mailbox-button").addEventListener("click", () => openMailboxDialog());
$("#cancel-mailbox").addEventListener("click", () => $("#mailbox-dialog").close("cancel"));
$("#close-mailbox-icon").addEventListener("click", () => $("#mailbox-dialog").close("cancel"));
$("#mailbox-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = $("#mailbox-email").value.trim();
  const password = $("#mailbox-password").value;
  const payload = { email, password };
  const mailboxId = state.editingMailboxId;
  $("#save-mailbox").disabled = true;
  $("#mailbox-dialog-status").textContent = "保存中...";
  try {
    await api(mailboxId ? `/api/v1/mailboxes/${encodeURIComponent(mailboxId)}` : "/api/v1/mailboxes", {
      method: mailboxId ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    $("#mailbox-dialog").close();
    state.editingMailboxId = "";
    await loadAll();
  } catch (error) {
    $("#mailbox-dialog-status").textContent = error.message;
  } finally {
    $("#save-mailbox").disabled = false;
  }
});
$("#mailboxes-body").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-mailbox-action]");
  if (button) handleMailboxAction(button.dataset.mailboxAction, button.dataset.id);
});
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
$("#delete-disabled-selected").addEventListener("click", deleteSelectedDisabledAccounts);
$("#accounts-head").addEventListener("change", (event) => {
  if (event.target.id !== "select-all-disabled") return;
  document.querySelectorAll("#accounts-body input[data-delete-disabled-account]").forEach((checkbox) => {
    const accountId = checkbox.dataset.deleteDisabledAccount;
    if (event.target.checked) state.selectedDisabledAccountIds.add(accountId);
    else state.selectedDisabledAccountIds.delete(accountId);
  });
  renderAccounts();
});
$("#accounts-body").addEventListener("change", (event) => {
  const checkbox = event.target.closest("input[data-delete-disabled-account]");
  if (!checkbox) return;
  if (checkbox.checked) state.selectedDisabledAccountIds.add(checkbox.dataset.deleteDisabledAccount);
  else state.selectedDisabledAccountIds.delete(checkbox.dataset.deleteDisabledAccount);
  renderAccounts();
});
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
$("#task-dialog").addEventListener("close", () => { activeTaskId = ""; stopTaskDialogRefresh(); releaseTaskEvidencePreviews($("#task-logs")); });
$("#task-logs").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-task-evidence]");
  if (button) toggleTaskEvidence(button);
});
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
