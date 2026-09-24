# Sub2API 401 自动重登恢复计划

## 1. 目标

把当前“检测 401 后生成授权链接、等待人工操作”的流程升级为真正的自动恢复闭环：

1. 通过 Sub2API Admin API 读取原账号详情和 `notes`。
2. 从备注中识别邮箱、邮箱密码、OpenAI/GPT 密码和 TOTP/2FA 密钥。
3. 具备登录邮箱和 OpenAI 密码即可启动自动恢复；邮箱密码和 TOTP 在对应页面出现时按需校验。
4. 使用真实 Chromium 完成 OpenAI OAuth 页面登录，不绕过 CAPTCHA、Cloudflare 或其他安全验证。
5. 通过邮箱 IMAP 获取一次性验证码，必要时使用 Outlook Webmail 浏览器回退；使用本地 TOTP 算法生成 2FA 验证码。
6. 完成 OAuth callback、PKCE token exchange，并把新凭据原子写回原 Sub2API 账号。
7. 检查原账号状态、清除错误状态、恢复 `schedulable`，并在 Dashboard 展示最终结果。

## 2. 当前缺口与已知事实

- 已有 401 分类、native refresh、refresh token fallback、PKCE callback、原账号写回、测试和任务锁。
- 当前备注只被 Sub2API 返回，服务没有解析或加密保存备注中的登录材料。
- 当前 Playwright 只打开授权页并等待人工 callback，不会填写登录表单、读取邮箱验证码或生成 TOTP。
- 目标账号 `222` 的备注非空且包含 `loganhoynes8273@outlook.com`；账号 `269` 的备注为空，因此本次只自动处理 `222`。
- 当前无头 Chromium 访问授权页时进入 Cloudflare `Just a moment`，需要先等待挑战完成，并在无头环境失败时使用容器内 Xvfb 的真实有头 Chromium 重试。

## 3. 实施方案

### 3.1 备注解析与凭据边界

- 新增容错的 key/value 解析器，支持中英文标签、冒号、等号、Markdown 行和常见空白格式。
- 邮箱优先使用备注值，并回退到 Sub2API 账号邮箱；登录邮箱和 OpenAI 密码是启动浏览器的必需字段，邮箱密码和 TOTP 密钥按页面步骤需要。
- 只保存解析后的必要字段，使用现有 AES-256-GCM 加密列；不保存原始备注，不把密码、验证码、TOTP 或 token 写入日志、API 响应或前端。
- 缺少启动必需字段时将账号标记为 `automation_blocked`；可在 Dashboard 为账号加密补录材料，补录后恢复任务重新具备执行条件。

### 3.2 邮箱验证码

- 首选 `IMAP4_SSL`，服务器和端口通过环境变量配置，默认适配 Outlook `outlook.office365.com:993`。
- 从任务开始时间之后的邮件中筛选 OpenAI 验证邮件，解析 6 位数字验证码，并使用短期去重避免读取旧码。
- IMAP 登录失败、验证码超时或邮箱要求额外交互时，使用 Outlook Webmail Playwright 回退；两种方式都使用代理并关闭页面后清理上下文。
- 邮箱访问错误分为可重试网络错误、凭据错误和需要额外验证三类，按任务策略处理。

### 3.3 OAuth 浏览器状态机

- 用真实 Chromium 上下文完成：Cloudflare 等待/重试、邮箱输入、密码输入、邮箱验证码、TOTP、授权确认和 callback。
- 选择器采用语义、`autocomplete`、`type`、placeholder 多层回退，并在每个阶段设置超时和有限重试。
- 无头模式先运行；检测到挑战持续存在时，自动启动 Xvfb 并用有头 Chromium 重试，不注入 stealth 脚本、不修改挑战响应、不绕过安全验证。
- 识别密码错误、验证码错误、TOTP 过期、账号身份不匹配和页面结构变化，保存脱敏原因并避免无限重试。

### 3.4 任务编排与写回

- 自动任务在执行前同步备注凭据并合并 Dashboard 补录材料；具备登录邮箱和 OpenAI 密码才进入浏览器流程，邮箱验证码和 TOTP 在页面实际要求时校验。
- OAuth 成功后保留旧 refresh token 的 rotation-safe 逻辑，校验 token 身份与原账号一致。
- 使用现有 `apply-oauth-credentials`、账号状态检查、`recover-state`、`schedulable` API，成功后任务为 `succeeded`。
- 任何中间失败都保持原账号 ID，不删除、不创建替代账号；账号级锁和 stale task 回收继续有效。

### 3.5 配置与运维

新增配置项：

- `AUTOMATION_REQUIRE_COMPLETE_NOTES`
- `MAIL_IMAP_HOST`、`MAIL_IMAP_PORT`、`MAIL_IMAP_FOLDER`
- `MAIL_CODE_TIMEOUT_SECONDS`、`MAIL_POLL_SECONDS`
- `AUTOMATION_BROWSER_RETRIES`、`AUTOMATION_CHALLENGE_TIMEOUT_SECONDS`
- `AUTOMATION_RETRY_FOREVER`、`AUTOMATION_RETRY_BACKOFF_SECONDS`、`AUTOMATION_CDP_URL`
- `OUTLOOK_WEBMAIL_ENABLED`

默认值面向 NAS + 代理环境，所有秘密仍只放在 `.env` 或本地加密数据库中。

## 4. 验收标准

### 自动化功能

- 备注解析单元测试覆盖中英文标签、特殊字符密码、TOTP URI、缺字段和账号邮箱不一致。
- 模拟 IMAP 邮件可以稳定提取新验证码，旧验证码和无关邮件会被忽略。
- 模拟浏览器页面可以走完登录、邮箱验证码、TOTP、授权确认和 callback 状态机；挑战页会等待并触发有头重试。
- 账号 `222` 自动完成 OAuth，原 Sub2API 账号凭据被更新，状态检查通过，状态恢复为 healthy/schedulable，任务为 succeeded。
- 账号 `269` 因备注不完整不执行自动登录，不读取或尝试使用不存在的凭据。

### 安全与稳定性

- 全部测试、Ruff、Python 编译、Compose 配置检查通过。
- 日志和 Dashboard 不出现密码、邮箱密码、TOTP、验证码、authorization code、state、access token 或 refresh token。
- 容器重启后任务锁、SQLite WAL、加密凭据和任务状态可恢复。
- Docker API 健康检查通过，worker 持续运行，代理可访问 Sub2API、OpenAI OAuth 和邮箱服务。

## 5. 部署验收顺序

1. 先备份现有 `data/recovery.db`，再更新镜像。
2. 执行本地测试和静态检查。
3. 重建并启动 `recovery-api`、`recovery-worker`。
4. 通过健康接口和 Dashboard 登录验证服务。
5. 触发目标账号自动恢复，观察任务阶段和脱敏日志。
6. 通过 Sub2API Admin API 只验证目标账号的状态、token 存在性、测试结果和调度状态，不输出秘密值。
7. 记录验收结果、失败原因和后续运维命令。

## 6. 风险与处理

- OpenAI 或 Outlook 页面改版：选择器采用多级回退，并把未知页面保存为脱敏阶段错误；下一版只需更新页面适配器。
- Cloudflare/CAPTCHA 要求真人交互：自动化会使用真实浏览器等待和有限重试，但不伪造或绕过安全检查；若服务方明确要求真人动作，任务会保留现场并报告需要的外部条件。
- 本次线上验收中，账号 `222` 的邮箱提交请求被 OpenAI `/api/accounts/authorize/continue` 返回 HTTP 403；服务已完成无头和 Xvfb 有头重试，并将原因记录为 `security_challenge`。这不是备注、邮箱密码、GPT 密码或 TOTP 解析失败，待上游风控/出口条件恢复后可从 Dashboard 重试。
- 对可重试的浏览器安全挑战、403/429 和网络故障，worker 会把同一任务以退避方式重新排队；`AUTOMATION_RETRY_FOREVER=true` 时不再把这类故障标记成永久 `automation_blocked`。备注缺字段仍保持永久跳过。
- Outlook IMAP 禁止密码登录：自动切换 Webmail provider；若邮箱本身需要 MFA，则按“邮箱无法自动访问”分类，不把 GPT 账号标记为已恢复。
- OAuth 身份不一致：拒绝写回，保护原账号不被其他账号凭据覆盖。
