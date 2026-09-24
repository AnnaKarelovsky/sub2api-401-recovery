# NAS 部署

## 1. 安装

### 使用预构建 Release 镜像（推荐）

部署主机只需要 Docker Engine、Docker Compose v2、`curl` 和 `openssl`。不需要安装 Python
或在本地构建 Chromium：

```bash
mkdir -p sub2api-401-recovery
cd sub2api-401-recovery
curl -fsSL https://raw.githubusercontent.com/AnnaKarelovsky/sub2api-401-recovery/v0.1.1/install-release.sh -o install-release.sh
chmod +x install-release.sh
./install-release.sh
```

首次执行会生成 `.env` 和加密密钥，并拉取对应 Release 的 GHCR 镜像。编辑 `.env` 填写
`SUB2API_BASE_URL`、`SUB2API_ADMIN_KEY`（或 `SUB2API_JWT`）和 `DASHBOARD_PASSWORD`，
然后再次执行 `./install-release.sh`。

升级到新版本时，设置目标版本并重新执行脚本：

```bash
RECOVERY_VERSION=v0.1.1 ./install-release.sh
```

脚本会保留已有 `.env`、`data/` 和 `backups/`。

### 从源码构建

Debian 12 需要 Docker Engine 和 Compose v2。将项目放到 NAS 后执行：

```bash
chmod +x install.sh update.sh backup.sh
./install.sh
```

安装脚本会创建本地 `.env` 并构建镜像。只有在 Sub2API 和 dashboard 必填项已经
配置时才会自动启动 Compose；否则先编辑 `.env`，再执行 `docker compose up -d`。

编辑 `.env` 至少填写：

- `SUB2API_BASE_URL`
- `SUB2API_ADMIN_KEY`（推荐）或 `SUB2API_JWT`
- `DASHBOARD_PASSWORD`
- `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`（如果 NAS 只能通过代理访问外部服务）

`ENCRYPTION_KEY` 和 `DASHBOARD_SECRET` 由安装脚本生成。两者一旦投入使用不要更换，否则历史凭据无法解密、登录会话全部失效。

## 2. 启动与检查

```bash
docker compose up -d
docker compose ps
docker compose logs -f recovery-api recovery-worker
```

控制台默认端口为 `1455`。`recovery-api` 提供 Web API 和 dashboard，`recovery-worker` 负责每 60 秒扫描和执行任务。两个进程共享 `./data/recovery.db`，SQLite WAL 和账号级锁保证同一账号不会并发恢复；worker 启动时会把上一次进程停止后遗留的运行中任务重新排队。

## 3. 代理

`httpx` 请求默认继承 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`。Compose 已将
`host.docker.internal` 映射到 NAS 主机；如果代理只监听 NAS 的 loopback，需让它
监听 Docker 可达的主机地址，并在 `.env` 中使用 `http://host.docker.internal:7890`。
Compose 也会把这些变量传给镜像构建，因此首次安装下载 Python 依赖、Chromium 和 Debian
图形库时也走同一代理。
Playwright 优先使用 `PLAYWRIGHT_PROXY`，未设置时按 `HTTPS_PROXY`、`HTTP_PROXY`、
`ALL_PROXY` 顺序继承。不要把代理账号密码写入任务日志。

默认 OAuth redirect 是 `http://localhost:1455/auth/callback`，与 Codex CLI 的注册 redirect 一致。自动恢复会读取账号 `notes` 中的登录材料，使用真实 Chromium 完成登录、邮箱验证码、TOTP 和 callback。邮箱验证码首选 Outlook IMAP，失败时回退到 Outlook Webmail 浏览器读取。服务不会绕过 Cloudflare、CAPTCHA 或 MFA；它会等待挑战完成，并在无头模式无法通过时用 Xvfb 重新启动真实有头 Chromium。

自动恢复配置：

```dotenv
AUTOMATION_REQUIRE_COMPLETE_NOTES=true
AUTOMATION_BROWSER_RETRIES=2
AUTOMATION_CHALLENGE_TIMEOUT_SECONDS=90
AUTOMATION_RETRY_FOREVER=true
AUTOMATION_RETRY_BACKOFF_SECONDS=900
# Optional: use a dedicated real Chromium exposed through CDP.
AUTOMATION_CDP_URL=
MAIL_IMAP_HOST=outlook.office365.com
MAIL_IMAP_PORT=993
MAIL_IMAP_FOLDER=INBOX
MAIL_CODE_TIMEOUT_SECONDS=150
MAIL_POLL_SECONDS=5
OUTLOOK_WEBMAIL_ENABLED=true
```

缺少登录邮箱或 OpenAI 密码时，账号进入 `automation_blocked`，不会创建可执行的自动登录任务。邮箱密码和 TOTP
属于按页面需要读取的可选材料：没有邮箱验证码时不要求邮箱密码，没有 2FA 页面时不要求 TOTP；如果页面实际
出现对应步骤，任务会在该阶段明确提示缺少材料。浏览器挑战、临时 403/429 和网络故障会按退避重新排队；启用
`AUTOMATION_RETRY_FOREVER=true` 时，worker 会持续自动重试，不会把这类临时故障转成“请手工登录”。容器没有
图形桌面时，自动化仍会通过 Xvfb 启动有头浏览器；只有在运行环境提供可用的 `DISPLAY` 或 VNC 时，才适合把
`PLAYWRIGHT_HEADLESS` 设为 `false`。

如果使用 `AUTOMATION_CDP_URL`，应提供一个专用的真实 Chromium 实例，例如通过 CDP 暴露的 NAS 浏览器；不要直接复用个人浏览器配置目录。CDP 浏览器由外部进程管理，worker 只复用其页面上下文并在完成后关闭自己创建的页面。

手工授权入口仍保留给没有登录必需材料，或自动浏览器在安全挑战中无法继续的运维场景：

```dotenv
PLAYWRIGHT_ENABLED=true
PLAYWRIGHT_HEADLESS=true
```

容器镜像会安装 Chromium 和 Xvfb。自动流程使用真实授权页面，不会绕过登录、邮箱验证码、TOTP、CAPTCHA 或其他验证。浏览器状态机只保存脱敏阶段错误，不会输出页面中的密码、验证码或 token。

## 4. 常用运维

运行参数现在可以在 Dashboard 的“设置”中修改，不必手写 `.env`。敏感参数会用
`ENCRYPTION_KEY` 加密写入 SQLite；保存后 API 立即加载，worker 会在下一轮轮询同步。
“配置存档”可以保存多套完整运行参数并随时切换。只有 `ENCRYPTION_KEY`、数据库路径、
监听地址/端口和 `DASHBOARD_SECRET` 属于启动引导配置，仍需保留在 `.env` 中。

可在 dashboard 中执行手工扫描、恢复和状态检查，命令行备份使用：

```bash
./backup.sh
docker compose restart recovery-worker
docker compose logs --since=10m recovery-worker
```

备份是 SQLite 在线一致性备份，写入 `backups/recovery-*.db`。备份文件包含加密凭据，必须按秘密文件处理；恢复时停止服务，将选定备份复制为 `data/recovery.db`，再启动 compose：

```bash
docker compose down
cp backups/recovery-YYYYMMDDTHHMMSSZ.db data/recovery.db
docker compose up -d
```

不要把 `.env`、`data/`、`backups/` 上传到 Git 或公共存储。

## 5. 升级

```bash
./update.sh
```

脚本先备份数据库，再拉取基础镜像、重新构建并启动。升级后检查两个容器为 `healthy/running`，再在 dashboard 执行一次扫描。Sub2API API 发生版本变化时，先对照 `docs/research/sub2api.md` 中的接口契约，再调整 client。

## 6. 安全边界

- Admin API key 只存在于 `.env`，不会进入前端。
- Web 登录使用环境变量账号和密码，dashboard API 使用签名 bearer token。
- 日志只记录阶段、状态、错误分类和脱敏原因；不会记录密码、token、TOTP、cookie 或 authorization code。
- 备注原文不会写入本地数据库；解析后的邮箱密码、OpenAI 密码和 TOTP 只以 AES-256-GCM 加密形式保存。
- `AUTOMATION_REQUIRE_COMPLETE_NOTES=true` 时，只有缺少登录邮箱或 OpenAI 密码的账号会被自动化前置校验阻止；账号材料可在 Dashboard 的“材料”入口中加密补录。
- 自动恢复只处理明确的 OAuth 认证失败；429、403、网络错误和未知错误不会被误当成 401。
