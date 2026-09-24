# Sub2API 401 Recovery

Sub2API 401 Recovery 是一个独立运行在 Docker 环境中的 Sub2API Companion Service。
它通过 Sub2API Admin API 发现明确的 OAuth 认证失败，优先尝试 token refresh；refresh
token 失效时，读取账号备注中的登录材料，通过真实浏览器完成 OAuth 重新授权，再把新凭据
写回原来的 Sub2API 账号。

项目不修改 Sub2API 源码，不创建替代账号。账号密码、邮箱密码、TOTP/2FA 密钥、OAuth
token 和浏览器材料会使用 AES-256-GCM 加密后保存；Dashboard、API 和日志不会返回这些
敏感值。

## 功能范围

- 通过 Admin API 读取 OpenAI OAuth 和 setup-token 账号。
- 直接读取账号详情判断 401，不通过模型请求测试账号，因此不会因为 `gpt-5.4` 模型不支持而产生测试报错。
- 对明确的 401、`token_revoked`、`invalid_token` 等认证失败自动创建恢复任务。
- 从账号 `notes` 识别邮箱、邮箱密码、OpenAI/GPT 密码和 TOTP/2FA 密钥；也可以直接在 Dashboard 为单个账号补录材料。
- 登录邮箱和 OpenAI/GPT 密码是启动真实 Chromium 自动授权的最低条件；邮箱密码和 TOTP 只在登录页面实际要求对应步骤时才需要。
- 自动完成 PKCE code exchange，将凭据写回原账号，检查状态并恢复调度。
- Dashboard 支持运行配置、配置存档、手动扫描、恢复任务和脱敏日志查看。
- 对临时网络错误、403/429 和浏览器安全挑战按退避策略重试。

## 重要边界

本项目只服务于你有权管理的 Sub2API 和 OpenAI 账号。自动化使用真实授权页面，不绕过
CAPTCHA、Cloudflare、MFA 或其他服务方安全检查；如果上游要求真人完成挑战，任务会保留
脱敏失败原因并按配置重试。缺少启动自动授权所需材料的账号会标记为 `automation_blocked`，不会被
强行执行自动登录。

## 快速开始

### 环境要求

- Linux 主机，或支持 Linux 容器的 Docker Desktop。
- Docker Engine 和 Docker Compose v2。
- 运行环境能访问 Sub2API Admin API、OpenAI 授权服务和账号邮箱服务。
- 如果外部服务只能通过代理访问，代理必须能从 Docker 容器访问。

### 推荐运行配置

自动恢复会启动真实 Chromium，并可能同时进行邮箱 IMAP 轮询，因此建议按下面的配置准备
运行环境：

| 用途 | CPU | 内存 | 可用磁盘 | 说明 |
| --- | --- | --- | --- | --- |
| 仅监控或手动授权 | 1 vCPU | 1 GB | 5 GB | 不运行自动浏览器时的最低建议 |
| 自动恢复的推荐配置 | 2 vCPU | 4 GB | 10 GB SSD | 适合单 worker 按队列逐个恢复账号 |
| 较大账号量或额外浏览器 | 4 vCPU | 8 GB | 20 GB SSD | 为 Chromium、日志和多个浏览器上下文预留余量 |

磁盘需要持久化，并能保存 Docker 镜像、SQLite 数据库和备份。网络不要求固定带宽，
但必须稳定访问 Sub2API、OpenAI 和账号邮箱；如果使用代理，代理出口也必须允许这些连接。

### 安装

#### 使用预构建 Release 安装（推荐）

如果不希望在部署主机上安装 Python、编译依赖或下载 Chromium，可以直接使用 GitHub Release
提供的预构建 Docker 镜像。主机只需要 Docker Engine、Docker Compose v2、`curl` 和
`openssl`：

```bash
mkdir -p sub2api-401-recovery
cd sub2api-401-recovery
curl -fsSL https://raw.githubusercontent.com/AnnaKarelovsky/sub2api-401-recovery/v0.1.1/install-release.sh -o install-release.sh
chmod +x install-release.sh
./install-release.sh
```

首次运行会下载 `docker-compose.release.yml` 和 `.env.example`，生成本地加密密钥，拉取
`ghcr.io/annakarelovsky/sub2api-401-recovery:v0.1.1`，并在 `.env` 缺少必填值时停止。编辑
`.env` 填好 Sub2API 地址、Admin API key 或 JWT、Dashboard 密码后，再次运行脚本即可启动。
数据、备份和 `.env` 都保存在当前目录，不会进入 Docker 镜像。

#### 从源码安装

源码安装适合开发或无法访问 GHCR 的环境，会在本地构建包含 Chromium 的镜像：

```bash
chmod +x install.sh update.sh backup.sh
./install.sh
```

首次运行会创建 `data/` 和 `backups/`，从 `.env.example` 创建 `.env`，自动生成
`ENCRYPTION_KEY`、`DASHBOARD_SECRET`，并构建带 Chromium、Xvfb 和 Python 依赖的本地镜像。

安装脚本不会上传 `.env`，也不会把真实凭据写入镜像。

### 首次 `.env` 配置

首次启动前，至少确认以下值：

```dotenv
SUB2API_BASE_URL=https://your-sub2api.example.com
SUB2API_ADMIN_KEY=your-admin-api-key
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change-to-a-strong-password
```

`SUB2API_ADMIN_KEY` 和 `SUB2API_JWT` 二选一，优先使用 Admin API key。`ENCRYPTION_KEY`
和 `DASHBOARD_SECRET` 会由安装脚本生成，投入使用后不要更换，否则历史加密凭据无法解密，
现有登录会话也会失效。

如果运行环境需要代理，在 `.env` 中配置容器可达的地址，例如：

```dotenv
HTTP_PROXY=http://host.docker.internal:7890
HTTPS_PROXY=http://host.docker.internal:7890
ALL_PROXY=http://host.docker.internal:7890
NO_PROXY=localhost,127.0.0.1,sub2api,host.docker.internal
```

如果代理程序只监听 `127.0.0.1`，Docker 容器通常无法访问它；需要让代理监听 Docker
可达的主机地址。不要把代理用户名和密码发到日志或 GitHub。

### 启动

```bash
docker compose up -d
docker compose ps
curl http://127.0.0.1:1455/api/v1/healthz
```

看到 `recovery-api` 为 `healthy`、`recovery-worker` 为 `Up` 后，在浏览器打开：

```text
http://<部署主机IP>:1455/
```

默认端口为 `1455`，可以通过 `.env` 中的 `APP_PORT` 修改宿主机端口映射。修改端口后，
还要同步调整 `OPENAI_OAUTH_REDIRECT_URI`，并保证 OAuth 回调地址与实际可访问地址一致。

## Dashboard 使用

### 设置运行配置

登录 Dashboard 后点击左侧“运行配置”。可以在页面配置 Sub2API 连接、扫描恢复、浏览器自动
授权、邮箱验证码、网络代理和 Dashboard 登录参数。

保存后 API 立即加载，worker 会在下一轮轮询检测到配置版本变化并同步。敏感字段只显示
“已配置”，不会回填密码或密钥；密码输入框留空表示保持当前值。

登录 Dashboard 后，账号、任务和统计数据会每 10 秒自动刷新；浏览器标签页切到后台时会
暂停请求，回到前台立即刷新，因此通常不需要手动点击“刷新”。worker 默认每 60 秒从
Sub2API 完整同步一次账号集合。一次完整同步成功后，已从 Sub2API 删除的账号会从当前列表
隐藏，但历史任务、日志和加密凭据仍会保留；账号之后重新出现在 Sub2API 时会自动恢复显示。
页面还支持按邮箱、用户名、账号 ID 或任务 ID 搜索，并会显示最近一次同步状态；点击“立即扫描”
后会持续显示扫描进度，直到扫描完成或失败。

以下是启动引导配置，不能在 Dashboard 修改：

- `ENCRYPTION_KEY`
- `DATABASE_PATH`
- `APP_HOST`、`APP_PORT`
- `DASHBOARD_SECRET`

这些值决定数据库位置、端口、加密和登录令牌边界，仍需保留在 `.env` 中。

### 配置存档

配置区顶部的“配置存档”用于保存多套完整运行参数，例如“直连”“家庭代理”“备用代理”。

1. 先在设置表单中填好一套参数。
2. 点击“保存当前配置”，输入唯一的存档名称。
3. 从下拉框选择存档，点击“切换”并确认。
4. 不再需要的存档可以删除。

存档内容使用现有 `ENCRYPTION_KEY` 加密保存到 SQLite，不包含启动引导配置。手动修改设置后，
当前存档会解除激活标记，避免显示的存档名称与实际运行参数不一致。

### 自动恢复工作流

worker 周期性扫描账号：

```text
读取账号详情 -> 识别明确 401 -> 解析 notes -> native/refresh token
-> 真实浏览器 OAuth -> 邮箱验证码/TOTP -> PKCE exchange
-> 写回原账号 -> 状态检查 -> 恢复 schedulable
```

### 自动恢复的必要条件

自动恢复只对满足以下条件的账号生效：

1. Sub2API Admin API 可用，并且账号详情中能读取到原账号的 `notes` 和当前 OAuth 状态。
2. worker 识别到明确的 OAuth 认证失败，例如 401、`token_revoked` 或 `invalid_token`。
   403、429、网络错误和普通业务错误不会被误判为 401。
3. Dashboard 的“自动重新授权”已启用，即 `PLAYWRIGHT_ENABLED=true`，并且运行环境包含
   可用的 Chromium。项目镜像会提供 Chromium 和 Xvfb。
4. 系统能取得启动登录所需的材料：登录邮箱和 OpenAI/GPT 密码。邮箱可来自备注、Dashboard
   的账号材料，或由 Sub2API 账号邮箱字段回退提供。默认 `AUTOMATION_REQUIRE_COMPLETE_NOTES=true`
   现在只阻止缺少这两个启动必需字段的账号，不再要求四项全部填写。
5. 如果 OpenAI 页面实际要求邮箱验证码，系统还需要邮箱密码，并且至少有一种验证码读取方式可用：
   默认的 Outlook IMAP，或启用 Outlook Webmail 兜底。缺少邮箱密码时任务会在 `email_code` 阶段
   明确停止，而不是在恢复前统一阻止。
6. 如果 OpenAI 页面实际要求 2FA，系统还需要 TOTP/2FA 密钥。缺少密钥时任务会在 `totp` 阶段
   明确停止。TOTP 必须是密钥，不是已经生成的 6 位或 8 位一次性验证码。
7. OpenAI 登录密码、TOTP 密钥和邮箱地址属于同一个账号，且当前仍有效。OpenAI 授权页面、邮箱服务
   和 OAuth callback 在浏览器所在环境可访问，且没有持续的 CAPTCHA、Cloudflare 或其他无法由自动化处理的安全挑战。

安全挑战不会被绕过。遇到临时 403/429、网络问题或挑战页面时，worker 会按退避策略持续
重试；如果上游一直要求人工挑战，任务不会被伪造为成功。

#### 推荐备注格式

最稳妥的方式是每个字段单独占一行，使用冒号、等号或空格分隔。中文或英文标签均可：

```text
邮箱: user@example.com
邮箱密码: mailbox-password
GPT密码: openai-password
2FA密钥: JBSWY3DPEHPK3PXP
```

下面这些标签也能被识别：

- 邮箱：`邮箱`、`登录邮箱`、`email`、`e-mail`、`mail`
- 邮箱密码：`邮箱登录密码`、`邮箱密码`、`email password`、`email login password`、`mail password`
- OpenAI 密码：`openai 登录密码`、`openai密码`、`ChatGPT密码`、`GPT密码`、`openai password`、`chatgpt password`、`gpt password`
- TOTP 密钥：`2FA密钥`、`2FA key`、`2FA secret`、`TOTP密钥`、`totp secret`、`authenticator key`

备注中的项目符号或编号可以保留，密码允许包含特殊字符。不要把多个字段写成同一行的逗号
句子，例如“邮箱，邮箱密码，GPT密码，2FA密钥……”，这种格式无法可靠区分字段。每个标签
后面的值应在同一行直接写完；也可以把值放在标签的下一行。

邮箱字段可以省略，系统会在 Sub2API 已返回账号邮箱时使用该邮箱作为回退值；为了避免账号
映射不一致，仍建议在备注中明确写出邮箱。TOTP 密钥可以写标准 Base32，例如
`JBSWY3DPEHPK3PXP`，也可以写完整的 `otpauth://totp/...?...secret=...` URI；系统会自动
提取并校验密钥。

备注也支持完整 JSON，适合由其他系统批量写入：

```json
{
  "email": "user@example.com",
  "email_password": "mailbox-password",
  "openai_password": "openai-password",
  "totp_secret": "JBSWY3DPEHPK3PXP"
}
```

也支持 `mailbox.password`、`gpt.password` 和 `2fa.secret` 这类嵌套字段。JSON 必须是完整
对象，不能在普通文字中间拼接半段 JSON。保存备注后执行 Dashboard 的“立即扫描”，即可
查看系统是否解析出材料。尚未读取备注或手动补录材料的账号会显示 `未检查`，不会被误判为缺少必填；
完成检查后，账号页的“自动登录材料”列会显示 `4/4 完整`、`3/4 可尝试` 或 `缺少必填`。密码和密钥不会显示在 Dashboard 或日志中。

#### 在 Dashboard 补录材料

不想手动修改 Sub2API 备注时，可以在“账号”页面或恢复控制台中点击账号的“材料”按钮。四项可以
分开填写，保存时只更新非空字段，空白字段保持原值不变。这里保存的是本服务自己的加密材料，自动
恢复会把它和 Sub2API 备注中的材料合并使用；不会把密码或 2FA 密钥回显到页面，也不会写入恢复日志。

页面中的判断含义如下：

- `未检查`：账号备注尚未被本服务读取，也没有在 Dashboard 中补录材料；这不是材料缺失结论。
- `4/4 完整`：四项都有，遇到邮箱验证码或 2FA 时都可以继续。
- `3/4 可尝试`：登录邮箱和 OpenAI 密码已有，浏览器可以启动；缺少的字段只有在对应页面出现时才会成为阻断原因。
- `缺少必填`：缺少登录邮箱或 OpenAI 密码，自动浏览器不会启动。

状态检查只读取 Sub2API 的账号详情接口 `/api/v1/admin/accounts/{id}`，不会调用模型，也不会发送
`gpt-5.4` 测试请求。恢复成功后任务阶段通常会依次显示 `reauthorization`、`apply_credentials`、
`status_check`、`recover_state`、`succeeded`。

## 自动化配置建议

首次启用自动授权时，在 Dashboard 的“自动重新授权”中确认：

```dotenv
PLAYWRIGHT_ENABLED=true
PLAYWRIGHT_HEADLESS=true
PLAYWRIGHT_TIMEOUT_SECONDS=600
AUTOMATION_REQUIRE_COMPLETE_NOTES=true
AUTOMATION_BROWSER_RETRIES=2
AUTOMATION_CHALLENGE_TIMEOUT_SECONDS=90
AUTOMATION_RETRY_FOREVER=true
AUTOMATION_RETRY_BACKOFF_SECONDS=900
MAIL_IMAP_HOST=outlook.office365.com
MAIL_IMAP_PORT=993
MAIL_IMAP_FOLDER=INBOX
MAIL_CODE_TIMEOUT_SECONDS=150
MAIL_POLL_SECONDS=5
OUTLOOK_WEBMAIL_ENABLED=true
```

邮箱验证码优先通过 Outlook IMAP 获取，失败时可以回退到 Outlook Webmail。若邮箱本身需要
额外 MFA，自动流程可能无法完成邮箱访问。无桌面服务器建议保持 `PLAYWRIGHT_HEADLESS=true`，
镜像会在需要时使用 Xvfb 运行真实有头 Chromium 重试。

如果使用专用浏览器 CDP：

```dotenv
AUTOMATION_CDP_URL=http://host.docker.internal:9222
```

CDP 浏览器应由独立进程管理，不要直接复用个人 Chrome 配置目录。

## 常用运维

查看状态和日志：

```bash
docker compose ps
docker compose logs --tail=100 recovery-api recovery-worker
docker compose logs -f recovery-worker
```

备份数据库：

```bash
./backup.sh
ls -lh backups/
```

备份是 SQLite 在线一致性备份，包含加密后的账号凭据，必须按秘密文件保护。恢复备份：

```bash
docker compose down
cp backups/recovery-YYYYMMDDTHHMMSSZ.db data/recovery.db
docker compose up -d
docker compose ps
```

升级：

```bash
./update.sh
docker compose ps
```

`update.sh` 会先备份数据库，再重新构建镜像并启动服务。升级不会删除 `data/`、`backups/`
或 Dashboard 配置存档。

## 故障排查

### Dashboard 无法登录

确认 `.env` 中的 `DASHBOARD_USERNAME`、`DASHBOARD_PASSWORD` 和 `DASHBOARD_SECRET`，再重启 API：

```bash
docker compose restart recovery-api
```

修改 Dashboard 登录密码后，旧 bearer session 可能仍在浏览器 localStorage 中；退出后重新登录，
必要时清理站点存储。

### Sub2API 连接失败

检查地址、Admin key/JWT 和代理是否能从容器访问，并查看 worker 日志：

```bash
docker compose logs --tail=100 recovery-worker
```

不要只根据 `status=error` 判断 401。项目会读取账号详情中的 HTTP 状态和错误文本，429、403、
网络错误和未知错误会保留为其他分类。

### 账号显示 `automation_blocked`

这表示当前账号缺少启动自动授权所需的登录邮箱或 OpenAI 密码，或者上一次自动授权已经在邮箱验证码
或 2FA 阶段明确停止。打开账号的“材料”编辑框补录缺失字段后，执行“立即扫描”或点击“重新尝试”。

### 任务显示 `security_challenge`、403 或超时

这通常是上游安全挑战、出口信誉、临时限流或页面变化，不等同于账号密码解析失败。先检查
代理出口和浏览器配置，再在 Dashboard 重试；开启持续重试时 worker 会按退避时间自动再次处理。

### 找不到设置或存档

浏览器可能缓存了旧版静态资源。执行强制刷新：

```text
Windows/Linux: Ctrl + F5
macOS: Command + Shift + R
```

然后确认：

```bash
curl -fsS http://127.0.0.1:1455/api/v1/healthz
docker compose ps
```

## 安全与备份边界

- `.env` 权限应为 `600`，`data/` 和 `backups/` 权限应为 `700`。
- `.env`、`data/`、`backups/`、SQLite WAL 文件和日志不得上传 GitHub 或公共存储。
- Admin API key、Dashboard 密码、账号备注原文和 OAuth token 不应写入 issue、截图或日志。
- SQLite 中的敏感值依赖 `ENCRYPTION_KEY` 解密；数据库备份和 `.env` 必须一起安全保存。
- 不要把 `ENCRYPTION_KEY`、`DASHBOARD_SECRET` 或真实 `.env` 提交到 Git。

## 开发与验证

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
.venv/bin/ruff check app tests
.venv/bin/python -m compileall -q app
node --check app/static/app.js
docker compose config --quiet
```

当前测试覆盖配置接口、加密存档、账号状态判断、备注解析、OAuth、邮箱验证码、TOTP、任务编排
和安全边界。真实 Sub2API/OpenAI 恢复验证必须在你自己的已授权部署中进行。

## 项目结构

```text
app/                         FastAPI、worker、恢复编排和 Dashboard
app/static/                  Dashboard 页面、样式和脚本
tests/                       单元测试与 API 测试
docs/deployment.md           通用部署和运维细节
docs/research/               上游接口与 OAuth 研究记录
.env.example                 不含秘密的配置模板
docker-compose.yml           API/worker 双容器部署
install.sh                   首次安装
update.sh                    备份、构建和升级
backup.sh                    SQLite 在线备份
```
