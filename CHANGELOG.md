# Changelog

## 0.1.0 - 2026-09-18

### Phase 1: research

- 完成 Sub2API Admin API、账号字段、OAuth 凭据结构、刷新和测试接口源码核查。
- 完成 OpenAI Codex 当前 PKCE、授权码交换、refresh token rotation、ID token claim 和 callback state 核查。
- 记录参考项目的可复用边界与不采用的高风险自动化做法。

Files: `docs/research/*`

### Phase 2-7: initial implementation

- 建立 FastAPI API、SQLite WAL 数据库、AES-256-GCM 凭据加密和账号级任务锁。
- 实现 Sub2API Admin API client、401/429/403/网络错误分类和安全日志脱敏。
- 实现 native refresh、refresh token fallback、原账号 apply、测试、recover-state、schedulable 恢复。
- 实现 PKCE OAuth session、人工 callback 粘贴流程和可选 Playwright 真实浏览器流程。
- 实现 dashboard、Docker Compose、安装、升级、备份脚本和 NAS 文档。

Files: `app/*`, `Dockerfile`, `docker-compose.yml`, `.env.example`, `install.sh`, `update.sh`, `backup.sh`, `docs/deployment.md`

Validation: unit and API tests are maintained under `tests/`; live Sub2API/OpenAI verification requires a configured deployment and is intentionally not run against production credentials.

### Hardening before handoff

- Added active-account probes for hidden upstream 401s, stale-worker task requeue, and account-level recovery continuity after restart.
- Hardened dashboard session token encoding, OAuth/SSE failure detection, RFC3339 expiry parsing, local MFA/mailbox credential isolation, and Docker proxy inheritance.
- Hardened nested upstream status/OAuth-error classification, SQLite connection closing, event-detail redaction, identity merging across JWTs, and task retry lease cleanup.
- Fixed nested OAuth token error parsing so invalidated refresh tokens enter the manual reauthorization flow instead of retrying as transient failures.
- Added explicit Docker build proxy arguments so dependency, Chromium, and Debian package downloads use the configured NAS egress path.
- Hardened local deployment permissions for `.env`, the SQLite database, and backup files.
- Added regression coverage for these paths; container health and Playwright import were verified with the built image.
- Added note-driven automatic reauthorization: nested account-note parsing, encrypted mailbox/OpenAI/TOTP material, Outlook IMAP/Webmail code retrieval, local TOTP generation, Cloudflare-aware real-browser retries, and automatic OAuth callback completion.
- Accounts without complete note material are marked `automation_blocked` and do not receive automatic recovery tasks.
- Captures HTTP 403/429 responses from the OpenAI authorization continuation endpoint as a redacted `security_challenge` failure instead of reporting only a generic OAuth-flow timeout.
- Live acceptance: account `222` reached the real browser and note-driven flow, but OpenAI returned HTTP 403 at email submission after the configured browser retries; account `269` was blocked because its note is incomplete.

### Dashboard layout

- Removed the duplicate top status bar and redundant console heading block.
- Moved scan and refresh actions into the left navigation.
- Expanded the account and recovery detail workbench to use the viewport height.
- Removed the outer page scrollbar while preserving internal account and detail scrolling.

Validation: `43 passed`; Ruff, Python compile, shell syntax, Compose config, Docker image startup, `/api/v1/healthz`, static index checks, and production Playwright layout checks pass.
