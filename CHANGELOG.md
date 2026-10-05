# Changelog

## 0.4.10 - 2026-10-05

### Deleted account detection

- Treats `get_account` HTTP 404 / `account not found` as a deleted Sub2API account.
- Hides retry actions for both newly detected and historical missing-account tasks.
- Keeps historical logs and evidence readable while rejecting backend retry attempts.

## 0.4.9 - 2026-10-05

### Dark theme fixes

- Fixed light backgrounds and low-contrast labels in the settings page action bar and section dividers.
- Styled successful recovery badges for dark mode.
- Preserved access to deleted-account task logs, added a short network retry for transient dashboard failures, and removed retry actions for deleted accounts.

## 0.4.8 - 2026-10-05

### Stale recovery state

- Treats current Sub2API credential metadata as authoritative during scans, avoiding false 401 detection from expired local token metadata.
- Clears stale `自动恢复已阻止` state when the current account check is healthy.

## 0.4.7 - 2026-10-05

### Hide rate-limited accounts

- Removed HTTP 429 accounts from the console and account page display.
- Removed the 429 status filter; rate-limited accounts remain tracked in the backend and reappear after the quota recovers.

## 0.4.6 - 2026-10-05

### Account table layout

- Prevented account status badges from wrapping individual Chinese characters into a vertical layout.

## 0.4.5 - 2026-10-05

### Frontend cache refresh

- Bumped the static asset versions so browsers fetch the translated `限额中` label and its styles after the 429 handling fix.

## 0.4.4 - 2026-10-04

### 429 handling

- Added a dedicated `限额中` account state for upstream HTTP 429 and usage-limit responses.
- 429 accounts no longer enter the 401 recovery queue or browser reauthorization flow.
- Manual recovery is rejected for rate-limited accounts; status checks remain available.
- Added regression coverage for scan classification and manual recovery protection.

## 0.4.3 - 2026-10-04

### Account material synchronization

- Newly discovered Sub2API accounts now read and parse their notes during the first 60-second account scan.
- Already checked accounts are not re-read on every scan; the daily full material sync remains available for note changes.
- Added regression coverage for immediate first-check behavior and updated deployment documentation.
- Reordered Docker build inputs so version or application changes do not invalidate the Chromium download layers.

## 0.4.2 - 2026-10-03

### Licensing and packaging

- Added the Apache License 2.0 and declared it in the Python package metadata.
- Published the license as part of the distribution package and synchronized release references to `v0.4.2`.

## 0.4.1 - 2026-10-03

### Browser recovery and release quality

- Hardened new-account enrollment after email submission by using the active form field first, adding a single submission retry, and allowing slower OAuth responses to complete.
- Added redacted authorization endpoint diagnostics to enrollment failures instead of reporting only a generic timeout.
- Added a sanitized screenshot of a real successful recovery flow to the project documentation.
- Synchronized package, API, installer, and prebuilt Compose versions to `0.4.1`.

## 0.4.0 - 2026-10-02

### Detection and recovery

- Added a low-frequency upstream 401 probe that selects a current text model from each account's `/models` catalog and parses Sub2API's SSE test response for `401` and `token_revoked` errors.
- Limited active probing to one account per scan with a default 30-minute per-account cooldown; passive Admin API state synchronization remains every 60 seconds.
- Added durable upstream-probe timestamps and Dashboard settings for probe enablement, interval, and per-scan limits.

### Dashboard and release packaging

- Stopped the recovery console from rebuilding unchanged screenshot previews during background refreshes, eliminating periodic evidence-image flicker.
- Rewrote the README as a user-facing project guide and added sanitized Dashboard screenshots.
- Updated the prebuilt release Compose file and installer to persist encrypted evidence storage and use the `v0.4.0` image.

Validation: automated tests, Ruff, Python compilation, JavaScript syntax, Docker health, dynamic SSE probe parsing, and Playwright refresh-stability checks passed.

## 0.3.0 - 2026-09-29

### Recovery workflow and operations

- Confirmed Sub2API OAuth 401 responses now start the browser OAuth reauthorization flow directly; native refresh and the old refresh token path are skipped.
- Synced the current Sub2API account-state fields (`error_message`, nested OAuth status, and token error codes) and shortened healthy-account detail polling to 60 seconds.
- Added a low-frequency upstream 401 probe that discovers each account's current text model dynamically, parses Sub2API SSE errors, and limits probing to one account per scan with a 30-minute per-account cooldown.
- Added retry-wait visibility, automatic retry timing, stale-worker recovery, and clearer task-stage reporting in the dashboard.
- Added encrypted screenshots for detected OpenAI account-disabled pages so operators can verify that the failure was classified correctly.
- Added guarded bulk deletion for accounts manually confirmed as disabled; recovery logs and screenshot evidence remain available for audit.
- Moved screenshot evidence to a required persistent host directory and documented the large-volume deployment requirement.

### Dashboard and documentation

- Improved account sorting, status filters, material indicators, log details, evidence previews, and direct-OAuth progress timelines.
- Added runtime configuration profiles and updated the README with deployment, recovery-material, and account-deletion guidance.

Validation: 83 automated tests passed; Ruff, Python compilation, JavaScript syntax, Docker health, worker restart state, and Playwright timeline rendering checks passed.

## 0.2.0 - 2026-09-26

### Account recovery and enrollment

- Added dashboard controls to view and edit account login materials; partial materials can be saved, and only credentials needed by the actual login flow are required.
- Added automatic account enrollment from the dashboard, including OAuth completion and import into the selected Sub2API account.
- Added a daily account-material scan so newly added or changed Sub2API accounts are discovered without checking each one manually.
- Improved recovery progress and failure details for browser authorization, mailbox codes, TOTP verification, and OAuth token refresh.
- Detects OpenAI accounts explicitly marked as deleted or disabled (`account_deactivated`) and reports that status instead of a generic authorization failure.
- Keeps disabled accounts from being incorrectly reset by scheduled scans; added coverage for enrollment, recovery, and worker behavior.
- Fixed overlapping account-list badges and status information in the dashboard.

Validation: automated tests run in the release workflow before the GHCR image is published. Live authorization still depends on upstream account eligibility and may stop at CAPTCHA or other security challenges.

## 0.1.1 - 2026-09-18

### Prebuilt release installation

- Added a GitHub Actions release workflow that tests tagged versions and publishes Docker images to GHCR.
- Added a release-only Compose file that runs the prebuilt image without a local Python or Chromium build.
- Added `install-release.sh` to initialize secrets, pull the release image, and start the service after `.env` is configured.
- Documented the release installation path for new deployments.

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
