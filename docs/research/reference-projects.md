# 参考项目研究

研究时间：2026-09-16。以下项目只用于核对公开实现的边界、错误处理和工程形态；没有复制未经官方确认的注册、验证码绕过、Cloudflare 绕过或批量账号操作逻辑。

## 7shi/codex-oauth

快照：`dd156ea57f618d138e2f8e091c04e00cccf3cacdc`。

项目 README 明确把它定位成 WHAM/Codex OAuth 的最小 Python 示例，并警告它不是生产认证框架。它确认 `auth.json` 需要保护、默认 callback 是 `localhost:1455`、refresh 前要留安全余量、401 后只重试一次。其 account id 提取策略（id token 优先、OpenAI auth namespace、organization fallback）被本项目用于字段兼容，但 token 永久存储改用 AES-GCM SQLite。

## tiantianGPU/reg-factory

快照：`4b9bc0659e0edf2a4f5ba3179d0c3972e23e1c33`。

项目覆盖大量浏览器和邮箱工作流，值得参考的是：Playwright 运行时抽象、邮箱 provider 接口、代理隔离、任务日志和凭据加密边界。它同时包含注册自动化和第三方验证码/接码集成，本项目不采用那些超出恢复任务范围的能力；邮箱验证码和 TOTP 保持在真实 OAuth 页面内完成。

## zc-zhangchen/any-auto-register

快照：`dfc697cb2fd39d14e7489ff306aaed8ad798e3f9`。

项目采用 FastAPI + SQLite + Playwright，并把任务、账号状态、资产和 secret box 分层。可借鉴的是项目分层和本地加密存储的方向；本平台使用自己的最小 schema，避免把注册平台字段或 cookie 池逻辑带入 Sub2API companion。

## 结论

参考项目共同说明了三条工程约束：

1. OAuth session 必须有 state、PKCE verifier、过期时间和单次完成语义。
2. token refresh 要处理 rotation、401 重试和永久 invalid grant。
3. 浏览器自动化应是可选执行器，不能把验证码、MFA、Cloudflare 识别为可绕过的业务步骤。

本项目据此实现了 `oauth_sessions`、加密 credential blob、账号级 lock、可选 Playwright runner 和 dashboard 粘贴 callback 流程。

参考链接：[codex-oauth](https://github.com/7shi/codex-oauth)、[reg-factory](https://github.com/tiantianGPU/reg-factory)、[any-auto-register](https://github.com/zc-zhangchen/any-auto-register)。
