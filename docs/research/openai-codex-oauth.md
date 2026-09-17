# OpenAI OAuth / Codex 源码研究

研究时间：2026-09-16。源码快照：`openai/codex` commit `0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`。

## Authorization Code + PKCE

当前 Codex 源码 `codex-rs/login/src/pkce.rs`：

1. 生成 64 个随机字节。
2. `code_verifier = base64url(random_bytes)`，去掉 padding，长度落在 RFC 7636 范围内。
3. `code_challenge = base64url(SHA256(code_verifier))`，使用 `S256`。
4. 生成 32 个随机字节的 state，并在 callback 做完全匹配。

授权端点是 `https://auth.openai.com/oauth/authorize`，当前 Codex `server.rs` 使用：

- `response_type=code`
- Codex client id `app_EMoamEEZ73f0CkXaXp7hrann`
- `redirect_uri=http://localhost:1455/auth/callback`（默认本地流程）
- `scope=openid profile email offline_access api.connectors.read api.connectors.invoke`
- `code_challenge`, `code_challenge_method=S256`, `state`
- `id_token_add_organizations=true`
- `codex_cli_simplified_flow=true`
- `originator=codex_cli_rs`

Sub2API 的旧 helper 也确认了同一 client id、端点和基础 scope，但它生成 hex verifier；本项目跟随当前官方 Codex 的 base64url verifier，并把 scope/client/redirect 全部配置化。

## Token exchange

`codex-rs/login/src/server.rs` 使用 token 端点 `https://auth.openai.com/oauth/token`，发送 URL encoded form：

```text
grant_type=authorization_code
code=<authorization code>
redirect_uri=<same redirect>
client_id=<client id>
code_verifier=<original verifier>
```

响应至少包含 `access_token`、`id_token`、`refresh_token`。项目把 `expires_in` 转换为 Unix 秒 `expires_at`，并保存 token endpoint 返回的新 refresh token。

## Refresh token 和 rotation

`codex-rs/login/src/auth/manager.rs` 确认 refresh 端点仍为 `/oauth/token`。当前 Codex 用 JSON body `{"grant_type":"refresh_token","refresh_token":"...","client_id":"..."}`；服务端可能返回新的 refresh token。若响应没有新 refresh token，客户端保留旧值；若返回 `invalid_grant`、`refresh_token_reused`、`refresh_token_invalidated` 或 session terminated 类错误，则进入人工重新授权。

## ID token / account id

`codex-rs/login/src/server.rs` 在保存 token 时从 JWT payload 读取 `chatgpt_account_id`；`manager.rs` 也会从当前 token data 暴露 account id、email。Sub2API 的 OpenAI helper确认具体 OpenAI claims 位于 `https://api.openai.com/auth` 下，包括：

- `chatgpt_account_id`
- `chatgpt_user_id`
- `chatgpt_plan_type`
- `organizations[].id` 和 `is_default`

本项目只对 token 做 best-effort payload 解码以填充展示和写回字段，不把未验签的 JWT claim 当作授权依据；真正的 token 有效性由 OAuth token endpoint 和 Sub2API account test 验证。

## 代理和安全

Codex 登录 client 支持 route-aware outbound client。平台服务通过 `httpx` 的环境代理变量访问 token endpoint，并支持 Playwright 显式代理。state、PKCE verifier 和 authorization code 都只在加密 session 或内存流程中使用，日志会脱敏。

## 参考链接

- [Codex PKCE implementation](https://github.com/openai/codex/blob/main/codex-rs/login/src/pkce.rs)
- [Codex OAuth callback and token exchange](https://github.com/openai/codex/blob/main/codex-rs/login/src/server.rs)
- [Codex auth manager and refresh endpoint](https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/manager.rs)
- [Codex account protocol](https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/src/protocol/v2/account.rs)
