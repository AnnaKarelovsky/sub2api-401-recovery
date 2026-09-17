# Sub2API 源码研究

研究时间：2026-09-16。源码快照：`Wei-Shaw/sub2api` commit `881f3202694c6bc932446931a30c27d9675178b9`。

## 账号模型

源码 `backend/ent/schema/account.go` 和 `backend/internal/service/account.go` 确认账号至少包含：

- `id`, `name`, `platform`, `type`, `status`, `schedulable`
- `credentials` JSONB：平台认证数据
- `extra` JSONB：平台扩展和持久化调度设置
- `error_message`, `temp_unschedulable_until`, `temp_unschedulable_reason`
- `proxy_id`, `group_ids`, `priority`, `concurrency`

OpenAI OAuth 使用 `platform=openai`、`type=oauth`；`setup-token` 也被 Sub2API 视为 OAuth 类账号。账号是否 `status=error` 不是 401 证据，扫描必须阅读错误消息、上游状态和 token 时间。

## 凭据结构

源码 `backend/internal/pkg/openai/oauth.go`、`backend/internal/service/openai_oauth_service.go` 和 OpenAI 账号服务确认 OAuth token 信息使用以下键：

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "id_token": "...",
  "expires_at": 1770000000,
  "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
  "email": "user@example.com",
  "chatgpt_account_id": "...",
  "chatgpt_user_id": "...",
  "organization_id": "...",
  "plan_type": "plus"
}
```

时间字段在不同历史路径可能是 Unix 秒、Unix 毫秒或 RFC3339 字符串；本项目写回 Unix 秒并读取时兼容数字/字符串。Sub2API 的普通 DTO 会通过 `RedactCredentials` 删除 token，只返回 `credentials_status`；不能依赖 `GET /admin/accounts/:id` 获得完整 token。

## Admin API 鉴权和响应

源码 `skills/sub2api-admin/references/admin-cli.md` 和 `backend/internal/pkg/response/response.go` 确认：

- 推荐 `x-api-key: <admin key>`。
- 备选 `Authorization: Bearer <admin JWT>`。
- 成功响应使用 `{ "code": 0, "message": "success", "data": ... }`。
- 失败响应包含 HTTP 状态和 `{code,message,reason,metadata}`。

本项目的 `Sub2APIClient` 同时支持两种认证，但优先使用 `SUB2API_ADMIN_KEY`。

## 使用的端点

源码路由 `backend/internal/server/routes/admin.go` 和 Admin Reference 确认了以下接口：

| 用途 | 方法和路径 |
| --- | --- |
| 列表 | `GET /api/v1/admin/accounts` |
| 详情 | `GET /api/v1/admin/accounts/:id` |
| 完整管理员导出 | `GET /api/v1/admin/accounts/data?ids=:id&include_proxies=false` |
| Sub2API native refresh | `POST /api/v1/admin/accounts/:id/refresh` |
| 账号状态检查 | `GET /api/v1/admin/accounts/:id` |
| 原子应用 OAuth 凭据 | `POST /api/v1/admin/accounts/:id/apply-oauth-credentials` |
| 清理错误和缓存状态 | `POST /api/v1/admin/accounts/:id/recover-state` |
| 恢复调度 | `POST /api/v1/admin/accounts/:id/schedulable` |

完整导出是明确的管理员备份接口，包含凭据，因此本项目只按单个账号请求并立即加密；任何响应、日志和 dashboard 都不输出原文 token。

## apply-oauth-credentials 契约

源码 `backend/internal/handler/admin/account_handler.go` 的 `ApplyOAuthCredentialsRequest` 确认 payload：

```json
{
  "type": "oauth",
  "credentials": {
    "access_token": "...",
    "refresh_token": "...",
    "id_token": "...",
    "expires_at": 1770000000
  },
  "extra": {
    "chatgpt_account_id": "...",
    "plan_type": "plus"
  }
}
```

处理器只接收 `type/credentials/extra`，对 `extra` 做 key 级合并，不覆盖持久化的配额、隐私和会话设置；随后 ClearError 并 invalidate token cache。恢复平台因此始终更新原账号，绝不删除旧账号或创建新账号。

## refresh 和状态检查

`backend/internal/repository/openai_oauth_service.go` 确认 Sub2API native refresh 使用 `application/x-www-form-urlencoded`：`grant_type=refresh_token`、`refresh_token`、`client_id`、`scope`。成功响应可能轮换 `refresh_token`，因此本项目只在响应存在时替换旧值，否则保留旧值。

账号状态检查只读取 Sub2API 账号详情中的 status、error_message 和 credentials_status；不会发送 ChatGPT/Codex 模型请求。

## 401 判定

Sub2API issue #4544 记录了失效 OAuth token 可能让上游 401 被包装成 gateway 502，并保留 `status=active`、`schedulable=true`。因此恢复服务不能只查 `status=error`，而要识别 `401`、`token_revoked`、`token_invalidated`、`invalid_token`、`invalid_grant` 等 OAuth 证据；429、403、代理/超时和未知错误分别保留为其他类别。

上游链接：

- [Sub2API account schema](https://github.com/Wei-Shaw/sub2api/blob/main/backend/ent/schema/account.go)
- [Admin account handler](https://github.com/Wei-Shaw/sub2api/blob/main/backend/internal/handler/admin/account_handler.go)
- [OpenAI OAuth helper](https://github.com/Wei-Shaw/sub2api/blob/main/backend/internal/pkg/openai/oauth.go)
- [OpenAI OAuth repository client](https://github.com/Wei-Shaw/sub2api/blob/main/backend/internal/repository/openai_oauth_service.go)
- [Admin API reference](https://github.com/Wei-Shaw/sub2api/blob/main/skills/sub2api-admin/references/admin-cli.md)
- [401 upstream issue](https://github.com/Wei-Shaw/sub2api/issues/4544)
