from __future__ import annotations

import threading
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .automatic_browser import AutomaticBrowserError, AutomaticOAuthRunner
from .browser import PlaywrightOAuthRunner
from .classifier import Classification, FailureClass, classify_account_snapshot, classify_failure
from .config import Settings
from .db import Database
from .note_credentials import NoteCredentials, parse_account_notes
from .oauth import OAuthError, OpenAIOAuthClient, TokenSet, build_authorization_url, generate_pkce
from .redaction import safe_error
from .sub2api import AccountTestResult, Sub2APIClient, Sub2APIError
from .totp import TOTPError


class RecoveryFailure(Exception):
    def __init__(
        self,
        reason: str,
        *,
        classification: Classification | None = None,
        retryable: bool = False,
        needs_reauthorization: bool = False,
        technical_detail: dict[str, Any] | None = None,
    ):
        super().__init__(reason)
        self.reason = safe_error(reason)
        self.classification = classification or classify_failure(message=reason)
        self.retryable = retryable
        self.needs_reauthorization = needs_reauthorization
        self.technical_detail = dict(technical_detail or {})


@dataclass(frozen=True)
class RecoveryRuntime:
    db: Database
    sub2api: Sub2APIClient
    oauth: OpenAIOAuthClient
    settings: Settings


class RecoveryCoordinator:
    def __init__(self, runtime: RecoveryRuntime):
        self.runtime = runtime
        self.db = runtime.db
        self.sub2api = runtime.sub2api
        self.oauth = runtime.oauth
        self.settings = runtime.settings
        self.browser = PlaywrightOAuthRunner(runtime.settings)
        self.automatic_browser = AutomaticOAuthRunner(runtime.settings)
        self._scan_lock = threading.Lock()

    def reconfigure(self, sub2api: Sub2APIClient, oauth: OpenAIOAuthClient) -> None:
        """Swap clients after Dashboard settings were reloaded."""
        self.sub2api = sub2api
        self.oauth = oauth
        self.runtime = RecoveryRuntime(self.db, sub2api, oauth, self.settings)
        self.browser = PlaywrightOAuthRunner(self.settings)
        self.automatic_browser = AutomaticOAuthRunner(self.settings)

    def scan(self, *, source: str = "worker") -> dict[str, int]:
        if not self._scan_lock.acquire(blocking=False):
            self.db.record_event(
                "scan_skipped",
                "Account scan skipped because another scan is already running",
                {"source": source},
            )
            return {"skipped": 1}
        try:
            self.db.record_event("scan_started", "Sub2API account scan started", {"source": source})
            accounts = self.sub2api.list_accounts()
            found = queued = auth_failures = 0
            remote_account_ids: set[int] = set()
            for raw in accounts:
                snapshot = normalize_snapshot(raw)
                account_id = snapshot.get("sub2api_account_id")
                if not account_id:
                    continue
                found += 1
                remote_account_ids.add(int(account_id))
                self.db.upsert_account_snapshot(snapshot)
                current = self.db.get_mapping(int(account_id)) or {}
                local_credentials = self.db.load_credentials(int(account_id))
                classification_snapshot = dict(raw)
                merged_credentials = dict(raw.get("credentials") or {})
                merged_credentials.update(local_credentials)
                classification_snapshot["credentials"] = merged_credentials
                classification = classify_account_snapshot(classification_snapshot)
                if current.get("status") == "account_disabled":
                    continue
                if classification and classification.category == FailureClass.AUTH_FAILURE:
                    auth_failures += 1
                    try:
                        previous_material = self._material_from_credentials(
                            local_credentials,
                            str(current.get("email") or ""),
                        )
                        material = self._sync_note_material(int(account_id), raw)
                    except Sub2APIError as exc:
                        self.db.record_event(
                            "account_notes_sync_failed",
                            "Could not read account note credentials",
                            {"account_id": int(account_id), "reason": safe_error(exc)},
                        )
                        material = self._material_from_credentials(local_credentials, current.get("email", ""))
                    if self.settings.automation_require_complete_notes and not material.ready_for_automation:
                        self._block_automation(
                            int(account_id),
                            classification,
                            _automation_block_reason(material),
                        )
                        continue
                    if self._suppress_unchanged_blocked_retry(current, previous_material, material):
                        continue
                    task_id, created = self.enqueue_recovery(
                        int(account_id),
                        trigger="automatic-scan",
                        classification=classification,
                        force=True,
                    )
                    queued += int(created)
                    if created:
                        self.db.append_log(
                            task_id,
                            level="INFO",
                            stage="scan",
                            message="Detected an OAuth authentication failure and queued recovery",
                            detail={"classification": classification.category.value},
                        )
                elif classification:
                    self.db.update_account_state(
                        int(account_id),
                        status=(
                            "account_error"
                            if classification.category == FailureClass.ACCOUNT_ERROR
                            else "observed"
                        ),
                        failure_class=classification.category.value,
                        failure_reason=classification.reason,
                    )
                elif snapshot.get("status") in {"active", "healthy"}:
                    if current and current.get("status") == "unknown":
                        self.db.update_account_state(
                            int(account_id), status="healthy", failure_class=None, failure_reason=None
                        )
                    if self._probe_due(current.get("last_test_at")):
                        probe = self.sub2api.inspect_account(int(account_id))
                        probe_is_auth = bool(
                            probe.classification
                            and probe.classification.category == FailureClass.AUTH_FAILURE
                        )
                        self.db.update_account_state(
                            int(account_id),
                            status="healthy" if probe.success else ("auth_failed" if probe_is_auth else "observed"),
                            failure_class=(
                                probe.classification.category.value if probe.classification else None
                            ),
                            failure_reason=None if probe.success else probe.reason,
                            mark_401=probe_is_auth,
                            mark_test=True,
                        )
                        if probe_is_auth:
                            auth_failures += 1
                            previous_material = self._material_from_credentials(
                                local_credentials,
                                str(current.get("email") or ""),
                            )
                            material = self._sync_note_material(int(account_id), {})
                            if self.settings.automation_require_complete_notes and not material.ready_for_automation:
                                self._block_automation(
                                    int(account_id),
                                    probe.classification,
                                    _automation_block_reason(material),
                                )
                                continue
                            if self._suppress_unchanged_blocked_retry(current, previous_material, material):
                                continue
                            task_id, created = self.enqueue_recovery(
                                int(account_id),
                                trigger="automatic-probe",
                                classification=probe.classification,
                                force=True,
                            )
                            queued += int(created)
                            if created:
                                self.db.append_log(
                                    task_id,
                                    level="INFO",
                                    stage="probe",
                                    message="Account test detected an OAuth authentication failure",
                                    detail={"classification": probe.classification.category.value},
                                )
            removed = self.db.mark_accounts_missing(remote_account_ids)
            result = {"found": found, "auth_failures": auth_failures, "queued": queued, "removed": removed}
            self.db.record_event("scan_completed", "Sub2API account scan completed", result)
            return result
        except Sub2APIError as exc:
            self.db.record_event("scan_failed", "Sub2API account scan failed", {"reason": safe_error(exc)})
            raise
        except Exception as exc:
            self.db.record_event("scan_failed", "Sub2API account scan failed", {"reason": safe_error(exc)})
            raise
        finally:
            self._scan_lock.release()

    def sync_materials(self, *, source: str = "worker-daily") -> dict[str, int]:
        """Read every remote account note and refresh local automation-material status."""
        if not self._scan_lock.acquire(blocking=False):
            self.db.record_event(
                "materials_sync_skipped",
                "Account material sync skipped because another account operation is already running",
                {"source": source},
            )
            return {"skipped": 1}
        try:
            self.db.record_event("materials_sync_started", "Account material sync started", {"source": source})
            accounts = self.sub2api.list_accounts()
            found = checked = failed = 0
            remote_account_ids: set[int] = set()
            for raw in accounts:
                snapshot = normalize_snapshot(raw)
                account_id = snapshot.get("sub2api_account_id")
                if not account_id:
                    continue
                found += 1
                account_id = int(account_id)
                remote_account_ids.add(account_id)
                self.db.upsert_account_snapshot(snapshot)
                try:
                    self._sync_note_material(account_id, raw)
                except Exception as exc:
                    failed += 1
                    self.db.record_event(
                        "account_notes_sync_failed",
                        "Could not read account note credentials during material sync",
                        {"account_id": account_id, "reason": safe_error(exc)},
                    )
                else:
                    checked += 1
            removed = self.db.mark_accounts_missing(remote_account_ids)
            result = {"found": found, "checked": checked, "failed": failed, "removed": removed}
            self.db.record_event("materials_sync_completed", "Account material sync completed", result)
            return result
        except Exception as exc:
            self.db.record_event(
                "materials_sync_failed",
                "Account material sync failed",
                {"reason": safe_error(exc)},
            )
            raise
        finally:
            self._scan_lock.release()

    def _probe_due(self, last_test_at: Any) -> bool:
        if not self.settings.scan_probe_active_accounts:
            return False
        if not last_test_at:
            return True
        try:
            parsed = datetime.fromisoformat(str(last_test_at))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) - parsed >= timedelta(
                seconds=self.settings.scan_probe_interval_seconds
            )
        except (TypeError, ValueError):
            return True

    def enqueue_recovery(
        self,
        account_id: int,
        *,
        trigger: str,
        classification: Classification | None = None,
        force: bool = False,
    ) -> tuple[str, bool]:
        task_id, created = self.db.create_task(account_id, trigger=trigger, force=force)
        self.db.update_account_state(
            account_id,
            status="recovering" if created or force else "auth_failed",
            failure_class=classification.category.value if classification else None,
            failure_reason=classification.reason if classification else None,
            mark_401=bool(classification and classification.category == FailureClass.AUTH_FAILURE),
        )
        return task_id, created

    def enqueue_account_enrollment(
        self,
        *,
        email: str,
        email_password: str,
        openai_password: str,
        totp_secret: str = "",
        name: str = "",
    ) -> dict[str, Any]:
        normalized_email = email.strip().lower()
        if "@" not in normalized_email or len(normalized_email) > 320:
            raise ValueError("登录邮箱格式无效")
        if not openai_password.strip():
            raise ValueError("OpenAI 密码不能为空")
        pkce = generate_pkce()
        enrollment_id = str(uuid.uuid4())
        display_name = name.strip() or normalized_email
        self.db.create_account_enrollment(
            {
                "id": enrollment_id,
                "email": normalized_email,
                "name": display_name,
                "auth_url": build_authorization_url(self.settings, pkce),
                "state": pkce.state,
                "code_verifier": pkce.code_verifier,
                "materials": NoteCredentials(
                    email=normalized_email,
                    email_password=email_password,
                    openai_password=openai_password,
                    totp_secret=totp_secret,
                ).as_dict(),
            }
        )
        return self.db.get_account_enrollment(enrollment_id) or {}

    def process_one_account_enrollment(self) -> bool:
        enrollment = self.db.claim_next_account_enrollment()
        if not enrollment:
            return False
        self.execute_account_enrollment(enrollment)
        return True

    def execute_account_enrollment(self, enrollment: dict[str, Any]) -> None:
        enrollment_id = str(enrollment["id"])
        email = str(enrollment["email"]).strip().lower()
        display_name = str(enrollment["name"])
        current_stage = "starting"

        def on_stage(stage: str, message: str) -> None:
            nonlocal current_stage
            current_stage = stage
            self.db.update_account_enrollment_stage(
                enrollment_id, stage=stage, message=message
            )

        def fail(stage: str, reason: str, *, skipped: bool = False) -> None:
            self.db.finish_account_enrollment(
                enrollment_id,
                status="skipped" if skipped else "failed",
                stage=stage,
                message=reason,
                error_reason=None if skipped else reason,
            )

        try:
            if not self.settings.playwright_enabled:
                fail("browser", "未启用浏览器自动授权，请在运行配置中启用后重新提交。")
                return
            material_values = enrollment.get("materials") or {}
            material = self._material_from_credentials(material_values, email)
            on_stage("credentials", "已读取加密保存的登录材料；邮箱验证码和 2FA 将按登录页要求使用。")
            started_at = datetime.now(timezone.utc)
            on_stage("browser", "正在启动 OpenAI OAuth 自动登录。")
            callback_url = self.automatic_browser.run(
                str(enrollment["auth_url"]),
                material,
                started_at=started_at,
                on_stage=on_stage,
            )
            on_stage("callback", "已收到 OAuth 回调，正在校验 state。")
            parsed_callback = urllib.parse.urlparse(callback_url)
            callback_query = urllib.parse.parse_qs(parsed_callback.query)
            callback_state = _first(callback_query, "state")
            if not callback_state or not hmac_compare(callback_state, str(enrollment["state"])):
                fail("callback", "OAuth state 校验失败，未创建账号。")
                return
            callback_error = _first(callback_query, "error")
            if callback_error:
                description = _first(callback_query, "error_description")
                reason = safe_error(description or callback_error)
                fail("callback", f"OpenAI OAuth 授权未完成：{reason}")
                return
            code = _first(callback_query, "code")
            if not code:
                fail("callback", "OAuth 回调中没有授权码，未创建账号。")
                return
            verifier = str(enrollment.get("code_verifier") or "")
            if not verifier:
                fail("token_exchange", "PKCE 校验器不可用，未创建账号。")
                return

            on_stage("token_exchange", "正在使用 PKCE 授权码交换 OAuth 凭据。")
            token_set = self.oauth.exchange_code(
                code=code,
                code_verifier=verifier,
                redirect_uri=self.settings.openai_oauth_redirect_uri,
            )
            on_stage("identity_check", "正在确认 OAuth 返回的邮箱与填写邮箱一致。")
            if not token_set.refresh_token:
                fail("token_exchange", "OAuth 响应没有 refresh token，未创建账号。")
                return
            returned_email = token_set.email.strip().lower()
            if not returned_email or returned_email != email:
                fail(
                    "identity_check",
                    "OAuth 返回的邮箱与填写邮箱不一致或为空，已阻止创建错误账号。",
                )
                return

            on_stage("duplicate_check", "正在检查 Sub2API 中是否已有相同邮箱的账号。")
            remote_accounts = self.sub2api.list_accounts()
            for remote in remote_accounts:
                credentials = remote.get("credentials") if isinstance(remote.get("credentials"), dict) else {}
                remote_email = str(remote.get("email") or credentials.get("email") or "").strip().lower()
                if remote_email == email:
                    remote_id = normalize_snapshot(remote).get("sub2api_account_id")
                    fail(
                        "duplicate_check",
                        f"Sub2API 已存在该邮箱账号（ID {remote_id or '未知'}），未重复创建。",
                        skipped=True,
                    )
                    return

            on_stage("create_account", "OAuth 已验证，正在向 Sub2API 创建新账号。")
            credentials = token_set.as_credentials()
            created = self.sub2api.create_account(
                {
                    "name": display_name,
                    "platform": "openai",
                    "type": "oauth",
                    "credentials": credentials,
                    "extra": _credential_extra(token_set),
                }
            )
            account_data = created.get("account") if isinstance(created.get("account"), dict) else created
            account_id = normalize_snapshot(account_data).get("sub2api_account_id")
            if not account_id:
                matches = self.sub2api.list_accounts()
                for remote in matches:
                    remote_credentials = remote.get("credentials") if isinstance(remote.get("credentials"), dict) else {}
                    remote_email = str(remote.get("email") or remote_credentials.get("email") or "").strip().lower()
                    if remote_email == email:
                        account_id = normalize_snapshot(remote).get("sub2api_account_id")
                        account_data = remote
                        break
            if not account_id:
                fail(
                    "create_account",
                    "Sub2API 已返回创建结果，但没有找到新账号 ID；请执行一次账号扫描确认是否已创建。",
                )
                return

            snapshot = dict(account_data)
            snapshot.setdefault("id", account_id)
            snapshot.setdefault("name", display_name)
            snapshot.setdefault("email", email)
            snapshot.setdefault("type", "oauth")
            self.db.upsert_account_snapshot(normalize_snapshot(snapshot))
            self.db.save_credentials(
                int(account_id), credentials, email=email, username=display_name
            )
            if material.as_dict():
                self.db.save_account_material(int(account_id), material.as_dict())
            self.db.mark_materials_checked(int(account_id))
            self.db.finish_account_enrollment(
                enrollment_id,
                status="succeeded",
                stage="completed",
                message=f"账号已创建并同步到 Sub2API，ID {account_id}。",
                sub2api_account_id=int(account_id),
            )
        except AutomaticBrowserError as exc:
            fail(exc.stage, safe_error(exc))
        except OAuthError as exc:
            fail("token_exchange", safe_error(exc))
        except Sub2APIError as exc:
            fail(current_stage, safe_error(exc))
        except Exception as exc:
            fail(current_stage, safe_error(exc))

    def process_one(self, worker_id: str) -> bool:
        task = self.db.claim_next_task(worker_id)
        if not task:
            return False
        self.execute_task(task)
        return True

    def execute_task(self, task: dict[str, Any]) -> None:
        task_id = str(task["id"])
        account_id = int(task["sub2api_account_id"])
        lock_token = self.db.acquire_account_lock(account_id, ttl_seconds=600)
        if not lock_token:
            self._retry_task(task, "Account is already being recovered by another worker")
            return
        try:
            self._execute_locked(task_id, account_id, task)
        except RecoveryFailure as exc:
            technical_detail = {
                "classification": exc.classification.category.value,
                "raw_reason": exc.reason,
                **exc.technical_detail,
            }
            self.db.append_log(
                task_id,
                level="ERROR",
                stage=str(self.db.get_task(task_id).get("stage") if self.db.get_task(task_id) else "recovery"),
                message=exc.reason,
                detail=technical_detail,
            )
            if exc.needs_reauthorization:
                self._mark_manual_required(
                    task_id,
                    account_id,
                    exc.reason,
                    exc.classification,
                    attempt=int(task.get("attempt") or 1),
                )
            elif exc.retryable and int(task.get("attempt") or 1) < self.settings.recovery_max_attempts:
                self._retry_task(task, exc.reason)
            else:
                self.db.finish_task(
                    task_id,
                    status="failed",
                    stage="failed",
                    failure_class=exc.classification.category.value,
                    error_reason=exc.reason,
                )
                self.db.update_account_state(
                    account_id,
                    status="auth_failed" if exc.classification.category == FailureClass.AUTH_FAILURE else "failed",
                    failure_class=exc.classification.category.value,
                    failure_reason=exc.reason,
                )
        except Exception as exc:
            reason = safe_error(exc)
            self.db.append_log(
                task_id,
                level="ERROR",
                stage="recovery",
                message=reason,
                detail={"exception_type": type(exc).__name__, "raw_reason": reason},
            )
            if int(task.get("attempt") or 1) < self.settings.recovery_max_attempts:
                self._retry_task(task, reason)
            else:
                self.db.finish_task(task_id, status="failed", stage="failed", error_reason=reason)
                self.db.update_account_state(
                    account_id, status="failed", failure_class=FailureClass.UNKNOWN.value, failure_reason=reason
                )
        finally:
            self.db.release_account_lock(account_id, lock_token)

    def _execute_locked(self, task_id: str, account_id: int, task: dict[str, Any]) -> None:
        mapping = self.db.get_mapping(account_id)
        if not mapping:
            raise RecoveryFailure("Account mapping does not exist", retryable=False)
        try:
            self._sync_note_material(account_id, {})
        except Sub2APIError as exc:
            raise RecoveryFailure(
                safe_error(exc),
                classification=exc.classification,
                retryable=exc.retryable,
                technical_detail=_sub2api_technical_detail(exc),
            ) from exc
        credentials = self.db.load_credentials(account_id)
        if not credentials.get("refresh_token") or not credentials.get("access_token"):
            self._log(task_id, "sync", "Fetching the selected account's encrypted credential export")
            self.db.set_task_stage(task_id, "sync")
            self._sync_account_credentials(account_id)
            credentials = self.db.load_credentials(account_id)

        oauth_session_id = str(task.get("auth_session_id") or "")
        oauth_session = self.db.get_oauth_session(oauth_session_id) if oauth_session_id else None
        if oauth_session and oauth_session.get("status") == "completed":
            self._apply_credentials_and_finish(
                task_id,
                account_id,
                mapping,
                credentials,
                method="automatic OAuth reauthorization",
            )
            return

        # Prefer Sub2API's own refresh implementation; it knows its internal cache and
        # provider-specific state. A successful native refresh is checked before fallback.
        self.db.set_task_stage(task_id, "native_refresh")
        self._log(task_id, "native_refresh", "Requesting Sub2API native OAuth refresh")
        try:
            self.sub2api.native_refresh(account_id)
            native_status = self._status_check(account_id, task_id, "native_refresh")
            if native_status.success:
                self._sync_account_credentials(account_id)
                self._finish_success(task_id, account_id, "native refresh")
                return
            self._log(task_id, "native_refresh", "Native refresh did not pass account status check", native_status)
        except Sub2APIError as exc:
            self._log(task_id, "native_refresh", "Native refresh failed; trying local refresh", exc)

        refresh_token = str(credentials.get("refresh_token") or "").strip()
        if not refresh_token:
            raise RecoveryFailure(
                "No refresh token is available for this account",
                classification=Classification(FailureClass.AUTH_FAILURE, "refresh token missing", True, True),
                needs_reauthorization=True,
                technical_detail={"error_code": "missing_refresh_token", "reauthorization_required": True},
            )

        self.db.set_task_stage(task_id, "refresh_token")
        self._log(task_id, "refresh_token", "Refreshing the OAuth token with rotation-safe handling")
        try:
            token_set = self.oauth.refresh_token(refresh_token, previous=credentials)
        except OAuthError as exc:
            if exc.reauth_required:
                raise RecoveryFailure(
                    safe_error(exc),
                    classification=Classification(FailureClass.AUTH_FAILURE, safe_error(exc), True, True),
                    needs_reauthorization=True,
                    technical_detail=_oauth_technical_detail(exc),
                ) from exc
            raise RecoveryFailure(
                safe_error(exc),
                retryable=True,
                technical_detail=_oauth_technical_detail(exc),
            ) from exc
        if not token_set.access_token:
            raise RecoveryFailure(
                "OAuth refresh returned no access token",
                retryable=True,
                technical_detail={"error_code": "missing_access_token"},
            )
        credentials.update(token_set.as_credentials())
        if not credentials.get("refresh_token"):
            raise RecoveryFailure(
                "OAuth refresh returned no refresh token",
                classification=Classification(FailureClass.AUTH_FAILURE, "refresh token missing after refresh", True, True),
                needs_reauthorization=True,
                technical_detail={"error_code": "missing_refresh_token", "reauthorization_required": True},
            )
        self.db.save_credentials(account_id, credentials, email=token_set.email or mapping.get("email"))

        self._apply_credentials_and_finish(
            task_id,
            account_id,
            mapping,
            credentials,
            token_set=token_set,
            method="refresh token",
        )

    def _apply_credentials_and_finish(
        self,
        task_id: str,
        account_id: int,
        mapping: dict[str, Any],
        credentials: dict[str, Any],
        *,
        token_set: TokenSet | None = None,
        method: str,
    ) -> None:
        self.db.set_task_stage(task_id, "apply_credentials")
        self._log(task_id, "apply_credentials", "Applying OAuth credentials to the original Sub2API account")
        try:
            self.sub2api.apply_oauth_credentials(
                account_id,
                _sub2api_credentials(credentials),
                extra=_credential_extra(token_set) if token_set else _credential_extra_from_credentials(credentials),
                credential_type=str(mapping.get("account_type") or "oauth"),
            )
        except Sub2APIError as exc:
            raise RecoveryFailure(
                safe_error(exc),
                classification=exc.classification,
                retryable=exc.retryable,
                technical_detail=_sub2api_technical_detail(exc),
            ) from exc
        result = self._status_check(account_id, task_id, "status_check")
        if not result.success:
            classification = result.classification or classify_failure(message=result.reason)
            if classification.category == FailureClass.AUTH_FAILURE:
                raise RecoveryFailure(
                    result.reason,
                    classification=classification,
                    needs_reauthorization=True,
                    technical_detail=_account_test_technical_detail(result),
                )
            raise RecoveryFailure(
                result.reason,
                classification=classification,
                retryable=True,
                technical_detail=_account_test_technical_detail(result),
            )
        self._finish_success(task_id, account_id, method)

    def _sync_account_credentials(self, account_id: int) -> None:
        exported = self.sub2api.export_account_credentials(account_id)
        if not exported:
            return
        credentials = exported.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            return
        self.db.save_credentials(
            account_id,
            credentials,
            email=str(credentials.get("email") or exported.get("email") or exported.get("name") or ""),
            username=str(exported.get("name") or ""),
        )

    def _sync_note_material(self, account_id: int, raw: dict[str, Any]) -> NoteCredentials:
        mapping = self.db.get_mapping(account_id) or {}
        existing = self.db.load_credentials(account_id)
        notes = raw.get("notes") if isinstance(raw, dict) else None
        notes_loaded = notes is not None
        if notes is None:
            get_account = getattr(self.sub2api, "get_account", None)
            if get_account is not None:
                detail = get_account(account_id)
                notes = detail.get("notes") if isinstance(detail, dict) else ""
                notes_loaded = True
        parsed = parse_account_notes(notes, fallback_email=str(mapping.get("email") or ""))
        merged = dict(existing)
        merged.update(parsed.as_dict())
        if parsed.as_dict():
            self.db.save_credentials(account_id, merged, email=parsed.email, username=str(mapping.get("username") or ""))
        if notes_loaded:
            self.db.mark_materials_checked(account_id)
        return self._material_from_credentials(merged, parsed.email or str(mapping.get("email") or ""))

    @staticmethod
    def _material_from_credentials(credentials: dict[str, Any], fallback_email: str = "") -> NoteCredentials:
        return NoteCredentials(
            email=str(credentials.get("email") or fallback_email or "").strip().lower(),
            email_password=str(credentials.get("email_password") or ""),
            openai_password=str(credentials.get("openai_password") or ""),
            totp_secret=str(credentials.get("totp_secret") or ""),
        )

    @staticmethod
    def _suppress_unchanged_blocked_retry(
        current: dict[str, Any],
        previous: NoteCredentials,
        latest: NoteCredentials,
    ) -> bool:
        return current.get("status") == "automation_blocked" and previous == latest

    def _block_automation(
        self,
        account_id: int,
        classification: Classification,
        reason: str,
        *,
        task_id: str | None = None,
    ) -> None:
        task_ids = [] if task_id else self.db.skip_pending_tasks(account_id, reason)
        if task_id:
            self.db.finish_task(
                task_id,
                status="skipped",
                stage="automation_blocked",
                failure_class=classification.category.value,
                error_reason=reason,
            )
            task_ids = [task_id]
        self.db.update_account_state(
            account_id,
            status="automation_blocked",
            failure_class=classification.category.value,
            failure_reason=reason,
        )
        for skipped_task_id in task_ids:
            self._log(skipped_task_id, "automation_blocked", reason)

    def _status_check(self, account_id: int, task_id: str, stage: str) -> AccountTestResult:
        self.db.set_task_stage(task_id, stage)
        result = self.sub2api.inspect_account(account_id)
        is_auth_failure = bool(
            result.classification and result.classification.category == FailureClass.AUTH_FAILURE
        )
        self.db.update_account_state(
            account_id,
            status="healthy" if result.success else ("auth_failed" if is_auth_failure else "observed"),
            failure_class=result.classification.category.value if result.classification else None,
            failure_reason=None if result.success else result.reason,
            mark_401=is_auth_failure,
            mark_test=True,
        )
        self._log(task_id, stage, result.reason, result)
        return result

    def _finish_success(self, task_id: str, account_id: int, method: str) -> None:
        self.db.set_task_stage(task_id, "recover_state")
        self._log(task_id, "recover_state", "Clearing Sub2API error state and restoring schedulability")
        try:
            self.sub2api.recover_state(account_id)
            self.sub2api.set_schedulable(account_id, True)
        except Sub2APIError as exc:
            raise RecoveryFailure(
                safe_error(exc),
                classification=exc.classification,
                retryable=exc.retryable,
                technical_detail=_sub2api_technical_detail(exc),
            ) from exc
        self.db.update_account_state(
            account_id,
            status="healthy",
            failure_class=None,
            failure_reason=None,
            mark_recovery=True,
        )
        self.db.finish_task(task_id, status="succeeded", stage="succeeded")
        self._log(task_id, "succeeded", f"Account recovered successfully using {method}")

    def _mark_manual_required(
        self,
        task_id: str,
        account_id: int,
        reason: str,
        classification: Classification,
        *,
        attempt: int = 1,
    ) -> None:
        if self.settings.playwright_enabled:
            try:
                material = self._sync_note_material(account_id, {})
                if material.ready_for_automation:
                    session = self.start_reauthorization(account_id, task_id=task_id)
                    self.db.set_task_stage(task_id, "automatic_reauthorization")
                    self._log(task_id, "automatic_reauthorization", "Starting automated OAuth browser recovery")
                    callback_url = self.automatic_browser.run(
                        str(session["auth_url"]),
                        material,
                        started_at=datetime.now(timezone.utc),
                        on_stage=lambda stage, message: self._log(task_id, stage, message),
                    )
                    self.complete_authorization(session_id=str(session["id"]), callback_url=callback_url)
                    self._log(task_id, "automatic_reauthorization", "Automated OAuth callback completed")
                    return
            except (AutomaticBrowserError, TOTPError) as exc:
                message = safe_error(getattr(exc, "reason", exc))
                account_disabled = (
                    isinstance(exc, AutomaticBrowserError) and exc.stage == "account_disabled"
                )
                final_classification = (
                    Classification(FailureClass.ACCOUNT_ERROR, message, False)
                    if account_disabled
                    else classification
                )
                session_id = self.db.get_task(task_id).get("auth_session_id") if self.db.get_task(task_id) else None
                if session_id:
                    self.db.complete_oauth_session(str(session_id), status="failed", error_reason=message)
                if isinstance(exc, AutomaticBrowserError) and exc.retryable and self.settings.automation_retry_forever:
                    self._schedule_automatic_retry(task_id, account_id, message, classification)
                    return
                if isinstance(exc, AutomaticBrowserError) and exc.retryable and attempt < self.settings.recovery_max_attempts:
                    self._retry_task({"id": task_id, "attempt": attempt}, message)
                    self.db.update_account_state(
                        account_id,
                        status="recovering",
                        failure_class=classification.category.value,
                        failure_reason=message,
                    )
                    return
                self.db.finish_task(
                    task_id,
                    status="failed",
                    stage=getattr(exc, "stage", "automatic_reauthorization"),
                    failure_class=final_classification.category.value,
                    error_reason=message,
                )
                self.db.update_account_state(
                    account_id,
                    status="account_disabled" if account_disabled else "automation_blocked",
                    failure_class=final_classification.category.value,
                    failure_reason=(
                        message
                        if account_disabled
                        else f"Automatic reauthorization exhausted its retries: {message}"
                    ),
                )
                self._log(task_id, getattr(exc, "stage", "automatic_reauthorization"), message, exc)
                return
            except RecoveryFailure:
                raise
            except Exception as exc:
                message = safe_error(exc)
                self.db.finish_task(
                    task_id,
                    status="failed",
                    stage="automatic_reauthorization",
                    failure_class=classification.category.value,
                    error_reason=message,
                )
                self.db.update_account_state(
                    account_id,
                    status="auth_failed",
                    failure_class=classification.category.value,
                    failure_reason=message,
                )
                self._log(task_id, "automatic_reauthorization", message, exc)
                return

        try:
            session = self.start_reauthorization(account_id, task_id=task_id)
            self.db.set_task_stage(task_id, "reauthorization", status="manual_required")
            self.db.set_task_auth_session(task_id, session["id"])
            self.db.update_account_state(
                account_id,
                status="reauth_required",
                failure_class=classification.category.value,
                failure_reason=reason,
            )
            self._log(
                task_id,
                "reauthorization",
                "Refresh token is not usable; administrator action is required",
                {"session_id": session["id"]},
            )
        except Exception as exc:
            self.db.finish_task(
                task_id,
                status="failed",
                stage="reauthorization",
                failure_class=classification.category.value,
                error_reason=safe_error(exc),
            )

    def _schedule_automatic_retry(
        self,
        task_id: str,
        account_id: int,
        reason: str,
        classification: Classification,
    ) -> None:
        delay = max(60, self.settings.automation_retry_backoff_seconds)
        available_at = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(timespec="seconds")
        self.db.finish_task(
            task_id,
            status="queued",
            stage="retry_wait",
            failure_class=classification.category.value,
            error_reason=safe_error(reason),
            available_at=available_at,
        )
        self.db.update_account_state(
            account_id,
            status="recovering",
            failure_class=classification.category.value,
            failure_reason=safe_error(reason),
        )
        self._log(
            task_id,
            "retry_wait",
            "Automatic reauthorization will retry after a transient browser or security failure",
            {"classification": classification.category.value, "raw_reason": safe_error(reason)},
        )

    def _retry_task(self, task: dict[str, Any], reason: str) -> None:
        task_id = str(task["id"])
        delay = self.settings.recovery_backoff_seconds * max(1, int(task.get("attempt") or 1))
        available = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(timespec="seconds")
        self.db.finish_task(task_id, status="queued", stage="retry_wait", error_reason=safe_error(reason), available_at=available)
        self._log(
            task_id,
            "retry_wait",
            f"Recovery will retry after a transient failure: {reason}",
            {"retryable": True, "backoff_seconds": delay, "raw_reason": safe_error(reason)},
        )

    def start_reauthorization(self, account_id: int, *, task_id: str | None = None) -> dict[str, Any]:
        if not self.db.get_mapping(account_id):
            self.db.upsert_account_snapshot(
                {"sub2api_account_id": account_id, "username": str(account_id), "status": "unknown"}
            )
        if task_id is None:
            task_id, _ = self.enqueue_recovery(account_id, trigger="manual-reauthorize", force=True)
        pkce = generate_pkce()
        session_id = str(uuid.uuid4())
        auth_url = build_authorization_url(self.settings, pkce)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(timespec="seconds")
        self.db.create_oauth_session(
            {
                "id": session_id,
                "sub2api_account_id": account_id,
                "task_id": task_id,
                "state": pkce.state,
                "code_verifier": pkce.code_verifier,
                "redirect_uri": self.settings.openai_oauth_redirect_uri,
                "auth_url": auth_url,
                "expires_at": expires_at,
            }
        )
        self.db.set_task_auth_session(task_id, session_id)
        return {
            "id": session_id,
            "task_id": task_id,
            "sub2api_account_id": account_id,
            "auth_url": auth_url,
            "status": "pending",
            "expires_at": expires_at,
        }

    def complete_authorization(
        self,
        *,
        session_id: str | None = None,
        callback_url: str = "",
        code: str = "",
        state: str = "",
    ) -> dict[str, Any]:
        callback_error = ""
        if callback_url:
            parsed = urllib.parse.urlparse(callback_url)
            query = urllib.parse.parse_qs(parsed.query)
            code = code or _first(query, "code")
            state = state or _first(query, "state")
            callback_error = _first(query, "error")
        session = self.db.get_oauth_session(session_id) if session_id else self.db.get_oauth_session_by_state(state)
        if not session or session.get("status") != "pending":
            raise RecoveryFailure("OAuth session was not found or is no longer pending")
        task_id = str(session.get("task_id") or "")
        if _expired(session.get("expires_at")):
            raise RecoveryFailure("OAuth session has expired; create a new authorization URL")
        if not state or not hmac_compare(state, str(session["state"])):
            raise RecoveryFailure("OAuth state validation failed")
        if callback_error:
            reason = safe_error(f"OAuth authorization was denied: {callback_error}")
            self.db.complete_oauth_session(str(session["id"]), status="failed", error_reason=reason)
            if task_id:
                self.db.finish_task(
                    task_id,
                    status="manual_required",
                    stage="reauthorization",
                    failure_class=FailureClass.AUTH_FAILURE.value,
                    error_reason=reason,
                )
            raise RecoveryFailure(
                reason,
                classification=Classification(FailureClass.AUTH_FAILURE, reason, True, True),
            )
        if not code:
            raise RecoveryFailure("Authorization code is missing")
        verifier = self.db.secret_box.decrypt(session["code_verifier_encrypted"])
        if not verifier:
            raise RecoveryFailure("OAuth PKCE verifier is unavailable")
        try:
            if task_id:
                self._log(task_id, "callback", "OAuth callback received; exchanging the authorization code")
            token_set = self.oauth.exchange_code(
                code=code,
                code_verifier=verifier,
                redirect_uri=str(session["redirect_uri"]),
            )
        except OAuthError as exc:
            self.db.complete_oauth_session(str(session["id"]), status="failed", error_reason=safe_error(exc))
            raise RecoveryFailure(safe_error(exc), needs_reauthorization=False) from exc
        if not token_set.refresh_token:
            self.db.complete_oauth_session(
                str(session["id"]), status="failed", error_reason="OAuth response did not include refresh token"
            )
            raise RecoveryFailure("OAuth response did not include refresh token")
        existing = self.db.load_credentials(int(session["sub2api_account_id"]))
        old_account_id = str(existing.get("chatgpt_account_id") or "")
        if old_account_id and token_set.chatgpt_account_id and old_account_id != token_set.chatgpt_account_id:
            reason = "OAuth account identity does not match the mapped Sub2API account"
            self.db.complete_oauth_session(str(session["id"]), status="failed", error_reason=reason)
            raise RecoveryFailure(reason)
        self.db.save_credentials(
            int(session["sub2api_account_id"]),
            token_set.as_credentials(),
            email=token_set.email,
        )
        self.db.complete_oauth_session(
            str(session["id"]), status="completed", token_payload=token_set.as_credentials()
        )
        if task_id:
            self._log(task_id, "token_exchange", "OAuth session received and encrypted credentials stored")
            self.db.finish_task(task_id, status="queued", stage="apply_credentials", error_reason=None)
            self._log(task_id, "reauthorization", "OAuth authorization completed; queued credential application")
        else:
            task_id, _ = self.enqueue_recovery(
                int(session["sub2api_account_id"]), trigger="oauth-callback", force=True
            )
        return {
            "session_id": str(session["id"]),
            "task_id": task_id,
            "sub2api_account_id": int(session["sub2api_account_id"]),
            "status": "completed",
            "email": token_set.email,
            "chatgpt_account_id": token_set.chatgpt_account_id,
        }

    def launch_browser(self, session_id: str) -> None:
        if not self.settings.playwright_enabled:
            raise RuntimeError("PLAYWRIGHT_ENABLED is false")
        session = self.db.get_oauth_session(session_id)
        if not session:
            raise RuntimeError("OAuth session was not found")

        def on_callback(callback_url: str) -> None:
            try:
                self.complete_authorization(session_id=session_id, callback_url=callback_url)
            except Exception as exc:
                self.db.complete_oauth_session(session_id, status="failed", error_reason=safe_error(exc))

        def on_error(reason: str) -> None:
            self.db.complete_oauth_session(session_id, status="failed", error_reason=safe_error(reason))

        self.browser.launch_async(str(session["auth_url"]), on_callback, on_error)

    def account_view(self, account_id: int) -> dict[str, Any] | None:
        row = self.db.get_mapping(account_id)
        if not row:
            return None
        credentials = self.db.load_credentials(account_id)
        return public_account(row, credentials)

    def update_account_materials(self, account_id: int, values: dict[str, Any]) -> dict[str, Any]:
        row = self.db.get_mapping(account_id)
        if not row:
            try:
                raw = self.sub2api.get_account(account_id)
            except Sub2APIError:
                raise
            self.db.upsert_account_snapshot(normalize_snapshot(raw))
            row = self.db.get_mapping(account_id)
        if not row:
            raise KeyError(f"account mapping not found: {account_id}")
        normalized: dict[str, str] = {}
        for key in ("email", "email_password", "openai_password", "totp_secret"):
            value = values.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{key} must be a string")
            if isinstance(value, str) and value.strip():
                normalized[key] = value.strip()
        if not normalized:
            raise ValueError("at least one account material field is required")
        if "email" in normalized and ("@" not in normalized["email"] or len(normalized["email"]) > 320):
            raise ValueError("login email is invalid")
        self.db.save_account_material(account_id, normalized)
        self.db.mark_materials_checked(account_id)
        updated = self.db.get_mapping(account_id) or row
        material = self._material_from_credentials(
            self.db.load_credentials(account_id),
            str(updated.get("email") or ""),
        )
        if updated.get("status") == "automation_blocked" and material.ready_for_automation:
            self.db.update_account_state(
                account_id,
                status="auth_failed",
                failure_class=str(updated.get("failure_class") or FailureClass.AUTH_FAILURE.value),
                failure_reason="OAuth authentication failure is ready for recovery",
            )
        return self.account_view(account_id) or {}

    def accounts_view(self) -> list[dict[str, Any]]:
        return [public_account(row, self.db.load_credentials(int(row["sub2api_account_id"]))) for row in self.db.list_accounts()]

    def _log(self, task_id: str, stage: str, message: str, detail: Any | None = None) -> None:
        if isinstance(detail, AccountTestResult):
            detail = _account_test_technical_detail(detail)
        elif isinstance(detail, Sub2APIError):
            detail = _sub2api_technical_detail(detail)
        elif isinstance(detail, OAuthError):
            detail = _oauth_technical_detail(detail)
        elif isinstance(detail, AutomaticBrowserError):
            detail = {
                "error_type": type(detail).__name__,
                "automation_stage": detail.stage,
                "retryable": detail.retryable,
            }
        elif isinstance(detail, TOTPError):
            detail = {"error_type": type(detail).__name__}
        self.db.append_log(task_id, level="INFO", stage=stage, message=message, detail=detail if isinstance(detail, dict) else None)


def _account_test_technical_detail(result: AccountTestResult) -> dict[str, Any]:
    return {
        "success": result.success,
        "status_code": result.status_code,
        "classification": result.classification.category.value if result.classification else None,
    }


def _sub2api_technical_detail(error: Sub2APIError) -> dict[str, Any]:
    return {
        "operation": error.operation,
        "status_code": error.status_code,
        "classification": error.classification.category.value if error.classification else None,
        "retryable": error.retryable,
    }


def _oauth_technical_detail(error: OAuthError) -> dict[str, Any]:
    return {
        "error_code": error.error_code or None,
        "reauthorization_required": error.reauth_required,
    }


def normalize_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    account_id = raw.get("id", raw.get("account_id", raw.get("sub2api_account_id")))
    try:
        account_id = int(account_id)
    except (TypeError, ValueError):
        account_id = 0
    credentials = raw.get("credentials") if isinstance(raw.get("credentials"), dict) else {}
    return {
        "sub2api_account_id": account_id,
        "account_type": str(raw.get("type") or "oauth"),
        "email": str(raw.get("email") or credentials.get("email") or ""),
        "username": str(raw.get("name") or raw.get("username") or ""),
        "status": str(raw.get("status") or "unknown"),
    }


def public_account(row: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]:
    material = NoteCredentials(
        email=str(credentials.get("email") or row.get("email") or "").strip().lower(),
        email_password=str(credentials.get("email_password") or ""),
        openai_password=str(credentials.get("openai_password") or ""),
        totp_secret=str(credentials.get("totp_secret") or ""),
    )
    explicit_material_configured = any(
        credentials.get(field) for field in ("email_password", "openai_password", "totp_secret")
    )
    materials_checked = bool(row.get("materials_checked_at")) or explicit_material_configured
    # Older databases predate materials_checked_at. An automation_blocked state is
    # definitive evidence that the recovery flow already evaluated the materials.
    if row.get("status") == "automation_blocked":
        materials_checked = True
    return {
        "sub2api_account_id": int(row["sub2api_account_id"]),
        "email": row.get("email") or "",
        "username": row.get("username") or "",
        "account_type": row.get("account_type") or "oauth",
        "status": row.get("status") or "unknown",
        "failure_class": row.get("failure_class"),
        "failure_reason": row.get("failure_reason"),
        "last_401_at": row.get("last_401_at"),
        "last_recovery_at": row.get("last_recovery_at"),
        "last_test_at": row.get("last_test_at"),
        "last_seen_at": row.get("last_seen_at"),
        "has_access_token": bool(credentials.get("access_token")),
        "has_refresh_token": bool(credentials.get("refresh_token")),
        "expires_at": credentials.get("expires_at"),
        "chatgpt_account_id": credentials.get("chatgpt_account_id") or "",
        "plan_type": credentials.get("plan_type") or "",
        "automation_ready": material.ready_for_automation,
        "automation_complete": material.complete,
        "automation_configured_count": material.configured_count,
        "automation_total": 4,
        "automation_materials_checked": materials_checked,
        "automation_materials_checked_at": row.get("materials_checked_at"),
        "automation_missing": list(material.missing_fields),
        "automation_required_missing": list(material.missing_required_fields),
        "automation_optional_missing": [
            label for label in material.missing_fields if label not in material.missing_required_fields
        ],
    }


def _credential_extra(token_set: TokenSet) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "email": token_set.email,
            "chatgpt_account_id": token_set.chatgpt_account_id,
            "chatgpt_user_id": token_set.chatgpt_user_id,
            "organization_id": token_set.organization_id,
            "plan_type": token_set.plan_type,
        }.items()
        if value
    }


def _credential_extra_from_credentials(credentials: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key in ("email", "chatgpt_account_id", "chatgpt_user_id", "organization_id", "plan_type")
        if (value := credentials.get(key))
    }


def _sub2api_credentials(credentials: dict[str, Any]) -> dict[str, Any]:
    """Keep local mailbox/MFA material out of the Sub2API OAuth payload."""

    local_only = {
        "email_password",
        "openai_password",
        "password",
        "totp_secret",
        "cookie",
        "cookies",
    }
    return {key: value for key, value in credentials.items() if str(key).lower() not in local_only}


def _automation_block_reason(material: NoteCredentials) -> str:
    missing = ", ".join(material.missing_required_fields)
    return f"Automatic authorization requires: {missing}" if missing else "Automatic authorization material is unavailable"


def _first(query: dict[str, list[str]], key: str) -> str:
    values = query.get(key) or []
    return values[0] if values else ""


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode(), right.encode())


def _expired(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed <= datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return True
