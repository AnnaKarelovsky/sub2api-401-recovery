from __future__ import annotations

from app.classifier import FailureClass
from app.oauth import TokenSet
from app.oauth import OAuthError
from app.automatic_browser import AutomaticBrowserError
from app.recovery import RecoveryCoordinator, RecoveryRuntime
from app.sub2api import AccountTestResult, Sub2APIError


class FakeSub2API:
    def __init__(self):
        self.applied = []
        self.recovered = []

    def native_refresh(self, account_id):
        raise Sub2APIError("native_refresh", 400, "native refresh unavailable")

    def export_account_credentials(self, account_id):
        return None

    def apply_oauth_credentials(self, account_id, credentials, extra=None, **kwargs):
        self.applied.append((account_id, credentials.copy(), extra or {}))
        return {"id": account_id}

    def inspect_account(self, account_id):
        return AccountTestResult(True, 200, "connection test passed", None)

    def recover_state(self, account_id):
        self.recovered.append(account_id)
        return {}

    def set_schedulable(self, account_id, schedulable=True):
        return {}


class ReplacementSub2API(FakeSub2API):
    def __init__(self):
        super().__init__()
        self.created = []
        self.disabled = []

    def list_accounts(self):
        return []

    def create_account(self, payload):
        self.created.append(payload)
        return {"id": 42, "name": payload["name"], "email": payload["credentials"]["email"], "type": "oauth"}

    def set_schedulable(self, account_id, schedulable=True):
        self.disabled.append((account_id, schedulable))
        return {}


class ScanSub2API(FakeSub2API):
    def __init__(self):
        super().__init__()
        self.accounts = [{"id": 7, "email": "present@example.com", "status": "active"}]

    def list_accounts(self):
        return self.accounts


class MaterialSyncSub2API(ScanSub2API):
    def get_account(self, account_id):
        return {
            "id": account_id,
            "notes": "邮箱: owner@example.com\nOpenAI密码: gpt-pass",
        }


class AuthFailureScanSub2API(ScanSub2API):
    def __init__(self, notes: str):
        super().__init__()
        self.accounts = [
            {
                "id": 7,
                "email": "present@example.com",
                "status": "active",
                "oauth_error": "invalid_grant",
            }
        ]
        self.notes = notes

    def get_account(self, account_id):
        return {"id": account_id, "notes": self.notes}


class ErrorScanSub2API(ScanSub2API):
    def __init__(self):
        super().__init__()
        self.accounts = [
            {
                "id": 292,
                "email": "workspace@example.com",
                "status": "error",
                "error_message": '{"code":"deactivated_workspace"}',
            }
        ]

class FakeOAuth:
    def refresh_token(self, refresh_token, previous=None):
        return TokenSet(
            access_token="new-access",
            refresh_token="new-refresh",
            id_token="",
            expires_at=1890000000,
            expires_in=3600,
            client_id="client",
            email="demo@example.com",
            chatgpt_account_id="acct-1",
        )


class ReauthOAuth:
    def refresh_token(self, refresh_token, previous=None):
        raise OAuthError("invalid_grant", error_code="invalid_grant", reauth_required=True)


def test_confirmed_401_skips_both_refresh_paths_and_starts_oauth(database, settings):
    settings.playwright_enabled = True

    class CountingSub2API(FakeSub2API):
        native_refresh_calls = 0

        def native_refresh(self, account_id):
            self.native_refresh_calls += 1
            return super().native_refresh(account_id)

    class CountingOAuth(ReauthOAuth):
        refresh_calls = 0

        def refresh_token(self, refresh_token, previous=None):
            self.refresh_calls += 1
            return super().refresh_token(refresh_token, previous)

    database.upsert_account_snapshot(
        {"sub2api_account_id": 80, "email": "confirmed-401@example.com", "status": "auth_failed"}
    )
    database.save_credentials(
        80,
        {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "email": "confirmed-401@example.com",
            "openai_password": "openai-password",
        },
    )
    database.update_account_state(
        80,
        status="auth_failed",
        failure_class=FailureClass.AUTH_FAILURE.value,
        failure_reason="Authentication failed (401): token_revoked",
        mark_401=True,
    )
    sub2api = CountingSub2API()
    oauth = CountingOAuth()
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, sub2api, oauth, settings))
    browser_calls = []

    def stop_browser_for_test(auth_url, material, **kwargs):
        browser_calls.append(auth_url)
        raise AutomaticBrowserError("test stops before external browser interaction", stage="totp", retryable=False)

    coordinator.automatic_browser.run = stop_browser_for_test
    task_id, _ = coordinator.enqueue_recovery(80, trigger="manual-recover")
    task = database.claim_next_task("test-worker")

    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    assert final_task["status"] == "failed"
    assert final_task["stage"] == "totp"
    assert final_task["auth_session_id"]
    assert len(browser_calls) == 1
    assert "/oauth/authorize" in browser_calls[0]
    assert sub2api.native_refresh_calls == 0
    assert oauth.refresh_calls == 0
    assert not any(log["stage"] in {"native_refresh", "refresh_token"} for log in database.list_logs(task_id))
    assert any(
        "skipping native and refresh-token attempts" in log["message"]
        for log in database.list_logs(task_id)
    )


class ReplacementOAuth:
    def exchange_code(self, *, code, code_verifier, redirect_uri):
        assert code == "authorization-code"
        assert code_verifier
        assert redirect_uri
        return TokenSet(
            access_token="replacement-access",
            refresh_token="replacement-refresh",
            id_token="",
            expires_at=1890000000,
            expires_in=3600,
            client_id="client",
            email="demo@example.com",
            chatgpt_account_id="acct-new",
        )


def test_scan_reconciles_local_accounts_with_remote_accounts(database, settings):
    database.upsert_account_snapshot({"sub2api_account_id": 7, "email": "present@example.com", "status": "active"})
    database.upsert_account_snapshot({"sub2api_account_id": 8, "email": "removed@example.com", "status": "active"})
    settings.scan_probe_active_accounts = False
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, ScanSub2API(), FakeOAuth(), settings))

    result = coordinator.scan()

    assert result["found"] == 1
    assert result["removed"] == 1
    assert [row["sub2api_account_id"] for row in database.list_accounts()] == [7]


def test_scan_marks_deactivated_workspace_as_account_error(database, settings):
    database.upsert_account_snapshot(
        {"sub2api_account_id": 292, "email": "workspace@example.com", "status": "healthy"}
    )
    settings.scan_probe_active_accounts = False
    coordinator = RecoveryCoordinator(
        RecoveryRuntime(database, ErrorScanSub2API(), FakeOAuth(), settings)
    )

    result = coordinator.scan()

    assert result["found"] == 1
    mapping = database.get_mapping(292)
    assert mapping["status"] == "account_error"
    assert mapping["failure_class"] == "ACCOUNT_ERROR"
    assert mapping["failure_reason"] == "Sub2API workspace is deactivated"


def test_scan_does_not_repeat_terminal_automation_failure_without_material_changes(database, settings):
    settings.scan_probe_active_accounts = False
    database.upsert_account_snapshot(
        {"sub2api_account_id": 7, "email": "present@example.com", "status": "active"}
    )
    database.save_credentials(
        7,
        {
            "email": "present@example.com",
            "email_password": "mail-pass",
            "openai_password": "gpt-pass",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        },
    )
    database.update_account_state(7, status="automation_blocked", failure_reason="MFA denied")
    sub2api = AuthFailureScanSub2API(
        "邮箱: present@example.com\n邮箱密码: mail-pass\nOpenAI密码: gpt-pass\n2FA密钥: JBSWY3DPEHPK3PXP"
    )
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, sub2api, FakeOAuth(), settings))

    result = coordinator.scan()

    assert result["queued"] == 0
    assert database.list_tasks(limit=10) == []
    assert database.get_mapping(7)["status"] == "automation_blocked"


def test_scan_retries_terminal_failure_when_notes_material_changes(database, settings):
    settings.scan_probe_active_accounts = False
    database.upsert_account_snapshot(
        {"sub2api_account_id": 7, "email": "present@example.com", "status": "active"}
    )
    database.save_credentials(
        7,
        {
            "email": "present@example.com",
            "email_password": "mail-pass",
            "openai_password": "old-pass",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        },
    )
    database.update_account_state(7, status="automation_blocked", failure_reason="MFA denied")
    sub2api = AuthFailureScanSub2API(
        "邮箱: present@example.com\n邮箱密码: mail-pass\nOpenAI密码: new-pass\n2FA密钥: JBSWY3DPEHPK3PXP"
    )
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, sub2api, FakeOAuth(), settings))

    result = coordinator.scan()

    assert result["queued"] == 1
    assert len(database.list_tasks(limit=10)) == 1
    assert database.get_mapping(7)["status"] == "recovering"


def test_scan_preserves_confirmed_openai_disabled_status(database, settings):
    settings.scan_probe_active_accounts = False
    database.upsert_account_snapshot(
        {"sub2api_account_id": 7, "email": "present@example.com", "status": "active"}
    )
    database.update_account_state(
        7,
        status="account_disabled",
        failure_class="ACCOUNT_ERROR",
        failure_reason="OpenAI account is disabled or deleted (account_deactivated)",
    )
    sub2api = AuthFailureScanSub2API(
        "邮箱: present@example.com\n邮箱密码: mail-pass\nOpenAI密码: gpt-pass\n2FA密钥: JBSWY3DPEHPK3PXP"
    )
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, sub2api, FakeOAuth(), settings))

    result = coordinator.scan()

    assert result["queued"] == 0
    assert database.list_tasks(limit=10) == []
    mapping = database.get_mapping(7)
    assert mapping["status"] == "account_disabled"
    assert mapping["failure_class"] == "ACCOUNT_ERROR"


def test_material_sync_reads_notes_without_creating_recovery_tasks(database, settings):
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, MaterialSyncSub2API(), FakeOAuth(), settings))

    result = coordinator.sync_materials()

    assert result == {"found": 1, "checked": 1, "failed": 0, "removed": 0}
    mapping = database.get_mapping(7)
    assert mapping["materials_checked_at"]
    credentials = database.load_credentials(7)
    assert credentials["email"] == "owner@example.com"
    assert credentials["openai_password"] == "gpt-pass"
    assert database.list_tasks(limit=10) == []


def test_automatic_security_failure_is_requeued_with_backoff(database, settings):
    settings.playwright_enabled = True
    database.upsert_account_snapshot({"sub2api_account_id": 10, "email": "auto@example.com", "status": "auth_failed"})
    database.save_credentials(
        10,
        {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "email_password": "mail-secret",
            "openai_password": "gpt-secret",
            "totp_secret": "totp-secret",
        },
    )
    task_id, _ = database.create_task(10, trigger="test")
    task = database.claim_next_task("test-worker")
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, FakeSub2API(), ReauthOAuth(), settings))

    def fail_automatically(*args, **kwargs):
        raise AutomaticBrowserError("Cloudflare challenge is still active", stage="security_challenge")

    coordinator.automatic_browser.run = fail_automatically
    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    assert final_task["status"] == "queued"
    assert final_task["stage"] == "retry_wait"
    assert database.get_mapping(10)["status"] == "recovering"


def test_account_disabled_browser_result_sets_explicit_terminal_status(database, settings):
    settings.playwright_enabled = True
    database.upsert_account_snapshot(
        {"sub2api_account_id": 13, "email": "disabled@example.com", "status": "auth_failed"}
    )
    database.save_credentials(
        13,
        {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "email": "disabled@example.com",
            "email_password": "mail-secret",
            "openai_password": "gpt-secret",
            "totp_secret": "totp-secret",
        },
    )
    task_id, _ = database.create_task(13, trigger="test")
    task = database.claim_next_task("test-worker")
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, FakeSub2API(), ReauthOAuth(), settings))

    def fail_as_disabled(*args, **kwargs):
        raise AutomaticBrowserError(
            "OpenAI account is disabled or deleted (account_deactivated)",
            stage="account_disabled",
            retryable=False,
            evidence=b"\x89PNG\r\n\x1a\naccount-disabled-page",
        )

    coordinator.automatic_browser.run = fail_as_disabled
    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    mapping = database.get_mapping(13)
    assert final_task["status"] == "failed"
    assert final_task["stage"] == "account_disabled"
    assert final_task["failure_class"] == "ACCOUNT_ERROR"
    assert mapping["status"] == "account_disabled"
    assert mapping["failure_class"] == "ACCOUNT_ERROR"
    assert "account_deactivated" in mapping["failure_reason"]
    evidence_log = next(
        log
        for log in database.list_logs(task_id)
        if log["stage"] == "account_disabled" and log.get("detail", {}).get("evidence_id")
    )
    evidence = database.get_task_evidence(task_id, evidence_log["detail"]["evidence_id"])
    assert evidence["content_type"] == "image/png"
    assert evidence["image"] == b"\x89PNG\r\n\x1a\naccount-disabled-page"


def test_disabled_browser_automation_uses_manual_authorization(database, settings):
    database.upsert_account_snapshot({"sub2api_account_id": 12, "email": "manual@example.com", "status": "auth_failed"})
    database.save_credentials(
        12,
        {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "email": "manual@example.com",
            "openai_password": "gpt-secret",
        },
    )
    task_id, _ = database.create_task(12, trigger="test")
    task = database.claim_next_task("test-worker")
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, FakeSub2API(), ReauthOAuth(), settings))
    coordinator.automatic_browser.run = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("browser must be disabled"))

    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    assert final_task["status"] == "manual_required"
    assert final_task["auth_session_id"]


def test_recovery_refreshes_applies_and_restores_original_account(database, settings):
    database.upsert_account_snapshot({"sub2api_account_id": 7, "email": "demo@example.com", "status": "auth_failed"})
    database.save_credentials(
        7,
        {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "chatgpt_account_id": "acct-1",
            "email_password": "mail-secret",
            "totp_secret": "totp-secret",
        },
    )
    task_id, _ = database.create_task(7, trigger="test")
    task = database.claim_next_task("test-worker")
    fake_sub2api = FakeSub2API()
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, fake_sub2api, FakeOAuth(), settings))
    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    assert final_task["status"] == "succeeded"
    assert fake_sub2api.applied[0][0] == 7
    assert fake_sub2api.applied[0][1]["refresh_token"] == "new-refresh"
    assert "email_password" not in fake_sub2api.applied[0][1]
    assert "totp_secret" not in fake_sub2api.applied[0][1]
    assert fake_sub2api.recovered == [7]
    assert database.get_mapping(7)["status"] == "healthy"


def test_invalid_grant_creates_manual_authorization_session(database, settings):
    database.upsert_account_snapshot({"sub2api_account_id": 9, "email": "reauth@example.com", "status": "auth_failed"})
    database.save_credentials(9, {"access_token": "old-access", "refresh_token": "old-refresh"})
    task_id, _ = database.create_task(9, trigger="test")
    task = database.claim_next_task("test-worker")
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, FakeSub2API(), ReauthOAuth(), settings))
    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    assert final_task["status"] == "manual_required"
    assert final_task["auth_session_id"]
    session = database.get_oauth_session(final_task["auth_session_id"])
    assert session["status"] == "pending"
    assert "old-refresh" not in str(database.list_logs(task_id))
    assert database.get_mapping(9)["status"] == "reauth_required"
    error_log = next(log for log in database.list_logs(task_id) if log["level"] == "ERROR")
    assert error_log["detail"]["error_code"] == "invalid_grant"
    assert error_log["detail"]["reauthorization_required"] is True


def test_oauth_identity_change_creates_replacement_account(database, settings):
    database.upsert_account_snapshot(
        {"sub2api_account_id": 7, "email": "demo@example.com", "username": "team", "status": "auth_failed"}
    )
    database.save_credentials(
        7,
        {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "chatgpt_account_id": "acct-old",
            "email": "demo@example.com",
            "email_password": "mail-secret",
            "openai_password": "gpt-secret",
            "totp_secret": "totp-secret",
        },
    )
    task_id, _ = database.create_task(7, trigger="test")
    sub2api = ReplacementSub2API()
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, sub2api, ReplacementOAuth(), settings))
    session = coordinator.start_reauthorization(7, task_id=task_id)
    callback_state = database.get_oauth_session(session["id"])["state"]

    result = coordinator.complete_authorization(
        session_id=session["id"],
        callback_url=f"http://localhost:1455/auth/callback?code=authorization-code&state={callback_state}",
    )

    assert result["status"] == "replaced"
    assert result["replacement_account_id"] == 42
    assert sub2api.disabled == [(7, False)]
    assert len(sub2api.created) == 1
    assert sub2api.created[0]["credentials"]["refresh_token"] == "replacement-refresh"
    assert database.get_task(task_id)["status"] == "succeeded"
    assert database.get_task(task_id)["stage"] == "account_replaced"
    assert database.get_mapping(7)["status"] == "account_replaced"
    assert database.get_mapping(42)["status"] == "unknown"
    replacement_credentials = database.load_credentials(42)
    assert replacement_credentials["refresh_token"] == "replacement-refresh"
    assert replacement_credentials["email_password"] == "mail-secret"
    assert database.get_oauth_session(session["id"])["status"] == "completed"


def test_scan_does_not_retry_replaced_account(database, settings):
    settings.scan_probe_active_accounts = False
    database.upsert_account_snapshot(
        {"sub2api_account_id": 7, "email": "present@example.com", "status": "active"}
    )
    database.update_account_state(
        7,
        status="account_replaced",
        failure_class="ACCOUNT_ERROR",
        failure_reason="replacement account created",
    )
    sub2api = AuthFailureScanSub2API(
        "邮箱: present@example.com\n邮箱密码: mail-pass\nOpenAI密码: gpt-pass\n2FA密钥: JBSWY3DPEHPK3PXP"
    )
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, sub2api, FakeOAuth(), settings))

    result = coordinator.scan()

    assert result["queued"] == 0
    assert database.list_tasks(limit=10) == []
    assert database.get_mapping(7)["status"] == "account_replaced"


def test_completed_oauth_session_applies_credentials_before_status_check(database, settings):
    database.upsert_account_snapshot({"sub2api_account_id": 11, "email": "oauth@example.com", "status": "auth_failed"})
    database.save_credentials(11, {"access_token": "old-access", "refresh_token": "old-refresh"})
    task_id, _ = database.create_task(11, trigger="test")
    coordinator = RecoveryCoordinator(RecoveryRuntime(database, FakeSub2API(), ReauthOAuth(), settings))
    session = coordinator.start_reauthorization(11, task_id=task_id)
    database.complete_oauth_session(
        session["id"],
        status="completed",
        token_payload={"access_token": "new-access", "refresh_token": "new-refresh"},
    )
    database.save_credentials(11, {"access_token": "new-access", "refresh_token": "new-refresh"})
    task = database.claim_next_task("test-worker")

    coordinator.execute_task(task)

    final_task = database.get_task(task_id)
    assert final_task["status"] == "succeeded"
    assert coordinator.sub2api.applied[0][1]["access_token"] == "new-access"
    assert database.get_mapping(11)["status"] == "healthy"
