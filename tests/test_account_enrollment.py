from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from app.automatic_browser import AutomaticBrowserError
from app.oauth import TokenSet
from app.recovery import RecoveryCoordinator, RecoveryRuntime


class EnrollmentSub2API:
    def __init__(self):
        self.accounts = []
        self.created = []

    def list_accounts(self):
        return list(self.accounts)

    def create_account(self, payload):
        self.created.append(payload)
        return {"id": 292, "name": payload["name"], "email": payload["credentials"]["email"], "type": "oauth"}


class EnrollmentOAuth:
    def __init__(self, email="owner@example.com"):
        self.email = email

    def exchange_code(self, *, code, code_verifier, redirect_uri):
        assert code == "authorization-code"
        assert code_verifier
        assert redirect_uri
        return TokenSet(
            access_token="oauth-access",
            refresh_token="oauth-refresh",
            id_token="identity-token",
            expires_at=1_900_000_000,
            expires_in=3600,
            client_id="oauth-client",
            email=self.email,
            chatgpt_account_id="chatgpt-account",
        )


class CallbackBrowser:
    def run(self, auth_url, material, *, started_at, on_stage):
        assert material.ready_for_automation
        on_stage("email", "Submitting the account email")
        state = parse_qs(urlparse(auth_url).query)["state"][0]
        return f"http://localhost:1455/auth/callback?code=authorization-code&state={state}"


def make_coordinator(database, settings, *, oauth=None):
    settings.playwright_enabled = True
    sub2api = EnrollmentSub2API()
    coordinator = RecoveryCoordinator(
        RecoveryRuntime(database, sub2api, oauth or EnrollmentOAuth(), settings)
    )
    coordinator.automatic_browser = CallbackBrowser()
    return coordinator, sub2api


def test_account_enrollment_automates_oauth_then_creates_sub2api_account(database, settings):
    coordinator, sub2api = make_coordinator(database, settings)
    enrollment = coordinator.enqueue_account_enrollment(
        email="owner@example.com",
        email_password="mail-secret",
        openai_password="openai-secret",
        totp_secret="totp-secret",
        name="Owner",
    )

    assert coordinator.process_one_account_enrollment()

    result = database.get_account_enrollment(enrollment["id"])
    assert result["status"] == "succeeded"
    assert result["sub2api_account_id"] == 292
    stages = [entry["stage"] for entry in result["logs"]]
    assert "identity_check" in stages
    assert stages[-3:] == ["duplicate_check", "create_account", "completed"]
    assert len(sub2api.created) == 1
    payload = sub2api.created[0]
    assert payload["platform"] == "openai"
    assert payload["type"] == "oauth"
    assert payload["credentials"]["refresh_token"] == "oauth-refresh"
    serialized_payload = json.dumps(payload)
    assert "mail-secret" not in serialized_payload
    assert "openai-secret" not in serialized_payload
    assert "totp-secret" not in serialized_payload

    stored = database.load_credentials(292)
    assert stored["email_password"] == "mail-secret"
    assert stored["openai_password"] == "openai-secret"
    assert stored["totp_secret"] == "totp-secret"
    assert stored["refresh_token"] == "oauth-refresh"
    assert database.get_mapping(292)["materials_checked_at"]
    with database.connect() as connection:
        secrets = connection.execute(
            "SELECT code_verifier_encrypted, materials_encrypted, auth_url, state "
            "FROM account_enrollments WHERE id=?",
            (enrollment["id"],),
        ).fetchone()
    assert tuple(secrets) == ("", "", "", "")


def test_account_enrollment_rejects_oauth_identity_mismatch(database, settings):
    coordinator, sub2api = make_coordinator(database, settings, oauth=EnrollmentOAuth("other@example.com"))
    enrollment = coordinator.enqueue_account_enrollment(
        email="owner@example.com",
        email_password="mail-secret",
        openai_password="openai-secret",
    )

    coordinator.process_one_account_enrollment()

    result = database.get_account_enrollment(enrollment["id"])
    assert result["status"] == "failed"
    assert result["stage"] == "identity_check"
    assert "不一致" in result["error_reason"]
    assert sub2api.created == []


def test_account_enrollment_reports_the_exact_automatic_browser_failure_stage(database, settings):
    coordinator, sub2api = make_coordinator(database, settings)

    class MailboxFailureBrowser:
        def run(self, auth_url, material, *, started_at, on_stage):
            on_stage("email_code", "Reading the verification code from the mailbox")
            raise AutomaticBrowserError("mailbox login was rejected", stage="email_code", retryable=False)

    coordinator.automatic_browser = MailboxFailureBrowser()
    enrollment = coordinator.enqueue_account_enrollment(
        email="owner@example.com",
        email_password="mail-secret",
        openai_password="openai-secret",
    )

    coordinator.process_one_account_enrollment()

    result = database.get_account_enrollment(enrollment["id"])
    assert result["status"] == "failed"
    assert result["stage"] == "email_code"
    assert result["error_reason"] == "mailbox login was rejected"
    assert sub2api.created == []
