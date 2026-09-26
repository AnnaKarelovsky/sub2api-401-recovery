from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.mailbox import ImapCodeReader, OutlookWebCodeReader
from app.note_credentials import NoteCredentials, parse_account_notes
from app.totp import normalize_totp_secret, totp_code
from app.automatic_browser import AutomaticBrowserError, AutomaticOAuthRunner


def test_parse_nested_account_note_credentials():
    parsed = parse_account_notes(
        '{"mailbox":{"bind_email":"owner@example.com","password":"mail-pass"},'
        '"gpt":{"password":"gpt-pass"},'
        '"two_factor":{"secret":"JBSWY3DPEHPK3PXP"}}'
    )

    assert parsed.email == "owner@example.com"
    assert parsed.email_password == "mail-pass"
    assert parsed.openai_password == "gpt-pass"
    assert parsed.totp_secret == "JBSWY3DPEHPK3PXP"
    assert parsed.complete


def test_parse_note_key_values_and_fallback_email():
    parsed = parse_account_notes(
        "邮箱密码: mail-pass\nGPT密码=gpt-pass\n2FA密钥: JBSWY3DPEHPK3PXP",
        fallback_email="owner@example.com",
    )

    assert parsed.email == "owner@example.com"
    assert parsed.complete


def test_partial_material_is_ready_until_an_optional_step_is_reached(settings):
    material = NoteCredentials(email="owner@example.com", openai_password="gpt-pass")
    assert material.ready_for_automation
    assert not material.complete
    assert material.missing_required_fields == ()
    assert material.missing_fields == ("邮箱密码", "2FA 密钥")

    runner = AutomaticOAuthRunner(settings)
    runner._run_once = lambda auth_url, received, **kwargs: "http://localhost:1455/auth/callback?code=x&state=y"
    assert runner.run("https://auth.example.test", material) == "http://localhost:1455/auth/callback?code=x&state=y"


def test_totp_matches_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert normalize_totp_secret("otpauth://totp/Test?secret=" + secret) == secret
    assert totp_code(secret, timestamp=59, digits=8) == "94287082"


def test_security_page_markers_are_classified_for_retry():
    assert AutomaticOAuthRunner._is_security_error("Oops, an error occurred. Try again")


def test_verification_code_errors_are_detected_without_logging_the_code():
    assert AutomaticOAuthRunner._is_verification_code_rejected("The code is incorrect. Try again.")
    assert AutomaticOAuthRunner._is_verification_code_rejected("This code has expired")
    assert not AutomaticOAuthRunner._is_verification_code_rejected("Enter the code from your authenticator app")


def test_click_matching_supports_accessibility_role_buttons(settings):
    class RoleButtonPage:
        def __init__(self):
            self.clicked = False

        def locator(self, selector):
            class Locator:
                def __init__(self, page, name):
                    self.page = page
                    self.name = name

                def count(self):
                    return int(self.name == "[role='button']")

                def nth(self, index):
                    class Button:
                        def is_visible(self, timeout=None):
                            return True

                        def is_enabled(self, timeout=None):
                            return True

                        def inner_text(self):
                            return "Continue authorization"

                        def get_attribute(self, name):
                            return None

                        def click(self, **kwargs):
                            page.clicked = True

                    page = self.page
                    return Button()

            return Locator(self, selector)

    page = RoleButtonPage()

    assert AutomaticOAuthRunner._click_consent_or_continue(page)
    assert page.clicked


def test_auth_response_diagnostic_omits_query_and_redacts_challenge_id():
    response = SimpleNamespace(
        url=(
            "https://auth.openai.com/api/accounts/mfa/"
            "a1b2c3d4e5f607182930aabbccddeeff?code=private-code&state=private-state"
        ),
        status=403,
        request=SimpleNamespace(method="POST"),
    )

    summary = AutomaticOAuthRunner._auth_response_summary(response)

    assert summary == "POST /api/accounts/mfa/[id] HTTP 403 category=access_denied"
    assert "private-code" not in summary
    assert "private-state" not in summary
    cloudflare_response = SimpleNamespace(
        url="https://auth.openai.com/cdn-cgi/challenge-platform/h/b/scripts/jsd/d76008a69eab/main.js",
        status=200,
        request=SimpleNamespace(method="GET"),
    )
    assert AutomaticOAuthRunner._auth_response_summary(cloudflare_response) is None


def test_auth_response_diagnostic_does_not_read_or_log_response_body():
    body_reads = []

    def response_body():
        body_reads.append(True)
        return {
            "error": {"code": "invalid_otp", "message": "Invalid code for owner@example.com"},
            "access_token": "private-token",
        }

    response = SimpleNamespace(
        url="https://auth.openai.com/api/accounts/mfa/verify?state=private-state",
        status=403,
        request=SimpleNamespace(method="POST"),
        json=response_body,
    )

    summary = AutomaticOAuthRunner._auth_response_summary(response)

    assert summary == "POST /api/accounts/mfa/verify HTTP 403 category=access_denied"
    assert body_reads == []
    assert "owner@example.com" not in summary
    assert "private-token" not in summary

    generic_forbidden = SimpleNamespace(
        url="https://auth.openai.com/api/accounts/mfa/verify",
        status=403,
        request=SimpleNamespace(method="POST"),
        json=lambda: {"error": {"message": "Request denied"}},
    )
    assert AutomaticOAuthRunner._auth_response_summary(generic_forbidden).endswith("category=access_denied")


def test_mfa_denials_stop_blind_retries_except_transient_categories():
    reason, retryable = AutomaticOAuthRunner._mfa_denial_reason("unclassified", status=403)
    assert "unclassified denial" in reason
    assert not retryable

    reason, retryable = AutomaticOAuthRunner._mfa_denial_reason("rate_limited", status=429)
    assert "rate-limited" in reason
    assert retryable


def test_mfa_http_denial_is_reported_as_terminal_totp_failure(settings):
    runner = AutomaticOAuthRunner(settings)
    page = SimpleNamespace(
        url="https://auth.openai.com/mfa-challenge/opaque",
        wait_for_timeout=lambda _milliseconds: None,
    )

    try:
        runner._complete_login(
            page,
            None,
            NoteCredentials(email="owner@example.com", openai_password="password"),
            datetime.now(timezone.utc),
            mfa_denials=[(403, "access_denied")],
        )
    except AutomaticBrowserError as exc:
        assert exc.stage == "totp"
        assert not exc.retryable
        assert "HTTP 403" in exc.reason
    else:
        raise AssertionError("MFA HTTP denial should stop the OAuth flow")


def test_account_deactivated_page_is_not_misreported_as_totp_failure(settings):
    class DisabledPage:
        url = "https://auth.openai.com/error"

        def locator(self, selector):
            class Body:
                def inner_text(self, timeout=None):
                    return "身份验证错误 该帐户已被删除或停用 错误代码: account_deactivated"

            return Body()

    runner = AutomaticOAuthRunner(settings)
    try:
        runner._complete_login(
            DisabledPage(),
            None,
            NoteCredentials(email="owner@example.com", openai_password="password"),
            datetime.now(timezone.utc),
            mfa_denials=[(403, "access_denied")],
        )
    except AutomaticBrowserError as exc:
        assert exc.stage == "account_disabled"
        assert not exc.retryable
        assert "account_deactivated" in exc.reason
    else:
        raise AssertionError("disabled account page should be classified as account disabled")


def test_managed_browser_cleanup_terminates_process_before_closing_browser():
    class Process:
        terminated = False
        waited = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            self.waited = True

    process = Process()

    class Browser:
        closed = False

        def close(self):
            assert process.terminated
            self.closed = True

    browser = Browser()

    AutomaticOAuthRunner._cleanup_managed_browser(browser, process, None)

    assert process.waited
    assert browser.closed


def test_outlook_webmail_diagnostic_redacts_dynamic_url_values():
    page = SimpleNamespace(
        url="https://outlook.live.com/mail/123456789012/?auth=private-value"
    )

    reason = OutlookWebCodeReader._page_unavailable_reason(
        page,
        ["login.live.com/authorize HTTP 302"],
    )

    assert "path=/mail/[id]/" in reason
    assert "login.live.com/authorize HTTP 302" in reason
    assert "private-value" not in reason


def test_page_diagnostic_classifies_link_without_recording_its_text():
    class LinkPage:
        def locator(self, selector):
            class Locator:
                def __init__(self, selector):
                    self.selector = selector

                def count(self):
                    return int(self.selector == "a[href]")

                def nth(self, index):
                    class Link:
                        def is_visible(self, timeout=None):
                            return True

                        def inner_text(self):
                            return "Try another method"

                        def get_attribute(self, name):
                            return None

                    return Link()

            return Locator(selector)

    assert AutomaticOAuthRunner._visible_link_actions(LinkPage()) == ["alternate_method"]


class FakeElement:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def is_visible(self, timeout=None):
        return self.selector == "input[autocomplete='one-time-code']" or self.selector == "button"

    def is_enabled(self, timeout=None):
        return True

    def get_attribute(self, name):
        if name == "maxlength":
            return "6"
        if name == "value":
            return ""
        return None

    def inner_text(self):
        return "Verify"

    def fill(self, value):
        self.page.submitted_codes.append(value)

    def click(self, **kwargs):
        self.page.clicks += 1
        if self.page.accept_second and self.page.clicks == 2:
            self.page.url = "http://localhost:1455/auth/callback?code=ok&state=ok"
        else:
            self.page.body = "Incorrect code. Try again."


class FakeLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def count(self):
        if self.selector == "body":
            return 1
        if self.selector in ("input[autocomplete='one-time-code']", "button"):
            return 1
        return 0

    def nth(self, index):
        return FakeElement(self.page, self.selector)

    def inner_text(self, timeout=None):
        return self.page.body


class FakeOtpPage:
    def __init__(self, *, accept_second=False):
        self.url = "https://auth.openai.com/u/login/verify"
        self.body = "Enter the code from your authenticator app"
        self.accept_second = accept_second
        self.clicks = 0
        self.submitted_codes = []

    def title(self):
        return "Sign in"

    def locator(self, selector):
        return FakeLocator(self, selector)

    def wait_for_timeout(self, milliseconds):
        return None


class FakeProgressPage:
    def __init__(self):
        self.url = "https://auth.openai.com/u/login/authorize"
        self.body = "Preparing authorization"
        self.wait_count = 0

    def title(self):
        return "Authorize"

    def locator(self, selector):
        return FakeProgressLocator(self, selector)

    def wait_for_timeout(self, milliseconds):
        self.wait_count += 1
        self.body = f"Authorization progress stage {chr(64 + self.wait_count)}"
        if self.wait_count == 30:
            self.url = "http://localhost:1455/auth/callback?code=ok&state=ok"


class FakeProgressLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def count(self):
        return int(self.selector == "body")

    def inner_text(self, timeout=None):
        return self.page.body


def test_login_waits_beyond_24_page_checks_for_oauth_callback(settings):
    runner = AutomaticOAuthRunner(settings)
    page = FakeProgressPage()
    material = NoteCredentials(email="owner@example.com", openai_password="gpt-pass")

    runner._complete_login(page, None, material, datetime.now(timezone.utc))

    assert page.wait_count == 30
    assert runner._is_callback(page.url)


def test_rejected_totp_retries_once_with_fresh_code(settings):
    runner = AutomaticOAuthRunner(settings)
    runner._fresh_totp_code = lambda secret, previous, page: "654321"
    page = FakeOtpPage(accept_second=True)
    material = NoteCredentials(
        email="owner@example.com",
        openai_password="gpt-pass",
        totp_secret="JBSWY3DPEHPK3PXP",
    )

    runner._complete_login(page, None, material, datetime.now(timezone.utc))

    assert page.clicks == 2
    assert len(page.submitted_codes) == 2
    assert len(page.submitted_codes[0]) == 6
    assert page.submitted_codes[1] == "654321"


def test_repeated_totp_rejection_reports_totp_stage(settings):
    runner = AutomaticOAuthRunner(settings)
    runner._fresh_totp_code = lambda secret, previous, page: "654321"
    page = FakeOtpPage()
    material = NoteCredentials(
        email="owner@example.com",
        openai_password="gpt-pass",
        totp_secret="JBSWY3DPEHPK3PXP",
    )

    try:
        runner._complete_login(page, None, material, datetime.now(timezone.utc))
    except AutomaticBrowserError as exc:
        assert exc.stage == "totp"
        assert "rejected the authenticator code twice" in exc.reason
    else:
        raise AssertionError("expected the second rejected TOTP to fail clearly")

    assert page.clicks == 2


def test_cloudflare_security_verification_page_is_waited_on():
    class FakePage:
        def title(self):
            return ""

        def locator(self, selector):
            class Body:
                def inner_text(self, timeout):
                    return "Performing security verification. This security service protects against malicious bots."

            return Body()

    assert AutomaticOAuthRunner._is_challenge(FakePage())


class FakeImap:
    def __init__(self, message: bytes):
        self.message = message
        self.logged_in = False

    def login(self, username: str, password: str):
        self.logged_in = True
        return "OK", []

    def select(self, folder: str, readonly: bool = True):
        return "OK", []

    def search(self, charset, *criteria):
        return "OK", [b"1"]

    def fetch(self, message_id, query):
        return "OK", [(b"RFC822", self.message)]

    def logout(self):
        return "OK", []


def test_imap_reader_extracts_recent_openai_code(settings):
    message = (
        b"Date: Wed, 16 Sep 2026 06:00:00 +0000\r\n"
        b"Subject: OpenAI verification code\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Your verification code is 123456."
    )
    reader = ImapCodeReader(settings, connection_factory=lambda *args, **kwargs: FakeImap(message))

    assert reader.wait_for_code(
        "owner@example.com",
        "mail-pass",
        since=datetime(2026, 9, 16, 5, 0, tzinfo=timezone.utc),
    ) == "123456"
