from __future__ import annotations

import imaplib
from datetime import datetime, timezone
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from app.mailbox import (
    ImapAccountDisabledReader,
    ImapCodeReader,
    MailboxError,
    Netease163WebCodeReader,
    MailboxEvidence,
    OutlookWebAccountDisabledReader,
    OutlookWebCodeReader,
    render_mailbox_evidence_screenshot,
)
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


def test_microsoft_security_rate_limit_is_detected():
    assert OutlookWebAccountDisabledReader._is_security_rate_limited(
        "You've requested too many codes today. Please try again tomorrow."
    )
    assert OutlookWebAccountDisabledReader._is_security_rate_limited("请求次数过多，请明天再试")
    assert not OutlookWebAccountDisabledReader._is_security_rate_limited("Enter the security code")


def test_security_email_code_prompt_accepts_mailbox_copy_variants():
    assert OutlookWebAccountDisabledReader._is_email_code_prompt("检查你的邮箱并输入邮件中的代码")
    assert OutlookWebAccountDisabledReader._is_email_code_prompt("Enter the code we sent")


def test_outlook_account_disabled_reader_searches_and_captures_the_matching_email(settings):
    screenshot = b"\x89PNG\r\n\x1a\nsource-mail-screenshot"

    class Search:
        def __init__(self):
            self.values = []

        def is_visible(self, timeout=None):
            return True

        def fill(self, value):
            self.values.append(value)

        def press(self, key, timeout=None):
            assert key == "Enter"

    class Candidate:
        def is_visible(self, timeout=None):
            return True

        def inner_text(self, timeout=None):
            return "OpenAI account deactivated 10/14/2026 9:30 AM"

        def evaluate(self, script):
            return ["2026-10-14T09:30:00+08:00"]

        def click(self, timeout=None):
            return None

    class Group:
        def __init__(self, items):
            self.items = items

        def count(self):
            return len(self.items)

        def nth(self, index):
            return self.items[index]

    class Body:
        def inner_text(self, timeout=None):
            return "Your OpenAI account has been deactivated."

    class Page:
        url = "https://outlook.live.com/mail/0/inbox"

        def __init__(self):
            self.search = Search()

        def locator(self, selector):
            if selector == "input[placeholder='Search']":
                return Group([self.search])
            if selector == "body":
                return Body()
            return Group([])

        def get_by_role(self, role):
            assert role == "option"
            return Group([Candidate()])

        def get_by_text(self, pattern, exact=False):
            return Group([])

        def wait_for_timeout(self, timeout):
            return None

        def screenshot(self, **kwargs):
            return screenshot

    page = Page()
    evidence = OutlookWebAccountDisabledReader(settings)._search_for_account_disabled_message(
        page,
        since=datetime(2026, 10, 13, tzinfo=timezone.utc),
        submit=True,
    )

    assert isinstance(evidence, MailboxEvidence)
    assert evidence.screenshot == screenshot
    assert page.search.values == ["", "OpenAI"]
    assert render_mailbox_evidence_screenshot(evidence, settings) == screenshot


def test_outlook_web_code_reader_parses_locale_received_time(settings):
    reader = OutlookWebCodeReader(settings)
    parsed = reader._parse_received_time("10/14/2026, 3:50 PM")
    assert parsed == datetime(2026, 10, 14, 15, 50, tzinfo=ZoneInfo("Asia/Shanghai"))


def test_outlook_web_code_reader_parses_chinese_relative_received_time(settings, monkeypatch):
    reader = OutlookWebCodeReader(settings)
    monkeypatch.setattr("app.mailbox.datetime", datetime)
    assert reader._parse_received_time("今天 16:47") is not None


def test_outlook_web_code_reader_requires_trusted_recent_microsoft_mail(settings):
    reader = OutlookWebCodeReader(settings)
    since = datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc)
    sender = "Microsoft account team <account-security-noreply@accountprotection.microsoft.com>"
    body = "Microsoft account Security code: 1234567"

    assert reader._extract_security_code(
        sender, body, received_at=since, since=since
    ) == "1234567"
    assert reader._extract_security_code(
        "attacker@example.com", body, received_at=since, since=since
    ) == ""
    assert reader._extract_security_code(
        sender,
        body,
        received_at=since.replace(hour=6),
        since=since,
    ) == ""


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


def test_click_action_submits_the_active_field_before_scanning_page_buttons():
    class Field:
        def __init__(self):
            self.pressed = []

        def press(self, key, timeout=None):
            self.pressed.append((key, timeout))

    field = Field()

    assert AutomaticOAuthRunner._click_action(object(), field=field)
    assert field.pressed == [("Enter", 3000)]


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


def test_mfa_response_body_can_identify_deleted_account_without_rendered_error_page():
    response = SimpleNamespace(
        text=lambda: '{"error_code":"account_deactivated"}',
    )

    assert AutomaticOAuthRunner._response_indicates_account_disabled(response)


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

        def screenshot(self, **kwargs):
            assert kwargs == {"type": "png", "animations": "disabled"}
            return b"\x89PNG\r\n\x1a\naccount-disabled-page"

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
        assert exc.evidence == b"\x89PNG\r\n\x1a\naccount-disabled-page"
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


def test_outlook_webmail_security_prompt_is_classified_without_calling_it_a_password_error():
    assert OutlookWebAccountDisabledReader._is_security_prompt("帮助保护你的帐户 添加电子邮件")
    assert OutlookWebAccountDisabledReader._is_add_email_prompt("帮助保护你的帐户 添加电子邮件")
    assert OutlookWebAccountDisabledReader._is_add_email_prompt("Help protect your account Add email")
    assert not OutlookWebAccountDisabledReader._is_add_email_prompt("Verify your identity")
    assert OutlookWebAccountDisabledReader._is_human_challenge("Verify you are human")
    assert not OutlookWebAccountDisabledReader._is_login_rejection("帮助保护你的帐户")
    assert OutlookWebAccountDisabledReader._is_login_rejection("Incorrect password")
    assert OutlookWebAccountDisabledReader._is_security_url(
        "https://account.live.com/interrupt/credentialaction?opaque=value"
    )


def test_openai_oauth_region_error_is_classified_as_a_blocked_environment():
    assert AutomaticOAuthRunner._is_region_error(
        '{"error":{"code":"unsupported_country_region_territory"}}'
    )
    assert not AutomaticOAuthRunner._is_region_error("Welcome back")


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


def test_imap_reader_extracts_microsoft_security_code_from_163(settings):
    message = (
        b"Date: Wed, 16 Sep 2026 06:00:00 +0000\r\n"
        b"From: Microsoft account security code <account-security-noreply@accountprotection.microsoft.com>\r\n"
        b"Subject: Microsoft account security code\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Use this code to verify your email: 1234567."
    )
    connection_args = []

    def connect(*args, **kwargs):
        connection_args.append(args)
        return FakeImap(message)

    reader = ImapCodeReader(settings, connection_factory=connect)

    assert reader.wait_for_code(
        "owner@163.com",
        "imap-auth-code",
        since=datetime(2026, 9, 16, 5, 0, tzinfo=timezone.utc),
        purpose="microsoft_security",
    ) == "1234567"
    assert connection_args[0][0] == "imap.163.com"


def test_imap_access_preflight_selects_inbox_read_only(settings):
    calls = []

    class TrackingImap(FakeImap):
        def select(self, folder, readonly=True):
            calls.append((folder, readonly))
            return "OK", []

    reader = ImapCodeReader(settings, connection_factory=lambda *args, **kwargs: TrackingImap(b""))
    reader.validate_access("owner@163.com", "imap-auth-code")

    assert calls == [("INBOX", True)]


def test_163_webmail_reader_only_extracts_recent_microsoft_security_codes(settings):
    reader = Netease163WebCodeReader(settings)
    since = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)
    message = (
        "Microsoft account security code "
        "account-security-noreply@accountprotection.microsoft.com "
        "Your security code is 1234567."
    )

    assert reader._extract_code(message, received_at=since, since=since) == "1234567"
    assert reader._extract_code(message, received_at=since.replace(hour=9), since=since) == ""
    assert reader._extract_code(
        message.replace("account-security-noreply@accountprotection.microsoft.com", "attacker@example.net"),
        received_at=since,
        since=since,
    ) == ""
    assert reader._extract_code_from_bodies(
        [
            "Microsoft account security code account-security-noreply@accountprotection.microsoft.com",
            "Your security code is 1234567.",
        ],
        received_at=since,
        since=since,
    ) == "1234567"


def test_163_webmail_reader_parses_localized_received_time():
    class Candidate:
        def evaluate(self, _script):
            return ["2026/10/13 18:30"]

    assert Netease163WebCodeReader._message_received_at(Candidate()) == datetime(
        2026, 10, 13, 10, 30, tzinfo=timezone.utc
    )
    assert Netease163WebCodeReader._parse_received_text("主题 2026/10/13 18:30 发件人") == datetime(
        2026, 10, 13, 10, 30, tzinfo=timezone.utc
    )


def test_163_webmail_reader_allows_minute_precision_overlap():
    reader = Netease163WebCodeReader(None)
    message = (
        "Microsoft account security code "
        "account-security-noreply@accountprotection.microsoft.com "
        "Your security code is 1234567."
    )
    since = datetime(2026, 10, 13, 10, 30, 42, tzinfo=timezone.utc)

    assert reader._extract_code(
        message,
        received_at=datetime(2026, 10, 13, 10, 30, tzinfo=timezone.utc),
        since=since,
    ) == "1234567"
    assert reader._extract_code(
        message,
        received_at=datetime(2026, 10, 13, 10, 28, 59, tzinfo=timezone.utc),
        since=since,
    ) == ""


def test_microsoft_code_reader_rejects_untrusted_sender(settings):
    message = (
        b"Date: Wed, 16 Sep 2026 06:00:00 +0000\r\n"
        b"From: attacker@example.net\r\n"
        b"Subject: Microsoft account security code\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Use this code to verify your email: 1234567."
    )
    reader = ImapCodeReader(settings, connection_factory=lambda *args, **kwargs: FakeImap(message))

    with pytest.raises(MailboxError, match="No new Microsoft security verification code"):
        reader.wait_for_code(
            "owner@163.com",
            "imap-auth-code",
            since=datetime(2026, 9, 16, 5, 0, tzinfo=timezone.utc),
            timeout_seconds=1,
            purpose="microsoft_security",
        )


def test_imap_reader_finds_recent_openai_disabled_mail(settings):
    message = (
        b"Date: Wed, 16 Sep 2026 06:00:00 +0000\r\n"
        b"Subject: Your OpenAI account has been deactivated\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Your account has been deactivated because of a violation of our policies."
    )
    reader = ImapAccountDisabledReader(settings, connection_factory=lambda *args, **kwargs: FakeImap(message))

    evidence = reader.find_account_disabled_message(
        "owner@outlook.com",
        "mail-pass",
        since=datetime(2026, 9, 16, 5, 0, tzinfo=timezone.utc),
    )

    assert evidence is not None
    assert evidence.provider == "outlook.office365.com"
    assert "deactivated" in evidence.subject.lower()
    assert "violation" in evidence.excerpt.lower()


def test_imap_reader_classifies_rejected_credentials(settings):
    class RejectingImap(FakeImap):
        def login(self, username: str, password: str):
            raise imaplib.IMAP4.error("AUTHENTICATIONFAILED")

    reader = ImapAccountDisabledReader(settings, connection_factory=lambda *args, **kwargs: RejectingImap(b""))

    with pytest.raises(MailboxError) as raised:
        reader.find_account_disabled_message(
            "owner@outlook.com",
            "wrong-password",
            since=datetime(2026, 9, 16, 5, 0, tzinfo=timezone.utc),
        )

    assert raised.value.code == "imap_login_rejected"
    assert not raised.value.retryable
    assert "does not confirm" in raised.value.reason
