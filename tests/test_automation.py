from __future__ import annotations

from datetime import datetime, timezone

from app.mailbox import ImapCodeReader
from app.note_credentials import parse_account_notes
from app.totp import normalize_totp_secret, totp_code
from app.automatic_browser import AutomaticOAuthRunner


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


def test_totp_matches_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert normalize_totp_secret("otpauth://totp/Test?secret=" + secret) == secret
    assert totp_code(secret, timestamp=59, digits=8) == "94287082"


def test_security_page_markers_are_classified_for_retry():
    assert AutomaticOAuthRunner._is_security_error("Oops, an error occurred. Try again")


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
