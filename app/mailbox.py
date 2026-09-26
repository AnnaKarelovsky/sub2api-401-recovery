from __future__ import annotations

import email
import email.policy
import imaplib
import re
import time
from datetime import datetime, timezone
from email.header import decode_header
from email.message import Message
from typing import Any, Callable
from urllib.parse import urlparse

from .config import Settings
from .redaction import safe_error


class MailboxError(RuntimeError):
    def __init__(self, reason: str, *, retryable: bool = True):
        super().__init__(reason)
        self.reason = safe_error(reason)
        self.retryable = retryable


class ImapCodeReader:
    def __init__(self, settings: Settings, *, connection_factory: Callable[..., Any] | None = None):
        self.settings = settings
        self.connection_factory = connection_factory or imaplib.IMAP4_SSL

    def wait_for_code(
        self,
        email_address: str,
        password: str,
        *,
        since: datetime,
        timeout_seconds: int | None = None,
    ) -> str:
        deadline = time.monotonic() + (timeout_seconds or self.settings.mail_code_timeout_seconds)
        last_error = ""
        while time.monotonic() < deadline:
            try:
                code = self._read_latest(email_address, password, since=since)
            except (imaplib.IMAP4.error, OSError, TimeoutError) as exc:
                last_error = safe_error(exc)
                break
            if code:
                return code
            time.sleep(max(1, self.settings.mail_poll_seconds))
        if last_error:
            raise MailboxError(f"IMAP mailbox access failed: {last_error}")
        raise MailboxError("No new OpenAI verification code arrived before timeout")

    def _read_latest(self, email_address: str, password: str, *, since: datetime) -> str:
        connection = self.connection_factory(
            self.settings.mail_imap_host,
            self.settings.mail_imap_port,
            timeout=min(30, max(5, self.settings.mail_code_timeout_seconds)),
        )
        try:
            try:
                connection.login(email_address, password)
            except Exception as exc:
                raise MailboxError("IMAP mailbox credentials were rejected", retryable=False) from exc
            status, _ = connection.select(self.settings.mail_imap_folder, readonly=True)
            if status != "OK":
                raise MailboxError("IMAP mailbox folder could not be opened")
            date_value = since.astimezone(timezone.utc).strftime("%d-%b-%Y")
            status, data = connection.search(None, "SINCE", date_value)
            if status != "OK" or not data or not data[0]:
                return ""
            message_ids = data[0].split()[-20:]
            for message_id in reversed(message_ids):
                status, fetched = connection.fetch(message_id, "(RFC822)")
                if status != "OK":
                    continue
                for item in fetched or []:
                    if not isinstance(item, tuple) or len(item) < 2:
                        continue
                    message = email.message_from_bytes(item[1], policy=email.policy.default)
                    received_at = _message_date(message)
                    if received_at and received_at < since:
                        continue
                    subject = _decode_header(str(message.get("Subject") or ""))
                    body = _message_text(message)
                    if not _looks_like_openai(subject + "\n" + body):
                        continue
                    match = re.search(r"(?<!\d)(\d{6})(?!\d)", subject + "\n" + body)
                    if match:
                        return match.group(1)
            return ""
        finally:
            try:
                connection.logout()
            except Exception:
                pass


class OutlookWebCodeReader:
    """Read a recent verification mail from Outlook Web in an existing browser context."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def wait_for_code(
        self,
        email_address: str,
        password: str,
        *,
        since: datetime,
        timeout_seconds: int | None = None,
        context: Any | None = None,
    ) -> str:
        if context is None:
            raise MailboxError("Outlook Webmail requires an active browser context", retryable=False)
        page = context.new_page()
        deadline = time.monotonic() + (timeout_seconds or self.settings.mail_code_timeout_seconds)
        email_done = False
        password_done = False
        body_unavailable_since: float | None = None
        page_responses: list[str] = []

        def capture_response(response: Any) -> None:
            try:
                parsed = urlparse(str(response.url))
                hostname = parsed.hostname or ""
                trusted_host = hostname in {"outlook.live.com", "login.live.com", "login.microsoftonline.com"} or hostname.endswith(
                    (".live.com", ".office.com", ".microsoftonline.com")
                )
                request = getattr(response, "request", None)
                resource_type = str(getattr(request, "resource_type", ""))
                if not trusted_host or (resource_type != "document" and response.status < 400):
                    return
                path = self._safe_mail_path(parsed.path)
                page_responses.append(f"{hostname}{path} HTTP {response.status}")
                del page_responses[:-4]
            except Exception:
                return

        try:
            page.on("response", capture_response)
            page.goto("https://outlook.live.com/mail/0/", wait_until="domcontentloaded", timeout=60_000)
            while time.monotonic() < deadline:
                try:
                    body = " ".join(page.locator("body").inner_text(timeout=5000).split())
                    body_unavailable_since = None
                except Exception as exc:
                    if exc.__class__.__name__ not in {"TimeoutError", "TimeoutErrorImpl"}:
                        raise
                    body_unavailable_since = body_unavailable_since or time.monotonic()
                    if time.monotonic() - body_unavailable_since >= 30:
                        raise MailboxError(self._page_unavailable_reason(page, page_responses)) from exc
                    page.wait_for_timeout(1000)
                    continue
                if _looks_like_openai(body):
                    match = re.search(r"(?<!\d)(\d{6})(?!\d)", body)
                    if match:
                        return match.group(1)
                if any(marker in body.lower() for marker in ("incorrect password", "account doesn’t exist", "account doesn't exist")):
                    raise MailboxError("Outlook mailbox credentials were rejected", retryable=False)
                if not email_done:
                    locator = _first_visible(page, ("input[type='email']", "input[autocomplete='username']"))
                    if locator is not None:
                        locator.fill(email_address)
                        _click_matching(page, ("next", "continue", "sign in"))
                        email_done = True
                        page.wait_for_timeout(800)
                        continue
                if not password_done:
                    locator = _first_visible(page, ("input[type='password']",))
                    if locator is not None:
                        locator.fill(password)
                        _click_matching(page, ("sign in", "next", "continue"))
                        password_done = True
                        page.wait_for_timeout(1200)
                        continue
                page.wait_for_timeout(max(1000, self.settings.mail_poll_seconds * 1000))
            raise MailboxError("No new OpenAI verification code arrived from Outlook Webmail")
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError(f"Outlook Webmail access failed: {safe_error(exc)}") from exc
        finally:
            page.close()

    @staticmethod
    def _safe_mail_path(path: str) -> str:
        path = re.sub(r"(?i)(?<=/)[0-9a-f]{10,}(?=/|$)", "[id]", path)
        return re.sub(r"(?<=/)\d{6,}(?=/|$)", "[id]", path)

    @staticmethod
    def _page_unavailable_reason(page: Any, responses: list[str]) -> str:
        try:
            path = OutlookWebCodeReader._safe_mail_path(urlparse(str(page.url)).path or "/")
        except Exception:
            path = "/unknown"
        recent = ",".join(responses[-4:]) if responses else "none"
        return f"Outlook Webmail page did not load content (path={path}; responses={recent})"


def _looks_like_openai(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in ("openai", "chatgpt", "codex", "verification code", "one-time code"))


def _first_visible(page: Any, selectors: tuple[str, ...]) -> Any | None:
    for selector in selectors:
        locator = page.locator(selector)
        for index in range(locator.count()):
            candidate = locator.nth(index)
            try:
                if candidate.is_visible(timeout=1000):
                    return candidate
            except Exception:
                continue
    return None


def _click_matching(page: Any, words: tuple[str, ...]) -> bool:
    for selector in ("button", "input[type='submit']"):
        locator = page.locator(selector)
        for index in range(locator.count()):
            candidate = locator.nth(index)
            try:
                if not candidate.is_visible(timeout=1000) or not candidate.is_enabled(timeout=1000):
                    continue
            except Exception:
                continue
            label = " ".join(
                filter(None, (candidate.inner_text(), candidate.get_attribute("aria-label"), candidate.get_attribute("value")))
            ).lower()
            if any(word in label for word in words):
                candidate.click()
                return True
    return False


def _message_text(message: Message) -> str:
    parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    else:
        payload = message.get_payload(decode=True)
        if isinstance(payload, bytes):
            parts.append(payload.decode(message.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(parts)


def _decode_header(value: str) -> str:
    parts: list[str] = []
    for chunk, encoding in decode_header(value):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(encoding or "utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return "".join(parts)


def _message_date(message: Message) -> datetime | None:
    value = message.get("Date")
    if not value:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
