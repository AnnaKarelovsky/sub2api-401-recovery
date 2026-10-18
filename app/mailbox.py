from __future__ import annotations

import email
import email.policy
import html
import imaplib
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from email.message import Message
from typing import Any, Callable, Literal
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from .config import Settings
from .redaction import safe_error


class MailboxError(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        retryable: bool = True,
        code: str = "",
        evidence: bytes | None = None,
        evidence_error: str | None = None,
    ):
        super().__init__(reason)
        self.reason = safe_error(reason)
        self.retryable = retryable
        self.code = code
        self.evidence = evidence
        self.evidence_error = safe_error(evidence_error) if evidence_error else None


@dataclass(frozen=True)
class MailboxEvidence:
    provider: str
    subject: str
    received_at: datetime | None
    excerpt: str
    screenshot: bytes | None = None


class ImapAccountDisabledReader:
    """Find recent OpenAI account-status mail without exposing mailbox contents to logs."""

    def __init__(self, settings: Settings, *, connection_factory: Callable[..., Any] | None = None):
        self.settings = settings
        self.connection_factory = connection_factory or imaplib.IMAP4_SSL

    def find_account_disabled_message(
        self,
        email_address: str,
        password: str,
        *,
        since: datetime,
    ) -> MailboxEvidence | None:
        domain = str(email_address.rsplit("@", 1)[-1]).strip().lower()
        if domain in {"example.com", "example.test", "invalid"}:
            raise MailboxError("mailbox provider is not configured for this address", retryable=False)
        host = self._host_for_email(email_address)
        try:
            connection = self.connection_factory(
                host,
                self.settings.mail_imap_port,
                timeout=min(30, max(5, self.settings.mail_code_timeout_seconds)),
            )
        except (imaplib.IMAP4.error, OSError, TimeoutError) as exc:
            raise MailboxError(f"IMAP mailbox access failed: {safe_error(exc)}") from exc
        try:
            try:
                connection.login(email_address, password)
            except (imaplib.IMAP4.error,) as exc:
                raise MailboxError(
                    "IMAP rejected the mailbox login; this does not confirm that webmail credentials are invalid",
                    retryable=False,
                    code="imap_login_rejected",
                ) from exc
            except (OSError, TimeoutError) as exc:
                raise MailboxError(
                    f"IMAP mailbox login failed: {safe_error(exc)}",
                    code="connection_failed",
                ) from exc
            except Exception as exc:
                raise MailboxError(
                    "IMAP mailbox login failed",
                    retryable=False,
                    code="imap_login_error",
                ) from exc
            status, _ = connection.select(self.settings.mail_imap_folder, readonly=True)
            if status != "OK":
                raise MailboxError("IMAP mailbox folder could not be opened")
            date_value = since.astimezone(timezone.utc).strftime("%d-%b-%Y")
            status, data = connection.search(None, "SINCE", date_value)
            if status != "OK" or not data or not data[0]:
                return None
            message_ids = data[0].split()[-50:]
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
                    subject = _decode_header(str(message.get("Subject") or "")).strip()
                    body = _message_text(message)
                    if not _looks_like_account_disabled_mail(subject, body):
                        continue
                    return MailboxEvidence(
                        provider=host,
                        subject=_safe_mail_text(subject, limit=240),
                        received_at=received_at,
                        excerpt=_safe_mail_text(body, limit=720),
                    )
            return None
        finally:
            try:
                connection.logout()
            except Exception:
                pass

    def _host_for_email(self, email_address: str) -> str:
        domain = str(email_address.rsplit("@", 1)[-1]).strip().lower()
        defaults = {
            "gmail.com": "imap.gmail.com",
            "googlemail.com": "imap.gmail.com",
            "icloud.com": "imap.mail.me.com",
            "me.com": "imap.mail.me.com",
            "mac.com": "imap.mail.me.com",
            "outlook.com": "outlook.office365.com",
            "hotmail.com": "outlook.office365.com",
            "live.com": "outlook.office365.com",
            "msn.com": "outlook.office365.com",
            "yahoo.com": "imap.mail.yahoo.com",
        }
        return defaults.get(domain, self.settings.mail_imap_host)


class OutlookWebAccountDisabledReader:
    """Read account-status mail through Outlook Web when IMAP basic auth is unavailable."""

    def __init__(
        self,
        settings: Settings,
        *,
        mailbox_lookup: Callable[[str], dict[str, str] | None] | None = None,
        code_reader: ImapCodeReader | None = None,
    ):
        self.settings = settings
        self.mailbox_lookup = mailbox_lookup
        self.code_reader = code_reader or ImapCodeReader(settings)

    def find_account_disabled_message(
        self,
        email_address: str,
        password: str,
        *,
        since: datetime,
    ) -> MailboxEvidence | None:
        domain = str(email_address.rsplit("@", 1)[-1]).strip().lower()
        if domain not in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
            raise MailboxError("Outlook Webmail fallback is only available for Microsoft mailboxes", retryable=False)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise MailboxError("Playwright is not installed; Outlook Webmail fallback is unavailable", retryable=False) from exc

        proxy = self.settings.playwright_proxy.strip()
        # Mailbox verification runs in the worker without a desktop session. The
        # interactive OAuth runner may use Xvfb, but this reader must stay headless.
        launch_options: dict[str, Any] = {"headless": True}
        if proxy:
            launch_options["proxy"] = {"server": proxy}
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_options)
                try:
                    page = browser.new_page(viewport={"width": 1440, "height": 900})
                    attach_playwright = getattr(self.code_reader, "attach_playwright", None)
                    detach_playwright = getattr(self.code_reader, "detach_playwright", None)
                    if attach_playwright:
                        attach_playwright(playwright)
                    try:
                        try:
                            return self._read_page(page, email_address, password, since=since)
                        except MailboxError as exc:
                            if exc.evidence is None:
                                try:
                                    exc.evidence = page.screenshot(
                                        type="png",
                                        full_page=True,
                                        animations="disabled",
                                    )
                                except Exception as screenshot_error:
                                    exc.evidence_error = safe_error(screenshot_error)
                            raise
                    finally:
                        if detach_playwright:
                            detach_playwright()
                finally:
                    browser.close()
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError(
                f"Outlook Webmail access failed: {safe_error(exc)}",
                retryable=True,
                code="webmail_unavailable",
            ) from exc

    def _read_page(
        self,
        page: Any,
        email_address: str,
        password: str,
        *,
        since: datetime,
    ) -> MailboxEvidence | None:
        # Microsoft may keep the OAuth handoff page blank while the next form
        # loads. Give that handoff its own bounded window instead of treating a
        # slow intermediate page as a bad password.
        deadline = time.monotonic() + max(60, int(self.settings.mail_code_timeout_seconds))
        email_submitted = False
        password_submitted = False
        authenticated = False
        security_email_attempted = False
        last_search_refresh = 0.0
        last_body = ""
        page.goto(
            "https://outlook.live.com/mail/0/?prompt=select_account",
            wait_until="domcontentloaded",
            timeout=60_000,
        )
        while time.monotonic() < deadline:
            try:
                body = " ".join(page.locator("body").inner_text(timeout=5000).split())
            except Exception:
                body = ""
            lowered = body.lower()
            last_body = lowered
            if self._is_security_rate_limited(lowered):
                raise MailboxError(
                    "Microsoft has rate-limited security email requests; try again tomorrow",
                    retryable=False,
                    code="webmail_security_rate_limited",
                )
            if self._is_human_challenge(lowered):
                raise MailboxError(
                    "Outlook Webmail requires an interactive human verification",
                    retryable=False,
                    code="webmail_human_verification_required",
                )
            security_url = self._is_security_url(page.url)
            if self._is_security_prompt(lowered) or security_url:
                # The credential-action URL is often committed before its
                # React page is hydrated. Do not classify an empty handoff as
                # a completed security challenge.
                if security_url and not self._is_security_prompt(lowered) and not self._is_email_code_prompt(lowered):
                    page.wait_for_timeout(1000)
                    continue
                if self._is_add_email_prompt(lowered) and not security_email_attempted:
                    self._complete_security_email_verification(page)
                    security_email_attempted = True
                    continue
                raise MailboxError(
                    "Outlook Webmail requires additional security verification",
                    retryable=False,
                    code="webmail_security_required",
                )
            if self._is_login_rejection(lowered):
                raise MailboxError(
                    "Outlook Webmail rejected the login",
                    retryable=False,
                    code="webmail_login_rejected",
                )
            if any(marker in lowered for marker in ("stay signed in", "保持登录", "保持登陆")):
                _click_matching(page, ("no", "否", "not now", "稍后"))
                page.wait_for_timeout(1000)
                continue
            if _looks_like_account_disabled_mail("", body):
                return MailboxEvidence(
                    provider="outlook.live.com",
                    subject="OpenAI account-status message found in Outlook Webmail",
                    received_at=None,
                    excerpt=_safe_mail_text(body, limit=720),
                    screenshot=page.screenshot(type="png", full_page=True, animations="disabled"),
                )

            email_locator = _first_visible(
                page,
                ("input[name='loginfmt']", "#i0116", "input[type='email']", "input[autocomplete='username']"),
            )
            password_locator = _first_visible(
                page,
                ("input[name='passwd']", "#i0118", "input[type='password']"),
            )
            if email_locator is None and password_locator is None and not email_submitted:
                if self._click_webmail_entry(page):
                    page.wait_for_timeout(1000)
                    continue
            if email_locator is not None and not email_submitted:
                email_locator.fill(email_address)
                if not _click_matching(page, ("next", "continue", "sign in")) and not _press_enter(email_locator):
                    raise MailboxError("Outlook Webmail login page did not provide a continue action", retryable=False, code="webmail_unavailable")
                email_submitted = True
                page.wait_for_timeout(800)
                continue
            # Microsoft can render the password input in the same DOM before
            # the email step has navigated. Wait until the email field is gone
            # so the password is submitted on the active page.
            if password_locator is not None and email_locator is None and not password_submitted:
                password_locator.fill(password)
                if not _click_matching(page, ("sign in", "next", "continue")) and not _press_enter(password_locator):
                    raise MailboxError("Outlook Webmail password page did not provide a continue action", retryable=False, code="webmail_unavailable")
                password_submitted = True
                page.wait_for_timeout(1200)
                continue
            if (
                password_submitted
                and email_locator is None
                and password_locator is None
                and not self._is_login_flow_url(page.url)
            ):
                authenticated = True
            if authenticated:
                refresh_search = time.monotonic() - last_search_refresh >= max(
                    5, self.settings.mail_poll_seconds
                )
                evidence = self._search_for_account_disabled_message(
                    page,
                    since=since,
                    submit=refresh_search,
                )
                if refresh_search:
                    last_search_refresh = time.monotonic()
                if evidence:
                    return evidence
            remaining_ms = max(250, int((deadline - time.monotonic()) * 1000))
            page.wait_for_timeout(min(max(500, self.settings.mail_poll_seconds * 1000), remaining_ms))

        try:
            final_body = " ".join(page.locator("body").inner_text(timeout=3000).split()).lower()
        except Exception:
            final_body = last_body
        if self._is_security_rate_limited(final_body):
            raise MailboxError(
                "Microsoft has rate-limited security email requests; try again tomorrow",
                retryable=False,
                code="webmail_security_rate_limited",
            )
        if self._is_human_challenge(final_body):
            raise MailboxError(
                "Outlook Webmail requires an interactive human verification",
                retryable=False,
                code="webmail_human_verification_required",
            )
        if self._is_security_prompt(final_body) or self._is_security_url(page.url):
            raise MailboxError(
                "Outlook Webmail requires additional security verification",
                retryable=False,
                code="webmail_security_required",
            )
        if self._is_login_rejection(final_body):
            raise MailboxError(
                "Outlook Webmail rejected the login",
                retryable=False,
                code="webmail_login_rejected",
            )
        if authenticated or (password_submitted and not self._is_login_flow_url(page.url)):
            return None
        path = self._safe_page_path(page.url)
        raise MailboxError(
            f"Outlook Webmail did not complete the login flow (path={path})",
            retryable=False,
            code="webmail_login_incomplete",
        )

    def _search_for_account_disabled_message(
        self,
        page: Any,
        *,
        since: datetime,
        submit: bool,
    ) -> MailboxEvidence | None:
        search = _first_visible(
            page,
            (
                "input[placeholder='Search']",
                "input[placeholder*='Search' i]",
                "input[placeholder*='搜索']",
                "input[aria-label*='Search' i]",
                "input[aria-label*='搜索']",
                "input[role='combobox']",
            ),
        )
        if search is None:
            return None
        if submit:
            search.fill("")
            search.fill("OpenAI")
            if not _press_enter(search):
                _click_matching(page, ("search", "搜索"))
            page.wait_for_timeout(1200)

        candidates: list[Any] = []
        options = page.get_by_role("option")
        for index in range(min(options.count(), 40)):
            candidate = options.nth(index)
            try:
                if candidate.is_visible(timeout=250):
                    row_text = candidate.inner_text(timeout=500)
                    if re.search(r"openai|chatgpt|codex", row_text, re.I):
                        candidates.append(candidate)
            except Exception:
                continue
        subjects = page.get_by_text(re.compile(r"openai|chatgpt|codex", re.I), exact=False)
        for index in range(min(subjects.count(), 20)):
            candidates.append(subjects.nth(index))

        for candidate in candidates:
            try:
                if not candidate.is_visible(timeout=250):
                    continue
                row_text = candidate.inner_text(timeout=500)
                received_at = OutlookWebCodeReader._message_received_at(candidate)
                if received_at is not None and received_at < since:
                    continue
                candidate.click(timeout=2000)
                page.wait_for_timeout(500)
                body = " ".join(page.locator("body").inner_text(timeout=3000).split())
                if not _looks_like_account_disabled_mail(row_text, body):
                    continue
                subject = _safe_mail_text(row_text, limit=240) or "OpenAI account-status message"
                return MailboxEvidence(
                    provider="outlook.live.com",
                    subject=subject,
                    received_at=received_at,
                    excerpt=_safe_mail_text(body, limit=720),
                    screenshot=page.screenshot(type="png", full_page=True, animations="disabled"),
                )
            except Exception:
                continue
        return None

    @staticmethod
    def _is_security_prompt(body: str) -> bool:
        body = str(body or "").lower()
        return any(
            marker in body
            for marker in (
                "help protect your account",
                "add email",
                "security info",
                "verify your identity",
                "保护你的帐户",
                "添加电子邮件",
                "安全信息",
            )
        )

    @staticmethod
    def _is_add_email_prompt(body: str) -> bool:
        lowered = str(body or "").lower()
        has_protection_prompt = any(
            marker in lowered
            for marker in ("help protect your account", "保护你的帐户", "帮助保护你的帐户")
        )
        has_add_email = any(
            marker in lowered
            for marker in ("add email", "add an email", "添加电子邮件", "添加邮箱")
        )
        return has_protection_prompt and has_add_email

    @staticmethod
    def _is_security_rate_limited(body: str) -> bool:
        lowered = str(body or "").lower()
        return any(
            marker in lowered
            for marker in (
                "requested too many codes today",
                "too many codes today",
                "try again tomorrow",
                "请求了太多代码",
                "请求次数过多",
                "请明天再试",
            )
        )

    @staticmethod
    def _is_human_challenge(body: str) -> bool:
        return any(
            marker in str(body or "").lower()
            for marker in (
                "verify you are human",
                "prove you're not a robot",
                "prove you are not a robot",
                "prove you're human",
                "i am not a robot",
                "captcha",
                "robot check",
                "complete the security check",
                "security check before continuing",
                "人机验证",
                "验证你是人类",
                "请证明你不是机器人",
                "请完成安全检查",
                "选择所有包含",
            )
        )

    def _complete_security_email_verification(self, page: Any) -> None:
        verification_email = self.settings.outlook_security_email.strip().lower()
        if not verification_email:
            raise MailboxError(
                "Configure a security email before retrying Outlook verification",
                retryable=False,
                code="webmail_security_email_not_configured",
            )
        if self.mailbox_lookup is None:
            raise MailboxError(
                "The configured 163 verification mailbox is unavailable",
                retryable=False,
                code="verification_mailbox_unavailable",
            )
        verification_mailbox = self.mailbox_lookup(verification_email)
        verification_password = str((verification_mailbox or {}).get("password") or "").strip()
        if not verification_password:
            raise MailboxError(
                "Save the verification mailbox password in the mailbox pool",
                retryable=False,
                code="verification_mailbox_unavailable",
            )

        if not _click_matching(page, ("add email", "add an email", "添加电子邮件", "添加邮箱")):
            email_field = _first_visible(
                page,
                ("input[type='email']", "input[autocomplete='email']", "input[name*='email' i]", "input[type='text']"),
            )
            if email_field is None:
                raise MailboxError(
                    "Microsoft security page did not expose an add-email action",
                    retryable=False,
                    code="webmail_security_required",
                )

        form_deadline = time.monotonic() + 20
        email_field = None
        while time.monotonic() < form_deadline:
            email_field = _first_visible(
                page,
                ("input[type='email']", "input[autocomplete='email']", "input[name*='email' i]", "input[type='text']"),
            )
            if email_field is not None:
                break
            body = self._page_body(page).lower()
            if self._is_human_challenge(body):
                raise MailboxError(
                    "Microsoft requires an interactive human verification",
                    retryable=False,
                    code="webmail_human_verification_required",
                )
            page.wait_for_timeout(500)
        if email_field is None:
            raise MailboxError(
                "Microsoft did not show the security email form",
                retryable=False,
                code="webmail_security_required",
            )

        email_field.fill(verification_email)
        code_requested_at = datetime.now(timezone.utc)
        if not _click_matching(
            page,
            ("next", "continue", "send", "send code", "发送", "下一步", "发送代码", "发送验证码"),
        ) and not _press_enter(email_field):
            raise MailboxError(
                "Microsoft security email form did not provide a submit action",
                retryable=False,
                code="webmail_security_required",
            )

        code_deadline = time.monotonic() + 45
        while time.monotonic() < code_deadline:
            body = self._page_body(page).lower()
            if self._is_security_rate_limited(body):
                raise MailboxError(
                    "Microsoft has rate-limited security email requests; try again tomorrow",
                    retryable=False,
                    code="webmail_security_rate_limited",
                )
            if self._is_human_challenge(body):
                raise MailboxError(
                    "Microsoft requires an interactive human verification",
                    retryable=False,
                    code="webmail_human_verification_required",
                )
            if self._security_code_field(page) is not None:
                break
            page.wait_for_timeout(500)
        else:
            raise MailboxError(
                "Microsoft did not show the security email code form",
                retryable=False,
                code="webmail_security_required",
            )

        try:
            wait_kwargs = {
                "since": code_requested_at,
                "timeout_seconds": self.settings.mail_code_timeout_seconds,
                "purpose": "microsoft_security",
            }
            if isinstance(self.code_reader, OutlookWebCodeReader):
                wait_kwargs["context"] = page.context
            code = self.code_reader.wait_for_code(verification_email, verification_password, **wait_kwargs)
        except MailboxError as exc:
            raise MailboxError(
                f"The verification mailbox could not provide a Microsoft security code: {exc.reason}",
                retryable=exc.retryable,
                code="verification_mailbox_unavailable",
            ) from exc

        code_field = self._security_code_field(page)
        if code_field is None:
            raise MailboxError(
                "Microsoft security code form disappeared before submission",
                retryable=False,
                code="webmail_security_required",
            )
        code_field.fill(code)
        if not _click_matching(page, ("verify", "next", "continue", "submit", "验证", "确认", "下一步")) and not _press_enter(code_field):
            raise MailboxError(
                "Microsoft security code form did not provide a submit action",
                retryable=False,
                code="webmail_security_required",
            )

        complete_deadline = time.monotonic() + 20
        while time.monotonic() < complete_deadline:
            body = self._page_body(page).lower()
            if self._is_human_challenge(body):
                raise MailboxError(
                    "Microsoft requires an interactive human verification",
                    retryable=False,
                    code="webmail_human_verification_required",
                )
            if any(
                marker in body
                for marker in ("incorrect code", "code didn't work", "invalid code", "验证码错误", "代码不正确")
            ):
                raise MailboxError(
                    "Microsoft rejected the security email code",
                    retryable=False,
                    code="webmail_security_code_rejected",
                )
            if not self._is_security_prompt(body) and not self._is_security_url(page.url):
                return
            if any(marker in body for marker in ("email added", "you've added", "已添加", "验证成功", "已验证")):
                _click_matching(page, ("done", "finish", "continue", "完成", "继续"))
            page.wait_for_timeout(500)
        raise MailboxError(
            "Microsoft security email verification did not complete",
            retryable=False,
            code="webmail_security_required",
        )

    @staticmethod
    def _page_body(page: Any) -> str:
        try:
            return " ".join(page.locator("body").inner_text(timeout=3000).split())
        except Exception:
            return ""

    @staticmethod
    def _is_email_code_prompt(body: str) -> bool:
        lowered = str(body or "").lower()
        return any(
            marker in lowered
            for marker in (
                "enter the code",
                "we sent a code",
                "code we sent",
                "security code",
                "verification code",
                "输入代码",
                "输入验证码",
                "我们已发送",
                "查看邮箱",
                "检查你的邮箱",
                "检查邮箱",
                "邮件中的代码",
                "邮箱中的代码",
                "安全代码",
            )
        )

    @staticmethod
    def _security_code_field(page: Any) -> Any | None:
        return _first_visible(
            page,
            (
                "input[autocomplete='one-time-code']",
                "input[inputmode='numeric']",
                "input[name*='code' i]",
                "input[id*='code' i]",
                "input[placeholder*='code' i]",
                "input[placeholder*='验证码']",
                "input[aria-label*='code' i]",
                "input[aria-label*='验证码']",
                "input[type='tel']",
                "#iOttText",
                "input[type='text']",
            ),
        )

    @staticmethod
    def _is_login_rejection(body: str) -> bool:
        body = str(body or "").lower()
        return any(
            marker in body
            for marker in (
                "incorrect password",
                "account doesn’t exist",
                "account doesn't exist",
                "密码不正确",
                "找不到此 microsoft 帐户",
            )
        )

    @staticmethod
    def _click_webmail_entry(page: Any) -> bool:
        for selector in ("a[href]", "button"):
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                try:
                    if not candidate.is_visible(timeout=500) or not candidate.is_enabled(timeout=500):
                        continue
                    label = " ".join(
                        filter(
                            None,
                            (
                                candidate.inner_text(),
                                candidate.get_attribute("aria-label"),
                                candidate.get_attribute("title"),
                                candidate.get_attribute("href"),
                            ),
                        )
                    ).lower()
                    if any(marker in label for marker in ("sign in", "log in", "登录", "登陆")):
                        candidate.click()
                        return True
                except Exception:
                    continue
        return False

    @staticmethod
    def _is_security_url(url: str) -> bool:
        parsed = urlparse(str(url or ""))
        return (parsed.hostname or "").lower() in {"account.live.com", "login.live.com"} and parsed.path.lower().startswith(
            "/interrupt/"
        )

    @staticmethod
    def _is_login_flow_url(url: str) -> bool:
        parsed = urlparse(str(url or ""))
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        return hostname in {"login.live.com", "login.microsoftonline.com"} and any(
            marker in path for marker in ("/oauth", "/common/", "/ppsecure/", "/kmsi")
        )

    @staticmethod
    def _safe_page_path(url: str) -> str:
        parsed = urlparse(str(url or ""))
        path = re.sub(r"(?i)(?<=/)[0-9a-f]{10,}(?=/|$)", "[id]", parsed.path or "/")
        return re.sub(r"(?<=/)\d{6,}(?=/|$)", "[id]", path)


def render_mailbox_evidence_screenshot(
    evidence: MailboxEvidence,
    settings: Settings,
) -> bytes:
    """Render a minimal, local evidence card instead of saving the full raw email."""
    if evidence.screenshot is not None:
        if not evidence.screenshot.startswith(b"\x89PNG\r\n\x1a\n"):
            raise MailboxError("mailbox evidence screenshot is not a PNG image", retryable=False)
        return evidence.screenshot
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise MailboxError("Playwright is not installed; mailbox evidence screenshot is unavailable", retryable=False) from exc
    received = evidence.received_at.isoformat(timespec="seconds") if evidence.received_at else "未知时间"
    document = f"""
    <!doctype html>
    <html lang="zh-CN">
      <head>
        <meta charset="utf-8" />
        <style>
          body {{ background: #f2f5f6; color: #17202a; font: 16px/1.55 Arial, sans-serif; margin: 0; padding: 36px; }}
          main {{ background: #fff; border: 1px solid #d9e1e5; border-radius: 8px; margin: 0 auto; max-width: 920px; padding: 28px 32px; }}
          .eyebrow {{ color: #0d7d79; font-size: 12px; font-weight: 700; letter-spacing: .12em; }}
          h1 {{ font-size: 25px; margin: 8px 0 20px; }}
          dl {{ border-top: 1px solid #d9e1e5; display: grid; gap: 12px 24px; grid-template-columns: 130px 1fr; margin: 0; padding-top: 18px; }}
          dt {{ color: #667581; }} dd {{ margin: 0; overflow-wrap: anywhere; }}
          .excerpt {{ background: #f7f9fa; border-left: 3px solid #b73838; margin-top: 24px; padding: 14px 16px; white-space: pre-wrap; }}
          .notice {{ color: #b73838; font-weight: 700; margin-top: 22px; }}
        </style>
      </head>
      <body>
        <main>
          <div class="eyebrow">MAILBOX VERIFICATION EVIDENCE</div>
          <h1>检测到疑似 OpenAI 账号停用邮件</h1>
          <dl>
            <dt>邮箱服务</dt><dd>{html.escape(evidence.provider)}</dd>
            <dt>邮件主题</dt><dd>{html.escape(evidence.subject)}</dd>
            <dt>接收时间</dt><dd>{html.escape(received)}</dd>
          </dl>
          <div class="notice">该截图由邮箱核验结果生成，未保存邮箱密码。</div>
          <div class="excerpt">{html.escape(evidence.excerpt)}</div>
        </main>
      </body>
    </html>
    """
    try:
        with sync_playwright() as playwright:
            proxy = settings.playwright_proxy.strip()
            launch_options: dict[str, Any] = {"headless": True}
            if proxy:
                launch_options["proxy"] = {"server": proxy}
            browser = playwright.chromium.launch(**launch_options)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 760})
                page.set_content(document, wait_until="domcontentloaded")
                return page.screenshot(type="png", full_page=True, animations="disabled")
            finally:
                browser.close()
    except MailboxError:
        raise
    except Exception as exc:
        raise MailboxError(
            f"Mailbox evidence screenshot failed: {safe_error(exc)}",
            retryable=False,
        ) from exc


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
        purpose: Literal["openai", "microsoft_security"] = "openai",
    ) -> str:
        deadline = time.monotonic() + (timeout_seconds or self.settings.mail_code_timeout_seconds)
        last_error = ""
        while time.monotonic() < deadline:
            try:
                code = self._read_latest(email_address, password, since=since, purpose=purpose)
            except (imaplib.IMAP4.error, OSError, TimeoutError) as exc:
                last_error = safe_error(exc)
                break
            if code:
                return code
            time.sleep(max(1, self.settings.mail_poll_seconds))
        if last_error:
            raise MailboxError(f"IMAP mailbox access failed: {last_error}")
        service = "Microsoft security" if purpose == "microsoft_security" else "OpenAI"
        raise MailboxError(f"No new {service} verification code arrived before timeout")

    def validate_access(self, email_address: str, password: str) -> None:
        connection = None
        try:
            connection = self.connection_factory(
                self._host_for_email(email_address),
                self.settings.mail_imap_port,
                timeout=min(30, max(5, self.settings.mail_code_timeout_seconds)),
            )
            try:
                connection.login(email_address, password)
            except imaplib.IMAP4.error as exc:
                raise MailboxError(
                    "IMAP rejected the mailbox login; a provider-specific authorization code may be required",
                    retryable=False,
                    code="imap_login_rejected",
                ) from exc
            except (OSError, TimeoutError) as exc:
                raise MailboxError(
                    f"IMAP mailbox login failed: {safe_error(exc)}",
                    code="connection_failed",
                ) from exc
            status, _ = connection.select(self.settings.mail_imap_folder, readonly=True)
            if status != "OK":
                raise MailboxError(
                    "IMAP mailbox folder could not be opened read-only",
                    retryable=False,
                    code="imap_folder_unavailable",
                )
        except MailboxError:
            raise
        except (imaplib.IMAP4.error, OSError, TimeoutError) as exc:
            raise MailboxError(
                f"IMAP mailbox validation failed: {safe_error(exc)}",
                code="connection_failed",
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.logout()
                except Exception:
                    pass

    def _read_latest(
        self,
        email_address: str,
        password: str,
        *,
        since: datetime,
        purpose: Literal["openai", "microsoft_security"] = "openai",
    ) -> str:
        connection = self.connection_factory(
            self._host_for_email(email_address),
            self.settings.mail_imap_port,
            timeout=min(30, max(5, self.settings.mail_code_timeout_seconds)),
        )
        try:
            try:
                connection.login(email_address, password)
            except (imaplib.IMAP4.error,) as exc:
                raise MailboxError(
                    "IMAP rejected the mailbox login; this does not confirm that webmail credentials are invalid",
                    retryable=False,
                    code="imap_login_rejected",
                ) from exc
            except (OSError, TimeoutError) as exc:
                raise MailboxError(
                    f"IMAP mailbox login failed: {safe_error(exc)}",
                    code="connection_failed",
                ) from exc
            except Exception as exc:
                raise MailboxError(
                    "IMAP mailbox login failed",
                    retryable=False,
                    code="imap_login_error",
                ) from exc
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
                    sender = _decode_header(str(message.get("From") or ""))
                    is_match = (
                        _looks_like_microsoft_security_code(sender, subject, body)
                        if purpose == "microsoft_security"
                        else _looks_like_openai(subject + "\n" + body)
                    )
                    if not is_match:
                        continue
                    pattern = r"(?<!\d)(\d{6,8})(?!\d)" if purpose == "microsoft_security" else r"(?<!\d)(\d{6})(?!\d)"
                    match = re.search(pattern, subject + "\n" + body)
                    if match:
                        return match.group(1)
            return ""
        finally:
            try:
                connection.logout()
            except Exception:
                pass

    def _host_for_email(self, email_address: str) -> str:
        domain = str(email_address.rsplit("@", 1)[-1]).strip().lower()
        defaults = {
            "gmail.com": "imap.gmail.com",
            "googlemail.com": "imap.gmail.com",
            "icloud.com": "imap.mail.me.com",
            "me.com": "imap.mail.me.com",
            "mac.com": "imap.mail.me.com",
            "outlook.com": "outlook.office365.com",
            "hotmail.com": "outlook.office365.com",
            "live.com": "outlook.office365.com",
            "msn.com": "outlook.office365.com",
            "yahoo.com": "imap.mail.yahoo.com",
            "163.com": "imap.163.com",
        }
        if domain.endswith(".163.com"):
            return "imap.163.com"
        return defaults.get(domain, self.settings.mail_imap_host)


class Netease163WebCodeReader:
    """Read new Microsoft security codes from an authenticated 163 webmail session."""

    # 163 search rows expose received time only to minute precision. A message
    # shown as 01:36 may have arrived at any point during that minute, so allow
    # the displayed minute to overlap the request timestamp.
    _search_time_precision_tolerance = timedelta(seconds=90)

    _search_selector = "input[aria-label='支持邮件全文搜索']"
    _mail_subject = re.compile(r"microsoft account security code|安全代码|安全验证码", re.IGNORECASE)
    _trusted_sender = re.compile(
        r"[\w.+-]+@(?:[\w-]+\.)*accountprotection\.microsoft\.com\b",
        re.IGNORECASE,
    )

    def __init__(self, settings: Settings):
        self.settings = settings
        self._local = threading.local()

    def attach_playwright(self, playwright: Any) -> None:
        self._local.playwright = playwright

    def detach_playwright(self) -> None:
        self.close_session()
        self._local.playwright = None

    def validate_access(self, email_address: str, password: str) -> None:
        self.close_session()
        domain = str(email_address.rsplit("@", 1)[-1]).strip().lower()
        if domain != "163.com" and not domain.endswith(".163.com"):
            raise MailboxError("The Microsoft security mailbox must be hosted by 163", retryable=False)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise MailboxError("Playwright is not installed; 163 webmail access is unavailable", retryable=False) from exc

        playwright = browser = None
        owns_playwright = True
        try:
            playwright = getattr(self._local, "playwright", None)
            if playwright is None:
                playwright = sync_playwright().start()
            else:
                owns_playwright = False
            launch_options: dict[str, Any] = {"headless": True}
            if self.settings.playwright_proxy.strip():
                launch_options["proxy"] = {"server": self.settings.playwright_proxy.strip()}
            browser = playwright.chromium.launch(**launch_options)
            page = browser.new_page()
            page.goto("https://mail.163.com/", wait_until="domcontentloaded", timeout=60_000)
            deadline = time.monotonic() + max(30, min(120, self.settings.mail_code_timeout_seconds))
            submitted = False
            while time.monotonic() < deadline:
                if self._authenticated_page(page):
                    self._local.session = (playwright, browser, page, email_address, password, owns_playwright)
                    return
                login_frame = self._login_frame(page)
                if login_frame is not None:
                    login_body = self._frame_text(login_frame).lower()
                    if OutlookWebAccountDisabledReader._is_human_challenge(login_body):
                        raise MailboxError(
                            "163 webmail requires an interactive human verification",
                            retryable=False,
                            code="163_human_verification_required",
                        )
                    if self._login_rejected(login_body):
                        raise MailboxError(
                            "163 webmail rejected the login",
                            retryable=False,
                            code="163_login_rejected",
                        )
                    email_field = login_frame.locator("input[name='email']").first
                    password_field = login_frame.locator("input[name='password']").first
                    if email_field.is_visible() and password_field.is_visible() and not submitted:
                        email_field.fill(email_address)
                        password_field.fill(password)
                        submitted = self._submit_login(login_frame, password_field)
                page.wait_for_timeout(500)
            if submitted:
                raise MailboxError(
                    "163 webmail login did not finish before timeout",
                    code="163_webmail_unavailable",
                )
            raise MailboxError(
                "163 webmail login form was not available",
                retryable=False,
                code="163_webmail_unavailable",
            )
        except MailboxError:
            self._close(playwright, browser, stop_playwright=owns_playwright)
            raise
        except Exception as exc:
            self._close(playwright, browser, stop_playwright=owns_playwright)
            raise MailboxError(
                f"163 webmail access failed: {safe_error(exc)}",
                code="163_webmail_unavailable",
            ) from exc

    def wait_for_code(
        self,
        email_address: str,
        password: str,
        *,
        since: datetime,
        timeout_seconds: int | None = None,
        purpose: Literal["openai", "microsoft_security"] = "microsoft_security",
    ) -> str:
        if purpose != "microsoft_security":
            raise MailboxError("163 webmail reader only accepts Microsoft security codes", retryable=False)
        session = getattr(self._local, "session", None)
        owns_session = not session or session[3:5] != (email_address, password)
        if owns_session:
            self.validate_access(email_address, password)
            session = self._local.session
        deadline = time.monotonic() + (timeout_seconds or self.settings.mail_code_timeout_seconds)
        try:
            while time.monotonic() < deadline:
                code = self._search_for_code(session[2], since=since)
                if code:
                    return code
                session[2].wait_for_timeout(max(1000, self.settings.mail_poll_seconds * 1000))
            raise MailboxError(
                "No new Microsoft security verification code arrived before timeout",
                code="163_security_code_not_arrived",
            )
        finally:
            if owns_session:
                self.close_session()

    def close_session(self) -> None:
        session = getattr(self._local, "session", None)
        if session:
            self._local.session = None
            self._close(session[0], session[1], stop_playwright=session[5])

    @staticmethod
    def _close(playwright: Any, browser: Any, *, stop_playwright: bool = True) -> None:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if stop_playwright and playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass

    @staticmethod
    def _login_frame(page: Any) -> Any | None:
        for frame in page.frames:
            try:
                if frame.locator("input[name='email']").count() and frame.locator("input[name='password']").count():
                    return frame
            except Exception:
                continue
        return None

    @staticmethod
    def _authenticated_page(page: Any) -> bool:
        try:
            for frame in page.frames:
                parsed = urlparse(str(frame.url))
                if parsed.hostname == "mail.163.com" and parsed.path == "/js6/main.jsp":
                    if "收件箱" in Netease163WebCodeReader._frame_text(frame):
                        return True
            return False
        except Exception:
            return False

    @staticmethod
    def _frame_text(frame: Any) -> str:
        try:
            return " ".join(frame.locator("body").inner_text(timeout=1500).split())
        except Exception:
            return ""

    @staticmethod
    def _login_rejected(body: str) -> bool:
        return any(
            marker in str(body or "").lower()
            for marker in ("用户名或密码错误", "账号或密码错误", "密码错误", "login failed", "incorrect password")
        )

    @staticmethod
    def _submit_login(login_frame: Any, password_field: Any) -> bool:
        """Submit the current 163 form, including its anchor-based login control."""
        for selector in ("#dologin", "button", "input[type='submit']", "input[type='button']", "[role='button']"):
            controls = login_frame.locator(selector)
            for index in range(controls.count()):
                control = controls.nth(index)
                try:
                    if not control.is_visible(timeout=500):
                        continue
                    if selector == "#dologin":
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            control_class = str(control.get_attribute("class") or "")
                            if "btndisabled" not in control_class:
                                break
                            login_frame.page.wait_for_timeout(100)
                    control.click(timeout=5000)
                    return True
                except Exception:
                    continue
        try:
            password_field.press("Enter", timeout=3000)
            return True
        except Exception:
            return False

    def _search_for_code(self, page: Any, *, since: datetime) -> str:
        main = page.main_frame
        search = None
        search_deadline = time.monotonic() + 15
        while time.monotonic() < search_deadline:
            search = _first_visible(main, (self._search_selector,))
            if search is not None:
                break
            page.wait_for_timeout(500)
        if search is None:
            raise MailboxError(
                "163 webmail mail search is unavailable",
                code="163_webmail_unavailable",
            )
        # Re-submit from an empty value on every poll. 163 may keep the prior
        # result set when the same query is submitted again, which hides a
        # message that arrived after the first search.
        search.fill("")
        search.fill("Microsoft account security code")
        _press_enter(search)
        page.wait_for_timeout(1500)

        for frame in page.frames:
            if frame is not main:
                frame_body = self._frame_text(frame).lower()
                if OutlookWebAccountDisabledReader._is_human_challenge(frame_body):
                    raise MailboxError(
                        "163 webmail requires an interactive human verification",
                        retryable=False,
                        code="163_human_verification_required",
                    )
            code = self._open_matching_message(frame, since=since)
            if code:
                return code
        return ""

    def _open_matching_message(self, frame: Any, *, since: datetime) -> str:
        # 163 renders the same subject in the search summary, an AI helper,
        # and the actual message row. Prefer the row elements so a click on a
        # summary node cannot prevent the real message from being opened.
        message_rows = frame.locator("b").filter(has_text=self._mail_subject)
        matches = message_rows if message_rows.count() else frame.get_by_text(self._mail_subject, exact=False)
        for index in range(min(matches.count(), 20)):
            candidate = matches.nth(index)
            try:
                if not candidate.is_visible(timeout=300):
                    continue
                received_at = self._message_received_at(candidate)
                candidate.click(timeout=1500)
                frame.locator("body").wait_for(state="visible", timeout=1500)
                frame.page.wait_for_timeout(500)
                bodies = [self._frame_text(open_frame) for open_frame in frame.page.frames]
                code = self._extract_code_from_bodies(bodies, received_at=received_at, since=since)
                if code:
                    return code
            except Exception:
                continue
        return ""

    @classmethod
    def _extract_code(cls, body: str, *, received_at: datetime | None, since: datetime) -> str:
        sender = cls._trusted_sender.search(body)
        if not sender or not cls._received_after_request(received_at, since):
            return ""
        if not _looks_like_microsoft_security_code(sender.group(0), "Microsoft account security code", body):
            return ""
        match = re.search(
            r"(?:security code|verification code|安全代码|安全验证码|验证码)[^\d]{0,48}(\d{6,8})(?!\d)",
            body,
            re.IGNORECASE,
        )
        return match.group(1) if match else ""

    @classmethod
    def _extract_code_from_bodies(
        cls,
        bodies: list[str],
        *,
        received_at: datetime | None,
        since: datetime,
    ) -> str:
        combined = "\n".join(body for body in bodies if body)
        if not cls._trusted_sender.search(combined) or not cls._received_after_request(received_at, since):
            return ""
        for body in bodies:
            if not re.search(r"security code|verification code|安全代码|验证码", body, re.IGNORECASE):
                continue
            match = re.search(
                r"(?:security code|verification code|安全代码|安全验证码|验证码)[^\d]{0,48}(\d{6,8})(?!\d)",
                body,
                re.IGNORECASE,
            )
            if match:
                return match.group(1)
        return ""

    @classmethod
    def _received_after_request(cls, received_at: datetime | None, since: datetime) -> bool:
        if received_at is None:
            return False
        return received_at >= since - cls._search_time_precision_tolerance

    @staticmethod
    def _message_received_at(candidate: Any) -> datetime | None:
        values: list[str] = []
        try:
            values = candidate.evaluate(
                """element => {
                  const out = [];
                  let node = element;
                  for (let i = 0; node && i < 6; i++, node = node.parentElement) {
                    const text = String(node.innerText || '').trim();
                    if (text && text.length < 500) out.push(text);
                    for (const item of [node, ...node.querySelectorAll('time,[title],[datetime]')]) {
                      for (const key of ['datetime', 'title', 'data-time', 'data-timestamp']) {
                        const value = item.getAttribute?.(key);
                        if (value) out.push(value);
                      }
                    }
                  }
                  return [...new Set(out)];
                }"""
            )
        except Exception:
            return None
        for value in values:
            normalized = str(value).strip()
            if normalized.isdigit() and len(normalized) in {10, 13}:
                seconds = int(normalized) / (1000 if len(normalized) == 13 else 1)
                return datetime.fromtimestamp(seconds, tz=timezone.utc)
            parsed = Netease163WebCodeReader._parse_received_text(normalized)
            if parsed is not None:
                return parsed.astimezone(timezone.utc)
        return None

    @staticmethod
    def _parse_received_text(value: str) -> datetime | None:
        """Parse a timestamp embedded in a 163 search-result row."""
        text = " ".join(str(value or "").split())
        timezone_local = ZoneInfo("Asia/Shanghai")
        now_local = datetime.now(timezone_local)
        patterns = (
            (
                r"(?<!\d)(\d{4})[/.年-](\d{1,2})[/.月-](\d{1,2})(?:日)?[ T年]"
                r"(\d{1,2}):(\d{2})(?::(\d{2}))?",
                lambda match: datetime(
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3)),
                    int(match.group(4)),
                    int(match.group(5)),
                    int(match.group(6) or 0),
                    tzinfo=timezone_local,
                ),
            ),
            (
                r"(?<!\d)(\d{1,2})[/-](\d{1,2})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?",
                lambda match: datetime(
                    now_local.year,
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3)),
                    int(match.group(4)),
                    int(match.group(5) or 0),
                    tzinfo=timezone_local,
                ),
            ),
            (
                r"(?:今天\s*)?(\d{1,2}):(\d{2})(?::(\d{2}))?",
                lambda match: datetime(
                    now_local.year,
                    now_local.month,
                    now_local.day,
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3) or 0),
                    tzinfo=timezone_local,
                ),
            ),
        )
        for pattern, builder in patterns:
            match = re.search(pattern, text)
            if not match:
                continue
            try:
                return builder(match)
            except ValueError:
                continue
        return None


class OutlookWebCodeReader:
    """Read recent verification mail from Outlook Web in an existing browser context."""

    _security_subject = re.compile(r"microsoft account security code|personal microsoft account security code", re.I)
    _trusted_security_sender = re.compile(
        r"[\w.+-]+@(?:[\w-]+\.)*accountprotection\.microsoft\.com\b", re.I
    )

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
        purpose: Literal["openai", "microsoft_security"] = "openai",
    ) -> str:
        if context is None:
            raise MailboxError("Outlook Webmail requires an active browser context", retryable=False)
        browser = context.browser
        if browser is None:
            raise MailboxError("Outlook Webmail browser context is unavailable", retryable=False)
        mailbox_context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = mailbox_context.new_page()
        deadline = time.monotonic() + (timeout_seconds or self.settings.mail_code_timeout_seconds)
        email_done = False
        password_done = False
        authenticated = False
        last_search_refresh = 0.0
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
            page.goto(
                "https://outlook.live.com/mail/0/?prompt=select_account",
                wait_until="domcontentloaded",
                timeout=60_000,
            )
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
                if purpose == "openai" and _looks_like_openai(body):
                    match = re.search(r"(?<!\d)(\d{6})(?!\d)", body)
                    if match:
                        return match.group(1)
                if OutlookWebAccountDisabledReader._is_human_challenge(body.lower()):
                    raise MailboxError(
                        "Outlook verification mailbox requires an interactive human verification",
                        retryable=False,
                        code="verification_mailbox_human_verification_required",
                    )
                if OutlookWebAccountDisabledReader._is_security_prompt(body.lower()) or OutlookWebAccountDisabledReader._is_security_url(page.url):
                    raise MailboxError(
                        "Outlook verification mailbox requires additional security verification",
                        retryable=False,
                        code="verification_mailbox_security_required",
                    )
                if any(marker in body.lower() for marker in ("incorrect password", "account doesn’t exist", "account doesn't exist")):
                    raise MailboxError(
                        "Outlook mailbox credentials were rejected",
                        retryable=False,
                        code="credentials_rejected",
                    )
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
                if (
                    password_done
                    and not _first_visible(page, ("input[type='email']", "input[autocomplete='username']", "input[type='password']"))
                    and not OutlookWebAccountDisabledReader._is_login_flow_url(page.url)
                ):
                    authenticated = True
                if authenticated and purpose == "microsoft_security":
                    refresh_search = time.monotonic() - last_search_refresh >= max(5, self.settings.mail_poll_seconds)
                    code = self._search_for_security_code(page, since=since, submit=refresh_search)
                    if refresh_search:
                        last_search_refresh = time.monotonic()
                    if code:
                        return code
                page.wait_for_timeout(max(1000, self.settings.mail_poll_seconds * 1000))
            if purpose == "microsoft_security":
                raise MailboxError(
                    "No new Microsoft security verification code arrived from Outlook Webmail",
                    code="outlook_security_code_not_arrived",
                )
            raise MailboxError("No new OpenAI verification code arrived from Outlook Webmail")
        except MailboxError:
            raise
        except Exception as exc:
            raise MailboxError(f"Outlook Webmail access failed: {safe_error(exc)}") from exc
        finally:
            mailbox_context.close()

    def _search_for_security_code(self, page: Any, *, since: datetime, submit: bool) -> str:
        search = _first_visible(
            page,
            (
                "input[placeholder='Search']",
                "input[aria-label*='Search for email' i]",
                "input[role='combobox']",
            ),
        )
        if search is None:
            return ""
        if submit:
            search.fill("")
            search.fill("Microsoft account security code")
            _press_enter(search)
            page.wait_for_timeout(1200)

        candidates: list[Any] = []
        options = page.get_by_role("option")
        for index in range(min(options.count(), 40)):
            candidate = options.nth(index)
            try:
                if candidate.is_visible(timeout=250) and self._security_subject.search(candidate.inner_text(timeout=500)):
                    candidates.append(candidate)
            except Exception:
                continue
        subjects = page.get_by_text(self._security_subject, exact=False)
        for index in range(min(subjects.count(), 20)):
            candidates.append(subjects.nth(index))

        for candidate in candidates:
            try:
                if not candidate.is_visible(timeout=250):
                    continue
                row_text = candidate.inner_text(timeout=500)
                received_at = self._message_received_at(candidate)
                if received_at is None or received_at < since - timedelta(seconds=90):
                    continue
                row_metadata = candidate.evaluate(
                    """element => {
                      const values = [];
                      let node = element;
                      for (let i = 0; node && i < 5; i++, node = node.parentElement) {
                        for (const item of [node, ...node.querySelectorAll('[email],[data-email],[title],[aria-label]')]) {
                          for (const key of ['email', 'data-email', 'title', 'aria-label']) {
                            const value = item.getAttribute?.(key);
                            if (value) values.push(value);
                          }
                        }
                      }
                      return [...new Set(values)];
                    }"""
                )
                candidate.click(timeout=2000)
                page.wait_for_timeout(500)
                body = " ".join(page.locator("body").inner_text(timeout=3000).split())
                sender_values = page.locator("[email]").evaluate_all(
                    "elements => elements.map(element => element.getAttribute('email') || '')"
                )
                sender_text = " ".join(str(value) for value in sender_values)
                trusted_metadata = page.locator("*").evaluate_all(
                    """elements => elements.flatMap(element => [...element.attributes]
                      .map(attribute => attribute.value))
                      .filter(value => /accountprotection\\.microsoft\\.com/i.test(value))"""
                )
                combined = (
                    f"{row_text}\n{' '.join(str(value) for value in row_metadata)}\n"
                    f"{sender_text}\n{' '.join(str(value) for value in trusted_metadata)}\n{body}"
                )
                code = self._extract_security_code(
                    combined,
                    body,
                    received_at=received_at,
                    since=since,
                )
                if code:
                    return code
            except Exception:
                continue
        return ""

    @classmethod
    def _extract_security_code(
        cls,
        sender_and_body: str,
        body: str,
        *,
        received_at: datetime | None,
        since: datetime,
    ) -> str:
        if received_at is None or received_at < since - timedelta(seconds=90):
            return ""
        sender = cls._trusted_security_sender.search(sender_and_body)
        if not sender or not _looks_like_microsoft_security_code(
            sender.group(0), "Microsoft account security code", body
        ):
            return ""
        match = re.search(
            r"(?:security code|verification code|安全代码|安全验证码|验证码)[^\d]{0,48}(\d{6,8})(?!\d)",
            body,
            re.I,
        )
        return match.group(1) if match else ""

    @staticmethod
    def _message_received_at(candidate: Any) -> datetime | None:
        try:
            values = candidate.evaluate(
                """element => {
                  const values = [];
                  let node = element;
                  for (let i = 0; node && i < 7; i++, node = node.parentElement) {
                    const text = String(node.innerText || '').trim();
                    if (text && text.length < 1000) values.push(text);
                    for (const item of [node, ...node.querySelectorAll('time,[title],[datetime],[aria-label]')]) {
                      for (const key of ['datetime', 'title', 'aria-label', 'data-time', 'data-timestamp']) {
                        const value = item.getAttribute?.(key);
                        if (value) values.push(value);
                      }
                    }
                  }
                  return [...new Set(values)];
                }"""
            )
        except Exception:
            return None
        for value in values:
            parsed = OutlookWebCodeReader._parse_received_time(str(value))
            if parsed is not None:
                return parsed.astimezone(timezone.utc)
        return None

    @staticmethod
    def _parse_received_time(value: str) -> datetime | None:
        text = " ".join(str(value or "").split())
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=ZoneInfo("Asia/Shanghai"))
        except ValueError:
            pass
        try:
            parsed = email.utils.parsedate_to_datetime(text)
            if parsed is not None:
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=ZoneInfo("Asia/Shanghai"))
        except (TypeError, ValueError, IndexError):
            pass

        timezone_local = ZoneInfo("Asia/Shanghai")
        now_local = datetime.now(timezone_local)
        patterns = (
            (r"(?<!\d)(\d{1,2})/(\d{1,2})/(\d{4}),?\s+(\d{1,2}):(\d{2})\s*([AP]M)", "%m/%d/%Y %I:%M %p"),
            (r"(?<!\d)(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})\s*([AP]M)", "%m/%d/%Y %I:%M %p"),
        )
        for pattern, date_format in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                candidate = (
                    f"{match.group(1)}/{match.group(2)}/{match.group(3)} "
                    f"{match.group(4)}:{match.group(5)} {match.group(6)}"
                )
                try:
                    return datetime.strptime(candidate, date_format).replace(tzinfo=timezone_local)
                except ValueError:
                    continue
        match = re.search(
            r"(?<!\d)(\d{4})[年/-](\d{1,2})[月/-](\d{1,2})日?\s+(\d{1,2}):(\d{2})",
            text,
        )
        if match:
            try:
                return datetime(
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3)),
                    int(match.group(4)),
                    int(match.group(5)),
                    tzinfo=timezone_local,
                )
            except ValueError:
                pass
        match = re.search(r"(?<!\d)(\d{1,2})月(\d{1,2})日\s+(\d{1,2}):(\d{2})", text)
        if match:
            try:
                return datetime(
                    now_local.year,
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3)),
                    int(match.group(4)),
                    tzinfo=timezone_local,
                )
            except ValueError:
                pass
        match = re.search(r"(今天|昨日|昨天)\s*(\d{1,2}):(\d{2})", text)
        if match:
            day = now_local.date()
            if match.group(1) in {"昨日", "昨天"}:
                day -= timedelta(days=1)
            try:
                return datetime(
                    day.year,
                    day.month,
                    day.day,
                    int(match.group(2)),
                    int(match.group(3)),
                    tzinfo=timezone_local,
                )
            except ValueError:
                pass
        match = re.search(r"(?<!\d)(\d{1,2})月(\d{1,2})日?\s+(\d{1,2}):(\d{2})", text)
        if match:
            try:
                return datetime(
                    now_local.year,
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3)),
                    int(match.group(4)),
                    tzinfo=timezone_local,
                )
            except ValueError:
                pass
        match = re.search(r"(?:today|yesterday)?\s*(\d{1,2}):(\d{2})\s*([AP]M)", text, re.I)
        if match:
            day = now_local.date()
            if "yesterday" in text.lower():
                day -= timedelta(days=1)
            try:
                parsed = datetime.strptime(f"{day.isoformat()} {match.group(1)}:{match.group(2)} {match.group(3)}", "%Y-%m-%d %I:%M %p")
                return parsed.replace(tzinfo=timezone_local)
            except ValueError:
                return None
        return None

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


def _looks_like_microsoft_security_code(sender: str, subject: str, body: str) -> bool:
    sender_lower = str(sender or "").lower()
    trusted_sender = "accountprotection.microsoft.com" in sender_lower or "microsoft.com" in sender_lower
    content = f"{subject}\n{body}".lower()
    security_code_message = any(
        marker in content
        for marker in (
            "microsoft account security code",
            "security code",
            "verification code",
            "verify your email",
            "安全代码",
            "验证码",
        )
    )
    return trusted_sender and security_code_message


def _looks_like_account_disabled_mail(subject: str, body: str) -> bool:
    text = f"{subject}\n{body}".lower()
    if not any(marker in text for marker in ("openai", "chatgpt", "codex")):
        return False
    return any(
        marker in text
        for marker in (
            "account deactivated",
            "account has been deactivated",
            "account has been deleted",
            "account deleted",
            "account disabled",
            "account is disabled",
            "account suspended",
            "account has been suspended",
            "账号已被删除或停用",
            "账户已被删除或停用",
            "账号已停用",
            "账户已停用",
        )
    )


def _safe_mail_text(value: str, *, limit: int) -> str:
    text = re.sub(r"<[^>]+>", " ", html.unescape(str(value or "")))
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"(?i)\b(?:https?://|www\.)\S+", "[链接]", text)
    return text[:limit] + ("…" if len(text) > limit else "")


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
    for selector in ("button[type='submit']", "input[type='submit']", "button"):
        locator = page.locator(selector)
        for index in range(locator.count()):
            candidate = locator.nth(index)
            try:
                if not candidate.is_visible(timeout=1000):
                    continue
            except Exception:
                continue
            label = " ".join(
                filter(None, (candidate.inner_text(), candidate.get_attribute("aria-label"), candidate.get_attribute("value")))
            ).lower()
            if any(word in label for word in words):
                try:
                    # click() waits for a dynamically enabled Microsoft button;
                    # checking is_enabled() first races the form's input event.
                    candidate.click(timeout=5000)
                    return True
                except Exception:
                    continue
    return False


def _press_enter(locator: Any) -> bool:
    try:
        locator.press("Enter", timeout=3000)
        return True
    except Exception:
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
