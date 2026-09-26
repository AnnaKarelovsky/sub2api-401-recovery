from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from .config import Settings
from .mailbox import ImapCodeReader, MailboxError
from .note_credentials import NoteCredentials
from .redaction import safe_error
from .totp import TOTPError, totp_code


class AutomaticBrowserError(RuntimeError):
    def __init__(self, reason: str, *, stage: str, retryable: bool = True):
        super().__init__(reason)
        self.reason = safe_error(reason)
        self.stage = stage
        self.retryable = retryable


class AutomaticOAuthRunner:
    """Complete OAuth with a real browser and account material from encrypted storage."""

    def __init__(self, settings: Settings, *, mail_reader: Any | None = None):
        self.settings = settings
        self.mail_reader = mail_reader or ImapCodeReader(settings)

    def run(
        self,
        auth_url: str,
        material: NoteCredentials,
        *,
        started_at: datetime | None = None,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> str:
        if not material.ready_for_automation:
            raise AutomaticBrowserError(
                "login email and OpenAI password are required to start automatic authorization",
                stage="credentials",
                retryable=False,
            )
        started_at = started_at or datetime.now(timezone.utc)
        last_error: AutomaticBrowserError | None = None
        modes = [self.settings.playwright_headless]
        if self.settings.playwright_headless and self.settings.automation_browser_retries > 1:
            modes.append(False)
        for headless in modes[: max(1, self.settings.automation_browser_retries)]:
            try:
                return self._run_once(
                    auth_url,
                    material,
                    started_at=started_at,
                    headless=headless,
                    on_stage=on_stage,
                )
            except AutomaticBrowserError as exc:
                last_error = exc
                if not exc.retryable:
                    break
        raise last_error or AutomaticBrowserError("automatic browser flow failed", stage="browser")

    def _run_once(
        self,
        auth_url: str,
        material: NoteCredentials,
        *,
        started_at: datetime,
        headless: bool,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> str:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise AutomaticBrowserError("Playwright is not installed", stage="browser", retryable=False) from exc

        configured_cdp_url = self.settings.automation_cdp_url.strip()
        with self._display(headless):
            with self._callback_listener(enabled=not bool(configured_cdp_url)):
                try:
                    with sync_playwright() as playwright:
                        cdp_url = configured_cdp_url
                        browser = None
                        browser_process = None
                        browser_data_dir = None
                        browser_owned = False
                        if cdp_url:
                            browser = playwright.chromium.connect_over_cdp(
                                cdp_url,
                                timeout=self.settings.playwright_timeout_seconds * 1000,
                            )
                            if not browser.contexts:
                                raise AutomaticBrowserError(
                                    "configured CDP browser has no usable browser context",
                                    stage="browser",
                                    retryable=True,
                                )
                            context = browser.contexts[0]
                        else:
                            browser_process, cdp_url, browser_data_dir = self._start_chromium(
                                playwright,
                                headless=headless,
                            )
                            browser = playwright.chromium.connect_over_cdp(
                                cdp_url,
                                timeout=self.settings.playwright_timeout_seconds * 1000,
                            )
                            browser_owned = True
                            if not browser.contexts:
                                raise AutomaticBrowserError(
                                    "managed Chromium has no usable browser context",
                                    stage="browser",
                                    retryable=True,
                                )
                            context = browser.contexts[0]
                        try:
                            page = context.new_page()
                            callback_urls: list[str] = []
                            security_failures: list[str] = []
                            auth_responses: list[str] = []
                            mfa_denials: list[tuple[int, str]] = []

                            def capture_callback(frame: Any) -> None:
                                if frame == page.main_frame and self._is_callback(frame.url):
                                    callback_urls.append(frame.url)

                            def capture_security_response(response: Any) -> None:
                                parsed = urlparse(str(response.url))
                                summary = self._auth_response_summary(response)
                                if summary:
                                    auth_responses.append(summary)
                                    del auth_responses[:-4]
                                if parsed.path == "/api/accounts/mfa/verify" and response.status >= 400:
                                    mfa_denials.append(
                                        (int(response.status), self._safe_auth_error_category(int(response.status)))
                                    )
                                if response.status not in {403, 429}:
                                    return
                                if parsed.path == "/api/accounts/authorize/continue":
                                    security_failures.append(
                                        f"OpenAI authorization endpoint returned HTTP {response.status}"
                                    )

                            page.on("framenavigated", capture_callback)
                            page.on("response", capture_security_response)
                            self._notify(on_stage, "browser", "Opening the OpenAI authorization page")
                            page.goto(auth_url, wait_until="domcontentloaded", timeout=60_000)
                            self._notify(on_stage, "oauth_flow", "OpenAI authorization page loaded")
                            self._wait_through_challenge(page, on_stage=on_stage)
                            self._complete_login(
                                page,
                                context,
                                material,
                                started_at,
                                security_failures,
                                on_stage=on_stage,
                                auth_responses=auth_responses,
                                mfa_denials=mfa_denials,
                            )
                            return self._wait_for_callback(page, callback_urls, on_stage=on_stage)
                        finally:
                            if browser_owned:
                                self._cleanup_managed_browser(browser, browser_process, browser_data_dir)
                except AutomaticBrowserError:
                    raise
                except Exception as exc:
                    reason = safe_error(exc)
                    raise AutomaticBrowserError(reason, stage="browser") from exc

    def _complete_login(
        self,
        page: Any,
        context: Any,
        material: NoteCredentials,
        started_at: datetime,
        security_failures: list[str] | None = None,
        on_stage: Callable[[str, str], None] | None = None,
        auth_responses: list[str] | None = None,
        mfa_denials: list[tuple[int, str]] | None = None,
    ) -> None:
        email_submitted = False
        password_submitted = False
        email_code_used = False
        email_code_submitted_at = 0.0
        totp_submitted_code = ""
        totp_submitted_at = 0.0
        totp_retry_count = 0
        otp_kind = ""
        last_action_signature: tuple[str, str] | None = None
        last_action_started_at = 0.0
        last_action_stage = "oauth_flow"
        deadline = time.monotonic() + self.settings.playwright_timeout_seconds
        last_page_signature: tuple[str, str] | None = None
        last_page_changed_at = time.monotonic()
        while time.monotonic() < deadline:
            if self._is_callback(page.url):
                return
            body = self._body_text(page).lower()
            if self._is_account_disabled(body):
                raise AutomaticBrowserError(
                    "OpenAI 账号已被删除或停用（account_deactivated）",
                    stage="account_disabled",
                    retryable=False,
                )
            if mfa_denials:
                # Let an error-page navigation finish before classifying a generic MFA 403.
                for _ in range(4):
                    page.wait_for_timeout(250)
                    body = self._body_text(page).lower()
                    if self._is_account_disabled(body):
                        raise AutomaticBrowserError(
                            "OpenAI 账号已被删除或停用（account_deactivated）",
                            stage="account_disabled",
                            retryable=False,
                        )
                status, category = mfa_denials[-1]
                message, retryable = self._mfa_denial_reason(category, status=status)
                raise AutomaticBrowserError(message, stage="totp", retryable=retryable)
            if self._is_challenge(page):
                self._wait_through_challenge(page, on_stage=on_stage)
                continue
            if security_failures:
                raise AutomaticBrowserError(security_failures[-1], stage="security_challenge", retryable=True)
            if self._is_security_error(body):
                raise AutomaticBrowserError(
                    "OAuth page requires a security challenge that automation cannot complete",
                    stage="security_challenge",
                    retryable=True,
                )
            if _contains_any(body, ("incorrect password", "wrong password", "invalid password")):
                raise AutomaticBrowserError("OpenAI password was rejected", stage="openai_password", retryable=False)
            if _contains_any(body, ("invalid email", "email is not valid", "account not found")):
                raise AutomaticBrowserError("account email was rejected", stage="email", retryable=False)

            page_url = urlparse(page.url)._replace(query="", fragment="").geturl()
            page_signature = (page_url, re.sub(r"\d+", "#", body))
            if page_signature != last_page_signature:
                last_page_signature = page_signature
                last_page_changed_at = time.monotonic()
            elif time.monotonic() - last_page_changed_at >= 30:
                stage = last_action_stage if last_action_stage in {
                    "email", "openai_password", "email_code", "totp"
                } else "oauth_flow"
                label = {
                    "email": "account email",
                    "openai_password": "password",
                    "email_code": "email verification code",
                    "totp": "authenticator code",
                    "oauth_flow": "OAuth authorization page",
                }[stage]
                raise AutomaticBrowserError(
                    f"OpenAI page made no progress after submitting the {label} "
                    f"({self._page_diagnostic(page, auth_responses=auth_responses)})",
                    stage=stage,
                    retryable=True,
                )

            if self._has_visible_input(
                page,
                (
                    "input[autocomplete='one-time-code']",
                    "input[inputmode='numeric']",
                    "input[name*='code' i]",
                    "input[type='tel']",
                ),
            ):
                is_totp_prompt = _contains_any(
                    body,
                    ("authenticator", "two-factor", "2fa", "verification app"),
                ) or (otp_kind == "totp" and not _contains_any(body, ("email", "inbox", "mailbox")))
                is_email_prompt = _contains_any(body, ("email", "inbox", "mailbox", "sent you a code"))
                if is_totp_prompt:
                    otp_kind = "totp"
                    if not totp_submitted_code:
                        if not material.totp_secret:
                            raise AutomaticBrowserError(
                                "2FA secret is not configured for this account",
                                stage="totp",
                                retryable=False,
                            )
                        self._notify(on_stage, "totp", "Generating and submitting the authenticator code")
                        try:
                            totp_submitted_code = totp_code(material.totp_secret)
                        except TOTPError as exc:
                            raise AutomaticBrowserError(
                                f"2FA secret is invalid: {safe_error(exc)}",
                                stage="totp",
                                retryable=False,
                            ) from exc
                        self._fill_code(page, totp_submitted_code, stage="totp")
                        last_action_signature = (page.url, body)
                        last_action_started_at = time.monotonic()
                        last_action_stage = "totp"
                        self._click_action(page)
                        totp_submitted_at = time.monotonic()
                    elif self._is_verification_code_rejected(body):
                        if totp_retry_count >= 1:
                            raise AutomaticBrowserError(
                                "OpenAI rejected the authenticator code twice; verify the 2FA secret and server clock",
                                stage="totp",
                                retryable=False,
                            )
                        self._notify(on_stage, "totp", "Authenticator code was rejected; retrying once with a fresh code")
                        totp_submitted_code = self._fresh_totp_code(
                            material.totp_secret,
                            totp_submitted_code,
                            page,
                        )
                        self._fill_code(page, totp_submitted_code, stage="totp")
                        last_action_signature = (page.url, body)
                        last_action_started_at = time.monotonic()
                        last_action_stage = "totp"
                        self._click_action(page)
                        totp_submitted_at = time.monotonic()
                        totp_retry_count += 1
                    elif time.monotonic() - totp_submitted_at >= 15:
                        raise AutomaticBrowserError(
                            "OpenAI did not advance after the authenticator code was submitted",
                            stage="totp",
                            retryable=True,
                        )
                elif not email_code_used:
                    otp_kind = "email"
                    if not material.email_password:
                        raise AutomaticBrowserError(
                            "email mailbox password is not configured for this account",
                            stage="email_code",
                            retryable=False,
                        )
                    self._notify(on_stage, "email_code", "Waiting for the email verification code")
                    code = self._mail_code(context, material, started_at, on_stage=on_stage)
                    self._fill_code(page, code, stage="email_code")
                    email_code_used = True
                    email_code_submitted_at = time.monotonic()
                    self._notify(on_stage, "email_code", "Email verification code received and submitted")
                    last_action_signature = (page.url, body)
                    last_action_started_at = time.monotonic()
                    last_action_stage = "email_code"
                    self._click_action(page)
                elif self._is_verification_code_rejected(body):
                    raise AutomaticBrowserError(
                        "OpenAI rejected the email verification code",
                        stage="email_code",
                        retryable=False,
                    )
                elif time.monotonic() - email_code_submitted_at >= 15:
                    raise AutomaticBrowserError(
                        "OpenAI did not advance after the email verification code was submitted",
                        stage="email_code",
                        retryable=True,
                    )
                elif is_email_prompt:
                    otp_kind = "email"
                page.wait_for_timeout(800)
                continue

            if not email_submitted:
                email_input = self._first_visible(page, (
                    "input[type='email']",
                    "input[autocomplete='username']",
                    "input[name='email']",
                    "input[placeholder*='email' i]",
                ))
                if email_input is not None:
                    self._notify(on_stage, "email", "Submitting the account email")
                    email_input.fill(material.email)
                    email_submitted = True
                    last_action_signature = (page.url, body)
                    last_action_started_at = time.monotonic()
                    last_action_stage = "email"
                    self._click_action(page)
                    page.wait_for_timeout(800)
                    continue

            if not password_submitted:
                password_input = self._first_visible(page, ("input[type='password']",))
                if password_input is not None:
                    self._notify(on_stage, "openai_password", "Submitting the OpenAI account password")
                    password_input.fill(material.openai_password)
                    password_submitted = True
                    last_action_signature = (page.url, body)
                    last_action_started_at = time.monotonic()
                    last_action_stage = "openai_password"
                    self._click_action(page)
                    page.wait_for_timeout(1000)
                    continue

            action_signature = (page.url, body)
            if action_signature == last_action_signature:
                if time.monotonic() - last_action_started_at >= 12:
                    messages = {
                        "email": ("OpenAI did not advance after the account email was submitted", "email"),
                        "openai_password": ("OpenAI did not advance after the password was submitted", "openai_password"),
                        "email_code": ("OpenAI did not advance after the email verification code was submitted", "email_code"),
                        "oauth_flow": ("OpenAI authorization page did not advance after Continue was submitted", "oauth_flow"),
                    }
                    message, stage = messages.get(last_action_stage, messages["oauth_flow"])
                    raise AutomaticBrowserError(message, stage=stage, retryable=True)
                page.wait_for_timeout(500)
                continue

            if self._click_consent_or_continue(page):
                last_action_signature = action_signature
                last_action_started_at = time.monotonic()
                last_action_stage = "oauth_flow"
                self._notify(on_stage, "oauth_flow", "Submitting the OAuth consent or continue step")
                page.wait_for_timeout(900)
                continue
            page.wait_for_timeout(1000)

        raise AutomaticBrowserError(
            "OAuth login flow exceeded its configured timeout before reaching the callback",
            stage=last_action_stage,
            retryable=True,
        )

    @staticmethod
    def _is_verification_code_rejected(body: str) -> bool:
        return _contains_any(
            body,
            (
                "incorrect code",
                "invalid code",
                "wrong code",
                "code is incorrect",
                "code is invalid",
                "code has expired",
                "code expired",
                "verification code is not valid",
                "invalid verification code",
                "verification code was invalid",
                "that code didn't work",
                "that code did not work",
            ),
        )

    def _fresh_totp_code(self, secret: str, previous_code: str, page: Any) -> str:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            code = totp_code(secret)
            if code != previous_code:
                return code
            wait_ms = max(250, int((30 - time.time() % 30 + 0.25) * 1000))
            page.wait_for_timeout(wait_ms)
        raise AutomaticBrowserError(
            "Could not generate a fresh authenticator code",
            stage="totp",
            retryable=True,
        )

    def _mail_code(
        self,
        context: Any,
        material: NoteCredentials,
        started_at: datetime,
        *,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> str:
        self._notify(on_stage, "email_code", "Reading the verification code from the mailbox")
        try:
            return self.mail_reader.wait_for_code(
                material.email,
                material.email_password,
                since=started_at,
                timeout_seconds=self.settings.mail_code_timeout_seconds,
            )
        except MailboxError as first_error:
            if not self.settings.outlook_webmail_enabled:
                raise AutomaticBrowserError(first_error.reason, stage="email_code", retryable=first_error.retryable)
            try:
                from .mailbox import OutlookWebCodeReader

                self._notify(on_stage, "email_code", "IMAP did not return a code; trying Outlook webmail")
                return OutlookWebCodeReader(self.settings).wait_for_code(
                    material.email,
                    material.email_password,
                    since=started_at,
                    timeout_seconds=self.settings.mail_code_timeout_seconds,
                    context=context,
                )
            except MailboxError as second_error:
                raise AutomaticBrowserError(
                    f"mailbox code retrieval failed: {second_error.reason}",
                    stage="email_code",
                    retryable=second_error.retryable,
                ) from first_error

    def _wait_through_challenge(
        self,
        page: Any,
        *,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> None:
        notified = False
        deadline = time.monotonic() + self.settings.automation_challenge_timeout_seconds
        while time.monotonic() < deadline:
            if self._is_callback(page.url) or not self._is_challenge(page):
                if notified:
                    self._notify(on_stage, "security_challenge", "Security challenge cleared")
                return
            if not notified:
                self._notify(on_stage, "security_challenge", "Waiting for the OpenAI security challenge")
                notified = True
            page.wait_for_timeout(3000)
        raise AutomaticBrowserError(
            "OAuth security challenge did not clear before timeout",
            stage="cloudflare_challenge",
            retryable=True,
        )

    def _wait_for_callback(
        self,
        page: Any,
        callback_urls: list[str] | None = None,
        *,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> str:
        self._notify(on_stage, "callback", "Waiting for the OAuth callback")
        deadline = time.monotonic() + self.settings.playwright_timeout_seconds
        while time.monotonic() < deadline:
            if callback_urls:
                self._notify(on_stage, "callback", "OAuth callback received")
                return callback_urls[-1]
            if self._is_callback(page.url):
                self._notify(on_stage, "callback", "OAuth callback received")
                return page.url
            page.wait_for_timeout(1000)
        if callback_urls:
            return callback_urls[-1]
        raise AutomaticBrowserError("OAuth callback was not reached", stage="callback", retryable=True)

    @staticmethod
    def _notify(
        on_stage: Callable[[str, str], None] | None,
        stage: str,
        message: str,
    ) -> None:
        if not on_stage:
            return
        try:
            on_stage(stage, message)
        except Exception:
            # Progress reporting must never interrupt the authorization flow.
            return

    def _is_callback(self, url: str) -> bool:
        parsed = urlparse(str(url))
        return parsed.path.rstrip("/") == urlparse(self.settings.openai_oauth_redirect_uri).path.rstrip("/")

    def _proxy_config(self) -> dict[str, str] | None:
        proxy = self.settings.playwright_proxy.strip()
        if not proxy:
            for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
                proxy = os.environ.get(name, "").strip()
                if proxy:
                    break
        return {"server": proxy} if proxy else None

    def _start_chromium(self, playwright: Any, *, headless: bool) -> tuple[subprocess.Popen[Any], str, str]:
        executable = self.settings.automation_chromium_path.strip()
        executable = executable or playwright.chromium.executable_path
        proxy = self._proxy_config()
        port = _free_local_port()
        data_dir = tempfile.mkdtemp(prefix="sub2api-oauth-chromium-")
        command = [
            executable,
            f"--user-data-dir={data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-dev-shm-usage",
            "--lang=en-US",
            "--window-size=1280,900",
            f"--remote-debugging-port={port}",
            "--remote-debugging-address=127.0.0.1",
            "--remote-allow-origins=*",
        ]
        if os.geteuid() == 0:
            command.append("--no-sandbox")
        if headless:
            command.append("--headless=new")
        if proxy:
            command.append(f"--proxy-server={proxy['server']}")
        command.append("about:blank")
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            shutil.rmtree(data_dir, ignore_errors=True)
            raise AutomaticBrowserError(
                f"managed Chromium could not start: {safe_error(exc)}",
                stage="browser",
                retryable=False,
            ) from exc
        deadline = time.monotonic() + 30
        endpoint = f"http://127.0.0.1:{port}"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                shutil.rmtree(data_dir, ignore_errors=True)
                raise AutomaticBrowserError(
                    "managed Chromium exited before CDP became ready",
                    stage="browser",
                    retryable=True,
                )
            try:
                with urllib.request.urlopen(f"{endpoint}/json/version", timeout=1):
                    return process, endpoint, data_dir
            except (OSError, urllib.error.URLError):
                time.sleep(0.2)
        process.terminate()
        shutil.rmtree(data_dir, ignore_errors=True)
        raise AutomaticBrowserError("managed Chromium CDP endpoint did not become ready", stage="browser")

    @contextmanager
    def _callback_listener(self, *, enabled: bool) -> Iterator[None]:
        if not enabled:
            yield
            return
        redirect = urlparse(self.settings.openai_oauth_redirect_uri)
        if redirect.hostname not in {"localhost", "127.0.0.1"}:
            yield
            return
        callback_path = redirect.path.rstrip("/") or "/"

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                if urlparse(self.path).path.rstrip("/") != callback_path:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = b"<html><body>Authorization callback received. You may close this window.</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        try:
            server = ThreadingHTTPServer(("127.0.0.1", redirect.port or 80), CallbackHandler)
        except OSError as exc:
            raise AutomaticBrowserError(
                f"OAuth callback listener could not bind localhost:{redirect.port or 80}",
                stage="callback",
                retryable=True,
            ) from exc
        listener_thread = threading.Thread(target=server.serve_forever, name="oauth-callback-listener", daemon=True)
        listener_thread.start()
        try:
            yield
        finally:
            server.shutdown()
            server.server_close()
            listener_thread.join(timeout=2)

    @contextmanager
    def _display(self, headless: bool) -> Iterator[str | None]:
        if headless:
            yield None
            return
        display = os.environ.get("DISPLAY", "").strip()
        if display:
            yield display
            return
        display = f":{100 + (os.getpid() % 100)}"
        socket_path = f"/tmp/.X11-unix/X{display.lstrip(':')}"
        try:
            process = subprocess.Popen(
                ["Xvfb", display, "-screen", "0", "1280x900x24", "-nolisten", "tcp", "-ac"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise AutomaticBrowserError("Xvfb is not available for headed browser retry", stage="browser", retryable=False) from exc
        previous_display = os.environ.get("DISPLAY")
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise AutomaticBrowserError("Xvfb exited before the headed browser could start", stage="browser")
                if os.path.exists(socket_path):
                    os.environ["DISPLAY"] = display
                    yield display
                    return
                time.sleep(0.1)
            raise AutomaticBrowserError("Xvfb did not become ready for headed browser retry", stage="browser")
        finally:
            if previous_display is None:
                os.environ.pop("DISPLAY", None)
            else:
                os.environ["DISPLAY"] = previous_display
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    @staticmethod
    def _body_text(page: Any) -> str:
        try:
            return " ".join(page.locator("body").inner_text(timeout=5000).split())
        except Exception:
            return ""

    @staticmethod
    def _is_challenge(page: Any) -> bool:
        title = ""
        try:
            title = page.title().lower()
        except Exception:
            pass
        body = AutomaticOAuthRunner._body_text(page).lower()
        return _contains_any(
            title + " " + body,
            (
                "just a moment",
                "checking your browser",
                "performing security verification",
                "security service to protect against malicious bots",
                "verify you are human",
                "enable javascript and cookies",
                "cloudflare",
            ),
        )

    @staticmethod
    def _is_security_error(body: str) -> bool:
        body = body.lower()
        return _contains_any(
            body,
            (
                "captcha",
                "verify you are human",
                "security challenge",
                "unusual traffic",
                "oops, an error occurred",
            ),
        )

    @staticmethod
    def _is_account_disabled(body: str) -> bool:
        body = body.lower()
        return _contains_any(
            body,
            (
                "account_deactivated",
                "account_disabled",
                "account_deleted",
                "account has been deleted or disabled",
                "account has been deleted or deactivated",
                "account is disabled",
                "account is deactivated",
                "该帐户已被删除或停用",
                "该账户已被删除或停用",
                "账号已被删除或停用",
                "帐户已被删除或停用",
                "账户已被删除或停用",
                "账号已停用",
                "帐户已停用",
                "账户已停用",
            ),
        )

    @staticmethod
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

    def _has_visible_input(self, page: Any, selectors: tuple[str, ...]) -> bool:
        return self._first_visible(page, selectors) is not None

    def _fill_code(self, page: Any, code: str, *, stage: str) -> None:
        inputs = []
        for selector in ("input[autocomplete='one-time-code']", "input[inputmode='numeric']", "input[name*='code' i]", "input[type='tel']"):
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                try:
                    if candidate.is_visible(timeout=1000) and candidate not in inputs:
                        inputs.append(candidate)
                except Exception:
                    continue
        if not inputs:
            raise AutomaticBrowserError(f"{stage} input was not found", stage=stage, retryable=True)
        if len(inputs) >= len(code) and all((candidate.get_attribute("maxlength") or "") == "1" for candidate in inputs[: len(code)]):
            for candidate, digit in zip(inputs, code, strict=False):
                candidate.fill(digit)
        else:
            inputs[0].fill(code)

    @staticmethod
    def _click_action(page: Any) -> bool:
        if AutomaticOAuthRunner._click_matching(
            page,
            ("continue", "next", "verify", "submit", "sign in", "log in", "confirm", "proceed"),
        ):
            return True
        field = AutomaticOAuthRunner._first_visible(
            page,
            (
                "input[type='email']",
                "input[autocomplete='username']",
                "input[type='password']",
                "input[autocomplete='one-time-code']",
                "input[inputmode='numeric']",
                "input[name*='code' i]",
                "input[type='tel']",
            ),
        )
        if field is None:
            return False
        submit = AutomaticOAuthRunner._first_visible(
            page,
            ("button[type='submit']", "input[type='submit']"),
        )
        try:
            if submit is not None:
                submit.click(force=True, timeout=3000)
            else:
                field.press("Enter", timeout=3000)
            return True
        except Exception:
            return False

    @staticmethod
    def _click_consent_or_continue(page: Any) -> bool:
        return AutomaticOAuthRunner._click_matching(
            page,
            ("allow", "authorize", "approve", "continue", "next", "submit", "log in", "sign in"),
        )

    @staticmethod
    def _click_matching(page: Any, words: tuple[str, ...]) -> bool:
        for selector in ("button", "[role='button']", "input[type='submit']", "a[href]"):
            locator = page.locator(selector)
            for index in range(locator.count()):
                candidate = locator.nth(index)
                try:
                    if not candidate.is_visible(timeout=1000) or not candidate.is_enabled(timeout=1000):
                        continue
                except Exception:
                    continue
                try:
                    label = " ".join(
                        filter(
                            None,
                            (
                                candidate.inner_text(),
                                candidate.get_attribute("aria-label"),
                                candidate.get_attribute("value"),
                            ),
                        )
                    ).lower()
                except Exception:
                    continue
                if any(word in label for word in words):
                    candidate.click(force=True, timeout=3000)
                    return True
        return False

    @staticmethod
    def _page_diagnostic(page: Any, *, auth_responses: list[str] | None = None) -> str:
        try:
            path = AutomaticOAuthRunner._safe_auth_path(urlparse(str(page.url)).path or "/")
        except Exception:
            path = "/unknown"
        controls = {
            "email": ("input[type='email']", "input[autocomplete='username']"),
            "password": ("input[type='password']",),
            "code": (
                "input[autocomplete='one-time-code']",
                "input[inputmode='numeric']",
                "input[name*='code' i]",
                "input[type='tel']",
            ),
            "button": ("button",),
            "role_button": ("[role='button']",),
            "submit": ("input[type='submit']", "button[type='submit']"),
            "link": ("a[href]",),
        }
        states = []
        for name, selectors in controls.items():
            visible = any(
                AutomaticOAuthRunner._first_visible(page, (selector,)) is not None
                for selector in selectors
            )
            states.append(f"{name}={'yes' if visible else 'no'}")
        link_actions = AutomaticOAuthRunner._visible_link_actions(page)
        states.append(f"link_actions={'+'.join(link_actions) if link_actions else 'none'}")
        recent_responses = ",".join(auth_responses[-8:]) if auth_responses else "none"
        return f"path={path}; " + ", ".join(states) + f"; auth_responses={recent_responses}"

    @staticmethod
    def _safe_auth_path(path: str) -> str:
        path = re.sub(r"(?i)(?<=/)[0-9a-f]{10,}(?=/|$)", "[id]", path)
        return re.sub(r"(?<=/)\d{6,}(?=/|$)", "[id]", path)

    @staticmethod
    def _auth_response_summary(response: Any) -> str | None:
        try:
            parsed = urlparse(str(response.url))
            hostname = parsed.hostname or ""
            if hostname != "openai.com" and not hostname.endswith(".openai.com"):
                return None
            path = AutomaticOAuthRunner._safe_auth_path(parsed.path)
            if not path.startswith(("/api/", "/mfa-challenge/")):
                return None
            request = getattr(response, "request", None)
            method = str(getattr(request, "method", "GET")).upper()
            category = AutomaticOAuthRunner._safe_auth_error_category(int(response.status))
            suffix = f" category={category}" if category else ""
            return f"{method} {path} HTTP {response.status}{suffix}"
        except Exception:
            return None

    @staticmethod
    def _safe_auth_error_category(status: int) -> str | None:
        if status < 400:
            return None
        if status == 429:
            return "rate_limited"
        if status == 403:
            return "access_denied"
        return "unclassified"

    @staticmethod
    def _mfa_denial_reason(category: str, *, status: int = 403) -> tuple[str, bool]:
        if category == "rate_limited":
            return f"OpenAI rate-limited MFA verification (HTTP {status}); the account will be retried automatically later.", True
        if category == "access_denied":
            return (
                f"OpenAI denied the MFA verification request (HTTP {status}). "
                "Check the 2FA setup and account security requirements.",
                False,
            )
        return (
            f"OpenAI MFA verification returned HTTP {status} with an unclassified denial. "
            "Check the 2FA setup and account security requirements.",
            False,
        )

    @staticmethod
    def _cleanup_managed_browser(
        browser: Any,
        browser_process: subprocess.Popen[Any] | None,
        browser_data_dir: str | None,
    ) -> None:
        if browser_process is not None:
            try:
                if browser_process.poll() is None:
                    browser_process.terminate()
                try:
                    browser_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    browser_process.kill()
                    try:
                        browser_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
            except OSError:
                pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
        if browser_data_dir:
            shutil.rmtree(browser_data_dir, ignore_errors=True)

    @staticmethod
    def _visible_link_actions(page: Any) -> list[str]:
        actions: set[str] = set()
        locator = page.locator("a[href]")
        for index in range(locator.count()):
            candidate = locator.nth(index)
            try:
                if not candidate.is_visible(timeout=1000):
                    continue
                label = " ".join(
                    filter(
                        None,
                        (candidate.inner_text(), candidate.get_attribute("aria-label")),
                    )
                ).lower()
            except Exception:
                continue
            if _contains_any(label, ("try another", "another method", "different method", "use a different")):
                actions.add("alternate_method")
            elif "resend" in label:
                actions.add("resend")
            elif _contains_any(label, ("forgot", "reset password")):
                actions.add("password_recovery")
            elif _contains_any(label, ("continue", "verify", "submit", "authorize", "approve", "proceed")):
                actions.add("continue")
            elif _contains_any(label, ("back", "cancel")):
                actions.add("back")
            else:
                actions.add("unclassified")
        return sorted(actions)


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
