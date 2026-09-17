from __future__ import annotations

import os
import threading
from collections.abc import Callable

from .config import Settings
from .redaction import safe_error


class BrowserAutomationUnavailable(RuntimeError):
    pass


class PlaywrightOAuthRunner:
    """Launches a real browser and waits for the user to finish OAuth.

    The runner never attempts to defeat CAPTCHA, Cloudflare, email verification, or
    MFA. Those checks remain visible to the user in the browser. It is intentionally
    optional because NAS images may choose to install Playwright browsers separately.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def launch_async(self, auth_url: str, on_callback: Callable[[str], None], on_error: Callable[[str], None]) -> None:
        thread = threading.Thread(
            target=self._run,
            args=(auth_url, on_callback, on_error),
            daemon=True,
            name="oauth-browser",
        )
        thread.start()

    def _run(self, auth_url: str, on_callback: Callable[[str], None], on_error: Callable[[str], None]) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            on_error("Playwright is not installed; use the displayed authorization URL instead")
            raise BrowserAutomationUnavailable from exc

        proxy = self.settings.playwright_proxy.strip()
        if not proxy:
            for name in (
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "http_proxy",
                "all_proxy",
            ):
                proxy = os.environ.get(name, "").strip()
                if proxy:
                    break
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=self.settings.playwright_headless,
                    proxy={"server": proxy} if proxy else None,
                )
                try:
                    page = browser.new_page()
                    page.goto(auth_url, wait_until="domcontentloaded", timeout=60_000)
                    page.wait_for_url("**/auth/callback**", timeout=self.settings.playwright_timeout_seconds * 1000)
                    on_callback(page.url)
                finally:
                    browser.close()
        except Exception as exc:  # browser errors are surfaced as a safe task message
            on_error(safe_error(exc))
