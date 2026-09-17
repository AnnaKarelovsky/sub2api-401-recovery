from __future__ import annotations

import html
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .auth import auth_dependency, login
from .config import (
    DASHBOARD_SETTING_DEFINITIONS,
    Settings,
    apply_dashboard_settings,
    coerce_dashboard_setting,
    configure_process_proxy,
    dashboard_settings_payload,
    dashboard_setting_values,
    get_settings,
    is_dashboard_secret,
)
from .db import Database
from .oauth import OpenAIOAuthClient
from .redaction import safe_error
from .recovery import RecoveryCoordinator, RecoveryRuntime
from .security import SecretBox, SessionToken
from .sub2api import Sub2APIClient, Sub2APIError


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=500)


class ReauthorizeRequest(BaseModel):
    launch_browser: bool = False
    session_id: str = ""


class CompleteOAuthRequest(BaseModel):
    callback_url: str = ""
    code: str = ""
    state: str = ""


class DashboardSettingsUpdate(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list)


class RuntimeProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)


class AppRuntime:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_settings = settings.model_copy(deep=True)
        self.db = Database(settings.database_path, SecretBox(settings.encryption_key))
        self.db.initialize()
        self.reload_settings(rebuild=False)
        self.sub2api = Sub2APIClient(settings)
        self.oauth = OpenAIOAuthClient(settings)
        self.coordinator = RecoveryCoordinator(RecoveryRuntime(self.db, self.sub2api, self.oauth, settings))

    def reload_settings(self, *, rebuild: bool = True) -> None:
        overrides = self.db.load_runtime_settings()
        apply_dashboard_settings(self.settings, overrides, base_settings=self.base_settings)
        self.settings.validate_runtime(require_sub2api=False)
        configure_process_proxy(self.settings)
        if not rebuild or not hasattr(self, "coordinator"):
            return
        old_sub2api = self.sub2api
        old_oauth = self.oauth
        self.sub2api = Sub2APIClient(self.settings)
        self.oauth = OpenAIOAuthClient(self.settings)
        self.coordinator.reconfigure(self.sub2api, self.oauth)
        old_sub2api.close()
        old_oauth.close()

    def update_settings(
        self,
        values: dict[str, Any],
        clear_secrets: list[str],
    ) -> dict[str, Any]:
        unknown = set(values) | set(clear_secrets)
        invalid = sorted(key for key in unknown if key not in DASHBOARD_SETTING_DEFINITIONS)
        if invalid:
            raise ValueError(f"settings are not editable: {', '.join(invalid)}")
        for key in clear_secrets:
            if not is_dashboard_secret(key):
                raise ValueError(f"only secret settings can be cleared: {key}")

        normalized: dict[str, Any] = {}
        for key, value in values.items():
            # An empty secret means "leave the existing value alone" in the UI.
            if is_dashboard_secret(key) and isinstance(value, str) and not value.strip():
                continue
            normalized[key] = coerce_dashboard_setting(key, value)

        merged = self.db.load_runtime_settings()
        for key in clear_secrets:
            merged.pop(key, None)
        merged.update(normalized)
        candidate = self.settings.model_copy(deep=True)
        apply_dashboard_settings(candidate, merged, base_settings=self.base_settings)
        candidate.validate_runtime(require_sub2api=False)
        self.db.save_runtime_settings(normalized, clear_keys=clear_secrets)
        self.reload_settings()
        return self.settings_payload()

    def reset_settings(self) -> dict[str, Any]:
        self.db.clear_runtime_settings()
        self.reload_settings()
        return self.settings_payload()

    def settings_payload(self) -> dict[str, Any]:
        payload = dashboard_settings_payload(
            self.settings,
            self.db.load_runtime_settings(),
            self.db.runtime_settings_revision(),
        )
        payload["active_profile_id"] = self.db.active_runtime_profile_id()
        payload["profiles"] = self.db.list_runtime_profiles()
        return payload

    def create_profile(self, name: str) -> dict[str, Any]:
        normalized_name = name.strip()
        if not normalized_name or any(ord(char) < 32 for char in normalized_name):
            raise ValueError("profile name is invalid")
        if any(profile["name"] == normalized_name for profile in self.db.list_runtime_profiles()):
            raise ValueError("profile name already exists")
        self.db.create_runtime_profile(normalized_name, dashboard_setting_values(self.settings))
        return self.settings_payload()

    def activate_profile(self, profile_id: str) -> dict[str, Any]:
        profile = self.db.get_runtime_profile(profile_id)
        if not profile:
            raise KeyError("runtime setting profile not found")
        normalized: dict[str, Any] = {}
        for key, value in profile["values"].items():
            normalized[key] = coerce_dashboard_setting(key, value)
        candidate = self.settings.model_copy(deep=True)
        apply_dashboard_settings(candidate, normalized, base_settings=self.base_settings)
        candidate.validate_runtime(require_sub2api=False)
        self.db.activate_runtime_profile(profile_id)
        self.reload_settings()
        return self.settings_payload()

    def delete_profile(self, profile_id: str) -> dict[str, Any]:
        if not self.db.delete_runtime_profile(profile_id):
            raise KeyError("runtime setting profile not found")
        return self.settings_payload()

    def close(self) -> None:
        self.sub2api.close()
        self.oauth.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    auth_required = auth_dependency(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runtime = AppRuntime(settings)
        app.state.runtime = runtime
        logging.basicConfig(
            level=settings.log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        try:
            yield
        finally:
            runtime.close()

    app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    def runtime(request: Request) -> AppRuntime:
        value = getattr(request.app.state, "runtime", None)
        if value is None:
            raise HTTPException(status_code=503, detail="service is starting")
        return value

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

    @app.get("/api/v1/healthz")
    def healthz(request: Request) -> dict[str, Any]:
        active = getattr(request.app.state, "runtime", None)
        return {"status": "ok" if active else "starting", "service": settings.app_name}

    @app.post("/api/v1/auth/login")
    def auth_login(payload: LoginRequest) -> dict[str, Any]:
        token = login(settings, payload.username, payload.password)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
        response = {"access_token": token, "token_type": "bearer"}
        return response

    @app.get("/api/v1/auth/me")
    def auth_me(session: SessionToken = Depends(auth_required)) -> dict[str, Any]:
        return {"username": session.subject, "expires_at": session.expires_at}

    @app.get("/api/v1/dashboard")
    def dashboard(
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        return {"summary": rt.db.dashboard_summary(), "accounts": rt.coordinator.accounts_view()[:20]}

    @app.get("/api/v1/settings")
    def settings_view(
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        return rt.settings_payload()

    @app.put("/api/v1/settings")
    def update_settings(
        payload: DashboardSettingsUpdate,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        try:
            return rt.update_settings(payload.values, payload.clear_secrets)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/settings/profiles")
    def create_profile(
        payload: RuntimeProfileCreate,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        try:
            return rt.create_profile(payload.name)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/settings/profiles/{profile_id}/activate")
    def activate_profile(
        profile_id: str,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        try:
            return rt.activate_profile(profile_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.delete("/api/v1/settings/profiles/{profile_id}")
    def delete_profile(
        profile_id: str,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        try:
            return rt.delete_profile(profile_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.delete("/api/v1/settings")
    def reset_settings(
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        return rt.reset_settings()

    @app.get("/api/v1/accounts")
    def accounts(
        status_filter: str = Query(default="", alias="status"),
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        items = rt.coordinator.accounts_view()
        if status_filter:
            items = [item for item in items if item.get("status") == status_filter]
        return {"items": items, "total": len(items)}

    @app.get("/api/v1/accounts/{account_id}")
    def account_detail(
        account_id: int,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        item = rt.coordinator.account_view(account_id)
        if not item:
            raise HTTPException(status_code=404, detail="account mapping not found")
        return item

    @app.post("/api/v1/scan", status_code=202)
    def trigger_scan(
        background: BackgroundTasks,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        background.add_task(_safe_scan, rt.coordinator)
        return {"status": "queued"}

    @app.post("/api/v1/accounts/{account_id}/recover", status_code=202)
    def recover_account(
        account_id: int,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        if not rt.db.get_mapping(account_id):
            try:
                raw = rt.sub2api.get_account(account_id)
            except Sub2APIError as exc:
                raise HTTPException(status_code=502, detail=safe_error(exc)) from exc
            from .recovery import normalize_snapshot

            rt.db.upsert_account_snapshot(normalize_snapshot(raw))
        task_id, created = rt.coordinator.enqueue_recovery(
            account_id,
            trigger="manual-recover",
            force=False,
        )
        return {"task_id": task_id, "created": created}

    @app.post("/api/v1/accounts/{account_id}/status")
    def account_status(
        account_id: int,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        result = rt.sub2api.inspect_account(account_id)
        is_auth_failure = bool(
            result.classification
            and result.classification.category.value == "401_AUTH_FAILURE"
        )
        rt.db.update_account_state(
            account_id,
            status="healthy" if result.success else ("auth_failed" if is_auth_failure else "observed"),
            failure_class=result.classification.category.value if result.classification else None,
            failure_reason=None if result.success else result.reason,
            mark_401=is_auth_failure,
            mark_test=True,
        )
        return {
            "success": result.success,
            "status_code": result.status_code,
            "reason": result.reason,
            "classification": result.classification.category.value if result.classification else None,
        }

    @app.post("/api/v1/accounts/{account_id}/reauthorize")
    def reauthorize(
        account_id: int,
        payload: ReauthorizeRequest,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        try:
            if payload.session_id:
                existing = rt.db.get_oauth_session(payload.session_id)
                if (
                    not existing
                    or int(existing["sub2api_account_id"]) != account_id
                    or existing.get("status") != "pending"
                ):
                    raise HTTPException(status_code=400, detail="OAuth session is not pending for this account")
                session = {
                    "id": existing["id"],
                    "task_id": existing.get("task_id"),
                    "sub2api_account_id": account_id,
                    "auth_url": existing["auth_url"],
                    "status": existing["status"],
                    "expires_at": existing["expires_at"],
                }
            else:
                session = rt.coordinator.start_reauthorization(account_id)
            if payload.launch_browser:
                rt.coordinator.launch_browser(session["id"])
            return session
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=safe_error(exc)) from exc

    @app.get("/api/v1/oauth/sessions/{session_id}")
    def oauth_session(
        session_id: str,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        session = rt.db.get_oauth_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="OAuth session not found")
        return {
            "id": session["id"],
            "task_id": session.get("task_id"),
            "sub2api_account_id": session["sub2api_account_id"],
            "auth_url": session["auth_url"],
            "status": session["status"],
            "error_reason": session.get("error_reason"),
            "expires_at": session["expires_at"],
        }

    @app.post("/api/v1/oauth/sessions/{session_id}/complete")
    def complete_oauth(
        session_id: str,
        payload: CompleteOAuthRequest,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        try:
            return rt.coordinator.complete_authorization(
                session_id=session_id,
                callback_url=payload.callback_url,
                code=payload.code,
                state=payload.state,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=safe_error(exc)) from exc

    @app.get("/auth/callback", response_class=HTMLResponse, include_in_schema=False)
    def oauth_callback(request: Request) -> HTMLResponse:
        rt = runtime(request)
        params = request.query_params
        try:
            result = rt.coordinator.complete_authorization(
                code=params.get("code", ""),
                state=params.get("state", ""),
                callback_url=str(request.url),
            )
            message = f"Authorization completed for Sub2API account {result['sub2api_account_id']}. You may close this window."
            return HTMLResponse(_callback_page("Authorization complete", message))
        except Exception as exc:
            return HTMLResponse(
                _callback_page("Authorization not completed", safe_error(exc)),
                status_code=400,
            )

    @app.get("/api/v1/tasks")
    def tasks(
        limit: int = Query(default=100, ge=1, le=500),
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        items = rt.db.list_tasks(limit=limit)
        return {"items": items, "total": len(items)}

    @app.get("/api/v1/tasks/{task_id}")
    def task_detail(
        task_id: str,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        item = rt.db.get_task(task_id)
        if not item:
            raise HTTPException(status_code=404, detail="task not found")
        item["logs"] = rt.db.list_logs(task_id)
        return item

    @app.post("/api/v1/tasks/{task_id}/retry", status_code=202)
    def retry_task(
        task_id: str,
        rt: AppRuntime = Depends(runtime),
        _: SessionToken = Depends(auth_required),
    ) -> dict[str, Any]:
        item = rt.db.get_task(task_id)
        if not item:
            raise HTTPException(status_code=404, detail="task not found")
        if rt.db.force_retry_task(task_id):
            return {"task_id": task_id, "created": False}
        new_id, created = rt.coordinator.enqueue_recovery(
            int(item["sub2api_account_id"]), trigger="manual-retry", force=True
        )
        return {"task_id": new_id, "created": created}

    return app


def _safe_scan(coordinator: RecoveryCoordinator) -> None:
    try:
        coordinator.scan()
    except Exception as exc:
        coordinator.db.record_event("api_scan_error", "Manual scan failed", {"reason": safe_error(exc)})


def _callback_page(title: str, message: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>"
        + html.escape(title)
        + "</title><style>body{font-family:system-ui;max-width:680px;margin:15vh auto;padding:2rem;color:#17202a}"
        "main{border:1px solid #d8e0e5;padding:2rem;border-radius:8px}h1{font-size:1.4rem}"
        "p{line-height:1.6}</style></head><body><main><h1>"
        + html.escape(title)
        + "</h1><p>"
        + html.escape(message)
        + "</p></main></body></html>"
    )


app = create_app()
