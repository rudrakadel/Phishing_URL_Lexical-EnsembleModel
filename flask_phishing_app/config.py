from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(slots=True)
class AppConfig:
    app_role: str
    env: str
    debug: bool
    host: str
    port: int
    secret_key: str
    max_content_length: int
    model_dir: str
    database_url: str
    require_auth: bool
    app_username: str
    app_password: str
    app_password_hash: str
    google_client_id: str
    session_cookie_secure: bool
    session_cookie_samesite: str
    session_cookie_name: str
    permanent_session_lifetime_minutes: int
    metrics_token: str
    rate_limit_login: int
    rate_limit_analyze: int
    rate_limit_batch: int
    rate_limit_notes: int
    rate_limit_window_seconds: int
    batch_max_urls: int
    url_max_length: int
    note_max_length: int
    enable_worker: bool
    worker_poll_interval_seconds: int
    worker_max_retries: int
    worker_stale_after_seconds: int
    request_timeout_seconds: int
    external_timeout_seconds: int
    ollama_timeout_seconds: int
    screenshot_timeout_ms: int

    @classmethod
    def from_env(cls, base_dir: Path, app_root: Path) -> "AppConfig":
        env = os.getenv("APP_ENV", os.getenv("FLASK_ENV", "development")).strip().lower()
        debug = _env_bool("FLASK_DEBUG", env != "production")
        secret_key = os.getenv("FLASK_SECRET_KEY", "")
        # Use `or` so that empty string values in .env fall back to the
        # Path(__file__)-relative defaults, making the project fully portable.
        database_url = (
            os.getenv("DATABASE_URL")
            or f"sqlite:///{(base_dir / 'data' / 'analysis_history.db').as_posix()}"
        )
        model_dir_resolved = (
            os.getenv("PHISHING_MODEL_DIR")
            or str(app_root)
        )
        return cls(
            app_role=os.getenv("APP_ROLE", "web").strip().lower(),
            env=env,
            debug=debug,
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=_env_int("APP_PORT", 5000),
            secret_key=secret_key,
            max_content_length=_env_int("APP_MAX_CONTENT_LENGTH", 8 * 1024 * 1024),
            model_dir=model_dir_resolved,
            database_url=database_url,
            require_auth=_env_bool("APP_REQUIRE_AUTH", True),
            app_username=os.getenv("APP_USERNAME", "admin"),
            app_password=os.getenv("APP_PASSWORD", "admin"),
            app_password_hash=os.getenv("APP_PASSWORD_HASH", ""),
            google_client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
            session_cookie_secure=_env_bool("SESSION_COOKIE_SECURE", env == "production"),
            session_cookie_samesite=os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
            session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "phishscope_session"),
            permanent_session_lifetime_minutes=_env_int("SESSION_LIFETIME_MINUTES", 480),
            metrics_token=os.getenv("METRICS_TOKEN", secrets.token_urlsafe(24)),
            rate_limit_login=_env_int("RATE_LIMIT_LOGIN_PER_WINDOW", 10),
            rate_limit_analyze=_env_int("RATE_LIMIT_ANALYZE_PER_WINDOW", 30),
            rate_limit_batch=_env_int("RATE_LIMIT_BATCH_PER_WINDOW", 5),
            rate_limit_notes=_env_int("RATE_LIMIT_NOTES_PER_WINDOW", 30),
            rate_limit_window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", 60),
            batch_max_urls=_env_int("BATCH_MAX_URLS", 50),
            url_max_length=_env_int("URL_MAX_LENGTH", 2048),
            note_max_length=_env_int("NOTE_MAX_LENGTH", 4000),
            enable_worker=_env_bool("ENABLE_BACKGROUND_WORKER", True),
            worker_poll_interval_seconds=_env_int("WORKER_POLL_INTERVAL_SECONDS", 2),
            worker_max_retries=_env_int("WORKER_MAX_RETRIES", 5),
            worker_stale_after_seconds=_env_int("WORKER_STALE_AFTER_SECONDS", 300),
            request_timeout_seconds=_env_int("REQUEST_TIMEOUT_SECONDS", 5),
            external_timeout_seconds=_env_int("EXTERNAL_TIMEOUT_SECONDS", 4),
            ollama_timeout_seconds=_env_int("OLLAMA_TIMEOUT_SECONDS", 30),
            screenshot_timeout_ms=_env_int("SCREENSHOT_TIMEOUT_MS", 15000),
        )

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def validate(self) -> None:
        if self.app_role not in {"web", "worker"}:
            raise RuntimeError("APP_ROLE must be 'web' or 'worker'")
        if self.is_production and not self.secret_key:
            raise RuntimeError("FLASK_SECRET_KEY must be set when APP_ENV=production")
