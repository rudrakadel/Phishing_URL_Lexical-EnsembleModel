from __future__ import annotations

import json
import logging
import re
import secrets
import time
import uuid
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, Response, g, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token as google_id_token
except Exception:  # pragma: no cover
    google_requests = None
    google_id_token = None

from config import AppConfig
from enrichment_queue import EnrichmentQueue
from metrics import MetricsRegistry
from rate_limit import RateLimiter
from services.analysis import PhishingAnalyzer
from services.storage import HistoryStore


BASE_DIR = Path(__file__).resolve().parent
APP_ROOT = BASE_DIR.parent


log = logging.getLogger("flask-phishing-app")
if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def create_app() -> Flask:
    config = AppConfig.from_env(BASE_DIR, APP_ROOT)
    config.validate()

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = config.secret_key or "dev-only-secret-key"
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    app.config["MODEL_DIR"] = config.model_dir
    app.config["DATABASE_URL"] = config.database_url
    app.config["REQUIRE_AUTH"] = config.require_auth
    app.config["APP_USERNAME"] = config.app_username
    app.config["APP_PASSWORD"] = config.app_password
    app.config["APP_PASSWORD_HASH"] = config.app_password_hash
    app.config["GOOGLE_CLIENT_ID"] = config.google_client_id
    app.config["SESSION_COOKIE_SECURE"] = config.session_cookie_secure
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = config.session_cookie_samesite
    app.config["SESSION_COOKIE_NAME"] = config.session_cookie_name
    app.permanent_session_lifetime = timedelta(minutes=config.permanent_session_lifetime_minutes)

    history = HistoryStore(app.config["DATABASE_URL"])
    analyzer = PhishingAnalyzer(BASE_DIR=BASE_DIR, model_dir=Path(app.config["MODEL_DIR"]))
    history.init_db()

    metrics = MetricsRegistry()
    rate_limiter = RateLimiter(config.rate_limit_window_seconds, redis_url=analyzer.redis_url)
    enrichment_queue = EnrichmentQueue(
        history=history,
        analyzer=analyzer,
        metrics=metrics,
        poll_interval_seconds=config.worker_poll_interval_seconds,
        max_retries=config.worker_max_retries,
        stale_after_seconds=config.worker_stale_after_seconds,
    )
    worker_active_in_process = bool(config.enable_worker and config.app_role == "worker")
    if worker_active_in_process:
        enrichment_queue.start()

    def json_error(message: str, status: int = 400) -> tuple[Response, int]:
        return jsonify({"error": message, "request_id": getattr(g, "request_id", None)}), status

    def read_json_dict() -> dict:
        payload = request.get_json(silent=True)
        return payload if isinstance(payload, dict) else {}

    def sanitize_url(value: str) -> str:
        url = str(value or "").strip()
        if len(url) > config.url_max_length:
            raise ValueError(f"url exceeds {config.url_max_length} characters")
        return url

    def sanitize_text_input(value: str) -> str:
        text = str(value or "").strip()
        max_text_length = min(config.max_content_length, max(config.url_max_length * 20, 10000))
        if len(text) > max_text_length:
            raise ValueError(f"text exceeds {max_text_length} characters")
        return text

    def extract_urls_from_text(value: str) -> list[str]:
        text = str(value or "").strip()
        if not text:
            return []
        normalized_text = re.sub(r"\bhxxps://", "https://", text, flags=re.IGNORECASE)
        normalized_text = re.sub(r"\bhxxp://", "http://", normalized_text, flags=re.IGNORECASE)
        pattern = re.compile(r"((?:(?:https?|ftp)://|www\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}(?::\d{2,5})?(?:/[^\s<>\")]*)?)", re.IGNORECASE)
        seen = set()
        urls: list[str] = []
        for match in pattern.findall(normalized_text):
            candidate = match.strip("()[]{}<>,.?!\"'`")
            candidate = re.sub(r"(?<!/)/+$", "", candidate)
            if not candidate:
                continue
            if candidate.lower().startswith("www."):
                normalized = f"http://{candidate}"
            elif candidate.startswith(("http://", "https://", "ftp://")):
                normalized = candidate
            else:
                normalized = f"http://{candidate}"
            if normalized not in seen:
                seen.add(normalized)
                urls.append(normalized)
        return urls

    def sanitize_username(value: str) -> str:
        username = str(value or "").strip().lower()
        if len(username) < 3 or len(username) > 40:
            raise ValueError("username must be between 3 and 40 characters")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
        if any(ch not in allowed for ch in username):
            raise ValueError("username may only contain letters, numbers, ., _, and -")
        return username

    def sanitize_first_name(value: str) -> str:
        first_name = str(value or "").strip()
        if len(first_name) < 2 or len(first_name) > 40:
            raise ValueError("first name must be between 2 and 40 characters")
        return first_name

    def sanitize_last_name(value: str) -> str:
        last_name = str(value or "").strip()
        if last_name and len(last_name) > 40:
            raise ValueError("last name must be 40 characters or fewer")
        return last_name

    def sanitize_mobile(value: str) -> str:
        mobile = "".join(ch for ch in str(value or "") if ch.isdigit())
        if len(mobile) != 10:
            raise ValueError("mobile number must contain exactly 10 digits")
        return mobile

    def sanitize_password(value: str) -> str:
        password = str(value or "")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        return password

    def finalize_analysis_result(result: dict, raw_input: str, original_url: str, extracted_urls: list[str] | None = None) -> dict:
        result["input_url"] = raw_input or original_url
        if extracted_urls is not None:
            result["extracted_urls"] = extracted_urls
        result["community_feedback"] = history.feedback_summary_for_url(result.get("url", original_url))
        result["enrichment"] = {"status": "complete"}
        return result

    def current_actor() -> str:
        username = session.get("username")
        if username:
            return f"user:{username}"
        return f"ip:{request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')}"

    def apply_rate_limit(bucket: str, limit: int):
        result = rate_limiter.check(f"{bucket}:{current_actor()}", limit)
        if not result.allowed:
            response = jsonify({"error": "rate limit exceeded", "retry_in_seconds": result.reset_in_seconds})
            response.status_code = 429
            response.headers["Retry-After"] = str(result.reset_in_seconds)
            return response
        return None

    def rate_limited(bucket: str, limit: int):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                blocked = apply_rate_limit(bucket, limit)
                if blocked:
                    return blocked
                return view(*args, **kwargs)

            return wrapped

        return decorator

    def auth_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not app.config["REQUIRE_AUTH"]:
                return view(*args, **kwargs)
            if session.get("authenticated"):
                return view(*args, **kwargs)
            if request.path.startswith("/api/"):
                return json_error("authentication required", 401)
            return redirect(url_for("login_page"))

        return wrapped

    def verify_legacy_password(password: str) -> bool:
        password_hash = app.config["APP_PASSWORD_HASH"]
        if password_hash:
            try:
                return check_password_hash(password_hash, password)
            except Exception:
                return False
        expected = app.config["APP_PASSWORD"]
        return bool(expected) and secrets.compare_digest(expected, password)

    @app.before_request
    def attach_request_context():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.request_started = time.perf_counter()
        session.permanent = True

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Request-ID"] = g.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://accounts.google.com; "
            "script-src 'self' https://accounts.google.com https://accounts.googleusercontent.com; "
            "img-src 'self' data: https://*.googleusercontent.com; "
            "frame-src 'self' https://accounts.google.com; "
            "connect-src 'self' http://127.0.0.1:11434 http://localhost:11434 https://www.virustotal.com https://urlhaus-api.abuse.ch"
        )
        duration = time.perf_counter() - g.request_started
        metrics.increment("phishscope_http_requests_total")
        metrics.observe("phishscope_http_request_duration", duration)
        metrics.gauge("phishscope_jobs_pending", float(history.count_pending_jobs()))
        log.info(
            json.dumps(
                {
                    "event": "http_request",
                    "request_id": g.request_id,
                    "method": request.method,
                    "path": request.path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration * 1000, 2),
                    "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
                }
            )
        )
        return response

    @app.get("/")
    def root():
        return redirect(url_for("login_page"))

    @app.get("/dashboard")
    @auth_required
    def index():
        return render_template("index.html", google_client_id=app.config["GOOGLE_CLIENT_ID"])

    @app.get("/about")
    def about():
        return render_template("about.html", google_client_id=app.config["GOOGLE_CLIENT_ID"])

    @app.get("/login")
    def login_page():
        return render_template("login.html", google_client_id=app.config["GOOGLE_CLIENT_ID"])

    @app.get("/history-center")
    @auth_required
    def history_center():
        return render_template("history_center.html", google_client_id=app.config["GOOGLE_CLIENT_ID"])

    @app.get("/security-layers")
    def security_layers():
        return render_template("security_layers.html", google_client_id=app.config["GOOGLE_CLIENT_ID"])

    @app.get("/api/auth/status")
    def auth_status():
        return jsonify(
            {
                "require_auth": app.config["REQUIRE_AUTH"],
                "authenticated": bool(session.get("authenticated")),
                "username": session.get("username"),
                "first_name": session.get("first_name"),
                "mobile": session.get("mobile"),
                "auth_provider": session.get("auth_provider"),
                "registered_users": history.count_users(),
                "google_enabled": bool(app.config["GOOGLE_CLIENT_ID"] and google_id_token and google_requests),
                "google_client_id": app.config["GOOGLE_CLIENT_ID"] or None,
            }
        )

    @app.post("/api/auth/register")
    @rate_limited("register", config.rate_limit_login)
    def register():
        payload = read_json_dict()
        try:
            username = sanitize_username(payload.get("username"))
            first_name = sanitize_first_name(payload.get("first_name"))
            last_name = sanitize_last_name(payload.get("last_name"))
            mobile = sanitize_mobile(payload.get("mobile"))
            password = sanitize_password(payload.get("password"))
        except ValueError as exc:
            return json_error(str(exc), 400)
        if history.get_user_by_username(username):
            return json_error("username is already taken", 409)
        if history.get_user_by_mobile(mobile):
            return json_error("mobile number is already registered", 409)
        password_hash = generate_password_hash(password)
        history.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            mobile=mobile,
            password_hash=password_hash,
        )
        session.clear()
        session["authenticated"] = True
        session["username"] = username
        session["first_name"] = first_name
        session["mobile"] = mobile
        session["auth_provider"] = "local"
        metrics.increment("phishscope_auth_success_total")
        return jsonify({"status": "ok", "username": username, "first_name": first_name})

    @app.post("/api/auth/login")
    @rate_limited("login", config.rate_limit_login)
    def login():
        payload = read_json_dict()
        identifier = str(payload.get("username") or payload.get("mobile") or "").strip().lower()
        password = str(payload.get("password") or "")
        if not identifier or not password:
            return json_error("username or mobile and password are required", 400)
        user = history.get_user_by_mobile("".join(ch for ch in identifier if ch.isdigit())) if any(ch.isdigit() for ch in identifier) else None
        if not user:
            user = history.get_user_by_username(identifier)
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["authenticated"] = True
            session["username"] = user["username"]
            session["first_name"] = user["first_name"]
            session["mobile"] = user["mobile"]
            session["auth_provider"] = "local"
            metrics.increment("phishscope_auth_success_total")
            return jsonify({"status": "ok", "first_name": user["first_name"]})
        if identifier == app.config["APP_USERNAME"] and verify_legacy_password(password):
            session.clear()
            session["authenticated"] = True
            session["username"] = identifier
            session["first_name"] = identifier.split("@")[0].split(".")[0].title()
            session["auth_provider"] = "local"
            metrics.increment("phishscope_auth_success_total")
            return jsonify({"status": "ok"})
        metrics.increment("phishscope_auth_failure_total")
        return json_error("invalid credentials", 401)

    @app.post("/api/auth/google")
    @rate_limited("login", config.rate_limit_login)
    def google_login():
        if not app.config["GOOGLE_CLIENT_ID"] or not google_id_token or not google_requests:
            return json_error("google auth not configured", 400)
        payload = read_json_dict()
        credential = str(payload.get("credential") or "").strip()
        if not credential:
            return json_error("credential is required", 400)
        try:
            claims = google_id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                app.config["GOOGLE_CLIENT_ID"],
            )
        except Exception as exc:
            metrics.increment("phishscope_auth_failure_total")
            return json_error(f"google token verification failed: {exc}", 401)

        session.clear()
        session["authenticated"] = True
        session["username"] = claims.get("email") or claims.get("name") or "google-user"
        session["first_name"] = (claims.get("given_name") or claims.get("name") or "Analyst").split(" ")[0]
        session["mobile"] = None
        session["auth_provider"] = "google"
        metrics.increment("phishscope_auth_success_total")
        return jsonify({"status": "ok", "username": session["username"], "first_name": session["first_name"]})

    @app.post("/api/auth/logout")
    def logout():
        session.clear()
        return jsonify({"status": "ok"})

    @app.get("/api/health")
    @auth_required
    def health():
        return jsonify(
            {
                "status": "ok",
                "app_role": config.app_role,
                "environment": config.env,
                "model_ready": analyzer.model_ready,
                "model_dir": analyzer.model_dir.as_posix(),
                "missing_dependencies": analyzer.missing_dependencies,
                "optional_services": analyzer.optional_services_status(),
                "database_ok": history.healthcheck(),
                "jobs_pending": history.count_pending_jobs(),
                "worker_enabled": config.enable_worker,
                "worker_active_in_process": worker_active_in_process,
            }
        )

    @app.get("/api/metrics")
    def metrics_view():
        if config.metrics_token and request.headers.get("X-Metrics-Token") != config.metrics_token:
            return json_error("forbidden", 403)
        return Response(metrics.render_prometheus(), mimetype="text/plain; version=0.0.4")

    @app.get("/api/history")
    @auth_required
    def get_history():
        limit = request.args.get("limit", default=20, type=int)
        limit = max(1, min(limit, 100))
        return jsonify({"items": history.fetch_recent(limit=limit, username=session.get("username"))})

    @app.post("/api/analyze")
    @auth_required
    @rate_limited("analyze", config.rate_limit_analyze)
    def analyze():
        payload = read_json_dict()
        try:
            raw_input = sanitize_text_input(payload.get("text", "") or payload.get("url", ""))
        except ValueError as exc:
            return json_error(str(exc), 400)
        if not raw_input:
            return json_error("url is required", 400)
        extracted = extract_urls_from_text(raw_input)
        if not extracted:
            return json_error("no valid URL found in input", 400)
        url = extracted[0]

        started = time.perf_counter()
        result = finalize_analysis_result(analyzer.analyze_url(url), raw_input, url, extracted)
        analysis_id = history.save(result, username=session.get("username"), auth_provider=session.get("auth_provider"))
        result["analysis_id"] = analysis_id
        result["notes"] = []
        result["enrichment_job_id"] = None
        metrics.increment("phishscope_analysis_requests_total")
        metrics.observe("phishscope_fast_analysis_duration", time.perf_counter() - started)
        return jsonify(result)

    @app.post("/api/batch")
    @auth_required
    @rate_limited("batch", config.rate_limit_batch)
    def batch():
        payload = read_json_dict()
        urls = payload.get("urls")
        text_blob = payload.get("text")
        if isinstance(urls, list):
            raw_items = urls
        elif isinstance(text_blob, str):
            raw_items = [line for line in text_blob.splitlines() if line.strip()]
        else:
            raw_items = []
        if not raw_items:
            return json_error("urls must be a non-empty array", 400)

        normalized: list[str] = []
        try:
            for item in raw_items[: config.batch_max_urls]:
                value = sanitize_url(item)
                if value:
                    normalized.extend(extract_urls_from_text(value))
        except ValueError as exc:
            return json_error(str(exc), 400)
        deduped: list[str] = []
        seen = set()
        for item in normalized:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        normalized = deduped[: config.batch_max_urls]
        if not normalized:
            return json_error("no valid urls supplied", 400)

        results = []
        for url in normalized:
            result = finalize_analysis_result(analyzer.analyze_url(url), url, url)
            analysis_id = history.save(result, username=session.get("username"), auth_provider=session.get("auth_provider"))
            result["analysis_id"] = analysis_id
            result["enrichment_job_id"] = None
            results.append(result)
        metrics.increment("phishscope_batch_requests_total")
        return jsonify({"count": len(results), "items": results})

    @app.get("/api/analysis/<int:analysis_id>")
    @auth_required
    def analysis_detail(analysis_id: int):
        result = history.get_analysis(analysis_id)
        if not result:
            return json_error("analysis not found", 404)
        result["community_feedback"] = history.feedback_summary_for_url(result.get("url", ""))
        return jsonify(result)

    @app.post("/api/analysis/<int:analysis_id>/notes")
    @auth_required
    @rate_limited("notes", config.rate_limit_notes)
    def save_note(analysis_id: int):
        payload = read_json_dict()
        note = str(payload.get("note") or "").strip()
        if not note:
            return json_error("note is required", 400)
        if len(note) > config.note_max_length:
            return json_error(f"note exceeds {config.note_max_length} characters", 400)
        if not history.get_analysis(analysis_id):
            return json_error("analysis not found", 404)
        history.save_note(analysis_id, note)
        return jsonify({"items": history.fetch_notes(analysis_id)})

    @app.post("/api/analysis/<int:analysis_id>/feedback")
    @auth_required
    @rate_limited("notes", config.rate_limit_notes)
    def save_feedback(analysis_id: int):
        payload = read_json_dict()
        helpful = payload.get("helpful")
        if not isinstance(helpful, bool):
            return json_error("helpful must be true or false", 400)
        corrected_label = str(payload.get("corrected_label") or "").strip()
        note = str(payload.get("note") or "").strip()
        if len(corrected_label) > 80:
            return json_error("corrected label must be 80 characters or fewer", 400)
        if len(note) > config.note_max_length:
            return json_error(f"feedback note exceeds {config.note_max_length} characters", 400)
        analysis = history.get_analysis(analysis_id)
        if not analysis:
            return json_error("analysis not found", 404)
        normalized_url = analysis.get("url", "")
        history.save_feedback(
            analysis_id=analysis_id,
            normalized_url=normalized_url,
            username=session.get("username"),
            helpful=helpful,
            corrected_label=corrected_label,
            note=note,
        )
        return jsonify(history.feedback_summary_for_url(normalized_url))

    @app.get("/api/report/<int:analysis_id>")
    @auth_required
    def report(analysis_id: int):
        result = history.get_analysis(analysis_id)
        if not result:
            return json_error("analysis not found", 404)
        pdf_path = analyzer.generate_pdf_report(result)
        if not pdf_path:
            return json_error("report generation unavailable", 503)
        return send_file(pdf_path, as_attachment=True, download_name=f"analysis-{analysis_id}.pdf")

    @app.errorhandler(404)
    def not_found(_error):
        return json_error("endpoint not found", 404)

    @app.errorhandler(500)
    def internal_error(_error):
        metrics.increment("phishscope_http_500_total")
        return json_error("internal server error", 500)

    return app


app = create_app()


if __name__ == "__main__":
    runtime_config = AppConfig.from_env(BASE_DIR, APP_ROOT)
    if runtime_config.app_role != "web":
        raise RuntimeError("app.py should be run with APP_ROLE=web. Use run_worker.py for the worker process.")
    app.run(debug=runtime_config.debug, host=runtime_config.host, port=runtime_config.port)
