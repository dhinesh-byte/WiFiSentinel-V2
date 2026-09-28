"""Shared session authentication for the defensive and offensive apps."""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets

from flask import Blueprint, jsonify, redirect, render_template_string, request, session, url_for


LOGIN_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in | WiFi Sentinel</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f2f6f2; color: #20342d; font: 15px "Segoe UI", sans-serif; }
    main { width: min(360px, calc(100% - 36px)); padding: 28px; border: 1px solid #dbe5de; background: #fff; }
    h1 { margin: 0 0 8px; font-size: 22px; }
    p { color: #718079; line-height: 1.5; }
    label { display: block; margin: 16px 0 6px; font-size: 12px; font-weight: 600; }
    input { width: 100%; box-sizing: border-box; min-height: 42px; padding: 8px 10px; border: 1px solid #c5d2c9; font: inherit; }
    button { width: 100%; min-height: 42px; margin-top: 20px; border: 0; background: #214e3d; color: #fff; font: inherit; font-weight: 600; cursor: pointer; }
    .error { color: #a32e2e; }
  </style>
</head>
<body>
  <main>
    <h1>WiFi Sentinel</h1>
    <p>Sign in to access the local security workspace.</p>
    {% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
    <form method="post" autocomplete="on">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"""


def _is_loopback(host: str) -> bool:
    normalized_host = host.strip().strip("[]").lower()
    if normalized_host == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized_host).is_loopback
    except ValueError:
        return False


def configure_access_control(app, host: str | None = None) -> None:
    """Configure local-only defaults and optional environment-based login."""
    bind_host = host or os.environ.get("WIFI_SENTINEL_HOST", "127.0.0.1")
    username = os.environ.get("WIFI_SENTINEL_USERNAME", "")
    password = os.environ.get("WIFI_SENTINEL_PASSWORD", "")
    secret_key = os.environ.get("WIFI_SENTINEL_SECRET_KEY", "")
    secure_cookie = os.environ.get("WIFI_SENTINEL_COOKIE_SECURE") == "1"

    if bool(username) != bool(password):
        raise RuntimeError("Set both WIFI_SENTINEL_USERNAME and WIFI_SENTINEL_PASSWORD.")

    auth_enabled = bool(username and password)
    remote_bind = not _is_loopback(bind_host)
    if auth_enabled and (len(password) < 16 or len(secret_key) < 32):
        raise RuntimeError(
            "Authentication requires a password of at least 16 characters and "
            "WIFI_SENTINEL_SECRET_KEY of at least 32 characters."
        )
    if remote_bind and not auth_enabled:
        raise RuntimeError(
            "Non-loopback binding requires configured credentials; the app stays local by default."
        )
    if remote_bind and not secure_cookie:
        raise RuntimeError(
            "Non-loopback binding requires WIFI_SENTINEL_COOKIE_SECURE=1 behind HTTPS."
        )

    app.secret_key = secret_key or secrets.token_urlsafe(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=secure_cookie,
        PERMANENT_SESSION_LIFETIME=3600,
    )
    blueprint = Blueprint("wifi_sentinel_access", __name__)

    def csrf_token() -> str:
        token = session.get("_csrf_token")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    @blueprint.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_enabled:
            return redirect(request.script_root + "/")
        if session.get("_authenticated") is True:
            return redirect(request.script_root + "/")
        error = None
        if request.method == "POST":
            expected_token = session.get("_csrf_token", "")
            supplied_token = request.form.get("csrf_token", "")
            if not hmac.compare_digest(str(expected_token), supplied_token):
                error = "The sign-in form expired. Please try again."
            elif hmac.compare_digest(request.form.get("username", ""), username) & hmac.compare_digest(
                request.form.get("password", ""), password
            ):
                session.clear()
                session["_authenticated"] = True
                csrf_token()
                session.permanent = True
                return redirect(request.script_root + "/")
            else:
                error = "Username or password was not accepted."

        return render_template_string(
            LOGIN_TEMPLATE,
            csrf_token=csrf_token(),
            error=error,
        )

    @blueprint.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("wifi_sentinel_access.login"))

    @app.context_processor
    def inject_access_helpers():
        return {"csrf_token": csrf_token, "auth_enabled": auth_enabled}

    @app.before_request
    def require_authenticated_session():
        if not auth_enabled:
            return None
        if request.endpoint == "wifi_sentinel_access.login":
            if request.endpoint == "wifi_sentinel_access.login" and request.method == "POST":
                expected_token = session.get("_csrf_token", "")
                supplied_token = request.form.get("csrf_token", "")
                if not hmac.compare_digest(str(expected_token), supplied_token):
                    return "Invalid CSRF token.", 400
            return None
        if request.endpoint == "wifi_sentinel_access.logout":
            expected_token = session.get("_csrf_token", "")
            supplied_token = request.form.get("csrf_token", "")
            if session.get("_authenticated") is True and not hmac.compare_digest(
                str(expected_token), supplied_token
            ):
                return "Invalid CSRF token.", 400
            return None
        if request.endpoint == "static":
            return None
        if session.get("_authenticated") is not True:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect(url_for("wifi_sentinel_access.login"))
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected_token = session.get("_csrf_token", "")
            supplied_token = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(str(expected_token), supplied_token):
                return jsonify({"error": "Invalid CSRF token."}), 400
        return None

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if auth_enabled:
            response.headers["Cache-Control"] = "no-store"
        return response

    app.register_blueprint(blueprint)
