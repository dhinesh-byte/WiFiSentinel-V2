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
    <meta name="theme-color" content="#120d18">
    <title>Sign in | VulnScan v4.13</title>
    <link rel="stylesheet" href="/static/css/app.css">
    <link rel="stylesheet" href="/static/css/auth.css">
</head>
<body class="auth-page">
    <header class="auth-header">
        <a class="auth-brand" href="/" aria-label="VulnScan home">
            <span class="auth-brand-mark" aria-hidden="true">V</span>
            <span class="auth-brand-copy"><strong>VulnScan</strong><small>SECURITY OPERATIONS</small></span>
            <span class="auth-version">v4.13</span>
        </a>
        <div class="auth-instance"><span class="auth-live-dot" aria-hidden="true"></span> LOCAL INSTANCE</div>
    </header>

    <main class="auth-main">
        <section class="auth-intro" aria-labelledby="auth-title">
            <p class="auth-eyebrow"><span></span> AUTHORIZED ACCESS ONLY</p>
            <h1 id="auth-title">Network security.<br><span>Under control.</span></h1>
            <p class="auth-description">A focused workspace for defensive scans, exposure review, and security findings.</p>
            <div class="auth-intro-meta">
                <span>DEFENSIVE + OFFENSIVE</span>
                <span>LOCAL SECURITY WORKSPACE</span>
            </div>
        </section>

        <section class="auth-card" aria-labelledby="signin-title">
            <div class="auth-card-heading">
                <span class="auth-card-icon" aria-hidden="true">⌁</span>
                <div>
                    <p class="auth-card-kicker">SECURE SIGN-IN</p>
                    <h2 id="signin-title">Welcome back</h2>
                </div>
            </div>
            <p class="auth-card-copy">Use your administrator or user account to continue.</p>
            {% if error %}<p class="auth-error" role="alert">{{ error }}</p>{% endif %}
            <form method="post" autocomplete="on">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <label for="username">Username</label>
                <input id="username" name="username" autocomplete="username" placeholder="Enter your username" required autofocus>
                <label for="password">Password</label>
                <div class="auth-password-control">
                    <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Enter your password" required aria-describedby="password-visibility-help">
                    <button id="password-toggle" class="auth-password-toggle" type="button" aria-controls="password" aria-label="Show password" aria-pressed="false">Show</button>
                </div>
                <button class="auth-submit" type="submit"><span>Sign in</span><span aria-hidden="true">→</span></button>
            </form>
            <div class="auth-card-footer"><span class="auth-lock" aria-hidden="true">▣</span> Protected VulnScan workspace</div>
        </section>
    </main>

    <footer class="auth-footer"><span>VULNSCAN v4.13</span><span>AUTHORIZED USE ONLY</span></footer>
    <script>
        const passwordInput = document.getElementById("password");
        const passwordToggle = document.getElementById("password-toggle");
        passwordToggle.addEventListener("click", () => {
            const showPassword = passwordInput.type === "password";
            passwordInput.type = showPassword ? "text" : "password";
            passwordToggle.textContent = showPassword ? "Hide" : "Show";
            passwordToggle.setAttribute("aria-label", showPassword ? "Hide password" : "Show password");
            passwordToggle.setAttribute("aria-pressed", String(showPassword));
        });
    </script>
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
    legacy_username = os.environ.get("WIFI_SENTINEL_USERNAME", "")
    legacy_password = os.environ.get("WIFI_SENTINEL_PASSWORD", "")
    admin_username = os.environ.get("VULNSCAN_ADMIN_USERNAME", "")
    admin_password = os.environ.get("VULNSCAN_ADMIN_PASSWORD", "")
    user_username = os.environ.get("VULNSCAN_USER_USERNAME", "")
    user_password = os.environ.get("VULNSCAN_USER_PASSWORD", "")
    secret_key = os.environ.get("WIFI_SENTINEL_SECRET_KEY", "")
    secure_cookie = os.environ.get("WIFI_SENTINEL_COOKIE_SECURE") == "1"

    credential_pairs = (
        ("WIFI_SENTINEL_USERNAME", legacy_username, "WIFI_SENTINEL_PASSWORD", legacy_password),
        ("VULNSCAN_ADMIN_USERNAME", admin_username, "VULNSCAN_ADMIN_PASSWORD", admin_password),
        ("VULNSCAN_USER_USERNAME", user_username, "VULNSCAN_USER_PASSWORD", user_password),
    )
    for username_name, configured_username, password_name, configured_password in credential_pairs:
        if bool(configured_username) != bool(configured_password):
            raise RuntimeError(f"Set both {username_name} and {password_name}.")

    role_auth_requested = bool(admin_username or user_username)
    if role_auth_requested:
        if legacy_username:
            if admin_username and (admin_username, admin_password) != (legacy_username, legacy_password):
                raise RuntimeError("Legacy and VulnScan administrator credentials conflict.")
            admin_username = admin_username or legacy_username
            admin_password = admin_password or legacy_password
        if not admin_username or not user_username:
            raise RuntimeError(
                "Role-based login requires both administrator and user credential pairs."
            )
        if hmac.compare_digest(admin_username, user_username):
            raise RuntimeError("Administrator and user usernames must be different.")
    else:
        admin_username = legacy_username
        admin_password = legacy_password

    auth_enabled = bool(admin_username and admin_password)

    remote_bind = not _is_loopback(bind_host)
    if auth_enabled and len(secret_key) < 32:
        raise RuntimeError(
            "Authentication requires WIFI_SENTINEL_SECRET_KEY of at least 32 characters."
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
            supplied_username = request.form.get("username", "")
            supplied_password = request.form.get("password", "")
            is_admin = hmac.compare_digest(supplied_username, admin_username) & hmac.compare_digest(
                supplied_password, admin_password
            )
            is_user = hmac.compare_digest(supplied_username, user_username) & hmac.compare_digest(
                supplied_password, user_password
            )
            if not hmac.compare_digest(str(expected_token), supplied_token):
                error = "The sign-in form expired. Please try again."
            elif is_admin or is_user:
                session.clear()
                session["_authenticated"] = True
                session["_role"] = "admin" if is_admin else "user"
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
        return {
            "csrf_token": csrf_token,
            "auth_enabled": auth_enabled,
            "is_admin": session.get("_role") == "admin",
        }

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
