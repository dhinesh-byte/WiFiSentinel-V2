import re

import pytest
from flask import Flask, render_template_string

from access_control import configure_access_control


def clear_credentials(monkeypatch):
    for name in (
        "WIFI_SENTINEL_USERNAME",
        "WIFI_SENTINEL_PASSWORD",
        "WIFI_SENTINEL_SECRET_KEY",
        "WIFI_SENTINEL_COOKIE_SECURE",
    ):
        monkeypatch.delenv(name, raising=False)


def set_credentials(monkeypatch, secure_cookie="0"):
    monkeypatch.setenv("WIFI_SENTINEL_USERNAME", "test-operator")
    monkeypatch.setenv("WIFI_SENTINEL_PASSWORD", "test-password-long")
    monkeypatch.setenv("WIFI_SENTINEL_SECRET_KEY", "test-secret-key-that-is-at-least-thirty-two-characters")
    monkeypatch.setenv("WIFI_SENTINEL_COOKIE_SECURE", secure_cookie)


def test_remote_bind_fails_closed_without_auth_and_secure_cookies(monkeypatch):
    clear_credentials(monkeypatch)
    with pytest.raises(RuntimeError, match="Non-loopback binding requires configured credentials"):
        configure_access_control(Flask("no-auth"), "0.0.0.0")

    set_credentials(monkeypatch)
    with pytest.raises(RuntimeError, match="WIFI_SENTINEL_COOKIE_SECURE=1"):
        configure_access_control(Flask("no-secure-cookie"), "0.0.0.0")

    monkeypatch.setenv("WIFI_SENTINEL_COOKIE_SECURE", "1")
    remote_app = Flask("remote-secure")
    configure_access_control(remote_app, "0.0.0.0")
    assert remote_app.config["SESSION_COOKIE_SECURE"] is True


def test_login_csrf_and_authenticated_scan_request(monkeypatch):
    clear_credentials(monkeypatch)
    set_credentials(monkeypatch)
    test_app = Flask("auth-test")
    configure_access_control(test_app)
    test_app.add_url_rule("/private", "private", lambda: render_template_string("{{ csrf_token() }}"))
    test_app.add_url_rule("/api/change", "change", lambda: "changed", methods=["POST"])
    client = test_app.test_client()

    assert client.get("/private").status_code == 302
    assert client.get("/api/change").status_code == 401
    login_page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', login_page).group(1)
    assert client.post("/login", data={"csrf_token": "wrong", "username": "test-operator", "password": "test-password-long"}).status_code == 400
    assert client.post("/login", data={"csrf_token": token, "username": "test-operator", "password": "test-password-long"}).status_code == 302
    csrf_token = client.get("/private").get_data(as_text=True)
    assert client.post("/api/change").status_code == 400
    assert client.post("/api/change", headers={"X-CSRF-Token": csrf_token}).status_code == 200
