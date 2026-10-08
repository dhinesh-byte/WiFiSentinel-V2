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
        "VULNSCAN_ADMIN_USERNAME",
        "VULNSCAN_ADMIN_PASSWORD",
        "VULNSCAN_USER_USERNAME",
        "VULNSCAN_USER_PASSWORD",
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


@pytest.mark.parametrize(
    ("username", "password", "expected_role"),
    [
        ("dhinesh", "dhinesh@123", "admin"),
        ("user", "user@123", "user"),
    ],
)
def test_admin_and_user_share_csrf_protected_login(monkeypatch, username, password, expected_role):
    clear_credentials(monkeypatch)
    monkeypatch.setenv("VULNSCAN_ADMIN_USERNAME", "dhinesh")
    monkeypatch.setenv("VULNSCAN_ADMIN_PASSWORD", "dhinesh@123")
    monkeypatch.setenv("VULNSCAN_USER_USERNAME", "user")
    monkeypatch.setenv("VULNSCAN_USER_PASSWORD", "user@123")
    monkeypatch.setenv("WIFI_SENTINEL_SECRET_KEY", "test-secret-key-that-is-at-least-thirty-two-characters")

    test_app = Flask("role-auth-test")
    configure_access_control(test_app)
    test_app.add_url_rule("/private", "private", lambda: "private")
    test_app.add_url_rule(
        "/role",
        "role",
        lambda: render_template_string("{{ 'admin' if is_admin else 'user' }}"),
    )
    client = test_app.test_client()

    login_page = client.get("/login").get_data(as_text=True)
    assert "administrator or user account" in login_page
    token = re.search(r'name="csrf_token" value="([^"]+)"', login_page).group(1)
    assert client.post("/login", data={"csrf_token": token, "username": username, "password": password}).status_code == 302
    assert client.get("/private").status_code == 200
    assert client.get("/role").get_data(as_text=True) == expected_role
    with client.session_transaction() as session:
        assert session["_role"] == expected_role


def test_role_auth_requires_both_distinct_accounts(monkeypatch):
    clear_credentials(monkeypatch)
    monkeypatch.setenv("VULNSCAN_ADMIN_USERNAME", "same-account")
    monkeypatch.setenv("VULNSCAN_ADMIN_PASSWORD", "test-admin-password-long")
    monkeypatch.setenv("VULNSCAN_USER_USERNAME", "same-account")
    monkeypatch.setenv("VULNSCAN_USER_PASSWORD", "test-user-password-long")

    with pytest.raises(RuntimeError, match="usernames must be different"):
        configure_access_control(Flask("duplicate-role-auth"))
