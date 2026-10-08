from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pytest
from flask import Flask

import app as app_module
from proxy.engine import ProxyConfigurationError, ProxyService
from proxy.engine import _ProxyAddon
from proxy.routes import register_proxy_routes
from mitmproxy.websocket import WebSocketMessage


class LocalTargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size) if size else b""
        self.server.received.append({"method": self.command, "path": self.path, "body": body, "headers": dict(self.headers)})
        status = 404 if self.path.startswith("/missing") else 200
        response = json.dumps({"method": self.command, "path": self.path, "body": body.decode("utf-8", "replace")}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond

    def log_message(self, format, *args):
        return


@pytest.fixture

def local_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalTargetHandler)
    server.received = []
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


@pytest.fixture

def proxy_service(tmp_path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        proxy_port = listener.getsockname()[1]
    service = ProxyService(tmp_path / "proxy-data")
    status = service.start({"address": "127.0.0.1", "port": proxy_port, "intercept": False})
    assert status["state"] == "running", status
    assert service.ca_certificate_path() is None
    assert not (service.ca_directory / "mitmproxy-ca-cert.pem").exists()
    try:
        yield service, proxy_port
    finally:
        service.stop()
        assert service.status()["state"] == "stopped"
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", proxy_port))
        assert service.ca_certificate_path() is None


def _send_request(proxy_port, url, *, method="GET", body=None, headers=None, result=None, completed=None):
    connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=8)
    request_headers = {"Content-Type": "application/json", "Connection": "close"}
    if headers:
        request_headers.update(headers)
    try:
        connection.request(method, url, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        if result is not None:
            result.update({"status": response.status, "body": response_body})
    except Exception as exc:
        if result is not None:
            result["error"] = exc
    finally:
        connection.close()
        if completed is not None:
            completed.set()


def _wait_until(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.025)
    return False


def test_proxy_is_a_separate_workspace_and_loopback_only():
    client = app_module.app.test_client()
    page = client.get("/proxy")
    assert page.status_code == 200
    assert b"VulnScan Proxy" in page.data
    assert b"HTTP History" in page.data
    assert b"WebSockets History" in page.data
    assert b"Match and Replace" in page.data
    assert b"Proxy Settings" in page.data
    assert b"Request Replay" in page.data
    assert b"Site Map" in page.data
    assert b"Scope" in page.data
    assert b"Issues" in page.data
    assert b"data-proxy-tab=\"intercept\"" in page.data
    assert b"data-proxy-tab=\"history\"" in page.data
    assert b"data-proxy-tab=\"websockets\"" in page.data
    assert b"data-proxy-tab=\"match\"" in page.data
    assert b"data-proxy-tab=\"settings\"" in page.data
    assert b'role="tablist" aria-label="Proxy workspaces"' in page.data
    assert b'role="tab" aria-controls="proxy-panel-history"' in page.data
    assert b'role="tabpanel" aria-labelledby="proxy-tab-history"' in page.data
    assert b"data-proxy-tab=\"history\">Logger" in page.data
    assert b"static/js/proxy.light.js" in page.data
    assert b'name="csrf-token" content="' in page.data
    assert b'id="request-edit-form"' in page.data
    assert b"data-target-tab=\"site-map\"" in page.data
    assert b"data-target-tab=\"scope\"" in page.data
    assert b"data-target-tab=\"issues\"" in page.data
    assert b'id="scope-note"' in page.data
    assert b"/proxy" in page.data
    assert b"/defensive" in page.data
    assert b"/offensive/" in page.data
    assert b'id="proxy-inspector-forward"' in page.data
    assert b'id="proxy-inspector-drop"' in page.data
    assert client.get("/api/proxy/status").get_json()["state"] in {"stopped", "running"}
    assert client.get("/api/proxy/target/scope").get_json()["scope"] == {"include": [], "exclude": []}

    isolated_app = Flask("proxy-security-test")
    isolated_app.secret_key = "test-secret"
    service = register_proxy_routes(isolated_app, app_module.DATA_DIR / "proxy-test")
    response = isolated_app.test_client().post("/api/proxy/settings", json={"address": "0.0.0.0"})
    assert response.status_code == 400
    assert "loopback" in response.get_json()["error"].lower()
    assert service.status()["state"] == "stopped"
    browser = isolated_app.test_client().post("/api/proxy/browser/open", json={})
    assert browser.status_code == 409


def test_target_summary_handles_requests_without_a_response(tmp_path):
    isolated_app = Flask("proxy-target-test")
    isolated_app.secret_key = "test-secret"
    service = register_proxy_routes(isolated_app, tmp_path / "proxy-data")
    service.history._records["failed-flow"] = {
        "id": "failed-flow",
        "host": "example.test",
        "path": "/unavailable",
        "response_status": None,
        "response_reason": "",
        "error": "connection refused",
        "timestamp": "2026-10-08T00:00:00Z",
    }

    response = isolated_app.test_client().get("/api/proxy/target")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["site_map"] == [{"host": "example.test", "paths": ["/unavailable"]}]
    assert payload["issues"] == [{
        "id": "failed-flow",
        "host": "example.test",
        "path": "/unavailable",
        "status": None,
        "title": "connection refused",
        "timestamp": "2026-10-08T00:00:00Z",
    }]


def test_proxy_scope_blocks_out_of_scope_traffic_before_capture(proxy_service, local_target):
    service, proxy_port = proxy_service
    service.update_scope({"include": [f"http://127.0.0.1:{local_target.server_port}/allowed"], "exclude": []})
    target = f"http://127.0.0.1:{local_target.server_port}"

    result = {}
    _send_request(proxy_port, f"{target}/blocked", result=result)
    assert result["status"] == 502
    assert not any(item["path"] == "/blocked" for item in service.history_page({})["items"])

    allowed_result = {}
    _send_request(proxy_port, f"{target}/allowed", result=allowed_result)
    assert allowed_result["status"] == 200
    assert any(item["path"] == "/allowed" for item in service.history_page({})["items"])


def test_proxy_scope_also_blocks_out_of_scope_replay(proxy_service, local_target):
    service, proxy_port = proxy_service
    target = f"http://127.0.0.1:{local_target.server_port}"
    service.update_scope({"include": [f"{target}/allowed"], "exclude": []})
    captured = {}
    _send_request(proxy_port, f"{target}/allowed/source", result=captured)
    assert captured["status"] == 200
    assert _wait_until(lambda: bool(service.history_page({"path": "/allowed/source"})["items"]))
    source = service.history_page({"path": "/allowed/source"})["items"][0]

    with pytest.raises(ProxyConfigurationError, match="outside the authorized target scope"):
        service.replay({"source_id": source["id"], "url": f"{target}/blocked"})

    assert not any(item["path"] == "/blocked" for item in local_target.received)


def test_proxy_forwards_and_captures_real_get_and_post(proxy_service, local_target):
    service, proxy_port = proxy_service
    target = f"http://127.0.0.1:{local_target.server_port}"
    get_result = {}
    _send_request(proxy_port, f"{target}/api/items?page=2", result=get_result)
    assert get_result["status"] == 200
    assert json.loads(get_result["body"])["path"] == "/api/items?page=2"

    post_result = {}
    _send_request(
        proxy_port,
        f"{target}/api/login",
        method="POST",
        body=b'{"user":"demo"}',
        headers={"Cookie": "session=abc123; theme=dark", "Sec-Fetch-Mode": "navigate"},
        result=post_result,
    )
    assert post_result["status"] == 200
    assert local_target.received[1]["body"] == b'{"user":"demo"}'
    assert _wait_until(lambda: service.history.stats(0)["responses"] == 2)

    items = service.history_page({"host": "127.0.0.1", "path": "/api", "page": 1})["items"]
    assert [item["method"] for item in items] == ["POST", "GET"]
    assert items[0]["status"] == 200
    detail = service.history.detail(items[0]["id"])
    assert detail["protocol"] == "HTTP/1.1"
    assert detail["response_protocol"] == "HTTP/1.1"
    assert detail["response_http_version"] == "HTTP/1.1"
    assert detail["authority"] == "127.0.0.1"
    assert detail["cookies"] == [{"name": "session", "value": "abc123"}, {"name": "theme", "value": "dark"}]
    assert json.loads(detail["request_body"]["text"]) == {"user": "demo"}
    assert json.loads(detail["response_body"]["text"])["path"] == "/api/login"
    assert detail["raw_response"].startswith("HTTP/1.1 200 OK")
    body_search = service.history_page({"q": "demo", "page": 1})["items"]
    assert any(item["path"] == "/api/login" for item in body_search)
    assert detail["query"] == [["page", "2"]] or service.history.detail(items[1]["id"])["query"] == [["page", "2"]]


def test_intercept_forward_and_drop_control_real_destination(proxy_service, local_target):
    service, proxy_port = proxy_service
    service.update_settings({"intercept": True})
    target = f"http://127.0.0.1:{local_target.server_port}"

    forwarded = {}
    forward_done = threading.Event()
    forward_worker = threading.Thread(target=_send_request, args=(proxy_port, f"{target}/forward"), kwargs={"result": forwarded, "completed": forward_done}, daemon=True)
    forward_worker.start()
    assert _wait_until(lambda: len(service.pending()) == 1)
    pending = service.pending()[0]
    assert not any(item["path"] == "/forward" for item in local_target.received)
    service.resolve_intercept(pending["id"], "forward")
    assert forward_done.wait(8)
    assert forwarded["status"] == 200
    assert any(item["path"] == "/forward" for item in local_target.received)

    dropped = {}
    drop_done = threading.Event()
    drop_worker = threading.Thread(target=_send_request, args=(proxy_port, f"{target}/drop"), kwargs={"result": dropped, "completed": drop_done}, daemon=True)
    drop_worker.start()
    assert _wait_until(lambda: any(item["path"].endswith("/drop") for item in service.pending()))
    drop = next(item for item in service.pending() if item["path"].endswith("/drop"))
    service.resolve_intercept(drop["id"], "drop")
    assert drop_done.wait(8)
    assert not any(item["path"] == "/drop" for item in local_target.received)
    assert service.history.detail(drop["id"])["state"] in {"Dropped", "Error"}


def test_proxy_starts_intercepting_by_default(tmp_path, local_target):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        proxy_port = listener.getsockname()[1]
    service = ProxyService(tmp_path / "proxy-data")
    status = service.start({"address": "127.0.0.1", "port": proxy_port})
    assert status["state"] == "running", status
    assert status["settings"]["intercept"] is True
    target = f"http://127.0.0.1:{local_target.server_port}"
    result = {}
    completed = threading.Event()
    worker = threading.Thread(
        target=_send_request,
        args=(proxy_port, f"{target}/held"),
        kwargs={"result": result, "completed": completed},
        daemon=True,
    )
    worker.start()
    try:
        assert _wait_until(lambda: bool(service.pending()))
        pending = service.pending()[0]
        assert not any(item["path"] == "/held" for item in local_target.received)
        service.resolve_intercept(pending["id"], "forward")
        assert completed.wait(8)
        assert result["status"] == 200
        assert any(item["path"] == "/held" for item in local_target.received)
    finally:
        service.stop()


def test_modified_intercept_and_manual_replay_both_use_real_proxy(proxy_service, local_target):
    service, proxy_port = proxy_service
    service.update_settings({"intercept": True})
    target = f"http://127.0.0.1:{local_target.server_port}"
    edited = {}
    edited_done = threading.Event()
    edited_worker = threading.Thread(target=_send_request, args=(proxy_port, f"{target}/before"), kwargs={"result": edited, "completed": edited_done}, daemon=True)
    edited_worker.start()
    assert _wait_until(lambda: bool(service.pending()))
    pending = service.pending()[0]
    service.resolve_intercept(pending["id"], "forward", {
        "method": "PUT",
        "url": f"{target}/after?mode=review",
        "headers": {"Content-Type": "text/plain", "X-Proxy-Test": "modified"},
        "body": "edited body",
    })
    assert edited_done.wait(8)
    assert edited["status"] == 200
    assert local_target.received[-1]["method"] == "PUT"
    assert local_target.received[-1]["path"] == "/after?mode=review"
    assert local_target.received[-1]["body"] == b"edited body"

    service.update_settings({"intercept": False})
    replay_result = {}
    _send_request(proxy_port, f"{target}/replay-source", result=replay_result)
    assert replay_result["status"] == 200
    assert _wait_until(lambda: service.history.stats(0)["responses"] >= 2)
    source = next(item for item in service.history_page({"path": "/replay-source"})["items"])
    replay = service.replay({"source_id": source["id"]})
    assert replay["status"] == 200
    assert sum(item["path"] == "/replay-source" for item in local_target.received) == 2
    assert service.history.stats(0)["requests"] >= 3


def test_modified_intercept_cannot_escape_target_scope(proxy_service, local_target):
    service, proxy_port = proxy_service
    service.update_settings({"intercept": True})
    target = f"http://127.0.0.1:{local_target.server_port}"
    service.update_scope({"include": [f"{target}/inside"], "exclude": []})
    result = {}
    completed = threading.Event()
    worker = threading.Thread(
        target=_send_request,
        args=(proxy_port, f"{target}/inside/request"),
        kwargs={"result": result, "completed": completed},
        daemon=True,
    )
    worker.start()
    assert _wait_until(lambda: bool(service.pending()))
    pending = service.pending()[0]

    with pytest.raises(ProxyConfigurationError, match="outside the authorized target scope"):
        service.resolve_intercept(pending["id"], "forward", {
            "url": f"{target}/outside",
            "headers": {},
            "body": "",
        })

    service.resolve_intercept(pending["id"], "forward")
    assert completed.wait(8)
    assert result["status"] == 200
    assert local_target.received[-1]["path"] == "/inside/request"


def test_proxy_refuses_untrusted_listener_and_https_without_explicit_ca(tmp_path):
    service = ProxyService(tmp_path / "proxy-data")
    with pytest.raises(ValueError, match="loopback"):
        service.start({"address": "0.0.0.0", "port": 8080})
    with pytest.raises(ValueError, match="Generate the local CA"):
        service.start({"address": "127.0.0.1", "port": 18081, "https_interception": True})
    assert not service.ca_directory.exists()


def test_ca_generation_is_explicit_and_exports_only_public_certificate(tmp_path):
    service = ProxyService(tmp_path / "proxy-data")
    result = service.generate_ca()
    assert result["ready"] is True
    assert service.ca_certificate_path().is_file()
    assert b"PRIVATE KEY" not in service.ca_certificate_path().read_bytes()
    assert (service.ca_directory / "mitmproxy-ca.pem").is_file()
    assert service.status()["state"] == "stopped"


def test_websocket_addon_captures_actual_frame_metadata(tmp_path):
    service = ProxyService(tmp_path / "proxy-data")
    frame = WebSocketMessage(type=1, from_client=True, content=b'{"action":"hello"}', timestamp=time.time())
    flow = SimpleNamespace(
        metadata={"vulnscan_request_id": "a" * 32},
        request=SimpleNamespace(pretty_host="app.local", host="app.local", path="/socket"),
        websocket=SimpleNamespace(messages=[frame]),
    )

    _ProxyAddon(service).websocket_message(flow)
    result = service.history.query_websockets(search="hello")

    assert result["total"] == 1
    assert result["items"][0]["host"] == "app.local"
    assert result["items"][0]["direction"] == "Client to server"
    assert result["items"][0]["type"] == "Text"
    assert result["items"][0]["payload"] == '{"action":"hello"}'


def test_https_interception_uses_explicit_local_ca_and_validates_upstream(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    server_cert = tmp_path / "authorized-test-server.pem"
    server_key = tmp_path / "authorized-test-server-key.pem"
    server_cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    server_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    target = ThreadingHTTPServer(("127.0.0.1", 0), LocalTargetHandler)
    target.received = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(server_cert), str(server_key))
    target.socket = context.wrap_socket(target.socket, server_side=True)
    target_worker = threading.Thread(target=target.serve_forever, daemon=True)
    target_worker.start()

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        proxy_port = listener.getsockname()[1]
    service = ProxyService(tmp_path / "proxy-data", upstream_ca_bundle=server_cert)
    service.generate_ca()
    status = service.start({"address": "127.0.0.1", "port": proxy_port, "https_interception": True, "intercept": False})
    assert status["state"] == "running", status
    try:
        client_context = ssl.create_default_context(cafile=str(service.ca_certificate_path()))
        connection = http.client.HTTPSConnection("127.0.0.1", proxy_port, context=client_context, timeout=8)
        connection.set_tunnel("127.0.0.1", target.server_port)
        connection.request("GET", "/secure?check=1")
        response = connection.getresponse()
        body = response.read()
        connection.close()
        assert response.status == 200
        assert json.loads(body)["path"] == "/secure?check=1"
        assert target.received[0]["path"] == "/secure?check=1"
        assert _wait_until(lambda: service.history.stats(0)["responses"] == 1)
        captured = service.history_page({"path": "/secure"})["items"]
        assert len(captured) == 1
        assert captured[0]["scheme"] == "https"
        assert service.history.stats(0)["https"] >= 1
    finally:
        service.stop()
        target.shutdown()
        target.server_close()
        target_worker.join(timeout=3)
