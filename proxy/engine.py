"""mitmproxy-backed local HTTP/HTTPS interception engine."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import logging
from pathlib import Path
import re
import ssl
import threading
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from mitmproxy import http as mitmproxy_http
from nmap_live import NmapLiveStream
from .history import ProxyHistory

logger = logging.getLogger("wifi_sentinel.proxy")
_METHOD_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")
_FORBIDDEN_MODIFIED_HEADERS = {"connection", "content-length", "host", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"}


class ProxyConfigurationError(ValueError):
    """A user-supplied Proxy setting is invalid or unsafe."""


class ProxyService:
    """Own the independent proxy listener, event stream, history, and flows."""

    def __init__(self, data_directory: Path, *, upstream_ca_bundle: Path | None = None) -> None:
        self.data_directory = Path(data_directory)
        self.ca_directory = self.data_directory / "mitmproxy"
        self._explicit_ca_marker = self.data_directory / "ca-generated-by-user"
        self._ca_explicit = self._explicit_ca_marker.is_file() and (self.ca_directory / "mitmproxy-ca-cert.pem").is_file()
        if not self._ca_explicit:
            self._discard_unconfirmed_ca()
        self.upstream_ca_bundle = upstream_ca_bundle
        self.history = ProxyHistory()
        self._lock = threading.RLock()
        self._flow_lock = threading.RLock()
        self._state = "stopped"
        self._error: str | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master = None
        self._flows: dict[str, Any] = {}
        self._ephemeral_confdir: tempfile.TemporaryDirectory | None = None
        self._runtime_confdir = self.ca_directory
        self._ready = threading.Event()
        self._pending: dict[str, dict[str, Any]] = {}
        self._settings: dict[str, Any] = {
            "address": "127.0.0.1",
            "port": 8080,
            "intercept": True,
            "https_interception": False,
            "history_enabled": True,
            "max_history_entries": 500,
            "capture_request_body": True,
            "capture_response_body": True,
            "max_body_size": 131072,
        }
        self._scope = {"include": [], "exclude": []}
        self._stream = NmapLiveStream(max_events=4000, max_output_bytes=4 * 1024 * 1024)
        self.history.configure(
            max_entries=self._settings["max_history_entries"],
            max_body_size=self._settings["max_body_size"],
            history_enabled=True,
            capture_request_body=True,
            capture_response_body=True,
        )

    @staticmethod
    def _loopback_address(value: Any) -> str:
        if not isinstance(value, str):
            raise ProxyConfigurationError("Listener address must be a local loopback address.")
        value = value.strip().lower()
        if value == "localhost":
            return "127.0.0.1"
        try:
            address = ipaddress.ip_address(value.strip("[]"))
        except ValueError as exc:
            raise ProxyConfigurationError("Listener address must be 127.0.0.1, ::1, or localhost. The Proxy will not bind to a network interface.") from exc
        if not address.is_loopback:
            raise ProxyConfigurationError("Proxy listeners are restricted to loopback addresses to prevent an open proxy.")
        return address.compressed

    def _validate_settings(self, payload: dict[str, Any], *, starting: bool = False) -> dict[str, Any]:
        updated = dict(self._settings)
        if "address" in payload:
            updated["address"] = self._loopback_address(payload["address"])
        if "port" in payload:
            try:
                port = int(payload["port"])
            except (TypeError, ValueError) as exc:
                raise ProxyConfigurationError("Listener port must be an integer between 1024 and 65535.") from exc
            if not 1024 <= port <= 65535:
                raise ProxyConfigurationError("Listener port must be between 1024 and 65535.")
            updated["port"] = port
        boolean_fields = ("intercept", "https_interception", "history_enabled", "capture_request_body", "capture_response_body")
        for field in boolean_fields:
            if field in payload:
                if not isinstance(payload[field], bool):
                    raise ProxyConfigurationError(f"{field.replace('_', ' ').capitalize()} must be true or false.")
                updated[field] = payload[field]
        integer_bounds = {"max_history_entries": (10, 5000), "max_body_size": (1024, 2 * 1024 * 1024)}
        for field, (minimum, maximum) in integer_bounds.items():
            if field in payload:
                try:
                    value = int(payload[field])
                except (TypeError, ValueError) as exc:
                    raise ProxyConfigurationError(f"{field.replace('_', ' ').capitalize()} must be an integer.") from exc
                if not minimum <= value <= maximum:
                    raise ProxyConfigurationError(f"{field.replace('_', ' ').capitalize()} must be between {minimum} and {maximum}.")
                updated[field] = value
        if not starting and self._state == "running" and (updated["address"], updated["port"]) != (self._settings["address"], self._settings["port"]):
            raise ProxyConfigurationError("Stop the Proxy before changing its listener address or port.")
        return updated

    def settings(self) -> dict[str, Any]:
        with self._lock:
            return {**self._settings}

    def scope(self) -> dict[str, list[dict[str, str]]]:
        with self._lock:
            return {"include": [dict(rule) for rule in self._scope["include"]], "exclude": [dict(rule) for rule in self._scope["exclude"]]}

    def update_scope(self, payload: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
        with self._lock:
            include = self._validate_scope_rules(payload.get("include", []), "include")
            exclude = self._validate_scope_rules(payload.get("exclude", []), "exclude")
            self._scope = {"include": include, "exclude": exclude}
        self._publish("scope", scope=self.scope())
        return self.scope()

    @staticmethod
    def _validate_scope_rules(rules: Any, section: str) -> list[dict[str, str]]:
        if not isinstance(rules, list):
            raise ProxyConfigurationError(f"{section} scope must be a list.")
        validated = []
        for rule in rules:
            if isinstance(rule, str):
                url = rule.strip()
                rule = {"url": url}
            elif not isinstance(rule, dict) or not isinstance(rule.get("url"), str) or not rule["url"].strip():
                raise ProxyConfigurationError(f"Every {section} scope rule requires a URL.")
            url = rule["url"].strip()
            if not url.startswith(("http://", "https://")):
                raise ProxyConfigurationError(f"{section} scope URLs must use HTTP or HTTPS.")
            validated.append({"url": url, "type": str(rule.get("type", "host")), "condition": str(rule.get("condition", "contains"))})
        return validated

    def _scope_allows(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return False
            host = parsed.hostname.lower()
            candidate = f"{parsed.scheme}://{host}{parsed.port and f':{parsed.port}' or ''}{parsed.path}"
        except (ValueError, TypeError):
            return False
        for rule in self._scope["exclude"]:
            if rule["url"].lower() in candidate.lower() or rule["url"].lower() in host:
                return False
        include = self._scope["include"]
        return not include or any(rule["url"].lower() in candidate.lower() or rule["url"].lower() in host for rule in include)

    def target_summary(self) -> dict[str, Any]:
        with self._lock:
            history = list(self.history._records.values())
        issues = [
            {
                "id": record["id"],
                "host": record["host"],
                "path": record["path"],
                "status": record["response_status"],
                "title": record["response_reason"] or record["error"] or "Request failed",
                "timestamp": record["timestamp"],
            }
            for record in history
            if (record.get("response_status") or 0) >= 400 or record.get("error")
        ]
        return {"site_map": self._site_map(history), "issues": issues}

    @staticmethod
    def _site_map(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        hosts: dict[str, set[str]] = {}
        for record in history:
            hosts.setdefault(str(record.get("host", "unknown")), set()).add(str(record.get("path", "/")))
        return [{"host": host, "paths": sorted(paths)} for host, paths in sorted(hosts.items())]

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            updated = self._validate_settings(payload)
            if updated["https_interception"] and not self._ca_explicit:
                raise ProxyConfigurationError("Generate the local CA certificate before enabling HTTPS interception.")
            self._settings = updated
            master = self._master if self._state == "running" else None
            loop = self._loop
            self.history.configure(
                max_entries=updated["max_history_entries"],
                max_body_size=updated["max_body_size"],
                history_enabled=updated["history_enabled"],
                capture_request_body=updated["capture_request_body"],
                capture_response_body=updated["capture_response_body"],
            )
        if master is not None and loop is not None:
            ignore_hosts = [r".*"] if not updated["https_interception"] else []
            try:
                loop.call_soon_threadsafe(lambda: master.options.update(ignore_hosts=ignore_hosts))
            except (RuntimeError, ValueError) as exc:
                raise ProxyConfigurationError(f"Could not apply HTTPS interception setting: {exc}") from exc
        self._publish("settings", settings=self.settings())
        return self.settings()

    def status(self) -> dict[str, Any]:
        with self._lock, self._flow_lock:
            ca_certificate = self.ca_directory / "mitmproxy-ca-cert.pem"
            return {
                "state": self._state,
                "running": self._state == "running",
                "address": self._settings["address"],
                "port": self._settings["port"],
                "listener": f"{self._settings['address']}:{self._settings['port']}" if self._state == "running" else None,
                "error": self._error,
                "settings": {**self._settings},
                "ca_ready": self._ca_explicit and ca_certificate.is_file(),
                "ca_certificate": ca_certificate.name if self._ca_explicit and ca_certificate.is_file() else None,
                "statistics": self.history.stats(len(self._pending)),
            }

    @property
    def event_stream(self) -> NmapLiveStream:
        with self._lock:
            return self._stream

    def _publish(self, event_type: str, **data: Any) -> None:
        with self._lock:
            stream = self._stream
        stream.publish(event_type, **data)

    def generate_ca(self) -> dict[str, Any]:
        with self._lock:
            if self._state in {"starting", "running", "stopping"}:
                raise ProxyConfigurationError("Stop the Proxy before generating its local CA.")
        certificate = self.ca_directory / "mitmproxy-ca-cert.pem"
        from mitmproxy.certs import CertStore
        CertStore.create_store(self.ca_directory, "mitmproxy", 2048, organization="VulnScan Proxy", cn="VulnScan Proxy Local CA")
        self._explicit_ca_marker.parent.mkdir(parents=True, exist_ok=True)
        self._explicit_ca_marker.write_text("Generated by an explicit VulnScan Proxy user action.\n", encoding="ascii")
        self._ca_explicit = True
        self._publish("ca", ready=True)
        return {"ready": True, "certificate": certificate.name}

    def ca_certificate_path(self) -> Path | None:
        path = self.ca_directory / "mitmproxy-ca-cert.pem"
        return path if self._ca_explicit and path.is_file() else None

    def _discard_unconfirmed_ca(self) -> None:
        for pattern in ("mitmproxy-ca*", "mitmproxy-dhparam.pem"):
            for path in self.ca_directory.glob(pattern):
                try:
                    path.unlink()
                except OSError:
                    logger.warning("Could not remove an unconfirmed Proxy CA artifact from the local configuration directory.")

    def start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ProxyConfigurationError("Proxy settings must be a JSON object.")
        with self._lock:
            if self._state in {"starting", "running", "stopping"}:
                raise ProxyConfigurationError("The Proxy is already starting or running.")
            updated = self._validate_settings(payload, starting=True)
            if updated["https_interception"] and not self._ca_explicit:
                raise ProxyConfigurationError("Generate the local CA certificate before starting with HTTPS interception enabled.")
            self._settings = updated
            self.history.configure(
                max_entries=updated["max_history_entries"],
                max_body_size=updated["max_body_size"],
                history_enabled=updated["history_enabled"],
                capture_request_body=updated["capture_request_body"],
                capture_response_body=updated["capture_response_body"],
            )
            self._state = "starting"
            self._error = None
            self._ready = threading.Event()
            self._stream = NmapLiveStream(max_events=4000, max_output_bytes=4 * 1024 * 1024)
            self._pending.clear()
            if self._ca_explicit:
                self._runtime_confdir = self.ca_directory
            else:
                self._ephemeral_confdir = tempfile.TemporaryDirectory(prefix="vulnscan-proxy-")
                self._runtime_confdir = Path(self._ephemeral_confdir.name)
        self._publish("status", state="starting")
        self._thread = threading.Thread(target=self._run_engine, name="vulnscan-proxy", daemon=True)
        self._thread.start()
        if not self._ready.wait(15):
            with self._lock:
                if self._state == "starting":
                    self._state = "error"
                    self._error = "Proxy startup timed out before the listener became ready."
            self._publish("status", state="error", error=self._error)
        return self.status()

    def _run_engine(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            settings = self.settings()
            options = Options(
                listen_host=settings["address"],
                listen_port=settings["port"],
                confdir=str(self._runtime_confdir),
                mode=["regular"],
                ignore_hosts=[] if settings["https_interception"] else [r".*"],
                ssl_insecure=False,
            )
            if self.upstream_ca_bundle is not None:
                options.update(ssl_verify_upstream_trusted_ca=str(self.upstream_ca_bundle))
            master = DumpMaster(options, loop=loop, with_termlog=False, with_dumper=False)
            self._master = master
            master.addons.add(_ProxyAddon(self))
            loop.run_until_complete(master.run())
        except Exception as exc:
            self._set_error(str(exc))
        finally:
            try:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
            except (RuntimeError, asyncio.CancelledError):
                pass
            with self._lock:
                if self._state == "running":
                    self._state = "stopped"
                self._master = None
                self._loop = None
                if self._state in {"starting", "stopping"}:
                    self._state = "stopped"
                self._ready.set()
                state = self._state
                ephemeral_confdir = self._ephemeral_confdir
                self._ephemeral_confdir = None
                self._runtime_confdir = self.ca_directory
            if ephemeral_confdir is not None:
                ephemeral_confdir.cleanup()
            self._publish("status", state=state)

    def _on_running(self) -> None:
        with self._lock:
            self._state = "running"
            self._error = None
            self._ready.set()
        self._publish("status", state="running", listener=self.status()["listener"])

    def _set_error(self, message: str) -> None:
        with self._lock:
            self._state = "error"
            self._error = str(message)[:1000]
            self._ready.set()
        logger.warning("Proxy startup/runtime error: %s", str(message)[:300])
        self._publish("status", state="error", error=self._error)

    def stop(self) -> dict[str, Any]:
        with self._lock:
            if self._state not in {"running", "starting"}:
                return self.status()
            self._state = "stopping"
            loop = self._loop
            master = self._master
            thread = self._thread
        self._publish("status", state="stopping")
        if loop is not None and master is not None and loop.is_running():
            loop.call_soon_threadsafe(master.shutdown)
        if thread is not None:
            thread.join(timeout=15)
        with self._lock:
            if self._state == "stopping":
                self._state = "error"
                self._error = "Proxy shutdown timed out; the listener may still be active."
            state = self._state
        if state == "stopped" and not self._ca_explicit:
            self._discard_unconfirmed_ca()
        if state == "stopped":
            self._publish("proxy_end", state="stopped")
        return self.status()

    def pending(self) -> list[dict[str, Any]]:
        with self._flow_lock:
            identifiers = list(self._pending)
        return [detail for identifier in identifiers if (detail := self.history.detail(identifier)) is not None]

    def resolve_intercept(self, flow_id: str, action: str, modified: dict[str, Any] | None = None) -> dict[str, Any]:
        if action not in {"forward", "drop"}:
            raise ProxyConfigurationError("Intercept action must be Forward or Drop.")
        with self._flow_lock:
            pending = self._pending.get(flow_id)
        if pending is None:
            raise ProxyConfigurationError("The intercepted request is no longer waiting.")
        flow = pending["flow"]
        if action == "forward" and modified is not None:
            self._apply_modified_request(flow_id, flow, modified, pending)
        loop = self._loop
        if loop is None or not loop.is_running():
            raise ProxyConfigurationError("The Proxy listener is not running.")
        completed = threading.Event()
        result: dict[str, Any] = {}

        def resolve() -> None:
            try:
                if action == "drop":
                    self.history.resolve_intercept(flow_id, "drop")
                    flow.metadata["vulnscan_dropped"] = True
                    flow.resume()
                    flow.kill()
                else:
                    self.history.resolve_intercept(flow_id, "forward")
                    flow.resume()
                result["record"] = self.history.detail(flow_id)
                with self._flow_lock:
                    self._pending.pop(flow_id, None)
                    self._flows.pop(flow_id, None)
                self._publish("intercept", action=action, request_id=flow_id)
            except Exception as exc:
                result["error"] = str(exc)
            finally:
                completed.set()

        loop.call_soon_threadsafe(resolve)
        if not completed.wait(5):
            raise ProxyConfigurationError("The intercepted request could not be resumed in time.")
        if "error" in result:
            raise ProxyConfigurationError(result["error"])
        return result["record"]

    def _apply_modified_request(self, flow_id: str, flow, modified: dict[str, Any], pending: dict[str, Any]) -> None:
        if pending.get("headers_only"):
            raise ProxyConfigurationError("This request body exceeded the configured capture limit. It can be forwarded or dropped, but not edited.")
        if not isinstance(modified, dict):
            raise ProxyConfigurationError("Modified request must be a JSON object.")
        method = modified.get("method", flow.request.method)
        url = modified.get("url", flow.request.url)
        headers = modified.get("headers", {})
        body = modified.get("body", "")
        if not isinstance(method, str) or not _METHOD_RE.fullmatch(method):
            raise ProxyConfigurationError("HTTP method is invalid.")
        if not isinstance(url, str) or len(url) > 4096:
            raise ProxyConfigurationError("Request URL is invalid.")
        original = urlsplit(flow.request.url)
        replacement = urlsplit(url)
        if replacement.scheme not in {"http", "https"} or not replacement.hostname or replacement.username or replacement.password or replacement.fragment:
            raise ProxyConfigurationError("Modified URL must be an HTTP or HTTPS URL without credentials or a fragment.")
        original_port = original.port or (443 if original.scheme == "https" else 80)
        replacement_port = replacement.port or (443 if replacement.scheme == "https" else 80)
        if (original.scheme.lower(), original.hostname.lower(), original_port) != (replacement.scheme.lower(), replacement.hostname.lower(), replacement_port):
            raise ProxyConfigurationError("Request editing cannot change the captured destination origin.")
        if not self._scope_allows(url):
            raise ProxyConfigurationError("The edited request URL is outside the authorized target scope.")
        if not isinstance(headers, dict) or len(headers) > 100:
            raise ProxyConfigurationError("Headers must be a JSON object with at most 100 entries.")
        clean_headers = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name):
                raise ProxyConfigurationError("A modified header name is invalid.")
            if name.lower() in _FORBIDDEN_MODIFIED_HEADERS:
                continue
            if not isinstance(value, str) or len(value) > 8192 or "\r" in value or "\n" in value:
                raise ProxyConfigurationError("A modified header value is invalid.")
            clean_headers[name] = value
        if not isinstance(body, str) or len(body.encode("utf-8")) > self.history.max_body_size:
            raise ProxyConfigurationError("Modified request body exceeds the configured body limit.")
        from mitmproxy.http import Headers
        flow.request.method = method.upper()
        flow.request.url = url
        flow.request.headers = Headers(**clean_headers)
        flow.request.content = body.encode("utf-8")
        flow.request.headers["content-length"] = str(len(body.encode("utf-8")))
        self.history.mark_modified(flow_id, flow)
        self._publish("request", request=self.history.detail(flow_id))

    def replay(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ProxyConfigurationError("Replay request must be a JSON object.")
        source_id = payload.get("source_id")
        source = self.history.get_internal(source_id) if isinstance(source_id, str) else None
        if source is None:
            raise ProxyConfigurationError("Select a captured request before replaying it.")
        settings = self.settings()
        if self.status()["state"] != "running":
            raise ProxyConfigurationError("Start the Proxy before sending a replay request.")
        method = payload.get("method", source["method"])
        url = payload.get("url", source["url"])
        headers = payload.get("headers", {})
        body = payload.get("body", "")
        if not isinstance(method, str) or not _METHOD_RE.fullmatch(method):
            raise ProxyConfigurationError("Replay method is invalid.")
        if not isinstance(url, str) or len(url) > 4096:
            raise ProxyConfigurationError("Replay URL is invalid.")
        original = urlsplit(source["url"])
        replacement = urlsplit(url)
        if replacement.scheme not in {"http", "https"} or not replacement.hostname or replacement.username or replacement.password or replacement.fragment:
            raise ProxyConfigurationError("Replay URL must be an HTTP or HTTPS URL without credentials or a fragment.")
        original_port = original.port or (443 if original.scheme == "https" else 80)
        replacement_port = replacement.port or (443 if replacement.scheme == "https" else 80)
        if (replacement.scheme.lower(), (replacement.hostname or "").lower(), replacement_port) != (original.scheme.lower(), original.hostname.lower(), original_port):
            raise ProxyConfigurationError("Replay stays on the captured HTTP or HTTPS origin; change only its path, query, method, headers, or body.")
        if not self._scope_allows(url):
            raise ProxyConfigurationError("The replay URL is outside the authorized target scope.")
        if not isinstance(headers, dict) or len(headers) > 100:
            raise ProxyConfigurationError("Replay headers must be a JSON object with at most 100 entries.")
        for name, value in headers.items():
            if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name) or not isinstance(value, str) or len(value) > 8192 or "\r" in value or "\n" in value:
                raise ProxyConfigurationError("Replay headers contain an invalid name or value.")
        if not isinstance(body, str) or len(body.encode("utf-8")) > settings["max_body_size"]:
            raise ProxyConfigurationError("Replay body exceeds the configured body limit.")
        target_host = replacement.hostname
        target_port = replacement_port
        path = replacement.path or "/"
        if replacement.query:
            path += "?" + replacement.query
        clean_headers = {
            name: value for name, value in headers.items()
            if name.lower() not in _FORBIDDEN_MODIFIED_HEADERS
        }
        request_body = body.encode("utf-8") if body else None
        if replacement.scheme == "https":
            if settings["https_interception"]:
                certificate = self.ca_certificate_path()
                if certificate is None:
                    raise ProxyConfigurationError("Generate the local CA before replaying HTTPS traffic with interception enabled.")
                context = ssl.create_default_context(cafile=str(certificate))
            elif self.upstream_ca_bundle is not None:
                context = ssl.create_default_context(cafile=str(self.upstream_ca_bundle))
            else:
                context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(target_host, target_port, context=context, timeout=30)
        else:
            connection = http.client.HTTPConnection(target_host, target_port, timeout=30)
        replay_started = time.monotonic()
        try:
            connection.request(method.upper(), path, body=request_body, headers=clean_headers)
            response = connection.getresponse()
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise ProxyConfigurationError(f"Replay failed: {exc}") from exc
        try:
            response_body = response.read(settings["max_body_size"] + 1)
            truncated = len(response_body) > settings["max_body_size"]
            response_body = response_body[:settings["max_body_size"]]
            elapsed_ms = max(0, round((time.monotonic() - replay_started) * 1000))
            response_headers = [[str(name), str(value)] for name, value in response.headers.items()]
            content_type = response.headers.get("Content-Type", "")
            replay_record = self.history.create_replay(
                source,
                response.status,
                str(response.reason or ""),
                response_headers,
                response_body,
                content_type,
            )
            from .history import _body_view
            body_view = _body_view(response_body, content_type, len(response_body), truncated, True)
            self._publish("request", request=self.history.detail(replay_record["id"]))
            return {
                "status": int(response.status),
                "reason": str(response.reason or ""),
                "headers": response_headers,
                "body": body_view,
                "url": url,
                "elapsed_ms": elapsed_ms,
            }
        finally:
            response.close()
            connection.close()

    def history_page(self, filters: dict[str, Any]) -> dict[str, Any]:
        try:
            page = max(1, min(100000, int(filters.get("page", 1))))
            page_size = max(10, min(200, int(filters.get("page_size", 80))))
        except (TypeError, ValueError):
            page, page_size = 1, 80
        return self.history.query(
            search=str(filters.get("q", ""))[:200],
            method=str(filters.get("method", "all"))[:16],
            status=str(filters.get("status", "all"))[:8],
            content_type=str(filters.get("content_type", "all"))[:32],
            host=str(filters.get("host", ""))[:200],
            path=str(filters.get("path", ""))[:500],
            page=page,
            page_size=page_size,
        )

    def clear_history(self) -> None:
        with self._flow_lock:
            keep_ids = set(self._pending)
        self.history.clear(keep_ids)
        self._publish("history_cleared")

    def _ensure_record(self, flow) -> str:
        flow_id = flow.metadata.get("vulnscan_request_id")
        if flow_id:
            return flow_id
        flow_id = uuid4().hex
        flow.metadata["vulnscan_request_id"] = flow_id
        peer = getattr(flow.client_conn, "peername", None)
        client = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) and len(peer) >= 2 else "Unknown client"
        self.history.create_request(flow_id, flow, client)
        return flow_id

    def _capture_chunk(self, flow_id: str, direction: str, chunk: bytes) -> bytes:
        return self.history.capture_chunk(flow_id, direction, chunk)

    def _queue_flow(self, flow, flow_id: str, headers_only: bool) -> None:
        flow.intercept()
        self.history.mark_intercepted(flow_id)
        with self._flow_lock:
            self._pending[flow_id] = {"flow": flow, "headers_only": headers_only}
        detail = self.history.detail(flow_id)
        self._publish("intercept", action="queued", request=detail, headers_only=headers_only)

    def _finish_pending(self, flow_id: str) -> None:
        with self._flow_lock:
            self._pending.pop(flow_id, None)
        detail = self.history.detail(flow_id)
        if detail is not None:
            self._publish("request", request=detail)

    def _finish_flow(self, flow_id: str) -> None:
        with self._flow_lock:
            self._flows.pop(flow_id, None)
        record = self.history.get_internal(flow_id)
        if record is not None and not record.get("history_enabled_at_capture"):
            self.history.discard(flow_id)


class _ProxyAddon:
    """Translate real mitmproxy flow hooks to VulnScan Proxy state."""

    def __init__(self, service: ProxyService) -> None:
        self.service = service

    def running(self) -> None:
        self.service._on_running()

    async def requestheaders(self, flow) -> None:
        request_url = str(flow.request.url)
        if not self.service._scope_allows(request_url):
            flow.metadata["vulnscan_scope_rejected"] = True
            flow.response = mitmproxy_http.Response.make(
                status_code=502,
                content=f"Request outside the authorized target scope: {request_url}\n",
                headers={"content-type": "text/plain; charset=utf-8"},
            )
            return
        flow_id = self.service._ensure_record(flow)
        length_value = flow.request.headers.get("content-length")
        try:
            content_length = int(length_value) if length_value is not None else None
        except ValueError:
            content_length = None
        transfer_encoding = str(flow.request.headers.get("transfer-encoding", "")).lower()
        has_unknown_body = content_length is None and "chunked" in transfer_encoding
        oversized = content_length is not None and content_length > self.service.history.max_body_size
        no_capture_stream = not self.service.history.capture_enabled("request") and not self.service.settings()["intercept"]
        if oversized or has_unknown_body or no_capture_stream:
            if content_length != 0:
                flow.request.stream = lambda chunk, identity=flow_id: self.service._capture_chunk(identity, "request", chunk)
                flow.metadata["vulnscan_request_streamed"] = True
        if (oversized or has_unknown_body) and self.service.settings()["intercept"]:
            flow.metadata["vulnscan_paused_at_headers"] = True
            self.service._queue_flow(flow, flow_id, headers_only=True)
            await flow.wait_for_resume()
            self.service._finish_pending(flow_id)

    async def request(self, flow) -> None:
        if flow.metadata.get("vulnscan_scope_rejected"):
            return
        flow_id = self.service._ensure_record(flow)
        self.service.history.update_request(flow_id, flow)
        self.service._publish("request", request=self.service.history.detail(flow_id))
        if flow.metadata.get("vulnscan_paused_at_headers"):
            return
        if self.service.settings()["intercept"]:
            self.service._queue_flow(flow, flow_id, headers_only=False)
            await flow.wait_for_resume()
            self.service._finish_pending(flow_id)

    def responseheaders(self, flow) -> None:
        if flow.metadata.get("vulnscan_scope_rejected"):
            return
        flow_id = self.service._ensure_record(flow)
        if flow.response is None:
            return
        response = flow.response
        record = self.service.history.get_internal(flow_id)
        if record is not None:
            record.update({
                "response_status": int(response.status_code),
                "response_reason": str(response.reason or ""),
                "response_headers": [[str(name), str(value)] for name, value in response.headers.items(multi=True)],
                "response_body_content_type": str(response.headers.get("content-type", "")),
            })
        length_value = response.headers.get("content-length")
        try:
            content_length = int(length_value) if length_value is not None else None
        except ValueError:
            content_length = None
        transfer_encoding = str(response.headers.get("transfer-encoding", "")).lower()
        bodyless = str(flow.request.method).upper() == "HEAD" or response.status_code in {204, 304}
        oversized = content_length is not None and content_length > self.service.history.max_body_size
        unknown_body = content_length is None and not bodyless
        if not bodyless and (oversized or "chunked" in transfer_encoding or unknown_body or not self.service.history.capture_enabled("response")):
            response.stream = lambda chunk, identity=flow_id: self.service._capture_chunk(identity, "response", chunk)
            flow.metadata["vulnscan_response_streamed"] = True

    def response(self, flow) -> None:
        if flow.metadata.get("vulnscan_scope_rejected"):
            return
        flow_id = self.service._ensure_record(flow)
        record = self.service.history.update_response(flow_id, flow)
        if record is not None:
            self.service._publish("response", request=self.service.history.detail(flow_id))
        self.service._finish_flow(flow_id)

    def error(self, flow) -> None:
        flow_id = flow.metadata.get("vulnscan_request_id")
        if not flow_id:
            return
        message = str(flow.error.msg if flow.error else "Proxy flow failed")
        record = self.service.history.update_error(flow_id, message)
        self.service._finish_pending(flow_id)
        if record is not None:
            self.service._publish("response", request=self.service.history.detail(flow_id))
        self.service._finish_flow(flow_id)

    def http_connected(self, flow) -> None:
        if not self.service.settings()["https_interception"]:
            self.service.history.add_https_tunnel()
            self.service._publish("statistics", statistics=self.service.history.stats(len(self.service._pending)))

    def http_connect_error(self, flow) -> None:
        self.service.history.increment_response_status(502)
        self.service._publish("statistics", statistics=self.service.history.stats(len(self.service._pending)))

    def websocket_message(self, flow) -> None:
        if flow.websocket is None or not flow.websocket.messages:
            return
        flow_id = self.service._ensure_record(flow)
        message = self.service.history.capture_websocket(
            request_id=flow_id,
            host=str(flow.request.pretty_host or flow.request.host),
            path=str(flow.request.path),
            message=flow.websocket.messages[-1],
        )
        if message is not None:
            self.service._publish("websocket", message=message)
