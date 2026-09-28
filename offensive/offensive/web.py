"""Non-invasive HTTP and TLS observations for authorized discovered services."""

from __future__ import annotations

import http.client
import ipaddress
import logging
import re
import socket
import ssl
import time
from collections.abc import Mapping
from typing import Any


logger = logging.getLogger(__name__)

_WEB_NAMES = {"http", "https", "http-proxy", "https-alt", "ssl/http"}
_HTTP_PORTS = {80, 8000, 8080}
_HTTPS_PORTS = {443, 8443}
_HEADER_NAMES = (
    "server",
    "x-powered-by",
    "location",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


class WebTLSAssessment:
    """Collect basic HTTP response and TLS handshake facts without crawling."""

    def __init__(self, timeout: float = 4.0, max_services_per_host: int = 8) -> None:
        self.timeout = max(1.0, min(timeout, 10.0))
        self.max_services_per_host = max(1, min(max_services_per_host, 16))

    def assess(self, enumeration_results: Mapping[str, Any]) -> dict[str, Any]:
        """Inspect enumerated HTTP(S) endpoints using a single HEAD request each."""
        if not isinstance(enumeration_results, Mapping):
            return {
                "status": "error",
                "services": [],
                "errors": ["Enumeration results must be a mapping."],
                "limitations": [],
            }

        errors = self._strings(enumeration_results.get("errors"))
        hosts_value = enumeration_results.get("hosts")
        if "hosts" in enumeration_results:
            if not isinstance(hosts_value, list):
                return {
                    "status": "incomplete",
                    "services": [],
                    "errors": [*errors, "Enumeration host list was malformed."],
                    "limitations": ["Web/TLS checks could not be matched to host records."],
                }
            hosts = hosts_value
        else:
            hosts = [enumeration_results]

        observations: list[dict[str, Any]] = []
        incomplete = enumeration_results.get("status") not in {"completed", "partial"}
        limitations: list[str] = []
        for host in hosts:
            if not isinstance(host, Mapping):
                errors.append("Malformed host result skipped during web/TLS checks.")
                incomplete = True
                continue
            host_status = self._text(host.get("status")).lower()
            if host_status not in {"completed", "partial"}:
                if host_status in {"failed", "timeout", "error"}:
                    errors.extend(self._strings(host.get("errors")))
                incomplete = True
                continue

            target = self._text(host.get("ip")) or self._text(host.get("target"))
            ports = host.get("ports")
            if not target or not isinstance(ports, list):
                errors.append("Host target or port list was missing for web/TLS checks.")
                incomplete = True
                continue
            try:
                target = str(ipaddress.ip_address(target))
            except ValueError:
                errors.append("Invalid host IP skipped during web/TLS checks.")
                incomplete = True
                continue
            server_name = self._server_name(host.get("hostname"), target)

            inspected = 0
            for entry in ports:
                if not isinstance(entry, Mapping) or self._text(entry.get("state")).lower() != "open":
                    continue
                protocol = self._text(entry.get("protocol")).lower()
                if protocol != "tcp" or not self._is_web_service(entry):
                    continue
                if self._port(entry.get("port")) is None:
                    errors.append("Web/TLS endpoint with an invalid port was skipped.")
                    incomplete = True
                    continue
                if inspected >= self.max_services_per_host:
                    limitations.append(
                        f"Web/TLS checks for {target} were capped at {self.max_services_per_host} endpoints."
                    )
                    break
                inspected += 1
                observation = self._inspect_service(target, entry, server_name)
                observations.append(observation)
                if observation["status"] != "completed":
                    incomplete = True
                    errors.extend(observation["errors"])

        if not observations:
            limitations.append("No enumerated HTTP or HTTPS service was available for web/TLS checks.")
        status = "incomplete" if incomplete else "completed"
        return {
            "status": status,
            "services": observations,
            "errors": self._unique(errors),
            "limitations": self._unique(limitations),
            "method": "One HTTP HEAD request per selected endpoint; TLS handshake only for HTTPS.",
        }

    def _inspect_service(
        self,
        target: str,
        entry: Mapping[str, Any],
        server_name: str | None = None,
    ) -> dict[str, Any]:
        port = int(entry["port"])
        service_name = self._text(entry.get("service")) or "unknown"
        server_name = server_name or target
        use_tls = self._uses_tls(entry, port)
        observation: dict[str, Any] = {
            "target": target,
            "port": port,
            "protocol": "tcp",
            "service": service_name,
            "transport": "https" if use_tls else "http",
            "status": "failed",
            "http_status": None,
            "redirect_location": None,
            "server_header": None,
            "technology_header": None,
            "response_headers": {},
            "missing_security_headers": [],
            "tls": None,
            "detection_method": "single HTTP HEAD request; TLS handshake for HTTPS",
            "evidence": [],
            "errors": [],
        }

        try:
            if use_tls:
                response, headers, tls_observation = self._https_head(target, port, server_name)
                observation["tls"] = tls_observation
            else:
                response, headers = self._http_head(target, port, server_name)
            observation["http_status"] = response.status
            observation["response_headers"] = headers
            observation["redirect_location"] = headers.get("location")
            observation["server_header"] = headers.get("server")
            observation["technology_header"] = headers.get("x-powered-by")
            relevant_headers = [
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
            ]
            if use_tls:
                relevant_headers.append("strict-transport-security")
            observation["missing_security_headers"] = [
                name for name in relevant_headers if not headers.get(name)
            ]
            observation["evidence"].append(
                f"HEAD / returned HTTP {response.status} from {target}:{port}."
            )
            for name in ("server", "x-powered-by", "location"):
                if headers.get(name):
                    observation["evidence"].append(
                        f"Response header {name}: {headers[name]}"
                    )
            if use_tls and observation["tls"]:
                tls = observation["tls"]
                if tls.get("version"):
                    observation["evidence"].append(
                        f"TLS negotiated {tls['version']} with cipher {tls.get('cipher') or 'unreported'}."
                    )
                if tls.get("certificate_expires"):
                    observation["evidence"].append(
                        f"Peer certificate expiry reported as {tls['certificate_expires']}."
                    )
            if observation["missing_security_headers"]:
                observation["evidence"].append(
                    "The HEAD response did not include: "
                    + ", ".join(observation["missing_security_headers"])
                    + "."
                )
            observation["status"] = "completed"
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            message = f"Web/TLS observation failed for {target}:{port}: {exc}"
            if isinstance(exc, ssl.SSLCertVerificationError):
                observation["tls"] = {
                    "certificate_verified": False,
                    "verification_error": str(exc),
                }
                observation["evidence"].append(
                    f"Standard TLS certificate verification failed: {exc}"
                )
            observation["errors"].append(message)
            logger.info(message)
        return observation

    def _http_head(
        self,
        target: str,
        port: int,
        server_name: str,
    ) -> tuple[Any, dict[str, str]]:
        connection = http.client.HTTPConnection(target, port, timeout=self.timeout)
        try:
            connection.request(
                "HEAD",
                "/",
                headers={
                    "Host": server_name,
                    "User-Agent": "WiFiSentinel-AuthorizedAssessment/2.0",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            return response, self._selected_headers(response.getheaders())
        finally:
            connection.close()

    def _https_head(
        self,
        target: str,
        port: int,
        server_name: str,
    ) -> tuple[Any, dict[str, str], dict[str, Any]]:
        raw_socket = socket.create_connection((target, port), timeout=self.timeout)
        context = ssl.create_default_context()
        try:
            with context.wrap_socket(raw_socket, server_hostname=server_name) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                expiry = certificate.get("notAfter") if certificate else None
                tls_info = {
                    "version": tls_socket.version(),
                    "cipher": cipher[0] if cipher else None,
                    "certificate_expires": expiry,
                    "certificate_days_remaining": self._days_remaining(expiry),
                    "certificate_verified": True,
                }
                request = (
                    f"HEAD / HTTP/1.1\r\nHost: {server_name}\r\n"
                    "User-Agent: WiFiSentinel-AuthorizedAssessment/2.0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                tls_socket.sendall(request)
                response = http.client.HTTPResponse(tls_socket)
                response.begin()
                headers = self._selected_headers(response.getheaders())
                return response, headers, tls_info
        except Exception:
            raw_socket.close()
            raise

    @staticmethod
    def _selected_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
        selected: dict[str, str] = {}
        allowed = set(_HEADER_NAMES)
        for name, value in headers:
            key = name.strip().lower()
            if key in allowed:
                selected[key] = value.strip()
        return selected

    @staticmethod
    def _days_remaining(expiry: str | None) -> int | None:
        if not expiry:
            return None
        try:
            return int((ssl.cert_time_to_seconds(expiry) - time.time()) // 86400)
        except (ValueError, OverflowError):
            return None

    @staticmethod
    def _is_web_service(entry: Mapping[str, Any]) -> bool:
        service = WebTLSAssessment._text(entry.get("service")).lower()
        port = entry.get("port")
        if service in _WEB_NAMES or any(service.startswith(name + "-") for name in _WEB_NAMES):
            return True
        return isinstance(port, int) and port in (_HTTP_PORTS | _HTTPS_PORTS) and service in {"", "unknown", "?"}

    @staticmethod
    def _uses_tls(entry: Mapping[str, Any], port: int) -> bool:
        service = WebTLSAssessment._text(entry.get("service")).lower()
        tunnel = WebTLSAssessment._text(entry.get("tunnel")).lower()
        if service in {"http", "http-proxy"} or service.startswith("http-"):
            return tunnel == "ssl"
        if service in {"https", "https-alt", "ssl/http"} or service.startswith("https-"):
            return True
        return tunnel == "ssl" or port in _HTTPS_PORTS

    @staticmethod
    def _server_name(hostname: Any, target: str) -> str:
        if not isinstance(hostname, str):
            return target
        candidate = hostname.strip().rstrip(".")
        if not candidate or len(candidate) > 253:
            return target
        labels = candidate.split(".")
        if any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            return target
        return candidate

    @staticmethod
    def _text(value: Any) -> str:
        return value.strip() if isinstance(value, str) else ""

    @staticmethod
    def _port(value: Any) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if 1 <= value <= 65535 else None

    @staticmethod
    def _strings(values: Any) -> list[str]:
        if not isinstance(values, (list, tuple)):
            return []
        return [value.strip() for value in values if isinstance(value, str) and value.strip()]

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))
