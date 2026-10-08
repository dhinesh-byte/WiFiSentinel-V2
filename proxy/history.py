"""Bounded, in-memory storage and safe rendering for captured proxy traffic."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import json
import mimetypes
import threading
from typing import Any
from urllib.parse import parse_qsl, urlsplit

_TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "image/svg+xml",
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _header_pairs(headers) -> list[list[str]]:
    try:
        return [[str(name), str(value)] for name, value in headers.items(multi=True)]
    except (AttributeError, TypeError):
        return []


def _cookies(value: str) -> list[dict[str, str]]:
    cookies = []
    for cookie in str(value).split(";"):
        name, separator, cookie_value = cookie.strip().partition("=")
        if separator and name:
            cookies.append({"name": name, "value": cookie_value})
    return cookies


def _refresh_search(record: dict[str, Any]) -> None:
    fragments = [record.get("method", ""), record.get("host", ""), record.get("path", ""), record.get("url", "")]
    for key in ("request_headers", "response_headers"):
        fragments.extend(f"{name}: {value}" for name, value in record.get(key, []))
    for key in ("request_body", "response_body"):
        try:
            fragments.append(bytes(record.get(key, b""))[:4096].decode("utf-8", errors="ignore"))
        except (TypeError, ValueError):
            pass
    record["_search_text"] = " ".join(str(fragment) for fragment in fragments if fragment).casefold()


def _body_view(raw: bytes, content_type: str, size: int, truncated: bool, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"kind": "disabled", "text": "Body capture is disabled.", "size": size, "truncated": False}
    if not raw and size == 0:
        return {"kind": "empty", "text": "", "size": 0, "truncated": False}
    normalized_type = content_type.lower().split(";", 1)[0].strip()
    if not any(normalized_type.startswith(prefix) for prefix in _TEXT_TYPES):
        guessed, _ = mimetypes.guess_type("capture." + normalized_type.split("/")[-1]) if "/" in normalized_type else (None, None)
        return {
            "kind": "binary",
            "text": f"Binary content omitted from text view ({content_type or guessed or 'unknown type'}, {size} bytes).",
            "size": size,
            "captured_size": len(raw),
            "truncated": truncated,
        }
    charset = "utf-8"
    for parameter in content_type.split(";")[1:]:
        name, separator, value = parameter.strip().partition("=")
        if separator and name.lower() == "charset":
            charset = value.strip('"\' ') or "utf-8"
            break
    try:
        text = raw.decode(charset, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    raw_text = text
    if normalized_type == "application/json" or normalized_type.endswith("+json"):
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "kind": "text",
        "text": text,
        "raw_text": raw_text,
        "size": size,
        "captured_size": len(raw),
        "truncated": truncated,
    }


class ProxyHistory:
    """Keep a bounded request/response history in process memory only."""

    def __init__(self, max_entries: int = 500, max_body_size: int = 131072) -> None:
        self._lock = threading.RLock()
        self._records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._websocket_records: list[dict[str, Any]] = []
        self._max_entries = max_entries
        self._max_body_size = max_body_size
        self._history_enabled = True
        self._capture_request_body = True
        self._capture_response_body = True
        self._counts = {"requests": 0, "responses": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "https": 0, "errors": 0, "intercepted": 0, "websocket_messages": 0}

    def configure(self, *, max_entries: int, max_body_size: int, history_enabled: bool,
                  capture_request_body: bool, capture_response_body: bool) -> None:
        with self._lock:
            self._max_entries = max_entries
            self._max_body_size = max_body_size
            self._history_enabled = history_enabled
            self._capture_request_body = capture_request_body
            self._capture_response_body = capture_response_body
            self._trim()
            del self._websocket_records[max_entries * 4:]

    @property
    def max_body_size(self) -> int:
        with self._lock:
            return self._max_body_size

    def capture_enabled(self, direction: str) -> bool:
        with self._lock:
            return self._capture_request_body if direction == "request" else self._capture_response_body

    def history_enabled(self) -> bool:
        with self._lock:
            return self._history_enabled

    def create_request(self, flow_id: str, flow, client: str) -> dict[str, Any]:
        request = flow.request
        parsed = urlsplit(request.path)
        record = {
            "id": flow_id,
            "timestamp": datetime.fromtimestamp(request.timestamp_start, timezone.utc).isoformat(timespec="milliseconds") if request.timestamp_start else _timestamp(),
            "method": str(request.method),
            "scheme": str(request.scheme),
            "host": str(request.pretty_host or request.host),
            "port": int(request.port),
            "path": str(request.path),
            "url": str(request.url),
            "query": [[str(key), str(value)] for key, value in parse_qsl(parsed.query, keep_blank_values=True)],
            "protocol": str(request.http_version or "HTTP/1.1"),
            "authority": str(request.host or request.pretty_host or ""),
            "cookies": _cookies(request.headers.get("cookie", "")),
            "request_headers": _header_pairs(request.headers),
            "request_body": bytearray(),
            "request_body_size": 0,
            "request_body_truncated": False,
            "request_body_captured": self.capture_enabled("request"),
            "request_body_content_type": str(request.headers.get("content-type", "")),
            "response_status": None,
            "response_reason": "",
            "response_protocol": "HTTP/1.1",
            "response_headers": [],
            "response_body": bytearray(),
            "response_body_size": 0,
            "response_body_truncated": False,
            "response_body_captured": self.capture_enabled("response"),
            "response_body_content_type": "",
            "response_size": 0,
            "duration_ms": None,
            "client": client,
            "error": None,
            "state": "Request",
            "intercepted": False,
            "modified": False,
            "created_at": _timestamp(),
            "history_enabled_at_capture": self.history_enabled(),
            "_started_epoch": request.timestamp_start or _timestamp_epoch(),
        }
        if str(request.scheme).lower() == "https":
            with self._lock:
                self._counts["https"] += 1
        with self._lock:
            self._counts["requests"] += 1
            _refresh_search(record)
            self._records[flow_id] = record
            self._trim()
            return record

    def add_https_tunnel(self) -> None:
        with self._lock:
            self._counts["https"] += 1

    def create_replay(self, source: dict[str, Any], response_status: int, response_reason: str,
                      response_headers: list[list[str]], response_body: bytes, response_content_type: str) -> dict[str, Any]:
        flow_id = source["id"] + "-replay"
        request = source
        record = {
            "id": flow_id,
            "timestamp": _timestamp(),
            "method": str(request["method"]),
            "scheme": str(request["scheme"]),
            "host": str(request["host"]),
            "port": int(request["port"]),
            "path": str(request["path"]),
            "url": str(request["url"]),
            "query": list(request.get("query", [])),
            "protocol": str(request["protocol"]),
            "authority": str(request["authority"]),
            "cookies": list(request.get("cookies", [])),
            "request_headers": list(request.get("request_headers", [])),
            "request_body": bytearray(request.get("request_body", b"")),
            "request_body_size": int(request.get("request_body_size", 0)),
            "request_body_truncated": bool(request.get("request_body_truncated", False)),
            "request_body_captured": self.capture_enabled("request"),
            "request_body_content_type": str(request.get("request_body_content_type", "")),
            "response_status": int(response_status),
            "response_reason": str(response_reason),
            "response_protocol": "HTTP/1.1",
            "response_headers": list(response_headers),
            "response_body": bytearray(response_body[:self._max_body_size]),
            "response_body_size": len(response_body),
            "response_body_truncated": len(response_body) > self._max_body_size,
            "response_body_captured": self.capture_enabled("response"),
            "response_body_content_type": str(response_content_type),
            "response_size": len(response_body),
            "duration_ms": None,
            "client": str(request.get("client", "replay")),
            "error": None,
            "state": "Replayed",
            "intercepted": False,
            "modified": False,
            "created_at": _timestamp(),
            "history_enabled_at_capture": self.history_enabled(),
            "replayed_from": str(request["id"]),
            "_started_epoch": _timestamp_epoch(),
        }
        with self._lock:
            self._counts["requests"] += 1
            self._counts["responses"] += 1
            self._counts[f"{response_status // 100}xx"] += 1
            _refresh_search(record)
            self._records[flow_id] = record
            self._trim()
        return record

    def capture_chunk(self, flow_id: str, direction: str, chunk: bytes) -> bytes:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None:
                return chunk
            body_key = f"{direction}_body"
            size_key = f"{direction}_body_size"
            trunc_key = f"{direction}_body_truncated"
            captured = record[body_key]
            record[size_key] += len(chunk)
            enabled = record[f"{direction}_body_captured"]
            remaining = self._max_body_size - len(captured) if enabled else 0
            if remaining > 0:
                captured.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                record[trunc_key] = True
            if direction == "response":
                record["response_size"] = record[size_key]
            return chunk

    def update_request(self, flow_id: str, flow) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None:
                return None
            request = flow.request
            record.update({
                "method": str(request.method),
                "scheme": str(request.scheme),
                "host": str(request.pretty_host or request.host),
                "port": int(request.port),
                "path": str(request.path),
                "url": str(request.url),
                "protocol": str(request.http_version or "HTTP/1.1"),
                "authority": str(request.host or request.pretty_host or ""),
                "cookies": _cookies(request.headers.get("cookie", "")),
                "request_headers": _header_pairs(request.headers),
                "request_body_content_type": str(request.headers.get("content-type", "")),
            })
            parsed = urlsplit(request.path)
            record["query"] = [[str(key), str(value)] for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
            raw = request.raw_content
            if raw is not None:
                body = bytes(raw)
                record["request_body_size"] = len(body)
                record["request_body"] = bytearray(body[:self._max_body_size]) if record["request_body_captured"] else bytearray()
                record["request_body_truncated"] = len(body) > self._max_body_size
            _refresh_search(record)
            return record

    def update_response(self, flow_id: str, flow) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None or flow.response is None:
                return None
            response = flow.response
            record.update({
                "response_status": int(response.status_code),
                "response_reason": str(response.reason or ""),
                "response_protocol": str(response.http_version or "HTTP/1.1"),
                "response_headers": _header_pairs(response.headers),
                "response_body_content_type": str(response.headers.get("content-type", "")),
                "state": "Response",
            })
            raw = response.raw_content
            if raw is not None:
                body = bytes(raw)
                record["response_size"] = len(body)
                record["response_body_size"] = len(body)
                record["response_body"] = bytearray(body[:self._max_body_size]) if record["response_body_captured"] else bytearray()
                record["response_body_truncated"] = len(body) > self._max_body_size
            _refresh_search(record)
            request_started = flow.request.timestamp_start
            response_finished = response.timestamp_end or _timestamp_epoch()
            if request_started:
                record["duration_ms"] = max(0, round((response_finished - request_started) * 1000))
            self._counts["responses"] += 1
            status = int(response.status_code)
            bucket = f"{status // 100}xx"
            if bucket in self._counts:
                self._counts[bucket] += 1
            return record

    def update_error(self, flow_id: str, error: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None:
                return None
            record["error"] = str(error)[:500]
            record["state"] = "Dropped" if "killed" in str(error).lower() else "Error"
            record["duration_ms"] = max(0, round((_timestamp_epoch() - record["_started_epoch"]) * 1000)) if "_started_epoch" in record else None
            if record["state"] == "Error":
                self._counts["errors"] += 1
            return record

    def mark_intercepted(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None:
                return None
            record["intercepted"] = True
            record["state"] = "Intercepted"
            self._counts["intercepted"] += 1
            return record

    def resolve_intercept(self, flow_id: str, action: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None:
                return None
            record["intercepted"] = False
            record["state"] = "Dropped" if action == "drop" else "Forwarded"
            return record

    def mark_modified(self, flow_id: str, flow) -> dict[str, Any] | None:
        with self._lock:
            record = self.update_request(flow_id, flow)
            if record is not None:
                record["modified"] = True
                record["state"] = "Modified"
            return record

    def get_internal(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._records.get(flow_id)

    def query(self, *, search: str = "", method: str = "all", status: str = "all",
              content_type: str = "all", host: str = "", path: str = "",
              page: int = 1, page_size: int = 80) -> dict[str, Any]:
        query = search.casefold().strip()
        method_filter = method.upper()
        status_filter = status.lower()
        host_filter = host.casefold().strip()
        path_filter = path.casefold().strip()
        with self._lock:
            values = list(reversed(self._records.values()))
            matching = []
            for item in values:
                if not item.get("history_enabled_at_capture"):
                    continue
                if method_filter not in {"", "ALL"} and item["method"].upper() != method_filter:
                    continue
                code = item.get("response_status")
                if status_filter in {"2xx", "3xx", "4xx", "5xx"} and (code is None or f"{code // 100}xx" != status_filter):
                    continue
                actual_type = str(item.get("response_body_content_type") or item.get("request_body_content_type") or "").casefold()
                if content_type not in {"", "all"} and not _content_type_matches(content_type, actual_type):
                    continue
                if host_filter not in item["host"].casefold() or path_filter not in item["path"].casefold():
                    continue
                searchable = item.get("_search_text", "")
                if query and query not in searchable:
                    continue
                matching.append(_summary(item))
            start = (page - 1) * page_size
            return {"items": matching[start:start + page_size], "total": len(matching), "page": page, "page_size": page_size}

    def detail(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get(flow_id)
            if record is None:
                return None
            return _public_detail(record)

    def increment_response_status(self, code: int) -> None:
        with self._lock:
            bucket = f"{code // 100}xx"
            if bucket in self._counts:
                self._counts[bucket] += 1
            self._counts["responses"] += 1

    def capture_websocket(self, *, request_id: str, host: str, path: str, message) -> dict[str, Any] | None:
        with self._lock:
            if not self._history_enabled:
                return None
            content = bytes(message.content or b"")
            is_text = bool(message.is_text)
            record = {
                "id": f"{request_id}:{len(self._websocket_records) + 1}",
                "request_id": request_id,
                "timestamp": datetime.fromtimestamp(message.timestamp, timezone.utc).isoformat(timespec="milliseconds") if message.timestamp else _timestamp(),
                "host": str(host)[:255],
                "path": str(path)[:2048],
                "direction": "Client to server" if message.from_client else "Server to client",
                "opcode": int(message.type),
                "type": "Text" if is_text else "Binary",
                "size": len(content),
                "payload": message.text[:self._max_body_size] if is_text else f"Binary WebSocket frame ({len(content)} bytes)",
                "truncated": is_text and len(message.text.encode("utf-8")) > self._max_body_size,
                "captured_at": _timestamp(),
            }
            record["_search_text"] = " ".join((record["host"], record["path"], record["direction"], record["type"], record["payload"])).casefold()
            self._websocket_records.insert(0, record)
            del self._websocket_records[self._max_entries * 4:]
            self._counts["websocket_messages"] += 1
            return {key: value for key, value in record.items() if not key.startswith("_")}

    def query_websockets(self, *, search: str = "", page: int = 1, page_size: int = 80) -> dict[str, Any]:
        query = search.casefold().strip()
        with self._lock:
            matching = [
                {key: value for key, value in record.items() if not key.startswith("_")}
                for record in self._websocket_records
                if not query or query in record["_search_text"]
            ]
            start = (page - 1) * page_size
            return {"items": matching[start:start + page_size], "total": len(matching), "page": page, "page_size": page_size}

    def stats(self, pending: int) -> dict[str, int]:
        with self._lock:
            return {**self._counts, "intercept_queue": pending}

    def clear(self, keep_ids: set[str] | None = None) -> None:
        keep_ids = keep_ids or set()
        with self._lock:
            self._records = OrderedDict((key, value) for key, value in self._records.items() if key in keep_ids)
            self._websocket_records.clear()

    def discard(self, flow_id: str) -> None:
        with self._lock:
            self._records.pop(flow_id, None)

    def _trim(self) -> None:
        while len(self._records) > self._max_entries:
            removable = next((key for key, value in self._records.items() if not value.get("intercepted")), None)
            if removable is None:
                break
            del self._records[removable]


def _timestamp_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


def _content_type_matches(selected: str, actual: str) -> bool:
    groups = {
        "html": ("text/html",),
        "json": ("application/json", "+json"),
        "xml": ("application/xml", "text/xml", "+xml"),
        "javascript": ("javascript",),
        "css": ("text/css",),
        "images": ("image/",),
        "other": (),
    }
    if selected == "other":
        return not any(fragment in actual for values in groups.values() if values for fragment in values)
    return any(fragment in actual for fragment in groups.get(selected, ()))


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    content_type = record.get("response_body_content_type") or record.get("request_body_content_type") or ""
    return {
        "id": record["id"],
        "timestamp": record["timestamp"],
        "method": record["method"],
        "scheme": record["scheme"],
        "host": record["host"],
        "port": record["port"],
        "path": record["path"],
        "query": record["query"],
        "status": record["response_status"],
        "content_type": content_type,
        "request_size": record.get("request_body_size", 0),
        "response_size": record.get("response_size", 0),
        "request_body_content_type": record.get("request_body_content_type", ""),
        "response_body_content_type": record.get("response_body_content_type", ""),
        "response_reason": record.get("response_reason", ""),
        "client": record.get("client", ""),
        "duration_ms": record.get("duration_ms"),
        "state": record["state"],
        "intercepted": record["intercepted"],
        "modified": record["modified"],
        "error": record["error"],
    }


def _raw_message(first_line: str, headers: list[list[str]], body: dict[str, Any]) -> str:
    lines = [first_line, *(f"{name}: {value}" for name, value in headers), "", body.get("raw_text", body["text"])]
    if body["kind"] == "binary":
        lines[-1] = f"[{body['text']}]"
    elif body["truncated"]:
        lines[-1] += "\n[Captured body truncated at configured maximum.]"
    return "\r\n".join(lines)


def _public_detail(record: dict[str, Any]) -> dict[str, Any]:
    request_body = _body_view(bytes(record["request_body"]), record["request_body_content_type"],
                              record["request_body_size"], record["request_body_truncated"], record["request_body_captured"])
    response_body = _body_view(bytes(record["response_body"]), record["response_body_content_type"],
                               record["response_body_size"], record["response_body_truncated"], record["response_body_captured"])
    request_target = f"{record['method']} {record['path']} {record['protocol']}"
    status = record.get("response_status")
    response_target = f"{record['response_protocol']} {status or '—'} {record.get('response_reason', '')}".rstrip()
    form_parameters = []
    if "application/x-www-form-urlencoded" in record["request_body_content_type"].lower() and request_body["kind"] == "text":
        form_parameters = [[key, value] for key, value in parse_qsl(request_body["text"], keep_blank_values=True)]
    return {
        **_summary(record),
        "url": record["url"],
        "protocol": record["protocol"],
        "response_protocol": record["response_protocol"],
        "response_http_version": record["response_protocol"],
        "authority": record["authority"],
        "cookies": record["cookies"],
        "http_version": record["protocol"],
        "request_headers": record["request_headers"],
        "response_headers": record["response_headers"],
        "request_body": request_body,
        "response_body": response_body,
        "query": record["query"],
        "form_parameters": form_parameters,
        "client": record["client"],
        "raw_request": _raw_message(request_target, record["request_headers"], request_body),
        "raw_response": _raw_message(response_target, record["response_headers"], response_body),
    }
