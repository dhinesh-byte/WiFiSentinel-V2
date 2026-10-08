"""Flask APIs for chat, memory, learning, context, and remediation state."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import hashlib
import logging
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from flask import Blueprint, Response, g, jsonify, request, session
from itsdangerous import BadSignature, URLSafeSerializer

from guidance_authorization import guidance_token_is_valid
from .agent import assessment_context_relevant, build_messages, greeting_reply, missing_finding_reply
from .context import ContextNotFound, build_scan_context, context_summary
from .conversation import append_exchange, new_conversation
from .learning import answer_quiz, learning_paths, start_quiz
from .knowledge import LEARNING_PATHS
from .memory import (
    clear_all,
    clear_conversation,
    clear_learning,
    load_conversation,
    load_memory,
    save_conversation,
    save_memory,
    signing_key,
)
from .provider import ProviderError, create_provider
from .safety import contains_secret, redact_sensitive_text, valid_message
from .schemas import ASSESSMENT_MODULES, MAX_REQUEST_BYTES, REMEDIATION_STATUSES, normalize_profile


logger = logging.getLogger("wifi_sentinel.ai")
_RATE_LOCK = threading.Lock()
_RATE_REQUESTS: dict[str, list[float]] = {}
_EPHEMERAL_QUIZZES: dict[str, dict] = {}
_EPHEMERAL_LOCK = threading.Lock()
_FRESH_FINDING_ANALYSIS = re.compile(
    r"^\s*(?:please\s+)?(?:analy[sz]e|assess|review|prioriti[sz]e|evaluate)\b",
    re.IGNORECASE,
)
_SENSITIVE_NAME = re.compile(r"(?:authorization|cookie|password|passphrase|secret|token|api[-_]?key|credential)", re.IGNORECASE)


def _friendly_provider_error(error: Exception) -> str:
    if isinstance(error, ProviderError):
        return str(error)
    return "AI service is currently unavailable. VulnScan scanning and analysis remain available."


def _redact_proxy_body(body: dict, content_type: str) -> dict:
    if not isinstance(body, dict):
        return {"kind": "unknown", "text": "Body unavailable."}
    result = {key: body.get(key) for key in ("kind", "size", "captured_size", "truncated") if key in body}
    text = body.get("text")
    if body.get("kind") != "text" or not isinstance(text, str):
        result["text"] = str(text or "")[:3000]
        return result
    text = text[:5000]
    if "json" in content_type.lower():
        try:
            parsed = json.loads(text)

            def redact_values(value):
                if isinstance(value, dict):
                    return {
                        key: "[REDACTED]" if _SENSITIVE_NAME.search(str(key)) else redact_values(item)
                        for key, item in value.items()
                    }
                if isinstance(value, list):
                    return [redact_values(item) for item in value[:100]]
                return redact_sensitive_text(value) if isinstance(value, str) else value

            text = json.dumps(redact_values(parsed), ensure_ascii=True, separators=(",", ":"))
        except (json.JSONDecodeError, TypeError):
            text = redact_sensitive_text(text)
    else:
        text = redact_sensitive_text(text)
    result["text"] = text[:5000]
    return result


def _safe_proxy_context(record: dict) -> dict:
    request_headers = record.get("request_headers", [])
    response_headers = record.get("response_headers", [])

    def safe_headers(headers):
        return [
            [str(name)[:128], redact_sensitive_text(str(value))[:1000]]
            for name, value in headers[:100]
            if isinstance(name, str) and isinstance(value, str) and not _SENSITIVE_NAME.search(name)
        ] if isinstance(headers, list) else []

    url = str(record.get("url", ""))[:4096]
    def safe_query(query: str) -> str:
        return urlencode([
            (key, "[REDACTED]" if _SENSITIVE_NAME.search(key) else redact_sensitive_text(value))
            for key, value in parse_qsl(query, keep_blank_values=True)
        ])

    try:
        parts = urlsplit(url)
        sanitized_query = safe_query(parts.query)
        safe_url = urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, sanitized_query, ""))
    except ValueError:
        safe_url = "[unavailable]"
        sanitized_query = ""
    raw_path = str(record.get("path", ""))[:2000]
    path_parts = urlsplit(raw_path)
    safe_path = urlunsplit(("", "", path_parts.path, safe_query(path_parts.query), ""))
    request_type = next((value for name, value in request_headers if name.lower() == "content-type"), "") if isinstance(request_headers, list) else ""
    response_type = str(record.get("content_type", ""))
    request_body = _redact_proxy_body(record.get("request_body", {}), request_type)
    response_body = _redact_proxy_body(record.get("response_body", {}), response_type)
    query = [
        [str(key)[:200], "[REDACTED]" if _SENSITIVE_NAME.search(str(key)) else redact_sensitive_text(str(value))[:1000]]
        for key, value in record.get("query", [])[:100]
    ] if isinstance(record.get("query"), list) else []
    return {
        "observed_request": {
            "method": str(record.get("method", ""))[:32],
            "url": safe_url,
            "host": str(record.get("host", ""))[:255],
            "port": record.get("port"),
            "path": safe_path,
            "http_version": str(record.get("http_version", ""))[:32],
            "headers": safe_headers(request_headers),
            "query": query,
            "body": request_body,
        },
        "observed_response": {
            "status": record.get("status"),
            "reason": str(record.get("response_reason", ""))[:128],
            "headers": safe_headers(response_headers),
            "body": response_body,
            "error": redact_sensitive_text(str(record.get("error") or ""))[:500],
        },
    }


def _rate_allowed(owner: str) -> bool:
    now = time.monotonic()
    key = hashlib.sha256(owner.encode("utf-8")).hexdigest()
    with _RATE_LOCK:
        recent = [stamp for stamp in _RATE_REQUESTS.get(key, []) if now - stamp < 60]
        if len(recent) >= 30:
            _RATE_REQUESTS[key] = recent
            return False
        recent.append(now)
        _RATE_REQUESTS[key] = recent
    return True


def register_ai_routes(app, project_root: Path, defensive_dir: Path, offensive_dir: Path, history_loader, proxy_context_loader=None):
    blueprint = Blueprint("wifi_sentinel_ai", __name__)
    ai_data_dir = project_root / "data" / "ai"
    owner_signer = URLSafeSerializer(signing_key(ai_data_dir), salt="wifi-sentinel-ai-owner")

    def owner_id():
        if session.get("_authenticated") is True:
            return "operator:" + os.environ.get("WIFI_SENTINEL_USERNAME", "configured-operator")
        cookie_value = request.cookies.get("wifi_sentinel_ai_owner", "")
        try:
            value = owner_signer.loads(cookie_value) if cookie_value else None
        except BadSignature:
            value = None
        if not isinstance(value, str) or len(value) < 32:
            value = session.get("_ai_owner")
        if not isinstance(value, str) or len(value) < 32:
            value = str(uuid4())
        session["_ai_owner"] = value
        g.ai_owner_cookie = owner_signer.dumps(value)
        return value

    @blueprint.after_request
    def persist_ai_owner(response):
        cookie_value = getattr(g, "ai_owner_cookie", None)
        if cookie_value:
            response.set_cookie(
                "wifi_sentinel_ai_owner",
                cookie_value,
                max_age=31536000,
                httponly=True,
                secure=app.config.get("SESSION_COOKIE_SECURE", False),
                samesite="Strict",
                path="/",
            )
        return response

    def request_payload():
        if request.content_length is not None and request.content_length > MAX_REQUEST_BYTES:
            return None, (jsonify({"success": False, "error": "AI requests are limited to 16 KB."}), 413)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return None, (jsonify({"success": False, "error": "A JSON request body is required."}), 400)
        return payload, None

    def prepare(payload, owner):
        message = redact_sensitive_text(valid_message(payload.get("message")))
        scan_id = payload.get("scan_id") or None
        proxy_request_id = payload.get("proxy_request_id") or None
        if proxy_request_id is not None and (
            not isinstance(proxy_request_id, str) or not re.fullmatch(r"[0-9a-f]{32}", proxy_request_id)
        ):
            raise ValueError("Captured Proxy request ID is invalid.")
        if proxy_request_id and scan_id:
            raise ValueError("Select either a saved scan or one captured Proxy request, not both.")
        proxy_record = proxy_context_loader(proxy_request_id) if proxy_request_id and proxy_context_loader else None
        if proxy_request_id and not isinstance(proxy_record, dict):
            raise ValueError("The selected Proxy capture is unavailable. Select it again from Proxy history.")
        proxy_context = _safe_proxy_context(proxy_record) if proxy_record else None
        module = payload.get("module") or "defensive"
        if not isinstance(module, str) or module.lower() not in ASSESSMENT_MODULES:
            raise ValueError("Assessment module must be defensive or offensive.")
        module = module.lower()
        host_id = payload.get("host_id") or None
        finding_id = payload.get("finding_id") or None
        service_id = payload.get("service_id") or None
        compare_scan_id = payload.get("compare_scan_id") or None
        device_os = payload.get("device_os") or ""
        if not isinstance(device_os, str) or device_os not in {"", "windows", "linux", "macos", "network_device"}:
            raise ValueError("Select a supported OS or leave it unselected.")
        guidance_token = payload.get("guidance_authorization_token") or None
        if guidance_token is not None and (
            not isinstance(guidance_token, str) or len(guidance_token) > 128
        ):
            raise ValueError("Guidance authorization token is invalid.")
        for field, value in (("scan_id", scan_id), ("host_id", host_id), ("finding_id", finding_id), ("service_id", service_id), ("compare_scan_id", compare_scan_id)):
            if value is not None and (not isinstance(value, str) or len(value) > 300):
                raise ValueError(f"{field} must be a short text identifier.")
        if not scan_id and any((host_id, finding_id, service_id, compare_scan_id)):
            raise ValueError("Select a saved assessment before selecting its host, service, or finding.")

        conversation_id = payload.get("conversation_id") or None
        if conversation_id is not None and (not isinstance(conversation_id, str) or len(conversation_id) > 80):
            raise ValueError("Conversation ID is invalid.")
        try:
            conversation = load_conversation(ai_data_dir, owner, conversation_id)
        except ValueError:
            conversation = None
        if conversation is None:
            conversation = new_conversation(module, scan_id, host_id, finding_id)

        greeting = greeting_reply(message)
        context = {}
        context_reply = None
        if scan_id and not greeting:
            candidate_context = build_scan_context(
                module, scan_id, host_id, finding_id, service_id, compare_scan_id,
                defensive_dir, offensive_dir, history_loader(),
            )
            if device_os:
                selected_host = candidate_context.get("selected_host")
                if isinstance(selected_host, dict):
                    selected_host["operator_confirmed_os"] = device_os
                    selected_host["operator_os_source"] = "User-confirmed; not detected by Nmap"
            has_guidance_authorization = (
                module == "offensive"
                and scan_id is not None
                and finding_id is not None
                and guidance_token_is_valid(guidance_token, scan_id, finding_id)
            )
            if assessment_context_relevant(message, candidate_context, conversation) or has_guidance_authorization:
                context = candidate_context
                if has_guidance_authorization:
                    context["guidance_authorization"] = {
                        "state": "confirmed",
                        "scope": "this report and finding only",
                    }
                else:
                    for finding in context.get("findings", []):
                        if isinstance(finding, dict):
                            finding.pop("exploitation_guidance", None)
                context_reply = missing_finding_reply(message, context, conversation)
        if context.get("selected_finding") and _FRESH_FINDING_ANALYSIS.match(message):
            conversation = new_conversation(module, scan_id, host_id, finding_id)
        elif proxy_context and _FRESH_FINDING_ANALYSIS.match(message):
            conversation = new_conversation(module)
        memory = load_memory(ai_data_dir, owner)
        if context and scan_id:
            remediation_records = memory.get("remediation", {})
            context_findings = context.get("findings", [])
            for finding in context_findings:
                finding_key = f"{module}:{scan_id}:{finding.get('id', '')}"
                saved_status = remediation_records.get(finding_key, {}).get("status", "OPEN")
                finding["workflow_status"] = saved_status
        profile = normalize_profile(memory.get("profile")) if memory.get("enabled", True) else normalize_profile(None)
        messages = build_messages(
            module,
            profile,
            conversation,
            message,
            context,
            memory.get("explicit_memories", []) if memory.get("enabled", True) else [],
            proxy_context=proxy_context,
        )
        return {
            "message": message,
            "module": module,
            "scan_id": scan_id,
            "host_id": host_id,
            "finding_id": finding_id,
            "context": context,
            "proxy_context": proxy_context,
            "greeting_reply": greeting,
            "context_reply": context_reply,
            "conversation": conversation,
            "messages": messages,
            "explicit_memories": memory.get("explicit_memories", []) if memory.get("enabled", True) else [],
        }

    def finish_chat(prepared, owner, answer):
        conversation = prepared["conversation"]
        append_exchange(
            conversation,
            prepared["module"],
            prepared["scan_id"],
            prepared["host_id"],
            prepared["finding_id"],
            prepared["message"],
            answer,
        )
        save_conversation(ai_data_dir, owner, conversation)
        question = prepared["message"].lower()
        if any(phrase in question for phrase in ("teach me", "learn about", "quiz me", "explain")):
            memory = load_memory(ai_data_dir, owner)
            if memory.get("enabled", True):
                topics = memory.setdefault("learning", {}).setdefault("topics_covered", [])
                topic = next((
                    concept
                    for path in LEARNING_PATHS
                    for concept in path["concepts"]
                    if concept.lower() in question
                ), None)
                if topic and topic not in topics:
                    topics.append(topic)
                    memory["learning"]["topics_covered"] = topics[-40:]
                    save_memory(ai_data_dir, owner, memory)
        return conversation["conversation_id"]

    def has_context(prepared):
        return bool(prepared["context"] or prepared["proxy_context"])

    def prepared_context_summary(prepared):
        if prepared["proxy_context"]:
            return "Selected VulnScan Proxy request and response capture."
        if prepared["context"]:
            return context_summary(prepared["context"])
        return "No assessment context used."

    @blueprint.get("/api/ai/status")
    def ai_status():
        try:
            provider, config = create_provider()
        except ProviderError as exc:
            return jsonify({"configured": False, "error": str(exc)})
        return jsonify({
            "configured": provider is not None,
            "provider": config.name if config else None,
            "model": config.model if config else None,
        })

    @blueprint.get("/api/ai/scans")
    def ai_scans():
        from history_data import collect_activity

        activity = collect_activity(history_loader(), defensive_dir, offensive_dir)
        return jsonify({"scans": [
            {"scan_id": item["scan_id"], "module": item["module_key"], "target": item["target"], "timestamp": item["timestamp"]}
            for item in activity if item.get("detail_available")
        ][:50]})

    @blueprint.post("/api/ai/chat")
    def ai_chat():
        payload, error = request_payload()
        if error:
            return error
        owner = owner_id()
        if not _rate_allowed(owner):
            return jsonify({"success": False, "error": "AI request limit reached. Try again in a minute."}), 429
        request_id = str(uuid4())
        started = time.monotonic()
        provider = None
        config = None
        try:
            prepared = prepare(payload, owner)
            if prepared["greeting_reply"]:
                answer = prepared["greeting_reply"]
                conversation_id = finish_chat(prepared, owner, answer)
                return jsonify({
                    "success": True,
                    "request_id": request_id,
                    "conversation_id": conversation_id,
                    "answer": answer,
                    "context_used": False,
                    "context_summary": "No assessment context used.",
                })
            if prepared["context_reply"]:
                answer = prepared["context_reply"]
                conversation_id = finish_chat(prepared, owner, answer)
                return jsonify({
                    "success": True,
                    "request_id": request_id,
                    "conversation_id": conversation_id,
                    "answer": answer,
                    "context_used": True,
                    "context_summary": context_summary(prepared["context"]),
                })
            provider, config = create_provider()
            if provider is None:
                return jsonify({"success": False, "error": "AI is not configured yet. Set AI_PROVIDER and AI_MODEL to enable answers."}), 503
            answer = provider.generate_response(prepared["messages"])
            conversation_id = finish_chat(prepared, owner, answer)
            logger.info("AI request id=%s provider=%s model=%s success=true latency_ms=%d", request_id, config.name, config.model, int((time.monotonic() - started) * 1000))
            return jsonify({
                "success": True,
                "request_id": request_id,
                "conversation_id": conversation_id,
                "answer": answer,
                "context_used": has_context(prepared),
                "context_summary": prepared_context_summary(prepared),
            })
        except ContextNotFound as exc:
            return jsonify({"success": False, "error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            logger.warning("AI request id=%s provider=%s model=%s success=false latency_ms=%d error=%s", request_id, config.name if config else "unavailable", config.model if config else "unavailable", int((time.monotonic() - started) * 1000), str(exc)[:100])
            return jsonify({"success": False, "error": _friendly_provider_error(exc)}), 503

    @blueprint.post("/api/ai/chat/stream")
    def ai_chat_stream():
        payload, error = request_payload()
        if error:
            return error
        owner = owner_id()
        if not _rate_allowed(owner):
            return jsonify({"success": False, "error": "AI request limit reached. Try again in a minute."}), 429
        request_id = str(uuid4())
        started = time.monotonic()
        try:
            prepared = prepare(payload, owner)
            if prepared["greeting_reply"]:
                answer = prepared["greeting_reply"]
                conversation_id = finish_chat(prepared, owner, answer)
                events = (
                    "data: " + json.dumps({"token": answer}, ensure_ascii=True) + "\n\n"
                    + "data: " + json.dumps({
                        "done": True,
                        "request_id": request_id,
                        "conversation_id": conversation_id,
                        "context_used": False,
                        "context_summary": "No assessment context used.",
                    }, ensure_ascii=True) + "\n\n"
                )
                return Response(events, mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
            if prepared["context_reply"]:
                answer = prepared["context_reply"]
                conversation_id = finish_chat(prepared, owner, answer)
                events = (
                    "data: " + json.dumps({"token": answer}, ensure_ascii=True) + "\n\n"
                    + "data: " + json.dumps({
                        "done": True,
                        "request_id": request_id,
                        "conversation_id": conversation_id,
                        "context_used": True,
                        "context_summary": context_summary(prepared["context"]),
                    }, ensure_ascii=True) + "\n\n"
                )
                return Response(events, mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
            provider, config = create_provider()
            if provider is None:
                return jsonify({"success": False, "error": "AI is not configured yet. Set AI_PROVIDER and AI_MODEL to enable answers."}), 503
        except ContextNotFound as exc:
            return jsonify({"success": False, "error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except ProviderError as exc:
            return jsonify({"success": False, "error": str(exc)}), 503

        def events():
            answer_parts = []
            try:
                for fragment in provider.stream_response(prepared["messages"]):
                    if not isinstance(fragment, str):
                        continue
                    answer_parts.append(fragment)
                    yield "data: " + json.dumps({"token": fragment}, ensure_ascii=True) + "\n\n"
                answer = "".join(answer_parts).strip()
                if not answer:
                    raise ProviderError("The AI provider returned an empty response.")
                conversation_id = finish_chat(prepared, owner, answer)
                logger.info("AI request id=%s provider=%s model=%s success=true latency_ms=%d", request_id, config.name, config.model, int((time.monotonic() - started) * 1000))
                yield "data: " + json.dumps({
                    "done": True,
                    "request_id": request_id,
                    "conversation_id": conversation_id,
                    "context_used": has_context(prepared),
                    "context_summary": prepared_context_summary(prepared),
                }, ensure_ascii=True) + "\n\n"
            except Exception as exc:
                logger.warning("AI request id=%s provider=%s model=%s success=false latency_ms=%d error=%s", request_id, config.name, config.model, int((time.monotonic() - started) * 1000), str(exc)[:100])
                yield "data: " + json.dumps({"error": _friendly_provider_error(exc)}, ensure_ascii=True) + "\n\n"

        return Response(events(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @blueprint.get("/api/ai/memory")
    def ai_memory():
        memory = load_memory(ai_data_dir, owner_id())
        return jsonify({
            "enabled": bool(memory.get("enabled", True)),
            "profile": normalize_profile(memory.get("profile")),
            "explicit_memories": memory.get("explicit_memories", [])[:20],
            "learning": memory.get("learning", {}),
        })

    @blueprint.post("/api/ai/memory")
    def update_ai_memory():
        payload, error = request_payload()
        if error:
            return error
        memory = load_memory(ai_data_dir, owner_id())
        if "enabled" in payload:
            if not isinstance(payload["enabled"], bool):
                return jsonify({"success": False, "error": "enabled must be boolean."}), 400
            memory["enabled"] = payload["enabled"]
        if "profile" in payload:
            if not isinstance(payload["profile"], dict):
                return jsonify({"success": False, "error": "profile must be an object."}), 400
            memory["profile"] = normalize_profile(payload["profile"])
        if "explicit_memories" in payload:
            items = payload["explicit_memories"]
            if not isinstance(items, list) or len(items) > 20:
                return jsonify({"success": False, "error": "explicit_memories must be a list of at most 20 notes."}), 400
            if any(not isinstance(item, str) or not item.strip() or len(item) > 240 or contains_secret(item) for item in items):
                return jsonify({"success": False, "error": "Each note must be safe text of at most 240 characters."}), 400
            memory["explicit_memories"] = [item.strip() for item in items]
        if "explicit_memory" in payload:
            item = payload["explicit_memory"]
            if not isinstance(item, str) or not item.strip() or len(item) > 240:
                return jsonify({"success": False, "error": "Memory must be text of at most 240 characters."}), 400
            if contains_secret(item):
                return jsonify({"success": False, "error": "Credentials and secrets cannot be saved as AI memory."}), 400
            entries = memory.setdefault("explicit_memories", [])
            entries.append(item.strip())
            memory["explicit_memories"] = entries[-20:]
        save_memory(ai_data_dir, owner_id(), memory)
        return jsonify({"success": True})

    @blueprint.post("/api/ai/memory/clear")
    def clear_ai_memory():
        payload, error = request_payload()
        if error:
            return error
        owner = owner_id()
        scope = payload.get("scope")
        if scope == "conversation":
            conversation_id = payload.get("conversation_id")
            if conversation_id is None:
                return jsonify({"success": True, "deleted": scope})
            if not isinstance(conversation_id, str):
                return jsonify({"success": False, "error": "conversation_id is required."}), 400
            try:
                clear_conversation(ai_data_dir, owner, conversation_id)
            except ValueError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400
        elif scope == "learning":
            clear_learning(ai_data_dir, owner)
            with _EPHEMERAL_LOCK:
                transient = _EPHEMERAL_QUIZZES.get(owner)
                if transient:
                    transient["learning"] = {"topics_covered": [], "topics_to_review": [], "quiz_results": []}
                    transient["pending_quizzes"] = {}
        elif scope == "all":
            clear_all(ai_data_dir, owner)
            with _EPHEMERAL_LOCK:
                _EPHEMERAL_QUIZZES.pop(owner, None)
        else:
            return jsonify({"success": False, "error": "Choose conversation, learning, or all."}), 400
        return jsonify({"success": True, "deleted": scope})

    @blueprint.get("/api/ai/learning")
    def ai_learning():
        memory = load_memory(ai_data_dir, owner_id())
        return jsonify({"profile": normalize_profile(memory.get("profile")), "paths": learning_paths(memory)})

    @blueprint.post("/api/ai/quiz")
    def ai_quiz():
        payload, error = request_payload()
        if error:
            return error
        owner = owner_id()
        memory = load_memory(ai_data_dir, owner)
        persistent = bool(memory.get("enabled", True))
        if not persistent:
            with _EPHEMERAL_LOCK:
                memory = _EPHEMERAL_QUIZZES.setdefault(owner, {
                    "pending_quizzes": {},
                    "learning": {"topics_covered": [], "topics_to_review": [], "quiz_results": []},
                })
        try:
            if payload.get("action", "start") == "answer":
                quiz_id, answer = payload.get("quiz_id"), payload.get("answer")
                if not isinstance(quiz_id, str) or not isinstance(answer, str) or len(answer) > 160:
                    raise ValueError("A quiz ID and short answer are required.")
                result = answer_quiz(memory, quiz_id, answer)
            else:
                topic = payload.get("topic")
                difficulty = payload.get("difficulty")
                if topic is not None and (not isinstance(topic, str) or len(topic) > 80):
                    raise ValueError("Topic must be short text.")
                result = start_quiz(memory, topic, difficulty)
            if persistent:
                save_memory(ai_data_dir, owner, memory)
            return jsonify({"success": True, **result})
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @blueprint.post("/api/ai/remediation")
    def update_remediation():
        payload, error = request_payload()
        if error:
            return error
        module, scan_id, finding_id, status = (payload.get(key) for key in ("module", "scan_id", "finding_id", "status"))
        if not all(isinstance(item, str) for item in (module, scan_id, finding_id, status)) or status not in REMEDIATION_STATUSES:
            return jsonify({"success": False, "error": "A valid assessment, finding, and remediation status are required."}), 400
        try:
            context = build_scan_context(module, scan_id, None, finding_id, None, None, defensive_dir, offensive_dir, history_loader())
        except ContextNotFound as exc:
            return jsonify({"success": False, "error": str(exc)}), 404
        owner = owner_id()
        memory = load_memory(ai_data_dir, owner)
        key = f"{module}:{scan_id}:{finding_id}"
        memory.setdefault("remediation", {})[key] = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "finding_title": context["selected_finding"].get("title", "Finding"),
        }
        save_memory(ai_data_dir, owner, memory)
        return jsonify({"success": True, "status": status})

    @blueprint.get("/api/ai/remediation")
    def get_remediation():
        module = request.args.get("module", "")
        scan_id = request.args.get("scan_id", "")
        finding_id = request.args.get("finding_id", "")
        if not all((module, scan_id, finding_id)):
            return jsonify({"success": False, "error": "Assessment and finding identifiers are required."}), 400
        try:
            build_scan_context(module, scan_id, None, finding_id, None, None, defensive_dir, offensive_dir, history_loader())
        except ContextNotFound as exc:
            return jsonify({"success": False, "error": str(exc)}), 404
        memory = load_memory(ai_data_dir, owner_id())
        key = f"{module}:{scan_id}:{finding_id}"
        record = memory.get("remediation", {}).get(key, {})
        return jsonify({"success": True, "status": record.get("status", "OPEN")})

    app.register_blueprint(blueprint)