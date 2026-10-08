"""Flask routes for the independent VulnScan Proxy workspace."""

from __future__ import annotations

import json
import ipaddress
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading

from flask import Blueprint, Response, jsonify, render_template, request, send_file, stream_with_context

from .engine import ProxyConfigurationError, ProxyService

_FLOW_ID = re.compile(r"^[0-9a-f]{32}$")


def register_proxy_routes(app, data_directory: Path) -> ProxyService:
    """Register Proxy routes on the unified app without changing scan routes."""
    service = ProxyService(data_directory)
    blueprint = Blueprint("vulnscan_proxy", __name__)
    app.extensions["vulnscan_proxy"] = service

    @blueprint.get("/proxy")
    def proxy_page():
        return render_template("proxy.light.html", active_mode="proxy", active_tool="Proxy")

    def _tool_page(tool_name: str, subtitle: str, description: str):
        return render_template(
            "proxy.light.html",
            active_mode=tool_name.lower(),
            active_tool=tool_name,
            active_tool_subtitle=subtitle,
            active_tool_description=description,
            target_mode=(tool_name == "Target"),
        )

    @blueprint.get("/target")
    def target_page():
        return _tool_page("Target", "Authorized target scope and findings.", "Target scope, inspections, and authorized hosts.")

    @blueprint.get("/intruder")
    def intruder_page():
        return _tool_page("Intruder", "Payload position and iteration workspace.", "Automated request fuzzing and payload delivery.")

    @blueprint.get("/repeater")
    def repeater_page():
        return _tool_page("Repeater", "Request sequencing and iterative validation.", "Issue verification and repeatable request replay.")

    @blueprint.get("/decoder")
    def decoder_page():
        return _tool_page("Decoder", "Transform, hash, and decode input values.", "Data decoding, encoding, and transformation utilities.")

    @blueprint.get("/compare")
    def compare_page():
        return _tool_page("Comparer", "Compare request and response variants.", "Response and payload comparison workspace.")

    @blueprint.get("/logger")
    def logger_page():
        return _tool_page("Logger", "HTTP event capture and inspection log.", "Recorded request and response history.")

    @blueprint.get("/extensions")
    def extensions_page():
        return _tool_page("Extensions", "Installed Burp extensions and automation.", "Third-party extension marketplace and module status.")

    @blueprint.get("/discover")
    def discover_page():
        return _tool_page("Discover", "Target enumeration and application discovery.", "Recon and discovery workflow for live targets.")

    @blueprint.get("/api/proxy/status")
    def proxy_status():
        return jsonify({"success": True, **service.status()})

    @blueprint.get("/api/proxy/target/scope")
    def proxy_scope():
        return jsonify({"success": True, "scope": service.scope()})

    @blueprint.get("/api/proxy/target")
    def proxy_target():
        return jsonify({"success": True, **service.target_summary()})

    @blueprint.put("/api/proxy/target/scope")
    def update_proxy_scope():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "A scope object is required."}), 400
        try:
            return jsonify({"success": True, "scope": service.update_scope(payload)})
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @blueprint.post("/api/proxy/start")
    def proxy_start():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "A JSON settings object is required."}), 400
        try:
            result = service.start(payload)
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        if result["state"] != "running":
            return jsonify({"success": False, "error": result["error"] or "Proxy failed to start.", **result}), 503
        return jsonify({"success": True, **result})

    @blueprint.post("/api/proxy/stop")
    def proxy_stop():
        return jsonify({"success": True, **service.stop()})

    @blueprint.get("/api/proxy/settings")
    def proxy_settings():
        return jsonify({"success": True, "settings": service.settings()})

    @blueprint.post("/api/proxy/settings")
    def update_proxy_settings():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "A JSON settings object is required."}), 400
        try:
            return jsonify({"success": True, "settings": service.update_settings(payload), **service.status()})
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @blueprint.get("/api/proxy/history")
    def proxy_history():
        filters = {
            "q": request.args.get("q", ""),
            "method": request.args.get("method", "all"),
            "status": request.args.get("status", "all"),
            "content_type": request.args.get("content_type", "all"),
            "host": request.args.get("host", ""),
            "path": request.args.get("path", ""),
            "page": request.args.get("page", "1"),
            "page_size": request.args.get("page_size", "80"),
        }
        return jsonify({"success": True, **service.history_page(filters)})

    @blueprint.get("/api/proxy/history/<flow_id>")
    def proxy_history_detail(flow_id):
        if not _FLOW_ID.fullmatch(flow_id):
            return jsonify({"success": False, "error": "Captured request was not found."}), 404
        detail = service.history.detail(flow_id)
        if detail is None:
            return jsonify({"success": False, "error": "Captured request was not found."}), 404
        return jsonify({"success": True, "request": detail})

    @blueprint.get("/api/proxy/websockets")
    def proxy_websockets():
        try:
            page = max(1, min(100000, int(request.args.get("page", "1"))))
            page_size = max(10, min(200, int(request.args.get("page_size", "80"))))
        except ValueError:
            page, page_size = 1, 80
        result = service.history.query_websockets(search=request.args.get("q", "")[:200], page=page, page_size=page_size)
        return jsonify({"success": True, **result})

    @blueprint.post("/api/proxy/history/clear")
    def clear_proxy_history():
        service.clear_history()
        return jsonify({"success": True})

    @blueprint.get("/api/proxy/intercepts")
    def proxy_intercepts():
        return jsonify({"success": True, "requests": service.pending()})

    @blueprint.post("/api/proxy/browser/open")
    def open_proxy_browser():
        remote_address = request.remote_addr or ""
        try:
            parsed_address = ipaddress.ip_address(remote_address.split("%", 1)[0])
            is_loopback = parsed_address.is_loopback or bool(parsed_address.ipv4_mapped and parsed_address.ipv4_mapped.is_loopback)
        except ValueError:
            is_loopback = False
        if not is_loopback:
            return jsonify({"success": False, "error": "The dedicated browser can only be launched from the local VulnScan instance."}), 403
        status = service.status()
        if not status["running"]:
            return jsonify({"success": False, "error": "Start the Proxy listener before opening a configured browser."}), 409
        candidates = [
            shutil.which("chrome"),
            shutil.which("chrome.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
        ]
        browser = next((path for path in candidates if path and Path(path).is_file()), None)
        if browser is None:
            return jsonify({"success": False, "error": "Google Chrome was not found. Configure another browser manually to use the listener address."}), 404
        profile = tempfile.TemporaryDirectory(prefix="vulnscan-proxy-browser-")
        command = [
            browser,
            f"--user-data-dir={profile.name}",
            "--no-first-run",
            "--new-window",
            f"--proxy-server=http://{status['address']}:{status['port']}",
            "--proxy-bypass-list=<-loopback>",
            "about:blank",
        ]
        try:
            launch_options = {"close_fds": True}
            if os.name == "nt":
                launch_options["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                launch_options["start_new_session"] = True
            process = subprocess.Popen(command, **launch_options)
        except OSError as exc:
            profile.cleanup()
            return jsonify({"success": False, "error": f"Chrome could not be started: {exc}"}), 500

        def remove_temporary_profile():
            process.wait()
            profile.cleanup()

        threading.Thread(target=remove_temporary_profile, name="vulnscan-proxy-browser", daemon=True).start()
        return jsonify({
            "success": True,
            "message": "A dedicated Chrome window was opened through the Proxy using a temporary profile.",
            "pid": process.pid,
            "listener": status["listener"],
            "https_note": "HTTPS interception still requires manually trusting the exported VulnScan Proxy CA on an authorized test device.",
        })

    @blueprint.post("/api/proxy/intercepts/<flow_id>/forward")
    def forward_proxy_request(flow_id):
        if not _FLOW_ID.fullmatch(flow_id):
            return jsonify({"success": False, "error": "Intercepted request was not found."}), 404
        payload = request.get_json(silent=True) or {}
        modified = payload.get("modified_request") if payload.get("modified") is True else None
        try:
            result = service.resolve_intercept(flow_id, "forward", modified)
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        return jsonify({"success": True, "request": result})

    @blueprint.post("/api/proxy/intercepts/<flow_id>/drop")
    def drop_proxy_request(flow_id):
        if not _FLOW_ID.fullmatch(flow_id):
            return jsonify({"success": False, "error": "Intercepted request was not found."}), 404
        try:
            result = service.resolve_intercept(flow_id, "drop")
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        return jsonify({"success": True, "request": result})

    @blueprint.post("/api/proxy/replay")
    def replay_proxy_request():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "A replay request object is required."}), 400
        try:
            result = service.replay(payload)
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        return jsonify({"success": True, "response": result})

    @blueprint.post("/api/proxy/ca/generate")
    def generate_proxy_ca():
        try:
            result = service.generate_ca()
        except ProxyConfigurationError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"success": False, "error": f"Local CA generation failed: {exc}"}), 500
        return jsonify({"success": True, **result})

    @blueprint.get("/api/proxy/ca/export")
    def export_proxy_ca():
        certificate = service.ca_certificate_path()
        if certificate is None:
            return jsonify({"success": False, "error": "Generate the local CA before exporting its public certificate."}), 404
        return send_file(certificate, mimetype="application/x-pem-file", as_attachment=True, download_name="vulnscan-proxy-ca-cert.pem")

    @blueprint.get("/api/proxy/events")
    def proxy_events():
        try:
            cursor = max(0, int(request.headers.get("Last-Event-ID", "0")))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid event cursor."}), 400
        stream = service.event_stream

        def generate():
            nonlocal cursor, stream
            while True:
                current_stream = service.event_stream
                if current_stream is not stream:
                    stream = current_stream
                    cursor = 0
                events, finished, gap = stream.events_after(cursor, timeout=15)
                if gap:
                    yield "event: history_gap\ndata: {}\n\n"
                for event in events:
                    cursor = event["id"]
                    event_type = event.get("type", "message")
                    payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
                    yield f"id: {cursor}\nevent: {event_type}\ndata: {payload}\n\n"
                if finished:
                    return
                if not events:
                    yield ": keep-alive\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    app.register_blueprint(blueprint)
    return service
