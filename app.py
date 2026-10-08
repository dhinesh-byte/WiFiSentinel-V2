from flask import Flask, Response, render_template, request, jsonify, send_file, session, stream_with_context
from jinja2 import ChoiceLoader, FileSystemLoader
from ai import register_ai_routes
from proxy import register_proxy_routes
from scanner.discovery import NetworkDiscovery
from scanner.ports import PortScanner
from nmap_options import aggregate_nmap_xml, validate_admin_nmap_options
from access_control import configure_access_control
from history_data import SAFE_REPORT_ID, collect_activity, load_detail, module_freshness
from importlib.util import module_from_spec, spec_from_file_location
from werkzeug.middleware.dispatcher import DispatcherMiddleware

import threading
import time
import uuid
import os
import json
import sys
import csv
import io
import logging
import inspect
import ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from nmap_live import NmapLiveStream, create_nmap_live_stream, record_nmap_job_event

PROJECT_ROOT = Path(__file__).resolve().parent
logger = logging.getLogger("wifi_sentinel.defensive")
OFFENSIVE_DIR = PROJECT_ROOT / "offensive"
search_path = [str(PROJECT_ROOT), str(OFFENSIVE_DIR)]
for candidate in list(sys.path):
    if candidate not in search_path:
        search_path.append(candidate)
sys.path[:] = search_path

app = Flask(__name__)
app.config["DEBUG"] = False
SERVER_HOST = os.environ.get("WIFI_SENTINEL_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("WIFI_SENTINEL_PORT", "5000"))
if not 1 <= SERVER_PORT <= 65535:
    raise RuntimeError("WIFI_SENTINEL_PORT must be between 1 and 65535.")
try:
    SCAN_WORKERS = max(1, min(8, int(os.environ.get("WIFI_SENTINEL_SCAN_WORKERS", "4"))))
except ValueError as exc:
    raise RuntimeError("WIFI_SENTINEL_SCAN_WORKERS must be an integer from 1 to 8.") from exc
try:
    SCAN_HOST_TIMEOUT = max(15, min(300, int(os.environ.get("WIFI_SENTINEL_HOST_TIMEOUT", "90"))))
except ValueError as exc:
    raise RuntimeError("Scanner host timeout must be an integer.") from exc
configure_access_control(app, SERVER_HOST)

offensive_spec = spec_from_file_location(
    "wifi_sentinel_offensive_app",
    OFFENSIVE_DIR / "app.py",
)
if offensive_spec is None or offensive_spec.loader is None:
    raise RuntimeError("Could not load the offensive assessment application.")
offensive_module = module_from_spec(offensive_spec)
sys.modules[offensive_spec.name] = offensive_module
offensive_spec.loader.exec_module(offensive_module)
offensive_module.app.jinja_loader = ChoiceLoader([
    offensive_module.app.jinja_loader,
    FileSystemLoader(str(PROJECT_ROOT / "templates")),
])
app.wsgi_app = DispatcherMiddleware(
    app.wsgi_app,
    {"/offensive": offensive_module.app},
)

# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
HISTORY_FILE = DATA_DIR / "scan_history.json"
DEFENSIVE_REPORT_DIR = DATA_DIR / "reports"
OFFENSIVE_REPORT_DIR = PROJECT_DIR / "offensive" / "reports"
HISTORY_LOCK = threading.Lock()

DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFENSIVE_REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# GLOBAL SCAN STATE
# ============================================================

scan_jobs = {}
scan_cancel_events = {}
nmap_live_streams: dict[str, NmapLiveStream] = {}


# ============================================================
# HISTORY HELPERS
# ============================================================

def load_history():
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as history_file:
            history = json.load(history_file)
        return history if isinstance(history, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_history_entry(entry):
    with HISTORY_LOCK:
        history = load_history()
        history.insert(0, entry)
        history = history[:50]
        temporary_path = HISTORY_FILE.with_suffix(".json.tmp")
        with temporary_path.open("w", encoding="utf-8") as history_file:
            json.dump(history, history_file, indent=4)
        os.replace(temporary_path, HISTORY_FILE)


proxy_service = register_proxy_routes(app, DATA_DIR / "proxy")

register_ai_routes(
    app,
    PROJECT_DIR,
    DEFENSIVE_REPORT_DIR,
    OFFENSIVE_REPORT_DIR,
    load_history,
    proxy_context_loader=proxy_service.history.detail,
)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    activity = collect_activity(
        load_history(),
        DEFENSIVE_REPORT_DIR,
        OFFENSIVE_REPORT_DIR,
    )
    freshness = module_freshness(activity)
    defensive_runs = [item for item in activity if item["module_key"] == "defensive"]
    offensive_runs = [item for item in activity if item["module_key"] == "offensive"]
    return render_template(
        "overview.html",
        recent_scans=activity[:8],
        defensive_scan_count=len(defensive_runs),
        offensive_report_count=len(offensive_runs),
        offensive_finding_count=sum(item["finding_count"] for item in offensive_runs),
        latest_device_count=defensive_runs[0]["host_count"] if defensive_runs else 0,
        freshness=freshness,
    )


@app.route("/history")
def scan_history_page():
    activity = collect_activity(load_history(), DEFENSIVE_REPORT_DIR, OFFENSIVE_REPORT_DIR)
    return render_template("history.html", activity=activity)


@app.route("/history/export.csv")
def export_scan_history_csv():
    activity = collect_activity(load_history(), DEFENSIVE_REPORT_DIR, OFFENSIVE_REPORT_DIR)
    query = request.args.get("q", "").strip().lower()
    selected_module = request.args.get("module", "all").lower()
    selected_status = request.args.get("status", "all").lower()
    filtered = []
    for scan in activity:
        normalized_status = scan["status"].lower()
        status_matches = (
            selected_status == "all"
            or (selected_status == "failed" and ("fail" in normalized_status or "error" in normalized_status))
            or (selected_status == "partial" and normalized_status in {"partial", "incomplete"})
            or normalized_status == selected_status
        )
        searchable = " ".join((
            scan["module"], scan["target"], scan["timestamp"], scan["status"],
            scan["coverage"], scan["detail"], "; ".join(scan["limitations"]),
        )).lower()
        if (selected_module == "all" or selected_module == scan["module_key"]) and status_matches and query in searchable:
            filtered.append(scan)

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("Module", "Target", "Timestamp", "Status", "Coverage", "Result", "Limitations"))
    for scan in filtered:
        writer.writerow((
            scan["module"], scan["target"], scan["timestamp"], scan["status"],
            scan["coverage"], scan["detail"], "; ".join(scan["limitations"]),
        ))
    response = Response("\ufeff" + output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = 'attachment; filename="wifi-sentinel-history.csv"'
    return response


@app.route("/history/<module>/<scan_id>")
def scan_history_detail(module, scan_id):
    detail = load_detail(
        module,
        scan_id,
        DEFENSIVE_REPORT_DIR,
        OFFENSIVE_REPORT_DIR,
        load_history(),
    )
    if detail is None:
        return jsonify({"error": "Saved scan details were not found."}), 404
    return render_template("history_detail.html", detail=detail, scan_id=scan_id)


@app.route("/history/<module>/<scan_id>/export")
def export_scan_history(module, scan_id):
    if module not in {"defensive", "offensive"} or not SAFE_REPORT_ID.fullmatch(scan_id):
        return jsonify({"error": "Unknown scan module."}), 404
    report_dir = DEFENSIVE_REPORT_DIR if module == "defensive" else OFFENSIVE_REPORT_DIR
    report_path = report_dir / f"{scan_id}.json"
    if report_path.is_file() and load_detail(
        module,
        scan_id,
        DEFENSIVE_REPORT_DIR,
        OFFENSIVE_REPORT_DIR,
        load_history(),
    ) is not None:
        return send_file(
            report_path,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"wifi-sentinel-{module}-{scan_id}.json",
        )
    detail = load_detail(
        module,
        scan_id,
        DEFENSIVE_REPORT_DIR,
        OFFENSIVE_REPORT_DIR,
        load_history(),
    )
    if detail is None:
        return jsonify({"error": "Saved scan details were not found."}), 404
    response = Response(
        json.dumps(detail["raw"], indent=2),
        mimetype="application/json",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="wifi-sentinel-{module}-{scan_id}.json"'
    )
    return response


@app.route("/defensive")
def index():

    return render_template(
        "defensive.html"
    )


def _call_discovery_method(instance, method_name, *args, **kwargs):
    method = getattr(instance, method_name)
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return method(*args, **kwargs)

    parameters = signature.parameters.values()
    accepts_var_keyword = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters)
    filtered_kwargs = {}
    for name, value in kwargs.items():
        if accepts_var_keyword or name in signature.parameters:
            filtered_kwargs[name] = value
    return method(*args, **filtered_kwargs)


# ============================================================
# START SCAN
# ============================================================

@app.route(
    "/api/scan/start",
    methods=["POST"]
)
def start_scan():

    data = request.get_json(silent=True) or {}

    target = str(data.get("target", "")).strip()
    profile = str(data.get("profile", "thorough")).strip().lower()

    if profile not in {"standard", "thorough", "deep"}:
        profile = "thorough"

    raw_timeout = data.get("timeout", 60)
    if raw_timeout in (None, "", "none", "null"):
        timeout = None
    else:
        try:
            timeout = int(raw_timeout)
        except (TypeError, ValueError):
            return jsonify({
                "success": False,
                "error": "Timeout must be 30, 60, 120, or null."
            }), 400

        if timeout not in {30, 60, 120}:
            return jsonify({
                "success": False,
                "error": "Timeout must be 30, 60, 120, or null."
            }), 400

    try:
        nmap_options = validate_admin_nmap_options(
            data.get("admin_nmap_options"),
            is_admin=session.get("_role") == "admin",
            has_raw_scan_privileges=PortScanner._has_os_detection_privileges(),
        )
    except PermissionError as exc:
        return jsonify({"success": False, "error": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


    if not target:
        return jsonify({
            "success": False,
            "error": "Please enter an IP address or network."
        }), 400

    discovery = NetworkDiscovery()
    allow_ipv6 = bool(nmap_options and nmap_options.get("ipv6"))
    if nmap_options:
        try:
            target_network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            target_network = None
        if target_network is not None and target_network.num_addresses > 256:
            return jsonify({
                "success": False,
                "error": "Advanced scans are limited to 256 target addresses per job.",
            }), 400
        if (
            target_network is not None
            and target_network.num_addresses > 1
            and nmap_options["discovery_method"] == "none"
        ):
            return jsonify({
                "success": False,
                "error": "Skipping host discovery is limited to one explicitly selected host.",
            }), 400

    if not _call_discovery_method(
        discovery,
        "validate_target",
        target,
        allow_ipv6=allow_ipv6,
    ):
        return jsonify({
            "success": False,
            "error": f"Invalid IP/network: {target}"
        }), 400

    # --------------------------------------------------------
    # Create job
    # --------------------------------------------------------

    target = _call_discovery_method(
        discovery,
        "normalize_target",
        target,
        allow_ipv6=allow_ipv6,
    )
    profile = str(data.get("profile", "thorough")).strip().lower()
    if profile not in {"standard", "thorough", "deep"}:
        profile = "thorough"

    job_id = str(uuid.uuid4())

    scan_jobs[job_id] = {
        "job_id": job_id,
        "target": target,
        "profile": profile,
        "timeout": timeout,
        "admin_nmap_options": nmap_options,
        "nmap_xml_outputs": [],
        "nmap_commands": [],
        "nmap_events": [],
        "nmap_output": [],
        "nmap_progress": None,
        "status": "starting",
        "phase": "Preparing scan",
        "progress": 0,
        "devices": [],
        "device_count": 0,
        "hosts_scanned": 0,
        "current_hosts": [],
        "open_ports": 0,
        "risks": 0,
        "started_at": time.time(),
        "elapsed": 0,
        "error": None,
        "finished": False,
        "limitations": [],
        "last_activity": "Scan job created",
        "last_activity_at": time.time(),
        "cancelled": False,
        "stages": {
            "discovery": {"status": "pending", "hosts": 0, "error": None},
            "port_enumeration": {"status": "pending", "open_ports": 0, "error": None},
            "service_detection": {"status": "pending", "services": 0, "error": None},
            "version_detection": {"status": "pending", "versions": 0, "error": None},
            "risk_analysis": {"status": "pending", "findings": 0, "error": None},
        },
    }

    scan_cancel_events[job_id] = threading.Event()
    create_nmap_live_stream(nmap_live_streams, job_id)
    logger.info("[SCAN] Created job %s target=%s", job_id, target)

    # --------------------------------------------------------
    # Background scan
    # --------------------------------------------------------

    thread = threading.Thread(
        target=run_scan,
        args=(job_id, target, profile, timeout, scan_cancel_events[job_id]),
        daemon=True
    )
    thread.start()

    return jsonify({
        "success": True,
        "job_id": job_id,
        "message": "Scan started",
        "profile": profile,
        "timeout": timeout,
    })


# ============================================================
# BACKGROUND SCANNER
# ============================================================
def run_scan(
    job_id,
    target,
    profile="thorough",
    timeout=60,
    cancel_event=None,
):


    job = scan_jobs[job_id]
    job.setdefault("stages", {
        "discovery": {"status": "pending", "hosts": 0, "error": None},
        "port_enumeration": {"status": "pending", "open_ports": 0, "error": None},
        "service_detection": {"status": "pending", "services": 0, "error": None},
        "version_detection": {"status": "pending", "versions": 0, "error": None},
        "risk_analysis": {"status": "pending", "findings": 0, "error": None},
    })

    try:

        def record_activity(message):
            job["last_activity"] = message
            job["last_activity_at"] = time.time()
            job.setdefault("nmap_events", []).append({
                "time": datetime.now().astimezone().isoformat(timespec="seconds"),
                "source": "VulnScan",
                "message": str(message)[:500],
            })
            job["nmap_events"] = job["nmap_events"][-100:]

        def record_nmap_command(target_label, command):
            item = {
                "target": target_label,
                "stage": job.get("phase"),
                "argv": list(command),
                "command": list(command),
                "status": "starting",
            }
            job.setdefault("nmap_commands", []).append(item)
            job["nmap_commands"] = job["nmap_commands"][-32:]
            record_activity(f"Nmap process started for {target_label}")

        def record_nmap_output(target_label, event):
            stream = nmap_live_streams.get(job_id)
            if stream is not None:
                record_nmap_job_event(job, target_label, str(job.get("phase", "")), event)
                stream.publish(event["type"], target=target_label, **{
                    key: value for key, value in event.items() if key != "type"
                })

        def record_nmap_progress(target, progress):
            job["nmap_progress"] = {"target": target, **progress}
            percent = progress["percent"]
            phase = progress["phase"]
            job["last_activity"] = (
                f"Nmap {phase}: {percent:g}% complete"
                + (f", {progress['remaining']} remaining" if progress.get("remaining") else "")
            )
            job["last_activity_at"] = time.time()
            record_activity(job["last_activity"])

        def cancelled():
            return cancel_event is not None and cancel_event.is_set()

        # ====================================================
        # PHASE 1 — DISCOVERY
        # ====================================================

        job["status"] = "scanning"
        job["phase"] = "Discovering devices"
        job["progress"] = 0
        record_activity("Nmap host discovery is starting")
        logger.info("[SCAN] Discovery started job=%s target=%s", job_id, target)

        discovery = NetworkDiscovery()
        nmap_options = job.get("admin_nmap_options")
        job["stages"]["discovery"] = {"status": "running", "hosts": 0, "error": None}

        discovery_result = _call_discovery_method(
            discovery,
            "discover",
            target,
            timeout=timeout,
            cancel_event=cancel_event,
            activity_callback=record_activity,
            progress_callback=lambda progress: record_nmap_progress("discovery", progress),
            command_callback=lambda command: record_nmap_command("discovery", command),
            output_callback=lambda event: record_nmap_output("discovery", event),
            nmap_options=nmap_options,
        )
        discovery_xml = discovery_result.get("nmap_xml")
        if isinstance(discovery_xml, str) and discovery_xml:
            job["nmap_xml_discovery"] = discovery_xml

        if not discovery_result["success"]:
            if discovery_result.get("status") == "cancelled" or cancelled():
                job["stages"]["discovery"] = {
                    "status": "cancelled",
                    "hosts": len(job.get("devices", [])),
                    "error": discovery_result.get("error"),
                }
                job["status"] = "cancelled"
                job["phase"] = "Scan cancelled"
                job["cancelled"] = True
                job["error"] = discovery_result.get("error")
                job["finished"] = True
                finish_scan(job_id)
                return
            job["stages"]["discovery"] = {
                "status": "failed",
                "hosts": 0,
                "error": discovery_result.get("error", "Discovery failed"),
            }

            job["status"] = "error"
            job["error"] = discovery_result.get(
                "error",
                "Discovery failed"
            )
            job["finished"] = True
            finish_scan(job_id)
            return

        devices = discovery_result.get(
            "devices",
            []
        )

        job["devices"] = devices
        job["stages"]["discovery"] = {"status": "completed", "hosts": len(devices), "error": None}
        for device in devices:
            logger.info("[SCAN] Host discovered job=%s host=%s", job_id, device.get("ip", "Unknown"))

        job["device_count"] = len(
            devices
        )
        job["progress"] = 25
        job["phase"] = "Discovery completed; preparing port assessment"
        record_activity(f"Discovery completed: {len(devices)} host(s) found")
        logger.info("[SCAN] Discovery completed job=%s hosts=%s", job_id, len(devices))

        # ----------------------------------------------------
        # No devices
        # ----------------------------------------------------

        if not devices:

            job["stages"]["port_enumeration"] = {"status": "skipped", "open_ports": 0, "error": "No active hosts were discovered."}
            job["stages"]["service_detection"] = {"status": "skipped", "services": 0, "error": "No active hosts were discovered."}
            job["stages"]["version_detection"] = {"status": "skipped", "versions": 0, "error": "No active hosts were discovered."}

            job["progress"] = 100
            job["status"] = "completed"
            job["phase"] = "No active devices found"
            job["finished"] = True

            finish_scan(
                job_id
            )

            return

        # ====================================================
        # PHASE 2 — PORT/SERVICE SCANNING
        # ====================================================

        job["phase"] = f"Scanning ports and services ({profile})"
        record_activity("Port assessment started")
        logger.info("[SCAN] Starting port assessment job=%s", job_id)

        scanner_kwargs = {
            "timeout": nmap_options["host_timeout"] if nmap_options else timeout,
        }
        if "profile" in inspect.signature(PortScanner).parameters:
            scanner_kwargs["profile"] = profile
        port_scanner = PortScanner(**scanner_kwargs)
        job["stages"]["port_enumeration"] = {"status": "running", "open_ports": 0, "error": None}
        job["stages"]["service_detection"] = {"status": "running", "services": 0, "error": None}
        job["stages"]["version_detection"] = {"status": "running", "versions": 0, "error": None}

        total_open_ports = 0
        scannable_devices = []
        for device in devices:
            ip = device.get("ip")
            if ip and ip != "Unknown":
                scannable_devices.append((device, ip))
            else:
                device["scan_error"] = "Discovery did not provide a usable IP address."

        active_host_ips = set()
        active_host_lock = threading.Lock()

        def scan_host(ip):
            with active_host_lock:
                active_host_ips.add(ip)
                job["current_hosts"] = sorted(active_host_ips)
            try:
                return _call_discovery_method(
                    port_scanner,
                    "scan_device",
                    ip,
                    aggressive=True,
                    nmap_options=nmap_options,
                    cancel_event=cancel_event,
                    progress_callback=lambda progress, host=ip: record_nmap_progress(host, progress),
                    command_callback=lambda command, host=ip: record_nmap_command(host, command),
                    output_callback=lambda event, host=ip: record_nmap_output(host, event),
                )
            finally:
                with active_host_lock:
                    active_host_ips.discard(ip)
                    job["current_hosts"] = sorted(active_host_ips)

        configured_workers = nmap_options["parallelism"] if nmap_options else SCAN_WORKERS
        worker_count = max(1, min(configured_workers, len(scannable_devices)))
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix=f"defensive-{job_id[:8]}",
        ) as executor:
            future_devices = {
                executor.submit(scan_host, ip): device
                for device, ip in scannable_devices
            }
            completed_hosts = 0
            for future in as_completed(future_devices):
                device = future_devices[future]
                ip = device["ip"]
                completed_hosts += 1
                if cancelled():
                    for pending_future in future_devices:
                        pending_future.cancel()
                    job["status"] = "cancelled"
                    job["phase"] = "Scan cancelled"
                    job["cancelled"] = True
                    job["finished"] = True
                    job["limitations"] = ["Port assessment was cancelled before all discovered hosts were scanned."]
                    finish_scan(job_id)
                    return
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "success": False,
                        "error": str(exc),
                        "open_ports": 0,
                        "ports": [],
                    }

                if result.get("success"):
                    xml_output = result.pop("nmap_xml", None)
                    if isinstance(xml_output, str) and xml_output:
                        job.setdefault("nmap_xml_outputs", []).append(xml_output)
                    for field, default in (
                        ("hostname", device.get("hostname", "Unknown")),
                        ("mac", device.get("mac", "Unknown")),
                        ("vendor", device.get("vendor", "Unknown")),
                        ("os", "Unknown"),
                        ("os_accuracy", 0),
                        ("os_matches", []),
                        ("uptime_seconds", None),
                        ("last_boot", None),
                        ("distance", None),
                        ("host_scripts", []),
                        ("status_reason", ""),
                        ("os_detection_status", "unknown"),
                        ("packet_trace", ""),
                        ("ports", []),
                        ("open_ports", 0),
                        ("traceroute", []),
                    ):
                        value = result.get(field, default)
                        if field in {"hostname", "mac", "vendor"} and value in (None, "", "Unknown"):
                            value = device.get(field, default)
                        device[field] = value
                    job["hosts_scanned"] += 1
                    total_open_ports += int(result.get("open_ports", 0))
                    job["stages"]["service_detection"]["services"] = sum(
                        1 for item in devices for port in item.get("ports", [])
                        if port.get("state") == "open" and port.get("service")
                    )
                    job["stages"]["version_detection"]["versions"] = sum(
                        1 for item in devices for port in item.get("ports", [])
                        if port.get("state") == "open" and port.get("version")
                    )
                else:
                    device["scan_error"] = result.get("error", "Port scan failed")
                    job["stages"]["port_enumeration"]["error"] = device["scan_error"]

                job["current_ip"] = ip
                job["open_ports"] = total_open_ports
                job["devices"] = devices
                job["progress"] = min(
                    90,
                    20 + int((completed_hosts / len(scannable_devices)) * 70),
                )
                job["phase"] = (
                    f"Scanning hosts ({completed_hosts}/{len(scannable_devices)} complete, "
                    f"up to {worker_count} in parallel)"
                )
                record_activity(f"Host assessment completed: {ip}")
                job["elapsed"] = round(time.time() - job["started_at"], 1)

        job["current_hosts"] = []
        partial_host_scan = any(device.get("scan_error") for device in devices)
        stage_status = "partial" if partial_host_scan else "completed"
        job["stages"]["port_enumeration"] = {"status": stage_status, "open_ports": total_open_ports, "error": job["stages"]["port_enumeration"].get("error")}
        job["stages"]["service_detection"]["status"] = stage_status
        job["stages"]["version_detection"]["status"] = stage_status

        # ====================================================
        # PHASE 3 — SECURITY ANALYSIS
        # ====================================================

        job["phase"] = "Analyzing security findings"
        job["progress"] = 93

        total_risks = 0
        job["stages"]["risk_analysis"] = {"status": "running", "findings": 0, "error": None}

        for device in devices:

            risks = analyze_device(
                device
            )

            device["risks"] = risks

            total_risks += len(
                risks
            )

        job["risks"] = total_risks
        record_activity(f"Risk analysis completed: {total_risks} finding(s)")
        job["stages"]["risk_analysis"] = {"status": "completed", "findings": total_risks, "error": None}

        # ====================================================
        # COMPLETE
        # ====================================================

        job["progress"] = 100
        job["phase"] = "Scan completed"
        job["status"] = "completed"
        job["finished"] = True

        job["elapsed"] = round(
            time.time()
            - job["started_at"],
            1
        )

        limitations = job.get("limitations", [])
        if not isinstance(limitations, list):
            limitations = []
        if job["hosts_scanned"] < job["device_count"]:
            job["status"] = "partial"
            limitations.append(
                "Port and service checks did not complete successfully for every discovered host."
            )
        if any(
            device.get("os_detection_status") == "skipped_unprivileged"
            for device in devices
        ):
            limitations.append(
                "OS fingerprinting was skipped because Nmap requires elevated privileges."
            )
        job["limitations"] = list(dict.fromkeys(limitations))

        finish_scan(
            job_id
        )
        logger.info("[SCAN] Completed job=%s status=%s", job_id, job["status"])

    except Exception as exc:

        job["status"] = "error"
        job["phase"] = "Scan failed"
        job["error"] = str(exc)
        logger.exception("[SCAN ERROR] job=%s", job_id)
        for stage in job.get("stages", {}).values():
            if stage.get("status") in {"running", "pending"}:
                stage["status"] = "failed"
                stage["error"] = str(exc)
        job["finished"] = True

        job["elapsed"] = round(
            time.time()
            - job["started_at"],
            1
        )
        job["limitations"] = ["The scan stopped before all checks completed."]
        finish_scan(job_id)


# ============================================================
# BASIC SECURITY ANALYSIS
# ============================================================

def analyze_device(
    device
):

    risks = []

    ports = device.get(
        "ports",
        []
    )

    for port in ports:

        if port.get(
            "state"
        ) != "open":

            continue

        port_number = str(
            port.get(
                "port",
                ""
            )
        )

        service = str(
            port.get(
                "service",
                ""
            )
        ).lower()

        # ----------------------------------------------------
        # Telnet
        # ----------------------------------------------------

        if port_number == "23":

            risks.append({
                "severity": "high",
                "title": "Telnet exposed",
                "port": 23,
                "description":
                    "Telnet transmits communication without modern encryption.",
                "protection":
                    "Disable Telnet and use SSH or another encrypted management protocol."
            })

        # ----------------------------------------------------
        # FTP
        # ----------------------------------------------------

        elif port_number == "21":

            risks.append({
                "severity": "medium",
                "title": "FTP service exposed",
                "port": 21,
                "description":
                    "Traditional FTP may expose credentials and data if encryption is not configured.",
                "protection":
                    "Disable unused FTP or use an encrypted alternative such as SFTP."
            })

        # ----------------------------------------------------
        # SMB
        # ----------------------------------------------------

        elif port_number in (
            "139",
            "445"
        ):

            risks.append({
                "severity": "medium",
                "title": "SMB service exposed",
                "port": int(port_number),
                "description":
                    "SMB exposure can increase the attack surface of a network device.",
                "protection":
                    "Restrict SMB access with firewall rules and keep the operating system patched."
            })

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        elif port_number == "80":

            risks.append({
                "severity": "low",
                "title": "HTTP service detected",
                "port": 80,
                "description":
                    "HTTP does not provide transport encryption by itself.",
                "protection":
                    "Prefer HTTPS and redirect HTTP traffic where appropriate."
            })

        # ----------------------------------------------------
        # SSH
        # ----------------------------------------------------

        elif port_number == "22":

            risks.append({
                "severity": "low",
                "title": "SSH service exposed",
                "port": 22,
                "description":
                    "SSH is a legitimate administration service but increases the exposed attack surface.",
                "protection":
                    "Restrict SSH to trusted hosts, use strong authentication, and disable unused access."
            })

        # ----------------------------------------------------
        # RDP
        # ----------------------------------------------------

        elif port_number == "3389":

            risks.append({
                "severity": "medium",
                "title": "RDP service exposed",
                "port": 3389,
                "description":
                    "Remote Desktop exposure increases the remote-access attack surface.",
                "protection":
                    "Restrict RDP using firewall/VPN controls and keep Windows fully updated."
            })

    return risks


# ============================================================
# SCAN STATUS
# ============================================================

@app.route(
    "/api/scan/status/<job_id>",
    methods=["GET"]
)
def scan_status(
    job_id
):

    job = scan_jobs.get(
        job_id
    )

    if job is None:

        return jsonify({
            "success": False,
            "error": "Scan job not found"
        }), 404

    job["elapsed"] = round(
        time.time()
        - job["started_at"],
        1
    )
    last_activity_at = job.get("last_activity_at", job["started_at"])
    job["last_activity_age"] = round(max(0, time.time() - last_activity_at), 1)

    return jsonify({
        "success": True,
        "scan": job
    })


@app.get("/api/scan/stream/<job_id>")
def stream_scan_output(job_id):
    if job_id not in scan_jobs:
        return jsonify({"success": False, "error": "Scan job not found"}), 404
    stream = nmap_live_streams.get(job_id)
    if stream is None:
        return jsonify({"success": False, "error": "Nmap output stream is unavailable"}), 404
    try:
        cursor = max(0, int(request.headers.get("Last-Event-ID", "0")))
    except ValueError:
        return jsonify({"success": False, "error": "Invalid stream event cursor"}), 400

    def generate():
        nonlocal cursor
        while True:
            events, finished, history_gap = stream.events_after(cursor, timeout=15)
            if history_gap:
                yield "event: history_gap\ndata: {}\n\n"
            for event in events:
                cursor = event["id"]
                payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                yield f"id: {cursor}\nevent: {event['type']}\ndata: {payload}\n\n"
                if event["type"] == "assessment_end":
                    return
            if finished:
                return
            if not events:
                yield ": keep-alive\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/scan/cancel/<job_id>", methods=["POST"])
def cancel_scan(job_id):
    job = scan_jobs.get(job_id)
    if job is None:
        return jsonify({"success": False, "error": "Scan job not found"}), 404
    if job.get("finished"):
        return jsonify({"success": False, "error": "Scan has already finished."}), 409
    cancel_event = scan_cancel_events.get(job_id)
    if cancel_event is None:
        return jsonify({"success": False, "error": "Scan cancellation is unavailable."}), 409
    cancel_event.set()
    job["last_activity"] = "Cancellation requested"
    job["last_activity_at"] = time.time()
    return jsonify({"success": True, "status": "cancelling", "scan": job})


# ============================================================
# SCAN RESULT
# ============================================================

@app.route(
    "/api/scan/result/<job_id>",
    methods=["GET"]
)
def scan_result(
    job_id
):

    job = scan_jobs.get(
        job_id
    )

    if job is None:

        return jsonify({
            "success": False,
            "error": "Scan job not found"
        }), 404

    return jsonify({
        "success": True,
        "scan": job
    })


# ============================================================
# DEVICE DETAILS
# ============================================================

@app.route(
    "/api/device/<job_id>/<ip_address>",
    methods=["GET"]
)
def device_details(
    job_id,
    ip_address
):

    job = scan_jobs.get(
        job_id
    )

    if job is None:

        return jsonify({
            "success": False,
            "error": "Scan job not found"
        }), 404

    for device in job.get(
        "devices",
        []
    ):

        if device.get(
            "ip"
        ) == ip_address:

            return jsonify({
                "success": True,
                "device": device
            })

    return jsonify({
        "success": False,
        "error": "Device not found"
    }), 404


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def scan_history():

    return jsonify({
        "success": True,
        "history": load_history()
    })


# ============================================================
# SAVE COMPLETED SCAN
# ============================================================

def finish_scan(
    job_id
):

    job = scan_jobs.get(
        job_id
    )

    if not job:
        return

    stream = nmap_live_streams.get(job_id)
    if stream is not None:
        scan_status = str(job.get("status", "")).lower()
        stream_status = (
            "STOPPED" if scan_status in {"cancelled", "canceled"}
            else "FAILED" if scan_status in {"error", "failed"}
            else "COMPLETED"
        )
        stream.close(stream_status)

    timestamp = datetime.now().isoformat(timespec="seconds")
    discovered = job.get("device_count", 0)
    scanned = job.get("hosts_scanned", 0)
    limitations = job.get("limitations", [])
    if not isinstance(limitations, list):
        limitations = []
    if scanned < discovered and not limitations:
        limitations = ["Some discovered hosts were not fully scanned."]

    report = {
        "id": job_id,
        "target": job.get("target"),
        "timestamp": timestamp,
        "duration": job.get("elapsed", 0),
        "status": job.get("status", "unknown"),
        "hosts_discovered": discovered,
        "hosts_scanned": scanned,
        "open_ports": job.get("open_ports", 0),
        "risks": job.get("risks", 0),
        "devices": job.get("devices", []),
        "limitations": limitations,
        "error": job.get("error"),
    }
    nmap_options = job.get("admin_nmap_options")
    nmap_xml_requested = bool(
        nmap_options and nmap_options.get("output_format") in {"xml", "both"}
    )
    if nmap_xml_requested:
        xml_outputs = job.get("nmap_xml_outputs") or []
        if not xml_outputs and isinstance(job.get("nmap_xml_discovery"), str):
            xml_outputs = [job["nmap_xml_discovery"]]
        if xml_outputs:
            xml_path = DEFENSIVE_REPORT_DIR / f"{job_id}.nmap.xml"
            temporary_xml_path = xml_path.with_suffix(".xml.tmp")
            try:
                temporary_xml_path.write_bytes(aggregate_nmap_xml(xml_outputs))
                os.replace(temporary_xml_path, xml_path)
                job["nmap_xml_available"] = True
            except (ET.ParseError, OSError, ValueError) as exc:
                job["nmap_xml_available"] = False
                job["nmap_xml_error"] = str(exc)
                limitations = list(limitations)
                limitations.append(f"Nmap XML export could not be generated: {exc}")
                report["limitations"] = limitations
        else:
            job["nmap_xml_available"] = False
            job["nmap_xml_error"] = "Nmap returned no XML host records to export."
            limitations = list(limitations)
            limitations.append(job["nmap_xml_error"])
            report["limitations"] = limitations
    report_path = DEFENSIVE_REPORT_DIR / f"{job_id}.json"
    detail_available = False
    try:
        with report_path.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2)
        detail_available = True
    except (OSError, TypeError, ValueError) as exc:
        job["report_error"] = str(exc)

    entry = {
        "id": job_id,
        "target": job.get("target"),
        "timestamp": timestamp,
        "duration": job.get("elapsed", 0),
        "devices": discovered,
        "hosts_discovered": discovered,
        "hosts_scanned": scanned,
        "open_ports": job.get("open_ports", 0),
        "risks": job.get("risks", 0),
        "status": job.get("status", "unknown"),
        "detail_available": detail_available,
        "limitations": limitations,
    }

    save_history_entry(
        entry
    )
    scan_cancel_events.pop(job_id, None)


@app.route("/api/scan/output/<job_id>/nmap.xml")
def export_defensive_nmap_xml(job_id):
    try:
        normalized_id = str(uuid.UUID(job_id))
    except (ValueError, TypeError, AttributeError):
        return jsonify({"success": False, "error": "Unknown scan job."}), 404
    xml_path = DEFENSIVE_REPORT_DIR / f"{normalized_id}.nmap.xml"
    if not xml_path.is_file():
        return jsonify({"success": False, "error": "Nmap XML export is not available."}), 404
    return send_file(
        xml_path,
        mimetype="application/xml",
        as_attachment=True,
        download_name=f"vulnscan-{normalized_id}.xml",
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    discovery = NetworkDiscovery()
    ports = PortScanner()

    return jsonify({
        "success": True,
        "application": "VulnScan v4.13",
        "nmap": discovery.is_available(),
        "nmap_version": ports.get_nmap_version(),
        "raw_scan_privileges": PortScanner._has_os_detection_privileges(),
    })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    from waitress import serve

    print("=" * 60)
    print("VulnScan v4.13")
    print("=" * 60)

    print(
        "Starting Flask server..."
    )

    print(f"Open: http://{SERVER_HOST}:{SERVER_PORT}")
    serve(app, host=SERVER_HOST, port=SERVER_PORT, threads=8)