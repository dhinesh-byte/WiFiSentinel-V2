from flask import Flask, Response, render_template, request, jsonify, send_file
from scanner.discovery import NetworkDiscovery
from scanner.ports import PortScanner
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


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
configure_access_control(app, SERVER_HOST)

OFFENSIVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offensive")
sys.path.insert(0, OFFENSIVE_DIR)
offensive_spec = spec_from_file_location(
    "wifi_sentinel_offensive_app",
    os.path.join(OFFENSIVE_DIR, "app.py"),
)
if offensive_spec is None or offensive_spec.loader is None:
    raise RuntimeError("Could not load the offensive assessment application.")
offensive_module = module_from_spec(offensive_spec)
sys.modules[offensive_spec.name] = offensive_module
offensive_spec.loader.exec_module(offensive_module)
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
        "dashboard.html"
    )


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

    if not target:
        return jsonify({
            "success": False,
            "error": "Please enter an IP address or network."
        }), 400

    discovery = NetworkDiscovery()

    if not discovery.validate_target(target):
        return jsonify({
            "success": False,
            "error": f"Invalid IP/network: {target}"
        }), 400

    job_id = str(uuid.uuid4())

    scan_jobs[job_id] = {
        "job_id": job_id,
        "target": target,
        "profile": profile,
        "timeout": timeout,
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
    }

    thread = threading.Thread(
        target=run_scan,
        args=(job_id, target, profile, timeout),
        daemon=True,
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
):
    try:

        # ====================================================
        # PHASE 1 — DISCOVERY
        # ====================================================

        job["status"] = "scanning"
        job["phase"] = "Discovering devices"
        job["progress"] = 10

        discovery = NetworkDiscovery()

        discovery_result = discovery.discover(
            target,
            timeout=timeout if timeout is not None else 3600,
        )

        if not discovery_result["success"]:

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

        job["device_count"] = len(
            devices
        )

        # ----------------------------------------------------
        # No devices
        # ----------------------------------------------------

        if not devices:

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

        port_scanner = PortScanner(
            timeout=timeout,
            profile=profile,
        )

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
                return port_scanner.scan_device(ip, aggressive=True)
            finally:
                with active_host_lock:
                    active_host_ips.discard(ip)
                    job["current_hosts"] = sorted(active_host_ips)

        worker_count = max(1, min(SCAN_WORKERS, len(scannable_devices)))
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
                else:
                    device["scan_error"] = result.get("error", "Port scan failed")

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
                job["elapsed"] = round(time.time() - job["started_at"], 1)

        job["current_hosts"] = []

        # ====================================================
        # PHASE 3 — SECURITY ANALYSIS
        # ====================================================

        job["phase"] = "Analyzing security findings"
        job["progress"] = 93

        total_risks = 0

        for device in devices:

            risks = analyze_device(
                device
            )

            device["risks"] = risks

            total_risks += len(
                risks
            )

        job["risks"] = total_risks

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

    except Exception as exc:

        job["status"] = "error"
        job["phase"] = "Scan failed"
        job["error"] = str(exc)
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

    return jsonify({
        "success": True,
        "scan": job
    })


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
        "application": "WiFi Sentinel V2.0",
        "nmap": discovery.is_available(),
        "nmap_version": ports.get_nmap_version()
    })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    from waitress import serve

    print("=" * 60)
    print("WiFi Sentinel V2.0")
    print("=" * 60)

    print(
        "Starting Flask server..."
    )

    print(f"Open: http://{SERVER_HOST}:{SERVER_PORT}")
    serve(app, host=SERVER_HOST, port=SERVER_PORT, threads=8)