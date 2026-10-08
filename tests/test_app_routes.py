import json
from pathlib import Path
import sys
import threading
import time

import app as app_module
from nmap_live import NmapLiveStream, record_nmap_job_event
from nmap_process import run_nmap


def test_combined_application_routes_and_scan_authorization():
    client = app_module.app.test_client()

    assert app_module.app.debug is False
    assert client.get("/").status_code == 200
    defensive_page = client.get("/defensive")
    assert defensive_page.status_code == 200
    assert b"https://www.virustotal.com/" in defensive_page.data
    assert b"https://haveibeenpwned.com/" in defensive_page.data
    assert b"noopener noreferrer" in defensive_page.data
    assert client.get("/offensive/").status_code == 200
    assert client.get("/history").status_code == 200
    assert client.post("/offensive/api/offensive/scans", json={"target": "192.0.2.1"}).status_code == 403
    assert client.post("/api/scan/start", json={}).status_code == 400


def test_defensive_nmap_output_stream_replays_raw_subprocess_output():
    scan_id = "a4df20c2-384c-4c63-93c7-38eeaed9549b"
    stream = NmapLiveStream()
    stream.publish("process_started", command_id="cmd-1", target="192.0.2.4")
    stream.publish("output", command_id="cmd-1", channel="stdout", text="Nmap output\nport line\n")
    stream.publish("progress", command_id="cmd-1", phase="SYN Scan", percent=42.0)
    stream.publish("process_exited", command_id="cmd-1", status="completed", returncode=0)
    stream.close("COMPLETED")
    app_module.scan_jobs[scan_id] = {"job_id": scan_id, "finished": True}
    app_module.nmap_live_streams[scan_id] = stream
    try:
        response = app_module.app.test_client().get(f"/api/scan/stream/{scan_id}")
        body = response.get_data(as_text=True)
        assert response.mimetype == "text/event-stream"
        assert "event: output" in body
        assert "event: progress" in body
        assert '"percent":42.0' in body
        assert "Nmap output\\nport line\\n" in body
        assert "event: assessment_end" in body
    finally:
        app_module.scan_jobs.pop(scan_id, None)
        app_module.nmap_live_streams.pop(scan_id, None)


def test_defensive_sse_delivers_subprocess_output_before_process_exit():
    scan_id = "a5df20c2-384c-4c63-93c7-38eeaed9549b"
    stream = NmapLiveStream()
    app_module.scan_jobs[scan_id] = {"job_id": scan_id, "finished": False}
    app_module.nmap_live_streams[scan_id] = stream
    script = (
        "import sys, time; "
        "print('Nmap live line', flush=True); "
        "time.sleep(0.6); "
        "print('Nmap done', flush=True)"
    )

    def publish(event):
        stream.publish(event["type"], target="127.0.0.1", **{
            key: value for key, value in event.items() if key != "type"
        })
        if event["type"] == "process_exited":
            stream.close("COMPLETED")

    worker = threading.Thread(target=lambda: run_nmap(
        [sys.executable, "-c", script, "-oX", "-", "127.0.0.1"],
        timeout=5,
        output_callback=publish,
    ))
    response = None
    try:
        worker.start()
        response = app_module.app.test_client().get(
            f"/api/scan/stream/{scan_id}",
            buffered=False,
        )
        received = ""
        for chunk in response.response:
            received += chunk.decode("utf-8")
            if '"text":"Nmap live line\\n"' in received:
                break

        assert response.mimetype == "text/event-stream"
        assert "event: output" in received
        assert '"text":"Nmap live line\\n"' in received
        assert worker.is_alive()
    finally:
        worker.join(timeout=3)
        if response is not None:
            response.close()
        app_module.scan_jobs.pop(scan_id, None)
        app_module.nmap_live_streams.pop(scan_id, None)


def test_offensive_nmap_output_stream_replays_raw_subprocess_output():
    offensive = app_module.offensive_module
    scan_id = "b4df20c2-384c-4c63-93c7-38eeaed9549b"
    stream = NmapLiveStream()
    stream.publish("process_started", command_id="cmd-1", target="192.0.2.4")
    stream.publish("output", command_id="cmd-1", channel="stderr", text="Nmap diagnostic\n")
    stream.publish("progress", command_id="cmd-1", phase="SYN Scan", percent=42.0)
    stream.publish("process_exited", command_id="cmd-1", status="completed", returncode=0)
    stream.close("COMPLETED")
    offensive.scan_jobs[scan_id] = {"scan_id": scan_id, "status": "completed"}
    offensive.nmap_live_streams[scan_id] = stream
    try:
        response = offensive.app.test_client().get(f"/api/offensive/scans/{scan_id}/stream")
        body = response.get_data(as_text=True)
        assert response.mimetype == "text/event-stream"
        assert "event: output" in body
        assert "event: progress" in body
        assert '"percent":42.0' in body
        assert "Nmap diagnostic\\n" in body
        assert "event: assessment_end" in body
    finally:
        offensive.scan_jobs.pop(scan_id, None)
        offensive.nmap_live_streams.pop(scan_id, None)


def test_scan_job_retains_actual_output_lines_and_process_metadata():
    job = {
        "nmap_commands": [{
            "target": "192.0.2.4",
            "stage": "Discovery",
            "argv": ["nmap", "192.0.2.4"],
        }],
        "nmap_output": [],
    }
    record_nmap_job_event(job, "192.0.2.4", "Discovery", {
        "type": "process_started",
        "command_id": "cmd-1",
        "argv": ["nmap", "192.0.2.4"],
        "start_time": "2026-10-06T12:00:00.000+00:00",
    })
    record_nmap_job_event(job, "192.0.2.4", "Discovery", {
        "type": "output",
        "command_id": "cmd-1",
        "channel": "stderr",
        "timestamp": "2026-10-06T12:00:00.100+00:00",
        "text": "Nmap requires elevated privileges\n",
    })
    record_nmap_job_event(job, "192.0.2.4", "Discovery", {
        "type": "process_exited",
        "command_id": "cmd-1",
        "status": "failed",
        "return_code": 1,
        "end_time": "2026-10-06T12:00:00.200+00:00",
        "duration": 0.2,
    })

    assert job["nmap_output"] == [{
        "timestamp": "2026-10-06T12:00:00.100+00:00",
        "stream": "stderr",
        "line": "Nmap requires elevated privileges",
        "target": "192.0.2.4",
        "stage": "Discovery",
        "command_id": "cmd-1",
    }]
    assert job["nmap_commands"][0]["start_time"] == "2026-10-06T12:00:00.000+00:00"
    assert job["nmap_commands"][0]["return_code"] == 1
    assert job["nmap_commands"][0]["duration"] == 0.2


def test_live_console_remains_running_between_nmap_commands():
    stream = NmapLiveStream()
    stream.publish("process_started", command_id="cmd-1")
    stream.publish("process_exited", command_id="cmd-1", status="completed", returncode=0)

    assert stream.state == "RUNNING"
    assert stream.finished is False

    stream.close("COMPLETED")
    assert stream.state == "COMPLETED"
    assert stream.finished is True


def test_offensive_custom_port_validation_rejects_nmap_option_injection():
    response = app_module.app.test_client().post(
        "/offensive/api/offensive/scans",
        json={
            "target": "127.0.0.1/32",
            "authorized": True,
            "profile": "custom",
            "custom_ports": "80 -sV",
        },
    )

    assert response.status_code == 400
    assert "Custom ports" in response.get_json()["error"]


def test_offensive_scan_cancel_endpoint_sets_worker_event():
    offensive = app_module.offensive_module
    scan_id = "4df20c2e-384c-4c63-93c7-38eeaed9549b"
    cancel_event = threading.Event()
    offensive.scan_jobs[scan_id] = {"scan_id": scan_id, "status": "running"}
    offensive.scan_cancel_events[scan_id] = cancel_event
    try:
        response = offensive.app.test_client().post(
            f"/api/offensive/scans/{scan_id}/cancel"
        )
        assert response.status_code == 200
        assert response.get_json()["status"] == "cancelling"
        assert cancel_event.is_set()
        assert offensive.scan_jobs[scan_id]["cancel_requested"] is True
    finally:
        offensive.scan_jobs.pop(scan_id, None)
        offensive.scan_cancel_events.pop(scan_id, None)


def test_vulnerability_guidance_requires_confirmation_and_scopes_saved_validation(monkeypatch):
    offensive = app_module.offensive_module
    report_id = "4df20c2e-384c-4c63-93c7-38eeaed9549b"
    finding_id = "cve:192.0.2.20:22:CVE-2024-12345"
    report = {
        "Security Findings": [{
            "id": finding_id,
            "finding_type": "cve-correlation",
            "vulnerability_status": "Potential vulnerability",
            "target": "192.0.2.20",
            "port": 22,
            "service": "ssh",
        }],
    }
    saved = {}
    monkeypatch.setattr(offensive.assessment_service, "load_report", lambda _report_id: report)
    monkeypatch.setattr(
        offensive.assessment_service,
        "save_report",
        lambda _report_id, value: saved.update(value),
    )
    client = offensive.app.test_client()

    response = client.post(
        f"/api/offensive/reports/{report_id}/guidance/authorize",
        json={"finding_id": finding_id, "authorized_lab_confirmed": False},
    )
    assert response.status_code == 403

    response = client.post(
        f"/api/offensive/reports/{report_id}/guidance/authorize",
        json={"finding_id": finding_id, "authorized_lab_confirmed": True},
    )
    assert response.status_code == 200
    token = response.get_json()["authorization_token"]

    for requested_report, requested_finding in (
        (report_id, "another-finding"),
        ("8df20c2e-384c-4c63-93c7-38eeaed9549b", finding_id),
    ):
        response = client.post(
            f"/api/offensive/reports/{requested_report}/validation",
            json={
                "finding_id": requested_finding,
                "authorization_token": token,
                "state": "VALIDATED",
                "observation": "This token must not authorize a different scope.",
            },
        )
        assert response.status_code == 403

    response = client.post(
        f"/api/offensive/reports/{report_id}/validation",
        json={
            "finding_id": finding_id,
            "authorization_token": token,
            "state": "VALIDATED",
            "observation": "The lab response matched the documented version-specific behavior.",
        },
    )
    assert response.status_code == 200
    assert saved["Vulnerability Validation"][0]["state"] == "VALIDATED"
    assert "not independently verified" in saved["Vulnerability Validation"][0]["source"].lower()

    response = client.post(
        f"/api/offensive/reports/{report_id}/validation",
        json={
            "finding_id": finding_id,
            "authorization_token": token,
            "state": "VERIFIED",
            "observation": "A re-scan after patching showed the issue is resolved.",
        },
    )
    assert response.status_code == 409

    response = client.post(
        f"/api/offensive/reports/{report_id}/validation",
        json={
            "finding_id": finding_id,
            "authorization_token": token,
            "state": "REMEDIATED",
            "observation": "The lab owner applied the documented vendor update.",
        },
    )
    assert response.status_code == 200
    response = client.post(
        f"/api/offensive/reports/{report_id}/validation",
        json={
            "finding_id": finding_id,
            "authorization_token": token,
            "state": "VERIFIED",
            "observation": "An authorized re-scan no longer reported the condition.",
        },
    )
    assert response.status_code == 200


def test_health_endpoint_reports_nmap_readiness():
    response = app_module.app.test_client().get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert isinstance(payload["nmap"], bool)
    assert payload["nmap_version"] is None or isinstance(payload["nmap_version"], str)


def test_admin_cannot_skip_discovery_for_a_subnet(monkeypatch):
    monkeypatch.setattr(
        app_module.PortScanner,
        "_has_os_detection_privileges",
        staticmethod(lambda: True),
    )
    client = app_module.app.test_client()
    with client.session_transaction() as client_session:
        client_session["_role"] = "admin"

    response = client.post(
        "/api/scan/start",
        json={
            "target": "192.0.2.0/30",
            "admin_nmap_options": {
                "scan_type": "connect",
                "discovery_method": "none",
            },
        },
    )

    assert response.status_code == 400
    assert "one explicitly selected host" in response.get_json()["error"].lower()


def test_history_detail_and_download_links_resolve_saved_reports(tmp_path, monkeypatch):
    defensive_dir = tmp_path / "defensive"
    offensive_dir = tmp_path / "offensive"
    defensive_dir.mkdir()
    offensive_dir.mkdir()
    defensive_id = "def-report-123"
    offensive_id = "off-report-123"
    (defensive_dir / f"{defensive_id}.json").write_text(
        json.dumps({
            "id": defensive_id,
            "target": "192.0.2.0/24",
            "timestamp": "2026-09-27T10:00:00",
            "status": "completed",
            "hosts_discovered": 1,
            "hosts_scanned": 1,
            "devices": [{
                "ip": "192.0.2.1",
                "hostname": "edge.example",
                "mac": "00:11:22:33:44:55",
                "vendor": "Example Vendor",
                "os": "Example OS",
                "os_accuracy": 92,
                "uptime_seconds": "3600",
                "distance": "1",
                "ports": [{
                    "port": 443,
                    "service": "https",
                    "product": "Example HTTP",
                    "cpes": ["cpe:/a:example:http"],
                    "service_confidence": "10",
                }],
            }],
        }),
        encoding="utf-8",
    )
    (offensive_dir / f"{offensive_id}.json").write_text(
        json.dumps({
            "assessment_status": "COMPLETED",
            "Scan Information": {"report_id": offensive_id, "target": "192.0.2.8"},
            "Hosts Assessed": [{"target": "192.0.2.8"}],
            "Security Findings": [],
            "Services Discovered": [],
            "Assessment Limitations": [],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "DEFENSIVE_REPORT_DIR", defensive_dir)
    monkeypatch.setattr(app_module, "OFFENSIVE_REPORT_DIR", offensive_dir)
    monkeypatch.setattr(app_module, "load_history", lambda: [])
    client = app_module.app.test_client()

    defensive_detail = client.get(f"/history/defensive/{defensive_id}")
    assert defensive_detail.status_code == 200
    assert b"Example OS (92%)" in defensive_detail.data
    assert b"00:11:22:33:44:55" in defensive_detail.data
    assert b"cpe:/a:example:http" in defensive_detail.data
    assert b"3600 seconds" in defensive_detail.data
    assert b"SERVICES" in defensive_detail.data
    assert b"FINDINGS" in defensive_detail.data
    offensive_detail = client.get(f"/history/offensive/{offensive_id}")
    assert offensive_detail.status_code == 200
    assert b"status-completed" in offensive_detail.data
    for module, report_id in (("defensive", defensive_id), ("offensive", offensive_id)):
        response = client.get(f"/history/{module}/{report_id}/export")
        assert response.status_code == 200
        assert "attachment;" in response.headers["Content-Disposition"]
        assert response.mimetype == "application/json"
    assert client.get("/history/defensive/../../outside/export").status_code == 404


def test_cancelled_history_detail_explains_missing_host_results(tmp_path, monkeypatch):
    defensive_dir = tmp_path / "defensive"
    offensive_dir = tmp_path / "offensive"
    defensive_dir.mkdir()
    offensive_dir.mkdir()
    scan_id = "cancelled-123"
    (defensive_dir / f"{scan_id}.json").write_text(
        json.dumps({
            "id": scan_id,
            "target": "192.0.2.0/24",
            "timestamp": "2026-10-05T12:00:00",
            "status": "cancelled",
            "hosts_discovered": 0,
            "hosts_scanned": 0,
            "devices": [],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "DEFENSIVE_REPORT_DIR", defensive_dir)
    monkeypatch.setattr(app_module, "OFFENSIVE_REPORT_DIR", offensive_dir)
    monkeypatch.setattr(app_module, "load_history", lambda: [])

    response = app_module.app.test_client().get(f"/history/defensive/{scan_id}")

    assert response.status_code == 200
    assert b"This scan was cancelled before host-level results were saved." in response.data
    assert b"No host-level details are available in this saved report." in response.data


def test_history_csv_export_applies_module_and_search_filters(tmp_path, monkeypatch):
    defensive_dir = tmp_path / "defensive"
    offensive_dir = tmp_path / "offensive"
    defensive_dir.mkdir()
    offensive_dir.mkdir()
    (defensive_dir / "def-456.json").write_text(
        json.dumps({
            "id": "def-456",
            "target": "198.51.100.2",
            "timestamp": "2026-09-27T10:00:00",
            "hosts_discovered": 1,
            "hosts_scanned": 1,
            "devices": [],
        }),
        encoding="utf-8",
    )
    (offensive_dir / "off-456.json").write_text(
        json.dumps({
            "assessment_status": "COMPLETED",
            "Scan Information": {
                "report_id": "off-456",
                "target": "203.0.113.8",
                "report_generated_at": "2026-09-27T11:00:00+00:00",
            },
            "Hosts Assessed": [{"target": "203.0.113.8"}],
            "Security Findings": [],
            "Assessment Limitations": [],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "DEFENSIVE_REPORT_DIR", defensive_dir)
    monkeypatch.setattr(app_module, "OFFENSIVE_REPORT_DIR", offensive_dir)
    monkeypatch.setattr(app_module, "load_history", lambda: [])

    response = app_module.app.test_client().get(
        "/history/export.csv?module=offensive&q=203.0.113.8"
    )
    content = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/csv; charset=utf-8"
    assert "attachment;" in response.headers["Content-Disposition"]
    assert "203.0.113.8" in content
    assert "198.51.100.2" not in content


def test_history_writes_are_project_path_based_and_capped(tmp_path, monkeypatch):
    history_path = tmp_path / "project-data" / "scan_history.json"
    history_path.parent.mkdir()
    monkeypatch.setattr(app_module, "HISTORY_FILE", history_path)
    monkeypatch.chdir(tmp_path)

    for index in range(52):
        app_module.save_history_entry({"id": str(index)})

    saved = app_module.load_history()
    assert history_path.is_absolute()
    assert len(saved) == 50
    assert saved[0]["id"] == "51"
    assert saved[-1]["id"] == "2"
    assert not Path(str(history_path) + ".tmp").exists()


def test_defensive_scan_uses_bounded_parallel_hosts_and_keeps_partial_results(monkeypatch):
    lock = threading.Lock()
    active = 0
    peak_active = 0

    class FakeDiscovery:
        def discover(self, target, timeout=None, cancel_event=None, activity_callback=None):
            return {
                "success": True,
                "devices": [{"ip": f"192.0.2.{index}", "ports": []} for index in range(1, 7)],
            }

    class FakePortScanner:
        def __init__(self, timeout=None):
            self.timeout = timeout

        def scan_device(self, ip, aggressive=False):
            nonlocal active, peak_active
            with lock:
                active += 1
                peak_active = max(peak_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            if ip.endswith(".6"):
                return {"success": False, "error": "host timed out"}
            return {
                "success": True,
                "hostname": ip,
                "mac": "Unknown",
                "vendor": "Unknown",
                "os": "Unknown",
                "os_accuracy": 0,
                "os_detection_status": "skipped_unprivileged",
                "ports": [],
                "open_ports": 0,
                "traceroute": [],
            }

    job_id = "parallel-scan-test"
    monkeypatch.setattr(app_module, "NetworkDiscovery", FakeDiscovery)
    monkeypatch.setattr(app_module, "PortScanner", FakePortScanner)
    monkeypatch.setattr(app_module, "SCAN_WORKERS", 3)
    monkeypatch.setattr(app_module, "finish_scan", lambda scan_id: None)
    app_module.scan_jobs[job_id] = {
        "job_id": job_id,
        "target": "192.0.2.0/29",
        "started_at": time.time(),
        "status": "starting",
        "devices": [],
        "hosts_scanned": 0,
        "open_ports": 0,
        "risks": 0,
        "finished": False,
    }
    try:
        app_module.run_scan(job_id, "192.0.2.0/29")
        job = app_module.scan_jobs[job_id]
        assert 1 < peak_active <= 3
        assert job["hosts_scanned"] == 5
        assert job["device_count"] == 6
        assert job["status"] == "partial"
        assert job["devices"][-1]["scan_error"] == "host timed out"
        assert any("OS fingerprinting was skipped" in item for item in job["limitations"])
        assert job["progress"] == 100
    finally:
        app_module.scan_jobs.pop(job_id, None)


def test_defensive_scan_can_be_cancelled_without_losing_discovery_state(tmp_path, monkeypatch):
    class WaitingDiscovery:
        @staticmethod
        def validate_target(target):
            return True

        @staticmethod
        def normalize_target(target):
            return "192.168.88.0/24"

        def discover(self, target, timeout=None, cancel_event=None, activity_callback=None):
            while not cancel_event.is_set():
                if activity_callback:
                    activity_callback("Waiting for authorized discovery process")
                time.sleep(0.01)
            return {
                "success": False,
                "status": "cancelled",
                "error": "Discovery cancelled by the operator.",
                "target": target,
                "devices": [],
            }

    monkeypatch.setattr(app_module, "NetworkDiscovery", WaitingDiscovery)
    monkeypatch.setattr(app_module, "DEFENSIVE_REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(app_module, "HISTORY_FILE", tmp_path / "scan_history.json")
    app_module.DEFENSIVE_REPORT_DIR.mkdir()
    client = app_module.app.test_client()
    started = client.post("/api/scan/start", json={"target": "192.168.88.40/24"})
    assert started.status_code == 200
    payload = started.get_json()
    job_id = payload["job_id"]
    assert payload["message"] == "Scan started"

    cancel = client.post(f"/api/scan/cancel/{job_id}")
    assert cancel.status_code == 200

    for _ in range(100):
        status = client.get(f"/api/scan/status/{job_id}").get_json()["scan"]
        if status["finished"]:
            break
        time.sleep(0.01)

    assert status["status"] == "cancelled"
    assert status["cancelled"] is True
    assert status["error"] == "Discovery cancelled by the operator."
