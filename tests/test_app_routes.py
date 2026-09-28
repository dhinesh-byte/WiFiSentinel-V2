import json
from pathlib import Path
import threading
import time

import app as app_module


def test_combined_application_routes_and_scan_authorization():
    client = app_module.app.test_client()

    assert app_module.app.debug is False
    assert client.get("/").status_code == 200
    assert client.get("/defensive").status_code == 200
    assert client.get("/offensive/").status_code == 200
    assert client.get("/history").status_code == 200
    assert client.post("/offensive/api/offensive/scans", json={"target": "192.0.2.1"}).status_code == 403
    assert client.post("/api/scan/start", json={}).status_code == 400


def test_health_endpoint_reports_nmap_readiness():
    response = app_module.app.test_client().get("/api/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert isinstance(payload["nmap"], bool)
    assert payload["nmap_version"] is None or isinstance(payload["nmap_version"], str)


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
    assert client.get(f"/history/offensive/{offensive_id}").status_code == 200
    for module, report_id in (("defensive", defensive_id), ("offensive", offensive_id)):
        response = client.get(f"/history/{module}/{report_id}/export")
        assert response.status_code == 200
        assert "attachment;" in response.headers["Content-Disposition"]
        assert response.mimetype == "application/json"
    assert client.get("/history/defensive/../../outside/export").status_code == 404


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
        def discover(self, target):
            return {
                "success": True,
                "devices": [{"ip": f"192.0.2.{index}", "ports": []} for index in range(1, 7)],
            }

    class FakePortScanner:
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
