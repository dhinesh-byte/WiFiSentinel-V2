import shutil
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as app_module


@pytest.mark.skipif(shutil.which("nmap") is None, reason="Nmap is required for the real local integration scan")
def test_real_local_scan_reaches_api_with_detailed_result(tmp_path, monkeypatch):
    """Exercise the real Flask -> discovery -> Nmap -> report response path."""
    monkeypatch.setattr(app_module, "DEFENSIVE_REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(app_module, "HISTORY_FILE", tmp_path / "scan_history.json")
    app_module.DEFENSIVE_REPORT_DIR.mkdir()

    client = app_module.app.test_client()
    started = client.post(
        "/api/scan/start",
        json={"target": "127.0.0.1/32", "profile": "standard"},
    )
    assert started.status_code == 200
    job_id = started.get_json()["job_id"]

    try:
        final_scan = None
        for _ in range(480):
            response = client.get(f"/api/scan/status/{job_id}")
            assert response.status_code == 200
            final_scan = response.get_json()["scan"]
            if final_scan["finished"]:
                break
            time.sleep(0.25)

        assert final_scan is not None
        assert final_scan["finished"] is True
        assert final_scan["status"] in {"completed", "partial"}, final_scan.get("error")
        assert final_scan["stages"]["discovery"]["status"] == "completed"
        assert isinstance(final_scan["devices"], list)
        assert isinstance(final_scan["stages"], dict)
        assert {"discovery", "port_enumeration", "service_detection", "version_detection", "risk_analysis"} <= final_scan["stages"].keys()

        for device in final_scan["devices"]:
            assert {"ip", "hostname", "mac", "vendor", "os", "ports", "risks"} <= device.keys()
            for port in device["ports"]:
                assert {"port", "protocol", "state", "service", "product", "version"} <= port.keys()

        result = client.get(f"/api/scan/result/{job_id}")
        assert result.status_code == 200
        assert result.get_json()["scan"]["devices"] == final_scan["devices"]
        assert (tmp_path / "reports" / f"{job_id}.json").is_file()
        stream = client.get(f"/api/scan/stream/{job_id}")
        stream_output = stream.get_data(as_text=True)
        assert stream.mimetype == "text/event-stream"
        assert "event: process_started" in stream_output
        assert "event: output" in stream_output
        assert "event: process_exited" in stream_output
        assert "event: assessment_end" in stream_output
    finally:
        app_module.scan_jobs.pop(job_id, None)
        app_module.nmap_live_streams.pop(job_id, None)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="Nmap is required for the real local integration scan")
def test_real_offensive_scan_streams_actual_nmap_output(tmp_path, monkeypatch):
    """Exercise the Offensive worker and SSE route with a single loopback host."""
    offensive = app_module.offensive_module
    monkeypatch.setattr(offensive.assessment_service, "report_directory", tmp_path / "offensive-reports")
    offensive.assessment_service.report_directory.mkdir()

    client = offensive.app.test_client()
    started = client.post(
        "/api/offensive/scans",
        json={
            "target": "127.0.0.1/32",
            "authorized": True,
            "profile": "quick",
            "include_web": False,
        },
    )
    assert started.status_code == 202
    scan_id = started.get_json()["scan_id"]

    try:
        final_scan = None
        for _ in range(480):
            response = client.get(f"/api/offensive/scans/{scan_id}")
            assert response.status_code == 200
            final_scan = response.get_json()
            if final_scan["status"] not in {"pending", "running"}:
                break
            time.sleep(0.25)

        assert final_scan is not None
        assert final_scan["status"] in {"completed", "partial"}, final_scan.get("errors")
        stream = client.get(f"/api/offensive/scans/{scan_id}/stream")
        stream_output = stream.get_data(as_text=True)
        assert stream.mimetype == "text/event-stream"
        assert "event: process_started" in stream_output
        assert "event: output" in stream_output
        assert "event: process_exited" in stream_output
        assert "event: assessment_end" in stream_output
        assert "stdout" in stream_output
    finally:
        offensive.scan_jobs.pop(scan_id, None)
        offensive.scan_cancel_events.pop(scan_id, None)
        offensive.nmap_live_streams.pop(scan_id, None)
