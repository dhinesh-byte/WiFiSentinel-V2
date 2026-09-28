import json

from history_data import collect_activity, load_detail, module_freshness


def test_collect_activity_skips_malformed_reports_and_orders_modules(tmp_path):
    defensive_dir = tmp_path / "defensive"
    offensive_dir = tmp_path / "offensive"
    defensive_dir.mkdir()
    offensive_dir.mkdir()
    (defensive_dir / "broken.json").write_text("{invalid", encoding="utf-8")
    (defensive_dir / "def-123.json").write_text(
        json.dumps({
            "id": "def-123",
            "target": "192.0.2.0/24",
            "timestamp": "2026-09-27T10:00:00",
            "status": "partial",
            "hosts_discovered": 2,
            "hosts_scanned": 1,
            "devices": [{"ip": "192.0.2.1", "ports": []}],
            "limitations": ["one host failed"],
        }),
        encoding="utf-8",
    )
    (offensive_dir / "off-123.json").write_text(
        json.dumps({
            "assessment_status": "COMPLETED",
            "Scan Information": {
                "report_id": "off-123",
                "target": "192.0.2.8",
                "report_generated_at": "2026-09-27T11:00:00+00:00",
            },
            "Hosts Assessed": [{"target": "192.0.2.8"}],
            "Security Findings": [{}],
            "Assessment Limitations": ["web check skipped"],
        }),
        encoding="utf-8",
    )

    records = collect_activity([], defensive_dir, offensive_dir)

    assert [record["module_key"] for record in records] == ["offensive", "defensive"]
    assert records[1]["coverage"] == "1/2 hosts checked"
    assert module_freshness(records)["offensive"]["limitations"] == ["web check skipped"]


def test_legacy_summary_has_detail_fallback_and_rejects_path_traversal(tmp_path):
    history = [{"target": "192.0.2.0/24", "timestamp": "2026-09-27T10:00:00", "devices": 4}]
    records = collect_activity(history, tmp_path, tmp_path)

    assert records[0]["scan_id"] == "legacy-0"
    detail = load_detail("defensive", "legacy-0", tmp_path, tmp_path, history)
    assert detail is not None
    assert detail["hosts"] == []
    assert "summary counts only" in detail["limitations"][0]
    assert load_detail("defensive", "../outside", tmp_path, tmp_path, history) is None
