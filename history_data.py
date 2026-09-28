"""Normalize saved defensive scans and offensive reports for the UI."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SAFE_REPORT_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as report_file:
            value = json.load(report_file)
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _number(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return default


def _date_key(value: Any) -> float:
    if not isinstance(value, str) or not value:
        return 0.0
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.timestamp()
    except ValueError:
        return 0.0


def _iso_date(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def collect_activity(
    defensive_history: Any,
    defensive_report_dir: Path,
    offensive_report_dir: Path,
) -> list[dict[str, Any]]:
    """Read valid history records and reports, skipping malformed files."""
    history = defensive_history if isinstance(defensive_history, list) else []
    defensive_reports: dict[str, dict[str, Any]] = {}
    for path in defensive_report_dir.glob("*.json") if defensive_report_dir.is_dir() else []:
        report = _read_json(path)
        if report is not None:
            report_id = str(report.get("id") or path.stem)
            if SAFE_REPORT_ID.fullmatch(report_id):
                defensive_reports[report_id] = report

    activity: list[dict[str, Any]] = []
    linked_defensive_ids: set[str] = set()
    for history_index, summary in enumerate(history):
        if not isinstance(summary, dict):
            continue
        raw_id = summary.get("id")
        scan_id = str(raw_id) if raw_id is not None else ""
        if not SAFE_REPORT_ID.fullmatch(scan_id):
            scan_id = f"legacy-{history_index}"
        report = defensive_reports.get(scan_id) if scan_id else None
        if report is not None:
            linked_defensive_ids.add(scan_id)
        data = {**summary, **(report or {})}
        devices = _as_list(data.get("devices"))
        discovered = _number(data.get("hosts_discovered", data.get("device_count", data.get("devices"))))
        if isinstance(data.get("devices"), list):
            discovered = _number(data.get("hosts_discovered", data.get("device_count", len(devices))))
        scanned_value = data.get("hosts_scanned")
        scanned = _number(scanned_value) if scanned_value is not None else (len(devices) if report else None)
        status = str(data.get("status", "completed")).replace("_", " ").title()
        limitations = _as_list(data.get("limitations"))
        if report is None:
            limitations = limitations or ["This older history entry contains summary counts only."]
        activity.append({
            "module": "Defensive",
            "module_key": "defensive",
            "scan_id": scan_id or str(summary.get("timestamp", "legacy"))[:40],
            "target": str(data.get("target") or data.get("network") or "Unknown target"),
            "timestamp": _iso_date(data.get("timestamp")),
            "status": status,
            "host_count": discovered,
            "hosts_scanned": scanned,
            "port_count": _number(data.get("open_ports")),
            "finding_count": _number(data.get("risks")),
            "detail": f"{discovered} discovered · {scanned if scanned is not None else '—'} checked",
            "coverage": f"{scanned}/{discovered} hosts checked" if scanned is not None else f"{discovered} hosts discovered; check coverage unavailable",
            "limitations": [str(item) for item in limitations if item],
            "detail_available": report is not None,
            "detail_url": f"/history/defensive/{scan_id}" if scan_id else "/history",
            "export_url": f"/history/defensive/{scan_id}/export" if scan_id else "",
            "metrics": {
                "Hosts discovered": discovered,
                "Hosts checked": scanned,
                "Open ports": _number(data.get("open_ports")),
                "Risks": _number(data.get("risks")),
            },
        })

    for scan_id, report in defensive_reports.items():
        if scan_id in linked_defensive_ids:
            continue
        devices = _as_list(report.get("devices"))
        discovered = _number(report.get("hosts_discovered", report.get("device_count", len(devices))))
        scanned_value = report.get("hosts_scanned")
        scanned = _number(scanned_value) if scanned_value is not None else len(devices)
        limitations = _as_list(report.get("limitations"))
        activity.append({
            "module": "Defensive",
            "module_key": "defensive",
            "scan_id": scan_id,
            "target": str(report.get("target") or report.get("network") or "Unknown target"),
            "timestamp": _iso_date(report.get("timestamp")),
            "status": str(report.get("status", "completed")).replace("_", " ").title(),
            "host_count": discovered,
            "hosts_scanned": scanned,
            "port_count": _number(report.get("open_ports")),
            "finding_count": _number(report.get("risks")),
            "detail": f"{discovered} discovered · {scanned} checked",
            "coverage": f"{scanned}/{discovered} hosts checked",
            "limitations": [str(item) for item in limitations if item],
            "detail_available": True,
            "detail_url": f"/history/defensive/{scan_id}",
            "export_url": f"/history/defensive/{scan_id}/export",
            "metrics": {
                "Hosts discovered": discovered,
                "Hosts checked": scanned,
                "Open ports": _number(report.get("open_ports")),
                "Risks": _number(report.get("risks")),
            },
        })

    if offensive_report_dir.is_dir():
        for path in offensive_report_dir.glob("*.json"):
            report = _read_json(path)
            if report is None:
                continue
            scan_information = report.get("Scan Information")
            if not isinstance(scan_information, dict):
                scan_information = {}
            scan_id = str(scan_information.get("report_id") or path.stem)
            if not SAFE_REPORT_ID.fullmatch(scan_id):
                continue
            hosts = _as_list(report.get("Hosts Assessed"))
            findings = _as_list(report.get("Security Findings"))
            limitations = _as_list(report.get("Assessment Limitations"))
            statistics = report.get("Final Statistics")
            if not isinstance(statistics, dict):
                statistics = {}
            discovered = _number(statistics.get("Hosts discovered", len(hosts)))
            assessed = _number(statistics.get("Hosts assessed", len(hosts)))
            open_ports = _number(statistics.get("Open ports", len(_as_list(report.get("Services Discovered")))))
            services_identified = _number(statistics.get("Services identified", len(_as_list(report.get("Services Discovered")))))
            activity.append({
                "module": "Offensive",
                "module_key": "offensive",
                "scan_id": scan_id,
                "target": str(scan_information.get("target") or "Unknown target"),
                "timestamp": _iso_date(scan_information.get("report_generated_at")),
                "status": str(report.get("assessment_status", "completed")).replace("_", " ").title(),
                "host_count": discovered,
                "hosts_scanned": assessed,
                "port_count": open_ports,
                "finding_count": len(findings),
                "detail": f"{assessed} hosts assessed · {len(findings)} findings",
                "coverage": f"{assessed}/{discovered or assessed} hosts assessed",
                "limitations": [str(item) for item in limitations if item],
                "detail_available": True,
                "detail_url": f"/history/offensive/{scan_id}",
                "export_url": f"/history/offensive/{scan_id}/export",
                "metrics": {
                    "Hosts discovered": discovered,
                    "Hosts assessed": assessed,
                    "Open ports": open_ports,
                    "Services": services_identified,
                    "Findings": len(findings),
                    "CVE matches": len(_as_list(report.get("CVE Matches"))),
                },
            })

    activity.sort(key=lambda item: _date_key(item["timestamp"]), reverse=True)
    return activity


def module_freshness(activity: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Summarize each module's latest run, coverage, and limitations."""
    latest: dict[str, dict[str, Any]] = {}
    for item in activity:
        key = item["module_key"]
        if key not in latest:
            latest[key] = item
    result = {}
    for key, label in (("defensive", "Defensive"), ("offensive", "Offensive")):
        item = latest.get(key)
        result[key] = {
            "module": label,
            "last_run": item["timestamp"] if item else "Never",
            "status": item["status"] if item else "No saved runs",
            "coverage": item["coverage"] if item else "No scan coverage available",
            "limitations": item["limitations"] if item else [],
            "stale_days": max(0, int((datetime.now(timezone.utc).timestamp() - _date_key(item["timestamp"])) // 86400)) if item and item["timestamp"] else None,
        }
    return result


def load_detail(
    module: str,
    scan_id: str,
    defensive_report_dir: Path,
    offensive_report_dir: Path,
    defensive_history: Any,
) -> dict[str, Any] | None:
    """Resolve one safe report ID and normalize it for a detail page."""
    if not SAFE_REPORT_ID.fullmatch(scan_id):
        return None
    module_key = module.lower()
    if module_key == "defensive":
        report = _read_json(defensive_report_dir / f"{scan_id}.json")
        if report is None:
            history = defensive_history if isinstance(defensive_history, list) else []
            report = next(
                (
                    entry
                    for index, entry in enumerate(history)
                    if isinstance(entry, dict)
                    and (
                        str(entry.get("id")) == scan_id
                        or (not entry.get("id") and f"legacy-{index}" == scan_id)
                    )
                ),
                None,
            )
        if report is None:
            return None
        source_hosts = _as_list(report.get("devices"))
        hosts = []
        findings = []
        services = []
        for device in source_hosts:
            if not isinstance(device, dict):
                continue
            ports = _as_list(device.get("ports"))
            risk = device.get("risk")
            risk_list = _as_list(device.get("risks"))
            if isinstance(risk, dict):
                findings.extend(str(reason) for reason in _as_list(risk.get("reasons")))
            for finding in risk_list:
                if isinstance(finding, dict):
                    findings.append(str(finding.get("title") or finding.get("description") or "Security risk"))
                else:
                    findings.append(str(finding))
            for port in ports:
                if isinstance(port, dict):
                    services.append({"host": device.get("ip", ""), **port})
            hosts.append({
                "ip": device.get("ip") or device.get("target") or "Unknown",
                "hostname": device.get("hostname") or "Unknown",
                "mac": device.get("mac") or "Unknown",
                "vendor": device.get("vendor") or "Unknown",
                "status": device.get("status") or "Observed",
                "os": device.get("os") or "Unknown",
                "os_accuracy": _number(device.get("os_accuracy")),
                "os_matches": _as_list(device.get("os_matches")),
                "uptime_seconds": device.get("uptime_seconds"),
                "last_boot": device.get("last_boot"),
                "distance": device.get("distance"),
                "status_reason": device.get("status_reason") or "",
                "host_scripts": _as_list(device.get("host_scripts")),
                "ports": ports,
                "risk": risk if isinstance(risk, dict) else {},
                "risks": risk_list,
            })
        discovered = _number(report.get("hosts_discovered", report.get("device_count", len(source_hosts))))
        scanned = report.get("hosts_scanned")
        return {
            "module": "Defensive",
            "target": report.get("target") or report.get("network") or "Unknown target",
            "timestamp": report.get("timestamp", ""),
            "status": str(report.get("status", "summary only")).replace("_", " ").title(),
            "coverage": f"{_number(scanned, len(hosts))}/{discovered} hosts checked" if scanned is not None or source_hosts else f"{discovered} hosts discovered; detailed coverage unavailable",
            "hosts": hosts,
            "services": services,
            "findings": findings,
            "limitations": _as_list(report.get("limitations")) or ([] if source_hosts else ["This older history record has summary counts only; device-level detail was not retained."]),
            "errors": [report["error"]] if report.get("error") else [],
            "raw": report,
        }

    if module_key == "offensive":
        report = _read_json(offensive_report_dir / f"{scan_id}.json")
        if report is None:
            return None
        scan_information = report.get("Scan Information")
        if not isinstance(scan_information, dict):
            scan_information = {}
        source_hosts = _as_list(report.get("Hosts Assessed"))
        hosts = [
            {
                "ip": host.get("target", "Unknown") if isinstance(host, dict) else "Unknown",
                "hostname": (host.get("hostname") or "Unknown") if isinstance(host, dict) else "Unknown",
                "status": host.get("status", "Assessed") if isinstance(host, dict) else "Assessed",
                "ports": [],
                "open_ports": _number(host.get("open_ports")) if isinstance(host, dict) else 0,
                "risk": {},
                "risks": [],
            }
            for host in source_hosts
        ]
        services = _as_list(report.get("Services Discovered"))
        findings = _as_list(report.get("Security Findings"))
        errors = _as_list(report.get("errors"))
        return {
            "module": "Offensive",
            "target": scan_information.get("target", "Unknown target"),
            "timestamp": scan_information.get("report_generated_at", ""),
            "status": str(report.get("assessment_status", "unknown")).replace("_", " ").title(),
            "coverage": f"{len(hosts)}/{len(hosts)} hosts assessed" if hosts else "No hosts assessed",
            "hosts": hosts,
            "services": services,
            "findings": findings,
            "limitations": _as_list(report.get("Assessment Limitations")),
            "errors": errors,
            "raw": report,
        }
    return None
