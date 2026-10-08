"""Build bounded AI context from validated, persisted VulnScan reports."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from history_data import SAFE_REPORT_ID, load_detail

from .schemas import MAX_CONTEXT_CHARS
from .safety import redact_sensitive_text

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _clean_nested(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return "[truncated]"
    if isinstance(value, str):
        return _text(value, 500)
    if isinstance(value, list):
        return [_clean_nested(item, depth + 1) for item in value[:20]]
    if isinstance(value, dict):
        return {
            _text(key, 80): _clean_nested(item, depth + 1)
            for key, item in list(value.items())[:30]
            if isinstance(key, str)
        }
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _text(value, 200)


class ContextNotFound(ValueError):
    pass


def _text(value: Any, limit: int = 320) -> str:
    if value is None:
        return ""
    value = redact_sensitive_text(_CONTROL_CHARS.sub("", str(value)).strip())
    return value[:limit]


def load_scan_report(module, scan_id, defensive_dir: Path, offensive_dir: Path, history):
    if module not in {"defensive", "offensive"} or not isinstance(scan_id, str) or not SAFE_REPORT_ID.fullmatch(scan_id):
        raise ContextNotFound("The selected assessment was not found.")
    report_dir = defensive_dir if module == "defensive" else offensive_dir
    path = report_dir / f"{scan_id}.json"
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError):
            report = None
        if isinstance(report, dict):
            return report
    if module == "defensive":
        detail = load_detail("defensive", scan_id, defensive_dir, offensive_dir, history)
        if detail is not None and isinstance(detail.get("raw"), dict):
            return detail["raw"]
    raise ContextNotFound("The selected assessment was not found or has no saved details.")


def _defensive_records(report):
    hosts = []
    findings = []
    services = []
    for device in report.get("devices", []) if isinstance(report.get("devices"), list) else []:
        if not isinstance(device, dict):
            continue
        ip = _text(device.get("ip") or device.get("target") or "Unknown", 80)
        ports = []
        for port in device.get("ports", []) if isinstance(device.get("ports"), list) else []:
            if not isinstance(port, dict):
                continue
            entry = {
                key: _clean_nested(port.get(key)) if key in {"evidence", "scripts", "cpes"} else _text(port.get(key), 220)
                for key in ("port", "protocol", "state", "service", "product", "version", "service_method", "service_confidence", "reason", "evidence", "scripts", "cpes")
                if port.get(key) is not None
            }
            ports.append(entry)
            if str(port.get("state", "")).lower() == "open":
                services.append({"target": ip, **entry})
        host = {
            "id": ip,
            "ip": ip,
            "hostname": _text(device.get("hostname"), 160),
            "mac": _text(device.get("mac"), 80),
            "vendor": _text(device.get("vendor"), 160),
            "os": _text(device.get("os"), 200),
            "os_accuracy": _text(device.get("os_accuracy"), 30),
            "ports": ports[:60],
            "risk": device.get("risk") if isinstance(device.get("risk"), dict) else {},
            "host_scripts": _clean_nested(device.get("host_scripts", [])),
        }
        hosts.append(host)
        for risk in device.get("risks", []) if isinstance(device.get("risks"), list) else []:
            if not isinstance(risk, dict):
                continue
            finding_id = f"def:{ip}:{_text(risk.get('port'), 12)}:{_text(risk.get('title'), 120)}"
            port_record = next((
                port for port in ports
                if str(port.get("port")) == str(risk.get("port"))
                and str(port.get("protocol") or "tcp").lower() == "tcp"
            ), {})
            script_evidence = [
                script for script in [
                    *(port_record.get("scripts", []) if isinstance(port_record.get("scripts"), list) else []),
                    *(host.get("host_scripts", []) if isinstance(host.get("host_scripts"), list) else []),
                ]
                if isinstance(script, dict)
            ]
            explicit_vulnerability = next((
                script for script in script_evidence
                if re.search(r"(?im)^\s*(?:\|\s*)?State:\s*VULNERABLE\s*$", str(script.get("output", "")))
            ), None)
            evidence = [
                _text(item, 500)
                for item in port_record.get("evidence", [])
                if isinstance(item, str) and item.strip()
            ] if isinstance(port_record.get("evidence"), list) else []
            if port_record.get("state"):
                protocol = _text(port_record.get("protocol") or "tcp", 8).upper()
                state = _text(port_record.get("state"), 24).upper()
                reason = _text(port_record.get("reason"), 80)
                observation = f"Nmap observed {protocol}/{port_record.get('port')} {state}"
                evidence.append(f"{observation} ({reason})." if reason else f"{observation}.")
            for script in script_evidence:
                script_id = _text(script.get("id"), 100)
                output = _text(script.get("output"), 500)
                if script_id and output:
                    evidence.append(f"Nmap NSE {script_id}: {output}")
            service = _text(risk.get("service") or port_record.get("service"), 100)
            service_confidence = port_record.get("service_confidence")
            confidence = (
                f"Nmap service match {service_confidence}/10"
                if str(service_confidence).isdigit()
                else "Not scored by the Defensive risk engine"
            )
            cve_match = re.search(
                r"\bCVE-\d{4}-\d{4,}\b",
                str(explicit_vulnerability.get("output", "")) if explicit_vulnerability else "",
                re.IGNORECASE,
            )
            findings.append({
                "id": finding_id,
                "title": _text(risk.get("title") or risk.get("description") or "Security observation"),
                "severity": _text(risk.get("severity") or "unknown", 24),
                "host": ip,
                "port": risk.get("port"),
                "protocol": _text(port_record.get("protocol") or "tcp", 8),
                "service": service,
                "product": _text(port_record.get("product"), 160),
                "version": _text(port_record.get("version"), 120),
                "confidence": confidence,
                "vulnerability_status": "CONFIRMED" if explicit_vulnerability else "UNKNOWN",
                "cve_id": cve_match.group(0).upper() if cve_match else None,
                "evidence": evidence or [f"Defensive risk analysis identified {risk.get('title') or 'this observation'} on {ip}; detailed port evidence was not saved."],
                "description": _text(risk.get("description")),
                "recommendation": _text(risk.get("protection")),
                "source": "Defensive risk analysis",
            })
    return hosts, findings, services


def _offensive_records(report):
    source_hosts = report.get("Hosts Assessed", [])
    hosts = []
    for source in source_hosts if isinstance(source_hosts, list) else []:
        if not isinstance(source, dict):
            continue
        ip = _text(source.get("target") or source.get("ip") or "Unknown", 80)
        hosts.append({
            "id": ip,
            "ip": ip,
            "hostname": _text(source.get("hostname"), 160),
            "mac": _text(source.get("mac"), 80),
            "vendor": _text(source.get("vendor"), 160),
            "os": _text(source.get("os"), 200),
            "status": _text(source.get("status"), 40),
            "open_ports": source.get("open_ports"),
            "services_identified": source.get("services_identified"),
        })
    services = []
    for source in report.get("Services Discovered", []) if isinstance(report.get("Services Discovered"), list) else []:
        if isinstance(source, dict):
            services.append({key: _text(source.get(key), 260) for key in (
                "target", "port", "protocol", "service", "product", "version", "state", "method", "confidence", "evidence", "cpes"
            ) if source.get(key) is not None})
    validation_records = report.get("Vulnerability Validation", [])
    validation_records = validation_records if isinstance(validation_records, list) else []
    findings = []
    source_services = [
        source for source in report.get("Services Discovered", [])
        if isinstance(source, dict)
    ] if isinstance(report.get("Services Discovered"), list) else []
    for index, source in enumerate(report.get("Security Findings", []) if isinstance(report.get("Security Findings"), list) else []):
        if not isinstance(source, dict):
            continue
        finding = {key: source.get(key) for key in (
            "id", "title", "severity", "confidence", "target", "port", "protocol", "service", "product", "version", "evidence", "description", "impact", "remediation", "detection_method", "vulnerability_status", "cve_id", "finding_type", "observed_cpe"
        ) if source.get(key) is not None}
        finding["risk"] = _text(source.get("severity"), 24)
        finding["user_validation_records"] = [
            {
                "state": _text(record.get("state"), 40),
                "observation": _text(record.get("observation"), 500),
                "timestamp": _text(record.get("timestamp"), 80),
                "source": _text(record.get("source"), 120),
            }
            for record in validation_records
            if isinstance(record, dict) and record.get("finding_id") == source.get("id")
        ][:10]
        finding["id"] = _text(finding.get("id") or f"off:{index}", 120)
        matching_services = [
            service for service in source_services
            if service.get("target") == finding.get("target")
            and str(service.get("port")) == str(finding.get("port"))
            and str(service.get("protocol") or "tcp").lower() == str(finding.get("protocol") or "tcp").lower()
        ]
        finding["nmap_evidence"] = [
            _text(value, 300)
            for service in matching_services
            for value in (service.get("evidence") if isinstance(service.get("evidence"), list) else [])
            if isinstance(value, str)
        ][:12]
        finding["nse_evidence"] = [
            {
                "id": _text(script.get("id"), 100),
                "output": _text(script.get("output"), 500),
            }
            for service in matching_services
            for script in (service.get("scripts") if isinstance(service.get("scripts"), list) else [])
            if isinstance(script, dict)
        ][:12]
        guidance = source.get("exploitation_guidance")
        if isinstance(guidance, dict):
            finding["exploitation_guidance"] = _clean_nested(guidance)
        for key, value in list(finding.items()):
            if isinstance(value, str):
                finding[key] = _text(value, 500)
            elif isinstance(value, list):
                if key == "nse_evidence":
                    finding[key] = [
                        {"id": _text(item.get("id"), 100), "output": _text(item.get("output"), 500)}
                        for item in value[:12] if isinstance(item, dict)
                    ]
                elif key == "user_validation_records":
                    finding[key] = [
                        {
                            "state": _text(item.get("state"), 40),
                            "observation": _text(item.get("observation"), 500),
                            "timestamp": _text(item.get("timestamp"), 80),
                            "source": _text(item.get("source"), 120),
                        }
                        for item in value[:10] if isinstance(item, dict)
                    ]
                else:
                    finding[key] = [_text(item, 300) for item in value[:12] if isinstance(item, str)]
        findings.append(finding)
    return hosts, findings, services


def _report_records(module, report):
    return _defensive_records(report) if module == "defensive" else _offensive_records(report)


def _scan_summary(module, report, hosts, findings, services):
    if module == "defensive":
        return {
            "module": "defensive",
            "scan_id": _text(report.get("id"), 80),
            "target": _text(report.get("target") or report.get("network"), 160),
            "profile": _text(report.get("profile") or (report.get("admin_nmap_options") or {}).get("assessment_profile"), 40),
            "timestamp": _text(report.get("timestamp"), 80),
            "status": _text(report.get("status"), 40),
            "hosts_discovered": report.get("hosts_discovered", report.get("device_count", len(hosts))),
            "hosts_scanned": report.get("hosts_scanned"),
            "open_ports": report.get("open_ports"),
            "limitations": [_text(item, 300) for item in report.get("limitations", [])[:12]] if isinstance(report.get("limitations"), list) else [],
        }
    info = report.get("Scan Information") if isinstance(report.get("Scan Information"), dict) else {}
    return {
        "module": "offensive",
        "scan_id": _text(info.get("report_id"), 80),
        "target": _text(info.get("target"), 160),
        "timestamp": _text(info.get("report_generated_at"), 80),
        "status": _text(report.get("assessment_status"), 40),
        "host_count": len(hosts),
        "service_count": len(services),
        "finding_count": len(findings),
        "limitations": [_text(item, 300) for item in report.get("Assessment Limitations", [])[:12]] if isinstance(report.get("Assessment Limitations"), list) else [],
    }


def _comparison(module, current_report, previous_report):
    current = _report_records(module, current_report)
    previous = _report_records(module, previous_report)

    def keys(records, index, key_fn):
        return {key_fn(item): item for item in records[index]}

    host_key = lambda item: item.get("ip", "Unknown")
    port_key = lambda item: f"{item.get('target', item.get('ip', '?'))}/{item.get('protocol') or 'tcp'}/{item.get('port', '?')}"
    finding_key = lambda item: str(item.get("id") or f"{item.get('host', item.get('target', '?'))}:{item.get('title', '?')}")
    deltas = {}
    for label, index, key_fn in (("hosts", 0, host_key), ("services", 2, port_key), ("findings", 1, finding_key)):
        now = keys(current, index, key_fn)
        before = keys(previous, index, key_fn)
        deltas[label] = {
            "added": [now[key] for key in sorted(now.keys() - before.keys())][:20],
            "removed": [before[key] for key in sorted(before.keys() - now.keys())][:20],
        }
    return {"previous_scan_id": _text((previous_report.get("Scan Information", {}) if module == "offensive" else previous_report).get("report_id") or previous_report.get("id"), 80), "changes": deltas}


def build_scan_context(module, scan_id, host_id, finding_id, service_id, compare_scan_id, defensive_dir, offensive_dir, history):
    report = load_scan_report(module, scan_id, defensive_dir, offensive_dir, history)
    hosts, findings, services = _report_records(module, report)
    summary = _scan_summary(module, report, hosts, findings, services)
    selected_host = None
    selected_finding = None
    selected_service = None

    if finding_id:
        selected_finding = next((item for item in findings if item.get("id") == finding_id), None)
        if selected_finding is None:
            raise ContextNotFound("The selected finding is not part of this assessment.")
        finding_host = selected_finding.get("host") or selected_finding.get("target")
        selected_host = next((item for item in hosts if item.get("ip") == finding_host), None)
        if host_id and (selected_host is None or selected_host["ip"] != host_id):
            raise ContextNotFound("The selected finding does not belong to that host.")
        host_id = selected_host["ip"] if selected_host else host_id
    if host_id:
        selected_host = next((item for item in hosts if item.get("ip") == host_id), None)
        if selected_host is None:
            raise ContextNotFound("The selected host is not part of this assessment.")
    if service_id:
        selected_service = next((item for item in services if f"{item.get('target', item.get('host', '?'))}:{item.get('port', '?')}/{item.get('protocol') or 'tcp'}" == service_id), None)
        if selected_service is None:
            raise ContextNotFound("The selected service is not part of this assessment.")
        if not selected_host:
            service_host = selected_service.get("target") or selected_service.get("host")
            selected_host = next((item for item in hosts if item.get("ip") == service_host), None)

    if selected_finding:
        if module == "defensive":
            selected_ip = (selected_host or {}).get("ip")
            relevant_findings = [
                item for item in findings if item.get("host") == selected_ip
            ][:20]
        else:
            relevant_findings = [selected_finding]
        relevant_services = [item for item in services if item.get("target", item.get("host")) == (selected_host or {}).get("ip") and str(item.get("port")) == str(selected_finding.get("port"))]
        relevant_hosts = [selected_host] if selected_host else []
    elif selected_host:
        relevant_hosts = [selected_host]
        relevant_findings = [item for item in findings if (item.get("host") or item.get("target")) == selected_host["ip"]][:20]
        relevant_services = [item for item in services if item.get("target", item.get("host")) == selected_host["ip"]][:40]
    elif selected_service:
        relevant_hosts = [selected_host] if selected_host else []
        relevant_findings = []
        relevant_services = [selected_service]
    else:
        relevant_hosts = hosts[:20]
        relevant_findings = findings[:30]
        relevant_services = services[:40]

    context = {
        "assessment": summary,
        "selected_host": relevant_hosts[0] if host_id and relevant_hosts else None,
        "selected_service": selected_service,
        "selected_finding": selected_finding,
        "hosts": relevant_hosts,
        "services": relevant_services,
        "findings": relevant_findings,
        "available_services": relevant_services[:40],
    }
    if compare_scan_id:
        if compare_scan_id == scan_id:
            raise ContextNotFound("Choose a different assessment to compare.")
        older = load_scan_report(module, compare_scan_id, defensive_dir, offensive_dir, history)
        context["comparison"] = _comparison(module, report, older)
    encoded = json.dumps(context, ensure_ascii=True, separators=(",", ":"))
    if len(encoded) > MAX_CONTEXT_CHARS:
        raise ContextNotFound("The selected assessment context is too large to send safely.")
    return context


def context_summary(context):
    assessment = context.get("assessment", {})
    if context.get("selected_finding"):
        selected = context["selected_finding"]
        return f"{assessment.get('module', 'scan').title()} finding: {selected.get('title', 'finding')} on {selected.get('host') or selected.get('target') or 'host'}"
    if context.get("selected_host"):
        return f"{assessment.get('module', 'scan').title()} host: {context['selected_host'].get('ip', 'unknown')}"
    return f"{assessment.get('module', 'scan').title()} assessment: {assessment.get('target', 'target unavailable')}"