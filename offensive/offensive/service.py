"""Bounded orchestration for authorized Offensive Security assessments."""

from __future__ import annotations

import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from offensive.discovery import OffensiveDiscovery
from offensive.enumeration import OffensiveEnumerator
from offensive.cve import OfflineCVEIndex
from offensive.findings import FindingManager
from offensive.report import SecurityReport
from offensive.vulnerability import VulnerabilityAssessment
from offensive.web import WebTLSAssessment


logger = logging.getLogger(__name__)


class OffensiveAssessmentService:
    """Run the authorized discovery-to-report workflow without exploitation."""

    def __init__(
        self,
        report_directory: str | Path | None = None,
        discovery_timeout: int = 45,
        enumeration_timeout: int = 60,
        max_workers: int = 3,
        maximum_network_addresses: int = 256,
    ) -> None:
        project_root = Path(__file__).resolve().parents[1]
        self.report_directory = Path(report_directory or project_root / "reports")
        self.discovery_timeout = max(10, min(discovery_timeout, 120))
        self.enumeration_timeout = max(15, min(enumeration_timeout, 180))
        self.max_workers = max(1, min(max_workers, 8))
        self.maximum_network_addresses = max(1, maximum_network_addresses)

    def validate_target(self, target: Any) -> str:
        """Validate an IPv4 target and cap CIDR size for bounded scan duration."""
        normalized_target = OffensiveDiscovery.validate_target(target)
        network = ipaddress.ip_network(normalized_target, strict=False)
        if network.num_addresses > self.maximum_network_addresses:
            raise ValueError(
                "Target exceeds the configured maximum of "
                f"{self.maximum_network_addresses} IPv4 addresses."
            )
        return normalized_target

    def run_authorized_assessment(
        self,
        target: str,
        authorization_confirmed: bool,
        report_id: str | None = None,
        include_udp: bool = False,
        include_web: bool = True,
    ) -> dict[str, Any]:
        """Run one authorized assessment and return its structured result."""
        if authorization_confirmed is not True:
            raise PermissionError("Explicit authorization is required before scanning.")
        if not isinstance(include_udp, bool) or not isinstance(include_web, bool):
            raise ValueError("Optional assessment settings must be boolean values.")
        normalized_target = self.validate_target(target)
        report_id = self._normalize_report_id(report_id)

        logger.info("Starting authorized Offensive assessment for %s", normalized_target)
        discovery = OffensiveDiscovery(timeout=self.discovery_timeout).discover(
            normalized_target
        )
        discovery_status = self._status(discovery)

        if discovery_status == "completed":
            enumeration = self._enumerate_discovered_hosts(
                discovery.get("hosts"),
                include_udp=include_udp,
            )
        else:
            discovery_errors = self._strings(discovery.get("errors"))
            message = "Enumeration was skipped because discovery did not complete."
            enumeration = {
                "status": discovery_status or "failed",
                "hosts": [],
                "host_count": 0,
                "total_open_ports": 0,
                "errors": discovery_errors or [message],
            }

        if include_web:
            try:
                web_assessment = WebTLSAssessment(timeout=4.0).assess(enumeration)
            except Exception as exc:
                logger.exception("Web/TLS assessment failed")
                web_assessment = {
                    "status": "error",
                    "services": [],
                    "errors": [f"Web/TLS assessment error: {exc}"],
                    "limitations": [],
                }
        else:
            web_assessment = {
                "status": "completed",
                "services": [],
                "errors": [],
                "limitations": ["Web/TLS checks were not requested for this scan."],
            }

        try:
            cve_correlation = OfflineCVEIndex().correlate(enumeration)
        except Exception as exc:
            logger.exception("Offline CVE correlation failed")
            cve_correlation = {
                "status": "error",
                "matches": [],
                "errors": [f"Offline CVE correlation error: {exc}"],
                "limitations": [],
            }

        assessment = VulnerabilityAssessment().assess(
            enumeration,
            web_assessment=web_assessment,
            cve_correlation=cve_correlation,
        )
        findings = FindingManager()
        try:
            findings.add_assessment_result(assessment)
        except (TypeError, ValueError) as exc:
            logger.exception("Could not store assessment findings")
            assessment = {
                **assessment,
                "status": "error",
                "errors": [*self._strings(assessment.get("errors")), str(exc)],
            }

        scan_information = {
            "target": normalized_target,
            "scan_type": "offensive",
            "report_id": report_id,
        }
        try:
            report = SecurityReport(
                discovery_results=discovery,
                enumeration_results=enumeration,
                vulnerability_assessment=assessment,
                findings=findings,
                scan_information=scan_information,
                web_assessment=web_assessment,
                cve_correlation=cve_correlation,
            ).to_dict()
        except Exception as exc:
            logger.exception("Could not generate security report")
            return self._failed_result(
                report_id,
                normalized_target,
                discovery,
                enumeration,
                assessment,
                f"Report generation failed: {exc}",
            )

        errors = self._unique_strings(
            self._strings(discovery.get("errors"))
            + self._strings(enumeration.get("errors"))
            + self._strings(assessment.get("errors"))
            + self._strings(web_assessment.get("errors"))
            + self._strings(cve_correlation.get("errors"))
        )
        limitations = self._unique_strings(
            self._strings(report.get("Assessment Limitations"))
        )
        final_status = self._overall_status(
            discovery_status,
            self._status(enumeration),
            self._status(assessment),
            report.get("assessment_status"),
        )

        result = {
            "scan_id": report_id,
            "report_id": report_id,
            "status": final_status,
            "scan_type": "offensive",
            "target": normalized_target,
            "hosts": self._mappings(discovery.get("hosts")),
            "services": report.get("Services Discovered", []),
            "uncertain_ports": report.get("UDP States Requiring Verification", []),
            "findings": report.get("Security Findings", []),
            "web_assessment": web_assessment,
            "cve_correlation": cve_correlation,
            "statistics": report.get("Final Statistics", {}),
            "limitations": limitations,
            "errors": errors,
            "report": report,
            "settings": {"include_udp": include_udp, "include_web": include_web},
        }

        try:
            self.save_report(report_id, report)
        except OSError as exc:
            logger.exception("Could not persist report %s", report_id)
            result["status"] = "incomplete"
            result["errors"] = self._unique_strings(
                [*result["errors"], f"Report could not be saved: {exc}"]
            )
            result["limitations"] = self._unique_strings(
                [*result["limitations"], "The report is available in this scan response but was not persisted."]
            )

        logger.info(
            "Finished Offensive assessment %s with status %s",
            report_id,
            result["status"],
        )
        return result

    def _enumerate_discovered_hosts(
        self,
        discovered_hosts: Any,
        include_udp: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(discovered_hosts, list):
            return {
                "status": "failed",
                "hosts": [],
                "host_count": 0,
                "total_open_ports": 0,
                "errors": ["Discovery did not provide a valid host list."],
            }

        enumerator = OffensiveEnumerator(timeout=self.enumeration_timeout)
        valid_hosts: list[tuple[str, Mapping[str, Any]]] = []
        failed_hosts: list[dict[str, Any]] = []
        errors: list[str] = []
        for host in discovered_hosts:
            if not isinstance(host, Mapping):
                errors.append("A malformed discovered-host record was skipped.")
                continue
            raw_ip = host.get("ip")
            try:
                ip_address = enumerator.validate_ip(raw_ip)
            except ValueError as exc:
                message = f"Discovered host could not be enumerated: {exc}"
                errors.append(message)
                failed_hosts.append(
                    {
                        "status": "failed",
                        "ip": raw_ip if isinstance(raw_ip, str) else "",
                        "hostname": host.get("hostname", "Unknown"),
                        "ports": [],
                        "errors": [message],
                    }
                )
                continue
            valid_hosts.append((ip_address, host))

        enumerated_hosts: list[dict[str, Any]] = []
        if valid_hosts:
            worker_count = min(self.max_workers, len(valid_hosts))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_hosts = {
                    executor.submit(
                        self._enumerate_host,
                        enumerator,
                        ip_address,
                        include_udp,
                    ): (ip_address, host)
                    for ip_address, host in valid_hosts
                }
                for future in as_completed(future_hosts):
                    ip_address, discovered_host = future_hosts[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        logger.exception("Enumeration crashed for %s", ip_address)
                        result = {
                            "status": "failed",
                            "ip": ip_address,
                            "hostname": "Unknown",
                            "ports": [],
                            "errors": [f"Enumeration error: {exc}"],
                        }

                    if not isinstance(result, dict):
                        result = {
                            "status": "failed",
                            "ip": ip_address,
                            "hostname": "Unknown",
                            "ports": [],
                            "errors": [
                                "Enumeration returned a malformed host result."
                            ],
                        }

                    result["ip"] = result.get("ip") or ip_address
                    for field in ("hostname", "mac", "vendor", "state"):
                        if result.get(field) in (None, "", "Unknown"):
                            result[field] = discovered_host.get(field, result.get(field, "Unknown"))
                    enumerated_hosts.append(result)
                    errors.extend(self._strings(result.get("errors")))

        enumerated_hosts.extend(failed_hosts)
        usable_count = sum(
            1
            for host in enumerated_hosts
            if self._status(host) in {"completed", "partial"}
            and isinstance(host.get("ports"), list)
        )
        if not enumerated_hosts and not errors:
            status = "completed"
        elif not enumerated_hosts:
            status = "incomplete"
        elif (
            usable_count == len(enumerated_hosts)
            and all(self._status(host) == "completed" for host in enumerated_hosts)
            and not errors
        ):
            status = "completed"
        elif usable_count:
            status = "partial"
        elif any(self._status(host) == "timeout" for host in enumerated_hosts):
            status = "incomplete"
        else:
            status = "failed"

        return {
            "status": status,
            "hosts": enumerated_hosts,
            "host_count": len(enumerated_hosts),
            "total_open_ports": sum(
                len(host.get("ports", []))
                for host in enumerated_hosts
                if isinstance(host.get("ports"), list)
            ),
            "errors": self._unique_strings(errors),
        }

    @staticmethod
    def _enumerate_host(
        enumerator: OffensiveEnumerator,
        ip_address: str,
        include_udp: bool,
    ) -> dict[str, Any]:
        """Run TCP enumeration and optionally append the bounded UDP profile."""
        tcp_result = enumerator.enumerate_host(ip_address)
        if not isinstance(tcp_result, dict):
            return {
                "status": "failed",
                "ip": ip_address,
                "ports": [],
                "errors": ["TCP enumeration returned malformed host data."],
            }
        tcp_result.setdefault("uncertain_ports", [])
        if not include_udp:
            return tcp_result
        if tcp_result.get("status") != "completed":
            tcp_result["udp_status"] = "skipped"
            return tcp_result

        udp_result = enumerator.enumerate_udp_host(ip_address)
        if not isinstance(udp_result, Mapping):
            udp_result = {
                "status": "failed",
                "ports": [],
                "uncertain_ports": [],
                "errors": ["UDP enumeration returned malformed data."],
            }
        udp_status = udp_result.get("status")
        tcp_result["udp_status"] = udp_status
        tcp_ports = tcp_result.get("ports")
        udp_ports = udp_result.get("ports")
        uncertain_ports = udp_result.get("uncertain_ports", [])
        if not isinstance(tcp_ports, list) or not isinstance(udp_ports, list):
            tcp_result["status"] = "partial"
            tcp_result.setdefault("errors", []).append(
                "UDP results could not be merged because port data was malformed."
            )
            return tcp_result

        tcp_result["ports"] = [*tcp_ports, *udp_ports]
        if isinstance(uncertain_ports, list):
            tcp_result["uncertain_ports"].extend(uncertain_ports)
        if udp_status != "completed":
            tcp_result["status"] = "partial"
            tcp_result.setdefault("errors", []).extend(
                OffensiveAssessmentService._strings(udp_result.get("errors"))
                or ["Selected UDP enumeration did not complete."]
            )
        return tcp_result

    def save_report(self, report_id: str, report: Mapping[str, Any]) -> Path:
        """Persist a report using a validated UUID filename."""
        safe_id = self._normalize_report_id(report_id)
        self.report_directory.mkdir(parents=True, exist_ok=True)
        destination = self.report_directory / f"{safe_id}.json"
        temporary = self.report_directory / f"{safe_id}.json.tmp"
        temporary.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination

    def load_report(self, report_id: str) -> dict[str, Any] | None:
        """Load a persisted report by its UUID, returning None when absent."""
        safe_id = self._normalize_report_id(report_id)
        path = self.report_directory / f"{safe_id}.json"
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Stored report is not a JSON object.")
        return data

    @staticmethod
    def _normalize_report_id(report_id: str | None) -> str:
        try:
            return str(UUID(report_id)) if report_id else str(uuid4())
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Report ID must be a valid UUID.") from exc

    @staticmethod
    def _overall_status(
        discovery_status: str,
        enumeration_status: str,
        assessment_status: str,
        report_status: Any,
    ) -> str:
        if discovery_status == "failed" or enumeration_status == "failed":
            return "failed"
        if discovery_status == "timeout":
            return "incomplete"
        if enumeration_status == "partial":
            return "partial"
        if (
            discovery_status != "completed"
            or enumeration_status != "completed"
            or assessment_status != "completed"
            or report_status != "COMPLETED"
        ):
            return "incomplete"
        return "completed"

    @staticmethod
    def _failed_result(
        report_id: str,
        target: str,
        discovery: Mapping[str, Any],
        enumeration: Mapping[str, Any],
        assessment: Mapping[str, Any],
        error: str,
    ) -> dict[str, Any]:
        return {
            "scan_id": report_id,
            "report_id": report_id,
            "status": "failed",
            "scan_type": "offensive",
            "target": target,
            "hosts": OffensiveAssessmentService._mappings(discovery.get("hosts")),
            "services": [],
            "findings": [],
            "statistics": {},
            "limitations": ["Report generation failed; findings and statistics are unavailable."],
            "errors": [error],
            "report": None,
        }

    @staticmethod
    def _status(data: Mapping[str, Any]) -> str:
        value = data.get("status")
        return value.strip().lower() if isinstance(value, str) else ""

    @staticmethod
    def _strings(values: Any) -> list[str]:
        if not isinstance(values, (list, tuple)):
            return []
        return [value.strip() for value in values if isinstance(value, str) and value.strip()]

    @staticmethod
    def _mappings(values: Any) -> list[dict[str, Any]]:
        if not isinstance(values, list):
            return []
        return [dict(value) for value in values if isinstance(value, Mapping)]

    @staticmethod
    def _unique_strings(values: list[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))
