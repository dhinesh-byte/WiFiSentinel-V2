"""Bounded orchestration for authorized Offensive Security assessments."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from pathlib import Path
from collections.abc import Mapping
from threading import Event
from typing import Any
from uuid import UUID, uuid4

from offensive.discovery import OffensiveDiscovery
from offensive.enumeration import OffensiveEnumerator, SAFE_NSE_MODULES
from offensive.cve import OfflineCVEIndex
from offensive.findings import FindingManager
from offensive.report import SecurityReport
from offensive.vulnerability import VulnerabilityAssessment
from offensive.web import WebTLSAssessment
from nmap_options import aggregate_nmap_xml


logger = logging.getLogger(__name__)

_SCAN_PROFILES = {
    "quick": {"ports": "22,53,80,443,445,3389,8080,8443", "timeout": 30},
    "standard": {
        "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,554,587,631,993,995,1433,1521,2049,2375,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,8888,9200",
        "timeout": 90,
    },
    "deep": {"ports": "1-65535", "timeout": 180},
}
_PORT_SPEC_PATTERN = re.compile(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*\Z")


class OffensiveAssessmentService:
    """Run the authorized discovery-to-report workflow without exploitation."""

    def __init__(
        self,
        report_directory: str | Path | None = None,
        discovery_timeout: int | None = None,
        enumeration_timeout: int = 60,
        max_workers: int = 3,
        maximum_network_addresses: int = 256,
    ) -> None:
        project_root = Path(__file__).resolve().parents[1]
        self.report_directory = Path(report_directory or project_root / "reports")
        self.discovery_timeout = discovery_timeout
        self.enumeration_timeout = max(15, min(enumeration_timeout, 180))
        self.max_workers = max(1, min(max_workers, 8))
        self.maximum_network_addresses = max(1, maximum_network_addresses)

    def validate_target(self, target: Any, *, allow_ipv6: bool = False) -> str:
        """Validate an IPv4 target and cap CIDR size for bounded scan duration."""
        normalized_target = OffensiveDiscovery.validate_target(target, allow_ipv6=allow_ipv6)
        network = ipaddress.ip_network(normalized_target, strict=False)
        if network.num_addresses > self.maximum_network_addresses:
            raise ValueError(
                "Target exceeds the configured maximum of "
                f"{self.maximum_network_addresses} IPv4 addresses."
            )
        return normalized_target

    @staticmethod
    def resolve_scan_config(
        profile: Any = "standard",
        port_spec: Any = None,
        scan_method: Any = "connect",
    ) -> dict[str, Any]:
        """Resolve UI choices into bounded settings consumed by Nmap."""
        if not isinstance(profile, str) or profile.lower() not in {*_SCAN_PROFILES, "custom"}:
            raise ValueError("Scan profile must be quick, standard, deep, or custom.")
        profile = profile.lower()
        if not isinstance(scan_method, str) or scan_method.lower() not in {"syn", "connect"}:
            raise ValueError("TCP scan method must be syn or connect.")
        scan_method = scan_method.lower()

        if profile == "custom":
            if not isinstance(port_spec, str) or not _PORT_SPEC_PATTERN.fullmatch(port_spec.strip()):
                raise ValueError("Custom ports must be comma-separated ports or ranges, such as 22,80,8000-8100.")
            ports = port_spec.strip()
            total_ports = 0
            for entry in ports.split(","):
                bounds = [int(value) for value in entry.split("-")]
                start, end = bounds[0], bounds[-1]
                if not 1 <= start <= end <= 65535:
                    raise ValueError("Custom port values must be between 1 and 65535, with ranges in ascending order.")
                total_ports += end - start + 1
            if total_ports > 4096:
                raise ValueError("Custom scans are limited to 4096 selected TCP ports.")
            timeout = 90
        else:
            ports = _SCAN_PROFILES[profile]["ports"]
            timeout = _SCAN_PROFILES[profile]["timeout"]
        return {
            "profile": profile,
            "ports": ports,
            "timeout": timeout,
            "scan_method": scan_method,
        }

    @staticmethod
    def resolve_nse_modules(value: Any = None) -> tuple[str, ...]:
        """Allow only reviewed, non-authenticating NSE protocol scripts."""
        if value is None:
            return ()
        if not isinstance(value, list) or any(
            not isinstance(module, str) or module not in SAFE_NSE_MODULES
            for module in value
        ):
            raise ValueError("NSE modules must be selected from the supported safe protocol checks.")
        return tuple(dict.fromkeys(value))

    def run_authorized_assessment(
        self,
        target: str,
        authorization_confirmed: bool,
        report_id: str | None = None,
        include_udp: bool = False,
        include_web: bool = True,
        progress_callback: Callable[[str, str, int], None] | None = None,
        scan_config: Mapping[str, Any] | None = None,
        nse_modules: tuple[str, ...] = (),
        admin_nmap_options: Mapping[str, Any] | None = None,
        cancel_event: Event | None = None,
        nmap_progress_callback: Callable[[str, Mapping[str, Any]], None] | None = None,
        nmap_command_callback: Callable[[str, list[str]], None] | None = None,
        nmap_output_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Run one authorized assessment and return its structured result."""
        if authorization_confirmed is not True:
            raise PermissionError("Explicit authorization is required before scanning.")
        if not isinstance(include_udp, bool) or not isinstance(include_web, bool):
            raise ValueError("Optional assessment settings must be boolean values.")
        allow_ipv6 = bool(admin_nmap_options and admin_nmap_options.get("ipv6"))
        normalized_target = self.validate_target(target, allow_ipv6=allow_ipv6)
        report_id = self._normalize_report_id(report_id)
        config = dict(scan_config or self.resolve_scan_config())
        nse_modules = self.resolve_nse_modules(list(nse_modules))

        if progress_callback is not None:
            progress_callback("Discovery in progress", "running", 10)

        logger.info("Starting authorized Offensive assessment for %s", normalized_target)
        discovery = OffensiveDiscovery(timeout=self.discovery_timeout).discover(
            normalized_target,
            nmap_options=admin_nmap_options,
            cancel_event=cancel_event,
            progress_callback=(
                (lambda progress: nmap_progress_callback("discovery", progress))
                if nmap_progress_callback is not None
                else None
            ),
            command_callback=(
                (lambda command: nmap_command_callback("discovery", command))
                if nmap_command_callback is not None
                else None
            ),
            output_callback=(
                (lambda event: nmap_output_callback("discovery", event))
                if nmap_output_callback is not None
                else None
            ),
        )
        discovery_xml = discovery.get("nmap_xml")
        nmap_xml_outputs = (
            [discovery_xml]
            if isinstance(discovery_xml, str) and discovery_xml
            else []
        )
        discovery_status = self._status(discovery)

        if discovery_status == "completed" and progress_callback is not None:
            progress_callback("Discovery complete", "running", 35)
        elif progress_callback is not None:
            progress_callback("Discovery did not complete", discovery_status or "incomplete", 20)

        if discovery_status == "completed":
            if progress_callback is not None:
                progress_callback("Port assessment initialized", "running", 38)
            enumeration = self._enumerate_discovered_hosts(
                discovery.get("hosts"),
                include_udp=include_udp,
                scan_config=config,
                progress_callback=progress_callback,
                nse_modules=nse_modules,
                admin_nmap_options=admin_nmap_options,
                cancel_event=cancel_event,
                nmap_progress_callback=nmap_progress_callback,
                nmap_command_callback=nmap_command_callback,
                nmap_output_callback=nmap_output_callback,
            )
            enumerated_hosts = enumeration.get("hosts")
            if isinstance(enumerated_hosts, list):
                for host in enumerated_hosts:
                    if not isinstance(host, dict):
                        continue
                    host_documents = host.pop("nmap_xml_documents", None)
                    if isinstance(host_documents, list):
                        nmap_xml_outputs.extend(
                            document for document in host_documents
                            if isinstance(document, str) and document
                        )
                    host_xml = host.pop("nmap_xml", None)
                    if isinstance(host_xml, str) and host_xml:
                        nmap_xml_outputs.append(host_xml)
            if progress_callback is not None:
                progress_callback(
                    "Enumerating services",
                    self._status(enumeration) or "running",
                    60,
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

        if progress_callback is not None:
            progress_callback("Checking web exposure", "running", 75)

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

        if progress_callback is not None:
            progress_callback("Correlating CVEs", "running", 85)

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
            "settings": {
                "include_udp": include_udp,
                "include_web": include_web,
                **config,
                "nse_modules": list(nse_modules),
            },
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

        port_state_results = []
        packet_trace_results = []
        enumerated_hosts = enumeration.get("hosts")
        if isinstance(enumerated_hosts, list):
            for host in enumerated_hosts:
                if not isinstance(host, Mapping):
                    continue
                packet_trace = host.get("packet_trace")
                if isinstance(packet_trace, str) and packet_trace:
                    packet_trace_results.append({
                        "target": host.get("ip", ""),
                        "trace": packet_trace[:12000],
                    })
                states = host.get("port_states")
                if not isinstance(states, list):
                    continue
                for port_state in states:
                    if isinstance(port_state, Mapping):
                        port_state_results.append({
                            "target": host.get("ip", ""),
                            "port": port_state.get("port"),
                            "protocol": port_state.get("protocol", ""),
                            "state": port_state.get("state", "unknown"),
                            "reason": port_state.get("reason", ""),
                        })
        report["Firewall / Filtering Analysis"] = port_state_results
        report["Nmap Packet Trace"] = packet_trace_results

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
        nmap_xml_available = False
        nmap_xml_error = None
        if admin_nmap_options and admin_nmap_options.get("output_format") in {"xml", "both"}:
            try:
                if not nmap_xml_outputs:
                    raise ValueError("Nmap returned no XML output to export.")
                self.save_nmap_xml(report_id, nmap_xml_outputs)
                nmap_xml_available = True
            except (OSError, ET.ParseError, ValueError) as exc:
                nmap_xml_error = f"Nmap XML export could not be generated: {exc}"
                errors = self._unique_strings([*errors, nmap_xml_error])
                limitations = self._unique_strings([*limitations, nmap_xml_error])
                report.setdefault("Assessment Limitations", []).append(nmap_xml_error)
        final_status = self._overall_status(
            discovery_status,
            self._status(enumeration),
            self._status(assessment),
            report.get("assessment_status"),
        )
        if cancel_event is not None and cancel_event.is_set():
            final_status = "cancelled"

        if progress_callback is not None:
            progress_callback(
                "Preparing findings report",
                final_status,
                100 if final_status in {"completed", "partial", "failed", "incomplete"} else 90,
            )

        result = {
            "scan_id": report_id,
            "report_id": report_id,
            "status": final_status,
            "phase": "Assessment complete",
            "progress": 100,
            "scan_type": "offensive",
            "target": normalized_target,
            "hosts": self._mappings(discovery.get("hosts")),
            "services": report.get("Services Discovered", []),
            "port_states": port_state_results,
            "packet_traces": packet_trace_results,
            "uncertain_ports": report.get("UDP States Requiring Verification", []),
            "findings": report.get("Security Findings", []),
            "web_assessment": web_assessment,
            "cve_correlation": cve_correlation,
            "statistics": report.get("Final Statistics", {}),
            "limitations": limitations,
            "errors": errors,
            "nmap_xml_available": nmap_xml_available,
            "report": report,
            "settings": {
                "include_udp": include_udp,
                "include_web": include_web,
                **config,
                "nse_modules": list(nse_modules),
            },
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
        scan_config: Mapping[str, Any] | None = None,
        progress_callback: Callable[[str, str, int], None] | None = None,
        nse_modules: tuple[str, ...] = (),
        admin_nmap_options: Mapping[str, Any] | None = None,
        cancel_event: Event | None = None,
        nmap_progress_callback: Callable[[str, Mapping[str, Any]], None] | None = None,
        nmap_command_callback: Callable[[str, list[str]], None] | None = None,
        nmap_output_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(discovered_hosts, list):
            return {
                "status": "failed",
                "hosts": [],
                "host_count": 0,
                "total_open_ports": 0,
                "errors": ["Discovery did not provide a valid host list."],
            }

        config = dict(scan_config or self.resolve_scan_config())
        enumerator = OffensiveEnumerator(
            timeout=max(
                config["timeout"],
                admin_nmap_options["host_timeout"],
            ) if admin_nmap_options else config["timeout"],
            port_range=config["ports"],
            scan_method=config["scan_method"],
            nmap_options=admin_nmap_options,
        )
        valid_hosts: list[tuple[str, Mapping[str, Any]]] = []
        failed_hosts: list[dict[str, Any]] = []
        errors: list[str] = []
        for host in discovered_hosts:
            if not isinstance(host, Mapping):
                errors.append("A malformed discovered-host record was skipped.")
                continue
            raw_ip = host.get("ip")
            try:
                ip_address = enumerator.validate_ip(
                    raw_ip,
                    allow_ipv6=bool(admin_nmap_options and admin_nmap_options.get("ipv6")),
                )
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
            parallel_limit = (
                admin_nmap_options["parallelism"]
                if admin_nmap_options
                else self.max_workers
            )
            worker_count = min(parallel_limit, len(valid_hosts))
            completed_hosts = 0
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_hosts = {
                    executor.submit(
                        self._enumerate_host,
                        enumerator,
                        ip_address,
                        include_udp,
                        nse_modules,
                        admin_nmap_options,
                        cancel_event,
                        (
                            (lambda progress, host=ip_address: nmap_progress_callback(host, progress))
                            if nmap_progress_callback is not None
                            else None
                        ),
                        (
                            (lambda command, host=ip_address: nmap_command_callback(host, command))
                            if nmap_command_callback is not None
                            else None
                        ),
                        (
                            (lambda event, host=ip_address: nmap_output_callback(host, event))
                            if nmap_output_callback is not None
                            else None
                        ),
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
                    for field in (
                        "hostname", "mac", "vendor", "state", "status_reason", "ipv6",
                        "discovery_method", "evidence", "device_type", "os", "traceroute",
                    ):
                        if result.get(field) in (None, "", "Unknown"):
                            result[field] = discovered_host.get(field, result.get(field, "Unknown"))
                    enumerated_hosts.append(result)
                    errors.extend(self._strings(result.get("errors")))
                    completed_hosts += 1
                    if progress_callback is not None:
                        progress = 38 + int(22 * completed_hosts / len(valid_hosts))
                        progress_callback(
                            f"Port and service assessment: {completed_hosts}/{len(valid_hosts)} hosts",
                            "running",
                            progress,
                        )

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
        nse_modules: tuple[str, ...] = (),
        admin_nmap_options: Mapping[str, Any] | None = None,
        cancel_event: Event | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        command_callback: Callable[[list[str]], None] | None = None,
        output_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Run TCP enumeration and optionally append the bounded UDP profile."""
        tcp_result = enumerator.enumerate_host(
            ip_address,
            nse_modules=nse_modules,
            admin_nmap_options=admin_nmap_options,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
            command_callback=command_callback,
            output_callback=output_callback,
        )
        if not isinstance(tcp_result, dict):
            return {
                "status": "failed",
                "ip": ip_address,
                "ports": [],
                "errors": ["TCP enumeration returned malformed host data."],
            }
        tcp_result.setdefault("uncertain_ports", [])
        if not include_udp or (admin_nmap_options and admin_nmap_options.get("scan_type") == "udp"):
            return tcp_result
        if tcp_result.get("status") != "completed":
            tcp_result["udp_status"] = "skipped"
            return tcp_result

        udp_result = enumerator.enumerate_udp_host(
            ip_address,
            admin_nmap_options=admin_nmap_options,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
            command_callback=command_callback,
            output_callback=output_callback,
        )
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
        tcp_xml = tcp_result.pop("nmap_xml", None)
        udp_xml = udp_result.get("nmap_xml")
        xml_documents = [
            document for document in (tcp_xml, udp_xml)
            if isinstance(document, str) and document
        ]
        if xml_documents:
            tcp_result["nmap_xml_documents"] = xml_documents
        udp_trace = udp_result.get("packet_trace")
        if isinstance(udp_trace, str) and udp_trace:
            current_trace = tcp_result.get("packet_trace")
            tcp_result["packet_trace"] = "\n".join(
                value for value in (current_trace, udp_trace) if isinstance(value, str) and value
            )[:12000]
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

    def save_nmap_xml(self, report_id: str, documents: list[str]) -> Path:
        """Persist aggregated Nmap XML under the validated report UUID."""
        safe_id = self._normalize_report_id(report_id)
        self.report_directory.mkdir(parents=True, exist_ok=True)
        destination = self.report_directory / f"{safe_id}.nmap.xml"
        temporary = self.report_directory / f"{safe_id}.nmap.xml.tmp"
        temporary.write_bytes(aggregate_nmap_xml(documents))
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
