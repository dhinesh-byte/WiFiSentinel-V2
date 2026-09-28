"""Structured and terminal-friendly reporting for authorized assessments."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .exploitation_guidance import (
	VULNERABILITY_STATUSES,
	build_exploitation_guidance,
)


logger = logging.getLogger(__name__)

_SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
_REQUIRED_FINDING_FIELDS = (
	"id",
	"title",
	"severity",
	"confidence",
	"target",
	"port",
	"protocol",
	"service",
	"evidence",
	"description",
	"attack_scenario",
	"impact",
	"remediation",
	"references",
)


class SecurityReport:
	"""Combine discovery, enumeration, assessment, and finding data.

	Parameters use the structured dictionaries returned by the Offensive
	modules. Individual findings may be dictionaries or objects with a
	``to_dict()`` method, such as :class:`offensive.findings.Finding`.
	"""

	def __init__(
		self,
		discovery_results: Mapping[str, Any] | list[Mapping[str, Any]] | None = None,
		enumeration_results: Mapping[str, Any] | None = None,
		vulnerability_assessment: Mapping[str, Any] | None = None,
		findings: Any = None,
		scan_information: Mapping[str, Any] | None = None,
		web_assessment: Mapping[str, Any] | None = None,
		cve_correlation: Mapping[str, Any] | None = None,
	) -> None:
		self.discovery_results = self._optional_mapping(
			discovery_results, "discovery results"
		)
		self.enumeration_results = self._optional_mapping(
			enumeration_results, "enumeration results"
		)
		self.vulnerability_assessment = self._optional_mapping(
			vulnerability_assessment, "vulnerability assessment"
		)
		self.scan_information = self._optional_mapping(
			scan_information, "scan information"
		)
		self.web_assessment = self._optional_mapping(web_assessment, "web assessment")
		self.cve_correlation = self._optional_mapping(cve_correlation, "CVE correlation")
		self._provided_discovered_hosts = (
			discovery_results if isinstance(discovery_results, list) else None
		)
		self._provided_findings = findings
		self._input_errors: list[str] = []
		for name, value in (
			("discovery results", discovery_results),
			("enumeration results", enumeration_results),
			("vulnerability assessment", vulnerability_assessment),
			("scan information", scan_information),
			("web assessment", web_assessment),
			("CVE correlation", cve_correlation),
		):
			if value is not None and not isinstance(value, Mapping):
				if name == "discovery results" and isinstance(value, list):
					continue
				self._input_errors.append(f"{name.capitalize()} must be a mapping.")
		self._generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

	def to_dict(self) -> dict[str, Any]:
		"""Return the complete report as JSON-compatible data."""
		report = self._build_report()
		logger.info(
			"Generated %s security report with %d finding(s)",
			report["assessment_status"],
			len(report["Security Findings"]),
		)
		return report

	def to_json(self, *, indent: int | None = 2) -> str:
		"""Serialize the report as machine-readable JSON."""
		return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

	def generate_text(self) -> str:
		"""Generate a readable report suitable for terminal output."""
		report = self.to_dict()
		lines = [
			"WiFi Sentinel V2.0 - Offensive Security Assessment",
			"=" * 58,
			f"Assessment Status: {report['assessment_status']}",
			"",
		]
		self._append_text_section(lines, "Executive Summary", report["Executive Summary"])
		self._append_text_section(lines, "Scan Information", report["Scan Information"])
		self._append_text_section(lines, "Hosts Assessed", report["Hosts Assessed"])
		self._append_text_section(lines, "Services Discovered", report["Services Discovered"])
		self._append_text_section(lines, "Web/TLS Observations", report["Web/TLS Observations"])
		self._append_text_section(
			lines,
			"UDP States Requiring Verification",
			report["UDP States Requiring Verification"],
		)
		self._append_text_section(lines, "CVE Correlation", report["CVE Correlation"])
		self._append_text_section(lines, "Segmentation Observations", report["Segmentation Observations"])
		self._append_findings(lines, report["Security Findings"])
		self._append_attack_scenarios(lines, report["Attack Scenarios"])
		self._append_attack_path_graph(lines, report["Attack Path Graph"])
		self._append_text_section(
			lines,
			"Defensive Recommendations",
			report["Defensive Recommendations"],
		)
		self._append_text_section(
			lines,
			"Assessment Limitations",
			report["Assessment Limitations"],
		)
		self._append_text_section(lines, "Final Statistics", report["Final Statistics"])
		return "\n".join(lines)

	def _build_report(self) -> dict[str, Any]:
		limitations = list(self._input_errors)
		errors: list[str] = []
		incomplete = bool(self._input_errors)

		discovery_status = self._status(self.discovery_results)
		if self.discovery_results is None and self._provided_discovered_hosts is None:
			incomplete = True
			limitations.append("Discovery results were not provided; discovered hosts could not be verified.")
		elif discovery_status != "completed":
			incomplete = True
			limitations.append(self._status_limitation("Discovery", discovery_status))
		if self.discovery_results is not None:
			errors.extend(self._strings(self.discovery_results.get("errors")))
			if self._strings(self.discovery_results.get("errors")):
				incomplete = True

		discovered_hosts, discovery_data_valid = self._discovered_hosts()
		if not discovery_data_valid:
			incomplete = True
			limitations.append("The discovery host list was missing or malformed.")

		enumeration_status = self._status(self.enumeration_results)
		if self.enumeration_results is None:
			incomplete = True
			limitations.append("Enumeration results were not provided; open ports and services could not be verified.")
		elif enumeration_status != "completed":
			incomplete = True
			limitations.append(self._status_limitation("Enumeration", enumeration_status))

		enumeration_hosts, enumeration_data_valid = self._enumeration_hosts()
		if not enumeration_data_valid:
			incomplete = True
			limitations.append("Enumeration did not provide a usable host result list.")
		if not enumeration_hosts and self.enumeration_results is not None:
			incomplete = True
			limitations.append("No host enumeration records were available for reporting.")

		host_rows: list[dict[str, Any]] = []
		service_rows: list[dict[str, Any]] = []
		uncertain_udp_rows: list[dict[str, Any]] = []
		open_port_count = 0
		identified_service_count = 0
		assessed_host_count = 0

		for host in enumeration_hosts:
			host_status = self._status(host)
			host_errors = self._strings(host.get("errors"))
			errors.extend(host_errors)
			if host_status != "completed" or host_errors:
				incomplete = True
				limitations.append(
					f"Host {self._host_target(host) or 'unknown'} enumeration status was "
					f"{host_status.upper() if host_status else 'NOT PROVIDED'}."
				)

			target = self._host_target(host)
			ports = host.get("ports")
			ports_valid = isinstance(ports, list)
			if not ports_valid:
				incomplete = True
				limitations.append(
					f"Port details for host {target or 'unknown'} were missing or malformed."
				)
				ports = []

			open_ports: list[dict[str, Any]] = []
			for port_entry in ports:
				if not isinstance(port_entry, Mapping):
					incomplete = True
					limitations.append("A malformed port entry was omitted from the report.")
					continue
				if self._text(port_entry.get("state")).lower() != "open":
					continue
				port_number = self._port(port_entry.get("port"))
				protocol = self._text(port_entry.get("protocol"))
				if port_number is None or not protocol:
					incomplete = True
					limitations.append("An open-port entry lacked a valid port or protocol and was omitted.")
					continue

				service = self._known_text(port_entry.get("service"))
				product = self._known_text(port_entry.get("product"))
				version = self._known_text(port_entry.get("version"))
				service_row = {
					"target": target or None,
					"port": port_number,
					"protocol": protocol,
					"service": service,
					"product": product,
					"version": version,
					"state": "open",
				}
				open_ports.append(service_row)
				service_rows.append(service_row)
				open_port_count += 1
				if service is not None:
					identified_service_count += 1

			uncertain_ports = host.get("uncertain_ports", [])
			if uncertain_ports:
				if not isinstance(uncertain_ports, list):
					incomplete = True
					limitations.append("Ambiguous UDP port data was malformed and omitted.")
				else:
					for uncertain in uncertain_ports:
						if not isinstance(uncertain, Mapping):
							incomplete = True
							limitations.append("A malformed ambiguous UDP entry was omitted.")
							continue
						port_number = self._port(uncertain.get("port"))
						if (
							port_number is None
							or self._text(uncertain.get("protocol")).lower() != "udp"
							or self._text(uncertain.get("state")).lower() != "open|filtered"
						):
							incomplete = True
							limitations.append("An ambiguous UDP result lacked valid state or port data.")
							continue
						uncertain_udp_rows.append(
							{
								"target": target or None,
								"port": port_number,
								"protocol": "udp",
								"state": "open|filtered",
								"service": self._known_text(uncertain.get("service")),
								"evidence": "Nmap could not distinguish an open UDP port from packet filtering.",
							}
						)
				if uncertain_udp_rows:
					limitations.append(
						"UDP open|filtered results are ambiguous and are excluded from confirmed open-port counts and vulnerability findings."
					)

			host_rows.append(
				{
					"target": target or None,
					"hostname": self._known_text(host.get("hostname")),
					"status": host_status.upper() if host_status else "NOT PROVIDED",
					"open_ports": len(open_ports),
					"services_identified": sum(
						1 for item in open_ports if item["service"] is not None
					),
				}
			)
			if host_status == "completed" and ports_valid and not host_errors:
				assessed_host_count += 1

		if self.enumeration_results is None or enumeration_status in {
			"failed",
			"timeout",
			"error",
		}:
			open_ports_stat: int | None = None
			services_stat: int | None = None
			assessed_hosts_stat: int | None = assessed_host_count
		else:
			open_ports_stat = open_port_count
			services_stat = identified_service_count
			assessed_hosts_stat = assessed_host_count

		vulnerability_status = self._status(self.vulnerability_assessment)
		if self.vulnerability_assessment is None:
			incomplete = True
			limitations.append("Vulnerability assessment results were not provided.")
		elif vulnerability_status != "completed":
			incomplete = True
			limitations.append(
				self._status_limitation("Vulnerability assessment", vulnerability_status)
			)
		if self.vulnerability_assessment is not None:
			errors.extend(self._strings(self.vulnerability_assessment.get("errors")))
			limitations.extend(self._strings(self.vulnerability_assessment.get("limitations")))
			if self._strings(self.vulnerability_assessment.get("errors")):
				incomplete = True

		web_observations: list[dict[str, Any]] = []
		web_status = "not_provided"
		if self.web_assessment is not None:
			web_status = self._status(self.web_assessment)
			if web_status != "completed":
				incomplete = True
			errors.extend(self._strings(self.web_assessment.get("errors")))
			limitations.extend(self._strings(self.web_assessment.get("limitations")))
			raw_web_services = self.web_assessment.get("services")
			if isinstance(raw_web_services, list):
				web_observations = [dict(item) for item in raw_web_services if isinstance(item, Mapping)]
				if len(web_observations) != len(raw_web_services):
					incomplete = True
					limitations.append("Malformed web/TLS observations were omitted from the report.")
			else:
				incomplete = True
				errors.append("Web/TLS assessment did not contain a valid services list.")

		cve_data: dict[str, Any] = {
			"status": "not_provided",
			"catalog_records": None,
			"catalog_metadata": {},
			"matches": [],
		}
		if self.cve_correlation is not None:
			cve_status = self._status(self.cve_correlation)
			cve_matches = self.cve_correlation.get("matches")
			cve_data["status"] = cve_status or "not_provided"
			cve_data["catalog_records"] = self.cve_correlation.get("catalog_records")
			metadata = self.cve_correlation.get("catalog_metadata")
			cve_data["catalog_metadata"] = dict(metadata) if isinstance(metadata, Mapping) else {}
			errors.extend(self._strings(self.cve_correlation.get("errors")))
			limitations.extend(self._strings(self.cve_correlation.get("limitations")))
			if cve_status != "completed":
				incomplete = True
			if isinstance(cve_matches, list):
				cve_data["matches"] = [dict(item) for item in cve_matches if isinstance(item, Mapping)]
				if len(cve_data["matches"]) != len(cve_matches):
					incomplete = True
					limitations.append("Malformed CVE correlation rows were omitted from the report.")
			else:
				incomplete = True
				errors.append("CVE correlation did not contain a valid matches list.")

		report_findings, finding_errors = self._collect_findings()
		if finding_errors:
			incomplete = True
			errors.extend(finding_errors)
			limitations.append("One or more findings were omitted because their data was invalid or incomplete.")

		status = "INCOMPLETE" if incomplete else "COMPLETED"
		if status == "COMPLETED" and not report_findings:
			summary = (
				"No security findings were identified from the checks performed. "
				"This does not guarantee that the target is completely secure."
			)
		elif status == "INCOMPLETE":
			summary = (
				"Assessment is incomplete. Available findings reflect only the evidence "
				"collected; missing scan or assessment data prevents a complete conclusion."
			)
		else:
			summary = (
				f"Assessment completed with {len(report_findings)} reported security finding(s). "
				"Finding severity and confidence reflect the supplied evidence."
			)

		finding_counts = {severity.lower(): 0 for severity in _SEVERITIES}
		for finding in report_findings:
			finding_counts[finding["severity"].lower()] += 1

		discovery_hosts_stat: int | None
		if self.discovery_results is None and self._provided_discovered_hosts is None:
			discovery_hosts_stat = None
		elif discovery_status != "completed" or not discovery_data_valid:
			discovery_hosts_stat = None
		else:
			discovery_hosts_stat = len(discovered_hosts)

		target = None
		if self.discovery_results is not None:
			target = self._known_text(self.discovery_results.get("target"))
		if target is None and self.scan_information is not None:
			target = self._known_text(self.scan_information.get("target"))

		scan_info = dict(self.scan_information or {})
		scan_info.update(
			{
				"target": target,
				"discovery_status": discovery_status.upper() if discovery_status else "NOT PROVIDED",
				"enumeration_status": enumeration_status.upper() if enumeration_status else "NOT PROVIDED",
				"vulnerability_assessment_status": (
					vulnerability_status.upper() if vulnerability_status else "NOT PROVIDED"
				),
				"report_generated_at": self._generated_at,
			}
		)

		recommendations = self._recommendations(report_findings)
		attack_paths = [self._attack_path(finding) for finding in report_findings]
		attack_path_graph = self._attack_path_graph(service_rows, report_findings)
		segmentation_observations = self._segmentation_observations(service_rows)
		if len({row.get("target") for row in host_rows if row.get("target")}) > 1:
			limitations.append(
				"Shared-service patterns do not establish a segmentation failure; VLAN, routing, and access-control policy were not provided or tested."
			)
		limitations = self._unique_strings(limitations)
		errors = self._unique_strings(errors)

		if status == "INCOMPLETE" and not limitations:
			limitations.append("Assessment data was incomplete; conclusions are limited.")

		return {
			"report_title": "WiFi Sentinel V2.0 - Offensive Security Assessment",
			"assessment_status": status,
			"Executive Summary": summary,
			"Scan Information": scan_info,
			"Hosts Assessed": host_rows,
			"Services Discovered": service_rows,
			"UDP States Requiring Verification": uncertain_udp_rows,
			"Web/TLS Observations": {
				"status": web_status.upper(),
				"services": web_observations,
			},
			"CVE Correlation": cve_data,
			"Segmentation Observations": segmentation_observations,
			"Security Findings": report_findings,
			"Attack Scenarios": attack_paths,
			"Attack Path Graph": attack_path_graph,
			"Defensive Recommendations": recommendations,
			"Assessment Limitations": limitations,
			"errors": errors,
			"Final Statistics": {
				"Hosts discovered": discovery_hosts_stat,
				"Hosts assessed": assessed_hosts_stat,
				"Open ports": open_ports_stat,
				"Services identified": services_stat,
				"UDP ports observed": sum(
					1 for service in service_rows if service["protocol"].lower() == "udp"
				),
				"UDP states requiring verification": len(uncertain_udp_rows),
				"Web endpoints assessed": sum(
					1 for item in web_observations if item.get("status") == "completed"
				),
				"CVE catalog matches": len(cve_data["matches"]),
				"Informational findings": finding_counts["informational"],
				"Low findings": finding_counts["low"],
				"Medium findings": finding_counts["medium"],
				"High findings": finding_counts["high"],
				"Critical findings": finding_counts["critical"],
			},
		}

	def _discovered_hosts(self) -> tuple[list[Mapping[str, Any]], bool]:
		if self._provided_discovered_hosts is not None:
			raw_hosts = self._provided_discovered_hosts
		elif self.discovery_results is not None:
			raw_hosts = self.discovery_results.get("hosts")
		else:
			return [], False
		if not isinstance(raw_hosts, list):
			return [], False
		hosts = [host for host in raw_hosts if isinstance(host, Mapping)]
		return hosts, len(hosts) == len(raw_hosts)

	def _enumeration_hosts(self) -> tuple[list[Mapping[str, Any]], bool]:
		if self.enumeration_results is None:
			return [], False
		if "hosts" in self.enumeration_results:
			raw_hosts = self.enumeration_results.get("hosts")
			if not isinstance(raw_hosts, list):
				return [], False
		elif "ip" in self.enumeration_results or "target" in self.enumeration_results:
			raw_hosts = [self.enumeration_results]
		else:
			return [], False
		hosts = [host for host in raw_hosts if isinstance(host, Mapping)]
		return hosts, len(hosts) == len(raw_hosts)

	def _collect_findings(self) -> tuple[list[dict[str, Any]], list[str]]:
		sources: list[Any] = []
		if self.vulnerability_assessment is not None:
			raw_findings = self.vulnerability_assessment.get("findings")
			if not isinstance(raw_findings, list):
				return [], ["Vulnerability assessment did not contain a findings list."]
			sources.extend(raw_findings)
		if self._provided_findings is not None:
			extra_findings = self._provided_findings
			if hasattr(extra_findings, "get_all_findings"):
				extra_findings = extra_findings.get_all_findings()
			if not isinstance(extra_findings, (list, tuple)):
				return [], ["Structured findings must be a list, tuple, or finding manager."]
			sources.extend(extra_findings)

		findings: list[dict[str, Any]] = []
		errors: list[str] = []
		seen: set[tuple[str, int, str]] = set()
		for index, source in enumerate(sources):
			if not isinstance(source, Mapping):
				converter = getattr(source, "to_dict", None)
				if callable(converter):
					source = converter()
			if not isinstance(source, Mapping):
				errors.append(f"Finding {index + 1} was not a dictionary or convertible finding.")
				continue
			finding, error = self._normalize_finding(source)
			if error:
				errors.append(f"Finding {index + 1}: {error}")
				continue
			assert finding is not None
			finding_type = self._text(source.get("finding_type"))
			if not finding_type:
				finding_type = re.sub(
					r"[^a-z0-9]+",
					"-",
					finding["title"].lower(),
				).strip("-")
			identity = (
				finding["target"].casefold(),
				finding["port"],
				finding_type.casefold(),
			)
			if identity in seen:
				continue
			seen.add(identity)
			findings.append(finding)
		return findings, errors

	@staticmethod
	def _normalize_finding(
		source: Mapping[str, Any],
	) -> tuple[dict[str, Any] | None, str | None]:
		missing = [field for field in _REQUIRED_FINDING_FIELDS if field not in source]
		if missing:
			return None, f"missing required fields: {', '.join(missing)}"

		text_fields = (
			"id", "title", "severity", "confidence", "target", "protocol",
			"service", "description", "attack_scenario", "impact", "remediation",
		)
		finding: dict[str, Any] = {}
		for field in text_fields:
			value = source.get(field)
			if not isinstance(value, str) or not value.strip():
				return None, f"{field} must be a non-empty string"
			finding[field] = value.strip()

		if finding["severity"] not in _SEVERITIES:
			return None, "severity is not an allowed value"
		if finding["confidence"] not in {"Confirmed", "Likely", "Potential", "Informational"}:
			return None, "confidence is not an allowed value"
		port = source.get("port")
		if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
			return None, "port must be an integer from 1 to 65535"
		finding["port"] = port

		evidence = SecurityReport._string_values(source.get("evidence"), "evidence")
		references = SecurityReport._string_values(source.get("references"), "references")
		if evidence is None or not evidence:
			return None, "evidence must contain at least one non-empty string"
		if references is None:
			return None, "references must be a list of strings"
		finding["evidence"] = evidence
		finding["references"] = references
		for field in ("product", "version", "observed_cpe"):
			value = source.get(field)
			if value is not None and not isinstance(value, str):
				return None, f"{field} must be a string or null"
			finding[field] = value.strip() if isinstance(value, str) and value.strip() else None
		finding_type = source.get("finding_type", "")
		if not isinstance(finding_type, str):
			return None, "finding_type must be a string"
		finding["finding_type"] = finding_type
		cve_id = source.get("cve_id")
		if cve_id is not None and (
			not isinstance(cve_id, str)
			or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE)
		):
			return None, "cve_id must be a CVE identifier or null"
		finding["cve_id"] = cve_id.upper() if isinstance(cve_id, str) else None
		vulnerability_status = source.get("vulnerability_status")
		if vulnerability_status is not None and (
			not isinstance(vulnerability_status, str)
			or vulnerability_status not in VULNERABILITY_STATUSES
		):
			return None, "vulnerability_status is not an allowed classification"
		detection_method = source.get("detection_method", "Not provided by assessment data")
		if not isinstance(detection_method, str) or not detection_method.strip():
			return None, "detection_method must be a non-empty string"
		finding["detection_method"] = detection_method.strip()
		guidance = build_exploitation_guidance(
			finding,
			vulnerability_status=vulnerability_status,
			cve_id=finding["cve_id"],
		)
		finding["vulnerability_status"] = guidance["vulnerability_status"]
		finding["exploitation_guidance"] = guidance
		return finding, None

	@staticmethod
	def _attack_path(finding: Mapping[str, Any]) -> dict[str, Any]:
		return {
			"finding_id": finding["id"],
			"target": finding["target"],
			"path": [
				{"stage": "Network Host", "detail": finding["target"]},
				{
					"stage": "Exposed Service",
					"detail": f"{finding['service']} ({finding['protocol']}/{finding['port']})",
				},
				{
					"stage": "Potential Weakness or Exposure",
					"detail": finding["title"],
				},
				{
					"stage": "Possible Security Impact",
					"detail": finding["impact"],
				},
				{
					"stage": "Defensive Control",
					"detail": finding["remediation"],
				},
			],
		}

	@staticmethod
	def _recommendations(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
		recommendations: list[dict[str, str]] = []
		seen: set[tuple[str, str]] = set()
		for finding in findings:
			identity = (finding["target"].casefold(), finding["remediation"].casefold())
			if identity in seen:
				continue
			seen.add(identity)
			recommendations.append(
				{
					"finding_id": finding["id"],
					"target": finding["target"],
					"recommendation": finding["remediation"],
				}
			)
		return recommendations

	@staticmethod
	def _attack_path_graph(
		services: list[dict[str, Any]],
		findings: list[dict[str, Any]],
	) -> dict[str, list[dict[str, Any]]]:
		nodes: dict[str, dict[str, Any]] = {}
		edges: list[dict[str, str]] = []
		seen_edges: set[tuple[str, str, str]] = set()

		def add_node(node_id: str, node_type: str, label: str, **attributes: Any) -> None:
			nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label, **attributes})

		def connect(source: str, target: str, relationship: str) -> None:
			identity = (source, target, relationship)
			if identity not in seen_edges:
				seen_edges.add(identity)
				edges.append({"source": source, "target": target, "relationship": relationship})

		for service in services:
			target = service.get("target")
			port = service.get("port")
			protocol = service.get("protocol")
			if not isinstance(target, str) or not isinstance(port, int) or not isinstance(protocol, str):
				continue
			host_id = f"host:{target}"
			port_id = f"port:{target}:{protocol}:{port}"
			service_id = f"service:{target}:{protocol}:{port}"
			service_name = service.get("service") or "Unidentified service"
			add_node(host_id, "host", target, target=target)
			add_node(port_id, "port", f"{port}/{protocol}", target=target, port=port, protocol=protocol)
			add_node(service_id, "service", str(service_name), target=target, port=port, protocol=protocol)
			connect(host_id, port_id, "exposes")
			connect(port_id, service_id, "identified_as")

		for finding in findings:
			target = finding["target"]
			port = finding["port"]
			protocol = finding["protocol"]
			host_id = f"host:{target}"
			port_id = f"port:{target}:{protocol}:{port}"
			service_id = f"service:{target}:{protocol}:{port}"
			finding_id = f"finding:{finding['id']}"
			impact_id = f"impact:{finding['id']}"
			control_id = f"control:{finding['id']}"
			add_node(host_id, "host", target, target=target)
			add_node(port_id, "port", f"{port}/{protocol}", target=target, port=port, protocol=protocol)
			add_node(service_id, "service", finding["service"], target=target, port=port, protocol=protocol)
			add_node(finding_id, "finding", finding["title"], finding_id=finding["id"], severity=finding["severity"])
			add_node(impact_id, "impact", finding["impact"], finding_id=finding["id"])
			add_node(control_id, "defense", finding["remediation"], finding_id=finding["id"])
			connect(host_id, port_id, "exposes")
			connect(port_id, service_id, "identified_as")
			connect(service_id, finding_id, "has_evidence_of")
			connect(finding_id, impact_id, "may_lead_to")
			connect(impact_id, control_id, "mitigated_by")
		return {"nodes": list(nodes.values()), "edges": edges}

	@staticmethod
	def _segmentation_observations(
		services: list[dict[str, Any]],
	) -> list[dict[str, Any]]:
		"""Summarize repeated services without inferring segmentation policy."""
		groups: dict[tuple[str, int, str], set[str]] = {}
		for service in services:
			target = service.get("target")
			port = service.get("port")
			protocol = service.get("protocol")
			if not isinstance(target, str) or not isinstance(port, int) or not isinstance(protocol, str):
				continue
			service_name = service.get("service")
			service_label = (
				service_name.casefold()
				if isinstance(service_name, str) and service_name
				else "unidentified"
			)
			groups.setdefault((protocol.casefold(), port, service_label), set()).add(target)

		observations: list[dict[str, Any]] = []
		for (protocol, port, service), targets in groups.items():
			if len(targets) < 2:
				continue
			ordered_targets = sorted(targets)
			observations.append(
				{
					"type": "shared_service_exposure",
					"service": service,
					"port": port,
					"protocol": protocol,
					"targets": ordered_targets,
					"observation": f"The same {service} service was observed on {len(ordered_targets)} scanned hosts.",
					"interpretation": (
						"This is an inventory pattern only. It does not establish that hosts can reach one another "
						"or that network segmentation is ineffective."
					),
					"review": "Compare these endpoints with approved network-zone and service-access policies.",
				}
			)
		return observations

	@staticmethod
	def _append_text_section(lines: list[str], title: str, content: Any) -> None:
		lines.extend([title, "-" * len(title)])
		if isinstance(content, Mapping):
			if not content:
				lines.append("  Not available")
			for key, value in content.items():
				lines.append(f"  {key}: {SecurityReport._display(value)}")
		elif isinstance(content, list):
			if not content:
				lines.append("  None reported")
			for item in content:
				if isinstance(item, Mapping):
					summary = ", ".join(
						f"{key}: {SecurityReport._display(value)}"
						for key, value in item.items()
					)
					lines.append(f"  - {summary}")
				else:
					lines.append(f"  - {SecurityReport._display(item)}")
		else:
			lines.append(f"  {SecurityReport._display(content)}")
		lines.append("")

	@staticmethod
	def _append_findings(lines: list[str], findings: list[dict[str, Any]]) -> None:
		title = "Security Findings"
		lines.extend([title, "-" * len(title)])
		if not findings:
			lines.append("  No findings were supplied.")
			lines.append("")
			return
		for finding in findings:
			guidance = finding.get("exploitation_guidance", {})
			lines.extend(
				[
					f"  Finding ID: {finding['id']}",
					f"  Title: {finding['title']}",
					f"  Severity: {finding['severity']}",
					f"  Confidence: {finding['confidence']}",
					f"  Vulnerability Status: {finding.get('vulnerability_status', 'Insufficient evidence')}",
					f"  CVE: {finding.get('cve_id') or 'None identified'}",
					f"  Target: {finding['target']}",
					f"  Port: {finding['port']}",
					f"  Protocol: {finding['protocol']}",
					f"  Service: {finding['service']}",
					f"  Evidence: {SecurityReport._display(finding['evidence'])}",
					f"  Description: {finding['description']}",
					f"  Possible Attack Scenario: {finding['attack_scenario']}",
					f"  Impact: {finding['impact']}",
					f"  Defensive Recommendation: {finding['remediation']}",
					f"  References: {SecurityReport._display(finding['references'])}",
					"",
				]
			)
			if isinstance(guidance, Mapping):
				lines.extend(
					[
						"  Exploitation Guidance:",
						f"    Why it may be vulnerable: {guidance.get('why_it_may_be_vulnerable', 'Insufficient evidence to determine vulnerability.')}",
						f"    Prerequisites: {SecurityReport._display(guidance.get('exploitation_prerequisites', []))}",
						f"    Safe verification: {SecurityReport._display(guidance.get('safe_verification_procedure', []))}",
						f"    Detection: {SecurityReport._display(guidance.get('detection_opportunities', []))}",
						f"    Defense: {guidance.get('defensive_remediation', finding['remediation'])}",
						f"    Verify fix: {SecurityReport._display(guidance.get('verification_after_remediation', []))}",
						"    Automatic exploitation: Disabled",
						"",
					]
				)

	@staticmethod
	def _append_attack_scenarios(lines: list[str], paths: list[dict[str, Any]]) -> None:
		title = "Attack Scenarios"
		lines.extend([title, "-" * len(title)])
		if not paths:
			lines.extend(["  No evidence-based attack paths could be constructed.", ""])
			return
		for attack_path in paths:
			lines.append(f"  Finding {attack_path['finding_id']}:")
			for index, step in enumerate(attack_path["path"]):
				prefix = "  -> " if index else "  "
				lines.append(f"{prefix}{step['stage']}: {step['detail']}")
			lines.append("")

	@staticmethod
	def _append_attack_path_graph(lines: list[str], graph: Mapping[str, Any]) -> None:
		title = "Attack Path Graph"
		lines.extend([title, "-" * len(title)])
		nodes = graph.get("nodes", [])
		edges = graph.get("edges", [])
		if not nodes:
			lines.extend(["  No observed hosts or services to map.", ""])
			return
		labels = {
			node["id"]: node["label"]
			for node in nodes
			if isinstance(node, Mapping) and "id" in node and "label" in node
		}
		for edge in edges:
			if not isinstance(edge, Mapping):
				continue
			source = labels.get(edge.get("source"), "Unknown node")
			target = labels.get(edge.get("target"), "Unknown node")
			lines.append(f"  {source} -> {target} [{edge.get('relationship', 'related')}]")
		lines.append("")

	@staticmethod
	def _display(value: Any) -> str:
		if value is None:
			return "Not available"
		if isinstance(value, list):
			return "; ".join(SecurityReport._display(item) for item in value) or "None"
		return str(value)

	@staticmethod
	def _optional_mapping(value: Any, name: str) -> Mapping[str, Any] | None:
		return value if isinstance(value, Mapping) else None

	@staticmethod
	def _status(data: Mapping[str, Any] | None) -> str:
		if data is None:
			return ""
		value = data.get("status")
		return value.strip().lower() if isinstance(value, str) else ""

	@staticmethod
	def _status_limitation(name: str, status: str) -> str:
		shown_status = status.upper() if status else "NOT PROVIDED"
		if name == "Enumeration":
			detail = "Open ports and service details could not be collected reliably."
		elif name == "Vulnerability assessment":
			detail = "Security assessment results may be incomplete or unavailable."
		else:
			detail = "The discovered host list may be incomplete or unavailable."
		return f"{name} status was {shown_status}. {detail}"

	@staticmethod
	def _host_target(host: Mapping[str, Any]) -> str:
		for key in ("ip", "target"):
			value = host.get(key)
			if isinstance(value, str) and value.strip():
				return value.strip()
		return ""

	@staticmethod
	def _port(value: Any) -> int | None:
		if isinstance(value, bool) or not isinstance(value, int):
			return None
		return value if 1 <= value <= 65535 else None

	@staticmethod
	def _text(value: Any) -> str:
		return value.strip() if isinstance(value, str) else ""

	@staticmethod
	def _known_text(value: Any) -> str | None:
		if not isinstance(value, str) or not value.strip():
			return None
		cleaned = value.strip()
		return None if cleaned.lower() in {"unknown", "?", "n/a"} else cleaned

	@staticmethod
	def _strings(values: Any) -> list[str]:
		if not isinstance(values, (list, tuple)):
			return []
		return [value.strip() for value in values if isinstance(value, str) and value.strip()]

	@staticmethod
	def _string_values(values: Any, field: str) -> list[str] | None:
		if not isinstance(values, (list, tuple)):
			return None
		if any(not isinstance(value, str) or not value.strip() for value in values):
			return None
		return [value.strip() for value in values]

	@staticmethod
	def _unique_strings(values: list[str]) -> list[str]:
		return list(dict.fromkeys(value for value in values if value))
