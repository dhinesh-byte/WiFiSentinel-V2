"""Typed finding records and management utilities for offensive assessments."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .exploitation_guidance import (
	VULNERABILITY_STATUSES,
	build_exploitation_guidance,
)


logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ("Informational", "Low", "Medium", "High", "Critical")
ALLOWED_SEVERITIES = frozenset(SEVERITY_LEVELS)
ALLOWED_CONFIDENCES = frozenset(
	{"Confirmed", "Likely", "Potential", "Informational"}
)
_ASSESSMENT_STATUSES = frozenset({"completed", "incomplete"})


@dataclass(frozen=True)
class Finding:
	"""A validated, evidence-backed security assessment finding."""

	id: str
	title: str
	severity: str
	confidence: str
	target: str
	port: int
	protocol: str
	service: str
	description: str
	evidence: tuple[str, ...] | list[str]
	attack_scenario: str
	impact: str
	remediation: str
	references: tuple[str, ...] | list[str]
	finding_type: str = ""
	product: str | None = None
	version: str | None = None
	observed_cpe: str | None = None
	detection_method: str = "Assessment data"
	vulnerability_status: str | None = None
	cve_id: str | None = None
	exploitation_guidance: Mapping[str, Any] | None = None

	def __post_init__(self) -> None:
		"""Validate required content and normalize collection fields."""
		for field_name in (
			"id",
			"title",
			"target",
			"protocol",
			"service",
			"description",
			"attack_scenario",
			"impact",
			"remediation",
		):
			value = getattr(self, field_name)
			if not isinstance(value, str) or not value.strip():
				raise ValueError(f"Finding {field_name} must be a non-empty string.")
			object.__setattr__(self, field_name, value.strip())

		if not isinstance(self.severity, str) or self.severity not in ALLOWED_SEVERITIES:
			raise ValueError(
				f"Severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}."
			)
		if not isinstance(self.confidence, str) or self.confidence not in ALLOWED_CONFIDENCES:
			raise ValueError(
				f"Confidence must be one of: {', '.join(sorted(ALLOWED_CONFIDENCES))}."
			)
		if isinstance(self.port, bool) or not isinstance(self.port, int):
			raise ValueError("Finding port must be an integer.")
		if not 1 <= self.port <= 65535:
			raise ValueError("Finding port must be between 1 and 65535.")

		evidence = self._text_tuple(self.evidence, "evidence")
		if not evidence:
			raise ValueError("A finding must include at least one evidence item.")
		references = self._text_tuple(self.references, "references")
		object.__setattr__(self, "evidence", evidence)
		object.__setattr__(self, "references", references)

		if not isinstance(self.finding_type, str):
			raise ValueError("Finding type must be a string.")
		if self.finding_type:
			finding_type = self.finding_type.strip()
		else:
			finding_type = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")
		if not finding_type:
			raise ValueError("Finding type must not be empty.")
		object.__setattr__(self, "finding_type", finding_type)
		for field_name in ("product", "version", "observed_cpe"):
			value = getattr(self, field_name)
			if value is not None and not isinstance(value, str):
				raise ValueError(f"Finding {field_name} must be a string or None.")
			if isinstance(value, str):
				object.__setattr__(self, field_name, value.strip() or None)
		if not isinstance(self.detection_method, str) or not self.detection_method.strip():
			raise ValueError("Finding detection_method must be a non-empty string.")
		object.__setattr__(self, "detection_method", self.detection_method.strip())
		if self.vulnerability_status is not None and (
			not isinstance(self.vulnerability_status, str)
			or self.vulnerability_status not in VULNERABILITY_STATUSES
		):
			raise ValueError("Finding vulnerability_status is not an allowed classification.")
		if self.cve_id is not None:
			if not isinstance(self.cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", self.cve_id, re.IGNORECASE):
				raise ValueError("Finding cve_id must be a valid CVE identifier or None.")
			object.__setattr__(self, "cve_id", self.cve_id.upper())
		guidance = self.exploitation_guidance
		if guidance is not None and not isinstance(guidance, Mapping):
			raise ValueError("Finding exploitation_guidance must be a mapping or None.")
		if isinstance(guidance, Mapping) and guidance.get("automatic_exploitation") is not False:
			raise ValueError("Finding guidance must explicitly disable automatic exploitation.")
		provided_status = self.vulnerability_status
		if provided_status is None and isinstance(guidance, Mapping):
			provided_status = guidance.get("vulnerability_status")
		guidance = build_exploitation_guidance(
			self.to_dict(),
			vulnerability_status=provided_status,
			cve_id=self.cve_id,
		)
		status = guidance.get("vulnerability_status")
		if status not in VULNERABILITY_STATUSES:
			raise ValueError("Finding guidance has an invalid vulnerability status.")
		if self.vulnerability_status is not None and self.vulnerability_status != status:
			raise ValueError("Finding vulnerability status does not match its guidance.")
		object.__setattr__(self, "vulnerability_status", status)
		object.__setattr__(self, "exploitation_guidance", guidance)

	@staticmethod
	def _text_tuple(values: Any, field_name: str) -> tuple[str, ...]:
		if not isinstance(values, (list, tuple)):
			raise ValueError(f"Finding {field_name} must be a list or tuple of strings.")
		if any(not isinstance(value, str) or not value.strip() for value in values):
			raise ValueError(f"Every finding {field_name} item must be a non-empty string.")
		return tuple(value.strip() for value in values)

	@classmethod
	def from_dict(cls, data: Mapping[str, Any]) -> Finding:
		"""Create and validate a finding from an assessment dictionary."""
		if not isinstance(data, Mapping):
			raise ValueError("Finding data must be a mapping.")

		required_fields = (
			"id",
			"title",
			"severity",
			"confidence",
			"target",
			"port",
			"protocol",
			"service",
			"description",
			"evidence",
			"attack_scenario",
			"impact",
			"remediation",
			"references",
		)
		missing = [field for field in required_fields if field not in data]
		if missing:
			raise ValueError(f"Finding data is missing required fields: {', '.join(missing)}.")

		values = {field: data[field] for field in required_fields}
		values["finding_type"] = data.get("finding_type", "")
		for field in (
			"product", "version", "observed_cpe", "detection_method",
			"vulnerability_status", "cve_id",
		):
			if field in data:
				values[field] = data[field]
		if "exploitation_guidance" in data:
			values["exploitation_guidance"] = data["exploitation_guidance"]
		return cls(**values)

	def to_dict(self) -> dict[str, Any]:
		"""Return a JSON-compatible representation of this finding."""
		return {
			"id": self.id,
			"title": self.title,
			"severity": self.severity,
			"confidence": self.confidence,
			"target": self.target,
			"port": self.port,
			"protocol": self.protocol,
			"service": self.service,
			"description": self.description,
			"evidence": list(self.evidence),
			"attack_scenario": self.attack_scenario,
			"impact": self.impact,
			"remediation": self.remediation,
			"references": list(self.references),
			"finding_type": self.finding_type,
			"product": self.product,
			"version": self.version,
			"observed_cpe": self.observed_cpe,
			"detection_method": self.detection_method,
			"vulnerability_status": self.vulnerability_status,
			"cve_id": self.cve_id,
			"exploitation_guidance": deepcopy(dict(self.exploitation_guidance or {})),
		}


class FindingManager:
	"""Store, filter, summarize, and export validated findings."""

	def __init__(self) -> None:
		self._findings: dict[tuple[str, int, str], Finding] = {}
		self._ids: set[str] = set()

	def add_finding(self, finding: Finding | Mapping[str, Any]) -> bool:
		"""Validate and add a finding; return False for a duplicate."""
		if isinstance(finding, Mapping):
			finding = Finding.from_dict(finding)
		elif not isinstance(finding, Finding):
			raise ValueError("Finding must be a Finding instance or a finding mapping.")

		identity = self._identity(finding)
		if identity in self._findings:
			logger.info("Ignoring duplicate finding for %s", identity)
			return False
		if finding.id in self._ids:
			logger.warning("Ignoring finding with duplicate id %s", finding.id)
			return False

		self._findings[identity] = finding
		self._ids.add(finding.id)
		logger.debug("Added finding %s", finding.id)
		return True

	def add_assessment_result(self, result: Mapping[str, Any]) -> int:
		"""Add validated findings from a completed or partial assessment.

		Results marked ``error``, ``insufficient_evidence``, or with any other
		unsupported status contribute no findings. Findings in an incomplete
		assessment are accepted only if each includes valid evidence.
		"""
		if not isinstance(result, Mapping):
			raise ValueError("Assessment result must be a mapping.")
		status = result.get("status")
		if not isinstance(status, str) or status not in _ASSESSMENT_STATUSES:
			logger.info("No findings imported from assessment status %r", status)
			return 0

		rows = result.get("findings")
		if not isinstance(rows, list):
			raise ValueError("Assessment findings must be provided as a list.")

		validated = [Finding.from_dict(row) for row in rows]
		added = sum(self.add_finding(finding) for finding in validated)
		if status == "incomplete":
			logger.warning(
				"Imported %d evidence-backed finding(s) from an incomplete assessment",
				added,
			)
		return added

	def remove_finding(self, finding_id: str) -> bool:
		"""Remove a finding by ID, returning whether one was removed."""
		if not isinstance(finding_id, str) or not finding_id.strip():
			raise ValueError("Finding id must be a non-empty string.")
		for identity, finding in self._findings.items():
			if finding.id == finding_id:
				del self._findings[identity]
				self._ids.remove(finding_id)
				logger.debug("Removed finding %s", finding_id)
				return True
		return False

	def get_all_findings(self) -> list[Finding]:
		"""Return all findings in insertion order."""
		return list(self._findings.values())

	def filter_by_severity(self, severity: str) -> list[Finding]:
		"""Return findings with an exact allowed severity."""
		if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
			raise ValueError(f"Unsupported severity: {severity!r}.")
		return [item for item in self._findings.values() if item.severity == severity]

	def filter_by_target(self, target: str) -> list[Finding]:
		"""Return findings for a target, matched case-insensitively."""
		if not isinstance(target, str) or not target.strip():
			raise ValueError("Target must be a non-empty string.")
		normalized_target = target.strip().casefold()
		return [
			item
			for item in self._findings.values()
			if item.target.casefold() == normalized_target
		]

	def count_by_severity(self) -> dict[str, int]:
		"""Return counts keyed by lowercase severity names."""
		counts = {severity.lower(): 0 for severity in SEVERITY_LEVELS}
		for finding in self._findings.values():
			counts[finding.severity.lower()] += 1
		return counts

	def summary(self) -> dict[str, int]:
		"""Return total and per-severity counts."""
		counts = self.count_by_severity()
		return {"total": len(self._findings), **counts}

	def to_dictionaries(self) -> list[dict[str, Any]]:
		"""Convert all findings to JSON-compatible dictionaries."""
		return [finding.to_dict() for finding in self._findings.values()]

	def export_json_compatible(self) -> list[dict[str, Any]]:
		"""Export findings as native JSON-compatible data structures."""
		return self.to_dictionaries()

	def export_json(self, *, indent: int | None = 2) -> str:
		"""Serialize all findings as a JSON string."""
		return json.dumps(self.export_json_compatible(), indent=indent)

	@staticmethod
	def _identity(finding: Finding) -> tuple[str, int, str]:
		return (
			finding.target.casefold(),
			finding.port,
			finding.finding_type.casefold(),
		)
