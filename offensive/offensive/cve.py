"""Exact-CPE correlation against a local offline vulnerability catalog."""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}


class OfflineCVEIndex:
    """Load validated records and correlate only exact Nmap CPE identifiers.

    No product-name or version substring matching is performed. Catalog data
    is kept offline so assessment runs do not depend on external availability.
    """

    def __init__(self, catalog_path: str | Path | None = None) -> None:
        project_root = Path(__file__).resolve().parents[1]
        self.catalog_path = Path(catalog_path or project_root / "data" / "cve_catalog.json")
        self._records_by_cpe: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.errors: list[str] = []
        self.catalog_metadata: dict[str, Any] = {}
        self._load_catalog()

    def correlate(self, enumeration_results: Mapping[str, Any]) -> dict[str, Any]:
        """Correlate observed open-port CPEs with exact catalog CPEs."""
        if not isinstance(enumeration_results, Mapping):
            return {
                "status": "error",
                "matches": [],
                "errors": ["Enumeration results must be a mapping."],
                "limitations": [],
                "catalog_records": self.record_count,
            }

        if "hosts" in enumeration_results:
            hosts = enumeration_results.get("hosts")
            if not isinstance(hosts, list):
                return {
                    "status": "incomplete",
                    "matches": [],
                    "errors": ["Enumeration host list was malformed."],
                    "limitations": ["CVE correlation could not inspect malformed host results."],
                    "catalog_records": self.record_count,
                }
        else:
            hosts = [enumeration_results]

        matches: list[dict[str, Any]] = []
        missing_cpe = False
        incomplete = False
        for host in hosts:
            if not isinstance(host, Mapping):
                incomplete = True
                continue
            target = self._text(host.get("ip")) or self._text(host.get("target"))
            ports = host.get("ports")
            if not isinstance(ports, list):
                incomplete = True
                continue
            for entry in ports:
                if not isinstance(entry, Mapping) or self._text(entry.get("state")).lower() != "open":
                    continue
                cpes = self._cpe_values(entry)
                if not cpes:
                    missing_cpe = True
                    continue
                for cpe in cpes:
                    for record in self._records_by_cpe.get(cpe.casefold(), []):
                        matches.append(
                            {
                                "id": record["cve_id"],
                                "target": target,
                                "port": entry.get("port"),
                                "protocol": self._text(entry.get("protocol")).lower(),
                                "service": self._text(entry.get("service")) or "unknown",
                                "product": self._known_text(entry.get("product")),
                                "version": self._known_text(entry.get("version")),
                                "cpe23_uri": cpe,
                                "severity": record["severity"],
                                "title": record["title"],
                                "summary": record["summary"],
                                "remediation": record["remediation"],
                                "references": list(record["references"]),
                                "confidence": "Likely",
                                "detection_method": "Exact CPE match in local offline catalog",
                                "evidence": [
                                    f"Enumerator reported CPE {cpe} for {target} port {entry.get('port')}/{entry.get('protocol')}.",
                                    f"Local catalog maps the exact CPE to {record['cve_id']}.",
                                ],
                            }
                        )

        limitations: list[str] = []
        if not self.record_count:
            limitations.append(
                "The offline CVE catalog is empty; no vulnerability correlation data was available."
            )
        if missing_cpe:
            limitations.append(
                "Some services lacked an exact CPE identifier and were not correlated."
            )
        if not matches and self.record_count:
            limitations.append(
                "No exact CPE matches were found in the local catalog; this does not establish absence of vulnerabilities."
            )
        if self.errors:
            limitations.append("Some invalid catalog records were skipped.")

        return {
            "status": "incomplete" if incomplete else "completed",
            "matches": matches,
            "errors": list(self.errors),
            "limitations": self._unique(limitations),
            "catalog_records": self.record_count,
            "catalog_metadata": dict(self.catalog_metadata),
        }

    @property
    def record_count(self) -> int:
        return sum(len(records) for records in self._records_by_cpe.values())

    def _load_catalog(self) -> None:
        try:
            raw_data = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.errors.append(f"Offline CVE catalog not found: {self.catalog_path}")
            logger.warning("Offline CVE catalog not found: %s", self.catalog_path)
            return
        except (OSError, json.JSONDecodeError) as exc:
            self.errors.append(f"Offline CVE catalog could not be read: {exc}")
            logger.error("Offline CVE catalog could not be read: %s", exc)
            return

        if not isinstance(raw_data, Mapping):
            self.errors.append("Offline CVE catalog root must be a JSON object.")
            return
        self.catalog_metadata = {
            key: raw_data[key]
            for key in ("schema_version", "source", "updated_at")
            if key in raw_data and isinstance(raw_data[key], (str, int, float, type(None)))
        }
        rows = raw_data.get("records")
        if not isinstance(rows, list):
            self.errors.append("Offline CVE catalog must contain a records list.")
            return

        for index, row in enumerate(rows):
            record = self._validate_record(row)
            if record is None:
                self.errors.append(f"Invalid offline CVE catalog record {index + 1} was skipped.")
                continue
            self._records_by_cpe[record["cpe23_uri"].casefold()].append(record)

    @staticmethod
    def _validate_record(row: Any) -> dict[str, Any] | None:
        if not isinstance(row, Mapping):
            return None
        required = ("cve_id", "cpe23_uri", "severity", "title", "summary", "remediation", "references")
        if any(key not in row for key in required):
            return None
        cve_id = OfflineCVEIndex._text(row.get("cve_id")).upper()
        cpe = OfflineCVEIndex._text(row.get("cpe23_uri"))
        severity = row.get("severity")
        title = OfflineCVEIndex._text(row.get("title"))
        summary = OfflineCVEIndex._text(row.get("summary"))
        remediation = OfflineCVEIndex._text(row.get("remediation"))
        references = row.get("references")
        if (
            not _CVE_ID.fullmatch(cve_id)
            or not cpe.startswith("cpe:2.3:")
            or not OfflineCVEIndex._has_concrete_version(cpe)
        ):
            return None
        if (
            not isinstance(severity, str)
            or severity not in _SEVERITIES
            or not title
            or not summary
            or not remediation
        ):
            return None
        if not isinstance(references, list) or any(
            not isinstance(item, str) or not item.strip() for item in references
        ):
            return None
        return {
            "cve_id": cve_id,
            "cpe23_uri": cpe,
            "severity": severity,
            "title": title,
            "summary": summary,
            "remediation": remediation,
            "references": [item.strip() for item in references],
        }

    @staticmethod
    def _cpe_values(entry: Mapping[str, Any]) -> list[str]:
        values = entry.get("cpes", entry.get("cpe", []))
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            return []
        return [
            value.strip()
            for value in values
            if isinstance(value, str)
            and value.strip().startswith("cpe:2.3:")
            and OfflineCVEIndex._has_concrete_version(value.strip())
        ]

    @staticmethod
    def _has_concrete_version(cpe: str) -> bool:
        parts = cpe.split(":")
        return len(parts) > 5 and parts[5] not in {"", "*", "-"}

    @staticmethod
    def _text(value: Any) -> str:
        return value.strip() if isinstance(value, str) else ""

    @staticmethod
    def _known_text(value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        cleaned = value.strip()
        return None if cleaned.casefold() in {"unknown", "?", "n/a"} else cleaned

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))
