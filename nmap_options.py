"""Validation and constants for administrator-only Nmap scan controls."""

from __future__ import annotations

import ctypes
import os
import re
from typing import Any
import xml.etree.ElementTree as ET


SCAN_FLAGS = {
    "connect": "-sT",
    "syn": "-sS",
    "udp": "-sU",
    "ack": "-sA",
    "window": "-sW",
    "fin": "-sF",
    "null": "-sN",
    "xmas": "-sX",
    "maimon": "-sM",
    "sctp-init": "-sY",
    "sctp-cookie": "-sZ",
    "ip-protocol": "-sO",
}

RAW_SCAN_TYPES = frozenset(SCAN_FLAGS) - {"connect"}
ADVANCED_ASSESSMENT_TYPES = frozenset({
    "ack", "window", "fin", "null", "xmas", "maimon",
    "sctp-init", "sctp-cookie", "ip-protocol",
})
SAFE_NSE_MODULES = {
    "smb": ("smb-protocols", "smb-security-mode", "smb-os-discovery"),
    "dns": ("dns-nsid",),
    "tls": ("ssl-cert", "ssl-enum-ciphers"),
    "database": ("oracle-tns-version",),
    "web": ("http-title", "http-headers", "http-methods", "http-server-header"),
}
ADMIN_NSE_MODULES = {
    "vulnerability": (
        "smb-vuln-ms17-010",
        "smb-vuln-ms10-054",
        "smb-vuln-ms10-061",
        "http-vuln-cve2017-5638",
    ),
}
NSE_MODULES = {**SAFE_NSE_MODULES, **ADMIN_NSE_MODULES}
DISCOVERY_METHODS = frozenset({"default", "arp", "icmp", "tcp-syn", "tcp-ack", "udp", "none"})
PORT_PRESETS = frozenset({"profile", "custom", "top-100", "top-1000", "all"})
OUTPUT_FORMATS = frozenset({"json", "xml", "both"})
ASSESSMENT_PROFILES = frozenset({"quick", "standard", "deep", "vulnerability", "full", "custom"})
_PORT_SPEC_PATTERN = re.compile(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*\Z")


def aggregate_nmap_xml(documents: list[str]) -> bytes:
    """Combine per-command Nmap XML host records into one importable document."""
    root = ET.Element(
        "nmaprun",
        {
            "scanner": "nmap",
            "args": "VulnScan aggregated authorized scan",
            "xmloutputversion": "1.05",
        },
    )
    for document in documents:
        if not isinstance(document, str) or not document.strip():
            continue
        parsed = ET.fromstring(document)
        for element in (*parsed.findall("scaninfo"), *parsed.findall("host")):
            root.append(element)
    if not root.findall("host"):
        raise ValueError("No Nmap host records are available for XML export.")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def has_raw_scan_privileges() -> bool:
    """Return whether this process can request raw-packet Nmap scans."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def validate_admin_nmap_options(
    value: Any,
    *,
    is_admin: bool,
    has_raw_scan_privileges: bool,
) -> dict[str, Any] | None:
    """Validate an optional admin scan profile without accepting raw Nmap args."""
    if value is None:
        return None
    if not is_admin:
        raise PermissionError("Advanced Nmap options are available to administrators only.")
    if not isinstance(value, dict):
        raise ValueError("Advanced Nmap options must be an object.")

    assessment_profile = value.get("assessment_profile", "custom")
    if not isinstance(assessment_profile, str) or assessment_profile not in ASSESSMENT_PROFILES:
        raise ValueError("Select a supported authorized assessment profile.")
    advanced_authorized = value.get("advanced_authorized", False)
    if not isinstance(advanced_authorized, bool):
        raise ValueError("Advanced assessment confirmation must be a boolean value.")

    scan_type = value.get("scan_type", "connect")
    if not isinstance(scan_type, str) or scan_type not in SCAN_FLAGS:
        raise ValueError("Select a supported Nmap scan type.")
    if scan_type in RAW_SCAN_TYPES and not has_raw_scan_privileges:
        raise PermissionError(
            "This scan type requires the VulnScan process to run with OS-level administrator privileges."
        )

    ports = value.get("ports", "")
    if not isinstance(ports, str):
        raise ValueError("Ports must be a comma-separated list or range.")
    ports = ports.strip()
    port_preset = value.get("port_preset", "custom" if ports else "profile")
    if not isinstance(port_preset, str) or port_preset not in PORT_PRESETS:
        raise ValueError("Select a supported port selection.")
    if port_preset == "custom" and not ports:
        raise ValueError("Enter custom ports or select a port preset.")
    if port_preset != "custom" and ports:
        raise ValueError("Custom port values can only be used with the custom selection.")
    if scan_type == "ip-protocol" and port_preset in {"top-100", "top-1000"}:
        raise ValueError("Top-port presets are not available for IP protocol scans.")
    if ports:
        if not _PORT_SPEC_PATTERN.fullmatch(ports):
            raise ValueError("Ports must use numbers and ranges only, for example 22,80,8000-8100.")
        total_ports = 0
        maximum_port = 255 if scan_type == "ip-protocol" else 65535
        for entry in ports.split(","):
            bounds = [int(part) for part in entry.split("-")]
            start, end = bounds[0], bounds[-1]
            if not 0 <= start <= end <= maximum_port or (scan_type != "ip-protocol" and start == 0):
                raise ValueError(f"Values must be between 1 and {maximum_port}.")
            total_ports += end - start + 1
        if total_ports > 4096:
            raise ValueError("Advanced scans are limited to 4096 selected ports or protocols.")
    if port_preset == "all" and scan_type in {"fin", "null", "xmas", "maimon", "ack", "window"}:
        raise ValueError("Use a bounded port selection for specialized TCP scans.")

    timing = value.get("timing", "T3")
    if not isinstance(timing, str) or timing not in {"T2", "T3", "T4"}:
        raise ValueError("Timing must be T2, T3, or T4.")

    discovery_method = value.get("discovery_method", "default")
    if not isinstance(discovery_method, str) or discovery_method not in DISCOVERY_METHODS:
        raise ValueError("Select a supported host discovery method.")

    max_retries = value.get("max_retries", 3)
    if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= 6:
        raise ValueError("Maximum retries must be a whole number from 0 to 6.")

    host_timeout = value.get("host_timeout", 90)
    if isinstance(host_timeout, bool) or not isinstance(host_timeout, int) or not 15 <= host_timeout <= 300:
        raise ValueError("Host timeout must be a whole number from 15 to 300 seconds.")

    parallelism = value.get("parallelism", 4)
    if isinstance(parallelism, bool) or not isinstance(parallelism, int) or not 1 <= parallelism <= 8:
        raise ValueError("Parallel host limit must be a whole number from 1 to 8.")

    max_rate = value.get("max_rate", 0)
    if isinstance(max_rate, bool) or not isinstance(max_rate, int) or max_rate not in {0, 5, 10, 20, 50}:
        raise ValueError("Maximum probe rate must be 0, 5, 10, 20, or 50 packets per second.")

    scan_delay = value.get("scan_delay", 0)
    if isinstance(scan_delay, bool) or not isinstance(scan_delay, int) or scan_delay not in {0, 10, 25, 50, 100, 250}:
        raise ValueError("Scan delay must be 0, 10, 25, 50, 100, or 250 milliseconds.")

    boolean_options = (
        "service_detection",
        "os_detection",
        "traceroute",
        "packet_trace",
        "reason",
        "ipv6",
    )
    normalized = {key: value.get(key, default) for key, default in (
        ("service_detection", True),
        ("os_detection", False),
        ("traceroute", False),
        ("packet_trace", False),
        ("reason", True),
        ("ipv6", False),
    )}
    if any(not isinstance(normalized[key], bool) for key in boolean_options):
        raise ValueError("Advanced scan flags must be boolean values.")
    if normalized["os_detection"] and not has_raw_scan_privileges:
        normalized["os_detection"] = True
    if normalized["traceroute"] and not has_raw_scan_privileges:
        raise PermissionError(
            "Traceroute requires the VulnScan process to run with OS-level administrator privileges."
        )
    if normalized["ipv6"] and discovery_method == "arp":
        raise ValueError("ARP discovery is not available for IPv6 targets.")
    if scan_type in {"fin", "null", "xmas"} and normalized["ipv6"]:
        raise ValueError("FIN, NULL, and Xmas scans are not supported for IPv6 targets.")

    output_format = value.get("output_format", "json")
    if not isinstance(output_format, str) or output_format not in OUTPUT_FORMATS:
        raise ValueError("Select JSON, XML, or combined output.")

    nse_modules = value.get("nse_modules", [])
    if not isinstance(nse_modules, list) or any(
        not isinstance(module, str) or module not in NSE_MODULES
        for module in nse_modules
    ):
        raise ValueError("NSE modules must be selected from the approved protocol checks.")

    exclude_ports = value.get("exclude_ports", "")
    if not isinstance(exclude_ports, str):
        raise ValueError("Excluded ports must be a comma-separated list or range.")
    exclude_ports = exclude_ports.strip()
    if exclude_ports:
        if not _PORT_SPEC_PATTERN.fullmatch(exclude_ports):
            raise ValueError("Excluded ports must use numbers and ranges only.")
        excluded_count = 0
        for entry in exclude_ports.split(","):
            bounds = [int(part) for part in entry.split("-")]
            start, end = bounds[0], bounds[-1]
            if not 1 <= start <= end <= (255 if scan_type == "ip-protocol" else 65535):
                raise ValueError("Excluded port values are outside the supported range.")
            excluded_count += end - start + 1
        if excluded_count > 4096:
            raise ValueError("A maximum of 4096 ports or protocols can be excluded.")

    include_udp = value.get("include_udp", False)
    if not isinstance(include_udp, bool):
        raise ValueError("Supplementary UDP assessment must be a boolean value.")

    advanced_required = (
        assessment_profile in {"vulnerability", "full"}
        or scan_type in ADVANCED_ASSESSMENT_TYPES
        or port_preset == "all"
        or "vulnerability" in nse_modules
    )
    if advanced_required and not advanced_authorized:
        raise PermissionError(
            "Confirm the Advanced authorized assessment before using this profile or scan option."
        )

    profile_settings = {
        "quick": {"port_preset": "top-100", "include_udp": False},
        "standard": {"port_preset": "profile", "include_udp": False},
        "deep": {"port_preset": "top-1000", "include_udp": False, "os_detection": True},
        "vulnerability": {
            "port_preset": "top-1000",
            "include_udp": False,
            "nse_modules": ["vulnerability"],
        },
        "full": {"port_preset": "all", "include_udp": True, "os_detection": True},
    }
    selected_profile = profile_settings.get(assessment_profile, {})
    port_preset = selected_profile.get("port_preset", port_preset)
    include_udp = selected_profile.get("include_udp", include_udp)
    normalized["os_detection"] = selected_profile.get("os_detection", normalized["os_detection"])
    nse_modules = list(dict.fromkeys([
        *nse_modules,
        *selected_profile.get("nse_modules", []),
    ]))
    if port_preset == "all" and scan_type in {"fin", "null", "xmas", "maimon", "ack", "window"}:
        raise ValueError("Use a bounded port selection for specialized TCP scans.")
    if assessment_profile == "full" and scan_type not in {"connect", "syn"}:
        raise ValueError("The Full assessment profile requires TCP Connect or TCP SYN scanning.")

    return {
        "assessment_profile": assessment_profile,
        "advanced_authorized": advanced_authorized,
        "scan_type": scan_type,
        "ports": ports,
        "port_preset": port_preset,
        "exclude_ports": exclude_ports,
        "include_udp": include_udp,
        "output_format": output_format,
        "timing": timing,
        "discovery_method": discovery_method,
        "max_retries": max_retries,
        "host_timeout": host_timeout,
        "parallelism": parallelism,
        "max_rate": max_rate,
        "scan_delay": scan_delay,
        **normalized,
        "nse_modules": list(dict.fromkeys(nse_modules)),
    }