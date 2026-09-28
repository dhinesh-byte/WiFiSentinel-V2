"""
WiFi Sentinel V2.0
scanner/ports.py

Defensive network exposure scanner.

Features:
- Fast TCP scanning
- Common-port detection
- Optional aggressive mode
- Lightweight service/version detection
- Bounded timeouts
- Defensive risk analysis
- Possible attack scenario
- Why the exposure matters
- How to defend

This module performs discovery/analysis only.
It does not exploit discovered services.
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any


class PortScanner:

    # Common ports suitable for a fast defensive scan.
    DEFAULT_PORTS = (
        "21,22,23,25,53,80,110,111,135,139,143,"
        "443,445,554,587,631,993,995,1433,1521,2049,"
        "2375,3000,3306,3389,5000,5432,5900,6379,"
        "8000,8080,8443,8888,9200"
    )

    # Broader profiles used by the UI scan configuration.
    THOROUGH_PORTS = "1-20000"
    DEEP_PORTS = "1-65535"

    SERVICE_PROFILES = {

        21: {
            "name": "FTP",
            "risk": "High",
            "attack": (
                "An attacker with network access could attempt "
                "unauthorized FTP authentication or investigate "
                "insecure file-transfer configuration."
            ),
            "why": (
                "FTP can expose file-transfer functionality and may "
                "lack strong protection for credentials and traffic."
            ),
            "defense": (
                "Disable FTP if unnecessary. Prefer SFTP or another "
                "secure transfer protocol and restrict access with "
                "firewall rules."
            ),
        },

        22: {
            "name": "SSH",
            "risk": "Medium",
            "attack": (
                "An attacker with network access could attempt "
                "unauthorized SSH authentication."
            ),
            "why": (
                "SSH provides remote administration, so unnecessary "
                "exposure increases the reachable attack surface."
            ),
            "defense": (
                "Use strong authentication or SSH keys, restrict "
                "trusted source addresses, disable unnecessary remote "
                "access, and keep SSH updated."
            ),
        },

        23: {
            "name": "Telnet",
            "risk": "High",
            "attack": (
                "An attacker with network access could attempt "
                "unauthorized remote access or observe unencrypted "
                "Telnet communication."
            ),
            "why": (
                "Telnet does not provide modern protection for "
                "remote-administration traffic."
            ),
            "defense": (
                "Disable Telnet and use SSH instead. Restrict remote "
                "administration to trusted systems."
            ),
        },

        25: {
            "name": "SMTP",
            "risk": "Medium",
            "attack": (
                "An attacker could investigate an exposed mail service "
                "for authentication or relay weaknesses."
            ),
            "why": (
                "Mail services handle sensitive account and message data."
            ),
            "defense": (
                "Restrict SMTP access, require authentication where "
                "appropriate, disable unnecessary exposure, and keep "
                "the mail service updated."
            ),
        },

        53: {
            "name": "DNS",
            "risk": "Medium",
            "attack": (
                "An attacker could interact with an exposed DNS service "
                "and investigate configuration weaknesses."
            ),
            "why": (
                "Incorrectly configured DNS can disclose network "
                "information or provide unintended functionality."
            ),
            "defense": (
                "Restrict DNS queries and zone transfers to trusted "
                "systems and keep the DNS service updated."
            ),
        },

        80: {
            "name": "HTTP",
            "risk": "Medium",
            "attack": (
                "An attacker could access the exposed web service and "
                "look for weak authentication, unsafe configuration, "
                "or outdated software."
            ),
            "why": (
                "An exposed web service increases the reachable "
                "application attack surface."
            ),
            "defense": (
                "Use HTTPS where supported, restrict administration "
                "interfaces, remove unnecessary services, use strong "
                "authentication, and update the application."
            ),
        },

        110: {
            "name": "POP3",
            "risk": "Medium",
            "attack": (
                "An attacker could attempt unauthorized authentication "
                "against an exposed POP3 service."
            ),
            "why": (
                "Mail services handle sensitive account information."
            ),
            "defense": (
                "Prefer secure mail protocols, require strong "
                "authentication, and restrict unnecessary network access."
            ),
        },

        135: {
            "name": "MS RPC",
            "risk": "Medium",
            "attack": (
                "An attacker could investigate exposed Windows RPC "
                "functionality from the reachable network."
            ),
            "why": (
                "RPC is legitimate Windows infrastructure but can "
                "increase lateral-movement exposure when unnecessarily "
                "reachable."
            ),
            "defense": (
                "Restrict RPC using Windows Firewall and network "
                "segmentation and keep Windows security updates current."
            ),
        },

        139: {
            "name": "NetBIOS",
            "risk": "Medium",
            "attack": (
                "An attacker could investigate exposed legacy Windows "
                "file and name-sharing functionality."
            ),
            "why": (
                "Legacy Windows networking can expose additional "
                "network information and services."
            ),
            "defense": (
                "Disable NetBIOS where it is not required and restrict "
                "legacy Windows networking traffic."
            ),
        },

        443: {
            "name": "HTTPS",
            "risk": "Low",
            "attack": (
                "An attacker could investigate the exposed HTTPS "
                "application for authentication or software weaknesses."
            ),
            "why": (
                "HTTPS protects transport traffic, but the application "
                "behind it can still contain vulnerabilities."
            ),
            "defense": (
                "Keep the application and TLS configuration updated, "
                "use strong authentication, and restrict management "
                "interfaces."
            ),
        },

        445: {
            "name": "SMB",
            "risk": "High",
            "attack": (
                "An attacker with network access could investigate "
                "exposed SMB resources or file-sharing configuration."
            ),
            "why": (
                "SMB provides network file and resource sharing and can "
                "increase lateral-movement exposure."
            ),
            "defense": (
                "Restrict SMB to trusted systems, disable unnecessary "
                "file sharing, disable SMBv1, use strong authentication, "
                "and keep the system updated."
            ),
        },

        554: {
            "name": "RTSP",
            "risk": "Medium",
            "attack": (
                "An attacker could investigate an exposed media-streaming "
                "service for unauthorized access."
            ),
            "why": (
                "RTSP is commonly used by cameras and media devices."
            ),
            "defense": (
                "Require authentication, restrict the service to trusted "
                "network segments, and update device firmware."
            ),
        },

        631: {
            "name": "IPP",
            "risk": "Medium",
            "attack": (
                "An attacker could investigate an exposed network "
                "printing service for unauthorized printer access."
            ),
            "why": (
                "Network printing services expose device functionality "
                "to reachable hosts."
            ),
            "defense": (
                "Restrict printer access to trusted devices and keep "
                "printer firmware updated."
            ),
        },

        1433: {
            "name": "Microsoft SQL Server",
            "risk": "High",
            "attack": (
                "An attacker could attempt unauthorized database "
                "authentication against an exposed SQL service."
            ),
            "why": (
                "Database services may contain sensitive application data."
            ),
            "defense": (
                "Do not expose the database unnecessarily. Restrict "
                "access with firewall rules, use strong authentication, "
                "and keep the database updated."
            ),
        },

        1521: {
            "name": "Oracle Database",
            "risk": "High",
            "attack": (
                "An attacker could attempt unauthorized database access "
                "against an exposed Oracle service."
            ),
            "why": (
                "Database services can provide access to sensitive data."
            ),
            "defense": (
                "Restrict database connectivity to trusted application "
                "systems and use strong authentication and current patches."
            ),
        },

        2049: {
            "name": "NFS",
            "risk": "High",
            "attack": (
                "An attacker could investigate exposed NFS resources "
                "for unauthorized file access."
            ),
            "why": (
                "NFS provides network file-system access and requires "
                "careful host and export restrictions."
            ),
            "defense": (
                "Restrict NFS exports to trusted hosts and networks and "
                "disable unnecessary exports."
            ),
        },

        2375: {
            "name": "Docker API",
            "risk": "High",
            "attack": (
                "An attacker who can reach an unsecured Docker API could "
                "potentially obtain powerful container-management access."
            ),
            "why": (
                "Container-management interfaces can provide highly "
                "privileged control over the host environment."
            ),
            "defense": (
                "Never expose an unauthenticated Docker API. Restrict "
                "container-management access to trusted systems and use "
                "secure authentication."
            ),
        },

        3306: {
            "name": "MySQL",
            "risk": "High",
            "attack": (
                "An attacker could attempt unauthorized database "
                "authentication against an exposed MySQL service."
            ),
            "why": (
                "Database services may contain sensitive application data."
            ),
            "defense": (
                "Restrict MySQL to trusted application hosts, use strong "
                "authentication, and keep the database updated."
            ),
        },

        3389: {
            "name": "RDP",
            "risk": "High",
            "attack": (
                "An attacker with network access could attempt "
                "unauthorized remote-desktop authentication."
            ),
            "why": (
                "RDP provides interactive remote access to Windows systems."
            ),
            "defense": (
                "Restrict RDP with firewall rules or VPN access, use "
                "strong authentication, and keep Windows updated."
            ),
        },

        5432: {
            "name": "PostgreSQL",
            "risk": "High",
            "attack": (
                "An attacker could attempt unauthorized authentication "
                "against an exposed PostgreSQL service."
            ),
            "why": (
                "Database services may contain sensitive application data."
            ),
            "defense": (
                "Restrict PostgreSQL to trusted application hosts and "
                "use strong authentication and current security updates."
            ),
        },

        5900: {
            "name": "VNC",
            "risk": "High",
            "attack": (
                "An attacker could attempt unauthorized remote-desktop "
                "access if the VNC service is insufficiently protected."
            ),
            "why": (
                "VNC can provide interactive control of a graphical desktop."
            ),
            "defense": (
                "Disable VNC when unnecessary, restrict it to trusted "
                "hosts or VPN access, and require strong authentication."
            ),
        },

        6379: {
            "name": "Redis",
            "risk": "High",
            "attack": (
                "An attacker could investigate an exposed Redis service "
                "for unauthorized access."
            ),
            "why": (
                "Redis can contain application data and should normally "
                "not be broadly reachable."
            ),
            "defense": (
                "Bind Redis to trusted interfaces, restrict access with "
                "firewall rules, require authentication where supported, "
                "and keep Redis updated."
            ),
        },

        9200: {
            "name": "Elasticsearch",
            "risk": "High",
            "attack": (
                "An attacker could investigate an exposed Elasticsearch "
                "service for unauthorized data access."
            ),
            "why": (
                "Logging and search platforms can contain sensitive "
                "operational information."
            ),
            "defense": (
                "Restrict Elasticsearch to trusted systems, require "
                "authentication, avoid unnecessary exposure, and keep "
                "the stack updated."
            ),
        },
    }

    def __init__(
        self,
        ports: str | None = None,
        timeout: int | None = 20,
        profile: str = "standard",
    ) -> None:

        self.profile = str(profile or "standard").lower()
        if self.profile not in {"standard", "thorough", "deep"}:
            self.profile = "standard"

        self.ports = ports or self.DEFAULT_PORTS

        if timeout is None:
            self.timeout = None
        else:
            self.timeout = max(5, min(int(timeout), 120))

        self.nmap_path = shutil.which("nmap")

    # =========================================================
    # NMAP AVAILABILITY
    # =========================================================

    def available(self) -> bool:
        return self.nmap_path is not None

    def is_available(self) -> bool:
        return self.available()

    def get_nmap_version(self) -> str | None:
        """Return the first Nmap version line, or None if unavailable."""
        if not self.nmap_path:
            return None
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        return next((line.strip() for line in result.stdout.splitlines() if line.strip()), None)

    @staticmethod
    def _has_os_detection_privileges() -> bool:
        """Check whether this process can request raw-packet OS fingerprinting."""
        if os.name == "nt":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                return False
        return hasattr(os, "geteuid") and os.geteuid() == 0

    # =========================================================
    # VALIDATION
    # =========================================================

    @staticmethod
    def _validate_ip(target: str) -> str:

        target = str(target).strip()

        try:
            address = ipaddress.ip_address(target)

        except ValueError as exc:

            raise ValueError(
                f"Invalid IPv4 address: {target}"
            ) from exc

        if address.version != 4:

            raise ValueError(
                "Only IPv4 addresses are supported."
            )

        return target

    # =========================================================
    # SECURITY ANALYSIS
    # =========================================================

    @classmethod
    def analyze_port(
        cls,
        port: int,
        service: str = "",
        product: str = "",
        version: str = "",
    ) -> dict[str, Any]:

        profile = cls.SERVICE_PROFILES.get(port)

        if profile is None:

            return {
                "port": port,
                "service": service or "Unknown",
                "product": product or "",
                "version": version or "",
                "risk": "Informational",

                "title": (
                    f"Exposed service on TCP/{port}"
                ),

                "description": (
                    f"TCP port {port} is reachable. "
                    "Review whether this service needs "
                    "network exposure."
                ),

                "possible_attack": (
                    "An attacker with network access could "
                    "investigate the exposed service for "
                    "authentication or configuration weaknesses."
                ),

                "why_it_matters": (
                    "Every reachable service increases the "
                    "network attack surface."
                ),

                "how_to_defend": (
                    "Disable the service if unnecessary. "
                    "Otherwise restrict access to trusted "
                    "hosts, require strong authentication, "
                    "and keep the software updated."
                ),
            }

        return {
            "port": port,
            "service": service or profile["name"],
            "product": product or "",
            "version": version or "",
            "risk": profile["risk"],

            "title": (
                f"{profile['name']} service exposed "
                f"on TCP/{port}"
            ),

            "description": (
                f"{profile['name']} is reachable "
                f"on TCP port {port}."
            ),

            "possible_attack": profile["attack"],

            "why_it_matters": profile["why"],

            "how_to_defend": profile["defense"],
        }

    # =========================================================
    # XML PARSER
    # =========================================================

    @staticmethod
    def _parse_nmap_xml(
        xml_data: str,
    ) -> list[dict[str, Any]]:

        results = []

        if not xml_data.strip():
            return results

        try:
            root = ET.fromstring(xml_data)

        except ET.ParseError:
            return results

        for host in root.findall("host"):

            status_element = host.find("status")

            state = (
                status_element.get(
                    "state",
                    "unknown",
                )
                if status_element is not None
                else "unknown"
            )

            address_element = host.find(
                "address[@addrtype='ipv4']"
            )

            if address_element is None:
                continue

            ip = address_element.get(
                "addr",
                "",
            )

            ports = []

            ports_element = host.find("ports")

            if ports_element is not None:

                for port_element in ports_element.findall(
                    "port"
                ):

                    protocol = port_element.get(
                        "protocol",
                        "tcp",
                    )

                    try:

                        port_number = int(
                            port_element.get(
                                "portid",
                                "0",
                            )
                        )

                    except ValueError:
                        continue

                    state_element = port_element.find(
                        "state"
                    )

                    port_state = (
                        state_element.get(
                            "state",
                            "unknown",
                        )
                        if state_element is not None
                        else "unknown"
                    )

                    if port_state != "open":
                        continue

                    service_element = port_element.find(
                        "service"
                    )

                    service = ""
                    product = ""
                    version = ""
                    extra = ""
                    tunnel = ""
                    service_method = ""
                    service_confidence = ""
                    cpes = []

                    if service_element is not None:

                        service = service_element.get(
                            "name",
                            "",
                        )

                        product = service_element.get(
                            "product",
                            "",
                        )

                        version = service_element.get(
                            "version",
                            "",
                        )

                        extra = service_element.get(
                            "extrainfo",
                            "",
                        )
                        tunnel = service_element.get("tunnel", "")
                        service_method = service_element.get("method", "")
                        service_confidence = service_element.get("conf", "")
                        cpes = [
                            cpe.text.strip()
                            for cpe in service_element.findall("cpe")
                            if cpe.text and cpe.text.strip()
                        ]

                    reason = state_element.get("reason", "") if state_element is not None else ""

                    analysis = PortScanner.analyze_port(
                        port=port_number,
                        service=service,
                        product=product,
                        version=version,
                    )

                    ports.append(
                        {
                            "port": port_number,
                            "protocol": protocol,
                            "state": port_state,
                            "service": service,
                            "product": product,
                            "version": version,
                            "extrainfo": extra,
                            "tunnel": tunnel,
                            "service_method": service_method,
                            "service_confidence": service_confidence,
                            "cpes": cpes,
                            "reason": reason,

                            "risk": analysis["risk"],
                            "title": analysis["title"],
                            "description": analysis["description"],

                            "possible_attack": (
                                analysis["possible_attack"]
                            ),

                            "why_it_matters": (
                                analysis["why_it_matters"]
                            ),

                            "how_to_defend": (
                                analysis["how_to_defend"]
                            ),
                        }
                    )

            mac = "Unknown"
            vendor = "Unknown"
            for address in host.findall("address"):
                if address.get("addrtype") == "mac":
                    mac = address.get("addr", "Unknown")
                    vendor = address.get("vendor", "Unknown")

            hostnames_element = host.find("hostnames")
            hostname_element = (
                hostnames_element.find("hostname")
                if hostnames_element is not None
                else None
            )
            hostname = (
                hostname_element.get("name", "Unknown")
                if hostname_element is not None
                else "Unknown"
            )

            os_matches = []
            os_element = host.find("os")
            if os_element is not None:
                for os_match in os_element.findall("osmatch"):
                    classes = []
                    for os_class in os_match.findall("osclass"):
                        classes.append({
                            "type": os_class.get("type", ""),
                            "vendor": os_class.get("vendor", ""),
                            "family": os_class.get("osfamily", ""),
                            "generation": os_class.get("osgen", ""),
                            "accuracy": os_class.get("accuracy", ""),
                            "cpes": [
                                cpe.text.strip()
                                for cpe in os_class.findall("cpe")
                                if cpe.text and cpe.text.strip()
                            ],
                        })
                    try:
                        accuracy = int(os_match.get("accuracy", "0"))
                    except ValueError:
                        accuracy = 0
                    os_matches.append({
                        "name": os_match.get("name", "Unknown"),
                        "accuracy": accuracy,
                        "classes": classes,
                    })
            os_matches.sort(key=lambda match: match["accuracy"], reverse=True)
            best_os = os_matches[0] if os_matches else {}

            uptime_element = host.find("uptime")
            distance_element = host.find("distance")
            scripts_element = host.find("hostscript")
            host_scripts = [
                {"id": script.get("id", "unknown"), "output": script.get("output", "")}
                for script in scripts_element.findall("script")
            ] if scripts_element is not None else []

            results.append({
                "ip": ip,
                "state": state,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "ports": ports,
                "open_ports": len(ports),
                "os": best_os.get("name", "Unknown"),
                "os_accuracy": best_os.get("accuracy", 0),
                "os_matches": os_matches,
                "uptime_seconds": uptime_element.get("seconds") if uptime_element is not None else None,
                "last_boot": uptime_element.get("lastboot") if uptime_element is not None else None,
                "distance": distance_element.get("value") if distance_element is not None else None,
                "host_scripts": host_scripts,
                "status_reason": status_element.get("reason", "") if status_element is not None else "",
            })

        return results

    # =========================================================
    # SINGLE HOST SCAN
    # =========================================================

    def scan_host(
        self,
        target: str,
        aggressive: bool = False,
    ) -> dict[str, Any]:

        target = self._validate_ip(target)

        if not self.available():

            return {
                "ip": target,
                "state": "error",
                "ports": [],
                "open_ports": 0,
                "scan_status": "nmap_unavailable",
                "error": (
                    "Nmap was not found. "
                    "Install Nmap and ensure it is in PATH."
                ),
            }

        selected_ports = self.ports
        if aggressive:
            if self.profile == "deep":
                selected_ports = self.DEEP_PORTS
            elif self.profile == "thorough":
                selected_ports = self.THOROUGH_PORTS

        command = [
            self.nmap_path,

            # TCP connect scan.
            "-sT",

            # Service/version detection.
            "-sV",

            # Version detection depth follows the selected profile.
            "--version-all" if self.profile == "deep" else "--version-light",

            # Return only open ports.
            "--open",

            # Faster timing template.
            "-T4",

            # Host timeout is added below only when configured.
            # Scan selected ports.
            "-p",
            selected_ports,

            # XML output for reliable parsing.
            "-oX",
            "-",

            target,
        ]
        if self.timeout is not None:
            insert_at = command.index("-p")
            command[insert_at:insert_at] = ["--host-timeout", f"{self.timeout}s"]

        os_detection_requested = self._has_os_detection_privileges()
        if os_detection_requested:
            command.insert(command.index("-oX"), "-O")

        try:

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=(self.timeout + 10) if self.timeout is not None else None,
                check=False,
            )

        except subprocess.TimeoutExpired:

            return {
                "ip": target,
                "state": "timeout",
                "ports": [],
                "open_ports": 0,
                "scan_status": "timeout",
                "error": (
                    "Host scan exceeded the configured timeout."
                ),
            }

        except OSError as exc:

            return {
                "ip": target,
                "state": "error",
                "ports": [],
                "open_ports": 0,
                "scan_status": "execution_error",
                "error": str(exc),
            }

        if completed.returncode != 0:

            return {
                "ip": target,
                "state": "error",
                "ports": [],
                "open_ports": 0,
                "scan_status": "nmap_error",
                "error": (
                    completed.stderr.strip()
                    or "Nmap returned an error."
                ),
            }

        parsed = self._parse_nmap_xml(
            completed.stdout
        )

        if not parsed:

            return {
                "success": True,
                "ip": target,
                "state": "up",
                "ports": [],
                "open_ports": 0,
                "scan_status": "complete",
                "error": None,
                "os_detection_status": "not_detected" if os_detection_requested else "skipped_unprivileged",
            }

        result = parsed[0]

        result["success"] = True
        result["scan_status"] = "complete"
        result["error"] = None
        result["os_detection_status"] = (
            "detected" if result.get("os_matches") else "not_detected"
        ) if os_detection_requested else "skipped_unprivileged"

        return result

    # =========================================================
    # IMPORTANT COMPATIBILITY METHOD
    # =========================================================

    def scan_device(
        self,
        target: str,
        aggressive: bool = False,
    ) -> dict[str, Any]:

        """
        Compatibility method used by app.py.

        Supports:

            scanner.scan_device(ip)

        and:

            scanner.scan_device(
                ip,
                aggressive=True
            )
        """

        return self.scan_host(
            target,
            aggressive=aggressive,
        )

    # =========================================================
    # OTHER COMPATIBILITY METHODS
    # =========================================================

    def scan(
        self,
        target: str,
        aggressive: bool = False,
    ) -> dict[str, Any]:

        return self.scan_host(
            target,
            aggressive=aggressive,
        )

    def scan_ports(
        self,
        target: str,
        aggressive: bool = False,
    ) -> dict[str, Any]:

        return self.scan_host(
            target,
            aggressive=aggressive,
        )

    # =========================================================
    # MULTIPLE DEVICE SCAN
    # =========================================================

    def scan_devices(
        self,
        devices: list[dict[str, Any] | str],
        aggressive: bool = False,
    ) -> list[dict[str, Any]]:

        results = []

        for item in devices:

            if isinstance(item, dict):

                target = item.get("ip")

            else:

                target = str(item)

            if not target:
                continue

            try:

                result = self.scan_device(
                    target,
                    aggressive=aggressive,
                )

            except ValueError as exc:

                result = {
                    "ip": str(target),
                    "state": "error",
                    "ports": [],
                    "open_ports": 0,
                    "scan_status": "invalid_target",
                    "error": str(exc),
                }

            results.append(result)

        return results

    # =========================================================
    # BUILD RISK FINDINGS
    # =========================================================

    @staticmethod
    def build_risk_findings(
        scan_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        findings = []

        for result in scan_results:

            ip = result.get(
                "ip",
                "Unknown",
            )

            for port in result.get(
                "ports",
                [],
            ):

                risk = port.get(
                    "risk",
                    "Informational",
                )

                if risk == "Informational":
                    continue

                findings.append(
                    {
                        "ip": ip,

                        "port": port.get(
                            "port"
                        ),

                        "service": port.get(
                            "service",
                            "Unknown",
                        ),

                        "level": risk,

                        "title": port.get(
                            "title",
                            "Potential service exposure",
                        ),

                        "description": port.get(
                            "description",
                            "",
                        ),

                        "possible_attack": port.get(
                            "possible_attack",
                            "",
                        ),

                        "why_it_matters": port.get(
                            "why_it_matters",
                            "",
                        ),

                        "how_to_defend": port.get(
                            "how_to_defend",
                            "",
                        ),
                    }
                )

        return findings


# =============================================================
# COMMAND-LINE TEST
# =============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "WiFi Sentinel V2.0 "
            "Defensive TCP Exposure Scanner"
        )
    )

    parser.add_argument(
        "ip",
        help="Authorized IPv4 address",
    )

    parser.add_argument(
        "--aggressive",
        action="store_true",
        help=(
            "Use the broader bounded TCP port set. "
            "Still subject to host timeout."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="Host timeout in seconds",
    )

    args = parser.parse_args()

    scanner = PortScanner(
        timeout=args.timeout
    )

    print("=" * 60)
    print("WiFi Sentinel V2.0")
    print("Defensive Port Analysis")
    print("=" * 60)

    print(
        f"Target          : {args.ip}"
    )

    print(
        f"Nmap available  : "
        f"{scanner.available()}"
    )

    print(
        f"Mode            : "
        f"{'Aggressive' if args.aggressive else 'Standard'}"
    )

    print(
        f"Timeout         : "
        f"{scanner.timeout}s"
    )

    print("-" * 60)

    if not scanner.available():

        print(
            "ERROR: Nmap is not available in PATH."
        )

        return

    result = scanner.scan_device(
        args.ip,
        aggressive=args.aggressive,
    )

    print(
        f"Scan status     : "
        f"{result.get('scan_status')}"
    )

    print(
        f"Open ports      : "
        f"{result.get('open_ports', 0)}"
    )

    if result.get("error"):

        print(
            f"Error           : "
            f"{result['error']}"
        )

        return

    print("-" * 60)

    ports = result.get(
        "ports",
        [],
    )

    if not ports:

        print(
            "No open TCP ports were identified "
            "in the selected scan range."
        )

        print()

        print(
            "No service-specific attack scenario "
            "was confirmed by this scan."
        )

        print()

        print(
            "General defense:"
        )

        print(
            "- Keep device firmware updated."
        )

        print(
            "- Disable unnecessary services."
        )

        print(
            "- Use strong unique administrator credentials."
        )

        print(
            "- Restrict management interfaces."
        )

        return

    for port in ports:

        print()

        print(
            f"TCP/{port['port']}"
        )

        print(
            f"Service         : "
            f"{port.get('service') or 'Unknown'}"
        )

        print(
            f"Product         : "
            f"{port.get('product') or 'Unknown'}"
        )

        print(
            f"Version         : "
            f"{port.get('version') or 'Unknown'}"
        )

        print(
            f"Risk            : "
            f"{port.get('risk', 'Informational')}"
        )

        print()

        print(
            "Possible attack:"
        )

        print(
            port.get(
                "possible_attack",
                "",
            )
        )

        print()

        print(
            "Why it matters:"
        )

        print(
            port.get(
                "why_it_matters",
                "",
            )
        )

        print()

        print(
            "How to defend:"
        )

        print(
            port.get(
                "how_to_defend",
                "",
            )
        )

        print("-" * 60)


if __name__ == "__main__":
    main()