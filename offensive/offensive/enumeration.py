"""
WiFi Sentinel V2.0
Offensive Security Module
Authorized Service Enumeration

Purpose:
    Perform controlled TCP service enumeration against hosts
    discovered on an authorized network.

This module does not:
    - exploit services
    - attempt passwords
    - perform credential attacks
    - modify remote systems
    - perform destructive actions
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any


logger = logging.getLogger(__name__)

_COMMON_UDP_PORTS = (53, 67, 68, 123, 137, 138, 161, 500, 514, 1900, 4500)


class OffensiveEnumerator:
    """
    Controlled service enumeration engine.

    Nmap is used for TCP port and service detection.
    """

    def __init__(
        self,
        timeout: int = 120,
        port_range: str = "1-1024",
    ) -> None:

        self.timeout = max(
            15,
            min(timeout, 600),
        )

        self.port_range = port_range

        self.nmap_path = shutil.which(
            "nmap"
        )

    # =========================================================
    # NMAP AVAILABILITY
    # =========================================================

    def available(self) -> bool:
        """Return whether Nmap is available."""

        return self.nmap_path is not None

    # =========================================================
    # IP VALIDATION
    # =========================================================

    @staticmethod
    def validate_ip(
        ip_address: str,
    ) -> str:
        """
        Validate an IPv4 host address.
        """

        if not isinstance(
            ip_address,
            str,
        ):

            raise ValueError(
                "IP address must be a string."
            )

        ip_address = (
            ip_address.strip()
        )

        try:

            address = ipaddress.ip_address(
                ip_address
            )

        except ValueError as exc:

            raise ValueError(
                f"Invalid IP address: "
                f"{ip_address}"
            ) from exc

        if address.version != 4:

            raise ValueError(
                "Only IPv4 addresses are supported."
            )

        return str(address)

    # =========================================================
    # XML PARSER
    # =========================================================

    @staticmethod
    def parse_xml(
        xml_data: str,
    ) -> dict[str, Any]:
        """
        Parse Nmap XML service enumeration output.
        """

        result: dict[str, Any] = {
            "status": "completed",
            "ip": "",
            "hostname": "Unknown",
            "host_state": "unknown",
            "ports": [],
            "uncertain_ports": [],
            "errors": [],
        }

        if not xml_data.strip():

            result["status"] = "failed"

            result["errors"].append(
                "Nmap returned empty output."
            )

            return result

        try:

            root = ET.fromstring(
                xml_data
            )

        except ET.ParseError as exc:

            logger.error(
                "Nmap XML parsing failed: %s",
                exc,
            )

            result["status"] = "failed"

            result["errors"].append(
                f"Invalid Nmap XML: {exc}"
            )

            return result

        host = root.find("host")

        if host is None:

            result["status"] = "failed"

            result["errors"].append(
                "No host information returned."
            )

            return result

        host_status = host.find("status")
        host_state = (
            host_status.get("state", "unknown")
            if host_status is not None
            else "unknown"
        )
        result["host_state"] = host_state

        if host_state != "up":

            result["status"] = "failed"

            if host_state == "down":
                error_message = "Nmap reported the target host as unreachable."
            else:
                error_message = "Nmap output did not confirm that the target host is up."

            result["errors"].append(error_message)

            return result

        # -----------------------------------------------------
        # HOST ADDRESS
        # -----------------------------------------------------

        for address in host.findall(
            "address"
        ):

            if (
                address.get("addrtype")
                == "ipv4"
            ):

                result["ip"] = (
                    address.get(
                        "addr",
                        "",
                    )
                )

                break

        # -----------------------------------------------------
        # HOSTNAME
        # -----------------------------------------------------

        hostnames = host.find(
            "hostnames"
        )

        if hostnames is not None:

            hostname = hostnames.find(
                "hostname"
            )

            if hostname is not None:

                result["hostname"] = (
                    hostname.get(
                        "name",
                        "Unknown",
                    )
                )

        # -----------------------------------------------------
        # PORTS
        # -----------------------------------------------------

        ports_element = host.find(
            "ports"
        )

        if ports_element is None:

            return result

        for port_element in ports_element.findall(
            "port"
        ):

            protocol = port_element.get(
                "protocol",
                "tcp",
            )

            port_id = port_element.get(
                "portid",
                "",
            )

            state_element = (
                port_element.find(
                    "state"
                )
            )

            service_element = (
                port_element.find(
                    "service"
                )
            )

            state = "unknown"

            if state_element is not None:

                state = state_element.get(
                    "state",
                    "unknown",
                )

            service_name = ""

            product = ""

            version = ""

            extrainfo = ""

            tunnel = ""
            cpes: list[str] = []

            if service_element is not None:

                service_name = (
                    service_element.get(
                        "name",
                        "",
                    )
                )

                product = (
                    service_element.get(
                        "product",
                        "",
                    )
                )

                version = (
                    service_element.get(
                        "version",
                        "",
                    )
                )

                extrainfo = (
                    service_element.get(
                        "extrainfo",
                        "",
                    )
                )

                tunnel = (
                    service_element.get(
                        "tunnel",
                        "",
                    )
                )

                cpes = [
                    cpe.text.strip()
                    for cpe in service_element.findall("cpe")
                    if cpe.text and cpe.text.strip()
                ]

            # Only expose ports that Nmap reports
            # as open.
            if state != "open" and not (
                protocol == "udp" and state == "open|filtered"
            ):

                continue

            try:

                port_number = int(
                    port_id
                )

            except ValueError:

                continue

            port_result = {
                    "port": port_number,
                    "protocol": protocol,
                    "state": state,
                    "service": (
                        service_name
                        or "unknown"
                    ),
                    "product": product
                    or "Unknown",
                    "version": version
                    or "Unknown",
                    "extrainfo": extrainfo
                    or "",
                    "tunnel": tunnel
                    or "",
                    "cpes": cpes,
                }
            if state == "open":
                result["ports"].append(port_result)
            else:
                result["uncertain_ports"].append(port_result)

        return result

    # =========================================================
    # ENUMERATE ONE HOST
    # =========================================================

    def enumerate_host(
        self,
        ip_address: str,
    ) -> dict[str, Any]:
        """
        Enumerate TCP services on one authorized host.

        Uses Nmap service detection on ports 1-1024 by default.
        """

        ip_address = self.validate_ip(
            ip_address
        )

        result: dict[str, Any] = {
            "status": "failed",
            "ip": ip_address,
            "hostname": "Unknown",
            "ports": [],
            "errors": [],
        }

        if not self.available():

            result["errors"].append(
                "Nmap was not found in PATH."
            )

            logger.error(
                "Nmap is unavailable."
            )

            return result

        command = [
            self.nmap_path,

            # TCP SYN scan.
            "-sS",

            # Service/version detection.
            "-sV",

            # Scan selected TCP ports.
            "-p",
            self.port_range,

            # XML output.
            "-oX",
            "-",

            # Target.
            ip_address,
        ]

        logger.info(
            "Enumerating authorized host: %s",
            ip_address,
        )

        try:

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )

        except subprocess.TimeoutExpired:

            logger.warning(
                "Enumeration timed out: %s",
                ip_address,
            )

            result["status"] = "timeout"

            result["errors"].append(
                "Nmap enumeration timed out."
            )

            return result

        except OSError as exc:

            logger.error(
                "Could not execute Nmap: %s",
                exc,
            )

            result["errors"].append(
                str(exc)
            )

            return result

        parsed = self.parse_xml(
            completed.stdout
        )

        parsed["ip"] = (
            parsed.get("ip")
            or ip_address
        )

        if completed.returncode != 0:

            error_message = (
                completed.stderr.strip()
                or "Nmap returned an error."
            )

            parsed["status"] = "failed"

            parsed.setdefault(
                "errors",
                [],
            ).append(
                error_message
            )

            logger.error(
                "Enumeration failed for %s: %s",
                ip_address,
                error_message,
            )

            return parsed

        logger.info(
            "Enumeration completed: "
            "%d open ports on %s",
            len(
                parsed.get(
                    "ports",
                    [],
                )
            ),
            ip_address,
        )

        return parsed

    def enumerate_udp_host(
        self,
        ip_address: str,
    ) -> dict[str, Any]:
        """Check a fixed, small set of common UDP ports on one authorized host."""
        ip_address = self.validate_ip(ip_address)
        result: dict[str, Any] = {
            "status": "failed",
            "ip": ip_address,
            "host_state": "unknown",
            "ports": [],
            "uncertain_ports": [],
            "errors": [],
            "scan_type": "udp",
        }
        if not self.available():
            result["errors"].append("Nmap was not found in PATH.")
            return result

        udp_ports = ",".join(str(port) for port in _COMMON_UDP_PORTS)
        command = [
            self.nmap_path,
            "-sU",
            "-sV",
            "-p",
            f"U:{udp_ports}",
            "-oX",
            "-",
            ip_address,
        ]
        logger.info("Checking selected UDP services on authorized host: %s", ip_address)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["errors"].append("Selected UDP enumeration timed out.")
            return result
        except OSError as exc:
            result["errors"].append(str(exc))
            return result

        parsed = self.parse_xml(completed.stdout)
        parsed["ip"] = parsed.get("ip") or ip_address
        parsed["scan_type"] = "udp"
        if completed.returncode != 0:
            parsed["status"] = "failed"
            parsed.setdefault("errors", []).append(
                completed.stderr.strip() or "Nmap UDP enumeration returned an error."
            )
        return parsed

    # =========================================================
    # ENUMERATE MULTIPLE HOSTS
    # =========================================================

    def enumerate_hosts(
        self,
        hosts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Enumerate a list of discovered hosts.

        Expected input:

        [
            {"ip": "192.168.1.1"},
            {"ip": "192.168.1.10"}
        ]
        """

        results: list[dict[str, Any]] = []

        errors: list[str] = []

        if not isinstance(
            hosts,
            list,
        ):

            return {
                "status": "failed",
                "hosts": [],
                "host_count": 0,
                "total_open_ports": 0,
                "errors": [
                    "Hosts must be provided as a list."
                ],
            }

        for host in hosts:

            if not isinstance(
                host,
                dict,
            ):

                errors.append(
                    "Invalid host entry skipped."
                )

                continue

            ip_address = host.get(
                "ip"
            )

            if not ip_address:

                errors.append(
                    "Host without an IP address skipped."
                )

                continue

            try:

                enumeration = (
                    self.enumerate_host(
                        ip_address
                    )
                )

            except ValueError as exc:

                errors.append(
                    str(exc)
                )

                continue

            # Preserve useful discovery
            # information.
            enumeration["mac"] = (
                host.get(
                    "mac",
                    "Unknown",
                )
            )

            enumeration["vendor"] = (
                host.get(
                    "vendor",
                    "Unknown",
                )
            )

            if (
                enumeration.get(
                    "hostname"
                )
                in (
                    "",
                    "Unknown",
                )
            ):

                enumeration["hostname"] = (
                    host.get(
                        "hostname",
                        "Unknown",
                    )
                )

            results.append(
                enumeration
            )

        total_open_ports = sum(
            len(
                host.get(
                    "ports",
                    [],
                )
            )
            for host in results
        )

        failed_hosts = sum(
            1
            for host in results
            if host.get("status")
            not in (
                "completed",
            )
        )

        if not results:

            overall_status = "failed"

        elif failed_hosts:

            overall_status = "partial"

        else:

            overall_status = "completed"

        return {
            "status": overall_status,
            "hosts": results,
            "host_count": len(results),
            "total_open_ports": (
                total_open_ports
            ),
            "errors": errors,
        }


# =============================================================
# COMMAND-LINE TEST
# =============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "WiFi Sentinel V2.0 - "
            "Authorized Offensive Enumeration"
        )
    )

    parser.add_argument(
        "target",
        help=(
            "Authorized IPv4 address to enumerate."
        ),
    )

    parser.add_argument(
        "--ports",
        default="1-1024",
        help=(
            "TCP port range. "
            "Default: 1-1024"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help=(
            "Maximum scan time per host "
            "in seconds."
        ),
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(levelname)s - %(message)s"
        ),
    )

    enumerator = OffensiveEnumerator(
        timeout=args.timeout,
        port_range=args.ports,
    )

    print("=" * 60)
    print("WiFi Sentinel V2.0")
    print("Offensive Security - Enumeration")
    print("=" * 60)

    print(
        f"Target         : {args.target}"
    )

    print(
        f"Nmap available : "
        f"{enumerator.available()}"
    )

    print(
        f"Port range     : "
        f"{args.ports}"
    )

    print("-" * 60)

    try:

        result = (
            enumerator.enumerate_host(
                args.target
            )
        )

    except ValueError as exc:

        print(
            f"Invalid target: {exc}"
        )

        return

    print(
        f"Status         : "
        f"{result.get('status')}"
    )

    print(
        f"Open ports     : "
        f"{len(result.get('ports', []))}"
    )

    print("-" * 60)

    for port in result.get(
        "ports",
        [],
    ):

        print(
            f"{port['port']}/"
            f"{port['protocol']}  "
            f"{port['service']}  "
            f"{port['product']} "
            f"{port['version']}"
        )

        if port.get(
            "extrainfo"
        ):

            print(
                f"  Info: "
                f"{port['extrainfo']}"
            )

    if not result.get(
        "ports"
    ):

        print(
            "No open TCP ports were "
            "identified in the selected range."
        )

    for error in result.get(
        "errors",
        [],
    ):

        print(
            f"ERROR: {error}"
        )


if __name__ == "__main__":
    main()