"""
WiFi Sentinel V2.0
Offensive Security Module
Authorized Network Discovery

Purpose:
    Discover active hosts on a network that the operator owns
    or is explicitly authorized to assess.

This module performs discovery only.
It does not exploit hosts or attempt authentication.
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


class OffensiveDiscovery:
    """
    Authorized network discovery engine.

    Uses Nmap host discovery and returns structured results.
    """

    def __init__(
        self,
        timeout: int = 60,
    ) -> None:

        self.timeout = max(
            10,
            min(timeout, 300),
        )

        self.nmap_path = shutil.which("nmap")

    # =========================================================
    # NMAP AVAILABILITY
    # =========================================================

    def available(self) -> bool:
        """Return True when Nmap is available."""

        return self.nmap_path is not None

    # =========================================================
    # TARGET VALIDATION
    # =========================================================

    @staticmethod
    def validate_target(
        target: str,
    ) -> str:
        """
        Validate an IPv4 address or IPv4 CIDR network.
        """

        if not isinstance(target, str):

            raise ValueError(
                "Target must be a string."
            )

        target = target.strip()

        if not target:

            raise ValueError(
                "Target cannot be empty."
            )

        try:

            if "/" in target:

                network = ipaddress.ip_network(
                    target,
                    strict=False,
                )

                if network.version != 4:

                    raise ValueError(
                        "Only IPv4 networks are supported."
                    )

                return str(network)

            address = ipaddress.ip_address(
                target
            )

            if address.version != 4:

                raise ValueError(
                    "Only IPv4 addresses are supported."
                )

            return str(address)

        except ValueError as exc:

            raise ValueError(
                f"Invalid IPv4 target: {target}"
            ) from exc

    # =========================================================
    # NMAP XML PARSER
    # =========================================================

    @staticmethod
    def parse_xml(
        xml_data: str,
    ) -> list[dict[str, Any]]:
        """
        Parse Nmap XML discovery output.
        """

        hosts: list[dict[str, Any]] = []

        if not xml_data.strip():

            return hosts

        try:

            root = ET.fromstring(
                xml_data
            )

        except ET.ParseError as exc:

            logger.error(
                "Unable to parse Nmap XML: %s",
                exc,
            )

            return hosts

        for host in root.findall("host"):

            status_element = host.find(
                "status"
            )

            state = "unknown"

            if status_element is not None:

                state = status_element.get(
                    "state",
                    "unknown",
                )

            ipv4 = ""
            mac = ""
            vendor = ""

            for address in host.findall(
                "address"
            ):

                address_type = address.get(
                    "addrtype",
                    "",
                )

                if address_type == "ipv4":

                    ipv4 = address.get(
                        "addr",
                        "",
                    )

                elif address_type == "mac":

                    mac = address.get(
                        "addr",
                        "",
                    )

                    vendor = address.get(
                        "vendor",
                        "",
                    )

            hostname = ""

            hostnames_element = host.find(
                "hostnames"
            )

            if hostnames_element is not None:

                hostname_element = (
                    hostnames_element.find(
                        "hostname"
                    )
                )

                if hostname_element is not None:

                    hostname = hostname_element.get(
                        "name",
                        "",
                    )

            if not ipv4:

                continue

            hosts.append(
                {
                    "ip": ipv4,
                    "hostname": hostname
                    or "Unknown",
                    "mac": mac
                    or "Unknown",
                    "vendor": vendor
                    or "Unknown",
                    "state": state,
                }
            )

        return hosts

    # =========================================================
    # DISCOVERY
    # =========================================================

    def discover(
        self,
        target: str,
    ) -> dict[str, Any]:
        """
        Discover active hosts on an authorized target.

        Returns a structured dictionary suitable for Flask
        or another application layer.
        """

        validated_target = self.validate_target(
            target
        )

        logger.info(
            "Starting offensive discovery: %s",
            validated_target,
        )

        if not self.available():

            logger.error(
                "Nmap is not available."
            )

            return {
                "status": "failed",
                "target": validated_target,
                "hosts": [],
                "errors": [
                    "Nmap was not found in PATH."
                ],
            }

        command = [
            self.nmap_path,

            # Host discovery only.
            "-sn",

            # XML output to stdout.
            "-oX",
            "-",

            validated_target,
        ]

        logger.debug(
            "Executing authorized discovery."
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
                "Discovery timed out: %s",
                validated_target,
            )

            return {
                "status": "timeout",
                "target": validated_target,
                "hosts": [],
                "errors": [
                    "Nmap discovery timed out."
                ],
            }

        except OSError as exc:

            logger.error(
                "Unable to execute Nmap: %s",
                exc,
            )

            return {
                "status": "failed",
                "target": validated_target,
                "hosts": [],
                "errors": [
                    str(exc)
                ],
            }

        if completed.returncode != 0:

            error_message = (
                completed.stderr.strip()
                or "Nmap returned an error."
            )

            logger.error(
                "Nmap discovery failed: %s",
                error_message,
            )

            return {
                "status": "failed",
                "target": validated_target,
                "hosts": [],
                "errors": [
                    error_message
                ],
            }

        hosts = self.parse_xml(
            completed.stdout
        )

        logger.info(
            "Discovery completed: %d hosts found.",
            len(hosts),
        )

        return {
            "status": "completed",
            "target": validated_target,
            "hosts": hosts,
            "host_count": len(hosts),
            "errors": [],
        }


# =============================================================
# COMMAND-LINE INTERFACE
# =============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "WiFi Sentinel V2.0 - "
            "Authorized Offensive Discovery"
        )
    )

    parser.add_argument(
        "target",
        help=(
            "Authorized IPv4 address or CIDR network, "
            "for example 192.168.1.0/24"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Discovery timeout in seconds.",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(levelname)s - %(message)s"
        ),
    )

    scanner = OffensiveDiscovery(
        timeout=args.timeout
    )

    print("=" * 60)
    print("WiFi Sentinel V2.0")
    print("Offensive Security - Discovery")
    print("=" * 60)

    print(
        f"Target         : {args.target}"
    )

    print(
        f"Nmap available : "
        f"{scanner.available()}"
    )

    print("-" * 60)

    try:

        result = scanner.discover(
            args.target
        )

    except ValueError as exc:

        print(
            f"Invalid target: {exc}"
        )

        return

    print(
        f"Status         : "
        f"{result['status']}"
    )

    print(
        f"Hosts found    : "
        f"{result.get('host_count', 0)}"
    )

    print("-" * 60)

    for host in result.get(
        "hosts",
        [],
    ):

        print(
            f"IP       : "
            f"{host.get('ip', 'Unknown')}"
        )

        print(
            f"Hostname : "
            f"{host.get('hostname', 'Unknown')}"
        )

        print(
            f"MAC      : "
            f"{host.get('mac', 'Unknown')}"
        )

        print(
            f"Vendor   : "
            f"{host.get('vendor', 'Unknown')}"
        )

        print(
            f"State    : "
            f"{host.get('state', 'Unknown')}"
        )

        print("-" * 60)

    for error in result.get(
        "errors",
        [],
    ):

        print(
            f"ERROR: {error}"
        )


if __name__ == "__main__":
    main()