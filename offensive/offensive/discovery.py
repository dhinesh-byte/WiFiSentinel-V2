"""
VulnScan v4.13
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
import xml.etree.ElementTree as ET
from collections.abc import Callable
from threading import Event
from typing import Any

from scanner.nmap_process import nmap_stderr_excerpt, run_nmap

logger = logging.getLogger(__name__)


class OffensiveDiscovery:
    """
    Authorized network discovery engine.

    Uses Nmap host discovery and returns structured results.
    """

    def __init__(
        self,
        timeout: int | None = None,
    ) -> None:

        self.timeout = timeout

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
        *,
        allow_ipv6: bool = False,
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

                if network.version != 4 and not allow_ipv6:

                    raise ValueError(
                        "IPv6 networks require administrator scan options."
                    )

                return str(network)

            address = ipaddress.ip_address(
                target
            )

            if address.version != 4 and not allow_ipv6:

                raise ValueError(
                    "IPv6 addresses require administrator scan options."
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
            ipv6 = ""
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

                elif address_type == "ipv6":

                    ipv6 = address.get("addr", "")

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

            ip_address = ipv4 or ipv6
            if not ip_address:

                continue

            hosts.append(
                {
                    "ip": ip_address,
                    "ipv6": ipv6 or "Unknown",
                    "hostname": hostname
                    or "Unknown",
                    "mac": mac
                    or "Unknown",
                    "vendor": vendor
                    or "Unknown",
                    "state": state,
                    "status_reason": (
                        status_element.get("reason", "")
                        if status_element is not None
                        else ""
                    ),
                    "discovery_method": "Nmap host discovery (-sn)",
                    "evidence": [f"Nmap reported host state {state} for {ip_address}."],
                }
            )

        return hosts

    # =========================================================
    # DISCOVERY
    # =========================================================

    def discover(
        self,
        target: str,
        nmap_options: dict[str, Any] | None = None,
        cancel_event: Event | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        command_callback: Callable[[list[str]], None] | None = None,
        output_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """
        Discover active hosts on an authorized target.

        Returns a structured dictionary suitable for Flask
        or another application layer.
        """

        allow_ipv6 = bool(nmap_options and nmap_options.get("ipv6"))
        validated_target = self.validate_target(target, allow_ipv6=allow_ipv6)
        target_is_network = "/" in target.strip()

        logger.info(
            "Starting offensive discovery: %s",
            validated_target,
        )

        if nmap_options and nmap_options["discovery_method"] == "none":
            network = ipaddress.ip_network(validated_target, strict=False)
            if target_is_network and network.num_addresses > 1:
                return {
                    "status": "failed",
                    "target": validated_target,
                    "hosts": [],
                    "errors": ["Skipping discovery is limited to one explicitly selected host."],
                }
            address = str(network.network_address)
            return {
                "status": "completed",
                "target": validated_target,
                "hosts": [{
                    "ip": address,
                    "ipv6": address if network.version == 6 else "Unknown",
                    "hostname": "Unknown",
                    "mac": "Unavailable",
                    "vendor": "Unavailable",
                    "state": "up",
                    "status_reason": "Host assumed online; discovery was disabled by the administrator.",
                    "discovery_method": "Discovery disabled (explicit host scope)",
                    "evidence": [f"The selected host {address} was treated as online at the administrator's request."],
                }],
                "host_count": 1,
                "errors": [],
            }

        if not self.available():
            logger.error("Nmap is not available.")
            return {
                "status": "failed",
                "target": validated_target,
                "hosts": [],
                "errors": ["Nmap was not found in PATH."],
            }

        command = [self.nmap_path, "-sn"]
        if allow_ipv6:
            command.append("-6")
        if nmap_options is not None:
            discovery_args = {
                "default": [],
                "arp": ["-PR"],
                "icmp": ["-PE"],
                "tcp-syn": ["-PS80,443"],
                "tcp-ack": ["-PA80,443"],
                "udp": ["-PU40125"],
            }
            command.extend(discovery_args[nmap_options["discovery_method"]])
            command.append(f"-{nmap_options['timing']}")
            if nmap_options.get("max_rate"):
                command.extend(["--max-rate", str(nmap_options["max_rate"])])
            if nmap_options.get("scan_delay"):
                command.extend(["--scan-delay", f"{nmap_options['scan_delay']}ms"])
            command.extend([
                "--max-retries",
                str(nmap_options["max_retries"]),
                "--host-timeout",
                f"{nmap_options['host_timeout']}s",
            ])
            if nmap_options["reason"]:
                command.append("--reason")
            if nmap_options["traceroute"]:
                command.append("--traceroute")
            if nmap_options["packet_trace"]:
                command.append("--packet-trace")
        command.extend(["-oX", "-", validated_target])

        logger.debug(
            "Executing authorized discovery."
        )

        try:

            completed = run_nmap(
                command,
                timeout=self.timeout,
                cancel_event=cancel_event,
                progress_callback=progress_callback,
                command_callback=command_callback,
                output_callback=output_callback,
            )

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

        if completed.status != "completed":
            logger.warning(
                "Discovery ended with status %s: %s",
                completed.status,
                validated_target,
            )
            return {
                "status": completed.status,
                "target": validated_target,
                "hosts": [],
                "errors": [completed.error or "Nmap discovery did not complete."],
            }

        if completed.returncode != 0:

            error_message = (
                nmap_stderr_excerpt(completed.stderr)
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

        result = {
            "status": "completed",
            "target": validated_target,
            "hosts": hosts,
            "host_count": len(hosts),
            "errors": [],
        }
        if nmap_options and nmap_options.get("output_format") in {"xml", "both"}:
            result["nmap_xml"] = completed.stdout
        return result


# =============================================================
# COMMAND-LINE INTERFACE
# =============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "VulnScan v4.13 - "
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
        default=None,
        help="Optional discovery timeout in seconds; omitted means wait for Nmap.",
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
    print("VulnScan v4.13")
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