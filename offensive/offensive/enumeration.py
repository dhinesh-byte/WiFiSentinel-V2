"""
VulnScan v4.13
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
import xml.etree.ElementTree as ET
from collections.abc import Callable
from threading import Event
from typing import Any


from nmap_options import NSE_MODULES, SAFE_NSE_MODULES, SCAN_FLAGS, has_raw_scan_privileges
from scanner.nmap_process import nmap_stderr_excerpt, run_nmap


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
        scan_method: str = "connect",
        nmap_options: dict[str, Any] | None = None,
    ) -> None:

        self.timeout = max(
            15,
            min(timeout, 600),
        )

        self.port_range = port_range
        if scan_method not in {"syn", "connect"}:
            raise ValueError("TCP scan method must be syn or connect.")
        self.scan_method = scan_method
        self.nmap_options = nmap_options

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
        allow_ipv6: bool = False,
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

        if address.version != 4 and not (allow_ipv6 and address.version == 6):

            raise ValueError(
            "IPv6 addresses require administrator scan options."
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
            "os": "Unknown",
            "os_accuracy": 0,
            "os_detection_status": "not_requested",
            "hostname": "Unknown",
            "host_state": "unknown",
            "status_reason": "",
            "mac": "Unknown",
            "vendor": "Unknown",
            "ports": [],
            "port_states": [],
            "uncertain_ports": [],
            "scripts": [],
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

        for script in host.findall("./hostscript/script"):
            script_id = script.get("id", "")
            script_output = script.get("output", "").strip()
            if script_id and script_output:
                result["scripts"].append({"id": script_id, "output": script_output})

        host_status = host.find("status")
        host_state = (
            host_status.get("state", "unknown")
            if host_status is not None
            else "unknown"
        )
        result["host_state"] = host_state
        result["status_reason"] = (
            host_status.get("reason", "")
            if host_status is not None
            else ""
        )

        for address in host.findall("address"):
            if address.get("addrtype") == "mac":
                result["mac"] = address.get("addr", "Unknown")
                result["vendor"] = address.get("vendor", "Unknown")

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

            if address.get("addrtype") in {"ipv4", "ipv6"} and not result["ip"]:
                result["ip"] = address.get("addr", "")

        os_element = host.find("os")
        os_match = os_element.find("osmatch") if os_element is not None else None
        if os_match is not None:
            result["os"] = os_match.get("name", "Unknown")
            try:
                result["os_accuracy"] = int(os_match.get("accuracy", "0"))
            except ValueError:
                result["os_accuracy"] = 0

        trace_element = host.find("trace")
        if trace_element is not None:
            result["traceroute"] = [
                {
                    "ttl": hop.get("ttl", ""),
                    "ip": hop.get("ipaddr", ""),
                    "host": hop.get("host", ""),
                    "rtt": hop.get("rtt", ""),
                }
                for hop in trace_element.findall("hop")
            ]

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
        port_elements = ports_element.findall("port") if ports_element is not None else []

        for port_element in port_elements:

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
            state_reason = state_element.get("reason", "") if state_element is not None else ""

            service_name = ""

            product = ""

            version = ""

            extrainfo = ""

            tunnel = ""
            service_method = ""
            service_confidence = ""
            cpes: list[str] = []
            scripts: list[dict[str, str]] = []

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

                service_method = service_element.get("method", "")
                service_confidence = service_element.get("conf", "")

                cpes = [
                    cpe.text.strip()
                    for cpe in service_element.findall("cpe")
                    if cpe.text and cpe.text.strip()
                ]

            for script in port_element.findall("script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "").strip()
                if script_id and script_output:
                    scripts.append({"id": script_id, "output": script_output})

            evidence = []
            if service_name:
                identity = " ".join(value for value in (product, version) if value)
                evidence.append(
                    f"Nmap identified {protocol}/{port_id} as {service_name}"
                    + (f" ({identity})" if identity else ".")
                )
            if extrainfo:
                evidence.append(f"Nmap service detail: {extrainfo}")
            evidence.extend(f"NSE {item['id']}: {item['output']}" for item in scripts)

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
                    "reason": state_reason,
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
                    "method": service_method or "Unknown",
                    "confidence": service_confidence or "Unknown",
                    "scripts": scripts,
                    "evidence": evidence,
                }
            result["port_states"].append(port_result)
            if state == "open":
                result["ports"].append(port_result)
            elif protocol == "udp" and state == "open|filtered":
                result["uncertain_ports"].append(port_result)

        return result

    # =========================================================
    # ENUMERATE ONE HOST
    # =========================================================

    def enumerate_host(
        self,
        ip_address: str,
        nse_modules: tuple[str, ...] = (),
        admin_nmap_options: dict[str, Any] | None = None,
        cancel_event: Event | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        command_callback: Callable[[list[str]], None] | None = None,
        output_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """
        Enumerate TCP services on one authorized host.

        Uses Nmap service detection on ports 1-1024 by default.
        """

        nmap_options = admin_nmap_options or self.nmap_options
        ip_address = self.validate_ip(ip_address, allow_ipv6=bool(nmap_options and nmap_options.get("ipv6")))

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

        if nmap_options is None:
            command = [
                self.nmap_path,
                "-sS" if self.scan_method == "syn" else "-sT",
                "-sV",
                "-p",
                self.port_range,
                "-oX",
                "-",
                ip_address,
            ]
        else:
            scan_type = nmap_options["scan_type"]
            port_preset = nmap_options.get(
                "port_preset",
                "custom" if nmap_options.get("ports") else "profile",
            )
            ports = nmap_options.get("ports")
            command = [self.nmap_path, SCAN_FLAGS[scan_type]]
            if nmap_options["ipv6"]:
                command.append("-6")
            if nmap_options["discovery_method"] == "none":
                command.append("-Pn")
            if nmap_options["service_detection"] and scan_type != "ip-protocol":
                command.append("-sV")
            if port_preset == "top-100":
                command.extend(["--top-ports", "100"])
            elif port_preset == "top-1000":
                command.extend(["--top-ports", "1000"])
            elif port_preset == "all":
                command.extend(["-p", "0-255" if scan_type == "ip-protocol" else "-"])
            else:
                selected_ports = ports or (
                    "0-255" if scan_type == "ip-protocol"
                    else ",".join(str(port) for port in _COMMON_UDP_PORTS)
                    if scan_type == "udp"
                    else self.port_range
                )
                if scan_type == "udp":
                    selected_ports = f"U:{selected_ports}"
                command.extend([
                    "-p",
                    selected_ports,
                ])
            command.append(f"-{nmap_options['timing']}")
            if nmap_options.get("max_rate"):
                command.extend(["--max-rate", str(nmap_options["max_rate"])])
            if nmap_options.get("scan_delay"):
                command.extend(["--scan-delay", f"{nmap_options['scan_delay']}ms"])
            command.extend(["--max-retries", str(nmap_options["max_retries"])])
            command.extend(["--host-timeout", f"{nmap_options['host_timeout']}s"])
            if nmap_options["reason"]:
                command.append("--reason")
            if nmap_options["traceroute"]:
                command.append("--traceroute")
            if nmap_options["packet_trace"]:
                command.append("--packet-trace")
            if nmap_options.get("exclude_ports"):
                command.extend(["--exclude-ports", nmap_options["exclude_ports"]])
            if nmap_options["os_detection"] and has_raw_scan_privileges():
                command.append("-O")
        scripts = tuple(
            script
            for module in dict.fromkeys((*nse_modules, *(nmap_options or {}).get("nse_modules", [])))
            for script in NSE_MODULES.get(module, ())
        )
        if nmap_options is not None:
            command.extend(["-oX", "-", ip_address])
        if scripts:
            command[-1:-1] = ["--script", ",".join(scripts)]

        logger.info(
            "Enumerating authorized host: %s",
            ip_address,
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

            logger.warning(
                "Unable to execute Nmap for %s: %s",
                ip_address,
                exc,
            )

            result["errors"].append(str(exc))

            return result

        if completed.status != "completed":
            result["status"] = completed.status

            result["errors"].append(completed.error or "Nmap enumeration did not complete.")

            return result

        parsed = self.parse_xml(
            completed.stdout
        )

        if nmap_options:
            if nmap_options["os_detection"]:
                parsed["os_detection_status"] = (
                    "detected" if parsed.get("os") != "Unknown" else "not_detected"
                ) if has_raw_scan_privileges() else "skipped_unprivileged"
                if not has_raw_scan_privileges():
                    parsed["os_detection_reason"] = (
                        "Nmap OS fingerprinting requires elevated privileges."
                    )
                elif parsed.get("os") == "Unknown":
                    parsed["os_detection_reason"] = (
                        "Nmap did not return a confident OS match."
                    )
            if nmap_options["packet_trace"]:
                parsed["packet_trace"] = completed.stderr[:12000]
            if nmap_options.get("output_format") in {"xml", "both"}:
                parsed["nmap_xml"] = completed.stdout

        parsed["ip"] = (
            parsed.get("ip")
            or ip_address
        )

        if completed.returncode != 0:

            error_message = (
                nmap_stderr_excerpt(completed.stderr)
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
        admin_nmap_options: dict[str, Any] | None = None,
        cancel_event: Event | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        command_callback: Callable[[list[str]], None] | None = None,
        output_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Check a fixed, small set of common UDP ports on one authorized host."""
        ip_address = self.validate_ip(
            ip_address,
            allow_ipv6=bool(admin_nmap_options and admin_nmap_options.get("ipv6")),
        )
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
        if admin_nmap_options is None:
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
        else:
            preset = admin_nmap_options.get("port_preset", "profile")
            custom_ports = admin_nmap_options.get("ports", "")
            command = [self.nmap_path, "-sU"]
            if admin_nmap_options["ipv6"]:
                command.append("-6")
            if admin_nmap_options["discovery_method"] == "none":
                command.append("-Pn")
            if admin_nmap_options["service_detection"]:
                command.append("-sV")
            if preset == "top-100":
                command.extend(["--top-ports", "100"])
            elif preset == "top-1000":
                command.extend(["--top-ports", "1000"])
            elif preset == "all":
                command.extend(["-p", "U:1-65535"])
            else:
                selected_udp_ports = custom_ports if preset == "custom" else udp_ports
                command.extend(["-p", f"U:{selected_udp_ports}"])
            command.extend([
                f"-{admin_nmap_options['timing']}",
            ])
            if admin_nmap_options.get("max_rate"):
                command.extend(["--max-rate", str(admin_nmap_options["max_rate"])])
            if admin_nmap_options.get("scan_delay"):
                command.extend(["--scan-delay", f"{admin_nmap_options['scan_delay']}ms"])
            command.extend([
                "--max-retries",
                str(admin_nmap_options["max_retries"]),
                "--host-timeout",
                f"{admin_nmap_options['host_timeout']}s",
            ])
            if admin_nmap_options["reason"]:
                command.append("--reason")
            if admin_nmap_options["traceroute"]:
                command.append("--traceroute")
            if admin_nmap_options["packet_trace"]:
                command.append("--packet-trace")
            if admin_nmap_options.get("exclude_ports"):
                command.extend(["--exclude-ports", admin_nmap_options["exclude_ports"]])
            scripts = tuple(
                script
                for module in admin_nmap_options.get("nse_modules", [])
                for script in NSE_MODULES.get(module, ())
            )
            if scripts:
                command.extend(["--script", ",".join(scripts)])
            command.extend(["-oX", "-", ip_address])
        logger.info("Checking selected UDP services on authorized host: %s", ip_address)
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
            result["errors"].append(str(exc))
            return result

        if completed.status != "completed":
            result["status"] = completed.status
            result["errors"].append(completed.error or "Nmap UDP enumeration did not complete.")
            return result

        parsed = self.parse_xml(completed.stdout)
        parsed["ip"] = parsed.get("ip") or ip_address
        parsed["scan_type"] = "udp"
        if admin_nmap_options:
            if admin_nmap_options["packet_trace"]:
                parsed["packet_trace"] = completed.stderr[:12000]
            if admin_nmap_options.get("output_format") in {"xml", "both"}:
                parsed["nmap_xml"] = completed.stdout
        if completed.returncode != 0:
            parsed["status"] = "failed"
            parsed.setdefault("errors", []).append(
                nmap_stderr_excerpt(completed.stderr) or "Nmap UDP enumeration returned an error."
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
            "VulnScan v4.13 - "
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
    print("VulnScan v4.13")
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