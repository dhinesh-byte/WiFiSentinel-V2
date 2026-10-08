import shutil
import xml.etree.ElementTree as ET
import ipaddress
from collections.abc import Callable
from threading import Event
from typing import Dict, List, Any
from scanner.nmap_process import nmap_stderr_excerpt, run_nmap


class NetworkDiscovery:
    """
    VulnScan v4.13
    Network discovery using Nmap.

    Use only on networks/devices you own or are authorized to assess.
    """

    def __init__(self):
        self.nmap_path = shutil.which("nmap")

    # ---------------------------------------------------------
    # NMAP CHECK
    # ---------------------------------------------------------

    def is_available(self) -> bool:
        return self.nmap_path is not None

    # ---------------------------------------------------------
    # VALIDATE TARGET
    # ---------------------------------------------------------

    def validate_target(self, target: str, allow_ipv6: bool = False) -> bool:
        try:
            network = ipaddress.ip_network(
                target,
                strict=False
            )
            return network.version == 4 or allow_ipv6
        except ValueError:
            return False

    @staticmethod
    def normalize_target(target: str, allow_ipv6: bool = False) -> str:
        """Return a canonical IPv4 or explicitly enabled IPv6 target."""
        raw_target = str(target).strip()
        network = ipaddress.ip_network(raw_target, strict=False)
        if network.version != 4 and not allow_ipv6:
            raise ValueError("IPv6 targets require administrator scan options.")
        return str(network) if "/" in raw_target else str(network.network_address)

    # ---------------------------------------------------------
    # DISCOVER HOSTS
    # ---------------------------------------------------------

    def discover(
        self,
        target: str,
        timeout: int | None = None,
        cancel_event: Event | None = None,
        activity_callback: Callable[[str], None] | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        command_callback: Callable[[list[str]], None] | None = None,
        output_callback: Callable[[dict[str, Any]], None] | None = None,
        nmap_options: dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        allow_ipv6 = bool(nmap_options and nmap_options.get("ipv6"))

        if not self.validate_target(target, allow_ipv6=allow_ipv6):
            return {
                "success": False,
                "error": f"Invalid network/IP: {target}",
                "target": target,
                "devices": []
            }
        target_is_network = "/" in target.strip()
        target = self.normalize_target(target, allow_ipv6=allow_ipv6)

        if nmap_options and nmap_options["discovery_method"] == "none":
            network = ipaddress.ip_network(target, strict=False)
            if target_is_network and network.num_addresses > 1:
                return {
                    "success": False,
                    "status": "failed",
                    "error": "Skipping discovery is limited to one explicitly selected host.",
                    "target": target,
                    "devices": [],
                }
            address = str(network.network_address)
            return {
                "success": True,
                "status": "completed",
                "target": target,
                "devices": [{
                    "ip": address,
                    "ipv6": address if network.version == 6 else "Unknown",
                    "hostname": "Unknown",
                    "mac": "Unavailable",
                    "vendor": "Unavailable",
                    "state": "up",
                    "status_reason": "Host assumed online; discovery was disabled by the administrator.",
                    "discovery_method": "Discovery disabled (explicit host scope)",
                    "evidence": ["The selected host was treated as online at the administrator's request."],
                }],
                "device_count": 1,
                "errors": [],
            }

        if not self.is_available():
            return {
                "success": False,
                "error": "Nmap was not found. Install Nmap and make sure it is in PATH.",
                "target": target,
                "devices": []
            }

        command = [self.nmap_path, "-sn"]
        if allow_ipv6:
            command.append("-6")
        if nmap_options is None:
            command.append("-PR")
        else:
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
            if nmap_options["reason"]:
                command.append("--reason")
            if nmap_options["traceroute"]:
                command.append("--traceroute")
            if nmap_options["packet_trace"]:
                command.append("--packet-trace")
        command.extend(["-oX", "-", target])

        try:
            completed = run_nmap(
                command,
                timeout=timeout,
                cancel_event=cancel_event,
                progress_callback=progress_callback,
                command_callback=command_callback,
                output_callback=output_callback,
            )
        except subprocess.TimeoutExpired:
            limit_text = "the configured timeout"
            if timeout is not None:
                limit_text = f"{timeout} seconds"
            return {
                "success": False,
                "error": f"Discovery timed out after {limit_text}.",
                "target": target,
                "devices": []
            }

        except (OSError, ValueError) as exc:
            return {
                "success": False,
                "status": "failed",
                "error": str(exc),
                "target": target,
                "devices": [],
            }

        if activity_callback is not None:
            activity_callback("Nmap host discovery process finished")
        if completed.status != "completed":
            return {
                "success": False,
                "status": completed.status,
                "error": completed.error or "Nmap discovery did not complete.",
                "target": target,
                "devices": [],
                "raw_output": completed.stdout,
            }

        if completed.returncode != 0:
            return {
                "success": False,
                "status": "failed",
                "error": nmap_stderr_excerpt(completed.stderr) or "Nmap discovery failed.",
                "target": target,
                "devices": [],
            }

        if not completed.stdout.strip():
            return {
                "success": False,
                "status": "failed",
                "error": nmap_stderr_excerpt(completed.stderr) or "Nmap returned no discovery data.",
                "target": target,
                "devices": []
            }

        try:
            devices = self._parse_xml(
                completed.stdout
            )

        except ET.ParseError as exc:
            return {
                "success": False,
                "error": f"Could not parse Nmap XML: {exc}",
                "target": target,
                "devices": []
            }

        result = {
            "success": True,
            "status": "completed",
            "target": target,
            "devices": devices,
            "device_count": len(devices)
        }
        if nmap_options and nmap_options.get("output_format") in {"xml", "both"}:
            result["nmap_xml"] = completed.stdout
        return result

    # ---------------------------------------------------------
    # XML PARSER
    # ---------------------------------------------------------

    def _parse_xml(
        self,
        xml_data: str
    ) -> List[Dict[str, Any]]:

        root = ET.fromstring(xml_data)

        devices = []

        for host in root.findall("host"):

            status = host.find("status")

            state = "unknown"

            if status is not None:
                state = status.get(
                    "state",
                    "unknown"
                )

            if state != "up":
                continue

            ipv4 = "Unknown"
            ipv6 = "Unknown"
            mac = "Unknown"
            vendor = "Unknown"

            for address in host.findall("address"):

                address_type = address.get(
                    "addrtype"
                )

                address_value = address.get(
                    "addr",
                    "Unknown"
                )

                if address_type == "ipv4":
                    ipv4 = address_value
                elif address_type == "ipv6":
                    ipv6 = address_value

                elif address_type == "mac":

                    mac = address_value

                    vendor = address.get(
                        "vendor",
                        "Unknown"
                    )

            # -------------------------------------------------
            # HOSTNAME
            # -------------------------------------------------

            hostname = "Unknown"

            hostnames = host.find("hostnames")

            if hostnames is not None:

                hostname_element = (
                    hostnames.find("hostname")
                )

                if hostname_element is not None:
                    hostname = hostname_element.get(
                        "name",
                        "Unknown"
                    )

            # -------------------------------------------------
            # DEVICE TYPE
            # -------------------------------------------------

            device_type = "Unknown"

            host_scripts = []

            hostscript = host.find("hostscript")

            if hostscript is not None:

                for script in hostscript.findall("script"):

                    host_scripts.append({
                        "id": script.get(
                            "id",
                            "unknown"
                        ),
                        "output": script.get(
                            "output",
                            ""
                        )
                    })

            # -------------------------------------------------
            # DEVICE OBJECT
            # -------------------------------------------------

            device = {
                "ip": ipv4 if ipv4 != "Unknown" else ipv6,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "state": state,
                "device_type": device_type,
                "ports": [],
                "open_ports": 0,
                "risks": [],
                "host_scripts": host_scripts
            }

            if ipv6 != "Unknown":
                device["ipv6"] = ipv6

            devices.append(device)

        return devices


# =============================================================
# SIMPLE FUNCTION
# =============================================================

def discover_network(
    target: str
) -> Dict[str, Any]:

    scanner = NetworkDiscovery()

    return scanner.discover(
        target
    )


# =============================================================
# COMMAND-LINE TEST
# =============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python discovery.py 192.168.88.0/24"
        )

        sys.exit(1)

    target = sys.argv[1]

    scanner = NetworkDiscovery()

    print("=" * 60)
    print("VulnScan v4.13")
    print("Network Discovery")
    print("=" * 60)

    print(
        f"Target: {target}"
    )

    print(
        f"Nmap available: {scanner.is_available()}"
    )

    result = scanner.discover(
        target
    )

    if not result["success"]:

        print(
            "\nERROR:"
        )

        print(
            result["error"]
        )

        sys.exit(1)

    print(
        f"\nDevices found: {result['device_count']}"
    )

    print("-" * 60)

    for device in result["devices"]:

        print(
            f"IP       : {device['ip']}"
        )

        print(
            f"Hostname : {device['hostname']}"
        )

        print(
            f"MAC      : {device['mac']}"
        )

        print(
            f"Vendor   : {device['vendor']}"
        )

        print(
            f"State    : {device['state']}"
        )

        print("-" * 60)