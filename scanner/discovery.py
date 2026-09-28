import subprocess
import shutil
import xml.etree.ElementTree as ET
import ipaddress
from typing import Dict, List, Any


class NetworkDiscovery:
    """
    WiFi Sentinel V2.0
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

    def validate_target(self, target: str) -> bool:
        try:
            ipaddress.ip_network(
                target,
                strict=False
            )
            return True
        except ValueError:
            return False

    # ---------------------------------------------------------
    # DISCOVER HOSTS
    # ---------------------------------------------------------

    def discover(
        self,
        target: str,
        timeout: int | None = 120
    ) -> Dict[str, Any]:

        if not self.is_available():
            return {
                "success": False,
                "error": "Nmap was not found. Install Nmap and make sure it is in PATH.",
                "target": target,
                "devices": []
            }

        if not self.validate_target(target):
            return {
                "success": False,
                "error": f"Invalid network/IP: {target}",
                "target": target,
                "devices": []
            }

        # Host discovery only.
        #
        # -sn = ping scan / host discovery
        # -PR = ARP discovery where applicable
        # -oX - = XML output to stdout
        command = [
            self.nmap_path,
            "-sn",
            "-PR",
            "-oX",
            "-",
            target
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
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

        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "target": target,
                "devices": []
            }

        if not result.stdout.strip():
            return {
                "success": False,
                "error": result.stderr.strip() or "Nmap returned no discovery data.",
                "target": target,
                "devices": []
            }

        try:
            devices = self._parse_xml(
                result.stdout
            )

        except ET.ParseError as exc:
            return {
                "success": False,
                "error": f"Could not parse Nmap XML: {exc}",
                "target": target,
                "devices": []
            }

        return {
            "success": True,
            "target": target,
            "devices": devices,
            "device_count": len(devices)
        }

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
                "ip": ipv4,
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
    print("WiFi Sentinel V2.0")
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