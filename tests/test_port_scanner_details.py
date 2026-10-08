from types import SimpleNamespace

import pytest
from threading import Event
import scanner.discovery as discovery_module
import scanner.ports as ports_module
from scanner.discovery import NetworkDiscovery
from scanner.ports import PortScanner


NMAP_XML = """<nmaprun><host>
<status state="up" reason="syn-ack" />
<address addr="192.0.2.4" addrtype="ipv4" />
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Vendor" />
<hostnames><hostname name="edge.example" /></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" />
<service name="https" product="Example HTTP" version="2.4" tunnel="ssl" method="probed" conf="10">
<cpe>cpe:/a:example:http</cpe></service></port></ports>
<os><osmatch name="Example OS 1" accuracy="96"><osclass type="general purpose" vendor="Example" osfamily="Linux" osgen="6.X" accuracy="96"><cpe>cpe:/o:example:linux:6</cpe></osclass></osmatch></os>
<uptime seconds="3600" lastboot="2026-09-27 08:00:00" /><distance value="1" />
</host></nmaprun>"""


def _run_scan(monkeypatch, privileged):
    scanner = PortScanner()
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: privileged))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(ports_module, "run_nmap", fake_run)
    return scanner.scan_host("192.0.2.4"), captured["command"]


def test_parser_preserves_host_identity_os_and_service_evidence():
    host = PortScanner._parse_nmap_xml(NMAP_XML)[0]
    port = host["ports"][0]

    assert host["hostname"] == "edge.example"
    assert host["mac"] == "00:11:22:33:44:55"
    assert host["vendor"] == "Example Vendor"
    assert host["os"] == "Example OS 1"
    assert host["os_accuracy"] == 96
    assert host["uptime_seconds"] == "3600"
    assert host["distance"] == "1"
    assert port["service_confidence"] == "10"
    assert port["tunnel"] == "ssl"
    assert port["cpes"] == ["cpe:/a:example:http"]


def test_os_fingerprinting_is_only_requested_with_privileges(monkeypatch):
    privileged_result, privileged_command = _run_scan(monkeypatch, True)
    assert privileged_result["success"] is True
    assert privileged_result["os_detection_status"] == "detected"
    assert "-O" in privileged_command

    unprivileged_result, unprivileged_command = _run_scan(monkeypatch, False)
    assert unprivileged_result["success"] is True
    assert unprivileged_result["os_detection_status"] == "skipped_unprivileged"
    assert "-O" not in unprivileged_command


def test_admin_scan_options_build_only_selected_allowlisted_nmap_flags(monkeypatch):
    scanner = PortScanner(timeout=90)
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: True))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="packet trace sample")

    monkeypatch.setattr(ports_module, "run_nmap", fake_run)
    result = scanner.scan_host(
        "192.0.2.4",
        nmap_options={
            "scan_type": "fin",
            "ports": "80,443",
            "timing": "T4",
            "max_retries": 2,
            "host_timeout": 45,
            "service_detection": True,
            "os_detection": True,
            "traceroute": True,
            "packet_trace": True,
            "reason": True,
            "ipv6": False,
            "nse_modules": ["tls"],
            "output_format": "both",
        },
    )

    command = captured["command"]
    assert "-sF" in command
    assert command[command.index("-p") + 1] == "80,443"
    assert "-T4" in command
    assert command[command.index("--max-retries") + 1] == "2"
    assert command[command.index("--host-timeout") + 1] == "45s"
    assert "--reason" in command
    assert "--traceroute" in command
    assert "--packet-trace" in command
    assert command[command.index("--script") + 1] == "ssl-cert,ssl-enum-ciphers"
    assert result["packet_trace"] == "packet trace sample"
    assert result["nmap_xml"] == NMAP_XML


def test_admin_combined_udp_scan_excludes_ports_and_skips_discovery(monkeypatch):
    scanner = PortScanner()
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: True))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(ports_module, "run_nmap", fake_run)
    scanner.scan_host(
        "192.0.2.4",
        nmap_options={
            "scan_type": "syn",
            "port_preset": "custom",
            "ports": "80,443",
            "include_udp": True,
            "exclude_ports": "25,135-139",
            "discovery_method": "none",
            "ipv6": False,
            "service_detection": True,
            "os_detection": False,
            "timing": "T3",
            "max_rate": 20,
            "scan_delay": 100,
            "max_retries": 2,
            "host_timeout": 90,
            "reason": True,
            "traceroute": False,
            "packet_trace": False,
            "nse_modules": [],
            "output_format": "json",
        },
    )

    command = captured["command"]
    assert "-sU" in command
    assert "-Pn" in command
    assert command[command.index("-p") + 1] == "T:80,443,U:80,443"
    assert command[command.index("--exclude-ports") + 1] == "25,135-139"
    assert command[command.index("--max-rate") + 1] == "20"
    assert command[command.index("--scan-delay") + 1] == "100ms"


def test_admin_udp_scan_uses_udp_port_defaults(monkeypatch):
    scanner = PortScanner()
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: True))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(ports_module, "run_nmap", fake_run)
    scanner.scan_host(
        "192.0.2.4",
        nmap_options={
            "scan_type": "udp",
            "port_preset": "profile",
            "ports": "",
            "include_udp": False,
            "ipv6": False,
            "service_detection": True,
            "os_detection": False,
            "timing": "T3",
            "max_retries": 2,
            "host_timeout": 90,
            "reason": True,
            "traceroute": False,
            "packet_trace": False,
            "nse_modules": [],
            "output_format": "json",
        },
    )

    command = captured["command"]
    assert command[command.index("-p") + 1] == "U:53,67,68,123,137,138,161,500,514,1900,4500"


def test_admin_skip_discovery_accepts_only_one_explicit_host(monkeypatch):
    scanner = NetworkDiscovery()
    monkeypatch.setattr(scanner, "is_available", lambda: False)
    options = {
        "ipv6": False,
        "discovery_method": "none",
        "timing": "T3",
        "max_retries": 3,
        "host_timeout": 90,
        "reason": True,
        "traceroute": False,
        "packet_trace": False,
        "output_format": "json",
    }

    single_host = scanner.discover("192.0.2.4", nmap_options=options)
    subnet = scanner.discover("192.0.2.0/30", nmap_options=options)

    assert single_host["success"] is True
    assert [device["ip"] for device in single_host["devices"]] == ["192.0.2.4"]
    assert subnet["success"] is False
    assert "one explicitly selected host" in subnet["error"].lower()

    ipv6_options = {**options, "ipv6": True}
    ipv6_host = scanner.discover("2001:db8::4", nmap_options=ipv6_options)
    assert ipv6_host["devices"][0]["ip"] == "2001:db8::4"


def test_admin_discovery_adds_bounded_rate_and_delay_flags(monkeypatch):
    scanner = NetworkDiscovery()
    scanner.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        kwargs["progress_callback"]({
            "phase": "Ping Scan",
            "percent": 25.0,
            "eta": "20:00",
            "remaining": "0:00:03",
        })
        return SimpleNamespace(
            status="completed",
            returncode=0,
            stdout="<nmaprun><host><status state='up'/><address addr='192.0.2.4' addrtype='ipv4'/></host></nmaprun>",
            stderr="",
        )

    monkeypatch.setattr(discovery_module, "run_nmap", fake_run)
    progress_events = []
    result = scanner.discover(
        "192.0.2.4",
        progress_callback=progress_events.append,
        nmap_options={
            "ipv6": False,
            "discovery_method": "icmp",
            "timing": "T3",
            "max_rate": 10,
            "scan_delay": 50,
            "max_retries": 2,
            "host_timeout": 90,
            "reason": True,
            "traceroute": False,
            "packet_trace": False,
            "output_format": "json",
        },
    )

    assert result["success"] is True
    assert captured["command"][captured["command"].index("--max-rate") + 1] == "10"
    assert captured["command"][captured["command"].index("--scan-delay") + 1] == "50ms"
    assert progress_events[0]["percent"] == 25.0


def test_port_scan_propagates_cancellation_and_nmap_progress(monkeypatch):
    scanner = PortScanner(timeout=30)
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: False))
    cancel_event = Event()
    progress_events = []
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        kwargs["progress_callback"]({
            "phase": "SYN Stealth Scan",
            "percent": 15.0,
            "eta": "",
            "remaining": "",
        })
        return SimpleNamespace(
            status="cancelled",
            returncode=-1,
            stdout="",
            stderr="",
            error="Nmap process cancelled by the operator.",
        )

    monkeypatch.setattr(ports_module, "run_nmap", fake_run)
    event_result = scanner.scan_host(
        "192.0.2.4",
        cancel_event=cancel_event,
        progress_callback=progress_events.append,
    )

    assert captured["cancel_event"] is cancel_event
    assert event_result["scan_status"] == "cancelled"
    assert progress_events[0]["phase"] == "SYN Stealth Scan"


@pytest.mark.parametrize(
    ("port_preset", "expected_flags"),
    [
        ("top-100", ["--top-ports", "100"]),
        ("top-1000", ["--top-ports", "1000"]),
        ("all", ["-p", "-"]),
    ],
)
def test_admin_port_presets_build_expected_nmap_flags(monkeypatch, port_preset, expected_flags):
    scanner = PortScanner()
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: True))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(ports_module, "run_nmap", fake_run)
    scanner.scan_host(
        "192.0.2.4",
        nmap_options={
            "scan_type": "connect",
            "ports": "",
            "port_preset": port_preset,
            "service_detection": True,
            "os_detection": False,
            "timing": "T3",
            "max_retries": 3,
            "host_timeout": 90,
            "reason": True,
            "traceroute": False,
            "packet_trace": False,
            "ipv6": False,
            "nse_modules": [],
            "output_format": "json",
        },
    )

    for flag in expected_flags:
        assert flag in captured["command"]


def test_empty_open_port_result_is_still_a_successful_scan(monkeypatch):
    scanner = PortScanner()
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: False))
    monkeypatch.setattr(
        ports_module,
        "run_nmap",
        lambda command, **kwargs: SimpleNamespace(
            status="completed",
            returncode=0,
            stdout="<nmaprun><host><status state='up'/><address addr='192.0.2.4' addrtype='ipv4'/></host></nmaprun>",
            stderr="",
        ),
    )

    result = scanner.scan_host("192.0.2.4")

    assert result["success"] is True
    assert result["open_ports"] == 0


def test_parser_does_not_drop_closed_or_filtered_ports(monkeypatch):
    xml = """<nmaprun><host>
    <status state='up' />
    <address addr='192.0.2.5' addrtype='ipv4' />
    <ports>
        <port protocol='tcp' portid='80'><state state='open' reason='syn-ack' /><service name='http' /></port>
        <port protocol='udp' portid='53'><state state='open' reason='udp-response' /><service name='domain' /></port>
        <port protocol='tcp' portid='8080'><state state='filtered' reason='no-response' /><service name='http' /></port>
        <port protocol='tcp' portid='22'><state state='closed' reason='conn-refused' /><service name='ssh' /></port>
    </ports>
    </host></nmaprun>"""

    host = PortScanner._parse_nmap_xml(xml)[0]

    assert host["ip"] == "192.0.2.5"
    assert host["open_ports"] == 2
    assert {port["port"] for port in host["ports"]} == {80, 53, 8080, 22}
    assert {port["state"] for port in host["ports"]} == {"open", "filtered", "closed"}
