from types import SimpleNamespace

import scanner.ports as ports_module
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
        return SimpleNamespace(returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(ports_module.subprocess, "run", fake_run)
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


def test_empty_open_port_result_is_still_a_successful_scan(monkeypatch):
    scanner = PortScanner()
    scanner.nmap_path = "nmap"
    monkeypatch.setattr(PortScanner, "_has_os_detection_privileges", staticmethod(lambda: False))
    monkeypatch.setattr(
        ports_module.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="<nmaprun><host><status state='up'/><address addr='192.0.2.4' addrtype='ipv4'/></host></nmaprun>",
            stderr="",
        ),
    )

    result = scanner.scan_host("192.0.2.4")

    assert result["success"] is True
    assert result["open_ports"] == 0
