from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import sys
import ssl
from threading import Thread
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "offensive"))

import offensive.discovery as discovery_module
import offensive.enumeration as enumeration_module
import offensive.vulnerability as vulnerability_module
from offensive.enumeration import OffensiveEnumerator
from offensive.report import SecurityReport
from offensive.vulnerability import VulnerabilityAssessment
from offensive.web import WebTLSAssessment


NMAP_XML = """<nmaprun><host><status state="up" />
<address addr="192.0.2.20" addrtype="ipv4" />
<hostnames><hostname name="ssh.example" /></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" />
<service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10">
<cpe>cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*</cpe></service></port></ports>
</host></nmaprun>"""


def enumeration_with_service(product="OpenSSH", version="9.6", cpes=None):
    port = {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "product": product,
        "version": version,
        "extrainfo": "",
        "cpes": cpes or [],
    }
    return {
        "status": "completed",
        "hosts": [{"status": "completed", "ip": "192.0.2.20", "hostname": "ssh.example", "ports": [port], "errors": []}],
        "errors": [],
    }


def test_offensive_enumeration_still_collects_service_identity(monkeypatch):
    enumerator = OffensiveEnumerator(timeout=20)
    enumerator.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(enumeration_module, "run_nmap", fake_run)
    result = enumerator.enumerate_host("192.0.2.20")

    assert result["status"] == "completed"
    assert result["ports"][0]["product"] == "OpenSSH"
    assert result["ports"][0]["version"] == "9.6"
    assert result["ports"][0]["method"] == "probed"
    assert result["ports"][0]["confidence"] == "10"
    assert result["ports"][0]["evidence"]
    assert "-sV" in captured["command"]


def test_scan_profile_and_tcp_method_change_nmap_command(monkeypatch):
    enumerator = OffensiveEnumerator(
        timeout=30,
        port_range="80,443,8000-8002",
        scan_method="syn",
    )
    enumerator.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(enumeration_module, "run_nmap", fake_run)
    result = enumerator.enumerate_host("192.0.2.20")

    assert result["status"] == "completed"
    assert "-sS" in captured["command"]
    assert captured["command"][captured["command"].index("-p") + 1] == "80,443,8000-8002"


def test_admin_scan_options_apply_exclusions_and_skip_discovery(monkeypatch):
    enumerator = OffensiveEnumerator(timeout=30)
    enumerator.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(enumeration_module, "run_nmap", fake_run)
    result = enumerator.enumerate_host(
        "192.0.2.20",
        admin_nmap_options={
            "scan_type": "ack",
            "port_preset": "custom",
            "ports": "80,443",
            "exclude_ports": "25,135-139",
            "discovery_method": "none",
            "ipv6": False,
            "service_detection": True,
            "os_detection": False,
            "timing": "T3",
            "max_rate": 10,
            "scan_delay": 50,
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
    assert result["status"] == "completed"
    assert "-sA" in command
    assert "-Pn" in command
    assert command[command.index("-p") + 1] == "80,443"
    assert command[command.index("--exclude-ports") + 1] == "25,135-139"
    assert command[command.index("--max-rate") + 1] == "10"
    assert command[command.index("--scan-delay") + 1] == "50ms"
    assert command[command.index("-oX") + 1] == "-"
    assert command[-1] == "192.0.2.20"


def test_admin_udp_profile_uses_bounded_udp_defaults(monkeypatch):
    enumerator = OffensiveEnumerator(timeout=30)
    enumerator.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(enumeration_module, "run_nmap", fake_run)
    enumerator.enumerate_host(
        "192.0.2.20",
        admin_nmap_options={
            "scan_type": "udp",
            "port_preset": "profile",
            "ports": "",
            "exclude_ports": "",
            "discovery_method": "default",
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

    assert captured["command"][captured["command"].index("-p") + 1] == (
        "U:53,67,68,123,137,138,161,500,514,1900,4500"
    )


def test_admin_skip_discovery_accepts_only_one_explicit_host(monkeypatch):
    discovery = discovery_module.OffensiveDiscovery()
    monkeypatch.setattr(discovery, "available", lambda: False)
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

    single_host = discovery.discover("192.0.2.20", nmap_options=options)
    subnet = discovery.discover("192.0.2.0/30", nmap_options=options)

    assert single_host["status"] == "completed"
    assert single_host["hosts"][0]["ip"] == "192.0.2.20"
    assert subnet["status"] == "failed"
    assert "one explicitly selected host" in subnet["errors"][0]


def test_only_allowlisted_safe_nse_modules_reach_nmap(monkeypatch):
    enumerator = OffensiveEnumerator(timeout=30)
    enumerator.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(enumeration_module, "run_nmap", fake_run)
    result = enumerator.enumerate_host("192.0.2.20", nse_modules=("smb", "tls"))

    assert result["status"] == "completed"
    assert captured["command"][captured["command"].index("--script") + 1] == (
        "smb-protocols,smb-security-mode,smb-os-discovery,ssl-cert,ssl-enum-ciphers"
    )
    assert "mysql-info" not in captured["command"]


def test_hostscript_vulnerability_output_is_preserved_and_assessed():
    xml = """<nmaprun><host><status state="up" />
<address addr="192.0.2.20" addrtype="ipv4" />
<hostscript><script id="smb-vuln-ms17-010" output="VULNERABLE&#10;State: VULNERABLE&#10;IDs: CVE:CVE-2017-0143" /></hostscript>
<ports><port protocol="tcp" portid="445"><state state="open" />
<service name="microsoft-ds" product="Windows SMB" /></port></ports>
</host></nmaprun>"""

    parsed = OffensiveEnumerator.parse_xml(xml)
    assessment = VulnerabilityAssessment().assess({
        "status": "completed",
        "hosts": [{**parsed, "status": "completed"}],
        "errors": [],
    })

    assert parsed["scripts"] == [{
        "id": "smb-vuln-ms17-010",
        "output": "VULNERABLE\nState: VULNERABLE\nIDs: CVE:CVE-2017-0143",
    }]
    finding = next(item for item in assessment["findings"] if item["finding_type"] == "nmap-script-vulnerability")
    assert finding["target"] == "192.0.2.20"
    assert finding["port"] == 445
    assert finding["cve_id"] == "CVE-2017-0143"
    assert finding["vulnerability_status"] == "Confirmed vulnerability"


def test_hostscript_negative_vulnerability_state_does_not_create_finding():
    assessment = VulnerabilityAssessment().assess({
        "status": "completed",
        "hosts": [{
            "status": "completed",
            "ip": "192.0.2.20",
            "scripts": [{"id": "smb-vuln-ms17-010", "output": "State: NOT VULNERABLE"}],
            "ports": [{"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds"}],
            "errors": [],
        }],
        "errors": [],
    })

    assert not any(item["finding_type"] == "nmap-script-vulnerability" for item in assessment["findings"])


def test_admin_udp_scan_applies_options_and_retains_xml_and_packet_trace(monkeypatch):
    enumerator = OffensiveEnumerator(timeout=120)
    enumerator.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="udp packet trace")

    monkeypatch.setattr(enumeration_module, "run_nmap", fake_run)
    options = {
        "ipv6": False,
        "discovery_method": "default",
        "service_detection": True,
        "port_preset": "custom",
        "ports": "53,123",
        "timing": "T4",
        "max_retries": 2,
        "host_timeout": 120,
        "reason": True,
        "traceroute": False,
        "packet_trace": True,
        "nse_modules": ["dns"],
        "output_format": "both",
    }

    result = enumerator.enumerate_udp_host("192.0.2.20", options)
    command = captured["command"]

    assert result["status"] == "completed"
    assert command[:2] == ["nmap", "-sU"]
    assert command[command.index("-p") + 1] == "U:53,123"
    assert command[command.index("--max-retries") + 1] == "2"
    assert command[command.index("--host-timeout") + 1] == "120s"
    assert command[command.index("--script") + 1] == "dns-nsid"
    assert "--packet-trace" in command
    assert result["packet_trace"] == "udp packet trace"
    assert result["nmap_xml"] == NMAP_XML


def test_admin_discovery_applies_method_and_retry_controls(monkeypatch):
    discovery = discovery_module.OffensiveDiscovery(timeout=90)
    discovery.nmap_path = "nmap"
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        kwargs["progress_callback"]({
            "phase": "Host Discovery",
            "percent": 40.0,
            "eta": "20:00",
            "remaining": "0:00:02",
        })
        return SimpleNamespace(status="completed", returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(discovery_module, "run_nmap", fake_run)
    options = {
        "ipv6": False,
        "discovery_method": "tcp-syn",
        "timing": "T4",
        "max_rate": 20,
        "scan_delay": 25,
        "max_retries": 1,
        "host_timeout": 60,
        "reason": True,
        "traceroute": False,
        "packet_trace": False,
        "output_format": "xml",
    }

    progress_events = []
    result = discovery.discover(
        "192.0.2.0/24",
        options,
        progress_callback=progress_events.append,
    )
    command = captured["command"]

    assert result["status"] == "completed"
    assert "-PS80,443" in command
    assert command[command.index("--max-rate") + 1] == "20"
    assert command[command.index("--scan-delay") + 1] == "25ms"
    assert "--max-retries" in command
    assert command[command.index("--max-retries") + 1] == "1"
    assert command[command.index("--host-timeout") + 1] == "60s"
    assert result["nmap_xml"] == NMAP_XML
    assert progress_events[0]["percent"] == 40.0


def test_supplementary_udp_results_preserve_both_xml_documents():
    from offensive.service import OffensiveAssessmentService

    class FakeEnumerator:
        def enumerate_host(self, *args, **kwargs):
            return {
                "status": "completed",
                "ip": "192.0.2.20",
                "ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
                "uncertain_ports": [],
                "packet_trace": "tcp trace",
                "nmap_xml": "<nmaprun><host /></nmaprun>",
                "errors": [],
            }

        def enumerate_udp_host(self, *args, **kwargs):
            return {
                "status": "completed",
                "ports": [{"port": 53, "protocol": "udp", "state": "open"}],
                "uncertain_ports": [],
                "packet_trace": "udp trace",
                "nmap_xml": "<nmaprun><host /></nmaprun>",
                "errors": [],
            }

    result = OffensiveAssessmentService._enumerate_host(
        FakeEnumerator(),
        "192.0.2.20",
        include_udp=True,
        admin_nmap_options={"scan_type": "syn", "output_format": "both"},
    )

    assert [port["protocol"] for port in result["ports"]] == ["tcp", "udp"]
    assert result["nmap_xml_documents"] == [
        "<nmaprun><host /></nmaprun>",
        "<nmaprun><host /></nmaprun>",
    ]
    assert result["packet_trace"] == "tcp trace\nudp trace"


def test_admin_parallelism_and_host_timeout_bound_offensive_enumeration(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor as RealThreadPoolExecutor
    import offensive.service as service_module

    captured = {}

    class CapturingExecutor(RealThreadPoolExecutor):
        def __init__(self, *args, **kwargs):
            captured["workers"] = kwargs["max_workers"]
            super().__init__(*args, **kwargs)

    class FakeEnumerator:
        def __init__(self, **kwargs):
            captured["timeout"] = kwargs["timeout"]

        @staticmethod
        def validate_ip(value, allow_ipv6=False):
            return value

        @staticmethod
        def enumerate_host(ip_address, **kwargs):
            return {
                "status": "completed",
                "ip": ip_address,
                "ports": [],
                "errors": [],
            }

    monkeypatch.setattr(service_module, "ThreadPoolExecutor", CapturingExecutor)
    monkeypatch.setattr(service_module, "OffensiveEnumerator", FakeEnumerator)
    service = service_module.OffensiveAssessmentService(max_workers=1)

    result = service._enumerate_discovered_hosts(
        [{"ip": "192.0.2.20"}, {"ip": "192.0.2.21"}],
        scan_config={"timeout": 30, "ports": "22", "scan_method": "connect"},
        admin_nmap_options={
            "host_timeout": 120,
            "parallelism": 2,
            "ipv6": False,
            "scan_type": "connect",
        },
    )

    assert result["status"] == "completed"
    assert captured == {"timeout": 120, "workers": 2}


def test_vulnerability_nse_modules_are_not_available_through_regular_user_controls():
    from offensive.service import OffensiveAssessmentService

    try:
        OffensiveAssessmentService.resolve_nse_modules(["vulnerability"])
    except ValueError:
        pass
    else:
        raise AssertionError("Vulnerability NSE selection bypassed the admin option gate.")


def test_custom_scan_profile_is_validated_and_bounded():
    from offensive.service import OffensiveAssessmentService

    config = OffensiveAssessmentService.resolve_scan_config(
        "custom", "22,80,8000-8002", "connect"
    )

    assert config == {
        "profile": "custom",
        "ports": "22,80,8000-8002",
        "timeout": 90,
        "scan_method": "connect",
    }
    for invalid_ports in ("80; -sV", "0", "8002-8000", "1-5000"):
        try:
            OffensiveAssessmentService.resolve_scan_config("custom", invalid_ports)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Invalid custom range accepted: {invalid_ports}")


def test_standard_profile_includes_common_application_ports():
    from offensive.service import OffensiveAssessmentService

    config = OffensiveAssessmentService.resolve_scan_config("standard")
    ports = set(config["ports"].split(","))

    assert {"53", "443", "445", "1433", "1521", "3306", "5432", "8080", "9200"} <= ports


def test_known_service_finding_includes_safe_guidance_and_no_vulnerability_claim():
    assessment = VulnerabilityAssessment().assess(enumeration_with_service())
    finding = next(item for item in assessment["findings"] if item["finding_type"] == "service-observed")

    assert finding["product"] == "OpenSSH"
    assert finding["version"] == "9.6"
    assert finding["vulnerability_status"] == "Needs verification"
    assert finding["exploitation_guidance"]["target"] == "192.0.2.20"
    assert finding["exploitation_guidance"]["automatic_exploitation"] is False
    assert finding["exploitation_guidance"]["safe_verification_procedure"]
    assert {
        "finding",
        "target",
        "port",
        "protocol",
        "service",
        "product",
        "version",
        "evidence",
        "vulnerability_status",
        "why_it_may_be_vulnerable",
        "exploitation_prerequisites",
        "attacker_investigation_methodology",
        "safe_verification_procedure",
        "expected_evidence_if_confirmed",
        "potential_impact",
        "detection_opportunities",
        "defensive_remediation",
        "verification_after_remediation",
        "confidence_level",
    } <= finding["exploitation_guidance"].keys()


def test_unknown_version_is_insufficient_evidence():
    assessment = VulnerabilityAssessment().assess(
        enumeration_with_service(product="Unknown", version="Unknown")
    )
    finding = next(item for item in assessment["findings"] if item["finding_type"] == "service-identification")

    assert finding["vulnerability_status"] == "Insufficient evidence"
    assert finding["exploitation_guidance"]["why_it_may_be_vulnerable"].startswith(
        "Insufficient evidence to determine vulnerability."
    )


def test_exact_cve_match_is_potential_and_includes_affected_version():
    cpe = "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"
    assessment = VulnerabilityAssessment().assess(
        enumeration_with_service(cpes=[cpe]),
        cve_correlation={
            "status": "completed",
            "errors": [],
            "limitations": [],
            "matches": [{
                "id": "CVE-2024-12345",
                "target": "192.0.2.20",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.6",
                "cpe23_uri": cpe,
                "severity": "High",
                "title": "Example advisory",
                "summary": "A test catalog description.",
                "remediation": "Apply the vendor-supported fixed version.",
                "references": ["Vendor advisory"],
                "confidence": "Likely",
                "evidence": ["Exact CPE matched a local record."],
            }],
        },
    )
    finding = next(item for item in assessment["findings"] if item.get("cve_id") == "CVE-2024-12345")
    guidance = finding["exploitation_guidance"]

    assert finding["vulnerability_status"] == "Potential vulnerability"
    assert guidance["cve"]["identifier"] == "CVE-2024-12345"
    assert guidance["cve"]["affected_product"] == "OpenSSH"
    assert guidance["cve"]["affected_version"] == "9.6"
    assert guidance["cve"]["severity"] == "High"
    assert guidance["cve"]["safe_verification_methodology"]
    assert guidance["automatic_exploitation"] is False


def test_web_header_guidance_and_assessment_do_not_execute_commands(monkeypatch):
    calls = []

    def forbidden_run(*args, **kwargs):
        calls.append(args)
        raise AssertionError("Assessment guidance must not execute subprocesses.")

    monkeypatch.setattr(subprocess, "run", forbidden_run)
    assessment = VulnerabilityAssessment().assess(
        enumeration_with_service(product="Example Web", version="1.0"),
        web_assessment={
            "status": "completed",
            "errors": [],
            "limitations": [],
            "services": [{
                "target": "192.0.2.20",
                "port": 8080,
                "protocol": "tcp",
                "service": "http",
                "evidence": ["HEAD / returned HTTP 200."],
                "missing_security_headers": ["content-security-policy"],
            }],
        },
    )
    finding = next(item for item in assessment["findings"] if item["finding_type"] == "web-headers")

    assert finding["vulnerability_status"] == "Needs verification"
    assert "HEAD" in finding["exploitation_guidance"]["safe_verification_procedure"][1]
    assert calls == []
    assert all(item["exploitation_guidance"]["automatic_exploitation"] is False for item in assessment["findings"])


def test_web_assessment_reports_methods_and_only_fixed_resources():
    requests = []

    class LocalHandler(BaseHTTPRequestHandler):
        def _respond(self, status, body=b""):
            self.send_response(status)
            self.send_header("Allow", "GET, HEAD, OPTIONS")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            requests.append((self.command, self.path))
            self._respond(200)

        def do_OPTIONS(self):
            requests.append((self.command, self.path))
            self._respond(204)

        def do_GET(self):
            requests.append((self.command, self.path))
            self._respond(200 if self.path == "/robots.txt" else 404, b"Disallow: /private\n")

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), LocalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = WebTLSAssessment(timeout=2).assess({
            "status": "completed",
            "hosts": [{
                "status": "completed",
                "ip": "127.0.0.1",
                "ports": [{"port": server.server_port, "protocol": "tcp", "state": "open", "service": "http"}],
            }],
        })
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    observation = result["services"][0]
    assert observation["methods"] == ["GET", "HEAD", "OPTIONS"]
    assert [(item["path"], item["status"], item["found"]) for item in observation["resources"]] == [
        ("/robots.txt", 200, True),
        ("/.well-known/security.txt", 404, False),
    ]
    assert requests == [
        ("HEAD", "/"),
        ("OPTIONS", "/"),
        ("GET", "/robots.txt"),
        ("GET", "/.well-known/security.txt"),
    ]
    assert "Disallow: /private" not in str(result)


def test_tls_verification_failures_remain_visible_and_actionable(monkeypatch):
    def reject_certificate(*args, **kwargs):
        raise ssl.SSLCertVerificationError("certificate key too weak")

    monkeypatch.setattr(WebTLSAssessment, "_https_head", reject_certificate)
    observation = WebTLSAssessment()._inspect_service(
        "192.0.2.20",
        {"port": 443, "protocol": "tcp", "service": "https"},
    )

    assert observation["status"] == "failed"
    assert observation["tls"]["certificate_verified"] is False
    assert "key strength" in observation["tls"]["remediation"]
    assert "verification remains enabled" in observation["tls"]["remediation"]


def test_report_serialization_retains_guidance_and_cve_fields():
    enumeration = enumeration_with_service(cpes=["cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"])
    enumeration["hosts"][0]["ports"][0]["extrainfo"] = "Ubuntu build"
    enumeration["hosts"][0]["ports"][0]["evidence"] = ["Nmap identified tcp/22 as ssh (OpenSSH 9.6)."]
    assessment = VulnerabilityAssessment().assess(enumeration)
    report = SecurityReport(
        discovery_results={"status": "completed", "hosts": [{"ip": "192.0.2.20"}]},
        enumeration_results=enumeration,
        vulnerability_assessment=assessment,
        scan_information={
            "target": "192.0.2.20",
            "scan_type": "offensive",
            "report_id": "guidance-test",
            "settings": {"profile": "standard", "ports": "1-1024"},
        },
    ).to_dict()
    finding = next(item for item in report["Security Findings"] if item["finding_type"] == "service-observed")

    assert finding["vulnerability_status"] == "Needs verification"
    assert finding["exploitation_guidance"]["automatic_exploitation"] is False
    assert report["Services Discovered"][0]["cpes"] == ["cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"]
    assert report["Services Discovered"][0]["extrainfo"] == "Ubuntu build"
    assert report["Services Discovered"][0]["evidence"]
    assert report["Scan Information"]["settings"] == {"profile": "standard", "ports": "1-1024"}
    text_report = SecurityReport(
        discovery_results={"status": "completed", "hosts": [{"ip": "192.0.2.20"}]},
        enumeration_results=enumeration_with_service(),
        vulnerability_assessment=assessment,
        scan_information={"target": "192.0.2.20", "scan_type": "offensive", "report_id": "guidance-test"},
    ).generate_text()
    assert "Exploitation Guidance:" in text_report
    assert "Automatic exploitation: Disabled" in text_report


def test_report_counts_tls_certificate_observations_from_service_enumeration():
    enumeration = enumeration_with_service()
    port = enumeration["hosts"][0]["ports"][0]
    port["service"] = "mysql"
    port["scripts"] = [{"id": "ssl-cert", "output": "Subject: commonName=localhost"}]

    report = SecurityReport(
        discovery_results={"status": "completed", "hosts": [{"ip": "192.0.2.20"}]},
        enumeration_results=enumeration,
        vulnerability_assessment={"status": "completed", "findings": []},
    ).to_dict()

    assert report["Final Statistics"]["TLS services"] == 1
