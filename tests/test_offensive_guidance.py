from types import SimpleNamespace
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "offensive"))

import offensive.enumeration as enumeration_module
import offensive.vulnerability as vulnerability_module
from offensive.enumeration import OffensiveEnumerator
from offensive.report import SecurityReport
from offensive.vulnerability import VulnerabilityAssessment


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
        return SimpleNamespace(returncode=0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(enumeration_module.subprocess, "run", fake_run)
    result = enumerator.enumerate_host("192.0.2.20")

    assert result["status"] == "completed"
    assert result["ports"][0]["product"] == "OpenSSH"
    assert result["ports"][0]["version"] == "9.6"
    assert "-sV" in captured["command"]


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


def test_report_serialization_retains_guidance_and_cve_fields():
    assessment = VulnerabilityAssessment().assess(enumeration_with_service())
    report = SecurityReport(
        discovery_results={"status": "completed", "hosts": [{"ip": "192.0.2.20"}]},
        enumeration_results=enumeration_with_service(),
        vulnerability_assessment=assessment,
        scan_information={"target": "192.0.2.20", "scan_type": "offensive", "report_id": "guidance-test"},
    ).to_dict()
    finding = next(item for item in report["Security Findings"] if item["finding_type"] == "service-observed")

    assert finding["vulnerability_status"] == "Needs verification"
    assert finding["exploitation_guidance"]["automatic_exploitation"] is False
    text_report = SecurityReport(
        discovery_results={"status": "completed", "hosts": [{"ip": "192.0.2.20"}]},
        enumeration_results=enumeration_with_service(),
        vulnerability_assessment=assessment,
        scan_information={"target": "192.0.2.20", "scan_type": "offensive", "report_id": "guidance-test"},
    ).generate_text()
    assert "Exploitation Guidance:" in text_report
    assert "Automatic exploitation: Disabled" in text_report
