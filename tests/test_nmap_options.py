import pytest
import xml.etree.ElementTree as ET

from scanner.nmap_options import aggregate_nmap_xml, validate_admin_nmap_options


def test_regular_user_cannot_submit_admin_nmap_options():
    with pytest.raises(PermissionError, match="administrators only"):
        validate_admin_nmap_options(
            {"scan_type": "connect"},
            is_admin=False,
            has_raw_scan_privileges=True,
        )


def test_admin_nmap_options_are_bounded_and_allowlisted():
    options = validate_admin_nmap_options(
        {
            "scan_type": "syn",
            "ports": "22,80,8000-8100",
            "timing": "T3",
            "max_retries": 2,
            "host_timeout": 120,
            "parallelism": 2,
            "nse_modules": ["smb", "tls", "smb"],
        },
        is_admin=True,
        has_raw_scan_privileges=True,
    )

    assert options["scan_type"] == "syn"
    assert options["ports"] == "22,80,8000-8100"
    assert options["nse_modules"] == ["smb", "tls"]
    assert options["reason"] is True


@pytest.mark.parametrize("scan_type", ["syn", "udp", "fin", "null", "xmas", "sctp-init", "sctp-cookie", "ip-protocol"])
def test_raw_scan_types_require_os_privileges(scan_type):
    with pytest.raises(PermissionError, match="OS-level administrator privileges"):
        validate_admin_nmap_options(
            {"scan_type": scan_type},
            is_admin=True,
            has_raw_scan_privileges=False,
        )


@pytest.mark.parametrize("ports", ["80 -sV", "0", "65536", "100-20", "1-5000"])
def test_invalid_advanced_ports_are_rejected(ports):
    with pytest.raises(ValueError):
        validate_admin_nmap_options(
            {"scan_type": "connect", "ports": ports},
            is_admin=True,
            has_raw_scan_privileges=True,
        )


def test_unsupported_nse_module_is_rejected():
    with pytest.raises(ValueError, match="approved protocol checks"):
        validate_admin_nmap_options(
            {"nse_modules": ["vuln"]},
            is_admin=True,
            has_raw_scan_privileges=True,
        )


def test_admin_port_presets_vulnerability_checks_and_xml_export_are_allowlisted():
    options = validate_admin_nmap_options(
        {
            "scan_type": "connect",
            "port_preset": "top-1000",
            "output_format": "both",
            "advanced_authorized": True,
            "nse_modules": ["vulnerability", "web"],
        },
        is_admin=True,
        has_raw_scan_privileges=True,
    )

    assert options["port_preset"] == "top-1000"
    assert options["output_format"] == "both"
    assert options["nse_modules"] == ["vulnerability", "web"]


def test_nmap_xml_aggregation_produces_one_importable_host_document():
    first = '<nmaprun><scaninfo type="connect" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>'
    second = '<nmaprun><scaninfo type="connect" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/></host></nmaprun>'

    root = ET.fromstring(aggregate_nmap_xml([first, second]))

    assert root.tag == "nmaprun"
    assert len(root.findall("host")) == 2
    assert len(root.findall("scaninfo")) == 2


@pytest.mark.parametrize(
    "options",
    [
        {"port_preset": "custom"},
        {"port_preset": "top-100", "ports": "80"},
        {"port_preset": "top-1000", "scan_type": "ip-protocol"},
        {"output_format": "grepable"},
        {"nse_modules": ["unreviewed-script"]},
    ],
)
def test_admin_options_reject_invalid_presets_formats_and_scripts(options):
    with pytest.raises(ValueError):
        validate_admin_nmap_options(
            options,
            is_admin=True,
            has_raw_scan_privileges=True,
        )


def test_no_advanced_options_preserves_existing_default_path():
    assert validate_admin_nmap_options(
        None,
        is_admin=False,
        has_raw_scan_privileges=False,
    ) is None


def test_assessment_profiles_apply_bounded_defaults_and_require_confirmation():
    quick = validate_admin_nmap_options(
        {"assessment_profile": "quick"},
        is_admin=True,
        has_raw_scan_privileges=False,
    )
    assert quick["port_preset"] == "top-100"
    assert quick["include_udp"] is False

    deep = validate_admin_nmap_options(
        {"assessment_profile": "deep"},
        is_admin=True,
        has_raw_scan_privileges=False,
    )
    assert deep["port_preset"] == "top-1000"
    assert deep["os_detection"] is True

    with pytest.raises(PermissionError, match="Confirm the Advanced authorized assessment"):
        validate_admin_nmap_options(
            {"assessment_profile": "full"},
            is_admin=True,
            has_raw_scan_privileges=True,
        )


def test_advanced_profiles_require_explicit_authorization():
    with pytest.raises(PermissionError, match="Confirm the Advanced authorized assessment"):
        validate_admin_nmap_options(
            {"scan_type": "fin"},
            is_admin=True,
            has_raw_scan_privileges=True,
        )

    with pytest.raises(PermissionError, match="Confirm the Advanced authorized assessment"):
        validate_admin_nmap_options(
            {"assessment_profile": "vulnerability"},
            is_admin=True,
            has_raw_scan_privileges=True,
        )

    with pytest.raises(ValueError, match="bounded port selection"):
        validate_admin_nmap_options(
            {
                "assessment_profile": "full",
                "scan_type": "fin",
                "advanced_authorized": True,
            },
            is_admin=True,
            has_raw_scan_privileges=True,
        )

    with pytest.raises(ValueError, match="TCP Connect or TCP SYN"):
        validate_admin_nmap_options(
            {
                "assessment_profile": "full",
                "scan_type": "udp",
                "advanced_authorized": True,
            },
            is_admin=True,
            has_raw_scan_privileges=True,
        )


def test_validated_exclusions_and_udp_options_are_returned():
    options = validate_admin_nmap_options(
        {
            "exclude_ports": "25,135-139",
            "include_udp": True,
        },
        is_admin=True,
        has_raw_scan_privileges=True,
    )

    assert options["exclude_ports"] == "25,135-139"
    assert options["include_udp"] is True
    assert options["max_rate"] == 0
    assert options["scan_delay"] == 0

    with pytest.raises(ValueError, match="Excluded port values"):
        validate_admin_nmap_options(
            {"exclude_ports": "0"},
            is_admin=True,
            has_raw_scan_privileges=True,
        )


def test_probe_rate_and_delay_are_bounded():
    options = validate_admin_nmap_options(
        {"max_rate": 20, "scan_delay": 100},
        is_admin=True,
        has_raw_scan_privileges=True,
    )
    assert options["max_rate"] == 20
    assert options["scan_delay"] == 100

    for invalid in (
        {"max_rate": 100},
        {"max_rate": True},
        {"scan_delay": 500},
        {"scan_delay": -1},
    ):
        with pytest.raises(ValueError):
            validate_admin_nmap_options(
                invalid,
                is_admin=True,
                has_raw_scan_privileges=True,
            )