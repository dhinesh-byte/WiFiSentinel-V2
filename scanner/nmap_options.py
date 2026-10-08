"""Compatibility re-export for the shared Nmap option helpers."""

from nmap_options import (
    DISCOVERY_METHODS,
    NSE_MODULES,
    RAW_SCAN_TYPES,
    SAFE_NSE_MODULES,
    SCAN_FLAGS,
    aggregate_nmap_xml,
    has_raw_scan_privileges,
    validate_admin_nmap_options,
)

__all__ = [
    "DISCOVERY_METHODS",
    "NSE_MODULES",
    "RAW_SCAN_TYPES",
    "SAFE_NSE_MODULES",
    "SCAN_FLAGS",
    "aggregate_nmap_xml",
    "has_raw_scan_privileges",
    "validate_admin_nmap_options",
]