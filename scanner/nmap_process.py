"""Compatibility re-export for the shared Nmap process runner."""

from nmap_process import (
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    NmapProcessResult,
    add_nmap_progress_args,
    nmap_stderr_excerpt,
    parse_nmap_progress_line,
    run_nmap,
)

__all__ = [
    "MAX_STDERR_BYTES",
    "MAX_STDOUT_BYTES",
    "NmapProcessResult",
    "add_nmap_progress_args",
    "nmap_stderr_excerpt",
    "parse_nmap_progress_line",
    "run_nmap",
]
