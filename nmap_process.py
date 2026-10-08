"""Shared bounded subprocess execution and progress parsing for Nmap scans."""

from __future__ import annotations

import re
import logging
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from threading import Event
from typing import Any


logger = logging.getLogger(__name__)
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
_PROGRESS_LINE = re.compile(
    r"^(?P<phase>.+?) Timing: About (?P<percent>\d+(?:\.\d+)?)% done;"
    r"(?: ETC: (?P<eta>.+?))?(?: \((?P<remaining>.+?) remaining\))?$"
)


@dataclass(frozen=True)
class NmapProcessResult:
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None


@lru_cache(maxsize=16)
def _supports_nmap_progress(executable: str) -> bool:
    try:
        result = subprocess.run(
            [executable, "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "--stats-every" in result.stdout or "--stats-every" in result.stderr


def add_nmap_progress_args(
    command: Sequence[str],
    *,
    stats_supported: bool | None = None,
) -> list[str]:
    """Request periodic Nmap statistics without accepting caller-provided flags."""
    result = list(command)
    if not result:
        raise ValueError("Nmap command cannot be empty.")
    if stats_supported is None:
        stats_supported = _supports_nmap_progress(result[0])
    if not stats_supported:
        return result
    try:
        output_index = result.index("-oX")
    except ValueError:
        raise ValueError("Nmap commands must specify XML output before progress can be enabled.")
    result[output_index:output_index] = ["--stats-every", "1s"]
    return result


def parse_nmap_progress_line(line: str) -> dict[str, Any] | None:
    """Parse an Nmap scan-phase timing line, if present."""
    match = _PROGRESS_LINE.match(line.strip())
    if match is None:
        return None
    try:
        percent = float(match.group("percent"))
    except ValueError:
        return None
    return {
        "phase": match.group("phase").strip(),
        "percent": max(0.0, min(100.0, percent)),
        "eta": (match.group("eta") or "").strip(),
        "remaining": (match.group("remaining") or "").strip(),
    }


def nmap_stderr_excerpt(stderr: str, max_chars: int = 12000) -> str:
    """Return a bounded diagnostic excerpt suitable for scan results."""
    if max_chars <= 0:
        raise ValueError("Nmap diagnostic excerpt size must be positive.")
    return stderr.strip()[:max_chars]


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_nmap(
    command: Sequence[str],
    *,
    timeout: float | None,
    cancel_event: Event | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    command_callback: Callable[[Sequence[str]], None] | None = None,
    output_callback: Callable[[dict[str, Any]], None] | None = None,
    max_stdout_bytes: int = MAX_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_STDERR_BYTES,
) -> NmapProcessResult:
    """Execute Nmap while draining both pipes, bounding retained output, and reporting stats."""
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("Nmap output limits must be positive.")
    full_command = add_nmap_progress_args(command)
    if cancel_event is not None and cancel_event.is_set():
        return NmapProcessResult(
            status="cancelled",
            returncode=None,
            stdout="",
            stderr="",
            error="Nmap process cancelled before it started.",
        )
    if command_callback is not None:
        command_callback(list(full_command))
    command_id = str(uuid.uuid4())
    try:
        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            shell=False,
        )
    except OSError as exc:
        if output_callback is not None:
            output_callback({
                "type": "execution_error",
                "command_id": command_id,
                "argv": list(full_command),
                "timestamp": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                "message": str(exc),
            })
        raise
    started_at = time.monotonic()
    start_time = datetime.now().astimezone().isoformat(timespec="milliseconds")
    if output_callback is not None:
        output_callback({
            "type": "process_started",
            "command_id": command_id,
            "argv": list(full_command),
            "start_time": start_time,
        })
    stdout_data = bytearray()
    stderr_data = bytearray()
    output_limit_reached = threading.Event()
    reader_failed = threading.Event()
    reader_errors: list[str] = []
    def publish_output(channel: str, text: str) -> None:
        if output_callback is None:
            return
        if text:
            output_callback({
                "type": "output",
                "command_id": command_id,
                "channel": channel,
                "timestamp": datetime.now().astimezone().isoformat(timespec="milliseconds"),
                "text": text,
            })

    def read_stdout() -> None:
        try:
            assert process.stdout is not None
            while True:
                line = process.stdout.readline()
                if not line:
                    return
                chunk = line.encode("utf-8", errors="replace")
                remaining = max_stdout_bytes - len(stdout_data)
                if remaining > 0:
                    stdout_data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    output_limit_reached.set()
                publish_output("stdout", line)
        except OSError as exc:
            reader_errors.append(f"stdout: {exc}")
            reader_failed.set()

    def read_stderr() -> None:
        try:
            assert process.stderr is not None
            while True:
                line = process.stderr.readline()
                if not line:
                    break
                publish_output("stderr", line)
                progress = parse_nmap_progress_line(line)
                if progress is not None:
                    if progress_callback is not None:
                        progress_callback(progress)
                    if output_callback is not None:
                        output_callback({
                            "type": "progress",
                            "command_id": command_id,
                            **progress,
                        })
                chunk = line.encode("utf-8", errors="replace")
                stderr_data.extend(chunk)
                if len(stderr_data) > max_stderr_bytes:
                    del stderr_data[: len(stderr_data) - max_stderr_bytes]
        except OSError as exc:
            reader_errors.append(f"stderr: {exc}")
            reader_failed.set()

    stdout_reader = threading.Thread(target=read_stdout, name="nmap-stdout-reader")
    stderr_reader = threading.Thread(target=read_stderr, name="nmap-stderr-reader")
    stdout_reader.start()
    stderr_reader.start()
    terminal_status = "completed"
    terminal_error = None
    try:
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                terminal_status = "cancelled"
                terminal_error = "Nmap process cancelled by the operator."
                _terminate_process(process)
                break
            if timeout is not None and time.monotonic() - started_at >= timeout:
                terminal_status = "timeout"
                terminal_error = f"Nmap process exceeded the {timeout:g}-second timeout."
                _terminate_process(process)
                break
            if output_limit_reached.is_set():
                terminal_status = "output_limit"
                terminal_error = "Nmap output exceeded the configured size limit."
                _terminate_process(process)
                break
            if reader_failed.is_set():
                terminal_status = "reader_error"
                terminal_error = "; ".join(reader_errors)
                _terminate_process(process)
                break
            time.sleep(0.05)
    finally:
        if process.poll() is None:
            _terminate_process(process)
        stdout_reader.join(timeout=5)
        stderr_reader.join(timeout=5)
        if stdout_reader.is_alive() or stderr_reader.is_alive():
            if process.poll() is None:
                process.kill()
                process.wait()
            stdout_reader.join()
            stderr_reader.join()

    if output_limit_reached.is_set() and terminal_status == "completed":
        terminal_status = "output_limit"
        terminal_error = "Nmap output exceeded the configured size limit."
    elif reader_failed.is_set() and terminal_status == "completed":
        terminal_status = "reader_error"
        terminal_error = "; ".join(reader_errors)
    if output_callback is not None:
        end_time = datetime.now().astimezone().isoformat(timespec="milliseconds")
        output_callback({
            "type": "process_exited",
            "command_id": command_id,
            "status": terminal_status,
            "returncode": process.returncode,
            "return_code": process.returncode,
            "start_time": start_time,
            "end_time": end_time,
            "duration": round(time.monotonic() - started_at, 3),
            "error": terminal_error,
        })
    return NmapProcessResult(
        status=terminal_status,
        returncode=process.returncode,
        stdout=stdout_data.decode("utf-8", errors="replace"),
        stderr=stderr_data.decode("utf-8", errors="replace"),
        error=terminal_error,
    )
