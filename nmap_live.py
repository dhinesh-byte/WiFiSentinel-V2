"""Thread-safe, bounded event history for live Nmap subprocess output."""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime
from typing import Any, MutableMapping

_REGISTRY_LOCK = threading.Lock()
_MAX_RETAINED_STREAMS = 16
_MAX_RETAINED_OUTPUT_BYTES = 20 * 1024 * 1024
_MAX_JOB_OUTPUT_LINES = 20_000


def record_nmap_job_event(
    job: dict[str, Any],
    target: str,
    stage: str,
    event: dict[str, Any],
) -> None:
    """Retain actual subprocess output and lifecycle metadata on its scan job."""
    event_type = event.get("type")
    commands = job.setdefault("nmap_commands", [])
    command_id = event.get("command_id")

    if event_type == "process_started":
        argv = list(event.get("argv", []))
        command = next((
            item for item in reversed(commands)
            if item.get("target") == target
            and item.get("argv") == argv
            and not item.get("command_id")
        ), None)
        if command is None:
            command = {"target": target, "stage": stage, "argv": argv}
            commands.append(command)
        command.update({
            "command_id": command_id,
            "command": argv,
            "stage": stage,
            "start_time": event.get("start_time"),
            "status": "running",
        })
    elif event_type == "execution_error":
        argv = list(event.get("argv", []))
        command = next((
            item for item in reversed(commands)
            if item.get("target") == target and item.get("argv") == argv
        ), None)
        if command is not None:
            command.update({
                "command_id": command_id,
                "stage": stage,
                "start_time": event.get("timestamp"),
                "end_time": event.get("timestamp"),
                "duration": 0,
                "status": "failed",
                "error": event.get("message"),
            })
    elif event_type == "process_exited":
        command = next((item for item in reversed(commands) if item.get("command_id") == command_id), None)
        if command is not None:
            return_code = event.get("return_code", event.get("returncode"))
            process_status = str(event.get("status", "failed"))
            if process_status == "completed" and return_code != 0:
                process_status = "failed"
            command.update({
                "return_code": return_code,
                "end_time": event.get("end_time"),
                "duration": event.get("duration"),
                "status": process_status,
            })
            if event.get("error"):
                command["error"] = event["error"]

    if event_type != "output":
        return

    output = event.get("text")
    if not isinstance(output, str) or not output:
        return
    timestamp = event.get("timestamp") or datetime.now().astimezone().isoformat(timespec="milliseconds")
    lines = job.setdefault("nmap_output", [])
    for line in output.splitlines():
        lines.append({
            "timestamp": timestamp,
            "stream": event.get("channel", "stdout"),
            "line": line,
            "target": target,
            "stage": stage,
            "command_id": command_id,
        })
    del lines[:-_MAX_JOB_OUTPUT_LINES]


def create_nmap_live_stream(registry: MutableMapping[str, "NmapLiveStream"], scan_id: str) -> "NmapLiveStream":
    """Create a stream and discard the oldest finished replay buffers when needed."""
    with _REGISTRY_LOCK:
        for old_id, old_stream in tuple(registry.items()):
            if len(registry) < _MAX_RETAINED_STREAMS:
                break
            if old_stream.finished:
                del registry[old_id]
        stream = NmapLiveStream(max_output_bytes=_MAX_RETAINED_OUTPUT_BYTES)
        registry[scan_id] = stream
        return stream


class NmapLiveStream:
    """Retain recent subprocess events and wake SSE readers as they arrive."""

    def __init__(self, *, max_events: int = 20_000, max_output_bytes: int = 32 * 1024 * 1024) -> None:
        self._condition = threading.Condition()
        self._events: deque[dict[str, Any]] = deque()
        self._max_events = max_events
        self._max_output_bytes = max_output_bytes
        self._output_bytes = 0
        self._next_id = 1
        self._finished = False
        self._state = "AWAITING PROCESS"
        self._active_processes: set[str] = set()
        self._process_failed = False

    @property
    def finished(self) -> bool:
        with self._condition:
            return self._finished

    @property
    def state(self) -> str:
        with self._condition:
            return self._state

    def publish(self, event_type: str, **data: Any) -> None:
        """Publish one structured event while preserving its stream order."""
        with self._condition:
            if event_type == "process_started":
                self._active_processes.add(str(data.get("command_id", "")))
                self._state = "RUNNING"
            elif event_type == "execution_error":
                self._process_failed = True
                if not self._active_processes:
                    self._state = "FAILED"
            elif event_type == "process_exited":
                self._active_processes.discard(str(data.get("command_id", "")))
                process_status = str(data.get("status", "")).lower()
                if process_status != "cancelled" and (
                    process_status != "completed" or data.get("returncode") != 0
                ):
                    self._process_failed = True
                if self._active_processes:
                    self._state = "RUNNING"
                elif process_status == "cancelled":
                    self._state = "STOPPED"
                elif self._process_failed:
                    self._state = "FAILED"
                else:
                    self._state = "RUNNING"
            event = {"id": self._next_id, "type": event_type, **data}
            self._next_id += 1
            if event_type == "output":
                self._output_bytes += len(str(data.get("text", "")).encode("utf-8"))
            self._events.append(event)
            while (
                len(self._events) > self._max_events
                or self._output_bytes > self._max_output_bytes
            ):
                removed = self._events.popleft()
                if removed.get("type") == "output":
                    self._output_bytes -= len(str(removed.get("text", "")).encode("utf-8"))
            self._condition.notify_all()

    def close(self, status: str) -> None:
        """Publish the terminal assessment state and wake connected clients."""
        with self._condition:
            if self._finished:
                return
            if status == "STOPPED":
                self._state = "STOPPED"
            elif self._process_failed:
                self._state = "FAILED"
            else:
                self._state = status
            event = {"id": self._next_id, "type": "assessment_end", "status": self._state}
            self._next_id += 1
            self._events.append(event)
            self._finished = True
            self._condition.notify_all()

    def events_after(
        self,
        event_id: int,
        *,
        timeout: float = 15.0,
    ) -> tuple[list[dict[str, Any]], bool, bool]:
        """Wait for newer events, returning events, completion, and replay-gap state."""
        with self._condition:
            if not any(event["id"] > event_id for event in self._events) and not self._finished:
                self._condition.wait(timeout)
            oldest_id = self._events[0]["id"] if self._events else self._next_id
            history_gap = event_id < oldest_id - 1
            events = [event for event in self._events if event["id"] > event_id]
            return events, self._finished, history_gap
