import sys
import threading
from types import SimpleNamespace

import nmap_process as nmap_process_module
from scanner.nmap_process import (
    add_nmap_progress_args,
    parse_nmap_progress_line,
    run_nmap,
)


def test_nmap_progress_line_and_stats_arguments_are_normalized():
    progress = parse_nmap_progress_line(
        "SYN Stealth Scan Timing: About 52.5% done; ETC: 20:00 (0:00:03 remaining)"
    )

    assert progress == {
        "phase": "SYN Stealth Scan",
        "percent": 52.5,
        "eta": "20:00",
        "remaining": "0:00:03",
    }
    command = ["nmap", "-oX", "-", "192.0.2.4"]
    assert add_nmap_progress_args(command, stats_supported=True) == [
        "nmap", "--stats-every", "1s", "-oX", "-", "192.0.2.4",
    ]
    assert add_nmap_progress_args(command, stats_supported=False) == command
    assert parse_nmap_progress_line("No timing data") is None


def test_progress_option_probe_uses_capability_and_caches_result(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="Nmap help: --stats-every <time>", stderr="")

    monkeypatch.setattr(nmap_process_module.subprocess, "run", fake_run)
    nmap_process_module._supports_nmap_progress.cache_clear()
    try:
        assert add_nmap_progress_args(["nmap", "-oX", "-", "192.0.2.4"])[1:3] == [
            "--stats-every",
            "1s",
        ]
        add_nmap_progress_args(["nmap", "-oX", "-", "192.0.2.4"])
        assert calls == [["nmap", "--help"]]
    finally:
        nmap_process_module._supports_nmap_progress.cache_clear()


def test_runner_streams_nmap_progress_and_preserves_xml():
    events = []
    output_events = []
    script = (
        "import sys; "
        "sys.stdout.write('<nmaprun><runstats/></nmaprun>'); sys.stdout.flush(); "
        "sys.stderr.write('SYN Stealth Scan Timing: About 42% done; ETC: 20:00 "
        "(0:00:02 remaining)\\n'); sys.stderr.flush()"
    )

    result = run_nmap(
        [sys.executable, "-c", script, "-oX", "-", "192.0.2.4"],
        timeout=5,
        progress_callback=events.append,
        output_callback=output_events.append,
    )

    assert result.status == "completed"
    assert result.returncode == 0
    assert result.stdout == "<nmaprun><runstats/></nmaprun>"
    assert events == [{
        "phase": "SYN Stealth Scan",
        "percent": 42.0,
        "eta": "20:00",
        "remaining": "0:00:02",
    }]
    progress_events = [event for event in output_events if event["type"] == "progress"]
    assert len(progress_events) == 1
    assert progress_events[0] == {
        "type": "progress",
        "command_id": progress_events[0]["command_id"],
        "phase": "SYN Stealth Scan",
        "percent": 42.0,
        "eta": "20:00",
        "remaining": "0:00:02",
    }


def test_runner_publishes_actual_stdout_stderr_and_process_exit():
    events = []
    script = (
        "import sys; "
        "sys.stdout.buffer.write(bytes([78, 109, 97, 112, 32, 115, 116, 100, 111, 117, 116, 10])); "
        "sys.stdout.flush(); "
        "sys.stderr.buffer.write(bytes([78, 109, 97, 112, 32, 115, 116, 100, 101, 114, 114, 10])); "
        "sys.stderr.flush()"
    )
    result = run_nmap(
        [sys.executable, "-c", script, "-oX", "-", "192.0.2.4"],
        timeout=5,
        output_callback=events.append,
    )

    assert result.status == "completed"
    assert "".join(event["text"] for event in events if event.get("channel") == "stdout") == "Nmap stdout\n"
    assert "".join(event["text"] for event in events if event.get("channel") == "stderr") == "Nmap stderr\n"
    assert events[0]["type"] == "process_started"
    assert events[-1]["type"] == "process_exited"
    assert events[-1]["returncode"] == 0


def test_runner_delivers_output_before_process_exits():
    output_received = threading.Event()
    result = []
    script = (
        "import sys, time; "
        "print('Nmap live line', flush=True); "
        "time.sleep(0.6); "
        "print('Nmap done', flush=True)"
    )

    def capture(event):
        if event.get("type") == "output" and "Nmap live line" in event.get("text", ""):
            output_received.set()

    worker = threading.Thread(target=lambda: result.append(run_nmap(
        [sys.executable, "-c", script, "-oX", "-", "192.0.2.4"],
        timeout=5,
        output_callback=capture,
    )))
    worker.start()
    assert output_received.wait(timeout=3)
    assert worker.is_alive()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert result[0].returncode == 0


def test_runner_publishes_actual_spawn_error():
    events = []
    try:
        run_nmap(
            ["nmap-that-does-not-exist", "-oX", "-", "192.0.2.4"],
            timeout=5,
            output_callback=events.append,
        )
    except OSError:
        pass
    else:
        raise AssertionError("A missing Nmap executable must preserve the spawn error.")

    assert len(events) == 1
    assert events[0]["type"] == "execution_error"
    assert events[0]["message"]


def test_runner_terminates_process_on_timeout_and_cancellation():
    sleep_script = "import time; time.sleep(10)"
    timed_out = run_nmap(
        [sys.executable, "-c", sleep_script, "-oX", "-", "192.0.2.4"],
        timeout=0.1,
    )
    assert timed_out.status == "timeout"
    assert "timeout" in (timed_out.error or "")

    cancel_event = threading.Event()
    timer = threading.Timer(0.1, cancel_event.set)
    timer.start()
    try:
        cancelled = run_nmap(
            [sys.executable, "-c", sleep_script, "-oX", "-", "192.0.2.4"],
            timeout=5,
            cancel_event=cancel_event,
        )
    finally:
        timer.cancel()
    assert cancelled.status == "cancelled"


def test_runner_does_not_launch_a_pre_cancelled_process(monkeypatch):
    cancel_event = threading.Event()
    cancel_event.set()

    def forbidden_popen(*args, **kwargs):
        raise AssertionError("A cancelled Nmap process must not be started.")

    monkeypatch.setattr(nmap_process_module.subprocess, "Popen", forbidden_popen)
    result = run_nmap(
        [sys.executable, "-c", "pass", "-oX", "-", "192.0.2.4"],
        timeout=5,
        cancel_event=cancel_event,
    )

    assert result.status == "cancelled"
    assert result.returncode is None


def test_runner_enforces_output_limits_while_draining_pipes():
    script = (
        "import os; "
        "chunk = b'x' * 4096; "
        "[(os.write(1, chunk)) for _ in range(1024)]"
    )
    result = run_nmap(
        [sys.executable, "-c", script, "-oX", "-", "192.0.2.4"],
        timeout=5,
        max_stdout_bytes=8192,
        max_stderr_bytes=8192,
    )

    assert result.status == "output_limit"
    assert len(result.stdout.encode("utf-8")) <= 8192


def test_runner_drains_and_bounds_noisy_diagnostic_output():
    script = (
        "import sys; "
        "sys.stderr.write('x' * 2097152); sys.stderr.flush(); "
        "sys.stdout.write('<nmaprun/>'); sys.stdout.flush()"
    )
    result = run_nmap(
        [sys.executable, "-c", script, "-oX", "-", "192.0.2.4"],
        timeout=5,
        max_stderr_bytes=1024,
    )

    assert result.status == "completed"
    assert result.stdout == "<nmaprun/>"
    assert len(result.stderr.encode("utf-8")) <= 1024
