"""Flask API for VulnScan v4.13 authorized Offensive assessments."""

from __future__ import annotations

import logging
import ipaddress
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Event, RLock
from uuid import UUID, uuid4

from flask import Flask, Response, jsonify, render_template, request, send_file, session, stream_with_context

from access_control import configure_access_control
from nmap_live import NmapLiveStream, create_nmap_live_stream, record_nmap_job_event
from offensive.discovery import OffensiveDiscovery
from guidance_authorization import (
	guidance_token_is_valid,
	issue_guidance_token,
)
from offensive.service import OffensiveAssessmentService
from scanner.nmap_options import validate_admin_nmap_options
from scanner.ports import PortScanner


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["DEBUG"] = False
configure_access_control(app)
assessment_service = OffensiveAssessmentService()
scan_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="offensive-scan")
scan_jobs: dict[str, dict] = {}
scan_cancel_events: dict[str, Event] = {}
nmap_live_streams: dict[str, NmapLiveStream] = {}
scan_jobs_lock = RLock()


@app.get("/")
def dashboard():
	"""Serve the complete offensive assessment and result workspace."""
	return render_template("dashboard.html")


@app.post("/api/offensive/scans")
def start_offensive_scan():
	"""Queue an authorized scan and return its pending job record."""
	payload = request.get_json(silent=True)
	if not isinstance(payload, dict):
		return jsonify({"status": "failed", "error": "A JSON request body is required."}), 400
	if payload.get("authorized") is not True:
		return jsonify(
			{
				"status": "failed",
				"error": "Confirm that you are authorized to assess this network.",
			}
		), 403
	try:
		admin_nmap_options = validate_admin_nmap_options(
			payload.get("admin_nmap_options"),
			is_admin=session.get("_role") == "admin",
			has_raw_scan_privileges=PortScanner._has_os_detection_privileges(),
		)
	except PermissionError as exc:
		return jsonify({"status": "failed", "error": str(exc)}), 403
	except ValueError as exc:
		return jsonify({"status": "failed", "error": str(exc)}), 400

	try:
		raw_target = payload.get("target")
		target = assessment_service.validate_target(
			raw_target,
			allow_ipv6=bool(admin_nmap_options and admin_nmap_options.get("ipv6")),
		)
	except ValueError as exc:
		return jsonify({"status": "failed", "error": str(exc)}), 400
	if admin_nmap_options and admin_nmap_options["discovery_method"] == "none":
		try:
			target_network = ipaddress.ip_network(str(raw_target).strip(), strict=False)
		except ValueError:
			return jsonify({"status": "failed", "error": "A valid single-host target is required when discovery is skipped."}), 400
		if target_network.num_addresses > 1:
			return jsonify({
				"status": "failed",
				"error": "Skipping host discovery is limited to one explicitly selected host.",
			}), 400
	include_udp = payload.get("include_udp", False)
	include_web = payload.get("include_web", True)
	if not isinstance(include_udp, bool) or not isinstance(include_web, bool):
		return jsonify(
			{"status": "failed", "error": "include_udp and include_web must be boolean values."}
		), 400
	if admin_nmap_options:
		include_udp = include_udp or admin_nmap_options["include_udp"]
	try:
		scan_config = assessment_service.resolve_scan_config(
			payload.get("profile", "standard"),
			payload.get("custom_ports"),
			payload.get("scan_method", "connect"),
		)
	except ValueError as exc:
		return jsonify({"status": "failed", "error": str(exc)}), 400
	try:
		nse_modules = assessment_service.resolve_nse_modules(payload.get("nse_modules", []))
	except ValueError as exc:
		return jsonify({"status": "failed", "error": str(exc)}), 400

	session.pop("_vulnerability_guidance_authorization", None)
	scan_id = str(uuid4())
	job = {
		"scan_id": scan_id,
		"report_id": scan_id,
		"scan_type": "offensive",
		"target": target,
		"status": "pending",
		"phase": "Queued for assessment",
		"progress": 0,
		"nmap_progress": None,
		"nmap_commands": [],
		"nmap_events": [],
		"nmap_output": [],
		"hosts": [],
		"services": [],
		"findings": [],
		"statistics": {},
		"limitations": [],
		"errors": [],
		"settings": {
			"include_udp": include_udp,
			"include_web": include_web,
			**scan_config,
			"nse_modules": list(nse_modules),
			"admin_nmap_options": admin_nmap_options,
		},
	}
	with scan_jobs_lock:
		scan_jobs[scan_id] = dict(job)
		cancel_event = Event()
		scan_cancel_events[scan_id] = cancel_event
		create_nmap_live_stream(nmap_live_streams, scan_id)

	scan_executor.submit(
		_run_scan_job,
		scan_id,
		target,
		include_udp,
		include_web,
		scan_config,
		nse_modules,
		admin_nmap_options,
		cancel_event,
	)
	return jsonify(job), 202


@app.post("/api/offensive/reports/<report_id>/guidance/authorize")
def authorize_vulnerability_guidance(report_id: str):
	"""Authorize non-executing guidance for one finding in a saved report."""
	payload = request.get_json(silent=True)
	if not isinstance(payload, dict) or payload.get("authorized_lab_confirmed") is not True:
		return jsonify({"status": "failed", "error": "Explicit authorized lab / CTF confirmation is required."}), 403
	finding_id = payload.get("finding_id")
	if not isinstance(finding_id, str) or not finding_id or len(finding_id) > 300:
		return jsonify({"status": "failed", "error": "A valid finding ID is required."}), 400
	try:
		report = assessment_service.load_report(report_id)
	except (ValueError, OSError):
		return jsonify({"status": "failed", "error": "The selected report was not found."}), 404
	if not isinstance(report, dict):
		return jsonify({"status": "failed", "error": "The selected report was not found."}), 404
	findings = report.get("Security Findings", [])
	finding = next(
		(item for item in findings if isinstance(item, dict) and item.get("id") == finding_id),
		None,
	) if isinstance(findings, list) else None
	if finding is None:
		return jsonify({"status": "failed", "error": "The finding is not part of this report."}), 404
	if (
		finding.get("finding_type") not in {"cve-correlation", "tls-certificate", "tls-expiry", "web-headers"}
		or finding.get("vulnerability_status") == "Insufficient evidence"
	):
		return jsonify({"status": "failed", "error": "This finding does not have sufficient vulnerability-indicator evidence for a guidance panel."}), 400
	token = issue_guidance_token(str(report_id), finding_id)
	session["_vulnerability_guidance_authorization"] = {
		"report_id": str(report_id),
		"finding_id": finding_id,
	}
	return jsonify({
		"status": "authorized",
		"authorization_token": token,
		"expires_in_seconds": 1800,
	})


@app.post("/api/offensive/reports/<report_id>/validation")
def add_vulnerability_validation_record(report_id: str):
	"""Append a user-recorded, evidence-backed validation state to a report."""
	payload = request.get_json(silent=True)
	if not isinstance(payload, dict):
		return jsonify({"status": "failed", "error": "A JSON request body is required."}), 400
	finding_id = payload.get("finding_id")
	token = payload.get("authorization_token")
	state = payload.get("state")
	observation = payload.get("observation")
	if not isinstance(finding_id, str) or not finding_id or len(finding_id) > 300:
		return jsonify({"status": "failed", "error": "A valid finding ID is required."}), 400
	if not guidance_token_is_valid(token, str(report_id), finding_id):
		return jsonify({"status": "failed", "error": "Confirm authorization for this finding before adding validation evidence."}), 403
	allowed_states = {"NOT VALIDATED", "POTENTIALLY VULNERABLE", "VALIDATED", "NOT VULNERABLE", "INCONCLUSIVE", "REMEDIATED", "VERIFIED"}
	if not isinstance(state, str) or state not in allowed_states:
		return jsonify({"status": "failed", "error": "Select a supported, user-recorded assessment state."}), 400
	if not isinstance(observation, str) or not observation.strip() or len(observation) > 2000:
		return jsonify({"status": "failed", "error": "Enter a concise observation or evidence note (maximum 2000 characters)."}), 400
	if state in {"VALIDATED", "REMEDIATED", "VERIFIED"} and len(observation.strip()) < 12:
		return jsonify({"status": "failed", "error": "Add specific observed evidence before recording this state."}), 400
	try:
		report = assessment_service.load_report(report_id)
	except (ValueError, OSError):
		return jsonify({"status": "failed", "error": "The selected report was not found."}), 404
	if not isinstance(report, dict):
		return jsonify({"status": "failed", "error": "The selected report was not found."}), 404
	findings = report.get("Security Findings", [])
	finding = next(
		(item for item in findings if isinstance(item, dict) and item.get("id") == finding_id),
		None,
	) if isinstance(findings, list) else None
	if finding is None:
		return jsonify({"status": "failed", "error": "The finding is not part of this report."}), 404
	records = report.setdefault("Vulnerability Validation", [])
	if not isinstance(records, list):
		return jsonify({"status": "failed", "error": "The report validation section is invalid."}), 500
	if state == "VERIFIED" and not any(
		isinstance(item, dict)
		and item.get("finding_id") == finding_id
		and item.get("state") in {"REMEDIATED", "VERIFIED"}
		for item in records
	):
		return jsonify({"status": "failed", "error": "Record remediation before recording post-remediation verification."}), 409
	record = {
		"finding_id": finding_id,
		"state": state,
		"target": finding.get("target"),
		"port": finding.get("port"),
		"service": finding.get("service"),
		"observation": observation.strip(),
		"timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
		"source": "User-recorded; not independently verified by VulnScan.",
	}
	records.append(record)
	try:
		assessment_service.save_report(report_id, report)
	except (OSError, ValueError):
		logger.exception("Could not update validation evidence for report %s", report_id)
		return jsonify({"status": "failed", "error": "The validation note could not be saved to the report."}), 500
	return jsonify({"status": "saved", "record": record})


@app.get("/api/offensive/scans/<scan_id>")
def get_offensive_scan(scan_id: str):
	"""Return a scan's pending, running, or terminal structured result."""
	try:
		normalized_id = str(UUID(scan_id))
	except (ValueError, TypeError, AttributeError):
		return jsonify({"status": "failed", "error": "Unknown scan ID."}), 404
	with scan_jobs_lock:
		job = scan_jobs.get(normalized_id)
		snapshot = dict(job) if job is not None else None
	if snapshot is None:
		return jsonify({"status": "failed", "error": "Unknown scan ID."}), 404
	return jsonify(snapshot)


@app.get("/api/offensive/scans/<scan_id>/stream")
def stream_offensive_scan_output(scan_id: str):
	try:
		normalized_id = str(UUID(scan_id))
	except (ValueError, TypeError, AttributeError):
		return jsonify({"status": "failed", "error": "Unknown scan ID."}), 404
	with scan_jobs_lock:
		exists = normalized_id in scan_jobs
		stream = nmap_live_streams.get(normalized_id)
	if not exists:
		return jsonify({"status": "failed", "error": "Unknown scan ID."}), 404
	if stream is None:
		return jsonify({"status": "failed", "error": "Nmap output stream is unavailable."}), 404
	try:
		cursor = max(0, int(request.headers.get("Last-Event-ID", "0")))
	except ValueError:
		return jsonify({"status": "failed", "error": "Invalid stream event cursor."}), 400

	def generate():
		nonlocal cursor
		while True:
			events, finished, history_gap = stream.events_after(cursor, timeout=15)
			if history_gap:
				yield "event: history_gap\ndata: {}\n\n"
			for event in events:
				cursor = event["id"]
				payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
				yield f"id: {cursor}\nevent: {event['type']}\ndata: {payload}\n\n"
				if event["type"] == "assessment_end":
					return
			if finished:
				return
			if not events:
				yield ": keep-alive\n\n"

	return Response(
		stream_with_context(generate()),
		mimetype="text/event-stream",
		headers={
			"Cache-Control": "no-cache",
			"X-Accel-Buffering": "no",
		},
	)


@app.post("/api/offensive/scans/<scan_id>/cancel")
def cancel_offensive_scan(scan_id: str):
	"""Request cancellation of a running authorized assessment."""
	try:
		normalized_id = str(UUID(scan_id))
	except (ValueError, TypeError, AttributeError):
		return jsonify({"status": "failed", "error": "Unknown scan ID."}), 404
	with scan_jobs_lock:
		job = scan_jobs.get(normalized_id)
		cancel_event = scan_cancel_events.get(normalized_id)
		if job is None:
			return jsonify({"status": "failed", "error": "Unknown scan ID."}), 404
		if job.get("status") not in {"pending", "running"}:
			return jsonify({"status": "failed", "error": "Scan has already finished."}), 409
		if cancel_event is None:
			return jsonify({"status": "failed", "error": "Scan cancellation is unavailable."}), 409
		cancel_event.set()
		job["cancel_requested"] = True
		job["phase"] = "Cancellation requested"
	return jsonify({"status": "cancelling", "scan_id": normalized_id})


@app.get("/api/offensive/reports/<report_id>")
def get_offensive_report(report_id: str):
	"""Retrieve a generated JSON security report by server-generated UUID."""
	try:
		report = assessment_service.load_report(report_id)
	except (ValueError, OSError):
		return jsonify({"status": "failed", "error": "Invalid report ID."}), 404
	if report is not None:
		return jsonify(report)

	try:
		normalized_id = str(UUID(report_id))
	except (ValueError, TypeError, AttributeError):
		return jsonify({"status": "failed", "error": "Unknown report ID."}), 404
	with scan_jobs_lock:
		job = scan_jobs.get(normalized_id)
		result = job.get("result") if job is not None else None
	if isinstance(result, dict) and isinstance(result.get("report"), dict):
		return jsonify(result["report"])
	if job is not None and job.get("status") in {"pending", "running"}:
		return jsonify({"status": "running", "error": "The report is not ready."}), 409
	return jsonify({"status": "failed", "error": "Report not found."}), 404


@app.get("/api/offensive/reports/<report_id>/nmap.xml")
def get_offensive_nmap_xml(report_id: str):
	"""Download a validated aggregated Nmap XML export."""
	try:
		normalized_id = assessment_service._normalize_report_id(report_id)
	except ValueError:
		return jsonify({"status": "failed", "error": "Invalid report ID."}), 404
	xml_path = assessment_service.report_directory / f"{normalized_id}.nmap.xml"
	if not xml_path.is_file():
		return jsonify({"status": "failed", "error": "Nmap XML export is not available."}), 404
	return send_file(
		xml_path,
		mimetype="application/xml",
		as_attachment=True,
		download_name=f"wifi-sentinel-{normalized_id}.xml",
	)


def _run_scan_job(
	scan_id: str,
	target: str,
	include_udp: bool = False,
	include_web: bool = True,
	scan_config: dict | None = None,
	nse_modules: tuple[str, ...] = (),
	admin_nmap_options: dict | None = None,
	cancel_event: Event | None = None,
) -> None:
	"""Run the worker and publish its final result to the in-memory job store."""
	started_at = time.monotonic()
	with scan_jobs_lock:
		job = scan_jobs.get(scan_id)
		if job is None:
			return
		job["started_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
		job["status"] = "running"
		job["phase"] = "Assessing target"
		job["progress"] = 5

	try:
		def _progress_update(phase: str, status: str, progress: int) -> None:
			with scan_jobs_lock:
				current = scan_jobs.get(scan_id)
				if current is None:
					return
				current["status"] = status
				current["phase"] = phase
				current["progress"] = max(0, min(100, progress))
				current["elapsed_seconds"] = round(time.monotonic() - started_at, 1)
				_append_nmap_event(current, "VulnScan", f"{phase} ({status})")

		def _nmap_progress_update(target_label: str, progress: dict) -> None:
			with scan_jobs_lock:
				current = scan_jobs.get(scan_id)
				if current is None:
					return
				current["nmap_progress"] = {"target": target_label, **progress}
				current["elapsed_seconds"] = round(time.monotonic() - started_at, 1)
				message = (
					f"{progress.get('phase', 'Nmap scan')}: "
					f"{progress.get('percent', 0):g}% complete"
				)
				if progress.get("remaining"):
					message += f"; {progress['remaining']} remaining"
				_append_nmap_event(current, "Nmap", message)

		def _nmap_command_update(target_label: str, command: list[str]) -> None:
			with scan_jobs_lock:
				current = scan_jobs.get(scan_id)
				if current is None:
					return
				current.setdefault("nmap_commands", []).append({
					"target": target_label,
					"stage": current.get("phase"),
					"argv": list(command),
					"command": list(command),
					"status": "starting",
				})
				current["nmap_commands"] = current["nmap_commands"][-32:]
				_append_nmap_event(current, "Nmap", f"Nmap process started for {target_label}")

		def _nmap_output_update(target_label: str, event: dict) -> None:
			stream = nmap_live_streams.get(scan_id)
			if stream is not None:
				with scan_jobs_lock:
					current = scan_jobs.get(scan_id)
					if current is not None:
						record_nmap_job_event(current, target_label, str(current.get("phase", "")), event)
				stream.publish(
					event["type"],
					target=target_label,
					**{key: value for key, value in event.items() if key != "type"},
				)

		result = assessment_service.run_authorized_assessment(
			target,
			authorization_confirmed=True,
			report_id=scan_id,
			include_udp=include_udp,
			include_web=include_web,
			progress_callback=_progress_update,
			scan_config=scan_config,
			nse_modules=nse_modules,
			admin_nmap_options=admin_nmap_options,
			cancel_event=cancel_event,
			nmap_progress_callback=_nmap_progress_update,
			nmap_command_callback=_nmap_command_update,
			nmap_output_callback=_nmap_output_update,
		)
	except Exception as exc:
		logger.exception("Offensive scan job %s failed", scan_id)
		result = {
			"scan_id": scan_id,
			"report_id": scan_id,
			"status": "failed",
			"phase": "Assessment failed",
			"progress": 0,
			"scan_type": "offensive",
			"target": target,
			"hosts": [],
			"services": [],
			"findings": [],
			"statistics": {},
			"limitations": ["The assessment worker failed before a report could be generated."],
			"errors": [str(exc)],
			"web_assessment": {"status": "error", "services": [], "errors": [str(exc)]},
			"cve_correlation": {"status": "error", "matches": [], "errors": [str(exc)]},
			"report": None,
			"settings": {
				"include_udp": include_udp,
				"include_web": include_web,
				**(scan_config or {}),
				"nse_modules": list(nse_modules),
				"admin_nmap_options": admin_nmap_options,
			},
		}

	with scan_jobs_lock:
		job = scan_jobs.get(scan_id)
		if job is not None:
			job.update(result)
			job["elapsed_seconds"] = round(time.monotonic() - started_at, 1)
			job.setdefault("phase", "Assessment complete")
			job.setdefault("progress", 100 if str(job.get("status", "")).lower() in {"completed", "partial", "failed", "incomplete"} else 0)
			job["result"] = result
			scan_cancel_events.pop(scan_id, None)
			stream = nmap_live_streams.get(scan_id)
			if stream is not None:
				status = str(result.get("status", "")).lower()
				stream.close(
					"STOPPED" if status in {"cancelled", "canceled"}
					else "FAILED" if status in {"failed", "error"}
					else "COMPLETED"
				)


def _append_nmap_event(job: dict, source: str, message: str) -> None:
	"""Store a bounded, timestamped event from actual scanner orchestration state."""
	events = job.setdefault("nmap_events", [])
	events.append({
		"time": datetime.now().astimezone().isoformat(timespec="seconds"),
		"source": source,
		"message": str(message)[:500],
	})
	del events[:-100]


@app.get("/api/health")
def offensive_health():
	"""Return the installed Nmap engine status for the Offensive dashboard."""
	discovery = OffensiveDiscovery()
	ports = PortScanner()
	return jsonify({
		"success": True,
		"application": "VulnScan v4.13",
		"nmap": discovery.available(),
		"nmap_version": ports.get_nmap_version(),
		"raw_scan_privileges": PortScanner._has_os_detection_privileges(),
	})


if __name__ == "__main__":
	from waitress import serve

	serve(
		app,
		host=os.environ.get("WIFI_SENTINEL_HOST", "127.0.0.1"),
		port=int(os.environ.get("WIFI_SENTINEL_PORT", "5000")),
		threads=8,
	)
