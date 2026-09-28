"""Flask API for WiFi Sentinel V2.0 authorized Offensive assessments."""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from threading import RLock
from uuid import UUID, uuid4

from flask import Flask, jsonify, render_template, request

from access_control import configure_access_control
from offensive.service import OffensiveAssessmentService


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["DEBUG"] = False
configure_access_control(app)
assessment_service = OffensiveAssessmentService()
scan_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="offensive-scan")
scan_jobs: dict[str, dict] = {}
scan_jobs_lock = RLock()


@app.get("/")
def dashboard():
	"""Serve the existing dashboard template without modifying its design."""
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
		target = assessment_service.validate_target(payload.get("target"))
	except ValueError as exc:
		return jsonify({"status": "failed", "error": str(exc)}), 400
	include_udp = payload.get("include_udp", False)
	include_web = payload.get("include_web", True)
	if not isinstance(include_udp, bool) or not isinstance(include_web, bool):
		return jsonify(
			{"status": "failed", "error": "include_udp and include_web must be boolean values."}
		), 400

	scan_id = str(uuid4())
	job = {
		"scan_id": scan_id,
		"report_id": scan_id,
		"scan_type": "offensive",
		"target": target,
		"status": "pending",
		"hosts": [],
		"services": [],
		"findings": [],
		"statistics": {},
		"limitations": [],
		"errors": [],
		"settings": {"include_udp": include_udp, "include_web": include_web},
	}
	with scan_jobs_lock:
		scan_jobs[scan_id] = dict(job)

	scan_executor.submit(_run_scan_job, scan_id, target, include_udp, include_web)
	return jsonify(job), 202


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


def _run_scan_job(
	scan_id: str,
	target: str,
	include_udp: bool = False,
	include_web: bool = True,
) -> None:
	"""Run the worker and publish its final result to the in-memory job store."""
	with scan_jobs_lock:
		job = scan_jobs.get(scan_id)
		if job is None:
			return
		job["status"] = "running"

	try:
		result = assessment_service.run_authorized_assessment(
			target,
			authorization_confirmed=True,
			report_id=scan_id,
			include_udp=include_udp,
			include_web=include_web,
		)
	except Exception as exc:
		logger.exception("Offensive scan job %s failed", scan_id)
		result = {
			"scan_id": scan_id,
			"report_id": scan_id,
			"status": "failed",
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
			"settings": {"include_udp": include_udp, "include_web": include_web},
		}

	with scan_jobs_lock:
		job = scan_jobs.get(scan_id)
		if job is not None:
			job.update(result)
			job["result"] = result


if __name__ == "__main__":
	from waitress import serve

	serve(
		app,
		host=os.environ.get("WIFI_SENTINEL_HOST", "127.0.0.1"),
		port=int(os.environ.get("WIFI_SENTINEL_PORT", "5000")),
		threads=8,
	)
