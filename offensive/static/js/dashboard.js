(() => {
	"use strict";

	const form = document.getElementById("scan-form");
	const targetInput = document.getElementById("target-input");
	const authorizationCheck = document.getElementById("authorization-check");
	const includeUdp = document.getElementById("include-udp");
	const includeWeb = document.getElementById("include-web");
	const startButton = document.getElementById("start-scan");
	const formError = document.getElementById("form-error");
	const sessionState = document.getElementById("session-state");
	const sessionStateLabel = document.getElementById("session-state-label");
	const scanStatus = document.getElementById("scan-status");
	const scanStage = document.getElementById("scan-stage");
	const scanMessage = document.getElementById("scan-message");
	const scanPulse = document.getElementById("scan-pulse");
	const reportLink = document.getElementById("report-link");
	const hostTableBody = document.getElementById("hosts-table-body");
	const serviceTableBody = document.getElementById("services-table-body");
	const udpUncertainty = document.getElementById("udp-uncertainty");
	const webTableBody = document.getElementById("web-table-body");
	const cveTableBody = document.getElementById("cve-table-body");
	const segmentationTableBody = document.getElementById("segmentation-table-body");
	const findingList = document.getElementById("finding-list");
	const findingEmpty = document.getElementById("finding-empty");
	const attackGraph = document.getElementById("attack-graph");
	const graphEmpty = document.getElementById("graph-empty");
	const limitationsList = document.getElementById("limitations-list");
	const errorsList = document.getElementById("errors-list");

	const terminalStatuses = new Set(["completed", "partial", "incomplete", "failed"]);
	let scanInProgress = false;

	function updateButtonState() {
		startButton.disabled = scanInProgress || !authorizationCheck.checked || !targetInput.value.trim();
	}

	function setStatus(status, stage, message) {
		const normalized = String(status || "pending").toLowerCase();
		sessionState.className = `session-state state-${normalized}`;
		sessionStateLabel.textContent = normalized.toUpperCase();
		scanStatus.textContent = normalized.toUpperCase();
		scanStage.textContent = stage;
		scanMessage.textContent = message;
		scanPulse.classList.toggle("is-running", normalized === "pending" || normalized === "running");
	}

	function showError(message) {
		formError.textContent = message;
		formError.hidden = false;
	}

	function clearError() {
		formError.textContent = "";
		formError.hidden = true;
	}

	function addCell(row, value, className = "") {
		const cell = document.createElement("td");
		if (className) cell.className = className;
		cell.textContent = value === null || value === undefined || value === "" ? "Not available" : String(value);
		row.append(cell);
	}

	function renderTableEmpty(body, columns, message) {
		const row = document.createElement("tr");
		row.className = "empty-row";
		const cell = document.createElement("td");
		cell.colSpan = columns;
		cell.textContent = message;
		row.append(cell);
		body.replaceChildren(row);
	}

	function renderHosts(hosts) {
		const rows = Array.isArray(hosts) ? hosts : [];
		document.getElementById("host-count").textContent = `${rows.length} HOST${rows.length === 1 ? "" : "S"}`;
		if (!rows.length) {
			renderTableEmpty(hostTableBody, 5, "No host assessment records were returned.");
			return;
		}

		const fragment = document.createDocumentFragment();
		for (const host of rows) {
			const row = document.createElement("tr");
			addCell(row, host.target, "mono-cell");
			addCell(row, host.hostname);
			const status = document.createElement("td");
			const state = document.createElement("span");
			const normalizedStatus = String(host.status || "not provided").toLowerCase();
			state.className = `enum-state ${normalizedStatus}`;
			state.textContent = normalizedStatus.toUpperCase();
			status.append(state);
			row.append(status);
			addCell(row, host.open_ports ?? "Not available", "mono-cell");
			addCell(row, host.services_identified ?? "Not available", "mono-cell");
			fragment.append(row);
		}
		hostTableBody.replaceChildren(fragment);
	}

	function renderServices(services, uncertainPorts = []) {
		const rows = Array.isArray(services) ? services : [];
		const uncertain = Array.isArray(uncertainPorts) ? uncertainPorts : [];
		udpUncertainty.hidden = uncertain.length === 0;
		udpUncertainty.textContent = uncertain.length
			? `${uncertain.length} UDP result(s) were open|filtered. They are ambiguous and are excluded from confirmed open-port totals and findings.`
			: "";
		document.getElementById("service-count").textContent = `${rows.length} SERVICE${rows.length === 1 ? "" : "S"}`;
		if (!rows.length) {
			renderTableEmpty(serviceTableBody, 5, "No service data was collected.");
			return;
		}

		const fragment = document.createDocumentFragment();
		for (const service of rows) {
			const row = document.createElement("tr");
			addCell(row, service.target, "mono-cell");
			const portCell = document.createElement("td");
			const protocol = String(service.protocol || "?").toLowerCase();
			const protocolTag = document.createElement("span");
			protocolTag.className = `protocol-tag ${protocol}`;
			protocolTag.textContent = `${service.port ?? "?"}/${protocol}`;
			portCell.append(protocolTag);
			row.append(portCell);
			addCell(row, service.service || "Unidentified");
			addCell(row, service.product);
			addCell(row, service.version, "mono-cell");
			fragment.append(row);
		}
		serviceTableBody.replaceChildren(fragment);
	}

	function renderWebObservations(webAssessment, reportSection) {
		const observations = webAssessment?.services || reportSection?.services || [];
		const rows = Array.isArray(observations) ? observations : [];
		document.getElementById("web-count").textContent = `${rows.length} ENDPOINT${rows.length === 1 ? "" : "S"}`;
		if (!rows.length) {
			renderTableEmpty(webTableBody, 7, "No web/TLS observations were returned.");
			return;
		}

		const fragment = document.createDocumentFragment();
		for (const observation of rows) {
			const row = document.createElement("tr");
			addCell(row, observation.target, "mono-cell");
			addCell(row, `${observation.port ?? "?"}/${observation.protocol || "tcp"}`, "mono-cell");
			addCell(row, observation.http_status ?? "No response", "mono-cell");
			const tls = observation.tls || {};
			const tlsLabel = tls.version
				? `${tls.version}${tls.cipher ? ` / ${tls.cipher}` : ""}`
				: (observation.transport === "https" ? "Not negotiated" : "Not used");
			addCell(row, tlsLabel, "mono-cell");
			addCell(row, observation.server_header || observation.technology_header);
			addCell(row, observation.technology_header);
			const notes = [];
			if (observation.redirect_location) notes.push(`Redirect: ${observation.redirect_location}`);
			if (tls.certificate_verified === false) notes.push(`Certificate verification failed: ${tls.verification_error || "details unavailable"}`);
			if (Number.isInteger(tls.certificate_days_remaining)) notes.push(`Certificate expires in ${tls.certificate_days_remaining} day(s)`);
			if (Array.isArray(observation.missing_security_headers) && observation.missing_security_headers.length) {
				notes.push(`Not observed: ${observation.missing_security_headers.join(", ")}`);
			}
			if (Array.isArray(observation.errors) && observation.errors.length) notes.push(...observation.errors);
			addCell(row, notes.join("; ") || "No flagged response observations");
			fragment.append(row);
		}
		webTableBody.replaceChildren(fragment);
	}

	function renderSegmentation(observations) {
		const rows = Array.isArray(observations) ? observations : [];
		document.getElementById("segmentation-count").textContent = `${rows.length} PATTERN${rows.length === 1 ? "" : "S"}`;
		if (!rows.length) {
			renderTableEmpty(segmentationTableBody, 5, "No repeated service pattern observed across assessed hosts.");
			return;
		}
		const fragment = document.createDocumentFragment();
		for (const observation of rows) {
			const row = document.createElement("tr");
			addCell(row, observation.service);
			addCell(row, `${observation.port ?? "?"}/${observation.protocol || "?"}`, "mono-cell");
			addCell(row, Array.isArray(observation.targets) ? observation.targets.join(", ") : "Not available", "mono-cell");
			addCell(row, observation.interpretation);
			addCell(row, observation.review);
			fragment.append(row);
		}
		segmentationTableBody.replaceChildren(fragment);
	}

	function renderCveMatches(correlation, reportSection) {
		const data = correlation || reportSection || {};
		const rows = Array.isArray(data.matches) ? data.matches : [];
		document.getElementById("cve-count").textContent = `${rows.length} MATCH${rows.length === 1 ? "" : "ES"}`;
		const catalogCount = data.catalog_records;
		document.getElementById("cve-note").textContent = catalogCount === 0
			? "The offline catalog is empty. No CVE conclusion can be drawn until catalog data is supplied."
			: "Only exact CPE matches are reported. No match does not establish that software is free of vulnerabilities.";
		if (!rows.length) {
			renderTableEmpty(cveTableBody, 6, catalogCount === 0 ? "No local CVE records are available." : "No exact CPE matches.");
			return;
		}

		const fragment = document.createDocumentFragment();
		for (const match of rows) {
			const row = document.createElement("tr");
			addCell(row, match.id, "mono-cell");
			const severityCell = document.createElement("td");
			const badge = document.createElement("span");
			badge.className = `severity-badge severity-${String(match.severity || "informational").toLowerCase()}`;
			badge.textContent = match.severity || "Informational";
			severityCell.append(badge);
			row.append(severityCell);
			addCell(row, `${match.target || "?"} / ${match.port ?? "?"}/${match.protocol || "?"}`, "mono-cell");
			addCell(row, [match.product, match.version].filter(Boolean).join(" / ") || match.cpe23_uri);
			addCell(row, match.confidence || "Potential");
			addCell(row, match.summary || match.title);
			fragment.append(row);
		}
		cveTableBody.replaceChildren(fragment);
	}

	function renderAttackGraph(graph) {
		const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
		const edges = Array.isArray(graph?.edges) ? graph.edges : [];
		document.getElementById("graph-count").textContent = `${edges.length} LINK${edges.length === 1 ? "" : "S"}`;
		graphEmpty.hidden = edges.length > 0;
		for (const oldEdge of attackGraph.querySelectorAll(".graph-edge")) oldEdge.remove();
		const labels = new Map(nodes.filter((node) => node && node.id).map((node) => [node.id, node]));
		for (const edge of edges) {
			const source = labels.get(edge.source);
			const target = labels.get(edge.target);
			if (!source || !target) continue;
			const row = document.createElement("div");
			row.className = "graph-edge";
			for (const node of [source, target]) {
				const item = document.createElement("span");
				item.className = `graph-node ${node.type || ""}`;
				item.textContent = node.label || node.id;
				row.append(item);
				if (node === source) {
					const arrow = document.createElement("span");
					arrow.className = "graph-arrow";
					arrow.textContent = "->";
					row.append(arrow);
				}
			}
			const relation = document.createElement("span");
			relation.className = "graph-relation";
			relation.textContent = edge.relationship || "related";
			row.append(relation);
			attackGraph.append(row);
		}
	}

	function appendFindingField(container, label, value, fullWidth = false) {
		const field = document.createElement("div");
		field.className = fullWidth ? "finding-field full-width" : "finding-field";
		const heading = document.createElement("strong");
		heading.textContent = label;
		field.append(heading);

		if (Array.isArray(value)) {
			const list = document.createElement("ul");
			if (value.length) {
				for (const item of value) {
					const entry = document.createElement("li");
					entry.textContent = String(item);
					list.append(entry);
				}
			} else {
				const entry = document.createElement("li");
				entry.textContent = "None provided";
				list.append(entry);
			}
			field.append(list);
		} else {
			const content = document.createElement("p");
			content.textContent = value === null || value === undefined || value === "" ? "Not provided" : String(value);
			field.append(content);
		}
		container.append(field);
	}

	function appendFindingPanel(container, label, fields) {
		const panel = document.createElement("details");
		panel.className = "finding-guidance-panel";
		const heading = document.createElement("summary");
		heading.textContent = label;
		panel.append(heading);
		const content = document.createElement("div");
		content.className = "finding-guidance-content";
		for (const [fieldLabel, value] of fields) {
			appendFindingField(content, fieldLabel, value, true);
		}
		panel.append(content);
		container.append(panel);
	}

	function renderFindings(findings) {
		const rows = Array.isArray(findings) ? findings : [];
		document.getElementById("finding-count").textContent = `${rows.length} FINDING${rows.length === 1 ? "" : "S"}`;
		document.getElementById("metric-findings").textContent = String(rows.length);
		findingEmpty.hidden = rows.length > 0;
		for (const oldFinding of findingList.querySelectorAll(".finding-item")) oldFinding.remove();

		for (const finding of rows) {
			const details = document.createElement("details");
			details.className = "finding-item";
			const summary = document.createElement("summary");
			summary.className = "finding-summary";

			const severity = document.createElement("span");
			const severityName = String(finding.severity || "informational");
			severity.className = `severity-badge severity-${severityName.toLowerCase()}`;
			severity.textContent = severityName;
			summary.append(severity);

			const confidence = document.createElement("span");
			confidence.className = "confidence-badge";
			confidence.textContent = finding.confidence || "Confidence not provided";
			summary.append(confidence);

			const vulnerabilityStatus = document.createElement("span");
			vulnerabilityStatus.className = "vulnerability-status";
			vulnerabilityStatus.textContent = finding.vulnerability_status || "Insufficient evidence";
			summary.append(vulnerabilityStatus);

			const title = document.createElement("span");
			title.className = "finding-title";
			title.textContent = finding.title || "Untitled finding";
			summary.append(title);

			const target = document.createElement("span");
			target.className = "finding-target";
			target.textContent = `${finding.target || "Unknown target"} / ${finding.protocol || "?"}/${finding.port ?? "?"} / ${finding.service || "Unidentified"}`;
			summary.append(target);

			const chevron = document.createElement("span");
			chevron.className = "finding-chevron";
			chevron.setAttribute("aria-hidden", "true");
			chevron.textContent = ">";
			summary.append(chevron);
			details.append(summary);

			const meta = document.createElement("div");
			meta.className = "finding-meta";
			const id = document.createElement("span");
			id.textContent = finding.id || "ID unavailable";
			const service = document.createElement("span");
			service.textContent = `${finding.protocol || "?"}/${finding.port ?? "?"} ${finding.service || "Unidentified"}`;
			meta.append(id, service);
			details.append(meta);

			const body = document.createElement("div");
			body.className = "finding-body";
			const guidance = finding.exploitation_guidance && typeof finding.exploitation_guidance === "object"
				? finding.exploitation_guidance
				: {};
			const cve = guidance.cve && typeof guidance.cve === "object" ? guidance.cve : {};
			appendFindingPanel(body, "Evidence", [
				["Finding", guidance.finding || finding.title],
				["Target", guidance.target || finding.target],
				["Port / protocol / service", `${finding.port ?? "?"}/${finding.protocol || "?"} ${finding.service || "Unidentified"}`],
				["Product / version", [finding.product, finding.version].filter(Boolean).join(" / ") || "Insufficient evidence to determine vulnerability."],
				["Observed evidence", finding.evidence],
				["Observed CPE", finding.observed_cpe],
			]);
			const exploitationFields = [
				["Vulnerability status", finding.vulnerability_status || guidance.vulnerability_status],
				["Why it may be vulnerable", guidance.why_it_may_be_vulnerable],
				["Exploitation prerequisites", guidance.exploitation_prerequisites],
				["Attacker investigation methodology", guidance.attacker_investigation_methodology],
				["Safe verification procedure", guidance.safe_verification_procedure],
				["Expected evidence if confirmed", guidance.expected_evidence_if_confirmed],
				["Potential impact", guidance.potential_impact || finding.impact],
				["Confidence level", guidance.confidence_level || finding.confidence],
				["Attacker Perspective", guidance.attacker_perspective],
				["Automatic exploitation", "Disabled. This module provides guidance only and does not execute exploits."],
			];
			if (cve.identifier) {
				exploitationFields.push(
					["CVE identifier", cve.identifier],
					["Affected product / version", `${cve.affected_product || "Not identified"} / ${cve.affected_version || "Not identified"}`],
					["CVE description", cve.description],
					["CVE severity", cve.severity],
					["CVE evidence", cve.evidence],
					["CVE prerequisites", cve.prerequisites],
					["CVE safe verification methodology", cve.safe_verification_methodology],
					["CVE remediation", cve.remediation],
				);
			}
			appendFindingPanel(body, "Exploitation Guidance", exploitationFields);
			appendFindingPanel(body, "Detection", [
				["Detection opportunities", guidance.detection_opportunities],
				["Defender Perspective", guidance.defender_perspective],
				["Detection method", finding.detection_method],
			]);
			appendFindingPanel(body, "Defense", [
				["Defensive remediation", guidance.defensive_remediation || finding.remediation],
				["References", finding.references],
			]);
			appendFindingPanel(body, "Verify Fix", [
				["Verification after remediation", guidance.verification_after_remediation],
			]);
			appendFindingField(body, "Description", finding.description);
			appendFindingField(body, "Product", finding.product);
			appendFindingField(body, "Version", finding.version);
			appendFindingField(body, "Observed CPE", finding.observed_cpe, true);
			appendFindingField(body, "Detection method", finding.detection_method, true);
			details.append(body);
			findingList.append(details);
		}
	}

	function renderList(listElement, items, emptyMessage) {
		const values = Array.isArray(items) ? items : [];
		if (!values.length) {
			const item = document.createElement("li");
			item.textContent = emptyMessage;
			listElement.replaceChildren(item);
			return;
		}
		const fragment = document.createDocumentFragment();
		for (const value of values) {
			const item = document.createElement("li");
			item.textContent = typeof value === "string" ? value : JSON.stringify(value);
			fragment.append(item);
		}
		listElement.replaceChildren(fragment);
	}

	function displayCount(value) {
		return value === null || value === undefined ? "--" : String(value);
	}

	function renderResult(result) {
		const report = result.report || {};
		const statistics = result.statistics || report["Final Statistics"] || {};
		const reportHosts = report["Hosts Assessed"];
		renderHosts(Array.isArray(reportHosts) ? reportHosts : []);
		renderServices(
			result.services || report["Services Discovered"] || [],
			result.uncertain_ports || report["UDP States Requiring Verification"] || [],
		);
		renderWebObservations(result.web_assessment, report["Web/TLS Observations"]);
		renderCveMatches(result.cve_correlation, report["CVE Correlation"]);
		renderSegmentation(report["Segmentation Observations"]);
		renderAttackGraph(report["Attack Path Graph"]);
		renderFindings(result.findings || report["Security Findings"] || []);

		document.getElementById("metric-discovered").textContent = displayCount(statistics["Hosts discovered"]);
		document.getElementById("metric-assessed").textContent = displayCount(statistics["Hosts assessed"]);
		document.getElementById("metric-ports").textContent = displayCount(statistics["Open ports"]);
		document.getElementById("metric-services").textContent = displayCount(statistics["Services identified"]);
		document.getElementById("metric-udp").textContent = displayCount(statistics["UDP ports observed"]);
		document.getElementById("metric-cve").textContent = displayCount(statistics["CVE catalog matches"]);

		renderList(limitationsList, result.limitations || report["Assessment Limitations"], "No additional limitations reported.");
		renderList(errorsList, result.errors, "No scan errors reported.");

		const status = String(result.status || "incomplete").toLowerCase();
		const summary = report["Executive Summary"] || "Assessment result received.";
		const stage = status === "completed" ? "ASSESSMENT COMPLETE" : `${status.toUpperCase()} RESULT`;
		setStatus(status, stage, summary);

		if (result.report_id) {
			reportLink.href = `/offensive/api/offensive/reports/${encodeURIComponent(result.report_id)}`;
			reportLink.download = `wifi-sentinel-report-${result.report_id}.json`;
			reportLink.hidden = false;
		} else {
			reportLink.hidden = true;
		}
	}

	function delay(milliseconds) {
		return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
	}

	async function readJson(response) {
		const data = await response.json().catch(() => ({}));
		if (!response.ok) {
			throw new Error(data.error || `Request failed with status ${response.status}.`);
		}
		return data;
	}

	async function pollScan(scanId) {
		while (true) {
			await delay(1100);
			const response = await fetch(`/offensive/api/offensive/scans/${encodeURIComponent(scanId)}`, {
				headers: { Accept: "application/json" },
			});
			const result = await readJson(response);
			const status = String(result.status || "running").toLowerCase();
			if (terminalStatuses.has(status)) return result;
			setStatus(status, "SCAN IN PROGRESS", "Discovery and service checks are still running.");
		}
	}

	form.addEventListener("submit", async (event) => {
		event.preventDefault();
		clearError();
		const target = targetInput.value.trim();
		if (!authorizationCheck.checked) {
			showError("Confirm authorization before starting an assessment.");
			return;
		}
		if (!target) {
			showError("Enter an IPv4 host or network.");
			targetInput.focus();
			return;
		}

		scanInProgress = true;
		updateButtonState();
		reportLink.hidden = true;
		setStatus("pending", "QUEUED", "Preparing the authorized assessment.");

		try {
			const startResponse = await fetch("/offensive/api/offensive/scans", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
					"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "",
				},
				body: JSON.stringify({
					target,
					authorized: true,
					include_udp: includeUdp.checked,
					include_web: includeWeb.checked,
				}),
			});
			const started = await readJson(startResponse);
			const finalResult = terminalStatuses.has(String(started.status).toLowerCase())
				? started
				: await pollScan(started.scan_id);
			renderResult(finalResult);
		} catch (error) {
			setStatus("failed", "REQUEST FAILED", "The assessment could not be completed.");
			showError(error instanceof Error ? error.message : "Unexpected scan error.");
		} finally {
			scanInProgress = false;
			updateButtonState();
		}
	});

	targetInput.addEventListener("input", updateButtonState);
	authorizationCheck.addEventListener("change", updateButtonState);
	updateButtonState();
})();
