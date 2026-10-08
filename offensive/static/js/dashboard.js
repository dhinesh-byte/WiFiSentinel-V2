(() => {
	"use strict";

	const form = document.getElementById("scan-form");
	const targetInput = document.getElementById("target-input");
	const targetInputWrap = document.getElementById("target-input-wrap");
	const targetValidity = document.getElementById("target-validity");
	const authorizationCheck = document.getElementById("authorization-check");
	const scanProfile = document.getElementById("scan-profile");
	const scanMethod = document.getElementById("scan-method");
	const customPorts = document.getElementById("custom-ports");
	const customPortsControl = document.getElementById("custom-ports-control");
	const includeUdp = document.getElementById("include-udp");
	const udpDurationImpact = document.getElementById("udp-duration-impact");
	const includeWeb = document.getElementById("include-web");
	const nseChecks = [
		["smb", document.getElementById("include-smb")],
		["dns", document.getElementById("include-dns")],
		["tls", document.getElementById("include-tls")],
		["database", document.getElementById("include-database")],
	];
	function buildAdminNmapOptions() {
		const enabled = document.getElementById("admin-nmap-enabled");
		if (!enabled || !enabled.checked) return null;
		const value = (id) => document.getElementById(id)?.value || "";
		const checked = (id) => Boolean(document.getElementById(id)?.checked);
		const portPreset = value("admin-nmap-port-preset");
		return {
			assessment_profile: value("admin-nmap-profile") || "custom",
			advanced_authorized: checked("admin-nmap-advanced-authorized"),
			scan_type: value("admin-scan-type"),
			discovery_method: value("admin-discovery-method"),
			port_preset: portPreset,
			ports: portPreset === "custom" ? value("admin-nmap-ports").trim() : "",
			exclude_ports: value("admin-nmap-exclude-ports").trim(),
			include_udp: checked("admin-nmap-udp"),
			timing: value("admin-nmap-timing"),
			max_rate: Number(value("admin-nmap-max-rate")),
			scan_delay: Number(value("admin-nmap-scan-delay")),
			max_retries: Number(value("admin-nmap-retries")),
			host_timeout: Number(value("admin-nmap-timeout")),
			parallelism: Number(value("admin-nmap-parallelism")),
			service_detection: checked("admin-nmap-service"),
			os_detection: checked("admin-nmap-os"),
			traceroute: checked("admin-nmap-traceroute"),
			packet_trace: checked("admin-nmap-packet-trace"),
			reason: checked("admin-nmap-reason"),
			ipv6: checked("admin-nmap-ipv6"),
			output_format: value("admin-nmap-output") || "json",
			nse_modules: [
				["smb", "admin-nmap-smb"],
				["dns", "admin-nmap-dns"],
				["tls", "admin-nmap-tls"],
				["web", "admin-nmap-web"],
				["vulnerability", "admin-nmap-vulnerability"],
			].filter(([, id]) => checked(id)).map(([module]) => module),
		};
	}
	function updateAdminPortControls() {
		const selection = document.getElementById("admin-nmap-port-preset");
		const portLabel = document.getElementById("admin-nmap-ports-label");
		const portInput = document.getElementById("admin-nmap-ports");
		if (!selection || !portLabel || !portInput) return;
		const custom = selection.value === "custom";
		portLabel.hidden = !custom;
		portInput.required = custom;
	}
	function updateAdminProfileControls() {
		const profile = document.getElementById("admin-nmap-profile");
		const preset = document.getElementById("admin-nmap-port-preset");
		if (!profile || !preset) return;
		const scanType = document.getElementById("admin-scan-type");
		if (
			profile.value === "full"
			&& scanType
			&& !["connect", "syn"].includes(scanType.value)
		) {
			scanType.value = "connect";
		}
		const defaults = {
			quick: { udp: false, os: false, vulnerability: false },
			standard: { udp: false, os: false, vulnerability: false },
			deep: { udp: false, os: true, vulnerability: false },
			vulnerability: { udp: false, os: false, vulnerability: true },
			full: { udp: true, os: true, vulnerability: false },
		};
		const selectedDefaults = defaults[profile.value];
		preset.disabled = Boolean(selectedDefaults);
		for (const [key, id] of Object.entries({
			udp: "admin-nmap-udp",
			os: "admin-nmap-os",
			vulnerability: "admin-nmap-vulnerability",
		})) {
			const control = document.getElementById(id);
			if (!control) continue;
			control.disabled = Boolean(selectedDefaults);
			if (selectedDefaults) control.checked = selectedDefaults[key];
		}
		updateAdminPortControls();
	}
	const adminNmapEnabled = document.getElementById("admin-nmap-enabled");
	const adminNmapFields = document.getElementById("admin-nmap-fields");
	function updateAdminNmapControls() {
		if (adminNmapFields && adminNmapEnabled) {
			adminNmapFields.disabled = !adminNmapEnabled.checked;
		}
	}
	document.getElementById("admin-nmap-port-preset")?.addEventListener("change", updateAdminPortControls);
	document.getElementById("admin-scan-type")?.addEventListener("change", updateAdminProfileControls);
	document.getElementById("admin-nmap-profile")?.addEventListener("change", () => {
		updateAdminProfileControls();
		syncProfileCards();
	});
	adminNmapEnabled?.addEventListener("change", updateAdminNmapControls);
	updateAdminNmapControls();
	updateAdminProfileControls();
	const startButton = document.getElementById("start-scan");
	const formError = document.getElementById("form-error");
	const sessionState = document.getElementById("session-state");
	const sessionStateLabel = document.getElementById("session-state-label");
	const scanStatus = document.getElementById("scan-status");
	const scanStage = document.getElementById("scan-stage");
	const scanMessage = document.getElementById("scan-message");
	const scanPulse = document.getElementById("scan-pulse");
	const reportLink = document.getElementById("report-link");
	const cancelButton = document.getElementById("cancel-scan");
	const nmapProgressLabel = document.getElementById("nmap-progress");
	const diagnosticFields = {
		engine: document.getElementById("diagnostic-engine"),
		version: document.getElementById("diagnostic-version"),
		target: document.getElementById("diagnostic-target"),
		profile: document.getElementById("diagnostic-profile"),
		privileges: document.getElementById("diagnostic-privileges"),
		interface: document.getElementById("diagnostic-interface"),
		start: document.getElementById("diagnostic-start"),
		duration: document.getElementById("diagnostic-duration"),
		exitStatus: document.getElementById("diagnostic-exit-status"),
		warnings: document.getElementById("diagnostic-warnings"),
		skipped: document.getElementById("diagnostic-skipped"),
	};
	const hostTableBody = document.getElementById("hosts-table-body");
	const serviceTableBody = document.getElementById("services-table-body");
	const udpUncertainty = document.getElementById("udp-uncertainty");
	const portStateSummary = document.getElementById("port-state-summary");
	const webTableBody = document.getElementById("web-table-body");
	const cveTableBody = document.getElementById("cve-table-body");
	const segmentationTableBody = document.getElementById("segmentation-table-body");
	const findingList = document.getElementById("finding-list");
	const findingEmpty = document.getElementById("finding-empty");
	const attackGraph = document.getElementById("attack-graph");
	const graphEmpty = document.getElementById("graph-empty");
	const limitationsList = document.getElementById("limitations-list");
	const errorsList = document.getElementById("errors-list");
	let latestOffensiveResult = null;
	let latestOffensiveHosts = [];
	let latestOffensiveServices = [];
	let latestOffensiveGraphNodes = [];
	let latestNmapCommandText = "";
	let currentGuidanceContext = null;
	const guidanceSessions = new Map();
	const userValidationRecords = new Map();
	function formatNmapCommand(argv) {
		return Array.isArray(argv)
			? argv.map((part) => {
				const value = String(part);
				return /[\s"]/u.test(value) ? `"${value.replace(/"/gu, '\\"')}"` : value;
			}).join(" ")
			: "";
	}

	function renderNmapConsole(scan) {
		const commandOutput = document.getElementById("nmap-command-output");
		const terminalOutput = document.getElementById("nmap-terminal-events");
		const copyButton = document.getElementById("nmap-copy-command");
		const commands = Array.isArray(scan?.nmap_commands) ? scan.nmap_commands : [];
		const events = (Array.isArray(scan?.nmap_events) ? scan.nmap_events : [])
			.filter((event) => String(event.source || "").toLowerCase() === "vulnscan");
		if (commands.length && commandOutput) {
			latestNmapCommandText = formatNmapCommand(commands[commands.length - 1].argv);
			commandOutput.textContent = commands.slice(-32).map((command) =>
				`$ ${command.target ? `[${String(command.target)}] ` : ""}${formatNmapCommand(command.argv)}`
			).join("\n\n");
			if (copyButton) copyButton.disabled = !latestNmapCommandText;
		}
		if (terminalOutput) {
			const fragment = document.createDocumentFragment();
			for (const event of events.slice(-100)) {
				const item = document.createElement("li");
				const time = document.createElement("time");
				const timestamp = Date.parse(event.time || "");
				time.textContent = Number.isFinite(timestamp)
					? new Date(timestamp).toLocaleTimeString([], {hour12: false})
					: "—";
				const source = document.createElement("span");
				source.className = "terminal-source";
				source.textContent = `[${String(event.source || "scan")}] `;
				item.append(time, source, document.createTextNode(String(event.message || "")));
				fragment.append(item);
			}
			if (!events.length) {
				const item = document.createElement("li");
				item.textContent = "No VulnScan assessment events have been reported yet.";
				fragment.append(item);
			}
			terminalOutput.replaceChildren(fragment);
		}
	}

	function resetNmapConsole() {
		latestNmapCommandText = "";
		const commandOutput = document.getElementById("nmap-command-output");
		const terminalOutput = document.getElementById("nmap-terminal-events");
		const eventsState = document.getElementById("nmap-events-state");
		const copyButton = document.getElementById("nmap-copy-command");
		if (commandOutput) commandOutput.textContent = "Waiting for the first Nmap process invocation.";
		if (copyButton) copyButton.disabled = true;
		window.VulnScanNmapConsole?.reset();
		if (terminalOutput) {
			const item = document.createElement("li");
			item.textContent = "No VulnScan assessment events have been reported for this scan.";
			terminalOutput.replaceChildren(item);
		}
		if (eventsState) eventsState.textContent = "ASSESSMENT EVENTS";
	}

	function syncProfileCards() {
		const selectedAdmin = adminNmapEnabled?.checked
			? document.getElementById("admin-nmap-profile")?.value
			: "";
		document.querySelectorAll(".scan-profile-card").forEach((card) => {
			const profile = card.dataset.adminProfileChoice || card.dataset.profileChoice;
			card.classList.toggle("is-selected", profile === (selectedAdmin || scanProfile.value));
		});
	}

	async function loadNmapEngineStatus() {
		const badge = document.querySelector(".nmap-engine-badge");
		const statusLabel = document.getElementById("nmap-engine-status");
		const versionLabel = document.getElementById("nmap-engine-version");
		if (!badge || !statusLabel || !versionLabel) return;
		try {
			const response = await fetch("/offensive/api/health", {headers: {Accept: "application/json"}});
			const health = await response.json();
			if (!response.ok || health.success !== true) {
				throw new Error(health.error || "Nmap engine health could not be verified.");
			}
			const ready = health.nmap === true;
			badge.classList.toggle("is-ready", ready);
			badge.classList.toggle("is-offline", !ready);
			statusLabel.textContent = ready ? "READY" : "OFFLINE";
			versionLabel.textContent = ready && health.nmap_version
				? String(health.nmap_version)
				: ready ? "Version unavailable" : "Nmap not found in PATH";
			if (diagnosticFields.engine) diagnosticFields.engine.textContent = ready ? "READY" : "OFFLINE";
			if (diagnosticFields.version) diagnosticFields.version.textContent = ready ? health.nmap_version || "Unavailable" : "Unavailable";
			window.VulnScanNmapConsole?.setVersion(health.nmap_version);
			if (diagnosticFields.privileges) {
				diagnosticFields.privileges.textContent = health.raw_scan_privileges === true
					? "Available"
					: health.raw_scan_privileges === false ? "Limited" : "Unavailable";
			}
		} catch (error) {
			statusLabel.textContent = "CHECK FAILED";
			versionLabel.textContent = error instanceof Error ? error.message : "Health endpoint unavailable";
			if (diagnosticFields.engine) diagnosticFields.engine.textContent = "Status unavailable";
		}
	}

	function showNmapEvidence(title, fields) {
		const dialog = document.getElementById("nmap-evidence-drawer");
		const content = document.getElementById("nmap-evidence-content");
		const heading = document.getElementById("nmap-evidence-title");
		if (!dialog || !content || !heading) return;
		heading.textContent = title;
		content.replaceChildren();
		for (const [label, value] of fields) {
			const wrapper = document.createElement("div");
			if (Array.isArray(value) || (typeof value === "string" && value.includes("\n"))) wrapper.className = "details-wide";
			const term = document.createElement("dt");
			term.textContent = label;
			const description = document.createElement("dd");
			description.textContent = value === null || value === undefined || value === ""
				? "Unavailable"
				: Array.isArray(value) ? value.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join("\n") : String(value);
			wrapper.append(term, description);
			content.append(wrapper);
		}
		if (!dialog.open) dialog.showModal();
	}

	document.getElementById("nmap-copy-command")?.addEventListener("click", async (event) => {
		const button = event.currentTarget;
		if (!latestNmapCommandText || !navigator.clipboard) return;
		try {
			await navigator.clipboard.writeText(latestNmapCommandText);
			button.textContent = "Copied";
			window.setTimeout(() => { button.textContent = "Copy command"; }, 1600);
		} catch {
			button.textContent = "Copy unavailable";
		}
	});
	document.getElementById("nmap-evidence-close")?.addEventListener("click", () => {
		document.getElementById("nmap-evidence-drawer")?.close();
	});
	document.getElementById("nmap-evidence-drawer")?.addEventListener("click", (event) => {
		if (event.target === event.currentTarget) event.currentTarget.close();
	});
	document.querySelectorAll("[data-results-view]").forEach((button) => {
		button.addEventListener("click", () => {
			const view = button.dataset.resultsView === "nmap" ? "nmap" : "vulnscan";
			document.body.dataset.resultsView = view;
			document.querySelectorAll("[data-results-view]").forEach((item) => {
				item.setAttribute("aria-pressed", String(item === button));
			});
		});
	});
	document.querySelectorAll("[data-profile-choice], [data-admin-profile-choice]").forEach((button) => {
		button.addEventListener("click", () => {
			const adminProfile = button.dataset.adminProfileChoice;
			if (adminProfile) {
				const profileControl = document.getElementById("admin-nmap-profile");
				if (profileControl) profileControl.value = adminProfile;
				if (adminNmapEnabled) adminNmapEnabled.checked = true;
				updateAdminNmapControls();
				updateAdminProfileControls();
			} else {
				scanProfile.value = button.dataset.profileChoice;
				if (adminNmapEnabled) {
					adminNmapEnabled.checked = false;
					updateAdminNmapControls();
				}
				updateProfileControls();
			}
			syncProfileCards();
		});
	});
	adminNmapEnabled?.addEventListener("change", syncProfileCards);
	loadNmapEngineStatus();

	hostTableBody?.addEventListener("click", (event) => {
		const button = event.target.closest("[data-evidence-host]");
		if (!button) return;
		const host = latestOffensiveHosts[Number(button.dataset.evidenceHost)];
		if (!host) return;
		showNmapEvidence(`Host evidence · ${host.target || host.ip || "Unknown"}`, [
			["Target", host.target || host.ip],
			["Hostname", host.hostname],
			["Host state", host.status],
			["State reason", host.status_reason],
			["Discovery method", host.discovery_method],
			["MAC address", host.mac],
			["Vendor", host.vendor],
			["OS fingerprint", host.os],
			["Device type", host.device_type],
			["Open ports", host.open_ports],
			["Services identified", host.services_identified],
			["Traceroute", host.traceroute],
			["Evidence", host.evidence],
		]);
	});
	serviceTableBody?.addEventListener("click", (event) => {
		const button = event.target.closest("[data-evidence-service]");
		if (!button) return;
		const service = latestOffensiveServices[Number(button.dataset.evidenceService)];
		if (!service) return;
		showNmapEvidence(`${service.target || "Host"} · ${service.protocol || "tcp"}/${service.port ?? "?"}`, [
			["Target", service.target],
			["Port / protocol", `${service.port ?? "?"}/${service.protocol || "tcp"}`],
			["Service", service.service],
			["Product", service.product],
			["Version", service.version],
			["Extra information", service.extrainfo],
			["Identification method", service.method],
			["Confidence", service.confidence],
			["CPE identifiers", service.cpes],
			["NSE scripts", service.scripts],
			["State reason", service.reason],
			["Evidence", service.evidence],
		]);
	});
	attackGraph?.addEventListener("click", (event) => {
		const button = event.target.closest("[data-evidence-graph-node]");
		if (!button) return;
		const node = latestOffensiveGraphNodes[Number(button.dataset.evidenceGraphNode)];
		if (!node) return;
		showNmapEvidence(`Assessment evidence · ${node.label || node.id || "Graph node"}`, [
			["Type", node.type],
			["Identifier", node.id],
			["Label", node.label],
			["Evidence", node.evidence],
			["Details", node.details],
		]);
	});

	const terminalStatuses = new Set(["completed", "partial", "incomplete", "failed", "cancelled"]);
	let scanInProgress = false;
	let activeScanId = null;

	function updateProgressBar(value) {
		const progressBar = document.getElementById("offensive-progress");
		if (!progressBar) return;
		const progress = Math.max(0, Math.min(100, Number(value) || 0));
		progressBar.style.width = `${progress}%`;
		progressBar.dataset.progress = String(progress);
		const track = progressBar.parentElement;
		if (track) track.setAttribute("aria-valuenow", String(Math.round(progress)));
	}

	function updateButtonState() {
		const targetDetails = parseIpv4Target(targetInput.value);
		startButton.disabled = scanInProgress || !authorizationCheck.checked || !targetDetails;
		startButton.hidden = scanInProgress;
		const hasTarget = Boolean(targetInput.value.trim());
		if (targetInputWrap) targetInputWrap.dataset.validation = !hasTarget ? "pending" : targetDetails ? "valid" : "invalid";
		if (targetValidity) {
			targetValidity.textContent = !hasTarget
				? "AWAITING TARGET"
				: targetDetails ? authorizationCheck.checked ? "TARGET READY" : "TARGET VALID" : "INVALID TARGET";
			targetValidity.classList.toggle("is-valid", Boolean(targetDetails));
			targetValidity.classList.toggle("is-invalid", hasTarget && !targetDetails);
		}
		const type = document.getElementById("target-type");
		const scope = document.getElementById("target-scope");
		const resolution = document.getElementById("target-resolution");
		if (type) type.textContent = targetDetails ? targetDetails.type : hasTarget ? "Invalid" : "Pending";
		if (scope) scope.textContent = authorizationCheck.checked ? "Operator-confirmed" : "Authorization required";
		if (resolution) resolution.textContent = targetDetails ? "Not applicable (numeric target)" : "Pending";
	}

	function parseIpv4Target(value) {
		const parts = value.trim().split("/");
		if (parts.length > 2 || !parts[0]) return null;
		const octets = parts[0].split(".");
		if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/u.test(octet)
			|| (octet.length > 1 && octet.startsWith("0"))
			|| Number(octet) > 255)) return null;
		if (parts.length === 2 && (!/^\d{1,2}$/u.test(parts[1]) || Number(parts[1]) > 32)) return null;
		return {type: parts.length === 2 ? "Network" : "Host"};
	}

	function updateProfileControls() {
		const customProfile = scanProfile.value === "custom";
		customPortsControl.hidden = !customProfile;
		customPorts.required = customProfile;
		if (scanProfile.value === "deep") includeUdp.checked = true;
		updateUdpImpact();
	}

	function updateUdpImpact() {
		udpDurationImpact.hidden = !includeUdp.checked;
	}

	function setStatus(status, stage, message) {
		const normalized = String(status || "pending").toLowerCase();
		sessionState.className = `session-state state-${normalized}`;
		sessionStateLabel.textContent = normalized.toUpperCase();
		scanStatus.textContent = normalized.toUpperCase();
		scanStage.textContent = stage;
		scanMessage.textContent = message;
		scanPulse.classList.toggle("is-running", normalized === "pending" || normalized === "running");
		updateProgressBar(document.getElementById("offensive-progress")?.dataset.progress);
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
		latestOffensiveHosts = rows;
		document.getElementById("host-count").textContent = `${rows.length} HOST${rows.length === 1 ? "" : "S"}`;
		if (!rows.length) {
			renderTableEmpty(hostTableBody, 9, "No host assessment records were returned.");
			return;
		}

		const fragment = document.createDocumentFragment();
		for (const [hostIndex, host] of rows.entries()) {
			const row = document.createElement("tr");
			addCell(row, [host.target, host.ipv6].filter(Boolean).join(" / "), "mono-cell");
			addCell(row, host.hostname);
			addCell(row, [host.mac, host.vendor].filter(Boolean).join(" / "));
			addCell(row, [host.device_type, host.os].filter(Boolean).join(" / "));
			const trace = Array.isArray(host.traceroute)
				? host.traceroute.map((hop) => `${hop.ttl || "?"}: ${hop.ip || "*"}${hop.host ? ` (${hop.host})` : ""}${hop.rtt ? ` ${hop.rtt} ms` : ""}`).join(" → ")
				: "";
			addCell(row, [
				host.discovery_method,
				host.status_reason ? `Host state reason: ${host.status_reason}` : "",
				trace ? `Traceroute: ${trace}` : "",
				...(Array.isArray(host.evidence) ? host.evidence : []),
			].filter(Boolean).join("; "));
			const status = document.createElement("td");
			const state = document.createElement("span");
			const normalizedStatus = String(host.status || "not provided").toLowerCase();
			state.className = `enum-state ${normalizedStatus}`;
			state.textContent = normalizedStatus.toUpperCase();
			status.append(state);
			row.append(status);
			addCell(row, host.open_ports ?? "Not available", "mono-cell");
			addCell(row, host.services_identified ?? "Not available", "mono-cell");
			const aiCell = document.createElement("td");
			const aiButton = document.createElement("button");
			aiButton.type = "button";
			aiButton.className = "ai-context-trigger";
			aiButton.dataset.resultsPanel = "interpretation";
			aiButton.dataset.aiHost = host.target || host.ip || "";
			aiButton.dataset.aiModule = "offensive";
			aiButton.textContent = "Explain host";
			aiCell.append(aiButton);
			const evidenceButton = document.createElement("button");
			evidenceButton.type = "button";
			evidenceButton.className = "subtle-button";
			evidenceButton.dataset.evidenceHost = String(hostIndex);
			evidenceButton.textContent = "Evidence";
			aiCell.append(evidenceButton);
			row.append(aiCell);
			fragment.append(row);
		}
		hostTableBody.replaceChildren(fragment);
	}

	function renderServices(services, uncertainPorts = [], portStates = []) {
		const rows = Array.isArray(services) ? services : [];
		latestOffensiveServices = rows;
		const uncertain = Array.isArray(uncertainPorts) ? uncertainPorts : [];
		udpUncertainty.hidden = uncertain.length === 0;
		udpUncertainty.textContent = uncertain.length
			? `${uncertain.length} UDP result(s) were open|filtered. They are ambiguous and are excluded from confirmed open-port totals and findings.`
			: "";
		const observedStates = Array.isArray(portStates) ? portStates : [];
		if (portStateSummary) {
			const counts = observedStates.reduce((summary, item) => {
				const state = String(item.state || "unknown");
				summary[state] = (summary[state] || 0) + 1;
				return summary;
			}, {});
			const stateCounts = Object.entries(counts).map(([state, count]) => `${state}: ${count}`).join(" · ");
			const evidence = observedStates.map((item) =>
				`${item.target || "?"} ${item.protocol || "?"}/${item.port ?? "?"} ${item.state || "unknown"}${item.reason ? ` (${item.reason})` : ""}`
			).join("; ");
			portStateSummary.textContent = observedStates.length
				? `Firewall/filtering states — ${stateCounts}. ${evidence}`
				: "";
			portStateSummary.hidden = observedStates.length === 0;
		}
		document.getElementById("service-count").textContent = `${rows.length} SERVICE${rows.length === 1 ? "" : "S"}`;
		if (!rows.length) {
			renderTableEmpty(serviceTableBody, 7, "No service data was collected.");
			return;
		}

		const fragment = document.createDocumentFragment();
		for (const [serviceIndex, service] of rows.entries()) {
			const row = document.createElement("tr");
			addCell(row, service.target, "mono-cell");
			const portCell = document.createElement("td");
			const protocol = String(service.protocol || "?").toLowerCase();
			const protocolTag = document.createElement("span");
			protocolTag.className = `protocol-tag ${protocol}`;
			protocolTag.textContent = `${service.port ?? "?"}/${protocol}`;
			portCell.append(protocolTag);
			const aiButton = document.createElement("button");
			aiButton.type = "button";
			aiButton.className = "ai-context-trigger";
			aiButton.dataset.resultsPanel = "interpretation";
			aiButton.dataset.aiHost = service.target || "";
			aiButton.dataset.aiService = `${service.target || "?"}:${service.port ?? "?"}/${protocol}`;
			aiButton.dataset.aiModule = "offensive";
			aiButton.textContent = "Explain service";
			portCell.append(aiButton);
			const evidenceButton = document.createElement("button");
			evidenceButton.type = "button";
			evidenceButton.className = "subtle-button";
			evidenceButton.dataset.evidenceService = String(serviceIndex);
			evidenceButton.textContent = "Evidence";
			portCell.append(evidenceButton);
			row.append(portCell);
			addCell(row, service.service || "Unidentified");
			addCell(row, service.product);
			addCell(row, service.version, "mono-cell");
			addCell(row, Array.isArray(service.cpes) ? service.cpes.join(", ") : "", "mono-cell");
			const evidenceCell = document.createElement("td");
			const evidence = [
				...(Array.isArray(service.evidence) ? service.evidence : []),
				service.extrainfo ? `Service detail: ${service.extrainfo}` : "",
				service.method && service.method !== "Unknown" ? `Identification method: ${service.method} (confidence ${service.confidence || "not reported"})` : "",
				...(Array.isArray(service.cpes) ? service.cpes.map((cpe) => `CPE: ${cpe}`) : []),
				...(Array.isArray(service.scripts) ? service.scripts.map((item) => `NSE ${item.id}: ${item.output}`) : []),
			].filter(Boolean);
			if (evidence.length) {
				const disclosure = document.createElement("details");
				disclosure.className = "service-evidence";
				const summary = document.createElement("summary");
				summary.textContent = `View evidence (${evidence.length})`;
				disclosure.append(summary);
				const list = document.createElement("ul");
				for (const item of evidence) {
					const entry = document.createElement("li");
					entry.textContent = item;
					list.append(entry);
				}
				disclosure.append(list);
				evidenceCell.append(disclosure);
			} else {
				evidenceCell.textContent = "No additional evidence";
			}
			row.append(evidenceCell);
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
			if (Array.isArray(observation.methods) && observation.methods.length) {
				notes.push(`Allowed methods: ${observation.methods.join(", ")}`);
			}
		if (Array.isArray(observation.resources)) {
			for (const resource of observation.resources) {
				notes.push(`${resource.path}: HTTP ${resource.status}${resource.found ? " (observed)" : " (not found)"}`);
			}
		}
			if (tls.certificate_verified === false) {
				notes.push(`Certificate verification failed: ${tls.verification_error || "details unavailable"}`);
				if (tls.remediation) notes.push(tls.remediation);
			}
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
		latestOffensiveGraphNodes = nodes;
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
				const item = document.createElement("button");
				item.type = "button";
				item.className = `graph-node ${node.type || ""}`;
				item.textContent = node.label || node.id;
				item.dataset.evidenceGraphNode = String(nodes.indexOf(node));
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

	const GUIDANCE_FINDING_TYPES = new Set([
		"cve-correlation",
		"tls-certificate",
		"tls-expiry",
		"web-headers",
	]);
	const guidanceDialog = document.getElementById("vulnerability-guidance-dialog");
	const guidanceLearningToggle = document.getElementById("guidance-learning-mode");

	function findingCanShowGuidance(finding) {
		return GUIDANCE_FINDING_TYPES.has(finding.finding_type)
			&& finding.vulnerability_status !== "Insufficient evidence";
	}

	function currentReportId() {
		return latestOffensiveResult?.scan_id
			|| latestOffensiveResult?.report_id
			|| latestOffensiveResult?.report?.["Scan Information"]?.report_id
			|| "";
	}

	function guidanceKey(reportId, findingId) {
		return `${reportId}:${findingId}`;
	}

	function appendGuidanceText(container, label, value) {
		const block = document.createElement("div");
		block.className = "guidance-copy-block";
		const heading = document.createElement("strong");
		heading.textContent = label;
		const body = document.createElement("p");
		body.textContent = Array.isArray(value)
			? value.length ? value.join(" ") : "Not reported by this assessment."
			: value === null || value === undefined || value === ""
				? "Not reported by this assessment."
				: String(value);
		block.append(heading, body);
		container.append(block);
	}

	function appendGuidanceList(container, label, values, learning = false) {
		const section = document.createElement("section");
		section.className = "guidance-copy-block";
		const heading = document.createElement("strong");
		heading.textContent = label;
		section.append(heading);
		const items = Array.isArray(values) ? values.filter((item) => typeof item === "string" && item.trim()) : [];
		if (!items.length) {
			const empty = document.createElement("p");
			empty.textContent = "No specific details were returned by this assessment.";
			section.append(empty);
		} else {
			const list = document.createElement("ol");
			for (const [index, value] of items.entries()) {
				const item = document.createElement("li");
				item.className = "guidance-step";
				const task = document.createElement("p");
				task.textContent = value;
				item.append(task);
				if (learning) {
					for (const [labelText, explanation] of [
						["WHY?", "This keeps the check focused on confirming the reported condition without changing target state."],
						["WHAT?", "Review only the named, authorized service and compare the observed response with trusted vendor or application documentation."],
						["EXPECTED?", "Use the expected evidence listed below; this scan cannot predict or fabricate a response that was not observed."],
						["MEANING?", "Treat a match as supporting evidence only when it meets the documented prerequisites. Otherwise record the result as inconclusive."],
					]) {
						const note = document.createElement("p");
						note.className = "guidance-learning-note";
						const prefix = document.createElement("b");
						prefix.textContent = labelText;
						note.append(prefix, document.createTextNode(` ${explanation}`));
						item.append(note);
					}
				}
				list.append(item);
			}
			section.append(list);
		}
		container.append(section);
	}

	function matchingValidationRecords(context) {
		const saved = latestOffensiveResult?.report?.["Vulnerability Validation"];
		const reportRecords = Array.isArray(saved) ? saved : [];
		const localRecords = userValidationRecords.get(guidanceKey(context.reportId, context.finding.id)) || [];
		const unique = new Map();
		for (const record of [...reportRecords, ...localRecords]) {
			if (record.finding_id === context.finding.id) {
				unique.set(`${record.timestamp}:${record.state}:${record.observation}`, record);
			}
		}
		return [...unique.values()].sort((left, right) => String(left.timestamp).localeCompare(String(right.timestamp)));
	}

	function renderGuidanceTimeline(context) {
		const list = document.getElementById("guidance-timeline");
		if (!list) return;
		const records = matchingValidationRecords(context);
		const hasRecord = (state) => records.some((record) => record.state === state);
		const validationState = document.getElementById("guidance-validation-state");
		const latestRecord = records[records.length - 1];
		if (validationState) {
			validationState.textContent = latestRecord?.state || "NOT VALIDATED";
			validationState.dataset.userRecorded = String(Boolean(latestRecord));
		}
		const stages = [
			["DETECTED", true],
			["ANALYZED", true],
			["AUTHORIZED", Boolean(context.authorizationToken)],
			["VALIDATED", hasRecord("VALIDATED")],
			["EVIDENCE COLLECTED", records.some((record) => Boolean(record.observation))],
			["REMEDIATED", hasRecord("REMEDIATED") || hasRecord("VERIFIED")],
			["VERIFIED", hasRecord("VERIFIED")],
		];
		list.replaceChildren();
		for (const [label, complete] of stages) {
			const item = document.createElement("li");
			item.className = complete ? "is-complete" : "is-pending";
			item.textContent = `${complete ? "✓" : "○"} ${label}`;
			list.append(item);
		}
	}

	function renderGuidanceDetails(context) {
		const finding = context.finding;
		const guidance = finding.exploitation_guidance || {};
		const cve = guidance.cve || {};
		const heading = document.getElementById("guidance-finding-name");
		const status = document.getElementById("guidance-vulnerability-status");
		const authTarget = document.getElementById("guidance-authorization-target");
		if (heading) heading.textContent = finding.title || "Vulnerability indicator";
		if (status) status.textContent = finding.vulnerability_status || "Insufficient evidence";
		if (authTarget) authTarget.textContent = finding.target || "Unavailable";
		const factRows = [
			["Vulnerability", finding.title],
			["CVE", finding.cve_id || "No CVE identified by this assessment"],
			["Severity", finding.severity],
			["Affected product", finding.product || cve.affected_product],
			["Detected version", finding.version || cve.affected_version],
			["Affected version range", "Not reported; verify against the vendor advisory"],
			["Target", finding.target],
			["Port", finding.port],
			["Protocol", finding.protocol],
			["Detection source", finding.detection_method],
			["Confidence", finding.confidence],
			["Scanner vulnerability status", finding.vulnerability_status],
		];
		renderEvidenceGrid(document.getElementById("guidance-finding-facts"), factRows);
		renderEvidenceGrid(document.getElementById("guidance-evidence-facts"), [
			["Target", finding.target],
			["Port", finding.port],
			["Service", finding.service],
			["Detected version", finding.version],
			["Nmap evidence", finding.nmap_evidence],
			["NSE evidence", finding.nse_evidence],
			["Finding evidence", finding.evidence],
			["Timestamp", latestOffensiveResult?.report?.["Scan Information"]?.report_generated_at || latestOffensiveResult?.started_at],
			["Confidence", finding.confidence],
		]);

		const understand = document.getElementById("guidance-understand");
		understand.replaceChildren();
		appendGuidanceText(understand, "What the scanner observed", finding.description);
		appendGuidanceText(understand, "Why this may matter", guidance.why_it_may_be_vulnerable);
		appendGuidanceText(understand, "Affected component", finding.product || finding.service);
		appendGuidanceText(understand, "Affected versions", cve.affected_version || "No affected-version range was provided. Check the vendor advisory; the detected version is not proof by itself.");
		appendGuidanceList(understand, "Preconditions and required access", guidance.exploitation_prerequisites);
		appendGuidanceText(understand, "Expected impact (assessment wording)", guidance.potential_impact || finding.impact);

		const labSetup = document.getElementById("guidance-lab-setup");
		labSetup.replaceChildren();
		appendGuidanceList(labSetup, "Target requirements", guidance.exploitation_prerequisites);
		appendGuidanceList(labSetup, "Safe lab checklist", [
			"Use an isolated lab, CTF, or sandbox containing only the confirmed target.",
			"Use vendor-supported inventory or a standard read-only client only to inspect the reported service.",
			"Keep the target reachable only from the approved lab network and use test data rather than real credentials or sensitive information.",
			"Do not change service state, submit state-changing requests, or run exploit code from this console.",
		]);
		appendGuidanceText(labSetup, "Tool purpose", "A standard client or vendor inventory tool can observe service identity and configuration; VulnScan does not launch those tools from this guide.");
		appendGuidanceText(labSetup, "Authentication", "Use only a test account if the lab owner requires authentication. No credential guessing or login attempts are included.");

		const steps = document.getElementById("guidance-validation-steps");
		steps.replaceChildren();
		appendGuidanceList(steps, "Read-only validation steps", guidance.safe_verification_procedure, Boolean(guidanceLearningToggle?.checked));
		appendGuidanceList(steps, "Expected evidence to support the finding", guidance.expected_evidence_if_confirmed);

		const concept = document.getElementById("guidance-concept");
		concept.replaceChildren();
		const flow = document.createElement("ol");
		flow.className = "guidance-concept-flow";
		for (const [label, value] of [
			["INPUT / OBSERVATION", finding.evidence],
			["AFFECTED COMPONENT", finding.product || finding.service],
			["VULNERABILITY CONDITION", guidance.why_it_may_be_vulnerable],
			["SECURITY BOUNDARY", "A boundary is crossed only if the documented weakness and its prerequisites are present; this scan did not test exploitation."],
			["POTENTIAL IMPACT", guidance.potential_impact || finding.impact],
		]) {
			const item = document.createElement("li");
			const labelNode = document.createElement("strong");
			labelNode.textContent = label;
			const valueNode = document.createElement("p");
			valueNode.textContent = Array.isArray(value) ? value.join(" ") : value || "Not reported by this assessment.";
			item.append(labelNode, valueNode);
			flow.append(item);
		}
		concept.append(flow);

		const expected = document.getElementById("guidance-expected");
		expected.replaceChildren();
		appendGuidanceList(expected, "Evidence expected if confirmed", guidance.expected_evidence_if_confirmed);
		appendGuidanceText(expected, "Interpretation", "A version banner, open port, CPE match, or user-entered observation alone does not establish exploitability. Compare results with the specific vendor advisory and prerequisites.");

		const impact = document.getElementById("guidance-impact");
		impact.replaceChildren();
		appendGuidanceText(impact, "WHAT HAPPENED", finding.description);
		appendGuidanceText(impact, "WHY IT MAY MATTER", guidance.why_it_may_be_vulnerable);
		appendGuidanceText(impact, "POTENTIAL IMPACT", guidance.potential_impact || finding.impact);
		appendGuidanceText(impact, "What an attacker could achieve", "No attacker action or successful exploitation was observed. Possible impact is limited to the assessment's stated potential impact and requires the documented conditions.");

		const remediation = document.getElementById("guidance-remediation");
		remediation.replaceChildren();
		appendGuidanceText(remediation, "Patch / upgrade / configuration", guidance.defensive_remediation || finding.remediation);
		appendGuidanceList(remediation, "How to verify the fix", guidance.verification_after_remediation);
		appendGuidanceText(remediation, "FIX → RE-SCAN → COMPARE → VERIFY", "Apply the change through your approved change process, repeat the same authorized scan, compare the finding and service version/configuration, then record the observed evidence.");
	}

	function renderEvidenceGrid(container, rows) {
		if (!container) return;
		container.replaceChildren();
		for (const [label, value] of rows) {
			const wrapper = document.createElement("div");
			if (Array.isArray(value)) wrapper.className = "details-wide";
			const term = document.createElement("dt");
			term.textContent = label;
			const description = document.createElement("dd");
			if (Array.isArray(value)) {
				description.textContent = value.length
					? value.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join("\n")
					: "None reported by this assessment";
			} else {
				description.textContent = value === null || value === undefined || value === ""
					? "Not reported by this assessment"
					: String(value);
			}
			wrapper.append(term, description);
			container.append(wrapper);
		}
	}

	async function openVulnerabilityGuidance(finding) {
		const reportId = currentReportId();
		if (!guidanceDialog || !reportId) {
			showError("A saved assessment report is required before opening validation guidance.");
			return;
		}
		const key = guidanceKey(reportId, finding.id);
		const context = {reportId, finding, authorizationToken: guidanceSessions.get(key) || ""};
		currentGuidanceContext = context;
		renderGuidanceDetails(context);
		renderGuidanceTimeline(context);
		const authPanel = document.getElementById("guidance-authorization");
		const details = document.getElementById("guidance-detail-panel");
		if (authPanel) authPanel.hidden = Boolean(context.authorizationToken);
		if (details) details.hidden = !context.authorizationToken;
		const checkbox = document.getElementById("guidance-authorization-check");
		if (checkbox) checkbox.checked = false;
		const error = document.getElementById("guidance-authorization-error");
		if (error) {
			error.hidden = true;
			error.textContent = "";
		}
		if (guidanceDialog.open) guidanceDialog.close();
		guidanceDialog.showModal();
	}

	document.getElementById("vulnerability-guidance-close")?.addEventListener("click", () => guidanceDialog?.close());
	guidanceDialog?.addEventListener("click", (event) => {
		if (event.target === event.currentTarget) guidanceDialog.close();
	});
	document.getElementById("guidance-authorization-check")?.addEventListener("change", (event) => {
		const button = document.getElementById("guidance-authorization-confirm");
		if (button) button.disabled = !event.currentTarget.checked;
	});
	document.getElementById("guidance-authorization-confirm")?.addEventListener("click", async (event) => {
		const context = currentGuidanceContext;
		if (!context || !document.getElementById("guidance-authorization-check")?.checked) return;
		const button = event.currentTarget;
		const error = document.getElementById("guidance-authorization-error");
		button.disabled = true;
		button.textContent = "CONFIRMING…";
		try {
			const response = await fetch(`/offensive/api/offensive/reports/${encodeURIComponent(context.reportId)}/guidance/authorize`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
					"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "",
				},
				body: JSON.stringify({finding_id: context.finding.id, authorized_lab_confirmed: true}),
			});
			const result = await readJson(response);
			if (result.status !== "authorized" || typeof result.authorization_token !== "string") {
				throw new Error("The authorization confirmation could not be verified.");
			}
			context.authorizationToken = result.authorization_token;
			guidanceSessions.set(guidanceKey(context.reportId, context.finding.id), context.authorizationToken);
			document.getElementById("guidance-authorization").hidden = true;
			document.getElementById("guidance-detail-panel").hidden = false;
			renderGuidanceDetails(context);
			renderGuidanceTimeline(context);
			button.textContent = "AUTHORIZED";
			if (error) error.hidden = true;
		} catch (requestError) {
			if (error) {
				error.textContent = requestError instanceof Error ? requestError.message : "Authorization could not be confirmed.";
				error.hidden = false;
			}
			button.disabled = false;
			button.textContent = "I CONFIRM AUTHORIZATION";
		}
	});
	guidanceLearningToggle?.addEventListener("change", () => {
		if (currentGuidanceContext?.authorizationToken) renderGuidanceDetails(currentGuidanceContext);
	});
	document.getElementById("guidance-copy-evidence")?.addEventListener("click", async (event) => {
		if (!currentGuidanceContext) return;
		const finding = currentGuidanceContext.finding;
		const records = matchingValidationRecords(currentGuidanceContext);
		const content = [
			`Target: ${finding.target}`,
			`Port: ${finding.port}/${finding.protocol}`,
			`Service: ${finding.service}`,
			`Detected version: ${finding.version || "Not reported"}`,
			`CVE: ${finding.cve_id || "Not identified"}`,
			`Detection source: ${finding.detection_method}`,
			`Confidence: ${finding.confidence}`,
			`Scanner evidence: ${(finding.evidence || []).join("; ")}`,
			`User-recorded observations: ${records.map((record) => `${record.timestamp} ${record.state}: ${record.observation}`).join(" | ") || "None"}`,
		].join("\n");
		try {
			await navigator.clipboard.writeText(content);
			event.currentTarget.textContent = "COPIED";
			window.setTimeout(() => { event.currentTarget.textContent = "COPY EVIDENCE"; }, 1500);
		} catch {
			document.getElementById("guidance-record-message").textContent = "Clipboard access was unavailable. Select and copy the evidence shown above.";
		}
	});
	document.getElementById("guidance-add-report")?.addEventListener("click", async (event) => {
		const context = currentGuidanceContext;
		if (!context?.authorizationToken) return;
		const observationInput = document.getElementById("guidance-observation");
		const stateInput = document.getElementById("guidance-result-state");
		const message = document.getElementById("guidance-record-message");
		const observation = observationInput.value.trim();
		if (!observation) {
			message.textContent = "Enter what you actually observed before adding a validation record.";
			observationInput.focus();
			return;
		}
		const button = event.currentTarget;
		button.disabled = true;
		message.textContent = "Saving user-recorded evidence...";
		try {
			const response = await fetch(`/offensive/api/offensive/reports/${encodeURIComponent(context.reportId)}/validation`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Accept: "application/json",
					"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "",
				},
				body: JSON.stringify({
					finding_id: context.finding.id,
					authorization_token: context.authorizationToken,
					state: stateInput.value,
					observation,
				}),
			});
			const result = await readJson(response);
			if (result.status !== "saved" || !result.record) throw new Error("The report did not confirm saving the evidence.");
			const key = guidanceKey(context.reportId, context.finding.id);
			const records = userValidationRecords.get(key) || [];
			records.push(result.record);
			userValidationRecords.set(key, records);
			message.textContent = `Saved ${result.record.state} as a user-recorded result. VulnScan did not independently verify it.`;
			renderGuidanceTimeline(context);
		} catch (saveError) {
			message.textContent = saveError instanceof Error ? saveError.message : "Evidence could not be added to the report.";
		} finally {
			button.disabled = false;
		}
	});
	document.querySelectorAll("[data-guidance-ai-question]").forEach((button) => {
		button.addEventListener("click", () => {
			const context = currentGuidanceContext;
			if (!context?.authorizationToken || !window.WifiSentinelAI?.ask) return;
			window.WifiSentinelAI.ask(button.dataset.guidanceAiQuestion, {
				scanId: context.reportId,
				module: "offensive",
				findingId: context.finding.id,
				hostId: context.finding.target,
				guidanceAuthorizationToken: context.authorizationToken,
			});
		});
	});

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
			appendFindingPanel(body, "View Evidence", [
				["Finding", guidance.finding || finding.title],
				["Target", guidance.target || finding.target],
				["Port / protocol / service", `${finding.port ?? "?"}/${finding.protocol || "?"} ${finding.service || "Unidentified"}`],
				["Product / version", [finding.product, finding.version].filter(Boolean).join(" / ") || "Insufficient evidence to determine vulnerability."],
				["Observed evidence", finding.evidence],
				["Observed CPE", finding.observed_cpe],
			]);
			appendFindingField(body, "Description", finding.description);
			appendFindingField(body, "Product", finding.product);
			appendFindingField(body, "Version", finding.version);
			if (findingCanShowGuidance(finding)) {
				const guidanceButton = document.createElement("button");
				guidanceButton.type = "button";
				guidanceButton.className = "guidance-launch-button";
				guidanceButton.textContent = "EXPLOIT / VALIDATION GUIDANCE";
				guidanceButton.addEventListener("click", () => openVulnerabilityGuidance(finding));
				body.append(guidanceButton);
			}
			const aiButton = document.createElement("button");
			aiButton.type = "button";
			aiButton.className = "ai-context-trigger";
			aiButton.dataset.aiFinding = finding.id || "";
			aiButton.dataset.aiHost = finding.target || "";
			aiButton.dataset.aiModule = "offensive";
			aiButton.textContent = "Ask AI about this finding";
			body.append(aiButton);
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

	function updateScanDiagnostics(scan) {
		if (!scan) return;
		const settings = scan.settings || {};
		const adminOptions = settings.admin_nmap_options || {};
		if (diagnosticFields.target) diagnosticFields.target.textContent = scan.target || "Unavailable";
		if (diagnosticFields.profile) {
			diagnosticFields.profile.textContent = adminOptions.assessment_profile || settings.profile || "Not reported";
		}
		const startedAt = scan.started_at;
		if (diagnosticFields.start) {
			const parsed = typeof startedAt === "number" ? new Date(startedAt * 1000) : new Date(startedAt || "");
			diagnosticFields.start.textContent = Number.isNaN(parsed.getTime()) ? "Not reported" : parsed.toLocaleString();
		}
		const elapsed = Number(scan.elapsed_seconds);
		if (diagnosticFields.duration) diagnosticFields.duration.textContent = Number.isFinite(elapsed) ? `${elapsed.toFixed(1)} s` : "Not reported";
		if (diagnosticFields.exitStatus) diagnosticFields.exitStatus.textContent = scan.nmap_exit_status ?? "Not reported";
		if (diagnosticFields.interface) diagnosticFields.interface.textContent = scan.interface || "Unavailable";
		const notEnabled = [];
		if (Object.keys(adminOptions).length) {
			if (!adminOptions.os_detection) notEnabled.push("OS fingerprinting was not enabled");
			if (!adminOptions.traceroute) notEnabled.push("Traceroute was not enabled");
			if (!adminOptions.packet_trace) notEnabled.push("Packet tracing was not enabled");
			if (!settings.include_udp && !adminOptions.include_udp) notEnabled.push("UDP scanning was not enabled");
			if (!settings.include_web) notEnabled.push("Web / TLS checks were not enabled");
			if (!(settings.nse_modules || []).length && !(adminOptions.nse_modules || []).length) {
				notEnabled.push("NSE modules were not enabled");
			}
		} else {
			if (!settings.include_udp) notEnabled.push("UDP scanning was not enabled");
			if (!settings.include_web) notEnabled.push("Web / TLS checks were not enabled");
			if (!(settings.nse_modules || []).length) notEnabled.push("NSE modules were not enabled");
		}
		const limitations = Array.isArray(scan.limitations) ? scan.limitations : [];
		if (diagnosticFields.skipped) {
			diagnosticFields.skipped.textContent = [...new Set(notEnabled)].join("; ") || "None reported";
		}
		if (diagnosticFields.warnings) diagnosticFields.warnings.textContent = limitations.join(" ") || "None reported";
	}

	function renderResult(result) {
		latestOffensiveResult = result;
		renderNmapConsole(result);
		updateScanDiagnostics(result);
		const report = result.report || {};
		const statistics = result.statistics || report["Final Statistics"] || {};
		const reportHosts = report["Hosts Assessed"];
		renderHosts(Array.isArray(reportHosts) ? reportHosts : []);
		renderServices(
			result.services || report["Services Discovered"] || [],
			result.uncertain_ports || report["UDP States Requiring Verification"] || [],
			result.port_states || report["Firewall / Filtering Analysis"] || [],
		);
		renderWebObservations(result.web_assessment, report["Web/TLS Observations"]);
		renderCveMatches(result.cve_correlation, report["CVE Correlation"]);
		renderSegmentation(report["Segmentation Observations"]);
		renderAttackGraph(report["Attack Path Graph"]);
		renderFindings(result.findings || report["Security Findings"] || []);
		const scanId = result.scan_id || result.report_id || report["Scan Information"]?.report_id;
		if (scanId && window.WifiSentinelAI) window.WifiSentinelAI.setContext({scanId, module: "offensive"});
		const xmlLink = document.getElementById("nmap-xml-link");
		if (xmlLink && scanId && result.nmap_xml_available === true) {
			xmlLink.href = `/offensive/api/offensive/reports/${encodeURIComponent(scanId)}/nmap.xml`;
			xmlLink.download = `wifi-sentinel-${scanId}.xml`;
			xmlLink.hidden = false;
		} else if (xmlLink) {
			xmlLink.hidden = true;
		}

		document.getElementById("metric-discovered").textContent = displayCount(statistics["Hosts discovered"]);
		document.getElementById("metric-assessed").textContent = displayCount(statistics["Hosts assessed"]);
		document.getElementById("metric-ports").textContent = displayCount(statistics["Open ports"]);
		document.getElementById("metric-services").textContent = displayCount(statistics["Services identified"]);
		document.getElementById("metric-versions").textContent = displayCount(statistics["Versions identified"]);
		document.getElementById("metric-web").textContent = displayCount(statistics["Web services"]);
		document.getElementById("metric-tls").textContent = displayCount(statistics["TLS services"]);
		document.getElementById("metric-risk").textContent = displayCount(statistics["Risk indicators"]);
		document.getElementById("metric-udp").textContent = displayCount(statistics["UDP ports observed"]);
		document.getElementById("metric-cve").textContent = displayCount(statistics["CVE catalog matches"]);

		renderList(limitationsList, result.limitations || report["Assessment Limitations"], "No additional limitations reported.");
		renderList(errorsList, result.errors, "No scan errors reported.");
		const packetTraceDetails = document.getElementById("nmap-packet-trace-details");
		const packetTraceOutput = document.getElementById("nmap-packet-trace");
		const packetTraces = Array.isArray(result.packet_traces) ? result.packet_traces : [];
		if (packetTraceDetails && packetTraceOutput) {
			packetTraceDetails.hidden = packetTraces.length === 0;
			packetTraceOutput.textContent = packetTraces
				.map((entry) => `${entry.target || "Target"}\n${entry.trace || ""}`)
				.join("\n\n");
		}

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
			latestOffensiveResult = result;
			renderNmapConsole(result);
			updateScanDiagnostics(result);
			const status = String(result.status || "running").toLowerCase();
			const elapsedLabel = document.getElementById("offensive-elapsed");
			if (elapsedLabel && Number.isFinite(Number(result.elapsed_seconds))) {
				elapsedLabel.textContent = `Elapsed: ${Math.max(0, Number(result.elapsed_seconds)).toFixed(1)} s`;
			}
			if (typeof result.progress === "number") {
				updateProgressBar(result.progress);
			}
			if (nmapProgressLabel) {
				const nmapProgress = result.nmap_progress;
				nmapProgressLabel.textContent = nmapProgress
					? `${nmapProgress.target}: ${nmapProgress.phase} - ${Number(nmapProgress.percent).toFixed(1)}% of phase${nmapProgress.remaining ? `; ${nmapProgress.remaining} remaining` : ""}`
					: "No Nmap timing update yet.";
			}
			const phase = result.phase || (status === "running" ? "Assessment in progress" : "Assessment update");
			const nmapProgress = result.nmap_progress;
			const nmapMessage = nmapProgress
				? `Nmap ${nmapProgress.phase} is ${Number(nmapProgress.percent).toFixed(1)}% through this phase${nmapProgress.remaining ? `; ${nmapProgress.remaining} remaining` : ""}.`
				: "";
			setStatus(status, phase.toUpperCase(), nmapMessage || result.message || `Assessment is ${status.toLowerCase()}.`);
			if (terminalStatuses.has(status) && cancelButton) cancelButton.hidden = true;
			if (terminalStatuses.has(status)) return result;
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
		if (!parseIpv4Target(target)) {
			showError("Enter a valid IPv4 host or CIDR network.");
			targetInput.focus();
			return;
		}

		scanInProgress = true;
		activeScanId = null;
		resetNmapConsole();
		latestOffensiveResult = null;
		latestOffensiveHosts = [];
		latestOffensiveServices = [];
		latestOffensiveGraphNodes = [];
		guidanceSessions.clear();
		userValidationRecords.clear();
		currentGuidanceContext = null;
		if (guidanceDialog?.open) guidanceDialog.close();
		if (window.WifiSentinelAI) window.WifiSentinelAI.setContext({scanId: "", module: "offensive"});
		updateButtonState();
		reportLink.hidden = true;
		setStatus("running", "INITIALIZING", "Initializing assessment...");

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
					profile: scanProfile.value,
					scan_method: scanMethod.value,
					custom_ports: customPorts.value.trim(),
					nse_modules: nseChecks.filter(([, input]) => input.checked).map(([module]) => module),
					admin_nmap_options: buildAdminNmapOptions(),
				}),
			});
			const started = await readJson(startResponse);
			activeScanId = started.scan_id;
			window.VulnScanNmapConsole?.connect(`/offensive/api/offensive/scans/${encodeURIComponent(activeScanId)}/stream`);
			if (cancelButton && activeScanId && !terminalStatuses.has(String(started.status).toLowerCase())) {
				cancelButton.hidden = false;
				cancelButton.disabled = false;
			}
			if (started && started.phase) {
				setStatus(String(started.status || "pending").toLowerCase(), String(started.phase).toUpperCase(), "Scan queue accepted. Initializing analysis.");
			}
			const finalResult = terminalStatuses.has(String(started.status).toLowerCase())
				? started
				: await pollScan(started.scan_id);
			renderResult(finalResult);
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unexpected scan error.";
			setStatus("failed", "ASSESSMENT FAILED", message);
			showError(message);
		} finally {
			scanInProgress = false;
			activeScanId = null;
			if (cancelButton) cancelButton.hidden = true;
			updateButtonState();
		}
	});

	cancelButton?.addEventListener("click", async () => {
		if (!activeScanId) return;
		cancelButton.disabled = true;
		try {
			const response = await fetch(`/offensive/api/offensive/scans/${encodeURIComponent(activeScanId)}/cancel`, {
				method: "POST",
				headers: {
					Accept: "application/json",
					"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "",
				},
			});
			await readJson(response);
			setStatus("running", "CANCELLING", "Cancellation requested. Waiting for active Nmap process cleanup.");
		} catch (error) {
			cancelButton.disabled = false;
			showError(error instanceof Error ? error.message : "Unable to cancel the assessment.");
		}
	});

	targetInput.addEventListener("input", updateButtonState);
	authorizationCheck.addEventListener("change", updateButtonState);
	scanProfile.addEventListener("change", () => {
		updateProfileControls();
		syncProfileCards();
	});
	includeUdp.addEventListener("change", updateUdpImpact);
	updateProfileControls();
	updateButtonState();
	syncProfileCards();
})();
