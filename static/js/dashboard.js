"use strict";

/* =========================================================
    VULNSCAN V4.13
   Dashboard Controller
   Backend-connected scanner
========================================================= */


/* =========================================================
   ELEMENTS
========================================================= */

const networkInput =
    document.getElementById("networkInput");

const scanButton =
    document.getElementById("scanButton");

const cancelScanButton =
    document.getElementById("cancelScanButton");

const scanStatus =
    document.getElementById("scanStatus");

const statusTitle =
    document.getElementById("statusTitle");

const statusMessage =
    document.getElementById("statusMessage");

const progressContainer =
    document.getElementById("progressContainer");

const progressBar =
    document.getElementById("progressBar");

const progressTrack =
    progressBar?.parentElement;

const progressPercent =
    document.getElementById("progressPercent");

const progressStage =
    document.getElementById("progressStage");

const progressDetail =
    document.getElementById("progressDetail");

const scanTimer =
    document.getElementById("scanTimer");

const scanOverlay =
    document.getElementById("scanOverlay");

const overlayProgressBar =
    document.getElementById("overlayProgressBar");

const overlayPercent =
    document.getElementById("overlayPercent");

const overlayStage =
    document.getElementById("overlayStage");

const overlayNetwork =
    document.getElementById("overlayNetwork");

const deviceCount =
    document.getElementById("deviceCount");

const portCount =
    document.getElementById("portCount");

const serviceCount =
    document.getElementById("serviceCount");

const riskCount =
    document.getElementById("riskCount");

const findingCount =
    document.getElementById("findingCount");

const monitorStageElements =
    [...document.querySelectorAll("[data-monitor-stage]")];

const activityStageElements =
    [...document.querySelectorAll("[data-activity-stage]")];

const scanTimeline =
    document.getElementById("scanTimeline");

const diagnosticFields = {
    scanId: document.getElementById("diagnostic-scan-id"),
    engine: document.getElementById("diagnostic-engine"),
    version: document.getElementById("diagnostic-version"),
    target: document.getElementById("diagnostic-target"),
    start: document.getElementById("diagnostic-start"),
    elapsed: document.getElementById("diagnostic-elapsed"),
    phase: document.getElementById("diagnostic-phase"),
    status: document.getElementById("diagnostic-status"),
    profile: document.getElementById("diagnostic-profile"),
    privileges: document.getElementById("diagnostic-privileges"),
    interface: document.getElementById("diagnostic-interface"),
    exitStatus: document.getElementById("diagnostic-exit-status"),
    activity: document.getElementById("diagnostic-activity"),
    nmapProgress: document.getElementById("diagnostic-nmap-progress"),
    skipped: document.getElementById("diagnostic-skipped"),
    errors: document.getElementById("diagnostic-errors"),
    warnings: document.getElementById("diagnostic-warnings"),
};

const scanState =
    document.getElementById("scanState");

const deviceCountBadge =
    document.getElementById("deviceCountBadge");

const devicesContainer =
    document.getElementById("devicesContainer");

const risksContainer =
    document.getElementById("risksContainer");

const historyContainer =
    document.getElementById("historyContainer");

const clearHistoryButton =
    document.getElementById("clearHistory");


/* =========================================================
   STATE
========================================================= */

let scanRunning = false;

let scanStartTime = null;

let timerInterval = null;

let statusInterval = null;

let currentJobId = null;

let currentNetwork = "";

let statusPoller = null;

let timelineJobId = null;

const timelineEvents = [];

const timelineEventKeys = new Set();
let latestDefensiveScan = null;
let latestNmapCommandText = "";
let currentScanProfile = "thorough";
let remediationFindings = [];
let selectedRemediationFinding = null;
let selectedRemediationDevice = null;
let remediationScanId = "";
let remediationStep = 0;
let remediationCompletedStep = -1;
let remediationGuidedStarted = false;
let remediationOsDevice = "";
let pendingVerification = null;

function formatNmapCommand(argv) {
    return Array.isArray(argv)
        ? argv.map((part) => {
            const value = String(part);
            return /[\s"]/u.test(value) ? `"${value.replace(/"/gu, '\\"')}"` : value;
        }).join(" ")
        : "";
}

function renderNmapConsole(scan) {
    if (!scan) return;
    const commandOutput = document.getElementById("nmap-command-output");
    const copyButton = document.getElementById("nmap-copy-command");
    const terminalOutput = document.getElementById("nmap-terminal-events");
    const commands = Array.isArray(scan.nmap_commands) ? scan.nmap_commands : [];
    const events = (Array.isArray(scan.nmap_events) ? scan.nmap_events : [])
        .filter((event) => String(event.source || "").toLowerCase() === "vulnscan");
    if (commands.length && commandOutput) {
        const latestCommand = commands[commands.length - 1];
        latestNmapCommandText = formatNmapCommand(latestCommand.argv);
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
    const copyButton = document.getElementById("nmap-copy-command");
    const terminalOutput = document.getElementById("nmap-terminal-events");
    const eventsState = document.getElementById("nmap-events-state");
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

async function loadNmapEngineStatus() {
    const badge = document.querySelector(".nmap-engine-badge");
    const statusLabel = document.getElementById("nmap-engine-status");
    const versionLabel = document.getElementById("nmap-engine-version");
    if (!badge || !statusLabel || !versionLabel) return;
    try {
        const response = await fetch("/api/health", {headers: {Accept: "application/json"}});
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
        if (diagnosticFields.version) diagnosticFields.version.textContent = ready ? (health.nmap_version || "Unavailable") : "Unavailable";
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

document.querySelectorAll("[data-results-view]").forEach((button) => {
    button.addEventListener("click", () => {
        const view = button.dataset.resultsView === "nmap" ? "nmap" : "vulnscan";
        document.body.dataset.resultsView = view;
        document.querySelectorAll("[data-results-view]").forEach((item) => {
            item.setAttribute("aria-pressed", String(item === button));
        });
    });
});

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

function showNmapEvidence(title, fields) {
    const dialog = document.getElementById("nmap-evidence-drawer");
    const content = document.getElementById("nmap-evidence-content");
    const heading = document.getElementById("nmap-evidence-title");
    if (!dialog || !content || !heading) return;
    heading.textContent = title;
    content.replaceChildren();
    for (const [label, value] of fields) {
        const wrapper = document.createElement("div");
        if (Array.isArray(value) || (typeof value === "string" && value.includes("\n"))) {
            wrapper.className = "details-wide";
        }
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

document.getElementById("nmap-evidence-close")?.addEventListener("click", () => {
    document.getElementById("nmap-evidence-drawer")?.close();
});

document.getElementById("nmap-evidence-drawer")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) event.currentTarget.close();
});

document.getElementById("devicesContainer")?.addEventListener("click", (event) => {
    const deviceButton = event.target.closest("[data-remediation-device]");
    if (deviceButton && latestDefensiveScan) {
        const device = latestDefensiveScan.devices?.[Number(deviceButton.dataset.remediationDevice)];
        if (device) {
            const deviceFindings = collectRisks([device]);
            renderRemediationPanel(latestDefensiveScan, deviceFindings, device);
            document.getElementById("defensive-remediation")?.scrollIntoView({behavior: "smooth", block: "start"});
        }
        return;
    }
    const button = event.target.closest("[data-evidence-host]");
    if (!button || !latestDefensiveScan) return;
    const hostIndex = Number(button.dataset.evidenceHost);
    const device = latestDefensiveScan.devices?.[hostIndex];
    if (!device) return;
    const portIndex = button.dataset.evidencePort;
    if (portIndex !== undefined) {
        const port = device.ports?.[Number(portIndex)];
        if (!port) return;
        showNmapEvidence(`${device.ip || "Host"} · ${port.protocol || "tcp"}/${port.port ?? "?"}`, [
            ["Host", device.ip],
            ["Port / protocol", `${port.port ?? "?"}/${port.protocol || "tcp"}`],
            ["State", port.state],
            ["Reason", port.reason],
            ["Service", port.service],
            ["Product", port.product],
            ["Version", port.version],
            ["Extra information", port.extrainfo],
            ["CPE identifiers", port.cpes],
            ["NSE scripts", port.scripts],
            ["Risk evidence", port.risk],
            ["Evidence", port.evidence],
        ]);
        return;
    }
    const osMatch = device.os_matches?.[0];
    const osClass = osMatch?.classes?.[0];
    showNmapEvidence(`Host evidence · ${device.ip || "Unknown"}`, [
        ["Hostname", device.hostname],
        ["Host state", device.status],
        ["State reason", device.status_reason],
        ["MAC address", device.mac],
        ["Vendor", device.vendor],
        ["OS fingerprint", device.os],
        ["OS match confidence", device.os_accuracy ? `${device.os_accuracy}%` : null],
        ["Device type", osClass?.type],
        ["Network distance", device.distance],
        ["Open ports", (device.ports || []).filter((port) => port.state === "open").map((port) => `${port.protocol || "tcp"}/${port.port}`)],
        ["Port states and reasons", (device.ports || []).map((port) => `${port.protocol || "tcp"}/${port.port}: ${port.state || "unknown"}${port.reason ? ` (${port.reason})` : ""}`)],
        ["Host scripts", device.host_scripts],
        ["Traceroute", device.traceroute],
        ["Latency", null],
        ["Findings", device.risks],
    ]);
});

loadNmapEngineStatus();


/* =========================================================
   SCAN STEPS
========================================================= */

const steps = {

    discovery:
        document.getElementById("stepDiscovery"),

    ports:
        document.getElementById("stepPorts"),

    risk:
        document.getElementById("stepRisk"),

    report:
        document.getElementById("stepReport")

};


/* =========================================================
   NETWORK VALIDATION
========================================================= */

function isValidNetwork(value) {

    value = value.trim();

    if (!value) {
        return false;
    }

    const cidrPattern =
        /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;

    return cidrPattern.test(value);
}


/* =========================================================
   TIMER
========================================================= */

function startTimer() {

    scanStartTime = Date.now();

    if (timerInterval) {
        clearInterval(timerInterval);
    }

    timerInterval =
        setInterval(() => {

            const elapsed =
                Math.floor(
                    (Date.now() - scanStartTime) / 1000
                );

            const minutes =
                String(
                    Math.floor(elapsed / 60)
                ).padStart(2, "0");

            const seconds =
                String(
                    elapsed % 60
                ).padStart(2, "0");

            if (scanTimer) {

                scanTimer.textContent =
                    `${minutes}:${seconds}`;

            }

        }, 250);
}


function stopTimer() {

    if (timerInterval) {

        clearInterval(
            timerInterval
        );

        timerInterval = null;
    }
}


/* =========================================================
   PROGRESS
========================================================= */

function setProgress(
    percent,
    stage,
    detail
) {

    percent =
        Math.max(
            0,
            Math.min(
                100,
                Number(percent) || 0
            )
        );

    if (progressBar) {

        progressBar.style.width =
            `${percent}%`;

    }
    progressTrack?.setAttribute("aria-valuenow", String(Math.round(percent)));

    if (progressPercent) {

        progressPercent.textContent =
            `${Math.round(percent)}%`;

    }

    if (progressStage) {

        progressStage.textContent =
            stage || "Scanning";

    }

    if (progressDetail) {

        progressDetail.textContent =
            detail || "";

    }

    if (overlayProgressBar) {

        overlayProgressBar.style.width =
            `${percent}%`;

    }

    if (overlayPercent) {

        overlayPercent.textContent =
            `${Math.round(percent)}%`;

    }

    if (overlayStage) {

        overlayStage.textContent =
            stage || "Scanning";

    }
}


/* =========================================================
   STEP MANAGEMENT
========================================================= */

function activateStep(step) {

    if (!step) {
        return;
    }

    Object.values(steps).forEach(
        element => {

            if (element) {

                element.classList.remove(
                    "active"
                );

            }

        }
    );

    step.classList.add(
        "active"
    );
}


function completeStep(step) {

    if (!step) {
        return;
    }

    step.classList.remove(
        "active"
    );

    step.classList.add(
        "completed"
    );
}


function resetSteps() {

    Object.values(steps).forEach(
        element => {

            if (element) {

                element.classList.remove(
                    "active",
                    "completed"
                );

            }

        }
    );

    if (steps.discovery) {

        steps.discovery.classList.add(
            "active"
        );

    }
}


/* =========================================================
   SHOW SCANNING UI
========================================================= */

function showScanningUI(
    network
) {

    scanRunning = true;

    if (scanButton) {

        scanButton.disabled = true;

        scanButton.innerHTML =
            `<span class="button-icon">◌</span>
             <span>Scanning...</span>`;

    }

    if (cancelScanButton) {
        cancelScanButton.hidden = false;
        cancelScanButton.disabled = false;
    }

    if (progressContainer) {

        progressContainer.classList.remove(
            "hidden"
        );

    }

    const indicator =
        scanStatus
            ? scanStatus.querySelector(
                ".status-indicator"
            )
            : null;

    if (indicator) {

        indicator.classList.remove(
            "ready"
        );

        indicator.classList.add(
            "scanning"
        );

    }

    if (statusTitle) {

        statusTitle.textContent =
            "Network scan in progress";

    }

    if (statusMessage) {

        statusMessage.textContent =
            "Analyzing the authorized network. Please wait.";

    }

    if (scanState) {

        scanState.textContent =
            "Scanning";

    }

    if (scanOverlay) {

        scanOverlay.classList.remove(
            "hidden"
        );

    }

    if (overlayNetwork) {

        overlayNetwork.textContent =
            `Analyzing ${network}`;

    }

    resetSteps();

    setProgress(
        0,
        "Starting scanner",
        "Connecting to the network scanner"
    );

    startTimer();
}


/* =========================================================
   UPDATE UI FROM REAL BACKEND STATUS
========================================================= */

function getStageState(stage) {
    const status = String(stage?.status || "pending").toLowerCase();
    if (["running"].includes(status)) return "running";
    if (["completed", "complete"].includes(status)) return "completed";
    if (["failed", "error"].includes(status)) return "failed";
    if (["partial", "warning", "skipped"].includes(status)) return "warning";
    return "waiting";
}

function combineStageStates(states) {
    if (states.includes("failed")) return "failed";
    if (states.includes("running")) return "running";
    if (states.includes("warning")) return "warning";
    if (states.every((state) => state === "completed")) return "completed";
    if (states.some((state) => state === "completed")) return "warning";
    return "waiting";
}

const monitorStateLabels = {
    waiting: "○ Waiting",
    running: "◉ Running",
    completed: "✓ Completed",
    warning: "⚠ Warning",
    failed: "✕ Failed",
};

function addTimelineEvent(key, label, timestamp = Date.now()) {
    if (!scanTimeline || timelineEventKeys.has(key)) return;
    timelineEventKeys.add(key);
    timelineEvents.push({label, timestamp});

    const emptyState = scanTimeline.querySelector(".timeline-empty");
    if (emptyState) emptyState.remove();

    const item = document.createElement("li");
    const time = document.createElement("time");
    const date = new Date(timestamp);
    time.dateTime = date.toISOString();
    time.textContent = date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
    });
    const description = document.createElement("span");
    description.textContent = label;
    item.append(time, description);
    scanTimeline.append(item);
}

function updateScanMonitor(scan) {
    const stages = scan.stages && typeof scan.stages === "object" ? scan.stages : {};
    const portState = getStageState(stages.port_enumeration);
    const serviceState = combineStageStates([
        getStageState(stages.service_detection),
        getStageState(stages.version_detection),
    ]);
    const riskState = getStageState(stages.risk_analysis);
    const scanStatusValue = String(scan.status || "running").toLowerCase();
    let reportState = "waiting";

    if (["failed", "error"].includes(scanStatusValue)) {
        reportState = "failed";
    } else if (scan.finished) {
        reportState = ["partial", "cancelled", "canceled", "incomplete"].includes(scanStatusValue)
            ? "warning"
            : "completed";
    } else if (riskState === "completed") {
        reportState = "running";
    }

    const stageStates = {
        target: scan.target ? "completed" : "waiting",
        discovery: getStageState(stages.discovery),
        ports: portState,
        services: serviceState,
        version: stages.version_detection ? getStageState(stages.version_detection) : "unavailable",
        os: stages.os_detection ? getStageState(stages.os_detection) : "unavailable",
        nse: stages.nse_scripts ? getStageState(stages.nse_scripts) : "unavailable",
        risk: riskState,
        report: reportState,
    };

    for (const element of monitorStageElements) {
        const state = stageStates[element.dataset.monitorStage] || "waiting";
        element.classList.remove("is-waiting", "is-running", "is-completed", "is-warning", "is-failed", "is-unavailable");
        element.classList.add(`is-${state}`);
        const stateText = element.querySelector("[data-stage-status]");
        if (stateText) stateText.textContent = monitorStateLabels[state] || "Not reported";
        const marker = element.querySelector(".stage-marker");
        if (marker) marker.textContent = (monitorStateLabels[state] || "—").slice(0, 1);
    }

    for (const element of activityStageElements) {
        const stage = element.dataset.activityStage;
        const state = stageStates[stage] || "waiting";
        element.classList.remove("is-waiting", "is-running", "is-completed", "is-warning", "is-failed", "is-unavailable");
        element.classList.add(`is-${state}`);
        const stateText = element.querySelector("[data-activity-status]");
        if (stateText) stateText.textContent = monitorStateLabels[state] || "Not reported";
        const label = element.querySelector("[data-activity-label]");
        if (label && stage === "services") {
            label.textContent = state === "running" ? "Checking exposed services..." : "Exposed service analysis";
        }
    }

    let statusLabel = "RUNNING";
    let indicatorState = "scanning";
    if (["starting", "pending", "queued"].includes(scanStatusValue)) statusLabel = "STARTING";
    if (["completed"].includes(scanStatusValue)) {
        statusLabel = "COMPLETED";
        indicatorState = "ready";
    } else if (["partial", "cancelled", "canceled", "incomplete"].includes(scanStatusValue)) {
        statusLabel = "WARNING";
        indicatorState = "warning";
    } else if (["failed", "error"].includes(scanStatusValue)) {
        statusLabel = "FAILED";
        indicatorState = "failed";
    }
    if (diagnosticFields.status) diagnosticFields.status.textContent = statusLabel;
    if (diagnosticFields.profile) {
        const options = scan.admin_nmap_options;
        diagnosticFields.profile.textContent = options?.assessment_profile || scan.profile || "Not reported";
    }
    if (diagnosticFields.exitStatus) {
        diagnosticFields.exitStatus.textContent = scan.nmap_exit_status ?? "Not reported";
    }
    if (diagnosticFields.interface) {
        diagnosticFields.interface.textContent = scan.interface || "Unavailable";
    }
    if (diagnosticFields.skipped) {
        const options = scan.admin_nmap_options;
        const skipped = [];
        if (options) {
            if (!options.os_detection) skipped.push("OS fingerprinting was not enabled");
            if (!options.traceroute) skipped.push("Traceroute was not enabled");
            if (!options.packet_trace) skipped.push("Packet tracing was not enabled");
            if (!options.include_udp) skipped.push("Supplementary UDP scanning was not enabled");
            if (!Array.isArray(options.nse_modules) || options.nse_modules.length === 0) {
                skipped.push("NSE modules were not enabled");
            }
            const explicitlySkipped = Object.entries(scan.stages || {})
                .filter(([, stage]) => String(stage?.status || "").toLowerCase() === "skipped")
                .map(([name]) => name.replaceAll("_", " "));
            skipped.push(...explicitlySkipped);
        }
        diagnosticFields.skipped.textContent = skipped.length ? [...new Set(skipped)].join("; ") : "None reported";
    }

    if (statusTitle) {
        if (["completed"].includes(scanStatusValue)) {
            statusTitle.textContent = "Defensive assessment completed";
        } else if (["partial", "cancelled", "canceled", "incomplete"].includes(scanStatusValue)) {
            statusTitle.textContent = "Assessment ended with warnings";
        } else if (["failed", "error"].includes(scanStatusValue)) {
            statusTitle.textContent = "Defensive assessment failed";
        } else {
            statusTitle.textContent = scan.phase || "Defensive assessment is running";
        }
    }

    if (statusMessage) {
        if (scan.error) {
            statusMessage.textContent = scan.error;
        } else if (scan.finished && Array.isArray(scan.limitations) && scan.limitations.length) {
            statusMessage.textContent = scan.limitations.join(" ");
        } else if (scan.finished) {
            statusMessage.textContent = `Target: ${scan.target || currentNetwork || "unknown"}.`;
        } else {
            statusMessage.textContent = scan.last_activity || "Defensive assessment is in progress.";
        }
    }

    const indicator = scanStatus ? scanStatus.querySelector(".status-indicator") : null;
    if (indicator) {
        indicator.classList.remove("ready", "scanning", "warning", "failed");
        indicator.classList.add(indicatorState);
    }

    const jobId = scan.job_id || currentJobId;
    const xmlDownload = document.getElementById("admin-nmap-xml-download");
    if (xmlDownload && jobId && scan.nmap_xml_available === true) {
        xmlDownload.href = `/api/scan/output/${encodeURIComponent(jobId)}/nmap.xml`;
        xmlDownload.hidden = false;
    }
    if (jobId && timelineJobId !== jobId) {
        timelineJobId = jobId;
        timelineEvents.length = 0;
        timelineEventKeys.clear();
        if (scanTimeline) scanTimeline.replaceChildren();
        const startedAt = Number(scan.started_at) * 1000;
        const initializedAt = Number.isFinite(startedAt) ? startedAt : Date.now();
        addTimelineEvent("initialized", "Scan initialized", initializedAt);
        if (scan.target) addTimelineEvent("target-validated", "Target validated", initializedAt);
    }

    if (stageStates.discovery === "running") addTimelineEvent("discovery-started", "Discovery started");
    if (stageStates.discovery === "completed") {
        const hosts = Number(stages.discovery?.hosts ?? scan.device_count) || 0;
        addTimelineEvent("discovery-completed", `${hosts} host${hosts === 1 ? "" : "s"} discovered`);
    }
    if (stageStates.ports === "running") addTimelineEvent("ports-started", "Port analysis started");
    if (stageStates.ports === "completed") addTimelineEvent("ports-completed", "Port analysis completed");
    if (stageStates.services === "running") addTimelineEvent("services-started", "Service analysis started");
    if (stageStates.services === "completed") {
        const services = Number(stages.service_detection?.services) || 0;
        addTimelineEvent("services-completed", `Service analysis completed: ${services} identified`);
    }
    if (stageStates.risk === "running") addTimelineEvent("risk-started", "Risk analysis started");
    if (stageStates.risk === "completed") {
        const findings = Number(stages.risk_analysis?.findings ?? scan.risks) || 0;
        addTimelineEvent("risk-completed", `Risk analysis completed: ${findings} finding${findings === 1 ? "" : "s"}`);
    }
    if (stageStates.report === "running") addTimelineEvent("report-started", "Report generation started");
    if (stageStates.report === "completed") addTimelineEvent("report-completed", "Report generated");
    if (stageStates.report === "warning") addTimelineEvent("report-warning", "Report generated with warnings");
    if (stageStates.report === "failed") addTimelineEvent("report-failed", "Scan failed before report generation");
}

function updateScanUI(
    scan
) {

    if (!scan) {
        return;
    }
    latestDefensiveScan = scan;
    renderNmapConsole(scan);

    const progress =
        Number(scan.progress) || 0;

    const phase =
        scan.phase ||
        "Scanning network";

    const startedAt = Number(scan.started_at);
    const elapsed = Number(scan.elapsed) || 0;
    if (diagnosticFields.scanId) diagnosticFields.scanId.textContent = scan.job_id || currentJobId || "Not available";
    if (diagnosticFields.target) diagnosticFields.target.textContent = scan.target || currentNetwork || "—";
    if (diagnosticFields.start) diagnosticFields.start.textContent = Number.isFinite(startedAt) ? new Date(startedAt * 1000).toLocaleString() : "Not available";
    if (diagnosticFields.elapsed) diagnosticFields.elapsed.textContent = `${String(Math.floor(elapsed / 60)).padStart(2, "0")}:${String(Math.floor(elapsed % 60)).padStart(2, "0")}`;
    if (diagnosticFields.profile) {
        diagnosticFields.profile.textContent = scan.admin_nmap_options?.assessment_profile || scan.profile || "Not reported";
    }
    if (diagnosticFields.phase) diagnosticFields.phase.textContent = phase;
    if (diagnosticFields.activity) diagnosticFields.activity.textContent = scan.last_activity ? `${scan.last_activity} (${scan.last_activity_age ?? 0}s ago)` : "None reported";
    if (diagnosticFields.nmapProgress) {
        const nmapProgress = scan.nmap_progress;
        diagnosticFields.nmapProgress.textContent = nmapProgress
            ? `${nmapProgress.target}: ${nmapProgress.phase} - ${Number(nmapProgress.percent).toFixed(1)}% of phase${nmapProgress.remaining ? `; ${nmapProgress.remaining} remaining` : ""}`
            : "No Nmap timing update yet";
    }
    if (diagnosticFields.errors) diagnosticFields.errors.textContent = scan.error || "None";
    if (diagnosticFields.warnings) diagnosticFields.warnings.textContent = Array.isArray(scan.limitations) && scan.limitations.length ? scan.limitations.join(" ") : "None";
    updateScanMonitor(scan);

    let detail =
        "Working...";


    /* -----------------------------------------------------
       Discovery
    ----------------------------------------------------- */

    if (
        phase.toLowerCase()
            .includes("discover")
    ) {

        activateStep(
            steps.discovery
        );

        detail =
            `${scan.device_count || 0} device(s) discovered`;

    }


    /* -----------------------------------------------------
       Ports
    ----------------------------------------------------- */

    else if (
        phase.toLowerCase()
            .includes("port")
    ) {

        completeStep(
            steps.discovery
        );

        activateStep(
            steps.ports
        );

        detail =
            `${scan.device_count || 0} devices • ` +
            `${scan.open_ports || 0} open ports`;

    }


    /* -----------------------------------------------------
       Security
    ----------------------------------------------------- */

    else if (
        phase.toLowerCase()
            .includes("security")
        ||
        phase.toLowerCase()
            .includes("risk")
    ) {

        completeStep(
            steps.discovery
        );

        completeStep(
            steps.ports
        );

        activateStep(
            steps.risk
        );

        detail =
            `${scan.risks || 0} security finding(s)`;

    }


    /* -----------------------------------------------------
       Report
    ----------------------------------------------------- */

    else if (
        phase.toLowerCase()
            .includes("report")
        ||
        progress >= 93
    ) {

        completeStep(
            steps.discovery
        );

        completeStep(
            steps.ports
        );

        completeStep(
            steps.risk
        );

        activateStep(
            steps.report
        );

        detail =
            "Preparing final security report";

    }


    /* -----------------------------------------------------
       Current IP
    ----------------------------------------------------- */

    if (Array.isArray(scan.current_hosts) && scan.current_hosts.length) {

        const visibleHosts = scan.current_hosts.slice(0, 3).join(", ");
        const remainingHosts = scan.current_hosts.length - 3;
        detail +=
            ` • Active hosts: ${visibleHosts}${remainingHosts > 0 ? ` +${remainingHosts}` : ""}`;

    } else if (scan.current_ip) {

        detail +=
            ` • Last host: ${scan.current_ip}`;

    }


    setProgress(
        progress,
        phase,
        detail
    );


    /* -----------------------------------------------------
       Live statistics
    ----------------------------------------------------- */

    if (deviceCount) {

        deviceCount.textContent =
            scan.device_count || 0;

    }

    if (deviceCountBadge) {

        deviceCountBadge.textContent =
            scan.device_count || 0;

    }

    if (portCount) {

        portCount.textContent =
            scan.open_ports || 0;

    }

    if (serviceCount) {
        serviceCount.textContent =
            Number(scan.stages?.service_detection?.services) || 0;
    }

    if (riskCount) {

        riskCount.textContent =
            scan.risks || 0;

    }

    if (findingCount) {
        findingCount.textContent = scan.risks || 0;
    }

    /* -----------------------------------------------------
       Live devices
    ----------------------------------------------------- */

    if (Array.isArray(scan.devices)) {

        displayDevices(
            scan.devices
        );

        const risks =
            collectRisks(
                scan.devices
            );

        displayRisks(
            risks
        );

    }

    if (scan.job_id && scan.finished && window.WifiSentinelAI) {
        window.WifiSentinelAI.setContext({scanId: scan.job_id, module: "defensive"});
    }

}


/* =========================================================
   START REAL BACKEND SCAN
========================================================= */

function buildAdminNmapOptions() {
    const enabled = document.getElementById("admin-nmap-enabled");
    if (!enabled || !enabled.checked) return null;

    const value = (id) => document.getElementById(id)?.value || "";
    const checked = (id) => Boolean(document.getElementById(id)?.checked);
    const scanType = value("admin-scan-type");
    const portPreset = value("admin-nmap-port-preset");
    return {
        assessment_profile: value("admin-nmap-profile") || "custom",
        advanced_authorized: checked("admin-nmap-advanced-authorized"),
        scan_type: scanType,
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
document.getElementById("admin-nmap-port-preset")?.addEventListener("change", updateAdminPortControls);
document.getElementById("admin-scan-type")?.addEventListener("change", updateAdminProfileControls);
document.getElementById("admin-nmap-profile")?.addEventListener("change", updateAdminProfileControls);
const adminNmapEnabled = document.getElementById("admin-nmap-enabled");
const adminNmapFields = document.getElementById("admin-nmap-fields");
function updateAdminNmapControls() {
    if (adminNmapFields && adminNmapEnabled) {
        adminNmapFields.disabled = !adminNmapEnabled.checked;
    }
}
adminNmapEnabled?.addEventListener("change", updateAdminNmapControls);
updateAdminNmapControls();
updateAdminProfileControls();

async function startScan(verification = null) {
    if (scanRunning) return;
    const network = verification?.device?.ip || (networkInput ? networkInput.value.trim() : "");
    if (!network) {
        handleScanError(new Error("Enter an authorized network range before starting the scan."));
        return;
    }
    const settings = verification
        ? {profile: verification.profile || currentScanProfile}
        : await openScanSettingsModal();
    if (!settings) return;
    currentScanProfile = settings.profile || "thorough";
    pendingVerification = verification && verification.finding ? {...verification, jobId: null} : null;
    resetNmapConsole();
    if (!verification) latestDefensiveScan = null;
    scanRunning = true;
    currentNetwork = network;
    showScanningUI(network);
    if (statusTitle) statusTitle.textContent = "Preparing scan";
    if (statusMessage) statusMessage.textContent = verification
        ? `Verification scan · one device · ${formatScanProfile(settings.profile)} profile`
        : `${formatScanProfile(settings.profile)} profile`;
    if (scanState) scanState.textContent = "Starting";
    try {
        const response = await fetch("/api/scan/start", {
            method:"POST",
            headers:{
                "Content-Type":"application/json",
                "Accept":"application/json",
                "X-CSRF-Token":document.querySelector('meta[name="csrf-token"]')?.content || "",
            },
            body:JSON.stringify({
                target:network,
                profile:settings.profile,
                admin_nmap_options:verification ? null : buildAdminNmapOptions(),
            })
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || data.message || "Unable to start the network scan.");
        }
        currentJobId = data.job_id;
        if (pendingVerification) pendingVerification.jobId = currentJobId;
        window.VulnScanNmapConsole?.connect(`/api/scan/stream/${encodeURIComponent(currentJobId)}`);
        if (window.WifiSentinelAI) {
            window.WifiSentinelAI.setContext({scanId: "", module: "defensive"});
        }
        if (overlayNetwork) overlayNetwork.textContent = `${network} • ${formatScanProfile(settings.profile)}`;
        if (overlayStage) overlayStage.textContent = `${formatScanProfile(settings.profile)} assessment started`;
        if (scanButton) {
            scanButton.disabled = true;
            scanButton.innerHTML = `<span class="button-icon">⌁</span><span>Scanning...</span>`;
        }
        startTimer();
        await pollScanStatus();
    } catch (error) {
        handleScanError(error);
    }
}


/* =========================================================
   SCAN SETTINGS MODAL
========================================================= */
function openScanSettingsModal() {
    const modal = document.getElementById("scanSettingsModal");
    const profileInput = document.getElementById("scanProfile");
    const startButton = document.getElementById("scanSettingsStart");
    const closeButton = document.getElementById("scanSettingsClose");
    const cancelButton = document.getElementById("scanSettingsCancel");
    const backdrop = modal ? modal.querySelector(".scan-settings-backdrop") : null;
    if (!modal || !startButton) return Promise.resolve({profile:"thorough"});
    return new Promise(resolve => {
        let settled=false;
        const cleanup=()=>{modal.classList.add("hidden");modal.setAttribute("aria-hidden","true");startButton.removeEventListener("click",confirm);closeButton?.removeEventListener("click",cancel);cancelButton?.removeEventListener("click",cancel);backdrop?.removeEventListener("click",cancel);document.removeEventListener("keydown",keyHandler);};
        const finish=value=>{if(settled)return;settled=true;cleanup();resolve(value);};
        const cancel=()=>finish(null);
        const confirm=()=>{finish({profile:profileInput?.value||"thorough"});};
        const keyHandler=e=>{if(e.key==="Escape"){e.preventDefault();cancel();}else if(e.key==="Enter"){e.preventDefault();confirm();}};
        modal.classList.remove("hidden");modal.setAttribute("aria-hidden","false");
        startButton.addEventListener("click",confirm);closeButton?.addEventListener("click",cancel);cancelButton?.addEventListener("click",cancel);backdrop?.addEventListener("click",cancel);document.addEventListener("keydown",keyHandler);
        profileInput?.focus();
    });
}
function formatScanProfile(profile){return {standard:"Standard",thorough:"Thorough",deep:"Deep"}[profile]||"Thorough";}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[character]));
}

function collectRisks(devices) {
    if (!Array.isArray(devices)) {
        return [];
    }

    const collected = [];
    devices.forEach((device) => {
        if (!device || !Array.isArray(device.risks)) {
            return;
        }

        device.risks.forEach((risk) => {
            if (!risk || !risk.title) {
                return;
            }
            const port = (device.ports || []).find((item) =>
                String(item?.port) === String(risk.port)
                && String(item?.protocol || "tcp").toLowerCase() === "tcp"
            ) || null;
            const scripts = [
                ...(port?.scripts || []),
                ...(device.host_scripts || []),
            ].filter((item) => item && typeof item === "object");
            const positiveScript = scripts.find((script) =>
                /(?:^|\n)\s*(?:\|\s*)?State:\s*VULNERABLE\s*(?:\n|$)/i.test(String(script.output || ""))
            );
            const evidence = Array.isArray(port?.evidence) ? port.evidence.filter((item) => typeof item === "string" && item.trim()) : [];
            if (port?.state) {
                const observation = `Nmap observed ${String(port.protocol || "tcp").toUpperCase()}/${port.port} ${String(port.state).toUpperCase()}`;
                evidence.push(port.reason ? `${observation} (${port.reason}).` : `${observation}.`);
            }
            for (const script of scripts) {
                if (script.id && script.output) evidence.push(`Nmap NSE ${script.id}: ${script.output}`);
            }
            const title = String(risk.title);
            collected.push({
                id: `def:${device.ip || "Unknown"}:${risk.port || ""}:${title}`,
                ip: device.ip || "Unknown",
                hostname: device.hostname || "Unknown",
                title,
                severity: risk.severity || "medium",
                port: risk.port || null,
                protocol: port?.protocol || "tcp",
                service: port?.service || "",
                product: port?.product || "",
                version: port?.version || "",
                confidence: port?.service_confidence
                    ? `Nmap service match ${port.service_confidence}/10`
                    : "Not scored by the Defensive risk engine",
                vulnerabilityStatus: positiveScript ? "CONFIRMED" : "UNKNOWN",
                description: risk.description || "",
                protection: risk.protection || "",
                evidence: evidence.length ? [...new Set(evidence)] : ["The saved Defensive report does not contain detailed port evidence for this finding."],
                device,
            });
        });
    });

    const severityRank = {critical: 4, high: 3, medium: 2, low: 1, informational: 0};
    return collected.sort((left, right) =>
        (right.vulnerabilityStatus === "CONFIRMED") - (left.vulnerabilityStatus === "CONFIRMED")
        || (severityRank[String(right.severity).toLowerCase()] || 0) - (severityRank[String(left.severity).toLowerCase()] || 0)
        || String(left.ip).localeCompare(String(right.ip))
        || Number(left.port || 0) - Number(right.port || 0)
    );
}

function detectedOsFamily(device) {
    const accuracy = Number(device?.os_accuracy) || 0;
    const detected = String(device?.os || "").trim();
    if (!detected || /^unknown$/i.test(detected) || accuracy < 90) return "";
    if (/windows/i.test(detected)) return "windows";
    if (/linux|ubuntu|debian|red hat|fedora|centos|arch/i.test(detected)) return "linux";
    if (/mac ?os|macos|darwin/i.test(detected)) return "macos";
    return "";
}

function remediationContext(finding = selectedRemediationFinding) {
    return {
        scanId: remediationScanId,
        module: "defensive",
        hostId: finding?.ip || selectedRemediationDevice?.ip || "",
        findingId: finding?.id || "",
        deviceOS: document.getElementById("remediation-os")?.value || "",
    };
}

async function saveRemediationStatus(status) {
    if (!remediationScanId || !selectedRemediationFinding?.id) return false;
    try {
        const response = await fetch("/api/ai/remediation", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
                "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "",
            },
            body: JSON.stringify({
                module: "defensive",
                scan_id: remediationScanId,
                finding_id: selectedRemediationFinding.id,
                status,
            }),
        });
        const result = await response.json();
        return response.ok && result.success === true;
    } catch {
        return false;
    }
}

function setRemediationStatus(status, label = status.replaceAll("_", " ")) {
    const state = document.getElementById("remediation-state");
    if (state) {
        state.textContent = label.toUpperCase();
        state.dataset.state = status.toLowerCase();
    }
}

function renderGuidedSteps() {
    const list = document.getElementById("remediation-step-list");
    if (!list) return;
    const steps = [
        ["Understand the issue", "Review what the scan observed and what remains unknown."],
        ["Check current configuration", "Confirm the service is intended and inspect its access controls."],
        ["Apply the recommended fix", "Make the approved change yourself; VulnScan does not execute it."],
        ["Verify the change", "Run a fresh scan against this device only."],
        ["Compare before and after", "Use Nmap states to decide whether the exposure changed."],
    ];
    list.innerHTML = steps.map(([title, detail], index) => {
        const state = index <= remediationCompletedStep ? "completed" : index === remediationStep ? "current" : "pending";
        const marker = state === "completed" ? "✓" : state === "current" ? "●" : "○";
        return `<li class="is-${state}"><span class="remediation-step-marker" aria-hidden="true">${marker}</span><span class="remediation-step-copy"><strong>STEP ${index + 1} · ${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></span><span class="remediation-step-state">${state}</span></li>`;
    }).join("");
    const started = remediationGuidedStarted;
    const startButton = document.getElementById("remediation-start-guided");
    const completeButton = document.getElementById("remediation-complete-step");
    const verifyButton = document.getElementById("remediation-verify-fix");
    if (startButton) startButton.hidden = started;
    if (completeButton) {
        completeButton.hidden = !started || remediationStep < 1 || remediationStep > 2;
        completeButton.textContent = remediationStep === 1 ? "I checked the configuration" : "I applied the recommended fix";
    }
    if (verifyButton) verifyButton.hidden = !started || remediationStep < 3;
}

function renderRemediationFinding(finding) {
    const priorFindingId = selectedRemediationFinding?.id || "";
    if (priorFindingId && priorFindingId !== finding?.id) {
        remediationStep = 0;
        remediationCompletedStep = -1;
        remediationGuidedStarted = false;
    }
    selectedRemediationFinding = finding;
    selectedRemediationDevice = finding?.device || null;
    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value || "Not reported";
    };
    setText("remediation-finding-title", finding?.title || "Select a finding");
    setText("remediation-device", finding ? `${finding.hostname} · ${finding.ip}` : "—");
    setText("remediation-service", finding ? `${finding.service || "Unknown service"} · ${finding.protocol}/${finding.port ?? "?"}` : "—");
    setText("remediation-version", finding?.product ? `${finding.product}${finding.version ? ` ${finding.version}` : ""}` : finding?.version || "Not identified");
    setText("remediation-confidence", finding?.confidence || "Not scored");
    setText("remediation-evidence", finding?.evidence?.join("\n") || "No detailed scanner evidence was saved.");
    setText("remediation-vulnerability-status", finding?.vulnerabilityStatus === "CONFIRMED"
        ? "CONFIRMED · Nmap NSE reported a positive vulnerable state"
        : "UNKNOWN · exposure observed; no specific vulnerability confirmed");
    setText("remediation-recommendation", finding?.protection || "Review whether this service is required and restrict access to approved devices.");
    const badge = document.getElementById("remediation-finding-severity");
    if (badge) {
        badge.textContent = String(finding?.severity || "FINDING").toUpperCase();
        badge.className = `risk-badge ${String(finding?.severity || "").toLowerCase()}`;
    }
    const osChoice = document.getElementById("remediation-os-choice");
    const osInput = document.getElementById("remediation-os");
    const detectedFamily = detectedOsFamily(selectedRemediationDevice);
    if (remediationOsDevice !== String(selectedRemediationDevice?.ip || "")) {
        remediationOsDevice = String(selectedRemediationDevice?.ip || "");
        if (osInput) osInput.value = "";
    }
    if (osChoice) osChoice.hidden = Boolean(detectedFamily);
    if (osInput && detectedFamily) osInput.value = "";

    const priorityList = document.getElementById("remediation-priority-list");
    if (priorityList) {
        priorityList.querySelectorAll("button[data-remediation-finding]").forEach((button) => {
            button.setAttribute("aria-current", String(button.dataset.remediationFinding === finding?.id));
        });
    }
    renderGuidedSteps();
}

function renderRemediationPanel(scan, findings = collectRisks(scan?.devices || []), deviceFilter = null) {
    const panel = document.getElementById("defensive-remediation");
    if (!panel) return;
    panel.hidden = false;
    const nextScanId = scan?.job_id || scan?.id || "";
    if (remediationScanId && nextScanId !== remediationScanId) {
        selectedRemediationFinding = null;
        selectedRemediationDevice = null;
        remediationStep = 0;
        remediationCompletedStep = -1;
        remediationGuidedStarted = false;
    }
    remediationFindings = findings;
    remediationScanId = nextScanId;
    selectedRemediationDevice = deviceFilter || selectedRemediationDevice;
    const target = document.getElementById("remediation-target");
    const count = document.getElementById("remediation-finding-count");
    const criticalHigh = document.getElementById("remediation-critical-high");
    const risk = document.getElementById("remediation-risk");
    if (target) target.textContent = deviceFilter?.ip || scan?.target || "Unknown target";
    if (count) count.textContent = String(findings.length);
    const criticalCount = findings.filter((item) => String(item.severity).toLowerCase() === "critical").length;
    const highCount = findings.filter((item) => String(item.severity).toLowerCase() === "high").length;
    if (criticalHigh) criticalHigh.textContent = `${criticalCount} / ${highCount}`;
    if (risk) risk.textContent = findings[0]?.severity?.toUpperCase() || "LOW";

    const noFindings = document.getElementById("remediation-no-findings");
    const body = document.getElementById("remediation-body");
    if (noFindings) noFindings.hidden = findings.length > 0;
    if (body) body.hidden = findings.length === 0;
    if (!findings.length) {
        selectedRemediationFinding = null;
        setRemediationStatus("detected", "No significant findings");
        return;
    }

    const priorityList = document.getElementById("remediation-priority-list");
    if (priorityList) {
        priorityList.innerHTML = findings.map((finding, index) => `
            <li><button type="button" data-remediation-finding="${escapeHtml(finding.id)}" aria-current="false">
                <span class="remediation-priority-number">${String(index + 1).padStart(2, "0")}</span>
                <span class="remediation-priority-title">${escapeHtml(finding.title)}<small>${escapeHtml(finding.ip)}${finding.port ? ` · ${escapeHtml(finding.protocol)}/${escapeHtml(finding.port)}` : ""}</small></span>
                <span class="remediation-priority-severity ${escapeHtml(String(finding.severity).toLowerCase())}">${escapeHtml(String(finding.severity).toUpperCase())}</span>
            </button></li>
        `).join("");
    }

    let selected = selectedRemediationFinding && findings.find((item) => item.id === selectedRemediationFinding.id);
    if (deviceFilter) selected = findings.find((item) => item.ip === deviceFilter.ip) || selected;
    if (!selected || !findings.some((item) => item.id === selected.id)) selected = findings[0];
    remediationStep = 0;
    remediationCompletedStep = -1;
    renderRemediationFinding(selected);
    setRemediationStatus("detected");
}

function remediationPrompt(finding = selectedRemediationFinding) {
    return `Analyze the selected Defensive finding as a remediation assistant. Use the supplied structured scan and Nmap evidence only. Prioritize the findings for this device using severity, observed exposure, evidence confidence, and potential impact, and explain the ordering briefly. For the selected finding, distinguish confirmed observations from likely, possible, and unknown conclusions; do not claim a CVE or vulnerability unless the supplied Nmap evidence explicitly confirms it. Explain what was detected, why it matters, the affected device and service, evidence, likely root cause (label inference), least-disruptive fix, safe verification, and next action. If OS detection is unavailable and no user-confirmed OS is present, say so and ask the user to select the OS; do not provide OS-specific commands. Never run or claim to run a command, modify the device, or verify a fix. Do not reveal hidden chain-of-thought. Analyze: ${finding?.title || "the selected Defensive findings"}.`;
}

async function analyzeSelectedFinding() {
    if (!selectedRemediationFinding || !remediationScanId || !window.WifiSentinelAI?.ask) return false;
    const aiStatus = document.getElementById("remediation-ai-status");
    const retryButton = document.getElementById("remediation-retry-ai");
    if (aiStatus) aiStatus.textContent = "AI ANALYZING";
    if (retryButton) retryButton.hidden = true;
    setRemediationStatus("analyzing");
    await saveRemediationStatus("ANALYZING");
    const succeeded = await window.WifiSentinelAI.ask(remediationPrompt(), remediationContext());
    if (succeeded) {
        if (aiStatus) aiStatus.textContent = "ANALYSIS READY · ACTION REQUIRED";
        remediationCompletedStep = Math.max(remediationCompletedStep, 0);
        remediationStep = Math.max(remediationStep, 1);
        renderGuidedSteps();
        setRemediationStatus("remediation_ready");
        await saveRemediationStatus("REMEDIATION_READY");
    } else {
        if (aiStatus) aiStatus.textContent = "AI UNAVAILABLE · FINDINGS PRESERVED";
        if (retryButton) retryButton.hidden = false;
        setRemediationStatus("detected");
        await saveRemediationStatus("DETECTED");
    }
    return succeeded;
}

async function loadRemediationStatus(finding) {
    if (!remediationScanId || !finding?.id) return;
    const query = new URLSearchParams({module: "defensive", scan_id: remediationScanId, finding_id: finding.id});
    try {
        const response = await fetch(`/api/ai/remediation?${query}`, {headers: {Accept: "application/json"}});
        const payload = await response.json();
        if (!response.ok || !payload.success) return;
        const status = String(payload.status || "DETECTED").toUpperCase();
        if (["INVESTIGATING", "ACTION_REQUIRED", "REMEDIATION_RECOMMENDED", "RESCAN_REQUIRED", "VERIFICATION_RUNNING", "VERIFIED", "STILL_PRESENT", "INCONCLUSIVE"].includes(status)) {
            remediationCompletedStep = status === "VERIFIED" ? 3 : Math.max(remediationCompletedStep, 0);
            remediationStep = status === "VERIFIED" ? 4 : status === "RESCAN_REQUIRED" ? 3 : status === "ACTION_REQUIRED" ? 1 : 1;
            renderGuidedSteps();
        }
        setRemediationStatus(status.toLowerCase());
    } catch { /* Saved scan evidence remains available if AI workflow state cannot be loaded. */ }
}

async function onDefensiveScanComplete(scan) {
    const status = String(scan.status || "").toLowerCase();
    if (!["completed", "partial"].includes(status)) return;
    const findings = collectRisks(scan.devices || []);
    renderRemediationPanel(scan, findings);
    if (!findings.length) return;
    const aiStatus = document.getElementById("remediation-ai-status");
    if (aiStatus) aiStatus.textContent = "ANALYZING DEFENSIVE EVIDENCE";
    await loadRemediationStatus(findings[0]);
    await analyzeSelectedFinding();
}

function findDevicePort(scan, ip, portNumber, protocol = "tcp") {
    const device = scan?.devices?.find((item) => String(item.ip) === String(ip));
    return device?.ports?.find((item) =>
        String(item.port) === String(portNumber)
        && String(item.protocol || "tcp").toLowerCase() === String(protocol || "tcp").toLowerCase()
    ) || null;
}

async function startVerificationScan() {
    if (scanRunning || !selectedRemediationFinding || !selectedRemediationFinding.ip || !selectedRemediationFinding.port || !latestDefensiveScan) return;
    const beforePort = findDevicePort(
        latestDefensiveScan,
        selectedRemediationFinding.ip,
        selectedRemediationFinding.port,
        selectedRemediationFinding.protocol,
    );
    pendingVerification = {
        finding: selectedRemediationFinding,
        originalScan: latestDefensiveScan,
        originalScanId: remediationScanId,
        beforeState: beforePort?.state || "not observed",
        profile: currentScanProfile,
    };
    remediationStep = 3;
    renderGuidedSteps();
    setRemediationStatus("verification_running");
    const aiStatus = document.getElementById("remediation-ai-status");
    if (aiStatus) aiStatus.textContent = "VERIFICATION SCAN RUNNING · ONE DEVICE";
    await saveRemediationStatus("VERIFICATION_RUNNING");
    await startScan(pendingVerification);
}

async function finishVerificationScan(scan) {
    const verification = pendingVerification;
    if (!verification || !verification.finding || !verification.finding.ip || !verification.finding.port) {
        pendingVerification = null;
        return;
    }
    const finding = verification.finding;
    const afterPort = findDevicePort(scan, finding.ip, finding.port, finding.protocol);
    const beforeState = String(verification.beforeState || "not observed").toUpperCase();
    const afterState = String(afterPort?.state || "not reported").toUpperCase();
    let outcome = "INCONCLUSIVE";
    let resultText = "Verification inconclusive. The scan did not return an explicit port state for this service.";
    if (["cancelled", "canceled"].includes(String(scan.status).toLowerCase())) {
        outcome = "CANCELLED";
        resultText = "Verification was cancelled. No remediation conclusion was recorded.";
    } else if (["completed", "partial"].includes(String(scan.status).toLowerCase())) {
        if (afterState === "CLOSED") {
            outcome = "VERIFIED";
            resultText = "Remediation verified from this scan vantage point: Nmap now reports the port closed.";
        } else if (afterState === "OPEN") {
            outcome = "STILL_PRESENT";
            resultText = "Issue still present: Nmap continues to report the service as open.";
        } else if (afterState === "FILTERED" || afterState === "OPEN|FILTERED") {
            resultText = "Verification inconclusive: Nmap reports filtered, which does not prove the service was removed.";
        }
    }

    const comparison = document.getElementById("remediation-comparison");
    if (comparison) comparison.hidden = false;
    const before = document.getElementById("remediation-before");
    const after = document.getElementById("remediation-after");
    const result = document.getElementById("remediation-verification-result");
    const serviceLabel = `${finding.protocol}/${finding.port} ${finding.service || "service"}`;
    if (before) before.textContent = `${serviceLabel} · ${beforeState}`;
    if (after) after.textContent = `${serviceLabel} · ${afterState}`;
    if (result) result.textContent = resultText;

    if (outcome === "VERIFIED") {
        remediationCompletedStep = 4;
        remediationStep = 5;
    } else {
        remediationCompletedStep = 3;
        remediationStep = 4;
    }
    renderGuidedSteps();
    setRemediationStatus(outcome.toLowerCase());
    const aiStatus = document.getElementById("remediation-ai-status");
    if (aiStatus) aiStatus.textContent = `${outcome.replaceAll("_", " ")} · NMAP EVIDENCE`;
    await saveRemediationStatus(outcome);

    const newScanId = scan.job_id || scan.id || "";
    pendingVerification = null;
    if (newScanId && window.WifiSentinelAI && outcome !== "CANCELLED") {
        await window.WifiSentinelAI.ask(
            `Compare the before and after Defensive scan evidence for ${finding.ip} ${finding.protocol}/${finding.port}. Explain only the observed state change, its limits, and the next safe action. The UI outcome is ${outcome}; do not claim more than the saved Nmap evidence supports.`,
            {
                scanId: newScanId,
                compareScanId: verification.originalScanId,
                module: "defensive",
                hostId: finding.ip,
                deviceOS: document.getElementById("remediation-os")?.value || "",
            },
        );
    }
}

document.getElementById("remediation-priority-list")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-remediation-finding]");
    if (!button) return;
    const finding = remediationFindings.find((item) => item.id === button.dataset.remediationFinding);
    if (!finding) return;
    remediationStep = 0;
    remediationCompletedStep = -1;
    const aiStatus = document.getElementById("remediation-ai-status");
    if (aiStatus) aiStatus.textContent = "ANALYZING SELECTED FINDING";
    renderRemediationFinding(finding);
    await loadRemediationStatus(finding);
    await analyzeSelectedFinding();
});

document.getElementById("remediation-open-ai")?.addEventListener("click", analyzeSelectedFinding);
document.getElementById("remediation-retry-ai")?.addEventListener("click", analyzeSelectedFinding);
document.getElementById("remediation-os")?.addEventListener("change", analyzeSelectedFinding);

document.getElementById("remediation-ask-general")?.addEventListener("click", () => {
    const scanId = latestDefensiveScan?.job_id || latestDefensiveScan?.id || "";
    if (!scanId || !window.WifiSentinelAI?.ask) return;
    window.WifiSentinelAI.ask(
        "Summarize the selected Defensive scan evidence. Confirm that no significant findings were generated by these checks, explain the scan coverage limits, and suggest a safe next step without claiming the device is vulnerability-free.",
        {scanId, module: "defensive"},
    );
});

document.getElementById("remediation-start-guided")?.addEventListener("click", async () => {
    remediationStep = Math.max(remediationStep, 1);
    setRemediationStatus("action_required");
    const aiStatus = document.getElementById("remediation-ai-status");
    if (aiStatus) aiStatus.textContent = "WAITING FOR USER ACTION";
    renderGuidedSteps();
    await saveRemediationStatus("ACTION_REQUIRED");
});

document.getElementById("remediation-complete-step")?.addEventListener("click", async () => {
    if (remediationStep < 1 || remediationStep > 2) return;
    remediationCompletedStep = Math.max(remediationCompletedStep, remediationStep);
    remediationStep += 1;
    renderGuidedSteps();
    if (remediationStep === 3) {
        setRemediationStatus("rescan_required");
        await saveRemediationStatus("RESCAN_REQUIRED");
    } else {
        await saveRemediationStatus("ACTION_REQUIRED");
    }
});

document.getElementById("remediation-verify-fix")?.addEventListener("click", startVerificationScan);

function displayDevices(devices) {
    if (!devicesContainer) {
        return;
    }

    if (!Array.isArray(devices) || devices.length === 0) {
        devicesContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">⌁</div>
                <h4>No scan results</h4>
                <p>Start a network scan to discover authorized network devices.</p>
            </div>
        `;
        return;
    }

    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[character]));
    const cards = devices.map((device, hostIndex) => {
        const ip = device && device.ip ? device.ip : "Unknown";
        const hostname = device && device.hostname && device.hostname !== "Unknown" ? device.hostname : "No hostname";
        const os = device && device.os && device.os !== "Unknown" ? device.os : "Operating system unknown";
        const openPorts = Array.isArray(device.ports)
            ? device.ports.filter((port) => port && port.state === "open").length
            : Number(device.open_ports || 0);
        const openPortRecords = Array.isArray(device.ports)
            ? device.ports
                .filter((port) => port && port.state === "open")
            : [];
        const ports = openPortRecords.map((port) => `${port.port}/${port.protocol || "tcp"}`).join(", ") || "None";
        const services = openPortRecords.map((port) => `${port.service || "Unknown"}${port.product ? ` (${port.product})` : ""}${port.version ? ` ${port.version}` : ""}`).join(", ") || "None identified";
        const portStates = Array.isArray(device.ports)
            ? device.ports.map((port) => `${port.protocol || "tcp"}/${port.port}: ${port.state || "unknown"}${port.reason ? ` (${port.reason})` : ""}`).join("; ")
            : "";
        const trace = Array.isArray(device.traceroute)
            ? device.traceroute.map((hop) => `${hop.ttl || "?"}: ${hop.ip || "*"}${hop.host ? ` (${hop.host})` : ""}${hop.rtt ? ` ${hop.rtt} ms` : ""}`).join(" → ")
            : "";
        const scriptOutput = Array.isArray(device.host_scripts)
            ? device.host_scripts.map((script) => `${script.id || "NSE"}: ${script.output || ""}`).join("\n")
            : "";
        const packetTrace = String(device.packet_trace || "");
        const diagnostics = [
            device.status_reason ? `<p>Host state reason: ${escapeHtml(device.status_reason)}</p>` : "",
            portStates ? `<p>Port states / reasons: ${escapeHtml(portStates)}</p>` : "",
            trace ? `<p>Traceroute: ${escapeHtml(trace)}</p>` : "",
            scriptOutput ? `<pre>${escapeHtml(scriptOutput)}</pre>` : "",
            packetTrace ? `<pre>${escapeHtml(packetTrace)}</pre>` : "",
        ].filter(Boolean).join("");
        const risks = Array.isArray(device.risks) ? device.risks : [];
        const risk = risks.length ? risks.map((item) => item.severity || "medium").join(", ") : "None";
        const portActions = openPortRecords.map((port) => {
            const portIndex = device.ports.indexOf(port);
            return `
            <button class="ai-context-trigger" data-results-panel="interpretation" type="button" data-ai-host="${escapeHtml(ip)}" data-ai-service="${escapeHtml(`${ip}:${port.port}/${port.protocol || "tcp"}`)}">Explain ${escapeHtml(port.protocol || "tcp")}/${escapeHtml(port.port)}</button>
            <button class="subtle-button" type="button" data-evidence-host="${hostIndex}" data-evidence-port="${portIndex}">Port evidence</button>
            `;
        }).join("");

        return `
            <article class="device-card">
                <div class="device-card-header">
                    <div>
                        <strong>${escapeHtml(hostname)}</strong>
                        <span>${escapeHtml(ip)}</span>
                    </div>
                    <span class="device-tag">${openPorts} open</span>
                </div>
                <div class="device-card-meta">
                    <span>MAC: ${escapeHtml(device.mac || "Unknown")} · Vendor: ${escapeHtml(device.vendor || "Unknown")}</span>
                    <span>OS: ${escapeHtml(os)}${device.os_accuracy ? ` (${device.os_accuracy}%)` : ""}</span>
                    <span>Ports: ${escapeHtml(ports)}</span>
                    <span>Services: ${escapeHtml(services)}</span>
                    <span data-results-panel="interpretation">Risk: ${escapeHtml(risk)}</span>
                </div>
                ${diagnostics ? `<details class="device-diagnostics"><summary>Scan evidence</summary>${diagnostics}</details>` : ""}
                <div class="ai-device-actions">
                    <button class="button button-secondary" type="button" data-remediation-device="${hostIndex}">Device security</button>
                    <button class="ai-context-trigger" data-results-panel="interpretation" type="button" data-ai-host="${escapeHtml(ip)}">Explain host</button>
                    <button class="subtle-button" type="button" data-evidence-host="${hostIndex}">Host evidence</button>
                    ${portActions}
                </div>
            </article>
        `;
    }).join("");

    devicesContainer.innerHTML = cards;
}

function displayRisks(risks) {
    if (!risksContainer) {
        return;
    }

    if (!Array.isArray(risks) || risks.length === 0) {
        risksContainer.innerHTML = `
            <div class="empty-state compact">
                <div class="empty-icon">✓</div>
                <h4>No findings yet</h4>
                <p>Security findings will appear after scanning.</p>
            </div>
        `;
        return;
    }

    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[character]));
    const items = risks.map((risk) => {
        const severity = (risk.severity || "medium").toUpperCase();
        const portText = risk.port ? ` • TCP/${risk.port}` : "";
        return `
            <article class="risk-card ${risk.severity || "medium"}">
                <div class="risk-head">
                    <span class="risk-badge ${risk.severity || "medium"}">${severity}</span>
                    <strong>${escapeHtml(risk.title)}</strong>
                </div>
                <p>${escapeHtml(risk.description)}${escapeHtml(portText)}</p>
                <small>${escapeHtml(risk.protection || "Review this exposure and restrict access where needed.")}</small>
                <button class="ai-context-trigger" type="button" data-ai-host="${escapeHtml(risk.ip)}" data-ai-finding="${escapeHtml(`def:${risk.ip}:${risk.port || ""}:${risk.title}`)}">Explain finding</button>
            </article>
        `;
    }).join("");

    risksContainer.innerHTML = items;
}

async function pollScanStatus() {
    if (!currentJobId) {
        return;
    }

    try {
        const response = await fetch(`/api/scan/status/${currentJobId}`);
        const payload = await response.json();

        if (!response.ok || !payload.success) {
            throw new Error(payload.error || "Unable to get scan status.");
        }

        const scan = payload.scan;
        if (scan) {
            updateScanUI(scan);
        }

        if (scan && scan.finished) {
            scanRunning = false;
            stopTimer();

            if (scanOverlay) {
                scanOverlay.classList.add("hidden");
            }
            if (progressContainer) {
                progressContainer.classList.add("hidden");
            }

            if (scanButton) {
                scanButton.disabled = false;
                scanButton.innerHTML = `<span class="button-icon">⌕</span><span>Start Scan</span>`;
            }

            if (cancelScanButton) {
                cancelScanButton.hidden = true;
                cancelScanButton.disabled = false;
            }

            if (statusTitle) {
                statusTitle.textContent = scan.status === "completed" ? "Scan completed" : scan.status === "cancelled" ? "Scan cancelled" : "Scan finished";
            }

            if (statusMessage) {
                const limitation = Array.isArray(scan.limitations) && scan.limitations.length ? ` ${scan.limitations.join(" ")}` : "";
                statusMessage.textContent = scan.error || `Target: ${currentNetwork || scan.target || "unknown"}.${limitation}`;
            }

            if (scanState) {
                scanState.textContent = scan.status === "completed" ? "Complete" : scan.status;
            }

            const indicator = scanStatus ? scanStatus.querySelector(".status-indicator") : null;
            if (indicator) {
                indicator.classList.remove("scanning", "ready", "warning", "failed");
                const terminalIndicator = ["error", "failed"].includes(String(scan.status).toLowerCase())
                    ? "failed"
                    : ["partial", "cancelled", "canceled", "incomplete"].includes(String(scan.status).toLowerCase())
                        ? "warning"
                        : "ready";
                indicator.classList.add(terminalIndicator);
            }

            if (pendingVerification && pendingVerification.jobId === scan.job_id) {
                await finishVerificationScan(scan);
            } else {
                await onDefensiveScanComplete(scan);
            }

            return;
        }

        statusPoller = window.setTimeout(pollScanStatus, 1200);
    } catch (error) {
        handleScanError(error);
    }
}

function handleScanError(error) {
    scanRunning = false;
    stopTimer();

    if (diagnosticFields.status) {
        diagnosticFields.status.textContent = "FAILED";
    }

    if (statusTitle) {
        statusTitle.textContent = "Scan failed";
    }

    if (statusMessage) {
        statusMessage.textContent = error && error.message ? error.message : "The scan could not be completed.";
    }

    if (scanState) {
        scanState.textContent = "Error";
    }

    const indicator = scanStatus ? scanStatus.querySelector(".status-indicator") : null;
    if (indicator) {
        indicator.classList.remove("ready", "scanning", "warning");
        indicator.classList.add("failed");
    }

    if (scanButton) {
        scanButton.disabled = false;
        scanButton.innerHTML = `<span class="button-icon">⌕</span><span>Start Scan</span>`;
    }

    if (scanOverlay) {
        scanOverlay.classList.add("hidden");
    }

    if (progressContainer) {
        progressContainer.classList.add("hidden");
    }

    if (statusPoller) {
        window.clearTimeout(statusPoller);
        statusPoller = null;
    }
}

if (scanButton) {
    scanButton.addEventListener("click", startScan);
}

if (cancelScanButton) {
    cancelScanButton.addEventListener("click", async () => {
        if (!currentJobId || !scanRunning || !window.confirm("Cancel this assessment?")) return;
        cancelScanButton.disabled = true;
        try {
            const response = await fetch(`/api/scan/cancel/${encodeURIComponent(currentJobId)}`, {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "",
                },
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) throw new Error(payload.error || "Unable to cancel the scan.");
            if (statusTitle) statusTitle.textContent = "Cancellation requested";
            if (statusMessage) statusMessage.textContent = "Waiting for the scanner process to stop; partial results will be preserved.";
        } catch (error) {
            cancelScanButton.disabled = false;
            handleScanError(error);
        }
    });
}

if (networkInput) {
    networkInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            startScan();
        }
    });
}

if (clearHistoryButton) {
    clearHistoryButton.addEventListener("click", () => {
        if (devicesContainer) {
            devicesContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">⌁</div>
                    <h4>No scan results</h4>
                    <p>Start a network scan to discover authorized network devices.</p>
                </div>
            `;
        }
        if (risksContainer) {
            risksContainer.innerHTML = `
                <div class="empty-state compact">
                    <div class="empty-icon">✓</div>
                    <h4>No findings yet</h4>
                    <p>Security findings will appear after scanning.</p>
                </div>
            `;
        }
        if (deviceCount) deviceCount.textContent = "0";
        if (portCount) portCount.textContent = "0";
        if (riskCount) riskCount.textContent = "0";
        if (scanState) scanState.textContent = "Ready";
        if (statusTitle) statusTitle.textContent = "Ready to scan";
        if (statusMessage) statusMessage.textContent = "Enter an authorized network range to begin.";
    });
}

/* =========================================================
   END SCAN SETTINGS MODAL
========================================================= */

;