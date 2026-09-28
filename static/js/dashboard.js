"use strict";

/* =========================================================
   WIFI SENTINEL V2.0
   Dashboard Controller
========================================================= */

const networkInput = document.getElementById("networkInput");
const scanButton = document.getElementById("scanButton");
const scanStatus = document.getElementById("scanStatus");
const statusTitle = document.getElementById("statusTitle");
const statusMessage = document.getElementById("statusMessage");
const progressContainer = document.getElementById("progressContainer");
const progressBar = document.getElementById("progressBar");
const progressPercent = document.getElementById("progressPercent");
const progressStage = document.getElementById("progressStage");
const progressDetail = document.getElementById("progressDetail");
const scanTimer = document.getElementById("scanTimer");
const scanOverlay = document.getElementById("scanOverlay");
const overlayProgressBar = document.getElementById("overlayProgressBar");
const overlayPercent = document.getElementById("overlayPercent");
const overlayStage = document.getElementById("overlayStage");
const overlayNetwork = document.getElementById("overlayNetwork");
const deviceCount = document.getElementById("deviceCount");
const portCount = document.getElementById("portCount");
const riskCount = document.getElementById("riskCount");
const scanState = document.getElementById("scanState");
const deviceCountBadge = document.getElementById("deviceCountBadge");
const devicesContainer = document.getElementById("devicesContainer");
const risksContainer = document.getElementById("risksContainer");
const historyContainer = document.getElementById("historyContainer");
const clearHistoryButton = document.getElementById("clearHistory");

let scanRunning = false;
let scanStartTime = null;
let timerInterval = null;
let statusInterval = null;
let currentJobId = null;
let currentNetwork = "";

const steps = {
    discovery: document.getElementById("stepDiscovery"),
    ports: document.getElementById("stepPorts"),
    risk: document.getElementById("stepRisk"),
    report: document.getElementById("stepReport")
};

function isValidNetwork(value) {
    const cidrPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/);
    return cidrPattern.test(value.trim());
}

function startTimer() {
    scanStartTime = Date.now();
    stopTimer();
    timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const minutes = String(Math.floor(elapsed / 60)).padStart(2, "0");
        const seconds = String(elapsed % 60).padStart(2, "0");
        if (scanTimer) scanTimer.textContent = `${minutes}:${seconds}`;
    }, 250);
}

function stopTimer() {
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = null;
}

function setProgress(percent, stage, detail) {
    const value = Math.max(0, Math.min(100, Number(percent) || 0));
    if (progressBar) progressBar.style.width = `${value}%`;
    if (progressPercent) progressPercent.textContent = `${Math.round(value)}%`;
    if (progressStage) progressStage.textContent = stage || "Scanning";
    if (progressDetail) progressDetail.textContent = detail || "";
    if (overlayProgressBar) overlayProgressBar.style.width = `${value}%`;
    if (overlayPercent) overlayPercent.textContent = `${Math.round(value)}%`;
    if (overlayStage) overlayStage.textContent = stage || "Scanning";
}

function activateStep(step) {
    if (!step) return;
    Object.values(steps).forEach(element => element?.classList.remove("active"));
    step.classList.add("active");
}

function completeStep(step) {
    if (!step) return;
    step.classList.remove("active");
    step.classList.add("completed");
}

function resetSteps() {
    Object.values(steps).forEach(element => element?.classList.remove("active", "completed"));
    steps.discovery?.classList.add("active");
}

function showScanningUI(network) {
    scanRunning = true;
    if (scanButton) {
        scanButton.disabled = true;
        scanButton.innerHTML = `<span class="button-icon">◌</span><span>Scanning...</span>`;
    }
    progressContainer?.classList.remove("hidden");
    const indicator = scanStatus?.querySelector(".status-indicator");
    indicator?.classList.remove("ready");
    indicator?.classList.add("scanning");
    if (statusTitle) statusTitle.textContent = "Network scan in progress";
    if (statusMessage) statusMessage.textContent = "Analyzing the authorized network. Please wait.";
    if (scanState) scanState.textContent = "Scanning";
    scanOverlay?.classList.remove("hidden");
    if (overlayNetwork) overlayNetwork.textContent = `Analyzing ${network}`;
    resetSteps();
    setProgress(2, "Starting scanner", "Connecting to the network scanner");
}

function finishClientScan(success, message) {
    scanRunning = false;
    stopTimer();
    if (statusInterval) clearInterval(statusInterval);
    statusInterval = null;
    scanOverlay?.classList.add("hidden");
    const indicator = scanStatus?.querySelector(".status-indicator");
    indicator?.classList.remove("scanning");
    indicator?.classList.add(success ? "ready" : "error");
    if (statusTitle) statusTitle.textContent = success ? "Scan completed" : "Scan failed";
    if (statusMessage) statusMessage.textContent = message || "";
    if (scanState) scanState.textContent = success ? "Complete" : "Error";
    if (scanButton) {
        scanButton.disabled = false;
        scanButton.innerHTML = `<span class="button-icon">⌕</span><span>Start Scan</span>`;
    }
}

function updateScanUI(scan) {
    if (!scan) return;
    const progress = Number(scan.progress) || 0;
    const phase = scan.phase || "Scanning network";
    let detail = "Working...";
    const lower = phase.toLowerCase();
    if (lower.includes("discover")) {
        activateStep(steps.discovery);
        detail = `${scan.device_count || 0} device(s) discovered`;
    } else if (lower.includes("port")) {
        completeStep(steps.discovery);
        activateStep(steps.ports);
        detail = `${scan.device_count || 0} devices • ${scan.open_ports || 0} open ports`;
    } else if (lower.includes("security") || lower.includes("risk")) {
        completeStep(steps.discovery);
        completeStep(steps.ports);
        activateStep(steps.risk);
        detail = `${scan.risks || 0} security finding(s)`;
    } else if (lower.includes("report") || progress >= 93) {
        completeStep(steps.discovery);
        completeStep(steps.ports);
        completeStep(steps.risk);
        activateStep(steps.report);
        detail = "Preparing final security report";
    }
    if (Array.isArray(scan.current_hosts) && scan.current_hosts.length) {
        const visible = scan.current_hosts.slice(0, 3).join(", ");
        const remaining = scan.current_hosts.length - 3;
        detail += ` • Active hosts: ${visible}${remaining > 0 ? ` +${remaining}` : ""}`;
    }
    setProgress(progress, phase, detail);
    if (deviceCount) deviceCount.textContent = scan.device_count || 0;
    if (deviceCountBadge) deviceCountBadge.textContent = scan.device_count || 0;
    if (portCount) portCount.textContent = scan.open_ports || 0;
    if (riskCount) riskCount.textContent = scan.risks || 0;
    if (Array.isArray(scan.devices)) {
        displayDevices(scan.devices);
        displayRisks(collectRisks(scan.devices));
    }
}

async function pollScanStatus() {
    if (!currentJobId) throw new Error("Scanner did not return a job ID.");
    const poll = async () => {
        try {
            const response = await fetch(`/api/scan/status/${encodeURIComponent(currentJobId)}`, { headers: { "Accept": "application/json" }, cache: "no-store" });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || "Unable to read scan status.");
            const scan = data.scan || data;
            updateScanUI(scan);
            if (scan.finished || ["completed", "error", "failed"].includes(String(scan.status).toLowerCase())) {
                if (scan.status === "completed") finishClientScan(true, "Defensive assessment completed.");
                else finishClientScan(false, scan.error || "Defensive assessment failed.");
                return;
            }
            statusInterval = setTimeout(poll, 1000);
        } catch (error) {
            finishClientScan(false, error.message || "Unable to read scan status.");
        }
    };
    await poll();
}

function handleScanError(error) {
    finishClientScan(false, error?.message || "Unable to start the defensive scanner.");
}

async function startScan() {
    if (scanRunning) return;
    const network = networkInput?.value.trim() || "";
    if (!isValidNetwork(network)) {
        handleScanError(new Error("Enter a valid IPv4 CIDR network, for example 192.168.1.0/24."));
        return;
    }
    const settings = await openScanSettingsModal();
    if (!settings) return;
    currentNetwork = network;
    showScanningUI(network);
    if (statusTitle) statusTitle.textContent = "Preparing scan";
    if (statusMessage) statusMessage.textContent = `${formatScanProfile(settings.profile)} profile • ${formatScanTimeout(settings.timeout)}`;
    try {
        const response = await fetch("/api/scan/start", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ target: network, profile: settings.profile, timeout: settings.timeout })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || data.message || "Unable to start the network scan.");
        currentJobId = data.job_id;
        if (overlayNetwork) overlayNetwork.textContent = `${network} • ${formatScanProfile(settings.profile)} • ${formatScanTimeout(settings.timeout)}`;
        if (overlayStage) overlayStage.textContent = `${formatScanProfile(settings.profile)} assessment started`;
        startTimer();
        await pollScanStatus();
    } catch (error) {
        handleScanError(error);
    }
}

function openScanSettingsModal() {
    const modal = document.getElementById("scanSettingsModal");
    const profileInput = document.getElementById("scanProfile");
    const startButton = document.getElementById("scanSettingsStart");
    const closeButton = document.getElementById("scanSettingsClose");
    const cancelButton = document.getElementById("scanSettingsCancel");
    const backdrop = modal?.querySelector(".scan-settings-backdrop");
    if (!modal || !startButton) return Promise.resolve({ profile: "thorough", timeout: 60 });
    return new Promise(resolve => {
        let settled = false;
        const cleanup = () => {
            modal.classList.add("hidden");
            modal.setAttribute("aria-hidden", "true");
            startButton.removeEventListener("click", confirm);
            closeButton?.removeEventListener("click", cancel);
            cancelButton?.removeEventListener("click", cancel);
            backdrop?.removeEventListener("click", cancel);
            document.removeEventListener("keydown", keyHandler);
        };
        const finish = value => { if (settled) return; settled = true; cleanup(); resolve(value); };
        const cancel = () => finish(null);
        const confirm = () => {
            const checked = document.querySelector('input[name="scanTimeout"]:checked');
            finish({ profile: profileInput?.value || "thorough", timeout: checked && checked.value !== "none" ? Number(checked.value) : null });
        };
        const keyHandler = event => { if (event.key === "Escape") cancel(); };
        modal.classList.remove("hidden");
        modal.setAttribute("aria-hidden", "false");
        startButton.addEventListener("click", confirm);
        closeButton?.addEventListener("click", cancel);
        cancelButton?.addEventListener("click", cancel);
        backdrop?.addEventListener("click", cancel);
        document.addEventListener("keydown", keyHandler);
    });
}

function formatScanProfile(profile) { return { standard: "Standard", thorough: "Thorough", deep: "Deep" }[profile] || "Thorough"; }
function formatScanTimeout(timeout) { return timeout === null ? "No timeout" : `${timeout}s timeout`; }

/* Safe UI helpers */
function displayDevices(devices) {
    if (!devicesContainer) return;
    if (!devices.length) return;
    devicesContainer.innerHTML = devices.map(device => `<div class="device-card"><strong>${escapeHtml(device.ip || "Unknown")}</strong><span>${escapeHtml(device.hostname || "Unknown")}</span><span>Open ports: ${Number(device.open_ports_count || (device.open_ports || []).length || 0)}</span></div>`).join("");
}

function collectRisks(devices) {
    const risks = [];
    devices.forEach(device => (device.findings || device.risks || []).forEach(item => risks.push({ ...item, ip: device.ip })));
    return risks;
}

function displayRisks(risks) {
    if (!risksContainer || !risks.length) return;
    risksContainer.innerHTML = risks.map(risk => `<div class="risk-card"><strong>${escapeHtml(risk.title || risk.name || "Security finding")}</strong><span>${escapeHtml(risk.ip || "Unknown")}</span><p>${escapeHtml(risk.description || risk.detail || "Review the associated evidence and remediation guidance.")}</p></div>`).join("");
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

/* CRITICAL: wire the visible Start Scan button to the real scanner. */
if (scanButton) scanButton.addEventListener("click", startScan);
if (networkInput) networkInput.addEventListener("keydown", event => { if (event.key === "Enter") startScan(); });
