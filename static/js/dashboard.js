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

let scanRunning = false;
let timerInterval = null;
let statusInterval = null;
let currentJobId = null;

function isValidTarget(value) {
    const v = String(value || "").trim();
    const parts = v.split("/");
    const ip = parts[0].split(".");
    if (ip.length !== 4 || ip.some(x => !/^\d+$/.test(x) || Number(x) > 255)) return false;
    if (parts.length === 1) return true;
    return parts.length === 2 && /^\d+$/.test(parts[1]) && Number(parts[1]) >= 0 && Number(parts[1]) <= 32;
}

function startTimer() {
    const started = Date.now();
    clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - started) / 1000);
        if (scanTimer) scanTimer.textContent = `${String(Math.floor(elapsed / 60)).padStart(2, "0")}:${String(elapsed % 60).padStart(2, "0")}`;
    }, 250);
}

function stopTimer() {
    clearInterval(timerInterval);
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

function finishClientScan(success, message) {
    scanRunning = false;
    stopTimer();
    clearTimeout(statusInterval);
    statusInterval = null;
    scanOverlay?.classList.add("hidden");
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
    setProgress(progress, phase, `${scan.device_count || 0} device(s) • ${scan.open_ports || 0} open ports`);
    if (deviceCount) deviceCount.textContent = scan.device_count || 0;
    if (deviceCountBadge) deviceCountBadge.textContent = scan.device_count || 0;
    if (portCount) portCount.textContent = scan.open_ports || 0;
    if (riskCount) riskCount.textContent = scan.risks || 0;
    if (Array.isArray(scan.devices)) displayDevices(scan.devices);
}

async function pollScanStatus() {
    const poll = async () => {
        try {
            const response = await fetch(`/api/scan/status/${encodeURIComponent(currentJobId)}`, { headers: { Accept: "application/json" }, cache: "no-store" });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || "Unable to read scan status.");
            const scan = data.scan || data;
            updateScanUI(scan);
            const state = String(scan.status || "").toLowerCase();
            if (scan.finished || ["completed", "error", "failed"].includes(state)) {
                finishClientScan(state === "completed", scan.error || (state === "completed" ? "Defensive assessment completed." : "Defensive assessment failed."));
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

function openScanSettingsModal() {
    const modal = document.getElementById("scanSettingsModal");
    const profileInput = document.getElementById("scanProfile");
    const startButton = document.getElementById("scanSettingsStart");
    const closeButton = document.getElementById("scanSettingsClose");
    const cancelButton = document.getElementById("scanSettingsCancel");
    const backdrop = modal?.querySelector(".scan-settings-backdrop");
    if (!modal || !startButton) return Promise.resolve({ profile: "thorough", timeout: 60 });
    return new Promise(resolve => {
        let done = false;
        const cleanup = () => {
            modal.classList.add("hidden");
            modal.setAttribute("aria-hidden", "true");
            startButton.removeEventListener("click", confirm);
            closeButton?.removeEventListener("click", cancel);
            cancelButton?.removeEventListener("click", cancel);
            backdrop?.removeEventListener("click", cancel);
        };
        const finish = value => { if (done) return; done = true; cleanup(); resolve(value); };
        const cancel = () => finish(null);
        const confirm = () => {
            const checked = document.querySelector('input[name="scanTimeout"]:checked');
            finish({ profile: profileInput?.value || "thorough", timeout: checked?.value === "none" ? null : Number(checked?.value || 60) });
        };
        modal.classList.remove("hidden");
        modal.setAttribute("aria-hidden", "false");
        startButton.addEventListener("click", confirm);
        closeButton?.addEventListener("click", cancel);
        cancelButton?.addEventListener("click", cancel);
        backdrop?.addEventListener("click", cancel);
    });
}

function formatScanProfile(profile) {
    return { standard: "Standard", thorough: "Thorough", deep: "Deep" }[profile] || "Thorough";
}

function formatScanTimeout(timeout) {
    return timeout === null ? "No timeout" : `${timeout}s timeout`;
}

async function startScan() {
    if (scanRunning) return;

    /* The configuration dialog must open even before a target is entered. */
    const settings = await openScanSettingsModal();
    if (!settings) return;

    const target = networkInput?.value.trim() || "";
    if (!isValidTarget(target)) {
        handleScanError(new Error("Enter a valid IPv4 address or CIDR network, for example 192.168.1.0/24."));
        return;
    }

    scanRunning = true;
    if (scanButton) {
        scanButton.disabled = true;
        scanButton.innerHTML = `<span class="button-icon">◌</span><span>Scanning...</span>`;
    }
    if (statusTitle) statusTitle.textContent = "Starting defensive assessment";
    if (statusMessage) statusMessage.textContent = `${formatScanProfile(settings.profile)} profile • ${formatScanTimeout(settings.timeout)}`;
    if (scanState) scanState.textContent = "Starting";
    scanOverlay?.classList.remove("hidden");
    if (overlayNetwork) overlayNetwork.textContent = `${target} • ${formatScanProfile(settings.profile)} • ${formatScanTimeout(settings.timeout)}`;
    setProgress(2, "Starting scanner", "Connecting to the local scanner");
    startTimer();

    try {
        const response = await fetch("/api/scan/start", {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify({ target, profile: settings.profile, timeout: settings.timeout })
        });
        const data = await response.json();
        if (!response.ok || !data.success || !data.job_id) throw new Error(data.error || data.message || "The defensive scanner did not return a scan job.");
        currentJobId = data.job_id;
        await pollScanStatus();
    } catch (error) {
        handleScanError(error);
    }
}

function displayDevices(devices) {
    if (!devicesContainer || !devices.length) return;
    devicesContainer.innerHTML = devices.map(device => `<div class="device-card"><strong>${escapeHtml(device.ip || "Unknown")}</strong><span>${escapeHtml(device.hostname || "Unknown")}</span><span>Open ports: ${Number(device.open_ports_count || (device.open_ports || []).length || 0)}</span></div>`).join("");
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

/* Bind after DOM load, so the button always works even if the script is cached. */
function bindScannerControls() {
    const button = document.getElementById("scanButton");
    const input = document.getElementById("networkInput");
    if (button && !button.dataset.bound) {
        button.addEventListener("click", startScan);
        button.dataset.bound = "true";
    }
    if (input && !input.dataset.bound) {
        input.addEventListener("keydown", event => { if (event.key === "Enter") startScan(); });
        input.dataset.bound = "true";
    }
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bindScannerControls);
else bindScannerControls();
