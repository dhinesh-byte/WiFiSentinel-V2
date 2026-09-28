"use strict";

/* =========================================================
   WIFI SENTINEL V2.0
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

const riskCount =
    document.getElementById("riskCount");

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
        2,
        "Starting scanner",
        "Connecting to the network scanner"
    );

    startTimer();
}


/* =========================================================
   UPDATE UI FROM REAL BACKEND STATUS
========================================================= */

function updateScanUI(
    scan
) {

    if (!scan) {
        return;
    }

    const progress =
        Number(scan.progress) || 0;

    const phase =
        scan.phase ||
        "Scanning network";

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

    if (riskCount) {

        riskCount.textContent =
            scan.risks || 0;

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

}


/* =========================================================
   START REAL BACKEND SCAN
========================================================= */

async function startScan() {
    if (scanRunning) return;
    const network = networkInput ? networkInput.value.trim() : "";
    if (!network) {
        handleScanError(new Error("Enter an authorized network range before starting the scan."));
        return;
    }
    const settings = await openScanSettingsModal();
    if (!settings) return;
    scanRunning = true;
    currentNetwork = network;
    showScanningUI(network);
    if (statusTitle) statusTitle.textContent = "Preparing scan";
    if (statusMessage) statusMessage.textContent = `${formatScanProfile(settings.profile)} profile • ${formatScanTimeout(settings.timeout)}`;
    if (scanState) scanState.textContent = "Starting";
    try {
        const response = await fetch("/api/scan/start", {
            method:"POST",
            headers:{"Content-Type":"application/json","Accept":"application/json"},
            body:JSON.stringify({target:network,profile:settings.profile,timeout:settings.timeout})
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || data.message || "Unable to start the network scan.");
        }
        currentJobId = data.job_id;
        if (overlayNetwork) overlayNetwork.textContent = `${network} • ${formatScanProfile(settings.profile)} • ${formatScanTimeout(settings.timeout)}`;
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
    if (!modal || !startButton) return Promise.resolve({profile:"thorough",timeout:60});
    return new Promise(resolve => {
        let settled=false;
        const cleanup=()=>{modal.classList.add("hidden");modal.setAttribute("aria-hidden","true");startButton.removeEventListener("click",confirm);closeButton?.removeEventListener("click",cancel);cancelButton?.removeEventListener("click",cancel);backdrop?.removeEventListener("click",cancel);document.removeEventListener("keydown",keyHandler);};
        const finish=value=>{if(settled)return;settled=true;cleanup();resolve(value);};
        const cancel=()=>finish(null);
        const confirm=()=>{const checked=document.querySelector('input[name="scanTimeout"]:checked');finish({profile:profileInput?.value||"thorough",timeout:checked&&checked.value!=="none"?Number(checked.value):null});};
        const keyHandler=e=>{if(e.key==="Escape"){e.preventDefault();cancel();}else if(e.key==="Enter"){e.preventDefault();confirm();}};
        modal.classList.remove("hidden");modal.setAttribute("aria-hidden","false");
        startButton.addEventListener("click",confirm);closeButton?.addEventListener("click",cancel);cancelButton?.addEventListener("click",cancel);backdrop?.addEventListener("click",cancel);document.addEventListener("keydown",keyHandler);
        profileInput?.focus();
    });
}
function formatScanProfile(profile){return {standard:"Standard",thorough:"Thorough",deep:"Deep"}[profile]||"Thorough";}
function formatScanTimeout(timeout){return timeout===null?"No timeout":`${timeout}s timeout`;}

/* =========================================================
   END SCAN SETTINGS MODAL
========================================================= */

;