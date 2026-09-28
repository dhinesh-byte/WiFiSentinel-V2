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

    if (scanRunning) {
        return;
    }

    const network =
        networkInput
            ? networkInput.value.trim()
            : "";


    /* -----------------------------------------------------
       Validate
    ----------------------------------------------------- */

    if (!isValidNetwork(network)) {

        if (statusTitle) {

            statusTitle.textContent =
                "Invalid network range";

        }

        if (statusMessage) {

            statusMessage.textContent =
                "Enter a valid CIDR range such as 192.168.88.0/24.";

        }

        if (networkInput) {

            networkInput.focus();

        }

        return;
    }


    /* -----------------------------------------------------
       Start UI
    ----------------------------------------------------- */

    showScanningUI(
        network
    );


    try {

        console.log(
            "Starting WiFi Sentinel scan:",
            network
        );


        /* -------------------------------------------------
           ACTUAL FLASK API
        ------------------------------------------------- */

        const response =
            await fetch(
                "/api/scan/start",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        "Accept":
                            "application/json",

                        "X-CSRF-Token":
                            document.querySelector('meta[name="csrf-token"]')?.content || ""
                    },

                    body: JSON.stringify({
                        target: network
                    })
                }
            );


        if (!response.ok) {

            let message =
                `Server returned ${response.status}`;

            try {

                const errorData =
                    await response.json();

                if (errorData.error) {

                    message =
                        errorData.error;

                }

            } catch (_) {
                /* Ignore JSON parsing error */
            }

            throw new Error(
                message
            );

        }


        const data =
            await response.json();


        if (
            !data.success ||
            !data.job_id
        ) {

            throw new Error(
                data.error ||
                "Scanner did not return a job ID."
            );

        }


        currentJobId =
            data.job_id;


        console.log(
            "Scan job started:",
            currentJobId
        );


        /* -------------------------------------------------
           Begin REAL status polling
        ------------------------------------------------- */

        await pollScanStatus(
            currentJobId
        );


    } catch (error) {

        console.error(
            "Scan error:",
            error
        );

        handleScanError(
            error
        );

    }

}


/* =========================================================
   POLL REAL SCAN STATUS
========================================================= */

async function pollScanStatus(
    jobId
) {

    if (!jobId) {

        throw new Error(
            "Missing scan job ID."
        );

    }


    if (statusInterval) {

        clearInterval(
            statusInterval
        );

        statusInterval = null;

    }


    /*
       We use a loop instead of a fake visual
       progress animation.

       The percentage now comes from Flask/Nmap.
    */

    while (true) {

        const response =
            await fetch(
                `/api/scan/status/${encodeURIComponent(jobId)}`,
                {
                    method: "GET",

                    headers: {
                        "Accept":
                            "application/json"
                    },

                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Status request failed: ${response.status}`
            );

        }


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                data.error ||
                "Unable to retrieve scan status."
            );

        }


        const scan =
            data.scan;


        /* -------------------------------------------------
           Update dashboard using REAL data
        ------------------------------------------------- */

        updateScanUI(
            scan
        );


        /* -------------------------------------------------
           Error
        ------------------------------------------------- */

        if (
            scan.status === "error"
        ) {

            throw new Error(
                scan.error ||
                "Network scan failed."
            );

        }


        /* -------------------------------------------------
           Complete
        ------------------------------------------------- */

        if (
            scan.finished === true ||
            scan.status === "completed"
        ) {

            await completeRealScan(
                scan
            );

            return;

        }


        /*
           Wait before asking Flask again.
        */

        await sleep(
            700
        );

    }

}


/* =========================================================
   COMPLETE REAL SCAN
========================================================= */

async function completeRealScan(
    scan
) {

    setProgress(
        100,
        "Scan complete",
        `${scan.device_count || 0} devices • ` +
        `${scan.open_ports || 0} open ports • ` +
        `${scan.risks || 0} findings`
    );


    completeStep(
        steps.discovery
    );

    completeStep(
        steps.ports
    );

    completeStep(
        steps.risk
    );

    completeStep(
        steps.report
    );


    /* -----------------------------------------------------
       Final statistics
    ----------------------------------------------------- */

    displayDevices(
        scan.devices || []
    );


    displayRisks(
        collectRisks(
            scan.devices || []
        )
    );


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
       Save history locally
    ----------------------------------------------------- */

    saveScanHistory(
        scan.target,
        scan
    );


    /* -----------------------------------------------------
       Refresh server history
    ----------------------------------------------------- */

    loadServerHistory();


    stopTimer();


    if (statusTitle) {

        statusTitle.textContent =
            "Scan completed";

    }

    if (statusMessage) {

        statusMessage.textContent =
            "Network analysis completed successfully.";

    }

    if (scanState) {

        scanState.textContent =
            "Complete";

    }


    if (scanOverlay) {

        setTimeout(
            () => {

                scanOverlay.classList.add(
                    "hidden"
                );

            },
            700
        );

    }


    scanRunning = false;


    if (scanButton) {

        scanButton.disabled = false;

        scanButton.innerHTML =
            `<span class="button-icon">⌕</span>
             <span>Start Scan</span>`;

    }


    const indicator =
        scanStatus
            ? scanStatus.querySelector(
                ".status-indicator"
            )
            : null;


    if (indicator) {

        indicator.classList.remove(
            "scanning"
        );

        indicator.classList.add(
            "ready"
        );

    }


    currentJobId = null;

}


/* =========================================================
   ERROR HANDLING
========================================================= */

function handleScanError(
    error
) {

    console.error(
        "WiFi Sentinel:",
        error
    );


    stopTimer();


    scanRunning = false;


    if (scanButton) {

        scanButton.disabled = false;

        scanButton.innerHTML =
            `<span class="button-icon">⌕</span>
             <span>Start Scan</span>`;

    }


    if (scanOverlay) {

        scanOverlay.classList.add(
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
            "scanning"
        );

        indicator.classList.add(
            "ready"
        );

    }


    if (statusTitle) {

        statusTitle.textContent =
            "Scan failed";

    }


    if (statusMessage) {

        statusMessage.textContent =
            error && error.message
                ? error.message
                : "Unable to complete the network scan.";

    }


    if (scanState) {

        scanState.textContent =
            "Error";

    }


    currentJobId = null;

}


/* =========================================================
   SLEEP
========================================================= */

function sleep(
    milliseconds
) {

    return new Promise(
        resolve =>
            setTimeout(
                resolve,
                milliseconds
            )
    );

}


/* =========================================================
   HISTORY
========================================================= */

function saveScanHistory(
    network,
    scan = null
) {

    let history =
        JSON.parse(
            localStorage.getItem(
                "wifiSentinelHistory"
            ) || "[]"
        );


    const entry = {

        network:
            network || "Unknown",

        time:
            new Date().toLocaleString(),

        timestamp:
            Date.now(),

        devices:
            scan
                ? scan.device_count || 0
                : 0,

        ports:
            scan
                ? scan.open_ports || 0
                : 0,

        risks:
            scan
                ? scan.risks || 0
                : 0,

        duration:
            scan
                ? scan.elapsed || 0
                : 0

    };


    /*
       Avoid duplicate consecutive scans.
    */

    if (
        history.length === 0 ||
        history[0].network !== entry.network
    ) {

        history.unshift(
            entry
        );

    } else {

        history[0] =
            entry;

    }


    history =
        history.slice(
            0,
            10
        );


    localStorage.setItem(
        "wifiSentinelHistory",
        JSON.stringify(history)
    );


    loadScanHistory();

}


/* =========================================================
   LOAD LOCAL HISTORY
========================================================= */

function loadScanHistory() {

    if (!historyContainer) {
        return;
    }


    const history =
        JSON.parse(
            localStorage.getItem(
                "wifiSentinelHistory"
            ) || "[]"
        );


    if (!history.length) {

        historyContainer.innerHTML = `

            <div class="empty-state compact">

                <div class="empty-icon">◷</div>

                <h4>No scan history</h4>

                <p>
                    Completed scans will appear here.
                </p>

            </div>

        `;

        return;
    }


    historyContainer.innerHTML =
        history.map(
            item => `

                <div class="history-item">

                    <div>

                        <div class="history-network">
                            ${escapeHTML(
                                item.network
                            )}
                        </div>

                        <span class="history-time">
                            ${escapeHTML(
                                item.time
                            )}
                        </span>

                    </div>

                    <div class="history-count">

                        ${
                            Number(item.devices) || 0
                        } DEVICES

                    </div>

                </div>

            `
        ).join("");

}


/* =========================================================
   SERVER HISTORY
========================================================= */

async function loadServerHistory() {

    try {

        const response =
            await fetch(
                "/api/history",
                {
                    method: "GET",
                    headers: {
                        "Accept":
                            "application/json"
                    },
                    cache: "no-store"
                }
            );


        if (!response.ok) {
            return;
        }


        const data =
            await response.json();


        if (
            !data.success ||
            !Array.isArray(
                data.history
            )
        ) {

            return;

        }


        /*
           Server history is available for
           future expansion.

           Local history remains visible so
           the existing UI is not changed.
        */

        console.log(
            "Server scan history:",
            data.history
        );

    } catch (error) {

        console.warn(
            "History request failed:",
            error
        );

    }

}


/* =========================================================
   CLEAR HISTORY
========================================================= */

function clearHistory() {

    localStorage.removeItem(
        "wifiSentinelHistory"
    );

    loadScanHistory();

}


if (clearHistoryButton) {

    clearHistoryButton.addEventListener(
        "click",
        clearHistory
    );

}


/* =========================================================
   DEVICE RENDERING
========================================================= */

function displayDevices(
    devices = []
) {

    if (!devicesContainer) {
        return;
    }


    if (!Array.isArray(devices)) {

        devices = [];

    }


    if (!devices.length) {

        devicesContainer.innerHTML = `

            <div class="empty-state">

                <div class="empty-icon">⌁</div>

                <h4>No devices discovered</h4>

                <p>
                    No active devices were returned by the scan.
                </p>

            </div>

        `;

        if (deviceCount) {
            deviceCount.textContent = "0";
        }

        if (deviceCountBadge) {
            deviceCountBadge.textContent = "0";
        }

        return;
    }


    if (deviceCount) {

        deviceCount.textContent =
            devices.length;

    }

    if (deviceCountBadge) {

        deviceCountBadge.textContent =
            devices.length;

    }


    devicesContainer.innerHTML =
        devices.map(
            device => {

                const ports =
                    Array.isArray(
                        device.ports
                    )
                        ? device.ports
                        : [];


                const risks =
                    Array.isArray(
                        device.risks
                    )
                        ? device.risks
                        : [];


                const riskLabel =
                    risks.length
                        ? `${risks.length} Finding(s)`
                        : "No findings";


                return `

                    <div
                        class="device-card"
                        data-ip="${escapeHTML(
                            device.ip ||
                            "Unknown"
                        )}"
                    >

                        <div class="device-header">

                            <div class="device-ip">

                                ${escapeHTML(
                                    device.ip ||
                                    "Unknown"
                                )}

                            </div>

                            <div class="device-status">
                                ● UP
                            </div>

                        </div>


                        <div class="device-info">

                            <div class="info-item">

                                <label>
                                    Hostname
                                </label>

                                <strong>
                                    ${escapeHTML(
                                        device.hostname ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="info-item">

                                <label>
                                    MAC Address
                                </label>

                                <strong>
                                    ${escapeHTML(
                                        device.mac ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="info-item">

                                <label>
                                    Open Ports
                                </label>

                                <strong>
                                    ${ports.length}
                                </strong>

                            </div>


                            <div class="info-item">

                                <label>
                                    Risk
                                </label>

                                <strong>
                                    ${escapeHTML(
                                        riskLabel
                                    )}
                                </strong>

                            </div>

                        </div>

                    </div>

                `;

            }
        ).join("");


    /*
       Update total port counter.
    */

    const totalPorts =
        devices.reduce(
            (
                total,
                device
            ) => {

                const ports =
                    Array.isArray(
                        device.ports
                    )
                        ? device.ports
                        : [];

                return total +
                    ports.filter(
                        port =>
                            port.state === "open"
                    ).length;

            },
            0
        );


    if (portCount) {

        portCount.textContent =
            totalPorts;

    }

}


/* =========================================================
   COLLECT RISKS FROM DEVICES
========================================================= */

function collectRisks(
    devices = []
) {

    const risks = [];


    devices.forEach(
        device => {

            if (
                !Array.isArray(
                    device.risks
                )
            ) {
                return;
            }


            device.risks.forEach(
                risk => {

                    risks.push({

                        ...risk,

                        ip:
                            device.ip ||
                            "Unknown",

                        hostname:
                            device.hostname ||
                            "Unknown"

                    });

                }
            );

        }
    );


    return risks;

}


/* =========================================================
   RISK RENDERING
========================================================= */

function displayRisks(
    risks = []
) {

    if (!risksContainer) {
        return;
    }


    if (!Array.isArray(risks)) {

        risks = [];

    }


    if (!risks.length) {

        risksContainer.innerHTML = `

            <div class="empty-state compact">

                <div class="empty-icon">✓</div>

                <h4>No security findings</h4>

                <p>
                    No potential defensive findings were returned.
                </p>

            </div>

        `;

        if (riskCount) {

            riskCount.textContent =
                "0";

        }

        return;
    }


    if (riskCount) {

        riskCount.textContent =
            risks.length;

    }


    risksContainer.innerHTML =
        risks.map(
            risk => {

                const level =
                    String(
                        risk.severity ||
                        risk.level ||
                        "low"
                    ).toLowerCase();


                return `

                    <div class="risk-card">

                        <div class="risk-icon">
                            ⚠
                        </div>

                        <div>

                            <h4>
                                ${escapeHTML(
                                    risk.title ||
                                    "Potential exposure"
                                )}
                            </h4>

                            <p>
                                ${escapeHTML(
                                    risk.description ||
                                    "Review this finding."
                                )}
                            </p>

                            ${
                                risk.protection
                                    ? `
                                        <p>
                                            <strong>
                                                Protection:
                                            </strong>
                                            ${escapeHTML(
                                                risk.protection
                                            )}
                                        </p>
                                      `
                                    : ""
                            }

                        </div>

                        <div class="risk-level ${escapeHTML(
                            level
                        )}">

                            ${escapeHTML(
                                level.toUpperCase()
                            )}

                        </div>

                    </div>

                `;

            }
        ).join("");

}


/* =========================================================
   SAFE HTML
========================================================= */

function escapeHTML(
    value
) {

    return String(
        value ?? ""
    )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );

}


/* =========================================================
   EVENT LISTENERS
========================================================= */

if (scanButton) {

    scanButton.addEventListener(
        "click",
        startScan
    );

}


if (networkInput) {

    networkInput.addEventListener(
        "keydown",
        event => {

            if (
                event.key ===
                "Enter"
            ) {

                event.preventDefault();

                startScan();

            }

        }
    );

}


/* =========================================================
   INITIALIZATION
========================================================= */

loadScanHistory();

loadServerHistory();


console.log(
    "WiFi Sentinel V2.0 dashboard loaded."
);