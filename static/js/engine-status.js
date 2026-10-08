(() => {
    const badge = document.querySelector(".nmap-engine-badge");
    const status = document.getElementById("nmap-engine-status");
    const version = document.getElementById("nmap-engine-version");
    if (!badge || !status || !version) return;

    fetch("/api/health", { headers: { Accept: "application/json" } })
        .then(async (response) => {
            const health = await response.json();
            if (!response.ok || health.nmap !== true) {
                throw new Error(health.error || "Nmap is unavailable.");
            }
            badge.classList.add("is-ready");
            status.textContent = "READY";
            version.textContent = health.nmap_version || "Version unavailable";
        })
        .catch(() => {
            badge.classList.add("is-offline");
            status.textContent = "OFFLINE";
            version.textContent = "Nmap not found in PATH";
        });
})();
