(() => {
    const dataElement = document.getElementById("history-data");
    const rows = [...document.querySelectorAll("#history-rows tr[data-record-index]")];
    if (!dataElement) return;

    const records = JSON.parse(dataElement.textContent || "[]");
    const search = document.getElementById("history-search");
    const moduleFilter = document.getElementById("module-filter");
    const statusFilter = document.getElementById("status-filter");
    const exportButton = document.getElementById("export-csv");
    const compareButton = document.getElementById("compare-scans");
    const selectionCount = document.getElementById("selection-count");
    const selectionHint = document.getElementById("selection-hint");
    const noResults = document.getElementById("no-filter-results");
    const dialog = document.getElementById("comparison-dialog");
    const comparisonTable = document.getElementById("comparison-table");

    function selectedRecords() {
        return rows
            .filter((row) => row.querySelector(".scan-select")?.checked)
            .map((row) => records[Number(row.dataset.recordIndex)])
            .filter(Boolean);
    }

    function updateFilters() {
        const query = search.value.trim().toLowerCase();
        const module = moduleFilter.value;
        const status = statusFilter.value;
        let visibleCount = 0;

        for (const row of rows) {
            const record = records[Number(row.dataset.recordIndex)];
            const haystack = [record.module, record.target, record.timestamp, record.status, record.coverage]
                .concat(record.detail || "", (record.limitations || []).join(" "))
                .join(" ")
                .toLowerCase();
            const moduleMatches = module === "all" || record.module_key === module;
            const normalizedStatus = String(record.status || "").toLowerCase();
            const statusMatches = status === "all"
                || (status === "failed" ? normalizedStatus.includes("fail") || normalizedStatus.includes("error") : status === "partial" ? normalizedStatus === "partial" || normalizedStatus === "incomplete" : normalizedStatus === status);
            const matches = moduleMatches && statusMatches && haystack.includes(query);
            row.hidden = !matches;
            if (!matches) row.querySelector(".scan-select").checked = false;
            if (matches) visibleCount += 1;
        }
        noResults.hidden = visibleCount > 0;
        updateSelection();
    }

    function updateSelection() {
        const checked = selectedRecords().length;
        selectionCount.textContent = `${checked}/2`;
        compareButton.disabled = checked !== 2;
        selectionHint.textContent = checked === 0
            ? "Select two scans to compare their coverage and results."
            : checked === 1
                ? "Select one more scan to compare."
                : "Two scans selected. Compare their coverage and reported metrics.";
    }

    exportButton.addEventListener("click", () => {
        const params = new URLSearchParams({
            q: search.value.trim(),
            module: moduleFilter.value,
            status: statusFilter.value,
        });
        window.location.assign(`/history/export.csv?${params.toString()}`);
    });

    function renderComparison(first, second) {
        comparisonTable.replaceChildren();
        const head = document.createElement("thead");
        const headRow = document.createElement("tr");
        for (const label of ["MEASURE", `${first.module} · ${first.target}`, `${second.module} · ${second.target}`]) {
            const cell = document.createElement("th");
            cell.textContent = label;
            headRow.append(cell);
        }
        head.append(headRow);
        const body = document.createElement("tbody");
        const labels = ["Date", "Status", "Coverage", ...new Set([...Object.keys(first.metrics || {}), ...Object.keys(second.metrics || {})]), "Limitations"];
        for (const label of labels) {
            const row = document.createElement("tr");
            const heading = document.createElement("th");
            heading.textContent = label;
            row.append(heading);
            for (const record of [first, second]) {
                const cell = document.createElement("td");
                if (label === "Date") cell.textContent = record.timestamp || "Unknown";
                else if (label === "Status") cell.textContent = record.status || "Unknown";
                else if (label === "Coverage") cell.textContent = record.coverage || "Unavailable";
                else if (label === "Limitations") cell.textContent = (record.limitations || []).join("; ") || "None recorded";
                else cell.textContent = record.metrics?.[label] ?? "Not recorded";
                row.append(cell);
            }
            body.append(row);
        }
        comparisonTable.append(head, body);
    }

    compareButton.addEventListener("click", () => {
        const selected = selectedRecords();
        if (selected.length !== 2) return;
        renderComparison(selected[0], selected[1]);
        dialog.showModal();
    });

    search.addEventListener("input", updateFilters);
    moduleFilter.addEventListener("change", updateFilters);
    statusFilter.addEventListener("change", updateFilters);
    document.querySelectorAll(".scan-select").forEach((checkbox) => checkbox.addEventListener("change", () => {
        const checked = selectedRecords();
        if (checked.length > 2) {
            checkbox.checked = false;
            selectionHint.textContent = "Choose exactly two scans for comparison.";
        }
        updateSelection();
    }));
    updateSelection();
})();
