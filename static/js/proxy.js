"use strict";

(() => {
    const byId = (id) => document.getElementById(id);
    const optionalById = (id) => byId(id) || null;
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
    const state = {running: false, settings: {}, page: 1, pageSize: 80, total: 0, websocketPage: 1, websocketPageSize: 80, websocketTotal: 0, selectedId: "", selected: null, selectedWebsocket: null, activeTab: "intercept", views: {request: "raw", response: "raw"}, queue: [], matchPreview: null, listenerNoticeDismissed: false};
    const filterIds = ["filter-search", "filter-method", "filter-status", "filter-host", "filter-path"];
    const dialog = byId("request-edit-dialog");
    let editOriginal = null;

    async function api(path, options = {}) {
        const headers = {...(options.headers || {})};
        if (options.body) headers["Content-Type"] = "application/json";
        if (csrf && options.method && options.method !== "GET") headers["X-CSRF-Token"] = csrf;
        const response = await fetch(path, {...options, headers});
        const type = response.headers.get("content-type") || "";
        const payload = type.includes("application/json") ? await response.json() : null;
        if (!response.ok || payload?.success === false) throw new Error(payload?.error || `Request failed (${response.status}).`);
        return payload;
    }

    function showError(message = "") {
        const element = byId("proxy-error");
        element.textContent = message;
        element.hidden = !message;
    }

    function setState(status) {
        state.running = status.running === true;
        state.settings = status.settings || state.settings;
        const badge = optionalById("proxy-state");
        if (badge) badge.dataset.state = status.state || "stopped";
        const labels = {starting: "PROXY STARTING", running: "PROXY RUNNING", stopping: "PROXY STOPPING", error: "PROXY ERROR", stopped: "PROXY STOPPED"};
        const stateLabel = optionalById("proxy-state-label");
        if (stateLabel) stateLabel.textContent = labels[status.state] || "PROXY STOPPED";
        const listenerLabel = optionalById("proxy-listener-label");
        if (listenerLabel) listenerLabel.textContent = status.running ? status.listener : `${status.address || "127.0.0.1"}:${status.port || 8080}`;
        const statusDetail = optionalById("proxy-status-detail");
        if (statusDetail) statusDetail.textContent = status.running ? `Proxy listening on ${status.listener}` : status.error || (status.state === "starting" ? "Starting proxy…" : "Proxy stopped");
        const modeCommand = optionalById("proxy-mode-command");
        if (modeCommand) modeCommand.textContent = status.settings?.intercept ? "INTERCEPT" : "PASSIVE";
        const listenerCommand = optionalById("listener-command");
        if (listenerCommand) listenerCommand.textContent = status.running ? status.listener : `${status.address || "127.0.0.1"}:${status.port || 8080}`;
        const banner = optionalById("proxy-listener-banner");
        if (banner) banner.hidden = status.running || state.listenerNoticeDismissed;
        const bannerText = optionalById("proxy-listener-banner-text");
        if (bannerText) bannerText.textContent = status.state === "starting"
            ? "Starting proxy listener…"
            : status.error ? `Proxy listener error: ${status.error}` : "No proxy listeners are currently running";
        for (const id of ["proxy-enable", "proxy-start", "proxy-stop", "replay-send", "proxy-intercept-toggle"]) {
            const element = optionalById(id);
            if (!element) continue;
            if (id === "proxy-enable") element.disabled = status.running || status.state === "starting" || status.state === "stopping";
            if (id === "proxy-enable") element.textContent = status.state === "error" ? "Retry" : "Enable";
            if (id === "proxy-start") element.disabled = status.running || status.state === "starting" || status.state === "stopping";
            if (id === "proxy-stop") element.disabled = !status.running && status.state !== "starting";
            if (id === "replay-send") element.disabled = !state.running || !state.selected;
            if (id === "proxy-intercept-toggle") {
                element.disabled = !state.running;
                element.textContent = status.settings?.intercept ? "Intercept on" : "Intercept off";
                element.setAttribute("aria-pressed", String(status.settings?.intercept === true));
            }
        }
        const guideListener = optionalById("guide-listener");
        if (guideListener) guideListener.textContent = `${status.address || "127.0.0.1"}:${status.port || 8080}`;
        for (const button of document.querySelectorAll("[data-open-browser]")) button.disabled = !state.running;
        for (const [key, id] of [["requests", "stat-requests"], ["responses", "stat-responses"], ["2xx", "stat-2xx"], ["3xx", "stat-3xx"], ["4xx", "stat-4xx"], ["5xx", "stat-5xx"], ["https", "stat-https"], ["errors", "stat-errors"], ["intercepted", "stat-intercepted"]]) {
            const element = optionalById(id);
            if (element) element.textContent = String(status.statistics?.[key] ?? 0);
        }
        const proxyAddress = optionalById("proxy-address");
        const proxyPort = optionalById("proxy-port");
        const settingHistory = optionalById("setting-max-history");
        const settingBody = optionalById("setting-max-body");
        const settingHistoryEnabled = optionalById("setting-history-enabled");
        const settingRequestBody = optionalById("setting-request-body");
        const settingResponseBody = optionalById("setting-response-body");
        const settingHttps = optionalById("setting-https");
        if (proxyAddress) proxyAddress.value = status.settings?.address || status.address || "127.0.0.1";
        if (proxyPort) proxyPort.value = String(status.settings?.port || status.port || 8080);
        if (settingHistory) settingHistory.value = String(status.settings?.max_history_entries || 500);
        if (settingBody) settingBody.value = String(status.settings?.max_body_size || 131072);
        if (settingHistoryEnabled) settingHistoryEnabled.checked = status.settings?.history_enabled !== false;
        if (settingRequestBody) settingRequestBody.checked = status.settings?.capture_request_body !== false;
        if (settingResponseBody) settingResponseBody.checked = status.settings?.capture_response_body !== false;
        if (settingHttps) settingHttps.checked = status.settings?.https_interception === true;
        setCaState(status.ca_ready);
        const generateCa = optionalById("generate-ca");
        if (generateCa) generateCa.disabled = status.running || status.state === "starting" || status.state === "stopping";
        updateInterceptControls();
        if (status.error) showError(status.error);
    }

    function currentIntercept() {
        return state.queue.find((item) => item.id === state.selectedId) || state.queue[0] || null;
    }

    function updateInterceptControls() {
        const enabled = state.settings.intercept === true;
        const pending = currentIntercept();
        const forwardSelected = optionalById("proxy-forward-selected");
        const dropSelected = optionalById("proxy-drop-selected");
        if (forwardSelected) forwardSelected.disabled = !pending;
        if (dropSelected) dropSelected.disabled = !pending;
        const empty = optionalById("intercept-empty-state");
        if (empty) empty.hidden = state.queue.length > 0;
        const emptyTitle = optionalById("intercept-empty-title");
        const emptyCopy = optionalById("intercept-empty-copy");
        if (emptyTitle) emptyTitle.textContent = enabled ? "Intercept is on" : "Interception is off";
        if (emptyCopy) emptyCopy.textContent = enabled
            ? "Waiting for a real request from a client configured to use this listener."
            : "Requests pass through automatically. Turn interception on to pause each new request for review.";
        const toggle = optionalById("proxy-intercept-toggle");
        if (toggle) {
            toggle.textContent = `◉ Intercept ${enabled ? "on" : "off"}`;
            toggle.disabled = !state.running;
            toggle.setAttribute("aria-pressed", String(enabled));
        }
        const treeToggle = optionalById("proxy-tree-intercept-toggle");
        if (treeToggle) {
            treeToggle.textContent = enabled ? "Intercept on" : "Intercept off";
            treeToggle.setAttribute("aria-pressed", String(enabled));
        }
    }

    function switchWorkspace(tabName) {
        state.activeTab = tabName;
        for (const tab of document.querySelectorAll(".burp-tabs [data-proxy-tab]")) {
            const active = tab.dataset.proxyTab === tabName;
            tab.setAttribute("aria-selected", String(active));
            tab.tabIndex = active ? 0 : -1;
        }
        for (const panel of document.querySelectorAll("[data-proxy-panel]")) {
            panel.hidden = panel.dataset.proxyPanel !== tabName;
        }
        for (const tool of document.querySelectorAll("[data-proxy-tool]")) {
            const active = tool.dataset.proxyTool === tabName;
            tool.hidden = !active;
            if (active) tool.open = true;
        }
    }

    function setCaState(ready) {
        const caStatus = optionalById("ca-status");
        const exportCa = optionalById("export-ca");
        if (caStatus) caStatus.textContent = ready ? "Ready · local certificate generated" : "Not configured";
        if (exportCa) exportCa.hidden = !ready;
    }

    function humanSize(value) {
        const bytes = Number(value) || 0;
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    function setCell(row, text, className = "") {
        const cell = document.createElement("td");
        cell.textContent = text || "—";
        if (className) cell.className = className;
        row.append(cell);
        return cell;
    }

    async function loadHistory() {
        const params = new URLSearchParams({page: String(state.page), page_size: String(state.pageSize)});
        const names = {"filter-search": "q", "filter-method": "method", "filter-status": "status", "filter-content-type": "content_type", "filter-host": "host", "filter-path": "path"};
        for (const [id, name] of Object.entries(names)) {
            const element = optionalById(id);
            if (!element) continue;
            const value = element.value.trim();
            if (value && value !== "all") params.set(name, value);
        }
        const result = await api(`/api/proxy/history?${params}`);
        state.total = result.total;
        const body = byId("proxy-history-rows");
        body.replaceChildren();
        if (!result.items.length) {
            const row = document.createElement("tr");
            const empty = setCell(row, "No matching captured traffic.", "burp-empty");
            empty.colSpan = 8;
            body.append(row);
        }
        for (const [index, item] of result.items.entries()) {
            const row = document.createElement("tr");
            row.dataset.requestId = item.id;
            row.classList.toggle("is-selected", item.id === state.selectedId);
            setCell(row, String((result.page - 1) * result.page_size + index + 1));
            setCell(row, item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : "—");
            setCell(row, (item.scheme || item.url || "").toLowerCase().startsWith("https") ? "HTTPS" : "HTTP");
            setCell(row, "→ Request");
            setCell(row, item.method, "method");
            setCell(row, item.url || item.path, "url");
            setCell(row, item.status ? String(item.status) : item.state, "status");
            setCell(row, humanSize((Number(item.request_size) || 0) + (Number(item.response_size) || 0)));
            row.addEventListener("click", () => selectRequest(item.id));
            body.append(row);
        }
        const first = result.total ? (result.page - 1) * result.page_size + 1 : 0;
        const last = Math.min(result.total, result.page * result.page_size);
        byId("history-page-label").textContent = result.total ? `${first}–${last} of ${result.total}` : "0 requests";
        byId("history-prev").disabled = result.page <= 1;
        byId("history-next").disabled = last >= result.total;
        const historyCount = optionalById("history-count");
        if (historyCount) historyCount.textContent = String(result.total);
    }

    function headersText(headers) {
        return (headers || []).map(([name, value]) => `${name}: ${value}`).join("\n") || "No headers captured.";
    }

    function activeRequestView(detail) {
        const view = state.views.request;
        if (view === "headers") return headersText(detail.request_headers);
        if (view === "params") return JSON.stringify({query: detail.query || [], form: detail.form_parameters || []}, null, 2);
        if (view === "body") return detail.request_body?.text || "No request body captured.";
        return detail.raw_request || "No raw request available.";
    }

    function activeResponseView(detail) {
        const view = state.views.response;
        if (view === "headers") return headersText(detail.response_headers);
        if (view === "body") return detail.response_body?.text || (detail.response_status ? "No response body captured." : "Waiting for response.");
        return detail.raw_response || "No response captured yet.";
    }

    function renderDetail() {
        const detail = state.selected;
        const empty = !detail;
        const selectedIntercept = state.queue.find((item) => item.id === state.selectedId) || null;
        byId("inspector-kicker").textContent = empty ? "SELECT A CAPTURE" : `${detail.scheme?.toUpperCase()} · ${detail.host}:${detail.port}`;
        byId("inspector-title").textContent = empty ? "Request" : `${detail.method} ${detail.path}`;
        byId("request-line-label").textContent = empty ? "No request selected" : `${detail.method} ${detail.path} ${detail.protocol || detail.http_version}`;
        byId("response-line-label").textContent = empty ? "Waiting for response" : detail.response_status ? `${detail.response_status} ${detail.response_reason || ""} · ${detail.duration_ms ?? "—"} ms` : detail.error || detail.state;
        const summary = byId("request-protocol-summary");
        summary.hidden = empty;
        byId("protocol-value").textContent = detail?.protocol || detail?.http_version || "—";
        byId("authority-value").textContent = detail?.authority || detail?.host || "—";
        byId("cookies-value").textContent = detail?.cookies?.length ? detail.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ") : "—";
        const responseProtocol = byId("response-protocol");
        responseProtocol.hidden = empty || !detail?.response_status;
        byId("response-protocol-value").textContent = detail?.response_protocol || detail?.response_http_version || "HTTP response";
        byId("request-content").textContent = empty ? "Choose a real captured request from HTTP history." : activeRequestView(detail);
        byId("response-content").textContent = empty ? "Response details appear when the destination replies." : activeResponseView(detail);
        for (const side of ["request", "response"]) {
            const panel = byId(`${side}-content`);
            for (const tab of document.querySelectorAll(`[data-side="${side}"]`)) {
                const active = tab.dataset.view === state.views[side];
                tab.setAttribute("aria-selected", String(active));
                tab.tabIndex = active ? 0 : -1;
                tab.classList.toggle("active", active);
                if (active) panel.setAttribute("aria-labelledby", tab.id);
            }
        }
        const selected = detail !== null;
        const intercepted = Boolean(detail?.intercepted);
        const contextMethod = optionalById("context-method");
        const contextUrl = optionalById("context-url");
        const contextProtocol = optionalById("context-protocol");
        const contextHost = optionalById("context-host");
        const contextStatus = optionalById("context-status");
        const contextSize = optionalById("context-size");
        if (contextMethod) contextMethod.textContent = empty ? "—" : detail.method;
        if (contextUrl) contextUrl.textContent = empty ? "Select a captured request" : detail.url || detail.path;
        if (contextProtocol) contextProtocol.textContent = empty ? "—" : detail.protocol || detail.http_version || "HTTP";
        if (contextHost) contextHost.textContent = empty ? "—" : detail.host || detail.authority || "—";
        if (contextStatus) contextStatus.textContent = empty ? "—" : detail.response_status ? `${detail.response_status} ${detail.response_reason || ""}`.trim() : detail.state || "Pending";
        if (contextSize) contextSize.textContent = empty ? "0 B" : humanSize((Number(detail.request_size) || 0) + (Number(detail.response_size) || 0));
        const contextForward = optionalById("context-forward");
        const contextDrop = optionalById("context-drop");
        const contextReplay = optionalById("context-replay");
        if (contextForward) contextForward.disabled = !selectedIntercept;
        if (contextDrop) contextDrop.disabled = !selectedIntercept;
        if (contextReplay) contextReplay.disabled = !selected;
        const copyCurl = optionalById("copy-curl");
        const openReplay = optionalById("open-replay");
        const editRequest = optionalById("edit-request");
        if (copyCurl) copyCurl.disabled = !selected;
        if (openReplay) openReplay.disabled = !selected;
        if (editRequest) {
            editRequest.disabled = !selectedIntercept;
            editRequest.textContent = detail?.modified ? "Edit intercepted request · MODIFIED" : "Edit intercepted request";
        }
        for (const id of ["proxy-inspector-forward", "proxy-inspector-drop"]) {
            const button = optionalById(id);
            if (!button) continue;
            button.disabled = !selectedIntercept;
            button.title = selectedIntercept
                ? `Decision for selected request: ${id === "proxy-inspector-forward" ? "Forward" : "Drop"}`
                : "Select an intercepted request to make this decision";
            button.classList.toggle("is-active", Boolean(selectedIntercept));
        }
    }

    async function selectRequest(id, provided = null) {
        state.selectedId = id;
        try {
            const result = provided ? {request: provided} : await api(`/api/proxy/history/${encodeURIComponent(id)}`);
            state.selected = result.request;
            renderDetail();
            for (const row of document.querySelectorAll("[data-request-id]")) row.classList.toggle("is-selected", row.dataset.requestId === id);
            if (state.selected && !state.selected.intercepted) fillReplay(state.selected);
        } catch (error) {
            showError(error.message);
        }
    }

    async function loadWebsockets() {
        const params = new URLSearchParams({page: String(state.websocketPage), page_size: String(state.websocketPageSize)});
        const search = byId("websocket-search").value.trim();
        if (search) params.set("q", search);
        const result = await api(`/api/proxy/websockets?${params}`);
        state.websocketTotal = result.total;
        const rows = byId("proxy-websocket-rows");
        rows.replaceChildren();
        if (!result.items.length) {
            const row = document.createElement("tr");
            const cell = setCell(row, "No WebSocket messages captured.", "proxy-empty");
            cell.colSpan = 7;
            rows.append(row);
        }
        for (const item of result.items) {
            const row = document.createElement("tr");
            row.dataset.websocketId = item.id;
            setCell(row, new Date(item.timestamp).toLocaleTimeString());
            setCell(row, item.host);
            setCell(row, item.path, "proxy-path-cell");
            setCell(row, item.direction);
            setCell(row, item.type);
            setCell(row, humanSize(item.size));
            setCell(row, item.payload, "proxy-path-cell");
            row.addEventListener("click", () => {
                state.selectedWebsocket = item;
                for (const candidate of rows.querySelectorAll("tr[data-websocket-id]")) candidate.classList.toggle("is-selected", candidate === row);
                byId("websocket-frame-detail").textContent = `${item.timestamp}\n${item.direction} · ${item.type} · ${item.size} bytes\n${item.host}${item.path}\n\n${item.payload}${item.truncated ? "\n[Frame preview truncated.]" : ""}`;
            });
            rows.append(row);
        }
        const first = result.total ? (result.page - 1) * result.page_size + 1 : 0;
        const last = Math.min(result.total, result.page * result.page_size);
        byId("websocket-page-label").textContent = result.total ? `${first}–${last} of ${result.total} messages` : "0 messages";
        byId("websocket-prev").disabled = result.page <= 1;
        byId("websocket-next").disabled = last >= result.total;
    }

    function appendEvent(message) {
        const list = byId("proxy-event-log-rows");
        if (list.children.length === 1 && list.firstElementChild.textContent === "Proxy events will appear here.") list.replaceChildren();
        const row = document.createElement("li");
        const time = document.createElement("time");
        time.textContent = new Date().toLocaleTimeString();
        const text = document.createElement("span");
        text.textContent = message;
        row.append(time, text);
        list.append(row);
        while (list.children.length > 100) list.firstElementChild.remove();
        byId("proxy-event-count").textContent = `${list.children.length} events`;
    }

    function fillReplay(detail) {
        byId("replay-method").value = detail.method;
        byId("replay-url").value = detail.url;
        const safeHeaders = Object.fromEntries((detail.request_headers || []).filter(([name]) => !["host", "content-length", "connection", "proxy-connection", "transfer-encoding"].includes(name.toLowerCase())));
        byId("replay-headers").value = JSON.stringify(safeHeaders, null, 2);
        byId("replay-body").value = detail.request_body?.kind === "text" ? detail.request_body.text : "";
        byId("replay-send").disabled = !state.running;
    }

    async function loadQueue() {
        const result = await api("/api/proxy/intercepts");
        state.queue = result.requests;
        byId("proxy-panel-intercept").classList.toggle("has-queue", state.queue.length > 0);
        updateMatchRequestOptions();
        const list = byId("intercept-queue");
        list.replaceChildren();
        byId("intercept-count").textContent = `${state.queue.length} waiting`;
        byId("proxy-intercepts").hidden = state.queue.length === 0;
        if (!state.queue.length) {
            const empty = document.createElement("p");
            empty.className = "proxy-empty";
            empty.textContent = "No requests waiting for a decision.";
            list.append(empty);
            updateInterceptControls();
            return;
        }
        const heading = byId("intercept-heading");
        heading.textContent = state.queue.length === 1 ? "1 paused request" : `${state.queue.length} paused requests`;
        for (const item of state.queue) {
            const card = document.createElement("article");
            card.className = "proxy-queue-item";
            const heading = document.createElement("div");
            heading.className = "proxy-queue-heading";
            const line = document.createElement("strong");
            line.textContent = `${item.method} ${item.path}`;
            const host = document.createElement("span");
            host.textContent = `${item.host}:${item.port}`;
            heading.append(line, host);
            const raw = document.createElement("pre");
            raw.textContent = item.raw_request || "Request headers captured; body exceeds the configured capture limit.";
            const actions = document.createElement("div");
            actions.className = "proxy-queue-actions";
            const edit = button("Edit Request", "proxy-button-secondary", () => openEditor(item));
            edit.disabled = item.request_body?.truncated === true || item.request_body?.kind === "disabled";
            const forward = button("Forward", "proxy-button-primary", () => resolveIntercept(item.id, "forward"));
            const drop = button("Drop", "proxy-button-danger", () => resolveIntercept(item.id, "drop"));
            actions.append(edit, forward, drop);
            card.append(heading, raw, actions);
            card.addEventListener("click", (event) => {
                if (event.target.closest("button")) return;
                state.selectedId = item.id;
                state.selected = item;
                updateInterceptControls();
                renderDetail();
            });
            list.append(card);
        }
        updateInterceptControls();
    }

    function updateMatchRequestOptions() {
        const select = byId("match-request-select");
        const previous = select.value;
        select.replaceChildren(new Option("Select a waiting request", ""));
        for (const item of state.queue) {
            select.add(new Option(`${item.method} ${item.host}${item.path}`, item.id));
        }
        select.value = state.queue.some((item) => item.id === previous) ? previous : state.queue[0]?.id || "";
        byId("preview-replace").disabled = !select.value;
        if (!select.value) byId("open-replace-editor").disabled = true;
    }

    function previewReplacement() {
        const requestId = byId("match-request-select").value;
        const detail = state.queue.find((item) => item.id === requestId);
        const find = byId("match-find").value;
        const replacement = byId("match-replace").value;
        if (!detail || !find) {
            byId("match-preview").textContent = "Select a waiting request and enter text to find.";
            state.matchPreview = null;
            byId("open-replace-editor").disabled = true;
            return;
        }
        const field = byId("match-field").value;
        let source;
        if (field === "body") source = detail.request_body?.kind === "text" ? detail.request_body.text : "";
        else if (field === "url") source = detail.url;
        else source = JSON.stringify(Object.fromEntries(detail.request_headers || []), null, 2);
        if (!source.includes(find)) {
            byId("match-preview").textContent = "No literal match was found in the selected request field.";
            state.matchPreview = null;
            byId("open-replace-editor").disabled = true;
            return;
        }
        const count = source.split(find).length - 1;
        const result = source.split(find).join(replacement);
        byId("match-preview").textContent = `PREVIEW ONLY · ${count} replacement${count === 1 ? "" : "s"}\n\n${result}`;
        state.matchPreview = {requestId, field, result};
        byId("open-replace-editor").disabled = false;
    }

    function button(label, className, handler) {
        const element = document.createElement("button");
        element.type = "button";
        element.className = `proxy-button ${className}`;
        element.textContent = label;
        element.addEventListener("click", handler);
        return element;
    }

    async function resolveIntercept(id, action, modifiedRequest = null) {
        try {
            const payload = modifiedRequest ? {modified: true, modified_request: modifiedRequest} : {};
            const result = await api(`/api/proxy/intercepts/${encodeURIComponent(id)}/${action}`, {method: "POST", body: JSON.stringify(payload)});
            if (result.request) await selectRequest(id, result.request);
            await Promise.all([loadQueue(), loadHistory(), loadStatus()]);
            if (dialog.open) dialog.close();
            showError("");
        } catch (error) {
            byId("edit-error").textContent = error.message;
            byId("edit-error").hidden = false;
            showError(error.message);
        }
    }

    function openEditor(detail, proposal = {}) {
        state.selected = detail;
        state.selectedId = detail.id;
        const headers = Object.fromEntries(detail.request_headers || []);
        editOriginal = {
            method: detail.method,
            url: detail.url,
            headers: JSON.stringify(headers, null, 2),
            body: detail.request_body?.kind === "text" ? detail.request_body.text : "",
        };
        byId("edit-method").value = proposal.method ?? editOriginal.method;
        byId("edit-url").value = proposal.url ?? editOriginal.url;
        byId("edit-headers").value = proposal.headers ?? editOriginal.headers;
        byId("edit-body").value = proposal.body ?? editOriginal.body;
        updateModifiedIndicator();
        byId("edit-error").hidden = true;
        dialog.showModal();
    }

    function openMatchPreviewInEditor() {
        if (!state.matchPreview) return;
        const detail = state.queue.find((item) => item.id === state.matchPreview.requestId);
        if (!detail) return;
        const proposal = {};
        proposal[state.matchPreview.field] = state.matchPreview.result;
        openEditor(detail, proposal);
        switchWorkspace("intercept");
    }

    function updateModifiedIndicator() {
        if (!editOriginal) return;
        const modified = editOriginal.method !== byId("edit-method").value
            || editOriginal.url !== byId("edit-url").value
            || editOriginal.headers !== byId("edit-headers").value
            || editOriginal.body !== byId("edit-body").value;
        byId("edit-modified-state").hidden = !modified;
        byId("forward-modified").textContent = modified ? "Forward Modified Request" : "Forward Request";
    }

    function buildCurl(detail) {
        const quote = (value) => `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("%", "%%")}"`;
        const parts = ["curl", "--request", quote(detail.method), quote(detail.url)];
        for (const [name, value] of detail.request_headers || []) parts.push("--header", quote(`${name}: ${value}`));
        if (detail.request_body?.kind === "text" && detail.request_body.text) parts.push("--data-raw", quote(detail.request_body.text));
        return parts.join(" ");
    }

    function copyText(text, buttonElement) {
        navigator.clipboard.writeText(text).then(() => {
            if (!buttonElement) return;
            const old = buttonElement.textContent;
            buttonElement.textContent = "Copied";
            setTimeout(() => { buttonElement.textContent = old; }, 1200);
        }).catch(() => showError("Clipboard access is unavailable in this browser context."));
    }

    async function applySettings(payload) {
        const result = await api("/api/proxy/settings", {method: "POST", body: JSON.stringify(payload)});
        state.settings = result.settings;
        setState({...result, running: result.state === "running"});
        showError("");
        return result;
    }

    function settingsPayload() {
        return {
            max_history_entries: Number(byId("setting-max-history").value),
            max_body_size: Number(byId("setting-max-body").value),
            history_enabled: byId("setting-history-enabled").checked,
            capture_request_body: byId("setting-request-body").checked,
            capture_response_body: byId("setting-response-body").checked,
            https_interception: byId("setting-https").checked,
        };
    }

    async function loadStatus() {
        try {
            const status = await api("/api/proxy/status");
            setState(status);
        } catch (error) { showError(error.message); }
    }

    async function refresh() {
        try { await Promise.all([loadStatus(), loadHistory(), loadQueue()]); }
        catch (error) { showError(error.message); }
    }

    async function startProxy() {
        showError("");
        state.listenerNoticeDismissed = false;
        try {
            const result = await api("/api/proxy/start", {method: "POST", body: JSON.stringify({address: byId("proxy-address").value, port: Number(byId("proxy-port").value)})});
            setState(result);
            appendEvent(`Proxy listening on ${result.listener}.`);
            await refresh();
        } catch (error) { showError(error.message); await loadStatus(); }
    }

    byId("proxy-start").addEventListener("click", startProxy);
    const proxyEnable = optionalById("proxy-enable");
    if (proxyEnable) proxyEnable.addEventListener("click", startProxy);
    const proxyBannerClose = optionalById("proxy-banner-close");
    if (proxyBannerClose) proxyBannerClose.addEventListener("click", () => {
        state.listenerNoticeDismissed = true;
        const banner = optionalById("proxy-listener-banner");
        if (banner) banner.hidden = true;
    });

    byId("proxy-stop").addEventListener("click", async () => {
        try {
            setState(await api("/api/proxy/stop", {method: "POST", body: "{}"}));
            appendEvent("Proxy listener stopped.");
            await refresh();
        }
        catch (error) { showError(error.message); }
    });

    byId("proxy-settings-save").addEventListener("click", async () => {
        try {
            const result = await applySettings({address: byId("proxy-address").value, port: Number(byId("proxy-port").value)});
            if (!result.running) byId("proxy-status-detail").textContent = `Ready to start on ${result.settings.address}:${result.settings.port}`;
        } catch (error) { showError(error.message); }
    });

    async function setIntercept(enabled) {
        try {
            await applySettings({intercept: enabled});
            await loadQueue();
            appendEvent(`Intercept ${enabled ? "enabled" : "disabled"}.`);
        } catch (error) { showError(error.message); await loadStatus(); }
    }

    const proxyInterceptToggle = optionalById("proxy-intercept-toggle");
    if (proxyInterceptToggle) proxyInterceptToggle.addEventListener("click", () => setIntercept(state.settings.intercept !== true));
    const proxyTreeInterceptToggle = optionalById("proxy-tree-intercept-toggle");
    if (proxyTreeInterceptToggle) proxyTreeInterceptToggle.addEventListener("click", () => setIntercept(state.settings.intercept !== true));

    byId("proxy-inspector-forward").addEventListener("click", () => {
        const pending = currentIntercept();
        if (pending) resolveIntercept(pending.id, "forward");
    });
    byId("proxy-inspector-drop").addEventListener("click", () => {
        const pending = currentIntercept();
        if (pending) resolveIntercept(pending.id, "drop");
    });
    for (const id of ["context-forward", "context-drop"]) {
        byId(id).addEventListener("click", () => {
            const pending = currentIntercept();
            if (pending) resolveIntercept(pending.id, id === "context-forward" ? "forward" : "drop");
        });
    }
    byId("context-replay").addEventListener("click", () => {
        if (state.selected) {
            fillReplay(state.selected);
            switchWorkspace("replay");
        }
    });
    byId("copy-listener").addEventListener("click", () => {
        const address = state.running ? byId("proxy-listener-label").textContent : `${byId("proxy-address").value}:${byId("proxy-port").value}`;
        copyText(address, byId("copy-listener"));
    });

    byId("proxy-connection-help").addEventListener("click", () => {
        const guide = byId("proxy-connection-guide");
        guide.hidden = !guide.hidden;
        byId("proxy-connection-help").setAttribute("aria-expanded", String(!guide.hidden));
    });

    async function openProxyBrowser() {
        try {
            const result = await api("/api/proxy/browser/open", {method: "POST", body: "{}"});
            appendEvent(result.message);
            showError("");
        } catch (error) { showError(error.message); }
    }
    for (const button of document.querySelectorAll("[data-open-browser]")) button.addEventListener("click", openProxyBrowser);

    const workspaceTabs = [...document.querySelectorAll(".burp-tabs [role='tab']")];
    workspaceTabs.forEach((tab) => tab.addEventListener("click", () => {
        switchWorkspace(tab.dataset.proxyTab);
        if (tab.dataset.proxyTab === "websockets") loadWebsockets().catch((error) => showError(error.message));
        if (tab.dataset.proxyTab === "match-replace") updateMatchRequestOptions();
    }));
    byId("proxy-workspace-tabs")?.addEventListener("keydown", (event) => {
        const currentIndex = workspaceTabs.indexOf(event.target);
        if (currentIndex < 0) return;
        let nextIndex = currentIndex;
        if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % workspaceTabs.length;
        else if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + workspaceTabs.length) % workspaceTabs.length;
        else if (event.key === "Home") nextIndex = 0;
        else if (event.key === "End") nextIndex = workspaceTabs.length - 1;
        else return;
        event.preventDefault();
        workspaceTabs[nextIndex].focus();
        workspaceTabs[nextIndex].click();
    });

    let websocketSearchTimer;
    byId("websocket-search").addEventListener("input", () => {
        state.websocketPage = 1;
        clearTimeout(websocketSearchTimer);
        websocketSearchTimer = setTimeout(() => loadWebsockets().catch((error) => showError(error.message)), 120);
    });
    byId("websocket-prev").addEventListener("click", () => {
        state.websocketPage = Math.max(1, state.websocketPage - 1);
        loadWebsockets().catch((error) => showError(error.message));
    });
    byId("websocket-next").addEventListener("click", () => {
        state.websocketPage += 1;
        loadWebsockets().catch((error) => showError(error.message));
    });

    byId("match-request-select").addEventListener("change", () => {
        state.matchPreview = null;
        byId("match-preview").textContent = "Enter literal text and select Preview replacement.";
        byId("open-replace-editor").disabled = true;
        byId("preview-replace").disabled = !byId("match-request-select").value;
    });
    byId("preview-replace").addEventListener("click", previewReplacement);
    byId("match-field").addEventListener("change", () => { state.matchPreview = null; byId("open-replace-editor").disabled = true; });
    byId("open-replace-editor").addEventListener("click", openMatchPreviewInEditor);

    byId("save-settings").addEventListener("click", async () => {
        try { await applySettings(settingsPayload()); await Promise.all([loadHistory(), loadQueue()]); }
        catch (error) { byId("setting-https").checked = state.settings.https_interception === true; showError(error.message); }
    });

    byId("generate-ca").addEventListener("click", async () => {
        byId("generate-ca").disabled = true;
        try { await api("/api/proxy/ca/generate", {method: "POST", body: "{}"}); setCaState(true); showError(""); }
        catch (error) { showError(error.message); }
        finally { byId("generate-ca").disabled = false; }
    });

    byId("proxy-clear-history").addEventListener("click", async () => {
        if (!window.confirm("Clear captured HTTP history? Intercepted requests will remain available until forwarded or dropped.")) return;
        try { await api("/api/proxy/history/clear", {method: "POST", body: "{}"}); state.selected = null; state.selectedId = ""; renderDetail(); await loadHistory(); }
        catch (error) { showError(error.message); }
    });

    byId("history-prev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); loadHistory().catch((error) => showError(error.message)); });
    byId("history-next").addEventListener("click", () => { state.page += 1; loadHistory().catch((error) => showError(error.message)); });
    let filterTimer;
    for (const id of filterIds) {
        const filter = optionalById(id);
        if (filter) filter.addEventListener(id.startsWith("filter-") && ["filter-search", "filter-host", "filter-path"].includes(id) ? "input" : "change", () => {
            state.page = 1;
            clearTimeout(filterTimer);
            filterTimer = setTimeout(() => loadHistory().catch((error) => showError(error.message)), 120);
        });
    }

    const messageTabs = [...document.querySelectorAll(".burp-message-tabs [role='tab']")];
    messageTabs.forEach((tab) => tab.addEventListener("click", () => {
        state.views[tab.dataset.side] = tab.dataset.view;
        renderDetail();
    }));
    document.querySelectorAll(".burp-message-tabs").forEach((tablist) => tablist.addEventListener("keydown", (event) => {
        const tabs = [...tablist.querySelectorAll("[role='tab']")];
        const currentIndex = tabs.indexOf(event.target);
        if (currentIndex < 0) return;
        let nextIndex = currentIndex;
        if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % tabs.length;
        else if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") nextIndex = 0;
        else if (event.key === "End") nextIndex = tabs.length - 1;
        else return;
        event.preventDefault();
        tabs[nextIndex].focus();
        tabs[nextIndex].click();
    }));

    document.querySelectorAll("[data-copy]").forEach((element) => element.addEventListener("click", () => {
        const detail = state.selected;
        if (!detail) return;
        const value = element.dataset.copy === "request" ? activeRequestView(detail) : activeResponseView(detail);
        copyText(value, element);
    }));

    byId("copy-curl").addEventListener("click", () => { if (state.selected) copyText(buildCurl(state.selected), byId("copy-curl")); });
    for (const id of ["proxy-inspector-forward", "proxy-inspector-drop"]) {
        const button = byId(id);
        if (button) button.addEventListener("click", () => {
            if (!state.selectedId || !state.queue.some((item) => item.id === state.selectedId)) return;
            resolveIntercept(state.selectedId, id === "proxy-inspector-forward" ? "forward" : "drop");
        });
    }
    byId("edit-request").addEventListener("click", () => {
        if (state.selectedId && state.queue.some((item) => item.id === state.selectedId)) openEditor(state.selected);
    });
    byId("forward-modified").addEventListener("click", async (event) => {
        event.preventDefault();
        try {
            const modified = {
                method: byId("edit-method").value,
                url: byId("edit-url").value,
                headers: JSON.parse(byId("edit-headers").value || "{}"),
                body: byId("edit-body").value,
            };
            await resolveIntercept(state.selectedId, "forward", modified);
        } catch (error) { byId("edit-error").textContent = error instanceof SyntaxError ? "Headers must be valid JSON." : error.message; byId("edit-error").hidden = false; }
    });
    for (const id of ["edit-method", "edit-url", "edit-headers", "edit-body"]) byId(id).addEventListener("input", updateModifiedIndicator);
    byId("open-replay").addEventListener("click", () => {
        if (!state.selected) return;
        fillReplay(state.selected);
        switchWorkspace("replay");
        byId("replay-panel").scrollIntoView({behavior: "smooth", block: "nearest"});
    });
    byId("replay-send").addEventListener("click", async () => {
        if (!state.selected) return;
        byId("replay-send").disabled = true;
        byId("replay-result").textContent = "Sending the selected request through the local Proxy…";
        try {
            const result = await api("/api/proxy/replay", {method: "POST", body: JSON.stringify({source_id: state.selected.id, method: byId("replay-method").value, url: byId("replay-url").value, headers: JSON.parse(byId("replay-headers").value || "{}"), body: byId("replay-body").value})});
            byId("replay-result").textContent = `HTTP ${result.response.status} ${result.response.reason}\n${headersText(result.response.headers)}\n\n${result.response.body.text}`;
            await Promise.all([loadHistory(), loadStatus()]);
        } catch (error) { byId("replay-result").textContent = error.message; }
        finally { byId("replay-send").disabled = !state.running; }
    });

    const events = new EventSource("/api/proxy/events");
    for (const eventName of ["request", "response", "intercept", "websocket", "status", "statistics", "history_cleared", "ca", "settings", "proxy_end"]) {
        events.addEventListener(eventName, (event) => {
            let data = {};
            try { data = JSON.parse(event.data); } catch { return; }
            if (eventName === "status") {
                const previous = byId("proxy-state").dataset.state;
                setState({...state, ...data, running: data.state === "running"});
                if (previous !== data.state) appendEvent(`Proxy ${data.state || "status updated"}.`);
            }
            if (eventName === "request" || eventName === "response") {
                const detail = data.request;
                if (detail?.id === state.selectedId) selectRequest(detail.id, detail);
                loadHistory().catch((error) => showError(error.message));
                if (detail) appendEvent(`${eventName === "request" ? "Request" : "Response"}: ${detail.method} ${detail.host}`);
            }
            if (eventName === "intercept") {
                loadQueue().catch((error) => showError(error.message));
                appendEvent(data.action === "queued" ? `Intercepted request from ${data.request?.host || "client"}.` : `Intercept ${data.action || "updated"}.`);
            }
            if (eventName === "websocket") {
                loadWebsockets().catch((error) => showError(error.message));
                appendEvent(`WebSocket frame captured from ${data.message?.host || "unknown host"}.`);
            }
            if (eventName === "history_cleared") { state.selected = null; state.selectedId = ""; renderDetail(); loadHistory(); }
            if (eventName === "ca") setCaState(data.ready === true);
            if (eventName === "statistics" || eventName === "intercept" || eventName === "response" || eventName === "request" || eventName === "websocket") loadStatus().catch(() => {});
        });
    }
    events.onerror = () => { /* EventSource reconnects automatically; scanner and captured history remain available. */ };

    switchWorkspace("intercept");
    refresh();
})();
