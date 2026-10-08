"use strict";

(() => {
    const $ = (id) => document.getElementById(id);
    const targetMode = document.body.dataset.targetMode === "true";
    const targetWorkspace = $("target-workspace");
    const state = {
        status: null,
        scope: {include: [], exclude: []},
        targetSummary: {site_map: [], issues: []},
        history: [],
        total: 0,
        page: 1,
        pageSize: 80,
        queue: [],
        selectedId: null,
        selected: null,
        websocket: [],
        websocketTotal: 0,
        websocketPage: 1,
        websocketPageSize: 80,
        activeTab: "intercept",
        targetTab: "site-map",
        editorSide: "request",
        editorView: "pretty",
        showHeaders: true,
        searchIndex: 0,
        searchMatches: [],
        intercept: true,
        settingsDirty: false,
    };
    let historySearchTimer = null;
    let websocketSearchTimer = null;

    if (targetMode && targetWorkspace) {
        targetWorkspace.hidden = false;
        document.querySelectorAll(".proxy-shell > .proxy-panel, .proxy-shell > .workspace-header:not(#target-workspace), .proxy-shell > .status-line").forEach((element) => {
            element.hidden = true;
        });
        document.querySelector(".module-tabs").hidden = true;
        document.querySelector(".tool-strip").hidden = true;
        $("target-link").classList.add("active");
        showTargetPanel("site-map");
    }

    async function api(path, options = {}) {
        const headers = {"Content-Type": "application/json", ...(options.headers || {})};
        if (options.method && options.method !== "GET") {
            const token = document.querySelector('meta[name="csrf-token"]')?.content;
            if (token) headers["X-CSRF-Token"] = token;
        }
        const response = await fetch(path, {
            ...options,
            headers,
        });
        const payload = response.headers.get("content-type")?.includes("application/json") ? await response.json() : null;
        if (!response.ok || payload?.success === false) throw new Error(payload?.error || `Request failed (${response.status})`);
        return payload;
    }

    function error(message) {
        const element = $("proxy-error");
        if (element) {
            element.textContent = message;
            element.hidden = !message;
        }
    }

    function setControls() {
        const status = state.status;
        if (!status) return;
        const running = status.running;
        const intercept = status.settings?.intercept === true;
        const start = $("proxy-start");
        const stop = $("proxy-stop");
        const browser = $("proxy-open-browser");
        if (start) start.disabled = running || status.state === "starting" || status.state === "stopping";
        if (stop) stop.disabled = !running && status.state !== "starting";
        if (browser) browser.disabled = !running;
        document.querySelectorAll("[data-open-browser]").forEach((button) => { button.disabled = !running; });
        const toggle = $("proxy-intercept-toggle");
        if (toggle) {
            toggle.disabled = !running;
            toggle.textContent = intercept ? "Intercept on" : "Intercept off";
            toggle.setAttribute("aria-pressed", String(intercept));
        }
        const listenerText = running ? status.listener : `${status.address}:${status.port}`;
        $("listener-chip-text").textContent = listenerText;
        $("listener-command").textContent = listenerText;
        $("proxy-mode-command").textContent = intercept ? "INTERCEPT" : "PASSIVE";
        $("menu-status-text").textContent = running ? "Proxy running" : status.error ? "Proxy error" : "Proxy stopped";
        $("menu-status-dot").parentElement.className = `app-menu-status ${running ? "running" : status.error ? "error" : ""}`;
        $("stat-requests").textContent = status.statistics?.requests ?? 0;
        $("stat-responses").textContent = status.statistics?.responses ?? 0;
        $("stat-intercepted").textContent = status.statistics?.intercepted ?? 0;
        $("stat-https").textContent = status.statistics?.https ?? 0;
        $("settings-history-count").textContent = status.statistics?.requests ?? 0;
        $("settings-intercept-count").textContent = state.queue.length;
        $("settings-websocket-count").textContent = status.statistics?.websocket_messages ?? 0;
        $("target-scope-summary").textContent = `Includes: ${state.scope.include.length}; excludes: ${state.scope.exclude.length}`;
        if (targetMode) return;
        const scopeDescription = `Includes ${state.scope.include.length} · Excludes ${state.scope.exclude.length}`;
        $("scope-note").textContent = state.scope.include.length || state.scope.exclude.length ? scopeDescription : "Target scope unrestricted · local listener";
        if (!state.settingsDirty) {
            $("proxy-address").value = status.address;
            $("proxy-port").value = status.port;
            $("setting-max-history").value = status.settings?.max_history_entries ?? 500;
            $("setting-max-body").value = status.settings?.max_body_size ?? 131072;
            $("setting-history-enabled").checked = status.settings?.history_enabled !== false;
            $("setting-request-body").checked = status.settings?.capture_request_body !== false;
            $("setting-response-body").checked = status.settings?.capture_response_body !== false;
            $("setting-https").checked = status.settings?.https_interception === true;
        }
        $("ca-status").textContent = status.ca_ready ? "Ready · local certificate generated" : "Not configured";
        $("export-ca").hidden = !status.ca_ready;
        $("generate-ca").disabled = running;
        $("regenerate-ca").disabled = running || !status.ca_ready;
        $("replay-send").disabled = !running || !state.selectedId || !bodyEditable(state.selected?.request_body);
        $("proxy-inspector-forward").disabled = !state.queue.some((item) => item.id === state.selectedId);
        $("proxy-inspector-drop").disabled = !state.queue.some((item) => item.id === state.selectedId);
        const selectedIntercept = state.queue.find((item) => item.id === state.selectedId);
        $("edit-request").disabled = !selectedIntercept || !bodyEditable(selectedIntercept.request_body);
        $("copy-request").disabled = !state.selected;
    }

    function bodyEditable(body) {
        return body?.size === 0 || (body?.kind === "text" && body.truncated !== true);
    }

    function showPanel(tab, panel) {
        document.querySelectorAll("[data-proxy-tab]").forEach((button) => {
            const selected = button.dataset.proxyTab === tab;
            button.classList.toggle("active", selected);
            if (button.getAttribute("role") === "tab") {
                button.setAttribute("aria-selected", String(selected));
                button.tabIndex = selected ? 0 : -1;
            } else if (button.tagName === "BUTTON") {
                button.setAttribute("aria-pressed", String(selected));
            }
        });
        document.querySelectorAll("[data-proxy-panel]").forEach((element) => {
            const selected = element.dataset.proxyPanel === tab;
            element.classList.toggle("active-panel", selected);
            element.hidden = !selected;
        });
        state.activeTab = tab;
        if (tab === "history") loadHistory();
        if (tab === "websockets") loadWebSockets();
        if (tab === "match") loadRules();
        if (tab === "settings") loadSettings();
        if (tab === "replay") loadReplay();
        if (["intruder", "repeater", "scanner", "decoder", "comparer", "extensions"].includes(tab)) populateToolRequests();
        if (tab === "scanner") renderScannerSummary();
        if (tab === "extensions") renderExtensions();
    }

    function showTargetPanel(tab) {
        state.targetTab = tab;
        document.querySelectorAll(`[data-target-tab]`).forEach((button) => button.classList.toggle("active", button.dataset.targetTab === tab));
        document.querySelectorAll(`[data-target-panel]`).forEach((panel) => panel.classList.toggle("active", panel.dataset.targetPanel === tab));
        if (tab === "site-map") renderSiteMap();
        if (tab === "scope") renderScope();
        if (tab === "issues") renderIssues();
    }

    function renderText(element, value) {
        if (element) element.textContent = value;
    }

    function detailText(detail) {
        return detail?.raw_request || detail?.request_body?.text || "No request available.";
    }

    function responseText(detail) {
        return detail?.raw_response || detail?.response_body?.text || "No response available.";
    }

    function prettyMessage(value) {
        const separator = value.indexOf("\r\n\r\n");
        if (separator < 0) return value;
        const headers = value.slice(0, separator);
        const body = value.slice(separator + 4);
        try {
            return `${headers}\r\n\r\n${JSON.stringify(JSON.parse(body), null, 2)}`;
        } catch {
            return value;
        }
    }

    function hexMessage(value) {
        const bytes = new TextEncoder().encode(value);
        const lines = [];
        for (let offset = 0; offset < bytes.length; offset += 16) {
            const chunk = bytes.slice(offset, offset + 16);
            const hex = [...chunk].map((byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
            const text = [...chunk].map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".").join("");
            lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  ${text}`);
        }
        return lines.join("\n");
    }

    function selectedEditorText() {
        const detail = state.selected;
        if (!detail) return "";
        let value = state.editorSide === "request" ? detailText(detail) : responseText(detail);
        if (!state.showHeaders) {
            const separator = value.indexOf("\r\n\r\n");
            if (separator >= 0) {
                const startLineEnd = value.indexOf("\r\n");
                const startLine = startLineEnd >= 0 && startLineEnd < separator ? value.slice(0, startLineEnd) : "";
                value = `${startLine}\r\n\r\n${value.slice(separator + 4)}`;
            }
        }
        if (state.editorView === "hex") return hexMessage(value);
        if (state.editorView === "pretty") return prettyMessage(value);
        return value;
    }

    function renderEditorSearch() {
        if (!state.selected) return;
        const content = state.editorSide === "request" ? $("request-content") : $("response-content");
        const query = $("editor-search").value;
        const value = selectedEditorText();
        const lowerValue = value.toLocaleLowerCase();
        const lowerQuery = query.toLocaleLowerCase();
        state.searchMatches = [];
        if (lowerQuery) {
            let offset = 0;
            while ((offset = lowerValue.indexOf(lowerQuery, offset)) !== -1) {
                state.searchMatches.push(offset);
                offset += lowerQuery.length;
            }
        }
        state.searchIndex = state.searchMatches.length ? Math.min(state.searchIndex, state.searchMatches.length - 1) : 0;
        $("highlight-count").textContent = `${state.searchMatches.length} highlight${state.searchMatches.length === 1 ? "" : "s"}`;
        $("search-prev").disabled = state.searchMatches.length === 0;
        $("search-next").disabled = state.searchMatches.length === 0;
        content.replaceChildren();
        const pre = document.createElement("pre");
        pre.className = "editor-message";
        if (!query || !state.searchMatches.length) {
            pre.textContent = value;
        } else {
            const parts = [];
            let cursor = 0;
            for (const [index, match] of state.searchMatches.entries()) {
                parts.push(escapeHtml(value.slice(cursor, match)));
                parts.push(`<mark class="${index === state.searchIndex ? "current-match" : ""}">${escapeHtml(value.slice(match, match + query.length))}</mark>`);
                cursor = match + query.length;
            }
            parts.push(escapeHtml(value.slice(cursor)));
            pre.innerHTML = parts.join("");
            pre.querySelector(".current-match")?.scrollIntoView({block: "nearest"});
        }
        content.append(pre);
    }

    function renderEditor() {
        const detail = state.selected;
        const request = $("request-content");
        const response = $("response-content");
        if (!detail) {
            request.innerHTML = '<div class="empty-editor"><span>↯</span><strong>No request selected</strong><small>Enable interception and capture a real request.</small></div>';
            response.innerHTML = '<div class="empty-editor"><span>↳</span><strong>No response selected</strong><small>Responses will appear here after the request is forwarded.</small></div>';
            renderText($("editor-selection-label"), "Select a captured request");
            renderText($("inspector-title"), "No selection");
            $("inspector-content").innerHTML = '<div class="inspector-empty">Select a request to inspect its request and response metadata.</div>';
            $("copy-request").disabled = true;
            $("edit-request").disabled = true;
            return;
        }
        request.textContent = detailText(detail);
        response.textContent = responseText(detail);
        renderText($("editor-selection-label"), `${detail.method} ${detail.host}:${detail.port}${detail.path}`);
        renderText($("inspector-title"), `${detail.method} ${detail.path}`);
        const rows = [
            ["Method", detail.method], ["URL", detail.url], ["Protocol", detail.protocol], ["Host", detail.host],
            ["Port", detail.port], ["Status", detail.response_status || "—"], ["Cookies", detail.cookies?.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ") || "—"],
            ["Client", detail.client || "—"], ["State", detail.state || "—"],
        ];
        $("inspector-content").innerHTML = rows.map(([label, value]) => `<div class="inspector-row"><b>${escapeHtml(label)}</b><b>${escapeHtml(String(value))}</b></div>`).join("");
        renderEditorSearch();
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>'"]/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[character]);
    }

    function renderHistory() {
        const body = $("proxy-history-rows");
        body.replaceChildren();
        if (!state.history.length) {
            const row = document.createElement("tr");
            row.innerHTML = '<td colspan="14">No matching captured traffic.</td>';
            body.append(row);
        }
        for (const item of state.history) {
            const row = document.createElement("tr");
            row.className = item.id === state.selectedId ? "selected" : "";
            row.innerHTML = `<td>${escapeHtml(item.host)}</td><td class="method">${escapeHtml(item.method)}</td><td>${escapeHtml(item.path)}</td><td>${escapeHtml(item.query?.map((pair) => pair.join("=")).join("&") || "—")}</td><td>${escapeHtml(item.modified ? "Yes" : "No")}</td><td class="status ${item.status >= 400 ? "error" : ""}">${escapeHtml(item.status || "—")}</td><td>${escapeHtml(item.response_size || 0)}</td><td>${escapeHtml(item.response_body_content_type || "—")}</td><td>${escapeHtml(item.request_body_content_type || "—")}</td><td>${escapeHtml(item.response_reason || "—")}</td><td>${escapeHtml(item.error || "—")}</td><td>${escapeHtml((item.scheme || "").toUpperCase())}</td><td>${escapeHtml(item.client || "—")}</td><td>${escapeHtml(item.timestamp)}</td>`;
            row.addEventListener("click", () => selectRequest(item.id));
            body.append(row);
        }
        renderText($("history-total"), `${state.total} request${state.total === 1 ? "" : "s"}`);
        $("history-page-label").textContent = state.total ? `${((state.page - 1) * state.pageSize) + 1}–${Math.min(state.total, state.page * state.pageSize)} of ${state.total}` : "0 requests";
        $("history-prev").disabled = state.page <= 1;
        $("history-next").disabled = state.page * state.pageSize >= state.total;
    }

    async function loadHistory() {
        const params = new URLSearchParams({page: String(state.page), page_size: String(state.pageSize)});
        for (const [id, name] of [["filter-search", "q"], ["filter-method", "method"], ["filter-status", "status"], ["filter-host", "host"], ["filter-content-type", "content_type"], ["filter-path", "path"]]) {
            const value = $(id)?.value.trim();
            if (value && value !== "all") params.set(name, value);
        }
        try {
            const result = await api(`/api/proxy/history?${params}`);
            state.history = result.items;
            state.total = result.total;
            renderHistory();
            populateToolRequests();
            if (state.activeTab === "scanner") renderScannerSummary();
        } catch (exception) { error(exception.message); }
    }

    async function selectRequest(id) {
        state.selectedId = id;
        try {
            const result = await api(`/api/proxy/history/${encodeURIComponent(id)}`);
            state.selected = result.request;
            renderEditor();
            renderHistory();
            setControls();
            const pending = state.queue.find((item) => item.id === id);
            if (pending) {
                $("intercept-queue").querySelectorAll(".intercept-row").forEach((row) => row.classList.toggle("selected", row.dataset.id === id));
            }
        } catch (exception) { error(exception.message); }
    }

    function renderInterceptQueue() {
        const container = $("intercept-queue");
        container.replaceChildren();
        for (const item of state.queue) {
            const row = document.createElement("button");
            row.type = "button";
            row.className = `intercept-row ${item.id === state.selectedId ? "selected" : ""}`;
            row.dataset.id = item.id;
            row.innerHTML = `<span class="time">${escapeHtml(item.timestamp)}</span><span class="method">${escapeHtml(item.method)}</span><span class="host">${escapeHtml(item.host)}</span><span class="path">${escapeHtml(item.path)}</span><span class="status">${escapeHtml(item.state)}</span>`;
            row.addEventListener("click", () => selectRequest(item.id));
            container.append(row);
        }
        $("intercept-table-count").textContent = state.queue.length;
        $("intercept-count").textContent = `${state.queue.length} waiting`;
    }

    async function loadIntercepts() {
        try {
            const result = await api("/api/proxy/intercepts");
            state.queue = result.requests;
            renderInterceptQueue();
            setControls();
            renderEditor();
        } catch (exception) { error(exception.message); }
    }

    async function resolveIntercept(action) {
        if (!state.selectedId) return;
        try {
            await api(`/api/proxy/intercepts/${encodeURIComponent(state.selectedId)}/${action}`, {method: "POST", body: JSON.stringify({modified: false})});
            state.selectedId = null;
            state.selected = null;
            await Promise.all([loadIntercepts(), loadHistory()]);
            renderEditor();
            setControls();
        } catch (exception) { error(exception.message); }
    }

    function openRequestEditor() {
        const item = state.queue.find((request) => request.id === state.selectedId);
        if (!item || !bodyEditable(item.request_body)) {
            error("This request body is binary, truncated, or uncaptured and cannot be safely edited here.");
            return;
        }
        $("edit-method").value = item.method;
        $("edit-url").value = item.url;
        $("edit-headers").value = JSON.stringify(Object.fromEntries(item.request_headers || []), null, 2);
        $("edit-body").value = item.request_body?.text || "";
        $("edit-error").hidden = true;
        $("request-edit-dialog").hidden = false;
        $("edit-method").focus();
    }

    function closeRequestEditor() {
        $("request-edit-dialog").hidden = true;
        $("edit-error").hidden = true;
    }

    async function forwardModifiedRequest(event) {
        event.preventDefault();
        if (!state.selectedId) return;
        let headers;
        try {
            headers = JSON.parse($("edit-headers").value || "{}");
        } catch {
            $("edit-error").textContent = "Headers must be valid JSON.";
            $("edit-error").hidden = false;
            return;
        }
        const modifiedRequest = {
            method: $("edit-method").value,
            url: $("edit-url").value,
            headers,
            body: $("edit-body").value,
        };
        try {
            await api(`/api/proxy/intercepts/${encodeURIComponent(state.selectedId)}/forward`, {
                method: "POST",
                body: JSON.stringify({modified: true, modified_request: modifiedRequest}),
            });
            closeRequestEditor();
            state.selectedId = null;
            state.selected = null;
            await Promise.all([loadIntercepts(), loadHistory()]);
            renderEditor();
            setControls();
        } catch (exception) {
            $("edit-error").textContent = exception.message;
            $("edit-error").hidden = false;
        }
    }

    async function copySelectedRequest() {
        if (!state.selected) return;
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(detailText(state.selected));
            } else {
                const temporary = document.createElement("textarea");
                temporary.value = detailText(state.selected);
                temporary.setAttribute("readonly", "");
                temporary.style.position = "fixed";
                temporary.style.opacity = "0";
                document.body.append(temporary);
                temporary.select();
                const copied = document.execCommand("copy");
                temporary.remove();
                if (!copied) throw new Error("Clipboard access is unavailable.");
            }
            error("");
        } catch (exception) {
            error(`Could not copy the request: ${exception.message || "clipboard access is unavailable"}`);
        }
    }

    async function loadWebSockets() {
        try {
            const params = new URLSearchParams({page: String(state.websocketPage), page_size: String(state.websocketPageSize)});
            const search = $("websocket-search").value.trim();
            if (search) params.set("q", search);
            const result = await api(`/api/proxy/websockets?${params}`);
            state.websocket = result.items;
            state.websocketTotal = result.total;
            const body = $("websocket-content");
            const table = $("websocket-table-wrap");
            const footer = $("websocket-footer");
            body.hidden = state.websocket.length > 0;
            table.hidden = !state.websocket.length;
            footer.hidden = !state.websocket.length;
            $("websocket-total").textContent = `${state.websocketTotal} message${state.websocketTotal === 1 ? "" : "s"}`;
            $("websocket-page-label").textContent = state.websocketTotal ? `${((state.websocketPage - 1) * state.websocketPageSize) + 1}–${Math.min(state.websocketTotal, state.websocketPage * state.websocketPageSize)} of ${state.websocketTotal}` : "0 messages";
            $("websocket-prev").disabled = state.websocketPage <= 1;
            $("websocket-next").disabled = state.websocketPage * state.websocketPageSize >= state.websocketTotal;
            const rows = $("proxy-websocket-rows");
            rows.replaceChildren();
            for (const item of state.websocket) {
                const row = document.createElement("tr");
                row.innerHTML = `<td>${escapeHtml(item.timestamp)}</td><td>${escapeHtml(item.direction)}</td><td>${escapeHtml(item.type)}</td><td>${escapeHtml(item.host)}</td><td>${escapeHtml(item.path)}</td><td>${escapeHtml(item.payload)}</td><td>${escapeHtml(item.size)}</td>`;
                rows.append(row);
            }
        } catch (exception) { error(exception.message); }
    }

    async function loadRules() {
        try {
            const result = await api("/api/proxy/settings");
            const rules = result.settings?.http_rules || [];
            const body = $("http-rules");
            body.replaceChildren();
            for (const rule of rules) {
                const row = document.createElement("tr");
                row.innerHTML = `<td>${rule.enabled ? "Yes" : "No"}</td><td>${escapeHtml(rule.type)}</td><td>${escapeHtml(rule.name)}</td><td>${escapeHtml(rule.match)}</td><td>${escapeHtml(rule.replace)}</td><td>${escapeHtml(rule.condition)}</td><td>${escapeHtml(rule.scope)}</td><td>${escapeHtml(rule.actions)}</td>`;
                body.append(row);
            }
        } catch (exception) { error(exception.message); }
    }

    async function loadSettings() {
        try {
            const result = await api("/api/proxy/settings");
            const settings = result.settings;
            const status = state.status || await api("/api/proxy/status");
            $("listener-table").innerHTML = `<tr><td>${status.running ? "Yes" : "No"}</td><td>${escapeHtml(`${status.address}:${status.port}`)}</td><td>—</td><td>—</td><td>${status.ca_ready ? "Local CA ready" : "Not configured"}</td><td>${settings.https_interception ? "HTTPS interception" : "CONNECT tunneling"}</td><td>${escapeHtml(status.state)}</td></tr>`;
            $("intercept-rules").innerHTML = '<tr><td colspan="5">Per-request decisions are available in the Intercept tab; conditional rules are not supported.</td></tr>';
            $("settings-history-count").textContent = status.statistics?.requests ?? 0;
            $("settings-intercept-count").textContent = state.queue.length;
            $("settings-websocket-count").textContent = status.statistics?.websocket_messages ?? 0;
        } catch (exception) { error(exception.message); }
    }

    function renderSiteMap() {
        const content = $("site-map-content");
        const entries = state.targetSummary.site_map;
        content.innerHTML = entries.length ? entries.map((entry) => `<div class="site-map-host"><strong>${escapeHtml(entry.host)}</strong><div>${entry.paths.slice(0, 20).map((path) => `<span>${escapeHtml(path)}</span>`).join("")}</div></div>`).join("") : '<div class="inspector-empty">Captured hosts will appear here after traffic is recorded.</div>';
    }

    function renderScope() {
        const include = $("scope-include");
        const exclude = $("scope-exclude");
        include.value = state.scope.include.map((rule) => rule.url).join("\n") || "";
        exclude.value = state.scope.exclude.map((rule) => rule.url).join("\n") || "";
        $("scope-summary").textContent = `Includes: ${state.scope.include.length}; excludes: ${state.scope.exclude.length}`;
    }

    async function saveScope() {
        const include = $("scope-include").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean).map((url) => ({url, type: "host", condition: "contains"}));
        const exclude = $("scope-exclude").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean).map((url) => ({url, type: "host", condition: "contains"}));
        try {
            const result = await api("/api/proxy/target/scope", {method: "PUT", body: JSON.stringify({include, exclude})});
            state.scope = result.scope;
            renderScope();
            setControls();
            error("");
        } catch (exception) { error(exception.message); }
    }

    function renderIssues() {
        const issues = state.targetSummary.issues;
        const list = $("issue-list");
        list.replaceChildren();
        if (!issues.length) {
            list.innerHTML = '<div class="inspector-empty">No captured errors or HTTP error responses.</div>';
        } else {
            for (const issue of issues) {
                const button = document.createElement("button");
                button.type = "button";
                button.textContent = `${issue.status || "ERROR"} ${issue.host}${issue.path}`;
                button.addEventListener("click", () => {
                    $("issue-detail").innerHTML = `<h3>${escapeHtml(issue.title)}</h3><p>${escapeHtml(issue.host)}${escapeHtml(issue.path)}</p><div class="issue-meta"><div><span>Status</span><strong>${escapeHtml(issue.status || "Error")}</strong></div><div><span>Captured</span><strong>${escapeHtml(issue.timestamp)}</strong></div><div><span>Source</span><strong>HTTP history</strong></div></div>`;
                    selectRequest(issue.id);
                });
                list.append(button);
            }
        }
        $("issues-total").textContent = `${issues.length} issue${issues.length === 1 ? "" : "s"}`;
        $("issue-detail").innerHTML = issues.length ? `<h3>${escapeHtml(issues[0].title)}</h3><p>${escapeHtml(issues[0].host)}${escapeHtml(issues[0].path)}</p><div class="issue-meta"><div><span>Status</span><strong>${escapeHtml(issues[0].status || "Error")}</strong></div><div><span>Captured</span><strong>${escapeHtml(issues[0].timestamp)}</strong></div><div><span>Source</span><strong>HTTP history</strong></div></div>` : '<div class="inspector-empty">No issues to display.</div>';
    }

    function populateToolRequests() {
        const options = state.history.map((item) => {
            const option = document.createElement("option");
            option.value = item.id;
            option.textContent = `${item.method} ${item.host}${item.path}`;
            return option;
        });
        const ids = ["intruder-request", "repeater-request"];
        ids.forEach((id) => {
            const select = $(id);
            const previous = select.value;
            select.replaceChildren();
            const empty = document.createElement("option");
            empty.value = "";
            empty.textContent = "Select captured history first";
            select.append(empty);
            select.append(...options.map((option) => option.cloneNode(true)));
            if (state.history.some((item) => item.id === previous)) select.value = previous;
        });
    }

    async function loadReplay() {
        try {
            let result = state.selected;
            if (!result) {
                const history = await api("/api/proxy/history?page=1&page_size=80");
                const first = history.items[0];
                result = first ? (await api(`/api/proxy/history/${encodeURIComponent(first.id)}`)).request : null;
            }
            if (!result) {
                $("replay-send").disabled = true;
                $("replay-result").value = "Capture a request before replaying traffic.";
                return;
            }
            state.selected = result;
            state.selectedId = result.id;
            $("replay-method").value = result.method;
            $("replay-url").value = result.url;
            $("replay-headers").value = JSON.stringify(Object.fromEntries(result.request_headers || []), null, 2);
            $("replay-body").value = result.request_body?.kind === "text" ? result.request_body.text : "";
            $("replay-send").disabled = !state.status?.running || !bodyEditable(result.request_body);
            if (!bodyEditable(result.request_body)) {
                $("replay-result").value = "This request body is binary, truncated, or uncaptured. Replay is disabled to avoid sending a changed request.";
            }
            setControls();
        } catch (exception) { error(exception.message); }
    }

    async function selectedHistoryItem(selectId) {
        if (!state.history.some((item) => item.id === selectId)) return null;
        return (await api(`/api/proxy/history/${encodeURIComponent(selectId)}`)).request;
    }

    async function renderIntruder() {
        const item = await selectedHistoryItem($("intruder-request").value);
        if (!item) {
            $("intruder-output").value = "Choose a request to generate payload variants.";
            return;
        }
        const body = item.request_body?.kind === "text" ? item.request_body.text : "";
        const mutations = [
            ["CRLF injection", body.replace(/(\w+)=([^&\n]*)/, "$1=$2%0d%0aX-Test: injected")],
            ["SQL/quote variant", body.replace(/\?/, "?x=' OR 1=1 --")],
            ["Encoded payload", encodeURIComponent(body || "test")],
            ["Double encoding", encodeURIComponent(encodeURIComponent(body || "test"))],
        ];
        $("intruder-output").value = mutations.map(([name, value]) => `${name}: ${value}`).join("\n\n");
    }

    async function runIntruder() {
        try {
            await renderIntruder();
            error("");
        } catch (exception) { error(exception.message); }
    }

    async function runRepeater() {
        let item;
        try {
            item = await selectedHistoryItem($("repeater-request").value);
        } catch (exception) {
            $("repeater-summary").value = exception.message;
            return;
        }
        if (!item) {
            $("repeater-summary").value = "Select a captured request first.";
            return;
        }
        if (!bodyEditable(item.request_body)) {
            $("repeater-summary").value = "This request body is binary, truncated, or uncaptured. Repeater will not send a changed request.";
            return;
        }
        $("repeater-url").value = item.url;
        $("repeater-summary").value = "Sending 3 repetitions…";
        const results = [];
        try {
            for (let index = 0; index < 3; index += 1) {
                const result = await api("/api/proxy/replay", {method: "POST", body: JSON.stringify({source_id: item.id, method: item.method, url: item.url, headers: Object.fromEntries(item.request_headers || []), body: item.request_body?.kind === "text" ? item.request_body.text : ""})});
                results.push(result.response);
            }
            $("repeater-summary").value = results.map((response, index) => `Run ${index + 1}: ${response.status || "error"} · ${response.elapsed_ms || 0} ms · ${response.body?.size || 0} bytes`).join("\n");
            $("repeater-response").value = JSON.stringify(results.at(-1), null, 2);
        } catch (exception) {
            $("repeater-summary").value = exception.message;
        }
    }

    function renderScannerSummary() {
        const issues = state.targetSummary.issues || [];
        const hosts = [...new Set((state.targetSummary.site_map || []).map((entry) => entry.host))];
        const lines = [
            `Hosts: ${hosts.length || 0}`,
            `Issues: ${issues.length}`,
            `Captured history: ${state.total}`,
            `Proxy: ${state.status?.running ? "running" : "stopped"}`,
            ...hosts.map((host) => `- ${host}`),
            ...issues.slice(0, 10).map((issue) => `- ${issue.status || "ERROR"} ${issue.host}${issue.path}`),
        ];
        $("scanner-output").innerHTML = `<div class="scanner-output-card"><strong>Passive captured-target summary</strong><pre>${escapeHtml(lines.join("\n"))}</pre><small>No active vulnerability probes are run from this panel.</small></div>`;
    }

    function decodeInput() {
        const mode = $("decoder-mode").value;
        const value = $("decoder-input").value;
        try {
            let output = value;
            if (mode === "url") output = decodeURIComponent(value.replace(/\+/g, " "));
            if (mode === "base64") output = decodeURIComponent(escape(atob(value)));
            if (mode === "html") output = value.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
            if (mode === "json") output = JSON.stringify(JSON.parse(value), null, 2);
            $("decoder-output").value = output;
            error("");
        } catch (exception) {
            $("decoder-output").value = "Unable to decode this input.";
            error(exception.message);
        }
    }

    function compareInputs() {
        const original = $("comparer-original").value.split(/\r?\n/);
        const modified = $("comparer-modified").value.split(/\r?\n/);
        const diff = [];
        const common = Math.max(original.length, modified.length);
        for (let index = 0; index < common; index += 1) {
            if (original[index] !== modified[index]) diff.push(`${index + 1}: ${original[index] ?? ""} → ${modified[index] ?? ""}`);
        }
        $("comparer-diff").value = diff.length ? diff.join("\n") : "No differences found.";
    }

    function renderExtensions() {
        $("extensions-output").innerHTML = '<div class="scanner-output-card"><strong>Built-in extensions</strong><pre>Intruder · Repeater · Scanner · Decoder · Comparer\nStatus: local tools enabled\nThird-party extensions: none</pre></div>';
    }

    async function replay() {
        try {
            const result = await api("/api/proxy/replay", {method: "POST", body: JSON.stringify({source_id: state.selectedId, method: $("replay-method").value, url: $("replay-url").value, headers: JSON.parse($("replay-headers").value || "{}"), body: $("replay-body").value})});
            $("replay-result").value = `HTTP ${result.response.status} ${result.response.reason}\n${(result.response.headers || []).map(([name, value]) => `${name}: ${value}`).join("\n")}\n\n${result.response.body?.text || ""}`;
            await loadHistory();
        } catch (exception) { error(exception.message); }
    }

    async function startProxy() {
        try {
            const result = await api("/api/proxy/start", {method: "POST", body: JSON.stringify({address: $("proxy-address").value, port: Number($("proxy-port").value), intercept: state.intercept})});
            state.status = result;
            state.settingsDirty = false;
            await refresh();
        } catch (exception) { error(exception.message); }
    }

    async function stopProxy() {
        try {
            state.status = await api("/api/proxy/stop", {method: "POST"});
            await refresh();
        } catch (exception) { error(exception.message); }
    }

    async function refresh() {
        try {
            const result = await api("/api/proxy/status");
            state.status = result;
            state.intercept = result.settings?.intercept === true;
            const scopeResult = await api("/api/proxy/target/scope");
            state.scope = scopeResult.scope;
            const targetResult = await api("/api/proxy/target");
            state.targetSummary = targetResult;
            setControls();
            renderScope();
            renderSiteMap();
            renderIssues();
            if (targetMode) return;
            await Promise.all([loadHistory(), loadIntercepts(), loadWebSockets()]);
        } catch (exception) {
            error(exception.message);
        }
    }

    function bind() {
        document.querySelectorAll("[data-proxy-tab]").forEach((button) => button.addEventListener("click", () => showPanel(button.dataset.proxyTab)));
        document.querySelectorAll('.module-tabs [role="tab"]').forEach((tab) => {
            tab.addEventListener("keydown", (event) => {
                const tabs = Array.from(document.querySelectorAll('.module-tabs [role="tab"]'));
                const index = tabs.indexOf(tab);
                let nextIndex = index;
                if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
                else if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
                else if (event.key === "Home") nextIndex = 0;
                else if (event.key === "End") nextIndex = tabs.length - 1;
                else return;
                event.preventDefault();
                tabs[nextIndex].focus();
                showPanel(tabs[nextIndex].dataset.proxyTab);
            });
        });
        document.querySelectorAll("[data-target-tab]").forEach((button) => button.addEventListener("click", () => showTargetPanel(button.dataset.targetTab)));
        $("proxy-start")?.addEventListener("click", startProxy);
        $("proxy-stop")?.addEventListener("click", stopProxy);
        $("proxy-intercept-toggle")?.addEventListener("click", async () => {
            const next = !state.intercept;
            try {
                const result = await api("/api/proxy/settings", {method: "POST", body: JSON.stringify({intercept: next})});
                state.status = result;
                state.intercept = next;
                setControls();
            } catch (exception) { error(exception.message); }
        });
        $("proxy-inspector-forward")?.addEventListener("click", () => resolveIntercept("forward"));
        $("proxy-inspector-drop")?.addEventListener("click", () => resolveIntercept("drop"));
        $("edit-request")?.addEventListener("click", openRequestEditor);
        $("copy-request")?.addEventListener("click", copySelectedRequest);
        $("request-edit-form")?.addEventListener("submit", forwardModifiedRequest);
        document.querySelectorAll("[data-close-request-editor]").forEach((button) => button.addEventListener("click", closeRequestEditor));
        $("request-edit-dialog")?.addEventListener("click", (event) => {
            if (event.target === $("request-edit-dialog")) closeRequestEditor();
        });
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && !$("request-edit-dialog").hidden) closeRequestEditor();
        });
        document.querySelectorAll("[data-open-browser]").forEach((button) => button.addEventListener("click", async () => { try { await api("/api/proxy/browser/open", {method: "POST"}); error(""); } catch (exception) { error(exception.message); } }));
        $("save-scope")?.addEventListener("click", saveScope);
        $("replay-send")?.addEventListener("click", replay);
        const clearCapturedTraffic = async () => {
            try {
                await api("/api/proxy/history/clear", {method: "POST"});
                state.page = 1;
                state.websocketPage = 1;
                if (!state.queue.some((item) => item.id === state.selectedId)) {
                    state.selectedId = null;
                    state.selected = null;
                }
                await Promise.all([loadHistory(), loadIntercepts(), loadWebSockets()]);
                renderEditor();
                setControls();
            } catch (exception) { error(exception.message); }
        };
        $("clear-history")?.addEventListener("click", clearCapturedTraffic);
        $("clear-all-session")?.addEventListener("click", clearCapturedTraffic);
        $("history-prev")?.addEventListener("click", () => { state.page = Math.max(1, state.page - 1); loadHistory(); });
        $("history-next")?.addEventListener("click", () => { state.page += 1; loadHistory(); });
        $("websocket-prev")?.addEventListener("click", () => { state.websocketPage = Math.max(1, state.websocketPage - 1); loadWebSockets(); });
        $("websocket-next")?.addEventListener("click", () => { state.websocketPage += 1; loadWebSockets(); });
        for (const id of ["filter-search", "filter-method", "filter-status", "filter-host", "filter-content-type", "filter-path"]) {
            const field = $(id);
            if (!field) continue;
            field.addEventListener(id === "filter-search" || id === "filter-host" || id === "filter-path" ? "input" : "change", () => {
                state.page = 1;
                clearTimeout(historySearchTimer);
                historySearchTimer = setTimeout(loadHistory, 180);
            });
        }
        $("websocket-search")?.addEventListener("input", () => {
            state.websocketPage = 1;
            clearTimeout(websocketSearchTimer);
            websocketSearchTimer = setTimeout(loadWebSockets, 180);
        });
        $("editor-search")?.addEventListener("input", () => {
            state.searchIndex = 0;
            renderEditorSearch();
        });
        for (const [id, view] of [["pretty-tab", "pretty"], ["raw-tab", "raw"], ["hex-tab", "hex"]]) {
            $(id)?.addEventListener("click", () => {
                state.editorView = view;
                for (const [buttonId, buttonView] of [["pretty-tab", "pretty"], ["raw-tab", "raw"], ["hex-tab", "hex"]]) {
                    $(buttonId).classList.toggle("active", buttonView === view);
                }
                renderEditorSearch();
            });
        }
        $("search-prev")?.addEventListener("click", () => {
            if (!state.searchMatches.length) return;
            state.searchIndex = (state.searchIndex - 1 + state.searchMatches.length) % state.searchMatches.length;
            renderEditorSearch();
        });
        $("search-next")?.addEventListener("click", () => {
            if (!state.searchMatches.length) return;
            state.searchIndex = (state.searchIndex + 1) % state.searchMatches.length;
            renderEditorSearch();
        });
        $("search-close")?.addEventListener("click", () => {
            $("editor-search").value = "";
            state.searchIndex = 0;
            renderEditorSearch();
            $("editor-search").focus();
        });
        $("save-settings")?.addEventListener("click", async () => {
            try {
                const snapshot = {address: $("proxy-address").value, port: Number($("proxy-port").value), max_history_entries: Number($("setting-max-history").value), max_body_size: Number($("setting-max-body").value), history_enabled: $("setting-history-enabled").checked, capture_request_body: $("setting-request-body").checked, capture_response_body: $("setting-response-body").checked, https_interception: $("setting-https").checked};
                state.status = await api("/api/proxy/settings", {method: "POST", body: JSON.stringify(snapshot)});
                state.settingsDirty = false;
                setControls();
            } catch (exception) { error(exception.message); }
        });
        for (const id of ["proxy-address", "proxy-port", "setting-max-history", "setting-max-body", "setting-history-enabled", "setting-request-body", "setting-response-body", "setting-https"]) {
            $(id)?.addEventListener("input", () => { state.settingsDirty = true; });
            $(id)?.addEventListener("change", () => { state.settingsDirty = true; });
        }
        $("generate-ca")?.addEventListener("click", async () => { try { await api("/api/proxy/ca/generate", {method: "POST"}); await refresh(); } catch (exception) { error(exception.message); } });
        $("export-ca")?.addEventListener("click", () => window.location.assign("/api/proxy/ca/export"));
        $("regenerate-ca")?.addEventListener("click", async () => { try { await api("/api/proxy/ca/generate", {method: "POST"}); await refresh(); } catch (exception) { error(exception.message); } });
        $("intruder-run")?.addEventListener("click", runIntruder);
        $("repeater-run")?.addEventListener("click", runRepeater);
        $("scanner-run")?.addEventListener("click", renderScannerSummary);
        $("decoder-run")?.addEventListener("click", decodeInput);
        $("comparer-run")?.addEventListener("click", compareInputs);
        $("extensions-refresh")?.addEventListener("click", renderExtensions);
        document.querySelectorAll("[data-settings-category]").forEach((button) => button.addEventListener("click", () => { document.querySelectorAll("[data-settings-category]").forEach((item) => item.classList.toggle("active", item === button)); document.querySelectorAll("[data-settings-section]").forEach((section) => section.classList.toggle("active", section.dataset.settingsSection === button.dataset.settingsCategory)); }));
        document.querySelectorAll("[data-editor-side]").forEach((button) => button.addEventListener("click", () => { state.editorSide = button.dataset.editorSide; document.querySelectorAll("[data-editor-side]").forEach((item) => item.classList.toggle("active", item === button)); $("request-content").classList.toggle("hidden", state.editorSide !== "request"); $("response-content").classList.toggle("hidden", state.editorSide !== "response"); renderEditorSearch(); }));
        const applyInterfaceSettings = () => {
            document.body.classList.toggle("compact-rows", $("setting-compact").checked);
            $("status-line").hidden = !$("setting-status").checked;
            state.showHeaders = $("setting-headers").checked;
            renderEditorSearch();
        };
        for (const id of ["setting-compact", "setting-status", "setting-headers"]) $(id)?.addEventListener("change", applyInterfaceSettings);
        applyInterfaceSettings();
    }

    bind();
    const initialTool = document.body.dataset.activeTool;
    const initialTab = ({intruder: "intruder", repeater: "repeater", scanner: "scanner", discover: "scanner", decoder: "decoder", comparer: "comparer", logger: "history", extensions: "extensions"})[initialTool];
    if (initialTab && !targetMode) showPanel(initialTab);
    refresh();

    const events = new EventSource("/api/proxy/events");
    const refreshTarget = async () => {
        try {
            state.targetSummary = await api("/api/proxy/target");
            renderSiteMap();
            renderIssues();
            if (state.activeTab === "scanner") renderScannerSummary();
        } catch (exception) { error(exception.message); }
    };
    const refreshStatus = async () => {
        try {
            state.status = await api("/api/proxy/status");
            state.intercept = state.status.settings?.intercept === true;
            setControls();
        } catch (exception) { error(exception.message); }
    };
    events.addEventListener("request", (event) => {
        const data = JSON.parse(event.data);
        if (data.request?.id === state.selectedId) {
            state.selected = data.request;
            renderEditor();
            setControls();
        }
        loadHistory();
        if (state.activeTab === "scanner" || targetMode) refreshTarget();
        refreshStatus();
    });
    events.addEventListener("response", (event) => {
        const data = JSON.parse(event.data);
        if (data.request?.id === state.selectedId) {
            state.selected = data.request;
            renderEditor();
            setControls();
        }
        loadHistory();
        if (state.activeTab === "scanner" || targetMode) refreshTarget();
        refreshStatus();
    });
    events.addEventListener("intercept", () => {
        loadIntercepts();
        refreshStatus();
    });
    events.addEventListener("websocket", () => {
        if (state.activeTab === "websockets") loadWebSockets();
        refreshStatus();
    });
    events.addEventListener("history_cleared", () => {
        state.page = 1;
        state.websocketPage = 1;
        if (!state.queue.some((item) => item.id === state.selectedId)) {
            state.selectedId = null;
            state.selected = null;
        }
        loadHistory();
        loadWebSockets();
        refreshTarget();
        renderEditor();
    });
    for (const eventName of ["status", "settings", "proxy_end", "statistics"]) {
        events.addEventListener(eventName, () => refreshStatus());
    }
})();
