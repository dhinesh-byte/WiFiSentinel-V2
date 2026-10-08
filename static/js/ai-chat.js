"use strict";

(() => {
    const drawer = document.getElementById("ai-drawer");
    const launcher = document.getElementById("ai-launcher");
    if (!drawer || !launcher) return;

    const transcript = document.getElementById("ai-transcript");
    const input = document.getElementById("ai-input");
    const composer = document.getElementById("ai-composer");
    const sendButton = document.getElementById("ai-send");
    const contextState = document.getElementById("ai-context-state");
    const contextMeta = document.getElementById("ai-context-meta");
    const statusIndicator = document.getElementById("ai-status-indicator");
    const availability = document.getElementById("ai-availability");
    const requestState = document.getElementById("ai-request-state");
    const headingSubtitle = drawer.querySelector(".ai-heading-copy span");
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
    const conversationKey = "wifiSentinelAiConversation";

    function readConversationId() {
        try {
            const value = localStorage.getItem(conversationKey) || "";
            return isConversationId(value) ? value : "";
        } catch {
            return "";
        }
    }

    function isConversationId(value) {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
    }

    const state = {
        conversationId: readConversationId(),
        scanId: "",
        module: document.body.dataset.mode === "offensive" ? "offensive" : "defensive",
        hostId: "",
        findingId: "",
        serviceId: "",
        compareScanId: "",
        deviceOS: "",
        guidanceAuthorizationToken: "",
        proxyRequestId: "",
        configured: false,
        busy: false,
        requestFailed: false,
    };

    function saveConversationId(value) {
        state.conversationId = isConversationId(value) ? value : "";
        try {
            if (state.conversationId) localStorage.setItem(conversationKey, state.conversationId);
            else localStorage.removeItem(conversationKey);
        } catch { /* In-memory conversation still works when browser storage is unavailable. */ }
    }

    function openDrawer() {
        drawer.dataset.open = "true";
        drawer.setAttribute("aria-hidden", "false");
        launcher.setAttribute("aria-expanded", "true");
        window.setTimeout(() => input?.focus(), 40);
    }

    function closeDrawer() {
        drawer.dataset.open = "false";
        drawer.setAttribute("aria-hidden", "true");
        launcher.setAttribute("aria-expanded", "false");
        launcher.focus();
    }

    function updateContext() {
        if (headingSubtitle) {
            headingSubtitle.textContent = state.module === "defensive"
                ? "Personal Defensive Security Assistant"
                : "Authorized assessment assistant";
        }
        if (state.proxyRequestId) {
            contextState.textContent = "Captured Proxy request selected";
            contextMeta.textContent = "VulnScan AI will use the selected request and response capture.";
        } else if (!state.scanId) {
            contextState.textContent = "No assessment selected.";
            contextMeta.textContent = "General cybersecurity questions are welcome.";
        } else if (state.findingId) {
            contextState.textContent = `${state.module === "offensive" ? "Offensive" : "Defensive"} finding selected`;
            contextMeta.textContent = state.hostId ? `Finding on ${state.hostId}` : "Selected finding from a saved report";
        } else if (state.hostId) {
            contextState.textContent = `${state.module === "offensive" ? "Offensive" : "Defensive"} host selected`;
            contextMeta.textContent = state.hostId;
        } else if (state.serviceId) {
            contextState.textContent = `${state.module === "offensive" ? "Offensive" : "Defensive"} service selected`;
            contextMeta.textContent = state.serviceId;
        } else {
            contextState.textContent = `${state.module === "offensive" ? "Offensive" : "Defensive"} assessment selected`;
            contextMeta.textContent = "VulnScan evidence will be used when relevant to your question.";
        }
    }

    function setContext(context = {}, options = {}) {
        if (!context || typeof context !== "object") context = {};
        if (Object.prototype.hasOwnProperty.call(context, "scanId")) state.scanId = stringValue(context.scanId);
        if (Object.prototype.hasOwnProperty.call(context, "module")) {
            state.module = context.module === "offensive" ? "offensive" : "defensive";
        }
        state.hostId = stringValue(context.hostId);
        state.findingId = stringValue(context.findingId);
        state.serviceId = stringValue(context.serviceId);
        state.compareScanId = stringValue(context.compareScanId);
        state.deviceOS = stringValue(context.deviceOS);
        state.guidanceAuthorizationToken = stringValue(context.guidanceAuthorizationToken);
        state.proxyRequestId = stringValue(context.proxyRequestId);
        if (!state.scanId) {
            state.hostId = "";
            state.findingId = "";
            state.serviceId = "";
            state.compareScanId = "";
            state.deviceOS = "";
        }
        updateContext();
        if (options.open) openDrawer();
    }

    function stringValue(value) {
        return typeof value === "string" ? value : "";
    }

    function addMessage(role, content) {
        const message = document.createElement("article");
        message.className = `ai-message ${role === "user" ? "ai-message-user" : "ai-message-assistant"}`;
        const label = document.createElement("div");
        label.className = "ai-message-label";
        label.textContent = role === "user" ? "You" : "VulnScan AI";
        const text = document.createElement("p");
        text.textContent = content || "";
        const time = document.createElement("time");
        time.dateTime = new Date().toISOString();
        time.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        message.append(label, text, time);
        transcript.append(message);
        transcript.scrollTop = transcript.scrollHeight;
        return { message, text };
    }

    function safeErrorMessage(payload, status) {
        const detail = payload && typeof payload.error === "string" ? payload.error.trim() : "";
        const implementationError = /unexpected token|cannot read properties|failed to fetch|networkerror|syntaxerror|typeerror|traceback|stack trace/i.test(detail);
        if (detail && !/[<>]/.test(detail) && !implementationError) return detail;
        if (status === 401 || status === 403) return "Your session has expired or this request is not authorized. Refresh the page and try again.";
        return "VulnScan AI returned an unexpected response. Refresh the page and try again; scanning remains available.";
    }

    async function readJsonResponse(response) {
        const contentType = response.headers.get("content-type") || "";
        if (!contentType.toLowerCase().includes("application/json")) {
            throw new Error(safeErrorMessage(null, response.status));
        }
        let payload;
        try {
            payload = await response.json();
        } catch {
            throw new Error("VulnScan AI returned an invalid response. Please try again.");
        }
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
            throw new Error("VulnScan AI returned an invalid response. Please try again.");
        }
        if (!response.ok || payload.success === false) {
            throw new Error(safeErrorMessage(payload, response.status));
        }
        return payload;
    }

    function setBusy(value) {
        state.busy = value;
        sendButton.disabled = value;
        input.disabled = value;
        sendButton.setAttribute("aria-busy", String(value));
        if (requestState) {
            requestState.textContent = value
                ? "AI ANALYZING"
                : state.requestFailed || !state.configured ? "AI UNAVAILABLE" : "CONNECTED TO OLLAMA";
            requestState.dataset.state = value ? "analyzing" : state.requestFailed || !state.configured ? "unavailable" : "ready";
        }
    }

    async function postJson(url, body) {
        const headers = { "Content-Type": "application/json", Accept: "application/json" };
        if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
        let response;
        try {
            response = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
        } catch {
            throw new Error("Cannot reach VulnScan AI right now. Check the connection and try again.");
        }
        return readJsonResponse(response);
    }

    async function streamAnswer(message, thinking) {
        const body = {
            message,
            conversation_id: state.conversationId || null,
            module: state.scanId ? state.module : null,
            scan_id: state.scanId || null,
            host_id: state.hostId || null,
            finding_id: state.findingId || null,
            service_id: state.serviceId || null,
            compare_scan_id: state.compareScanId || null,
            device_os: state.deviceOS || "",
            guidance_authorization_token: state.guidanceAuthorizationToken || null,
            proxy_request_id: state.proxyRequestId || null,
        };
        const headers = { "Content-Type": "application/json", Accept: "text/event-stream, application/json" };
        if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
        let response;
        try {
            response = await fetch("/api/ai/chat/stream", { method: "POST", headers, body: JSON.stringify(body) });
        } catch {
            throw new Error("Cannot reach VulnScan AI right now. Check the connection and try again.");
        }

        const contentType = response.headers.get("content-type") || "";
        if (contentType.toLowerCase().includes("application/json")) {
            const payload = await readJsonResponse(response);
            if (typeof payload.answer !== "string") throw new Error("VulnScan AI returned an invalid response. Please try again.");
            saveConversationId(payload.conversation_id);
            thinking.text.textContent = payload.answer;
            return;
        }
        if (!response.ok || !contentType.toLowerCase().includes("text/event-stream")) {
            throw new Error(safeErrorMessage(null, response.status));
        }
        if (!response.body || typeof response.body.getReader !== "function") {
            throw new Error("VulnScan AI could not start a response stream. Please try again.");
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let received = false;
        let completed = false;
        while (true) {
            const { value, done } = await reader.read();
            buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
            const events = buffer.split("\n\n");
            buffer = events.pop() || "";
            for (const event of events) {
                const line = event.split("\n").find((item) => item.startsWith("data: "));
                if (!line) continue;
                let data;
                try {
                    data = JSON.parse(line.slice(6));
                } catch {
                    throw new Error("VulnScan AI returned an invalid stream response. Please try again.");
                }
                if (data.error) throw new Error(safeErrorMessage(data, response.status));
                if (typeof data.token === "string") {
                    received = true;
                    if (thinking.text.querySelector(".ai-thinking")) thinking.text.replaceChildren();
                    thinking.text.textContent += data.token;
                    transcript.scrollTop = transcript.scrollHeight;
                }
                if (data.done) {
                    completed = true;
                    saveConversationId(data.conversation_id);
                }
            }
            if (done) break;
        }
        if (!received) throw new Error("VulnScan AI returned an empty response. Please try again.");
        if (!completed) throw new Error("VulnScan AI ended the response unexpectedly. Please try again.");
    }

    async function sendMessage(text = input.value.trim()) {
        if (!text || state.busy) return false;
        addMessage("user", text);
        input.value = "";
        state.requestFailed = false;
        setBusy(true);
        const thinking = addMessage("assistant", "");
        const dots = document.createElement("span");
        dots.className = "ai-thinking";
        dots.setAttribute("aria-label", "VulnScan AI is thinking");
        for (let index = 0; index < 3; index += 1) dots.append(document.createElement("i"));
        thinking.text.append(dots);
        try {
            await streamAnswer(text, thinking);
            addCommandCopyControls(thinking);
            return true;
        } catch (error) {
            thinking.text.textContent = error instanceof Error ? safeErrorMessage({ error: error.message }, 0) : "VulnScan AI could not complete the request. Please try again.";
            state.requestFailed = true;
            return false;
        } finally {
            setBusy(false);
            input.focus();
        }
    }

    function addCommandCopyControls(thinking) {
        if (state.module !== "defensive" || !state.scanId) return;
        const text = thinking.text.textContent || "";
        const commands = [...text.matchAll(/```[^\n]*\n([\s\S]*?)```/gu)]
            .map((match) => match[1].trim())
            .filter(Boolean);
        if (!commands.length) return;
        const actions = document.createElement("div");
        actions.className = "ai-command-actions";
        for (const command of commands) {
            const block = document.createElement("pre");
            block.textContent = command;
            const copy = document.createElement("button");
            copy.type = "button";
            copy.className = "subtle-button";
            copy.textContent = "Copy command";
            copy.addEventListener("click", async () => {
                try {
                    await navigator.clipboard.writeText(command);
                    copy.textContent = "Copied";
                } catch {
                    copy.textContent = "Copy unavailable";
                }
            });
            actions.append(block, copy);
        }
        thinking.message.append(actions);
    }

    async function loadStatus() {
        try {
            const response = await fetch("/api/ai/status", { headers: { Accept: "application/json" } });
            const status = await readJsonResponse(response);
            state.configured = status.configured === true;
            state.requestFailed = false;
            statusIndicator.dataset.ready = String(state.configured);
            statusIndicator.setAttribute("aria-label", state.configured ? "AI provider connected" : "AI is not configured");
            availability.textContent = state.configured
                ? `Ready · ${status.provider} / ${status.model}`
                : "AI is not configured yet. Set AI_PROVIDER and AI_MODEL to enable replies.";
        } catch (error) {
            state.configured = false;
            state.requestFailed = true;
            statusIndicator.dataset.ready = "false";
            statusIndicator.setAttribute("aria-label", "AI status unavailable");
            availability.textContent = error instanceof Error ? error.message : "AI status is unavailable. Scanning remains available.";
        }
        setBusy(false);
    }

    async function clearConversation() {
        try {
            await postJson("/api/ai/memory/clear", {
                scope: "conversation",
                conversation_id: state.conversationId || null,
            });
            saveConversationId("");
            transcript.replaceChildren();
            addMessage("assistant", "Conversation cleared. What would you like to explore?");
        } catch (error) {
            addMessage("assistant", error instanceof Error ? safeErrorMessage({ error: error.message }, 0) : "The conversation could not be cleared. Please try again.");
        }
    }

    launcher.addEventListener("click", openDrawer);
    document.getElementById("ai-close").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && drawer.dataset.open === "true") closeDrawer();
    });
    composer.addEventListener("submit", (event) => {
        event.preventDefault();
        sendMessage();
    });
    input.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            composer.requestSubmit();
        }
    });
    document.getElementById("ai-clear-conversation").addEventListener("click", clearConversation);
    document.addEventListener("click", (event) => {
        const contextButton = event.target.closest("[data-ai-scan-id], [data-ai-host], [data-ai-finding], [data-ai-service]");
        if (!contextButton || contextButton.closest("#ai-drawer")) return;
        setContext({
            scanId: contextButton.dataset.aiScanId || state.scanId,
            module: contextButton.dataset.aiModule || state.module,
            hostId: contextButton.dataset.aiHost,
            findingId: contextButton.dataset.aiFinding,
            serviceId: contextButton.dataset.aiService,
        }, { open: true });
    });

    window.WifiSentinelAI = {
        setContext,
        open: openDrawer,
        ask(message, context = {}) {
            setContext(context);
            openDrawer();
            return sendMessage(typeof message === "string" ? message : "");
        },
    };
    updateContext();
    loadStatus();
})();