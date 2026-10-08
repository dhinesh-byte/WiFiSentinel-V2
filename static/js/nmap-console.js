(() => {
	"use strict";

	const shell = document.getElementById("nmap-terminal-shell");
	const feed = document.getElementById("nmap-terminal-output");
	const commands = document.getElementById("nmap-terminal-commands");
	const state = document.getElementById("nmap-terminal-state");
	const version = document.getElementById("nmap-terminal-version");
	const notice = document.getElementById("nmap-terminal-notice");
	const copyButton = document.getElementById("nmap-copy-output");
	const clearButton = document.getElementById("nmap-clear-output");
	const autoScroll = document.getElementById("nmap-auto-scroll");
	const jumpButton = document.getElementById("nmap-jump-latest");
	if (!shell || !feed || !commands || !state) return;
	const panel = shell.closest(".nmap-live-console");

	let source = null;
	let activeUrl = null;
	let reconnectTimer = null;
	let reconnectAttempt = 0;
	let streamFinished = false;
	let processCount = 0;
	let outputLineBreaks = 0;
	let outputHasText = false;
	let outputEndsWithLineBreak = false;
	const activeProcesses = new Set();
	let processFailed = false;
	let followLatest = true;
	const cursor = document.createElement("span");
	cursor.className = "nmap-terminal-cursor";
	cursor.setAttribute("aria-hidden", "true");

	function setState(value) {
		state.textContent = value;
		state.dataset.state = value.toLowerCase().replaceAll(" ", "-");
		panel?.classList.toggle("is-running", value === "RUNNING");
		if (value === "RUNNING") {
			if (!cursor.isConnected) feed.append(cursor);
		} else {
			cursor.remove();
		}
	}

	function updateOutputCount() {
		const counter = document.getElementById("nmap-output-count");
		if (!counter) return;
		const lines = outputLineBreaks + (outputHasText && !outputEndsWithLineBreak ? 1 : 0);
		counter.textContent = `Lines: ${lines}`;
	}

	function scrollToLatest() {
		shell.scrollTop = shell.scrollHeight;
		if (jumpButton) jumpButton.hidden = true;
	}

	function writeOutput(text, channel) {
		if (text) {
			outputHasText = true;
			outputLineBreaks += (text.match(/\n/gu) || []).length;
			outputEndsWithLineBreak = text.endsWith("\n");
			updateOutputCount();
		}
		const chunk = document.createElement("span");
		chunk.className = channel === "stderr" ? "nmap-output-stderr" : "nmap-output-stdout";
		chunk.dataset.nmapOutputChunk = "true";
		chunk.textContent = text;
		cursor.remove();
		feed.append(chunk);
		if (state.textContent === "RUNNING") feed.append(cursor);
		if (followLatest) scrollToLatest();
		else if (jumpButton) jumpButton.hidden = false;
	}

	function closeStream() {
		if (reconnectTimer !== null) {
			window.clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}
		if (source) {
			source.close();
			source = null;
		}
	}

	function reset() {
		closeStream();
		activeUrl = null;
		streamFinished = false;
		reconnectAttempt = 0;
		feed.replaceChildren();
		commands.replaceChildren();
		processCount = 0;
		outputLineBreaks = 0;
		outputHasText = false;
		outputEndsWithLineBreak = false;
		updateOutputCount();
		activeProcesses.clear();
		processFailed = false;
		if (notice) {
			notice.textContent = "";
			notice.hidden = true;
		}
		followLatest = true;
		if (autoScroll) {
			autoScroll.checked = true;
		}
		setState("AWAITING PROCESS");
	}

	function connect(url) {
		closeStream();
		activeUrl = url;
		streamFinished = false;
		reconnectAttempt = 0;
		if (!url || typeof EventSource !== "function") {
			if (notice) {
				notice.textContent = "Live output streaming is unavailable in this browser.";
				notice.hidden = false;
			}
			return;
		}
		source = new EventSource(url);
		const connectedSource = source;
		source.onopen = () => {
			if (source !== connectedSource) return;
			reconnectAttempt = 0;
			if (notice) notice.hidden = true;
		};
		source.onerror = () => {
			if (source !== connectedSource) return;
			if (notice) {
				notice.textContent = "LIVE STREAM DISCONNECTED · reconnecting";
				notice.hidden = false;
			}
			if (connectedSource.readyState === EventSource.CLOSED && activeUrl && !streamFinished && reconnectTimer === null) {
				const retryUrl = activeUrl;
				const delay = Math.min(1000 * (2 ** reconnectAttempt), 15000);
				reconnectAttempt += 1;
				reconnectTimer = window.setTimeout(() => connect(retryUrl), delay);
			}
		};

		source.addEventListener("process_started", (message) => {
			const event = JSON.parse(message.data);
			processCount += 1;
			activeProcesses.add(String(event.command_id || processCount));
			setState("RUNNING");
			const separator = document.createElement("div");
			separator.className = "nmap-terminal-command";
			separator.textContent = `NMAP COMMAND ${processCount}${event.target ? ` · ${event.target}` : ""}`;
			commands.append(separator);
		});

		source.addEventListener("output", (message) => {
			const event = JSON.parse(message.data);
			writeOutput(String(event.text || ""), event.channel);
		});

		source.addEventListener("process_exited", (message) => {
			const event = JSON.parse(message.data);
			const exitLabel = event.returncode === null || event.returncode === undefined
				? "NO EXIT CODE"
				: `EXIT ${event.returncode}`;
			const outcome = event.status === "cancelled"
				? "CANCELLED"
				: event.status === "completed" && event.returncode === 0
					? "COMPLETED"
					: "FAILED";
			activeProcesses.delete(String(event.command_id || ""));
			if (outcome === "FAILED") processFailed = true;
			setState(activeProcesses.size
				? "RUNNING"
				: outcome === "CANCELLED" ? outcome : processFailed ? "FAILED" : "RUNNING");
			if (notice && outcome !== "COMPLETED") {
				notice.textContent = event.error
					? `${exitLabel} · ${event.error}`
					: exitLabel;
				notice.hidden = false;
			}
		});

		source.addEventListener("execution_error", (message) => {
			const event = JSON.parse(message.data);
			processFailed = true;
			if (!activeProcesses.size) setState("FAILED");
			if (notice) {
				notice.textContent = `Nmap could not be started: ${String(event.message || "Execution failed.")}`;
				notice.hidden = false;
			}
				writeOutput(`${String(event.message || "Nmap could not be started.")}\n`, "stderr");
		});

		source.addEventListener("assessment_end", (message) => {
			const event = JSON.parse(message.data);
			streamFinished = true;
			activeUrl = null;
			const statusValue = String(event.status || "completed").toLowerCase();
			setState(statusValue === "partial" || statusValue === "incomplete"
				? "COMPLETED WITH WARNINGS"
				: statusValue === "failed" || statusValue === "cancelled" ? statusValue.toUpperCase() : "COMPLETED");
			closeStream();
		});

		source.addEventListener("history_gap", () => {
			if (notice) {
				notice.textContent = "Some earlier stream events are outside the replay window; new Nmap output is continuing below.";
				notice.hidden = false;
			}
		});
	}

	copyButton?.addEventListener("click", async () => {
		const actualOutput = [...feed.querySelectorAll("[data-nmap-output-chunk]")]
			.map((chunk) => chunk.textContent || "")
			.join("");
		try {
			await navigator.clipboard.writeText(actualOutput);
			copyButton.textContent = "Copied";
			window.setTimeout(() => { copyButton.textContent = "Copy"; }, 1400);
		} catch {
			if (notice) {
				notice.textContent = "Clipboard access was unavailable.";
				notice.hidden = false;
			}
		}
	});

	clearButton?.addEventListener("click", () => {
		feed.replaceChildren();
		commands.replaceChildren();
		outputLineBreaks = 0;
		outputHasText = false;
		outputEndsWithLineBreak = false;
		updateOutputCount();
	});

	autoScroll?.addEventListener("change", () => {
		followLatest = autoScroll.checked;
		if (followLatest) scrollToLatest();
		else if (jumpButton) jumpButton.hidden = false;
	});

	shell.addEventListener("scroll", () => {
		const atBottom = shell.scrollHeight - shell.scrollTop - shell.clientHeight < 16;
		if (atBottom) {
			followLatest = true;
			if (autoScroll) {
				autoScroll.checked = true;
			}
			if (jumpButton) jumpButton.hidden = true;
		} else if (autoScroll?.checked) {
			followLatest = false;
			autoScroll.checked = false;
			if (jumpButton) jumpButton.hidden = false;
		}
	});

	jumpButton?.addEventListener("click", () => {
		followLatest = true;
		if (autoScroll) {
			autoScroll.checked = true;
		}
		scrollToLatest();
	});

	window.VulnScanNmapConsole = {
		connect,
		reset,
		setVersion(value) {
			if (version && value) version.textContent = String(value);
		},
	};
})();
