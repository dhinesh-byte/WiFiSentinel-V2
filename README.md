# VulnScan v4.13

## Local development

Install dependencies and start the unified application from the project directory:

```powershell
python -m pip install -r requirements.txt
python app.py
```

The default bind is `127.0.0.1:5000`; debug mode is disabled and Waitress serves the application. Data and report locations are resolved relative to the project files, not the current working directory.

Defensive host checks run concurrently with a conservative default of four workers. Tune within the enforced 1–8 worker limit with `WIFI_SENTINEL_SCAN_WORKERS`; per-host timeout and port-selection behavior remain unchanged.

## Remote deployment

Keep the service on loopback unless it is protected by an HTTPS reverse proxy. A non-loopback bind is refused unless authentication, a strong signing key, and secure cookies are configured. Set these environment variables before starting the service:

```powershell
$env:WIFI_SENTINEL_HOST = '127.0.0.1'
$env:WIFI_SENTINEL_PORT = '5000'
$env:WIFI_SENTINEL_USERNAME = 'operator'
$env:WIFI_SENTINEL_PASSWORD = '<set a non-empty password>'
$env:WIFI_SENTINEL_SECRET_KEY = '<use a random secret of at least 32 characters>'
$env:WIFI_SENTINEL_COOKIE_SECURE = '1'
python app.py
```

To accept connections from a reverse proxy on another machine, set `WIFI_SENTINEL_HOST` to the required interface address. Terminate TLS at the trusted proxy, restrict access to that proxy, and keep `WIFI_SENTINEL_COOKIE_SECURE=1`. Do not expose the Waitress port directly to an untrusted network.

The overview and `/history` page use saved defensive scan records and offensive JSON reports. New defensive runs save detailed JSON under `data/reports`; older summary-only entries remain visible but cannot recover device details that were never stored.

### Admin and user login

VulnScan uses one shared sign-in page for both account types. Set distinct administrator and user usernames and non-empty passwords with `VULNSCAN_ADMIN_USERNAME`, `VULNSCAN_ADMIN_PASSWORD`, `VULNSCAN_USER_USERNAME`, and `VULNSCAN_USER_PASSWORD`. Standard scan access is shared, while the advanced Nmap controls described below are administrator-only. Authentication also requires `WIFI_SENTINEL_SECRET_KEY` with at least 32 characters. The legacy `WIFI_SENTINEL_USERNAME` and `WIFI_SENTINEL_PASSWORD` pair remains supported as a single administrator account. Environment files are examples only; the application does not load `.env` automatically.

### Administrator Nmap controls

The Defensive and Offensive scan forms show advanced Nmap controls only to administrators. They are opt-in for each scan; leaving them disabled preserves the existing scan flow. Controls include host-discovery methods; TCP connect/SYN, UDP, FIN/NULL/Xmas, SCTP, and IP-protocol scans; port presets or bounded custom ports; service/version and OS detection; IPv6; traceroute; state-reason and packet-trace output; timing, retries, timeouts, and parallelism; and approved NSE checks for web, SMB, DNS, TLS, databases, and selected vulnerability indicators. Web/TLS assessment also uses the existing application-level checks.

Named Quick, Standard, Deep, Vulnerability, and Full profiles apply bounded defaults. Vulnerability and Full profiles, all-port scans, vulnerability checks, and specialized scan techniques require a separate per-scan authorization confirmation. Skipping host discovery is limited to one explicitly selected host; UDP can be assessed with a bounded supplementary service set.

The server validates every option and does not accept arbitrary Nmap arguments or NSE script names. Advanced jobs are limited to 256 target addresses and custom port selections to 4,096 ports/protocols. Raw-packet scan types, OS fingerprinting, and traceroute require the VulnScan process to have the necessary OS-level privileges; unavailable OS fingerprinting is reported as skipped. Nmap's port-state reasons, progress/timing details, and requested packet traces are included in results when available. JSON remains the application report format; administrators can additionally select XML export and download the combined Nmap XML artifact when Nmap returns XML data.

Long scans show Nmap's own phase percentage and ETA when the installed Nmap advertises periodic statistics and emits timing updates; otherwise the dashboard uses stage/host progress and does not invent a Nmap percentage. Both scan modes allow an active assessment to be cancelled, including while Nmap is running. Nmap XML output is capped at 16 MiB per process and retained diagnostic output at 1 MiB; exceeding the XML limit ends that process with an explicit output-limit result. Timeout, cancellation, output-limit, and scanner execution failures remain distinguishable in scan results. TLS certificate verification failures are reported as assessment errors, with validation guidance, and are not bypassed.

Both Defensive and Offensive scan dashboards include an Nmap Live Console. Server-Sent Events relay stdout and stderr from the exact Nmap subprocesses already launched by the scanner; stdout remains the XML stream used by VulnScan's parser, while stderr includes Nmap's own diagnostics and timing output. VulnScan assessment events remain in a separate panel. The console is a bounded live/replay window, not a persisted report artifact.

## VulnScan Proxy

VulnScan Proxy is an independent HTTP/HTTPS traffic workbench at `/proxy`; it does not use the Defensive or Offensive scanner pipelines. Its Intercept, HTTP history, WebSockets history, Match and replace, Request replay, and Proxy settings workspaces use the maintained `mitmproxy` engine declared in `requirements.txt`. It captures traffic from real clients configured to use the displayed local listener, defaulting to `127.0.0.1:8080`. The listener is restricted to loopback so VulnScan cannot be exposed as a network-wide open proxy. **Open browser** launches Chrome with a temporary profile configured for the running listener; it does not reuse or modify the user's normal browser profile.

Start the Proxy from its page, then configure an authorized browser or test client to use the listener address. HTTP requests are forwarded and captured directly. HTTPS uses a CONNECT tunnel by default; to inspect decrypted HTTPS, explicitly generate the local CA in Proxy Settings, enable HTTPS interception, export the public certificate, and install/trust it manually only on a device or test application you own or are authorized to assess. VulnScan never changes the operating-system trust store, and upstream certificate verification stays enabled. The private CA material is stored under `data/proxy/` and excluded from Git.

Intercept mode pauses real requests until the user chooses Forward or Drop. Request editing is explicit, visibly marked, and restricted to the captured destination origin. Match and replace only previews literal changes on a selected intercepted request; the user must open the request editor and explicitly forward it. WebSocket history is populated from real mitmproxy frame events. Request Replay also requires a manual Send action and remains on the captured origin. Captured traffic is held in memory only; history and body captures are bounded and can be disabled or cleared in the UI. Binary bodies are represented as metadata rather than rendered as text. Replay responses are captured by the local Proxy when routed through the listener.

## VulnScan AI

VulnScan AI is one optional personal cybersecurity assistant shared by Defensive, Offensive, and scan-history views. It infers whether a message asks for an explanation, learning, risk clarification, remediation, troubleshooting, assessment interpretation, a quiz, or general discussion. The chat keeps one continuous conversation and automatically uses a selected saved assessment, host, or finding. Scanning, risk analysis, reports, and history do not depend on an AI provider. With no provider configured, the drawer clearly reports that AI replies are unavailable and the rest of the platform remains usable.

### Setup and providers

The provider adapter uses Python's standard library; no model SDK is required. It supports the OpenAI Chat Completions API (`openai`) and OpenAI-compatible endpoints (`openai_compatible`), including compatible hosted services and local servers. Provider/model names and keys are read only from environment variables. The application does not load `.env` files automatically; `.env.example` is a safe reference, not a secret store.

#### Local Ollama

Install Ollama for your Windows user, then pull a compact instruction model:

```powershell
ollama pull qwen2.5:3b
$env:AI_PROVIDER = 'openai_compatible'
$env:AI_MODEL = 'qwen2.5:3b'
$env:AI_BASE_URL = 'http://127.0.0.1:11434/v1'
$env:AI_API_KEY = ''
$env:WIFI_SENTINEL_PORT = '5004'
python app.py
```

Ollama must be running locally on port `11434`. This loads a pretrained model and grounds answers with VulnScan's system prompt and selected scan evidence; it does not fine-tune model weights. Fine-tuning would require a chosen training dataset, model-specific training tools, and suitable hardware, none of which are included in this project.

PowerShell example for an OpenAI-compatible local endpoint:

```powershell
$env:AI_PROVIDER = 'openai_compatible'
$env:AI_MODEL = '<model name provided by your endpoint>'
$env:AI_BASE_URL = 'http://127.0.0.1:11434/v1'
$env:AI_API_KEY = ''
$env:AI_TEMPERATURE = '0.3'
$env:AI_MAX_TOKENS = '900'
python app.py
```

For OpenAI, set `AI_PROVIDER=openai`, `AI_MODEL`, and `AI_API_KEY`; `AI_BASE_URL` defaults to `https://api.openai.com/v1`. For another compatible endpoint, set `AI_PROVIDER=openai_compatible`, `AI_MODEL`, and `AI_BASE_URL`; its API key may be empty if the endpoint does not require one. Optional bounds are `AI_TEMPERATURE` (0–2) and `AI_MAX_TOKENS` (64–4096). The configured endpoint must support the OpenAI chat-completions request format. Streaming uses server-sent events; a compatible response without streaming is returned as a complete response when its endpoint replies with JSON.

### Improving answer quality and fine-tuning

VulnScan currently improves answers through its system instructions, selected saved-report evidence, recent conversation, and optional user preferences; it does not update model weights. Scan answers are instructed to distinguish recorded observations from interpretation, say when evidence is missing, and recommend bounded, non-destructive next steps. Keep report context as the source of current scan facts: fine-tuning is better suited to stable response behavior than to memorizing changing vulnerabilities or private scan results.

A responsible fine-tuning effort should proceed in stages:

1. Establish a reviewed baseline of representative questions and expected-answer criteria for explanations, troubleshooting, scan interpretation, remediation, learning, follow-ups, uncertainty, and prompt-injection attempts.
2. Create a first-party, human-reviewed dataset of synthetic or explicitly approved examples. Remove credentials, personal data, identifying targets, and private report contents; confirm the data license and consent before using any external or user-provided material.
3. Convert examples to the selected model's supported chat-training format, commonly JSONL records with `messages` containing `system`, `user`, and `assistant` turns. Keep separate training, validation, and held-out evaluation examples; do not evaluate only on training examples.
4. Fine-tune an instruction model with that model's documented training tools, starting with a parameter-efficient adapter such as LoRA when supported. Training is a separate offline workflow; the current OpenAI-compatible/Ollama inference adapter does not train models.
5. Compare the candidate against the baseline for factual grounding, unsupported-claim rate, usefulness, safety-boundary adherence, language/profile behavior, and latency. Review failures manually, rerun the held-out set after each dataset or prompt change, and deploy only when it improves quality without weakening safety.
6. Keep the existing system prompt, server-side report validation, bounded context, and authorization checks in production. Version the model and adapter, retain a rollback option, and do not use live conversations or scan reports for training by default.

Fine-tuning requires a chosen base model that permits training, a legally usable reviewed dataset, model-specific training software, and suitable compute. None is included in this application. Do not send private scan data to a training service unless the organization has explicitly approved its data handling and retention terms.

### Architecture and use

The `ai/` package separates provider construction, prompts/personality, report context, conversations, local memory, learning, safety, and Flask APIs. The drawer has a single conversation view. Selecting a host, service, or finding attaches its identifier to the next chat request; the server reloads the saved report and rejects identifiers that are not present. No scan evidence is required for general cybersecurity questions.

For quiz requests, the assistant asks one short original question in the conversation and explains the answer after the user replies. It can teach concepts at beginner level by default and expand technically when asked. Finding workflow statuses remain separate from scan results and are never automatically marked verified. Only a later assessment can provide verification evidence.

### Memory and privacy

Conversations, explicit memories, learning progress, and remediation statuses are stored as JSON beneath `data/ai/`. A signed, HTTP-only, same-site browser cookie isolates unauthenticated local sessions; when the existing single-operator login is enabled, memory follows that configured operator. The signing key and all AI data are local and excluded from Git. Personal preferences and learning progress can be disabled, reviewed, or cleared from the drawer. Conversation history is separate to support follow-ups and has its own delete control; learning-only and all-memory deletion remove their corresponding saved records.

When the user asks about a scan, only structured fields from the selected saved report are sent. Host/finding questions narrow this further to the selected entity and related records. No raw HTML, arbitrary client-supplied scan object, scan history dump, API key, or application credential is intentionally sent. Scanner-sourced strings are treated as untrusted data, bounded, and redacted for common secret formats. The configured provider receives the prompt, the bounded recent conversation/summary, enabled user preferences or explicit memories, and the selected structured evidence. Do not configure a provider unless its data handling is acceptable for your assessment environment.

Requests are size-limited and rate-limited per session. Provider/model, request ID, success/failure, and latency may be logged; prompt text, scan evidence, and provider keys are not logged. API errors are returned without stopping scanner workflows. Do not place credentials or secrets in explicit memory; common credential formats are rejected there and redacted from conversation/report context.

### Security boundaries and troubleshooting

AI answers distinguish saved scanner observations from general security knowledge, interpretation, and recommendations. A port/service observation or exact-CPE catalog correlation is not proof of exploitability. The assistant does not run scans, exploit systems, attempt credentials, or apply changes. Offensive assessment guidance remains limited to explicitly authorized scope and safe validation. Remediation status `VERIFIED` is a user-controlled workflow label, not proof by itself; verify with a subsequent scan.

Eligible findings in the Offensive dashboard include an **EXPLOIT / VALIDATION GUIDANCE** panel. Detailed guidance and related AI context are gated by an explicit authorized lab/CTF confirmation scoped to that report and finding. The panel provides scanner-backed evidence, read-only validation ideas, conceptual explanations, remediation guidance, and a workflow timeline; VulnScan does not execute validation or exploit actions. Validation states and observations added to a report are explicitly labeled as user-recorded and are not independently verified by VulnScan.

- `AI is not configured yet`: set `AI_PROVIDER`, `AI_MODEL`, and the endpoint/key values required by that provider, then restart Flask.
- `The AI provider rejected its API key`: check `AI_API_KEY` with the provider; never paste it into chat or memory.
- Timeouts or rate limits: check endpoint reachability, provider availability, and request limits. Scanner features remain available.
- Missing assessment detail: older history summaries may not retain hosts, ports, or findings. The assistant will not reconstruct evidence that was not saved.
