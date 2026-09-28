# WiFi Sentinel

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
$env:WIFI_SENTINEL_PASSWORD = '<use a unique password of at least 16 characters>'
$env:WIFI_SENTINEL_SECRET_KEY = '<use a random secret of at least 32 characters>'
$env:WIFI_SENTINEL_COOKIE_SECURE = '1'
python app.py
```

To accept connections from a reverse proxy on another machine, set `WIFI_SENTINEL_HOST` to the required interface address. Terminate TLS at the trusted proxy, restrict access to that proxy, and keep `WIFI_SENTINEL_COOKIE_SECURE=1`. Do not expose the Waitress port directly to an untrusted network.

The overview and `/history` page use saved defensive scan records and offensive JSON reports. New defensive runs save detailed JSON under `data/reports`; older summary-only entries remain visible but cannot recover device details that were never stored.
