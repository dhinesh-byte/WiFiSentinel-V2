"""Repository-grounded VulnScan knowledge and general learning paths."""

PROJECT_KNOWLEDGE = """VulnScan v4.13 is a Flask application with separate Defensive and Offensive modules.
Defensive mode runs Nmap host discovery, port/service/version and optional OS detection, then records device risks and JSON reports under data/reports. Its risk observations are heuristic exposure indicators, not proof of a vulnerability.
Offensive mode is an explicitly authorized, non-exploitative assessment workflow. It discovers hosts, enumerates ports/services, runs selected allow-listed protocol NSE checks, performs bounded web/TLS observations, and correlates an offline CVE catalog only on exact CPE matches. Its reports retain evidence, confidence, limitations, remediation and verification guidance.
Scan history is stored as JSON summaries plus JSON reports. Older history entries may contain summary counts without device-level detail. Do not claim missing details are known.
Scanner evidence, general security knowledge, interpretation, and recommendations must be distinguished. Never turn an open port or a service label into a confirmed vulnerability. A CVE match is a catalog correlation, not proof of exploitability. A fix is verified only by a later assessment that confirms the observation changed.
All assessment activity remains explicitly operator-controlled. Never exploit, guess credentials, execute destructive actions, or claim that this assistant performed a scan or remediation."""

LEARNING_PATHS = [
    {
        "id": "networking-basics",
        "title": "Networking Basics",
        "concepts": ["IP addresses", "TCP and UDP", "Ports", "DNS", "HTTP", "TLS", "SMB"],
    },
    {
        "id": "web-security",
        "title": "Web Security",
        "concepts": ["HTTP", "Authentication", "Sessions", "Input validation", "OWASP concepts"],
    },
    {
        "id": "network-security",
        "title": "Network Security",
        "concepts": ["Host discovery", "Service enumeration", "Network segmentation", "TLS", "Firewall concepts"],
    },
]