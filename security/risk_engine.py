RISK_RULES = {
    21: {
        "service": "FTP",
        "risk": "HIGH",
        "score": 75,
        "why": "FTP can expose file-transfer services and may use unencrypted authentication.",
        "attacks": [
            "Credential attacks against exposed FTP authentication",
            "Unauthorized file access when permissions are weak",
            "Exposure of transferred data when encryption is not used"
        ],
        "defense": [
            "Disable FTP if it is not required",
            "Prefer secure file-transfer protocols",
            "Use strong authentication",
            "Restrict access to trusted devices"
        ]
    },

    22: {
        "service": "SSH",
        "risk": "MEDIUM",
        "score": 45,
        "why": "SSH provides remote administration and increases the device's remote-access attack surface.",
        "attacks": [
            "Credential guessing against exposed SSH",
            "Exploitation of an outdated SSH implementation",
            "Abuse of incorrect access permissions"
        ],
        "defense": [
            "Use strong authentication",
            "Restrict SSH to trusted devices",
            "Keep SSH and the operating system updated",
            "Disable SSH when it is unnecessary"
        ]
    },

    23: {
        "service": "Telnet",
        "risk": "CRITICAL",
        "score": 95,
        "why": "Telnet is an insecure remote-access protocol that can transmit credentials and data without modern encryption.",
        "attacks": [
            "Credential interception on an untrusted network",
            "Credential attacks",
            "Unauthorized remote access when credentials are compromised"
        ],
        "defense": [
            "Disable Telnet",
            "Use SSH instead",
            "Restrict remote administration to trusted networks"
        ]
    },

    80: {
        "service": "HTTP",
        "risk": "MEDIUM",
        "score": 50,
        "why": "HTTP provides a web service without transport encryption by default.",
        "attacks": [
            "Exposure of unencrypted traffic",
            "Abuse of vulnerable web applications",
            "Exploitation of insecure web-server configuration"
        ],
        "defense": [
            "Prefer HTTPS",
            "Keep the web server updated",
            "Review authentication and authorization",
            "Restrict unnecessary network access"
        ]
    },

    443: {
        "service": "HTTPS",
        "risk": "LOW",
        "score": 20,
        "why": "HTTPS is encrypted, but the underlying web application or server may still contain vulnerabilities.",
        "attacks": [
            "Exploitation of vulnerable web applications",
            "Weak authentication or authorization",
            "Outdated server software"
        ],
        "defense": [
            "Keep the web server updated",
            "Use secure authentication",
            "Review application permissions",
            "Use valid and modern TLS configuration"
        ]
    },

    445: {
        "service": "SMB",
        "risk": "HIGH",
        "score": 80,
        "why": "SMB provides network file and printer sharing and can create significant exposure when unnecessarily accessible.",
        "attacks": [
            "Unauthorized file-sharing access",
            "Abuse of weak permissions",
            "Exploitation of vulnerable or outdated SMB implementations"
        ],
        "defense": [
            "Restrict SMB to trusted devices",
            "Review sharing permissions",
            "Keep Windows and SMB components updated",
            "Disable unnecessary file sharing"
        ]
    },

    3389: {
        "service": "RDP",
        "risk": "HIGH",
        "score": 80,
        "why": "RDP provides remote desktop access and should be restricted to trusted systems.",
        "attacks": [
            "Credential attacks against remote access",
            "Exploitation of outdated RDP components",
            "Unauthorized remote access after credential compromise"
        ],
        "defense": [
            "Restrict RDP access",
            "Use strong authentication",
            "Keep Windows updated",
            "Disable RDP when unnecessary"
        ]
    },

    3306: {
        "service": "MySQL",
        "risk": "HIGH",
        "score": 75,
        "why": "A database service exposed to the network can increase the risk of unauthorized database access.",
        "attacks": [
            "Credential attacks",
            "Unauthorized database access",
            "Abuse of insecure database configuration"
        ],
        "defense": [
            "Restrict database access to required hosts",
            "Use strong database credentials",
            "Keep the database updated",
            "Do not expose the database unnecessarily"
        ]
    },

    5432: {
        "service": "PostgreSQL",
        "risk": "HIGH",
        "score": 75,
        "why": "A network-accessible database service should only be reachable by trusted applications and administrators.",
        "attacks": [
            "Credential attacks",
            "Unauthorized database access",
            "Misconfiguration abuse"
        ],
        "defense": [
            "Restrict database network access",
            "Use strong authentication",
            "Keep PostgreSQL updated",
            "Review access-control rules"
        ]
    }
}


def analyze_port(port):
    """
    Return security information for a detected port.
    """

    try:
        port = int(port)
    except (TypeError, ValueError):
        return {
            "service": "Unknown",
            "risk": "UNKNOWN",
            "score": 0,
            "why": "The port number could not be analyzed.",
            "attacks": [],
            "defense": []
        }

    if port in RISK_RULES:
        return RISK_RULES[port]

    return {
        "service": "Unknown",
        "risk": "LOW",
        "score": 10,
        "why": "An open port was detected, but no specific risk rule is configured for this port.",
        "attacks": [
            "Unnecessary service exposure",
            "Risk may increase if the underlying service is outdated or misconfigured"
        ],
        "defense": [
            "Identify the service using the port",
            "Disable it if unnecessary",
            "Keep the service updated",
            "Restrict access to trusted devices"
        ]
    }


def calculate_device_risk(ports):
    """
    Calculate an overall device risk from detected ports.
    """

    if not ports:
        return {
            "risk": "LOW",
            "score": 0
        }

    analyses = [
        analyze_port(port.get("port"))
        for port in ports
    ]

    highest_score = max(
        analysis["score"]
        for analysis in analyses
    )

    if highest_score >= 90:
        level = "CRITICAL"
    elif highest_score >= 70:
        level = "HIGH"
    elif highest_score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk": level,
        "score": highest_score
    }