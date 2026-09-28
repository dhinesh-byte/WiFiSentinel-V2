def analyze_attack_paths(ports):
    """
    Defensive analysis of possible attack paths.

    This function does NOT perform attacks.
    It only identifies security concerns associated
    with exposed services.
    """

    attack_paths = []

    port_numbers = {
        port.get("port")
        for port in ports
    }

    if 21 in port_numbers:
        attack_paths.append({
            "title": "FTP Exposure",
            "severity": "MEDIUM",
            "description": (
                "FTP is reachable and may expose "
                "authentication or file-transfer services."
            ),
            "recommendation": (
                "Verify authentication, disable anonymous "
                "access, and use encrypted file transfer."
            )
        })

    if 22 in port_numbers:
        attack_paths.append({
            "title": "SSH Remote Access Exposure",
            "severity": "MEDIUM",
            "description": (
                "SSH provides remote administrative access "
                "and should be properly secured."
            ),
            "recommendation": (
                "Use strong authentication, keep SSH updated, "
                "and restrict access to trusted hosts."
            )
        })

    if 23 in port_numbers:
        attack_paths.append({
            "title": "Telnet Exposure",
            "severity": "HIGH",
            "description": (
                "Telnet provides remote access without "
                "modern encrypted communication."
            ),
            "recommendation": (
                "Disable Telnet and use a secure alternative "
                "such as SSH."
            )
        })

    if 80 in port_numbers:
        attack_paths.append({
            "title": "Web Application Exposure",
            "severity": "MEDIUM",
            "description": (
                "An HTTP service is reachable and may expose "
                "a web application to the local network."
            ),
            "recommendation": (
                "Review the application configuration, "
                "authentication, and security updates."
            )
        })

    if 443 in port_numbers:
        attack_paths.append({
            "title": "HTTPS Application Exposure",
            "severity": "LOW",
            "description": (
                "An HTTPS service is reachable and represents "
                "a web application attack surface."
            ),
            "recommendation": (
                "Keep the application and TLS configuration "
                "properly maintained."
            )
        })

    if 139 in port_numbers or 445 in port_numbers:
        attack_paths.append({
            "title": "Windows File-Sharing Exposure",
            "severity": "HIGH",
            "description": (
                "SMB/NetBIOS file-sharing services are reachable."
            ),
            "recommendation": (
                "Restrict file sharing to trusted devices "
                "and review share permissions."
            )
        })

    if 3389 in port_numbers:
        attack_paths.append({
            "title": "Remote Desktop Exposure",
            "severity": "HIGH",
            "description": (
                "Remote Desktop is reachable from the "
                "scanned network."
            ),
            "recommendation": (
                "Restrict RDP access and require strong "
                "authentication."
            )
        })

    if 3306 in port_numbers:
        attack_paths.append({
            "title": "Database Exposure",
            "severity": "HIGH",
            "description": (
                "A MySQL database service is reachable "
                "from the scanned network."
            ),
            "recommendation": (
                "Restrict database access to required hosts "
                "and review authentication."
            )
        })

    if 5432 in port_numbers:
        attack_paths.append({
            "title": "PostgreSQL Exposure",
            "severity": "HIGH",
            "description": (
                "A PostgreSQL database service is reachable."
            ),
            "recommendation": (
                "Restrict database network access and "
                "review authentication configuration."
            )
        })

    return attack_paths