"""
NETGUARD - Member 3: Security Analysis Engine
Evaluates discovered devices and open ports against defensive cybersecurity rules,
generating structured, evidence-based security findings and actionable recommendations.
"""

from typing import Dict, List, Tuple


def analyze_network_security(devices: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Performs deterministic, evidence-based security audits on discovered devices.
    Returns: (findings_list, recommendations_list)
    """
    findings: List[Dict] = []
    recommendations: List[Dict] = []
    finding_counter = 1

    for device in devices:
        ip = device.get("ip", "Unknown")
        hostname = device.get("hostname", "Unknown Host")
        open_ports = device.get("open_ports", [])
        port_numbers = {p["port"] for p in open_ports}

        # Rule 1: Telnet Exposure (Port 23) - Critical
        if 23 in port_numbers:
            p_info = next(p for p in open_ports if p["port"] == 23)
            version_str = p_info.get("version") or "Standard Telnet listener"
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": f_id,
                "title": "Critical Legacy Telnet Service Exposed",
                "device_ip": ip,
                "hostname": hostname,
                "port": 23,
                "protocol": "tcp",
                "service": "telnet",
                "severity": "Critical",
                "evidence": f"Port 23/tcp detected OPEN on host {ip}. Identified version banner: {version_str}",
                "explanation": (
                    "Telnet is a 1980s legacy remote management protocol that transmits all login credentials "
                    "and command traffic completely unencrypted over the local network. Anyone with physical "
                    "or Wi-Fi network access can intercept passwords in plaintext."
                ),
                "solution": (
                    "1. Access the device administration console.\n"
                    "2. Disable the Telnet service immediately.\n"
                    "3. Replace with SSH (Port 22) for secure encrypted remote administration.\n"
                    "4. If SSH is not supported, restrict management access to an isolated VLAN."
                ),
                "verification": f"Test connection to {ip}:23 using 'Test-NetConnection -ComputerName {ip} -Port 23' or re-scan with NetGuard. Port must show CLOSED.",
                "requires_manual_verification": False
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Disable Telnet on {hostname} ({ip})",
                "priority": "Critical",
                "category": "Remote Access Hardening",
                "action": "Disable Telnet and enforce SSH with key-based authentication.",
                "impact": "Eliminates plaintext credential theft and eavesdropping risks.",
                "status": "Pending",
                "notes": ""
            })

        # Rule 2: Unencrypted FTP (Port 21) - High
        if 21 in port_numbers:
            p_info = next(p for p in open_ports if p["port"] == 21)
            version_str = p_info.get("version") or "Standard FTP server"
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": f_id,
                "title": "Cleartext FTP File Transfer Protocol Detected",
                "device_ip": ip,
                "hostname": hostname,
                "port": 21,
                "protocol": "tcp",
                "service": "ftp",
                "severity": "High",
                "evidence": f"Port 21/tcp detected OPEN on {ip}. Banner: {version_str}",
                "explanation": (
                    "The standard File Transfer Protocol (FTP) sends usernames, passwords, and sensitive company "
                    "documents across the local network without encryption. Network sniffing or rogue devices can "
                    "capture confidential files."
                ),
                "solution": (
                    "1. Deactivate standard FTP service in the device settings.\n"
                    "2. Enable SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS/SSL).\n"
                    "3. Ensure anonymous FTP login is strictly disabled."
                ),
                "verification": f"Verify connection with TLS required or verify Port 21 is closed on {ip}.",
                "requires_manual_verification": True
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Upgrade FTP to SFTP/FTPS on {hostname} ({ip})",
                "priority": "High",
                "category": "Data Encryption in Transit",
                "action": "Disable cleartext FTP Port 21 and transition file transfers to SFTP (Port 22) or FTPS.",
                "impact": "Protects business files, payroll, and customer data from network interception.",
                "status": "Pending",
                "notes": ""
            })

        # Rule 3: Exposed SMB / Legacy NetBIOS (Ports 445 / 139) - High / Critical
        if 445 in port_numbers or 139 in port_numbers:
            exposed_ports = [p for p in [139, 445] if p in port_numbers]
            port_str = ", ".join(str(p) for p in exposed_ports)
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": f_id,
                "title": "Exposed Windows SMB / File Sharing Services",
                "device_ip": ip,
                "hostname": hostname,
                "port": 445 if 445 in port_numbers else 139,
                "protocol": "tcp",
                "service": "smb/netbios",
                "severity": "High",
                "evidence": f"Ports {port_str}/tcp open on {ip}. SMB / NetBIOS file sharing active.",
                "explanation": (
                    "SMB (Server Message Block) allows network file and printer sharing. If exposed on unsegmented "
                    "workstations or outdated OS versions (such as Windows 7 or older Samba), it is susceptible to "
                    "ransomware lateral movement (e.g. WannaCry/EternalBlue) and credential harvesting."
                ),
                "solution": (
                    "1. Disable SMBv1 across the network via Group Policy or Windows Features.\n"
                    "2. Enforce SMB signing and encryption (SMB 3.0+).\n"
                    "3. If this host is an end-user workstation, disable file sharing in Network Settings."
                ),
                "verification": f"Run 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' on Windows host to ensure SMBv1 is Disabled.",
                "requires_manual_verification": True
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Harden File Sharing & Disable SMBv1 on {hostname} ({ip})",
                "priority": "High",
                "category": "Ransomware Defense",
                "action": "Ensure SMBv1 is disabled and restrict SMB sharing to authorized departmental file servers only.",
                "impact": "Stops lateral spreading of ransomware and worm attacks.",
                "status": "Pending",
                "notes": ""
            })

        # Rule 4: Remote Desktop Protocol (RDP - Port 3389) - High
        if 3389 in port_numbers:
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": f_id,
                "title": "Exposed Remote Desktop Protocol (RDP)",
                "device_ip": ip,
                "hostname": hostname,
                "port": 3389,
                "protocol": "tcp",
                "service": "rdp",
                "severity": "High",
                "evidence": f"Port 3389/tcp detected OPEN on {ip}. Windows Terminal Services listening.",
                "explanation": (
                    "Remote Desktop Protocol provides full graphical login to the machine. RDP endpoints are "
                    "prime targets for brute-force attacks and credential stuffing, especially if Network Level "
                    "Authentication (NLA) is not strictly enforced."
                ),
                "solution": (
                    "1. Enforce Network Level Authentication (NLA) in System Properties > Remote Settings.\n"
                    "2. Never expose Port 3389 directly to the internet; use a secure VPN for remote workers.\n"
                    "3. Require complex passwords and multi-factor authentication for remote access accounts."
                ),
                "verification": "Confirm NLA checkbox is enabled: System Properties > Remote > 'Allow connections only from computers running Remote Desktop with Network Level Authentication'.",
                "requires_manual_verification": True
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Enforce NLA & Restrict RDP on {hostname} ({ip})",
                "priority": "High",
                "category": "Access Control",
                "action": "Enable Network Level Authentication and restrict RDP access behind VPN.",
                "impact": "Prevents unauthorized graphical access and brute-force takeover.",
                "status": "Pending",
                "notes": ""
            })

        # Rule 5: Exposed Database Listeners (MySQL 3306, MSSQL 1433, Postgres 5432, Redis 6379, MongoDB 27017)
        db_ports = {
            3306: ("MySQL / MariaDB", "High"),
            1433: ("Microsoft SQL Server", "High"),
            5432: ("PostgreSQL", "High"),
            6379: ("Redis In-Memory Store", "Critical"),
            27017: ("MongoDB NoSQL", "High")
        }
        for db_p, (db_name, db_sev) in db_ports.items():
            if db_p in port_numbers:
                f_id = f"FIND-{finding_counter:03d}"
                finding_counter += 1

                findings.append({
                    "id": f_id,
                    "title": f"Unrestricted Database Listener: {db_name}",
                    "device_ip": ip,
                    "hostname": hostname,
                    "port": db_p,
                    "protocol": "tcp",
                    "service": db_name.lower().split()[0],
                    "severity": db_sev,
                    "evidence": f"Port {db_p}/tcp open on {ip}. Database service {db_name} accessible across local network.",
                    "explanation": (
                        f"{db_name} is listening directly on a network-wide interface. Many database instances "
                        f"in small businesses are configured with default or blank passwords, allowing full extraction "
                        f"of customer records, transactions, and employee data."
                    ),
                    "solution": (
                        f"1. Bind {db_name} listener to localhost (127.0.0.1) if only local applications need access.\n"
                        "2. If remote access is required, configure host firewall to whitelist specific application server IPs only.\n"
                        "3. Enforce strong, randomized administrative passwords and audit user privileges."
                    ),
                    "verification": f"Verify bind-address = 127.0.0.1 in configuration file, or verify host firewall blocks access from general employee subnets.",
                    "requires_manual_verification": True
                })

                recommendations.append({
                    "finding_id": f_id,
                    "device_ip": ip,
                    "title": f"Secure Database Port {db_p} on {hostname} ({ip})",
                    "priority": db_sev,
                    "category": "Database Security",
                    "action": f"Bind {db_name} to 127.0.0.1 or restrict network access via host firewall.",
                    "impact": "Prevents unauthorized direct data dumps and data breach incidents.",
                    "status": "Pending",
                    "notes": ""
                })

        # Rule 6: Unencrypted VNC Remote Screen Access (Port 5900) - High
        if 5900 in port_numbers:
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": f_id,
                "title": "Unencrypted VNC Screen Control Exposed",
                "device_ip": ip,
                "hostname": hostname,
                "port": 5900,
                "protocol": "tcp",
                "service": "vnc",
                "severity": "High",
                "evidence": f"Port 5900/tcp detected OPEN on {ip}. VNC server active.",
                "explanation": (
                    "VNC allows real-time viewing and mouse/keyboard control of the screen. Standard VNC "
                    "transmits screen bitmaps and keystrokes unencrypted, and frequently relies on weak 8-character passwords."
                ),
                "solution": (
                    "1. Disable VNC if not actively required for point-of-sale maintenance.\n"
                    "2. Tunnel VNC connections through SSH (ssh -L 5900:localhost:5900).\n"
                    "3. Restrict incoming connections to trusted administrator IP addresses."
                ),
                "verification": f"Scan host {ip}:5900 to ensure port is closed or bound only to localhost.",
                "requires_manual_verification": False
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Secure or Disable VNC on {hostname} ({ip})",
                "priority": "High",
                "category": "Screen Access Security",
                "action": "Disable VNC or tunnel through SSH encryption.",
                "impact": "Stops eavesdropping on live screens (POS cash registers, admin workstations).",
                "status": "Pending",
                "notes": ""
            })

        # Rule 7: Cleartext HTTP Web Management Interface (Port 80 / 8080 without HTTPS 443) - Medium
        if (80 in port_numbers or 8080 in port_numbers) and 443 not in port_numbers:
            http_port = 80 if 80 in port_numbers else 8080
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": f_id,
                "title": "Unencrypted HTTP Web Management (No HTTPS Detected)",
                "device_ip": ip,
                "hostname": hostname,
                "port": http_port,
                "protocol": "tcp",
                "service": "http",
                "severity": "Medium",
                "evidence": f"Port {http_port}/tcp open on {ip}, but encrypted HTTPS (Port 443) was not detected.",
                "explanation": (
                    "The device provides a web management interface over unencrypted HTTP. When administrators "
                    "log into this web panel, passwords and session cookies are sent in plain text across the network."
                ),
                "solution": (
                    "1. Enable HTTPS in the device administration portal.\n"
                    "2. Enable automatic redirection from HTTP to HTTPS.\n"
                    "3. If HTTPS cannot be enabled, change the default administrator password immediately."
                ),
                "verification": f"Access https://{ip} in a browser and verify successful encrypted TLS connection.",
                "requires_manual_verification": True
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Enable HTTPS for Web Admin on {hostname} ({ip})",
                "priority": "Medium",
                "category": "Web Console Hardening",
                "action": "Activate TLS/SSL on web console and disable unencrypted HTTP.",
                "impact": "Protects administrator login credentials from packet sniffing.",
                "status": "Pending",
                "notes": ""
            })

        # Rule 8: Excessive Exposed Attack Surface (> 4 open ports on single device) - Low
        if len(open_ports) > 4:
            f_id = f"FIND-{finding_counter:03d}"
            finding_counter += 1
            port_list_str = ", ".join(str(p["port"]) for p in open_ports)

            findings.append({
                "id": f_id,
                "title": "Broad Attack Surface (Multiple Open Ports)",
                "device_ip": ip,
                "hostname": hostname,
                "port": "Multiple",
                "protocol": "tcp",
                "service": "multiple",
                "severity": "Low",
                "evidence": f"{len(open_ports)} open TCP ports identified on {ip} ({port_list_str}).",
                "explanation": (
                    f"This device has {len(open_ports)} listening network services. The principle of least privilege "
                    "dictates that devices should only expose services strictly necessary for their business function."
                ),
                "solution": (
                    "1. Review the running services on this host.\n"
                    "2. Stop and disable any services or background daemons not required for day-to-day operations.\n"
                    "3. Configure host-based firewall (Windows Defender Firewall or iptables) to block unused inbound ports."
                ),
                "verification": "Re-audit device to confirm unnecessary listening ports are closed.",
                "requires_manual_verification": True
            })

            recommendations.append({
                "finding_id": f_id,
                "device_ip": ip,
                "title": f"Minimize Open Services on {hostname} ({ip})",
                "priority": "Low",
                "category": "Surface Reduction",
                "action": "Disable unneeded background services and tighten local firewall rules.",
                "impact": "Reduces vectors available to potential attackers.",
                "status": "Pending",
                "notes": ""
            })

    return findings, recommendations
