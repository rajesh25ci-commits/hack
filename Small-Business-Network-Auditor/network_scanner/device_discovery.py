"""
NETGUARD - Member 1: Device Discovery Module
Handles local IP detection, subnet validation, ARP/Ping discovery,
hostname resolution, and MAC address collection.
"""

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Callable

from config import PERMITTED_PRIVATE_RANGES, MAX_HOSTS_PER_SCAN


def get_local_ip_and_subnet() -> Tuple[str, str]:
    """
    Detect the active local machine IP and suggest a safe /24 CIDR subnet.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Does not actually transmit packets to 8.8.8.8, purely retrieves active interface IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    if local_ip.startswith("127."):
        return local_ip, "127.0.0.1/32"

    try:
        # Create standard /24 subnet for local discovery
        ip_obj = ipaddress.IPv4Interface(f"{local_ip}/24")
        return local_ip, str(ip_obj.network)
    except Exception:
        return local_ip, f"{local_ip}/32"


def validate_target_subnet(target_str: str) -> Tuple[bool, str, str]:
    """
    Validates that the target is a valid IPv4 address or CIDR within
    permitted private/local ranges, with a safe host count.

    Returns: (is_valid, normalized_cidr, error_message)
    """
    if not target_str or not target_str.strip():
        return False, "", "Target network or IP address cannot be empty."

    target_clean = target_str.strip()

    try:
        # Try parsing as network or single host
        if "/" in target_clean:
            network = ipaddress.ip_network(target_clean, strict=False)
        else:
            ip = ipaddress.ip_address(target_clean)
            network = ipaddress.ip_network(f"{ip}/32", strict=False)
    except ValueError as e:
        return False, "", f"Invalid IP/CIDR format: {str(e)}"

    # Enforce IPv4
    if network.version != 4:
        return False, "", "Only IPv4 networks are supported for defensive auditing."

    # Check if network is in permitted private/local ranges
    permitted_nets = [ipaddress.ip_network(r) for r in PERMITTED_PRIVATE_RANGES]
    is_private = any(network.subnet_of(p) or network == p for p in permitted_nets)

    if not is_private:
        return False, "", (
            "Safety restriction violation: Scans are strictly restricted to private "
            "and local networks (RFC 1918 / Loopback: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). "
            "Scanning external or public IP addresses is not permitted."
        )

    # Enforce safe subnet size (at most /24 or 256 addresses)
    if network.num_addresses > MAX_HOSTS_PER_SCAN:
        return False, "", (
            f"Subnet too large ({network.num_addresses} addresses). To ensure safe and responsive scanning, "
            f"please specify a subnet with prefix /24 or smaller (maximum {MAX_HOSTS_PER_SCAN} hosts)."
        )

    return True, str(network), ""


def get_mac_address(ip_str: str) -> Optional[str]:
    """
    Lookup MAC address for an IP using the local ARP table cache.
    Works cross-platform without administrative privilege requirements.
    """
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(["arp", "-a", ip_str], stderr=subprocess.DEVNULL, timeout=2).decode("latin-1")
            match = re.search(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", output)
            if match:
                return match.group(1).replace("-", ":").upper()
        else:
            output = subprocess.check_output(["arp", "-n", ip_str], stderr=subprocess.DEVNULL, timeout=2).decode("utf-8")
            match = re.search(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", output)
            if match:
                return match.group(1).replace("-", ":").upper()
    except Exception:
        pass
    return None


def get_hostname(ip_str: str) -> Optional[str]:
    """
    Resolve reverse DNS / NetBIOS hostname for an IP address.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return None


def probe_single_host(ip_str: str, timeout: float = 0.5) -> bool:
    """
    Check if a host is responsive by attempting lightweight connection
    to common diagnostic ports (80, 443, 22, 445, 139, 53, 8080) or loopback.
    """
    # For loopback, always responsive
    if ip_str.startswith("127."):
        return True

    # Quick socket probe across fast ports
    probe_ports = [80, 443, 22, 445, 139, 53, 3389, 8080]
    for port in probe_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip_str, port))
            s.close()
            if result == 0:
                return True
        except Exception:
            continue

    # Fallback to ICMP ping using OS command (1 packet, short timeout)
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_str]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip_str]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def discover_devices(
    target_network: str,
    max_threads: int = 40,
    progress_callback: Optional[Callable[[float, str], None]] = None
) -> List[Dict]:
    """
    Discovers live devices on the validated target network.
    Returns list of discovered device dictionaries.
    """
    is_valid, normalized_cidr, error = validate_target_subnet(target_network)
    if not is_valid:
        raise ValueError(error)

    network = ipaddress.ip_network(normalized_cidr, strict=False)
    
    # Handle single IP vs subnet
    if network.num_addresses == 1:
        hosts = [str(network.network_address)]
    else:
        # Exclude network and broadcast if > 2 addresses
        hosts = [str(h) for h in network.hosts()]
        if not hosts:
            hosts = [str(network.network_address)]

    total_hosts = len(hosts)
    discovered_devices: List[Dict] = []
    completed = 0

    if progress_callback:
        progress_callback(0.05, f"Starting device discovery across {total_hosts} addresses...")

    with ThreadPoolExecutor(max_workers=min(max_threads, total_hosts or 1)) as executor:
        future_to_ip = {executor.submit(probe_single_host, ip): ip for ip in hosts}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1

            try:
                is_alive = future.result()
                if is_alive:
                    hostname = get_hostname(ip)
                    mac = get_mac_address(ip)
                    discovered_devices.append({
                        "ip": ip,
                        "hostname": hostname or "Unknown Host",
                        "mac": mac,
                        "status": "online",
                        "open_ports": [],
                        "services_summary": []
                    })
            except Exception:
                pass

            if progress_callback:
                pct = 0.05 + (0.45 * (completed / total_hosts))
                progress_callback(pct, f"Discovered {len(discovered_devices)} online host(s)... ({completed}/{total_hosts})")

    # Sort discovered devices by IP integer value
    discovered_devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return discovered_devices


def generate_simulated_devices(target: str = "192.168.1.0/24") -> List[Dict]:
    """
    Generates a realistic, clearly labelled simulated small business network.
    Covers real-world SMB risks:
    - Gateway router with exposed web admin
    - Legacy Windows PC with Telnet & SMBv1
    - Synology NAS with cleartext FTP
    - Retail Point of Sale (POS) machine with unencrypted VNC
    - Office Network Printer
    - Inventory Database Server with exposed MySQL
    """
    base_prefix = "192.168.1"
    try:
        net = ipaddress.ip_network(target, strict=False)
        first_ip = list(net.hosts())[0] if net.num_addresses > 1 else net.network_address
        octets = str(first_ip).split(".")
        base_prefix = f"{octets[0]}.{octets[1]}.{octets[2]}"
    except Exception:
        base_prefix = "192.168.1"

    return [
        {
            "ip": f"{base_prefix}.1",
            "hostname": "gateway-router.local",
            "mac": "00:1A:2B:3C:4D:01",
            "status": "online",
            "scan_mode": "simulated",
            "open_ports": [
                {"port": 53, "protocol": "tcp", "service": "dns", "version": "Dnsmasq 2.80"},
                {"port": 80, "protocol": "tcp", "service": "http", "version": "lighttpd 1.4.53 (Router Admin WebGUI)"},
                {"port": 443, "protocol": "tcp", "service": "https", "version": "OpenSSL/1.1.1 (Router SSL WebGUI)"},
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": "Dropbear sshd 2020.81"}
            ],
            "services_summary": ["DNS", "HTTP Admin", "HTTPS", "SSH"]
        },
        {
            "ip": f"{base_prefix}.15",
            "hostname": "accounting-pc-win7.local",
            "mac": "00:1A:2B:4E:5F:15",
            "status": "online",
            "scan_mode": "simulated",
            "open_ports": [
                {"port": 23, "protocol": "tcp", "service": "telnet", "version": "Microsoft Windows Telnet Service"},
                {"port": 139, "protocol": "tcp", "service": "netbios-ssn", "version": "Microsoft Windows NetBIOS"},
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "Windows 7 SMBv1 (Legacy File Sharing)"},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": "Microsoft Terminal Services (RDP without NLA)"}
            ],
            "services_summary": ["Telnet (Critical)", "NetBIOS", "SMBv1", "RDP"]
        },
        {
            "ip": f"{base_prefix}.25",
            "hostname": "office-nas-storage.local",
            "mac": "00:11:32:8A:9B:25",
            "status": "online",
            "scan_mode": "simulated",
            "open_ports": [
                {"port": 21, "protocol": "tcp", "service": "ftp", "version": "ProFTPD 1.3.5 (Unencrypted FTP)"},
                {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.29 (Storage Web Interface)"},
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "Samba 4.9.5"}
            ],
            "services_summary": ["Unencrypted FTP", "HTTP", "SMB"]
        },
        {
            "ip": f"{base_prefix}.42",
            "hostname": "checkout-pos-terminal.local",
            "mac": "B8:27:EB:12:34:42",
            "status": "online",
            "scan_mode": "simulated",
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http", "version": "POS Embedded Terminal Server"},
                {"port": 5900, "protocol": "tcp", "service": "vnc", "version": "TightVNC 2.8.11 (Unencrypted Remote Control)"}
            ],
            "services_summary": ["HTTP", "VNC (Remote Control)"]
        },
        {
            "ip": f"{base_prefix}.80",
            "hostname": "hplaserjet-frontdesk.local",
            "mac": "00:25:B3:67:89:80",
            "status": "online",
            "scan_mode": "simulated",
            "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http", "version": "HP HTTP Server (Embedded Web JetAdmin)"},
                {"port": 631, "protocol": "tcp", "service": "ipp", "version": "CUPS/IPP Printing Service"},
                {"port": 9100, "protocol": "tcp", "service": "jetdirect", "version": "HP Raw JetDirect Port"}
            ],
            "services_summary": ["HTTP JetAdmin", "IPP Printer", "JetDirect"]
        },
        {
            "ip": f"{base_prefix}.110",
            "hostname": "inventory-db-srv.local",
            "mac": "52:54:00:12:34:AE",
            "status": "online",
            "scan_mode": "simulated",
            "open_ports": [
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2p1 Ubuntu"},
                {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7.33 (Exposed Database)"},
                {"port": 6379, "protocol": "tcp", "service": "redis", "version": "Redis server 5.0.7 (Unprotected Cache)"}
            ],
            "services_summary": ["SSH", "MySQL Database", "Redis Cache"]
        }
    ]
