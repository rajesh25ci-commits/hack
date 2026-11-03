"""
NETGUARD - Member 2: Port Scanner Module
Integrates python-nmap with resilient native Python socket fallback,
TCP port scanning, service banner grabbing, timeouts, and JSON formatting.
"""

import socket
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Callable

from config import KNOWN_SERVICES, SOCKET_CONNECT_TIMEOUT

# Check if nmap binary exists on the system PATH
def is_nmap_available() -> bool:
    """Check if the nmap binary executable is available on PATH."""
    return shutil.which("nmap") is not None


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Safely attempts to grab the service identification banner.
    Sends passive or standard probes based on port (e.g. HTTP, FTP, SSH).
    """
    banner = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Some services (SSH, FTP, SMTP, Telnet) immediately send a banner upon connection
        if port in [21, 22, 23, 25, 110, 143]:
            try:
                response = s.recv(1024).decode("utf-8", errors="ignore").strip()
                if response:
                    banner = response.split("\n")[0].strip()
            except Exception:
                pass
        elif port in [80, 8080, 8000, 3000, 5000]:
            # For HTTP, send a simple HEAD request
            probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetGuard-Auditor/1.0\r\n\r\n"
            s.sendall(probe.encode("utf-8"))
            try:
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()
                        break
            except Exception:
                pass
        s.close()
    except Exception:
        pass
    return banner


def scan_single_port(ip: str, port: int, timeout: float = SOCKET_CONNECT_TIMEOUT) -> Optional[Dict]:
    """
    Attempts a single TCP connect to the specified IP and port.
    Returns port information dictionary if open, else None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            known = KNOWN_SERVICES.get(port, {})
            service_name = known.get("name", f"service-{port}")
            version = grab_banner(ip, port, timeout=1.0)

            return {
                "port": port,
                "protocol": "tcp",
                "service": service_name,
                "version": version or (known.get("desc") if known else None)
            }
    except Exception:
        pass
    return None


def scan_ports_with_nmap(ip: str, ports: List[int], timeout: int = 30) -> List[Dict]:
    """
    Scans ports using python-nmap when nmap binary is available.
    """
    import nmap
    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in ports)
    
    # -sT: unprivileged TCP connect scan (safe, no raw packet driver needed)
    # -Pn: Treat host as online
    # -T3: Normal polite timing
    # --host-timeout: maximum scan time
    args = f"-sT -Pn -T3 --host-timeout {timeout}s"
    
    nm.scan(hosts=ip, ports=port_str, arguments=args)
    
    open_ports: List[Dict] = []
    if ip in nm.all_hosts():
        tcp_data = nm[ip].get("tcp", {})
        for port, info in tcp_data.items():
            if info.get("state") == "open":
                open_ports.append({
                    "port": int(port),
                    "protocol": "tcp",
                    "service": info.get("name", KNOWN_SERVICES.get(port, {}).get("name", f"port-{port}")),
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip() or None
                })
    return open_ports


def scan_ports_with_socket(
    ip: str,
    ports: List[int],
    max_workers: int = 25,
    timeout: float = SOCKET_CONNECT_TIMEOUT
) -> List[Dict]:
    """
    Robust native multi-threaded TCP socket scanner.
    Works anywhere without external binary or root privileges.
    """
    open_ports: List[Dict] = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as executor:
        future_to_port = {executor.submit(scan_single_port, ip, p, timeout): p for p in ports}
        for future in as_completed(future_to_port):
            try:
                res = future.result()
                if res:
                    open_ports.append(res)
            except Exception:
                pass

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def scan_device_ports(
    ip: str,
    ports: List[int],
    prefer_nmap: bool = True,
    timeout: int = 30
) -> List[Dict]:
    """
    Scans ports for a specific device, using Nmap if available and falling back to native socket.
    """
    if prefer_nmap and is_nmap_available():
        try:
            return scan_ports_with_nmap(ip, ports, timeout=timeout)
        except Exception:
            # Graceful fallback to socket if nmap failed or threw permissions error
            return scan_ports_with_socket(ip, ports)
    else:
        return scan_ports_with_socket(ip, ports)


def scan_network_ports(
    devices: List[Dict],
    ports: List[int],
    progress_callback: Optional[Callable[[float, str], None]] = None,
    prefer_nmap: bool = True
) -> List[Dict]:
    """
    Iterates through all discovered devices and scans their open ports.
    Updates the device dicts with open_ports and services_summary.
    """
    total_devices = len(devices)
    if total_devices == 0:
        return devices

    for index, dev in enumerate(devices):
        ip = dev["ip"]
        if progress_callback:
            pct = 0.50 + (0.45 * (index / total_devices))
            progress_callback(pct, f"Auditing open ports on host {ip} ({index + 1}/{total_devices})...")

        # If device already has ports (e.g. from simulated mode), preserve or scan
        if dev.get("scan_mode") == "simulated" and dev.get("open_ports"):
            continue

        open_ports = scan_device_ports(ip, ports, prefer_nmap=prefer_nmap)
        dev["open_ports"] = open_ports

        # Create quick human-readable service summary
        services = []
        for p in open_ports:
            svc_name = p.get("service") or f"Port {p['port']}"
            services.append(f"{svc_name} ({p['port']})")
        dev["services_summary"] = services

    if progress_callback:
        progress_callback(0.95, "Port scanning completed. Aggregating results...")

    return devices
