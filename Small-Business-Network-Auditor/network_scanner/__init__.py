"""
Network Scanner Package for NETGUARD
Modules for Host Discovery and Port Scanning.
"""

from .device_discovery import (
    validate_target_subnet,
    get_local_ip_and_subnet,
    discover_devices,
    generate_simulated_devices
)
from .port_scanner import (
    scan_device_ports,
    scan_network_ports,
    is_nmap_available
)

__all__ = [
    "validate_target_subnet",
    "get_local_ip_and_subnet",
    "discover_devices",
    "generate_simulated_devices",
    "scan_device_ports",
    "scan_network_ports",
    "is_nmap_available"
]
