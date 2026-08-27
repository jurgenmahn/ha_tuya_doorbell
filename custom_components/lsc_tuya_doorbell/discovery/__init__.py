"""Device discovery for Tuya devices on the local network.

Ports 6666/6667 can only be held by one listener per host. The shared
`DiscoveryManager` owns them; everything else asks it for devices through
`async_discover_devices(hass)` instead of binding a socket of its own.
"""

from .manager import (
    DISCOVERY_DATA_KEY,
    DiscoveryManager,
    async_discover_devices,
    async_get_manager,
)
from .scanner import TCPScanner
from .udp_listener import DiscoveredDevice, UDPDiscoveryListener

__all__ = [
    "DISCOVERY_DATA_KEY",
    "DiscoveredDevice",
    "DiscoveryManager",
    "TCPScanner",
    "UDPDiscoveryListener",
    "async_discover_devices",
    "async_get_manager",
]
