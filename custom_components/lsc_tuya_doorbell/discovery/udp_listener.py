"""UDP broadcast listener for Tuya device discovery."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from ..const import DEVICE_TYPE_UNKNOWN, PRODUCT_KEY_DEVICE_TYPE
from ..protocol.encryption import TuyaCipher

_LOGGER = logging.getLogger(__name__)

# UDP discovery ports
UDP_PORT_PLAIN = 6666
UDP_PORT_ENCRYPTED = 6667

# Broadcast packet structure: [header 20 bytes][payload][footer 8 bytes]
HEADER_SIZE = 20
FOOTER_SIZE = 8


def classify_device_type(product_key: str) -> str:
    """Classify device type from product key."""
    return PRODUCT_KEY_DEVICE_TYPE.get(product_key, DEVICE_TYPE_UNKNOWN)


@dataclass
class DiscoveredDevice:
    """Represents a Tuya device found via UDP broadcast."""

    device_id: str
    ip: str
    version: str
    product_key: str = ""
    device_type: str = DEVICE_TYPE_UNKNOWN
    last_seen: float = field(default_factory=time.monotonic)

    def is_expired(self, ttl: float = 300.0) -> bool:
        """Check if this discovery entry has expired."""
        return (time.monotonic() - self.last_seen) > ttl


class UDPDiscoveryListener:
    """Listens for Tuya UDP broadcast announcements on ports 6666/6667."""

    def __init__(self) -> None:
        self._callbacks: list[Callable[[DiscoveredDevice], None]] = []
        self._transports: list[asyncio.DatagramTransport] = []
        self._devices: dict[str, DiscoveredDevice] = {}

    def on_device_found(self, callback: Callable[[DiscoveredDevice], None]) -> Callable[[], None]:
        """Register a callback for when a device is discovered. Returns unregister function."""
        self._callbacks.append(callback)
        return lambda: self._callbacks.remove(callback)

    @property
    def devices(self) -> dict[str, DiscoveredDevice]:
        """Return all discovered devices."""
        return dict(self._devices)

    async def start(self) -> None:
        """Start listening on UDP ports 6666 and 6667."""
        loop = asyncio.get_running_loop()

        for port in [UDP_PORT_PLAIN, UDP_PORT_ENCRYPTED]:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda p=port: _UDPProtocol(self, p),
                    local_addr=("0.0.0.0", port),
                    allow_broadcast=True,
                )
                self._transports.append(transport)
                _LOGGER.debug("UDP listener started on port %s", port)
            except OSError:
                _LOGGER.debug("Could not bind UDP port %s (may be in use)", port)

    async def stop(self) -> None:
        """Stop all UDP listeners."""
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        _LOGGER.debug("UDP listeners stopped")

    async def scan(self, timeout: float = 10.0) -> list[DiscoveredDevice]:
        """Listen for devices for a specified duration and return all found."""
        self._devices.clear()
        await self.start()
        try:
            await asyncio.sleep(timeout)
        finally:
            await self.stop()
        return list(self._devices.values())

    def _handle_broadcast(self, data: bytes, addr: tuple, port: int) -> None:
        """Process a received UDP broadcast packet."""
        try:
            # Extract payload (skip header and footer)
            if len(data) <= HEADER_SIZE + FOOTER_SIZE:
                return
            payload_bytes = data[HEADER_SIZE:-FOOTER_SIZE]

            # Decrypt if from encrypted port
            if port == UDP_PORT_ENCRYPTED:
                try:
                    payload_bytes = TuyaCipher.decrypt_udp(payload_bytes)
                except Exception:
                    # Other Tuya devices on the network — not our device, ignore
                    return

            # Parse JSON
            payload_str = payload_bytes.decode("utf-8", errors="ignore").strip("\x00")
            info = json.loads(payload_str)

            device_id = info.get("gwId", "")
            if not device_id:
                return

            product_key = info.get("productKey", "")
            device = DiscoveredDevice(
                device_id=device_id,
                ip=info.get("ip", addr[0]),
                version=info.get("version", "3.3"),
                product_key=product_key,
                device_type=classify_device_type(product_key),
            )

            is_new = device_id not in self._devices
            self._devices[device_id] = device

            if is_new:
                _LOGGER.debug(
                    "Discovered device %s at %s (v%s, type=%s, product=%s)",
                    device_id, device.ip, device.version,
                    device.device_type, product_key,
                )

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(device)
                except Exception:
                    _LOGGER.debug("Discovery callback error", exc_info=True)

        except (json.JSONDecodeError, UnicodeDecodeError):
            _LOGGER.debug("Malformed UDP broadcast from %s", addr[0])
        except Exception:
            _LOGGER.debug("Error processing UDP broadcast", exc_info=True)


class _UDPProtocol(asyncio.DatagramProtocol):
    """Internal DatagramProtocol for UDP broadcast reception."""

    def __init__(self, listener: UDPDiscoveryListener, port: int) -> None:
        self._listener = listener
        self._port = port

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._listener._handle_broadcast(data, addr, self._port)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("UDP error on port %s: %s", self._port, exc)
