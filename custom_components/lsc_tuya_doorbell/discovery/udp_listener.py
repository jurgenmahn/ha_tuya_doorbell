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

# Protocol version assumed when a broadcast does not name one at all.
DEFAULT_PROTOCOL_VERSION = "3.3"


def classify_device_type(product_key: str) -> str:
    """Classify device type from product key."""
    return PRODUCT_KEY_DEVICE_TYPE.get(product_key, DEVICE_TYPE_UNKNOWN)


@dataclass
class DiscoveredDevice:
    """A Tuya device found via UDP broadcast.

    Everything in here comes from an unauthenticated broadcast, so it is
    self-reported by the device and nothing has been verified against the
    local key yet. That matters most for `version` — see `version_hint`.
    """

    device_id: str
    ip: str
    version: str
    product_key: str = ""
    device_type: str = DEVICE_TYPE_UNKNOWN
    last_seen: float = field(default_factory=time.monotonic)
    version_confirmed: bool = False

    @property
    def version_hint(self) -> str:
        """Protocol version as advertised in the broadcast — a guess, not a fact.

        Tuya firmware routinely announces a protocol version it does not
        actually speak over TCP: 3.3 is broadcast by devices that negotiate
        3.4 or 3.5, and the reverse happens too. Only a successful TCP
        handshake with the local key proves the version, at which point
        `version_confirmed` is set.

        Callers that put this in front of a user (the config flow) must offer
        it as an editable default, never as a fixed value.
        """
        return self.version

    def is_expired(self, ttl: float = 300.0) -> bool:
        """Check if this discovery entry has expired."""
        return (time.monotonic() - self.last_seen) > ttl


class UDPDiscoveryListener:
    """Listens for Tuya UDP broadcast announcements on ports 6666/6667.

    Only one listener per host can hold these ports. Inside Home Assistant the
    shared `DiscoveryManager` owns them; use `DiscoveryManager.async_discover`
    instead of instantiating a second listener.
    """

    def __init__(self) -> None:
        self._callbacks: list[Callable[[DiscoveredDevice], None]] = []
        self._transports: list[asyncio.DatagramTransport] = []
        self._devices: dict[str, DiscoveredDevice] = {}
        # Broadcast storms would otherwise turn one broken sender into a
        # flooded log; each distinct problem is reported once per listener.
        self._warned: set[str] = set()

    def on_device_found(
        self, callback: Callable[[DiscoveredDevice], None]
    ) -> Callable[[], None]:
        """Register a discovery callback. Returns an idempotent unregister function."""
        self._callbacks.append(callback)

        def _unregister() -> None:
            # Callers unregister in a `finally`, which can run twice on a
            # cancelled task; removing an absent callback must not raise.
            if callback in self._callbacks:
                self._callbacks.remove(callback)

        return _unregister

    def clear_callbacks(self) -> None:
        """Drop every registered callback."""
        self._callbacks.clear()

    @property
    def callback_count(self) -> int:
        """Number of registered callbacks (used to detect leaks)."""
        return len(self._callbacks)

    @property
    def listening(self) -> bool:
        """Whether at least one UDP port is currently bound."""
        return bool(self._transports)

    @property
    def devices(self) -> dict[str, DiscoveredDevice]:
        """Return all discovered devices."""
        return dict(self._devices)

    async def start(self) -> bool:
        """Bind UDP ports 6666 and 6667. Returns True if at least one bound."""
        if self._transports:
            return True

        loop = asyncio.get_running_loop()
        failures: list[str] = []

        for port in (UDP_PORT_PLAIN, UDP_PORT_ENCRYPTED):
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda p=port: _UDPProtocol(self, p),
                    local_addr=("0.0.0.0", port),
                    allow_broadcast=True,
                )
            except OSError as err:
                failures.append(f"{port} ({err.strerror or err})")
                continue
            self._transports.append(transport)
            _LOGGER.debug("UDP listener started on port %s", port)

        if self._transports:
            if failures:
                _LOGGER.debug(
                    "Some Tuya discovery ports were unavailable: %s",
                    ", ".join(failures),
                )
            return True

        _LOGGER.warning(
            "Could not bind any Tuya discovery port (%s). Another process on this "
            "host is already listening there — usually a second Tuya-based "
            "integration, or this integration's own background listener. Automatic "
            "discovery will report no devices until that port is free; in the "
            "meantime add the device manually with its IP address, device ID and "
            "local key.",
            ", ".join(failures) or "no ports attempted",
        )
        return False

    async def stop(self) -> None:
        """Release the UDP ports.

        Registered callbacks deliberately survive, because their lifetime
        belongs to whoever registered them; use `clear_callbacks` or the
        unregister function returned by `on_device_found` to drop them.
        """
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        self._warned.clear()
        _LOGGER.debug("UDP listeners stopped")

    async def scan(self, timeout: float = 10.0) -> list[DiscoveredDevice]:
        """Bind the ports, listen for `timeout` seconds and return what was seen.

        Prefer `DiscoveryManager.async_discover`: this method needs the UDP
        ports for itself and therefore fails whenever a background listener is
        already running.
        """
        self._devices.clear()
        if not await self.start():
            return []
        try:
            await asyncio.sleep(timeout)
        finally:
            await self.stop()
        return list(self._devices.values())

    def _warn_once(self, key: str, message: str, *args: object) -> None:
        """Log a warning the first time a given problem occurs on this listener."""
        if key in self._warned:
            return
        self._warned.add(key)
        _LOGGER.warning(message, *args)

    def _handle_broadcast(self, data: bytes, addr: tuple, port: int) -> None:
        """Process a received UDP broadcast packet."""
        try:
            # Extract payload (skip header and footer)
            if len(data) <= HEADER_SIZE + FOOTER_SIZE:
                return
            payload_bytes = data[HEADER_SIZE:-FOOTER_SIZE]

            if port == UDP_PORT_ENCRYPTED:
                payload_bytes = self._decode_encrypted(payload_bytes, addr)
                if payload_bytes is None:
                    return

            payload_str = payload_bytes.decode("utf-8", errors="ignore").strip("\x00")
            info = json.loads(payload_str)

            device_id = info.get("gwId", "")
            if not device_id:
                return

            product_key = info.get("productKey", "")
            device = DiscoveredDevice(
                device_id=device_id,
                ip=info.get("ip", addr[0]),
                # Self-reported and often wrong; see DiscoveredDevice.version_hint.
                version=info.get("version", DEFAULT_PROTOCOL_VERSION),
                product_key=product_key,
                device_type=classify_device_type(product_key),
            )

            is_new = device_id not in self._devices
            self._devices[device_id] = device

            if is_new:
                _LOGGER.debug(
                    "Discovered device %s at %s (v%s hint, type=%s, product=%s)",
                    device_id, device.ip, device.version,
                    device.device_type, product_key,
                )

            for callback in list(self._callbacks):
                try:
                    callback(device)
                except Exception:
                    # A raising callback is a bug in the consumer, not a stray
                    # packet; drop it so one broken listener cannot block the
                    # others, and say so loudly.
                    self._warn_once(
                        f"callback:{callback!r}",
                        "A discovery callback raised and has been unregistered; "
                        "device %s will not reach it. Please report this with "
                        "debug logging enabled",
                        device_id,
                    )
                    _LOGGER.debug("Discovery callback traceback", exc_info=True)
                    if callback in self._callbacks:
                        self._callbacks.remove(callback)

        except (json.JSONDecodeError, UnicodeDecodeError):
            # Foreign devices share these broadcast ports; their packets are
            # not our problem and must not fill the log.
            _LOGGER.debug("Malformed UDP broadcast from %s", addr[0])
        except Exception:
            self._warn_once(
                f"broadcast:{addr[0]}",
                "Unexpected error while processing a Tuya broadcast from %s; "
                "that device will be skipped. Enable debug logging for this "
                "integration and report the traceback",
                addr[0],
            )
            _LOGGER.debug("Broadcast processing traceback", exc_info=True)

    def _decode_encrypted(self, payload_bytes: bytes, addr: tuple) -> bytes | None:
        """Decrypt a port-6667 payload, or return None if it is not ours."""
        try:
            return TuyaCipher.decrypt_udp(payload_bytes)
        except Exception:
            # Port 6667 uses one fixed, publicly known key, so this is never a
            # "wrong local key" — either the packet is not a Tuya announcement,
            # or the firmware broadcasts in the clear on the encrypted port.
            if payload_bytes.lstrip(b"\x00").startswith(b"{"):
                return payload_bytes
            self._warn_once(
                f"decrypt:{addr[0]}",
                "Could not decrypt a UDP packet from %s on port %s. If this is "
                "your doorbell, it is speaking an unexpected dialect — add it "
                "manually by IP address and report the issue; otherwise it is "
                "unrelated traffic and can be ignored",
                addr[0], UDP_PORT_ENCRYPTED,
            )
            _LOGGER.debug("UDP decrypt traceback", exc_info=True)
            return None


class _UDPProtocol(asyncio.DatagramProtocol):
    """Internal DatagramProtocol for UDP broadcast reception."""

    def __init__(self, listener: UDPDiscoveryListener, port: int) -> None:
        self._listener = listener
        self._port = port

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._listener._handle_broadcast(data, addr, self._port)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("UDP error on port %s: %s", self._port, exc)
