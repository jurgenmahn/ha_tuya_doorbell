"""Discovery lifecycle management and caching."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Callable

from ..const import DOMAIN
from .scanner import TCPScanner
from .udp_listener import (
    UDP_PORT_ENCRYPTED,
    UDP_PORT_PLAIN,
    DiscoveredDevice,
    UDPDiscoveryListener,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = 300  # 5 minutes

# Key under which the shared manager lives in hass.data[DOMAIN].
DISCOVERY_DATA_KEY = "discovery"

# Tuya devices announce themselves roughly every 5 seconds and not in step
# with each other, so after the first answer we stay open for one more full
# interval — otherwise a two-doorbell household reliably sees only one.
SETTLE_SECONDS = 6.0


class DiscoveryManager:
    """Owns the UDP discovery ports and caches what they hear.

    Only one instance may exist per Home Assistant instance: ports 6666/6667
    cannot be shared. Everything that needs a device list — the config flow
    included — goes through `async_discover` rather than binding its own
    listener.
    """

    def __init__(
        self,
        hass: HomeAssistant | None = None,
        cache_ttl: float = DEFAULT_CACHE_TTL,
    ) -> None:
        self._hass = hass
        self._udp_listener = UDPDiscoveryListener()
        self._tcp_scanner = TCPScanner(hass=hass)
        self._cache: dict[str, DiscoveredDevice] = {}
        self._cache_ttl = cache_ttl
        self._background_task: asyncio.Task | None = None
        self._running = False
        self._unsubscribe: Callable[[], None] | None = None

    @property
    def cache(self) -> dict[str, DiscoveredDevice]:
        """Return current cache (without expired entries)."""
        self._evict_expired()
        return dict(self._cache)

    @property
    def listening(self) -> bool:
        """Whether the shared background listener currently holds the UDP ports."""
        return self._running

    async def start_background_listener(self) -> None:
        """Start the persistent UDP listener that feeds the shared cache."""
        if self._running:
            return

        unsubscribe = self._udp_listener.on_device_found(self._remember)
        if not await self._udp_listener.start():
            # start() already logged an actionable warning about the port.
            unsubscribe()
            return

        self._unsubscribe = unsubscribe
        self._running = True
        _LOGGER.debug("Background discovery listener started")

    async def stop(self) -> None:
        """Stop the background listener, drop its callback and clear the cache."""
        self._running = False
        if self._unsubscribe is not None:
            # Without this a start -> stop -> start cycle stacks up callbacks
            # and every broadcast gets cached N times.
            self._unsubscribe()
            self._unsubscribe = None
        await self._udp_listener.stop()
        self._cache.clear()
        _LOGGER.debug("Discovery manager stopped")

    async def async_discover(self, timeout: float = 10.0) -> list[DiscoveredDevice]:
        """Return the devices known on the local network.

        Answers immediately from the shared cache when the background listener
        has already heard something. Only an empty cache costs time: then it
        waits up to `timeout` seconds for a first broadcast, plus one broadcast
        interval to pick up its neighbours.

        Works with and without a running background listener — without one it
        binds a private listener for the duration of the call. It never opens a
        second socket on a port this manager already holds, which is exactly
        what made discovery fail for every device after the first.
        """
        known = list(self.cache.values())
        if known:
            _LOGGER.debug(
                "Discovery served %d device(s) from the shared cache", len(known)
            )
            return known

        if self._running:
            _LOGGER.debug("Cache empty, waiting on the background listener")
            await self._await_broadcasts(self._udp_listener, timeout)
            return list(self.cache.values())

        _LOGGER.debug("No background listener, opening a temporary one")
        listener = UDPDiscoveryListener()
        unsubscribe = listener.on_device_found(self._remember)
        try:
            if not await listener.start():
                return []
            await self._await_broadcasts(listener, timeout)
        finally:
            unsubscribe()
            await listener.stop()

        return list(self.cache.values())

    def get_cached_device(self, device_id: str) -> DiscoveredDevice | None:
        """Look up a device in the cache. Returns None if not found or expired."""
        device = self._cache.get(device_id)
        if device and not device.is_expired(self._cache_ttl):
            return device
        # Remove expired entry
        if device:
            del self._cache[device_id]
        return None

    async def find_device(
        self,
        device_id: str,
        timeout: float = 30.0,
    ) -> DiscoveredDevice | None:
        """Find one specific device: cache first, then listen for its broadcast."""
        cached = self.get_cached_device(device_id)
        if cached:
            _LOGGER.debug("Device %s found in cache at %s", device_id, cached.ip)
            return cached

        _LOGGER.debug("Actively scanning for device %s (timeout=%ss)", device_id, timeout)
        event = asyncio.Event()

        def _on_found(device: DiscoveredDevice) -> None:
            self._remember(device)
            if device.device_id == device_id:
                event.set()

        # Reuse the background listener when it holds the ports; binding a
        # second socket on 6666/6667 always fails while it is running.
        own_listener = not self._running
        listener = UDPDiscoveryListener() if own_listener else self._udp_listener
        unsubscribe = listener.on_device_found(_on_found)

        try:
            if own_listener and not await listener.start():
                return None
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            _LOGGER.debug("UDP scan timed out for device %s", device_id)
        finally:
            unsubscribe()
            if own_listener:
                await listener.stop()

        return self.get_cached_device(device_id)

    async def full_scan(
        self,
        device_id: str,
        local_key: str,
        version: str,
        subnet: str | None = None,
    ) -> str | None:
        """Full discovery: UDP listener → TCP scan fallback. Returns IP or None."""
        # Step 1: Try UDP (matches by gwId/device_id from broadcast)
        device = await self.find_device(device_id, timeout=10.0)
        if device:
            # Validate with local_key crypto handshake to prevent wrong-device switch
            scanner = TCPScanner(hass=self._hass)
            if await scanner.identify_device(device.ip, device_id, local_key, version):
                device.version_confirmed = version == device.version
                return device.ip
            _LOGGER.warning(
                "Device at %s matched device_id %s via UDP but failed local_key "
                "validation — this is a different device, ignoring",
                device.ip, device_id,
            )

        # Step 2: TCP subnet scan (already validates via crypto handshake)
        _LOGGER.info("UDP discovery failed for %s, falling back to TCP scan", device_id)
        scanner = TCPScanner(hass=self._hass)
        hosts = await scanner.scan_subnet(subnet)

        for ip in hosts:
            if await scanner.identify_device(ip, device_id, local_key, version):
                _LOGGER.info("Device %s found via TCP scan at %s", device_id, ip)
                self._cache[device_id] = DiscoveredDevice(
                    device_id=device_id,
                    ip=ip,
                    version=version,
                    # The handshake succeeded with this version, so unlike a
                    # broadcast hint it is now proven.
                    version_confirmed=True,
                )
                return ip

        _LOGGER.warning("Device %s not found via UDP or TCP scan", device_id)
        return None

    async def _await_broadcasts(
        self, listener: UDPDiscoveryListener, timeout: float
    ) -> None:
        """Wait for a first broadcast on `listener`, then one settle interval."""
        first_seen = asyncio.Event()
        unsubscribe = listener.on_device_found(lambda _device: first_seen.set())
        try:
            await asyncio.wait_for(first_seen.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "No Tuya device announced itself on UDP %s/%s within %.0fs. Devices "
                "broadcast every few seconds, so check that Home Assistant shares a "
                "network with the device (host networking when running in Docker, "
                "no VLAN or client isolation in between) and that the device is "
                "powered on. You can always add it manually by IP address",
                UDP_PORT_PLAIN, UDP_PORT_ENCRYPTED, timeout,
            )
            return
        finally:
            unsubscribe()

        await asyncio.sleep(min(SETTLE_SECONDS, timeout))

    def _remember(self, device: DiscoveredDevice) -> None:
        """Store a freshly heard device in the shared cache."""
        self._cache[device.device_id] = device

    def _evict_expired(self) -> None:
        """Remove expired entries from cache."""
        expired = [
            did for did, dev in self._cache.items()
            if dev.is_expired(self._cache_ttl)
        ]
        for did in expired:
            del self._cache[did]


def async_get_manager(hass: HomeAssistant) -> DiscoveryManager | None:
    """Return the shared DiscoveryManager, or None when no entry is set up yet."""
    manager = hass.data.get(DOMAIN, {}).get(DISCOVERY_DATA_KEY)
    return manager if isinstance(manager, DiscoveryManager) else None


async def async_discover_devices(
    hass: HomeAssistant, timeout: float = 10.0
) -> list[DiscoveredDevice]:
    """Discover Tuya devices without caring who owns the UDP ports.

    This is the entry point for the config flow. With at least one config entry
    set up, the shared manager already holds ports 6666/6667 and has a warm
    cache — this reuses it. For the very first device no manager exists yet, so
    a throwaway manager binds the ports itself.
    """
    manager = async_get_manager(hass)
    if manager is not None:
        return await manager.async_discover(timeout=timeout)

    _LOGGER.debug("No shared discovery manager yet, discovering standalone")
    standalone = DiscoveryManager(hass=hass)
    try:
        return await standalone.async_discover(timeout=timeout)
    finally:
        await standalone.stop()
