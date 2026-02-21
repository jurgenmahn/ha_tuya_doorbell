"""Discovery lifecycle management and caching."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

from .scanner import TCPScanner
from .udp_listener import DiscoveredDevice, UDPDiscoveryListener

_LOGGER = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = 300  # 5 minutes


class DiscoveryManager:
    """Manages device discovery lifecycle: background UDP listener + cache + TCP fallback."""

    def __init__(self, cache_ttl: float = DEFAULT_CACHE_TTL) -> None:
        self._udp_listener = UDPDiscoveryListener()
        self._tcp_scanner = TCPScanner()
        self._cache: dict[str, DiscoveredDevice] = {}
        self._cache_ttl = cache_ttl
        self._background_task: asyncio.Task | None = None
        self._running = False

    @property
    def cache(self) -> dict[str, DiscoveredDevice]:
        """Return current cache (without expired entries)."""
        self._evict_expired()
        return dict(self._cache)

    async def start_background_listener(self) -> None:
        """Start persistent UDP listener as a background task."""
        if self._running:
            return

        self._running = True

        def _on_device(device: DiscoveredDevice) -> None:
            self._cache[device.device_id] = device

        self._udp_listener.on_device_found(_on_device)
        await self._udp_listener.start()
        _LOGGER.debug("Background discovery listener started")

    async def stop(self) -> None:
        """Stop background listener and clear cache."""
        self._running = False
        await self._udp_listener.stop()
        self._cache.clear()
        _LOGGER.debug("Discovery manager stopped")

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
        """Find a device: check cache first, then actively listen via UDP."""
        # Check cache first
        cached = self.get_cached_device(device_id)
        if cached:
            _LOGGER.debug("Device %s found in cache at %s", device_id, cached.ip)
            return cached

        # Active UDP scan
        _LOGGER.debug("Actively scanning for device %s (timeout=%ss)", device_id, timeout)
        result: DiscoveredDevice | None = None
        event = asyncio.Event()

        def _on_found(device: DiscoveredDevice) -> None:
            nonlocal result
            self._cache[device.device_id] = device
            if device.device_id == device_id:
                result = device
                event.set()

        listener = UDPDiscoveryListener()
        listener.on_device_found(_on_found)
        await listener.start()

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            _LOGGER.debug("UDP scan timed out for device %s", device_id)
        finally:
            await listener.stop()

        return result

    async def full_scan(
        self,
        device_id: str,
        local_key: str,
        version: str,
        subnet: str | None = None,
    ) -> str | None:
        """Full discovery: UDP listener → TCP scan fallback. Returns IP or None."""
        # Step 1: Try UDP
        device = await self.find_device(device_id, timeout=10.0)
        if device:
            return device.ip

        # Step 2: TCP subnet scan
        _LOGGER.info("UDP discovery failed for %s, falling back to TCP scan", device_id)
        scanner = TCPScanner()
        hosts = await scanner.scan_subnet(subnet)

        for ip in hosts:
            if await scanner.identify_device(ip, device_id, local_key, version):
                _LOGGER.info("Device %s found via TCP scan at %s", device_id, ip)
                # Add to cache
                self._cache[device_id] = DiscoveredDevice(
                    device_id=device_id,
                    ip=ip,
                    version=version,
                )
                return ip

        _LOGGER.warning("Device %s not found via UDP or TCP scan", device_id)
        return None

    def _evict_expired(self) -> None:
        """Remove expired entries from cache."""
        expired = [
            did for did, dev in self._cache.items()
            if dev.is_expired(self._cache_ttl)
        ]
        for did in expired:
            del self._cache[did]
