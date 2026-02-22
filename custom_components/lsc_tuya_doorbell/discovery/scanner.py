"""TCP port scanner for Tuya device discovery (fallback method)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket

_LOGGER = logging.getLogger(__name__)

DEFAULT_PORT = 6668
DEFAULT_MAX_CONCURRENT = 50
DEFAULT_TIMEOUT = 1.0


class TCPScanner:
    """Scans a subnet for Tuya devices by checking for open TCP ports."""

    def __init__(
        self,
        port: int = DEFAULT_PORT,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._port = port
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._timeout = timeout

    async def scan_subnet(self, subnet: str | None = None) -> list[str]:
        """Scan all IPs in a subnet for the Tuya port. Returns list of responding IPs."""
        if subnet is None:
            subnet = self._detect_local_subnet()
            if not subnet:
                _LOGGER.warning("Could not detect local subnet")
                return []

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            _LOGGER.warning("Invalid subnet: %s", subnet)
            return []

        hosts = [str(ip) for ip in network.hosts()]
        _LOGGER.debug("Scanning %s hosts in %s on port %s", len(hosts), subnet, self._port)

        tasks = [self._check_host(ip) for ip in hosts]
        results = await asyncio.gather(*tasks)

        found = [ip for ip, is_open in zip(hosts, results) if is_open]
        _LOGGER.debug("Found %s hosts with open port %s", len(found), self._port)
        return found

    async def identify_device(
        self,
        ip: str,
        device_id: str,
        local_key: str,
        version: str,
    ) -> bool:
        """Verify a device at the given IP by attempting a connection + DP query.

        A heartbeat alone is not sufficient for protocol 3.3 — any Tuya device
        will respond. A DP query requires the correct local_key to decrypt the
        response, so it validates device identity.
        """
        from ..protocol.connection import TuyaConnection

        conn = TuyaConnection(ip, self._port, device_id, local_key, version)
        try:
            await conn.connect()
            # DP query requires correct local_key for encryption/decryption.
            # If this returns data (even empty dict), the key matches.
            # Wrong key → decrypt fails → exception or garbage.
            result = await conn.query_dps()
            if result is not None:
                _LOGGER.debug(
                    "Device at %s verified via DP query (got %d DPs)",
                    ip, len(result),
                )
                return True
            # query_dps returns {} on timeout — try heartbeat as fallback
            # for v3.4/v3.5 where session key negotiation already validates
            hb = await conn.heartbeat()
            if hb:
                _LOGGER.debug("Device at %s verified via heartbeat", ip)
            return hb
        except Exception:
            _LOGGER.debug("Device at %s failed identity check", ip)
            return False
        finally:
            await conn.disconnect()

    async def _check_host(self, ip: str) -> bool:
        """Check if a host has the Tuya port open."""
        async with self._semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, self._port),
                    timeout=self._timeout,
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return False

    @staticmethod
    def _detect_local_subnet() -> str | None:
        """Detect the local subnet using stdlib (no netifaces dependency)."""
        try:
            # Create a UDP socket to determine the local IP
            # (doesn't actually send data)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()

            # Assume /24 subnet (most common for home networks)
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
        except Exception:
            _LOGGER.debug("Failed to detect local subnet", exc_info=True)
            return None
