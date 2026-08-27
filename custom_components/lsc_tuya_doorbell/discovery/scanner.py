"""TCP port scanner for Tuya device discovery (fallback method)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

DEFAULT_PORT = 6668
DEFAULT_MAX_CONCURRENT = 50
DEFAULT_TIMEOUT = 1.0

# A /22 is already 1022 probes; anything larger is a routed network that a
# broadcast-based doorbell will not be on anyway, and sweeping it would keep
# the event loop busy for many minutes.
MAX_SCAN_HOSTS = 1024

# Only used to ask the kernel which interface serves the default route; no
# packet is sent.
_ROUTE_PROBE_TARGET = "8.8.8.8"
_ROUTE_PROBE_PORT = 80


def _probe_source_ip() -> str | None:
    """Blocking: ask the kernel for the source address of the default route."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((_ROUTE_PROBE_TARGET, _ROUTE_PROBE_PORT))
            return str(sock.getsockname()[0])
    except OSError as err:
        _LOGGER.debug("Source IP probe failed: %s", err)
        return None


class TCPScanner:
    """Scans a subnet for Tuya devices by checking for open TCP ports."""

    def __init__(
        self,
        hass: HomeAssistant | None = None,
        port: int = DEFAULT_PORT,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._hass = hass
        self._port = port
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._timeout = timeout

    async def scan_subnet(self, subnet: str | None = None) -> list[str]:
        """Scan a subnet (or every local one) for the Tuya port. Returns open IPs."""
        if subnet is not None:
            subnets = [subnet]
        else:
            subnets = await self.async_detect_local_subnets()
            if not subnets:
                _LOGGER.warning(
                    "Could not determine which network Home Assistant is on, so the "
                    "TCP fallback scan cannot run. Configure the device with an "
                    "explicit IP address instead of relying on discovery"
                )
                return []

        hosts: list[str] = []
        seen: set[str] = set()
        for candidate in subnets:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                _LOGGER.warning("Invalid subnet: %s", candidate)
                continue

            if network.num_addresses > MAX_SCAN_HOSTS:
                _LOGGER.warning(
                    "Skipping %s: %s addresses is too large to sweep. Pass a smaller "
                    "subnet, or configure the device by IP address",
                    candidate, network.num_addresses,
                )
                continue

            for ip in network.hosts():
                text = str(ip)
                if text not in seen:
                    seen.add(text)
                    hosts.append(text)

        if not hosts:
            return []

        _LOGGER.debug(
            "Scanning %s hosts in %s on port %s",
            len(hosts), ", ".join(subnets), self._port,
        )

        results = await asyncio.gather(*(self._check_host(ip) for ip in hosts))

        found = [ip for ip, is_open in zip(hosts, results) if is_open]
        _LOGGER.debug("Found %s hosts with open port %s", len(found), self._port)
        return found

    async def async_detect_local_subnets(self) -> list[str]:
        """Return the IPv4 networks Home Assistant is actually attached to."""
        if self._hass is not None:
            subnets = await self._async_subnets_from_hass()
            if subnets:
                return subnets

        return await self._async_subnets_from_route_probe()

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

        from ..protocol.constants import ProtocolVersion

        # A sweep probes every host on the subnet, so refusals, timeouts and
        # protocol-level rejections are the normal outcome and stay at debug.
        expected: tuple[type[BaseException], ...] = (
            OSError, asyncio.TimeoutError, ValueError,
        )
        try:
            from ..protocol.constants import TuyaProtocolError
        except ImportError:
            pass
        else:
            expected += (TuyaProtocolError,)

        conn = TuyaConnection(ip, self._port, device_id, local_key, version)
        try:
            await conn.connect()

            # For v3.4/v3.5, session key negotiation already validates the
            # local_key during connect(). A successful connect is proof.
            if version in (ProtocolVersion.V34, ProtocolVersion.V35):
                _LOGGER.debug("Device at %s verified via session key negotiation", ip)
                return True

            # For v3.3, connect() is just TCP — no crypto validation.
            # DP query requires the correct local_key to decrypt the response.
            # An empty dict {} means timeout (no proof), we need actual data.
            result = await conn.query_dps()
            if result:
                _LOGGER.debug(
                    "Device at %s verified via DP query (got %d DPs)",
                    ip, len(result),
                )
                return True

            _LOGGER.debug(
                "Device at %s: DP query returned no data, cannot verify identity",
                ip,
            )
            return False
        except expected as err:
            # The caller reports the overall failure once, at WARNING.
            _LOGGER.debug("Device at %s failed identity check: %s", ip, err)
            return False
        except Exception:
            _LOGGER.warning(
                "Unexpected error while verifying the device at %s; treating it as "
                "no match and continuing the scan. Enable debug logging for this "
                "integration and report the traceback",
                ip,
            )
            _LOGGER.debug("Identity check traceback", exc_info=True)
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

    async def _async_subnets_from_hass(self) -> list[str]:
        """Read the enabled adapters from Home Assistant's network integration."""
        try:
            from homeassistant.components import network
        except ImportError:
            _LOGGER.debug("homeassistant.components.network is unavailable")
            return []

        try:
            adapters = await network.async_get_adapters(self._hass)
        except Exception as err:
            _LOGGER.warning(
                "Could not read the Home Assistant network configuration (%s); "
                "falling back to probing the default route, which assumes a /24. "
                "If the device is not found, configure its IP address manually",
                err,
            )
            _LOGGER.debug("Adapter lookup traceback", exc_info=True)
            return []

        subnets: list[str] = []
        for adapter in adapters:
            if not adapter.get("enabled"):
                continue
            for ipv4 in adapter.get("ipv4") or []:
                try:
                    net = ipaddress.ip_network(
                        f"{ipv4['address']}/{ipv4['network_prefix']}", strict=False
                    )
                except (KeyError, ValueError):
                    _LOGGER.debug("Skipping unusable adapter address %s", ipv4)
                    continue
                # Loopback and link-local carry no Tuya devices, and a
                # link-local /16 would blow past the host budget.
                if net.is_loopback or net.is_link_local:
                    continue
                subnets.append(str(net))

        return sorted(set(subnets))

    async def _async_subnets_from_route_probe(self) -> list[str]:
        """Last resort: derive a /24 from the default-route source address."""
        if self._hass is not None:
            local_ip = await self._hass.async_add_executor_job(_probe_source_ip)
        else:
            loop = asyncio.get_running_loop()
            local_ip = await loop.run_in_executor(None, _probe_source_ip)

        if not local_ip:
            return []

        _LOGGER.warning(
            "Home Assistant's network configuration was unavailable, so the scan "
            "guesses a /24 around %s. On a network with a different prefix, or on a "
            "host with several interfaces, the device may not be found — configure "
            "its IP address manually if discovery keeps failing",
            local_ip,
        )
        return [str(ipaddress.ip_network(f"{local_ip}/24", strict=False))]
