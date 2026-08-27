"""Tests for device discovery and device type classification."""

from __future__ import annotations

import asyncio
import json
import struct
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.lsc_tuya_doorbell.const import (
    DEVICE_TYPE_DOORBELL,
    DEVICE_TYPE_UNKNOWN,
)
from custom_components.lsc_tuya_doorbell.discovery.manager import (
    DISCOVERY_DATA_KEY,
    DiscoveryManager,
    async_discover_devices,
    async_get_manager,
)
from custom_components.lsc_tuya_doorbell.discovery.scanner import TCPScanner
from custom_components.lsc_tuya_doorbell.discovery.udp_listener import (
    DiscoveredDevice,
    UDPDiscoveryListener,
    classify_device_type,
)


class TestClassifyDeviceType:
    """Tests for classify_device_type."""

    def test_known_doorbell_product_key(self):
        assert classify_device_type("jtc6fpl3") == DEVICE_TYPE_DOORBELL

    def test_unknown_product_key(self):
        assert classify_device_type("abc12345") == DEVICE_TYPE_UNKNOWN

    def test_empty_product_key(self):
        assert classify_device_type("") == DEVICE_TYPE_UNKNOWN


class TestDiscoveredDevice:
    """Tests for DiscoveredDevice dataclass."""

    def test_device_type_default(self):
        dev = DiscoveredDevice(device_id="abc123", ip="1.2.3.4", version="3.3")
        assert dev.device_type == DEVICE_TYPE_UNKNOWN

    def test_device_type_set(self):
        dev = DiscoveredDevice(
            device_id="abc123", ip="1.2.3.4", version="3.3",
            device_type=DEVICE_TYPE_DOORBELL,
        )
        assert dev.device_type == DEVICE_TYPE_DOORBELL

    def test_is_expired(self):
        dev = DiscoveredDevice(
            device_id="abc123", ip="1.2.3.4", version="3.3",
            last_seen=time.monotonic() - 400,
        )
        assert dev.is_expired(ttl=300.0) is True

    def test_not_expired(self):
        dev = DiscoveredDevice(device_id="abc123", ip="1.2.3.4", version="3.3")
        assert dev.is_expired(ttl=300.0) is False


class TestUDPBroadcastParsing:
    """Tests for _handle_broadcast device type extraction."""

    def _make_broadcast_packet(self, payload: dict) -> bytes:
        """Build a fake UDP broadcast packet with 20-byte header + JSON + 8-byte footer."""
        json_bytes = json.dumps(payload).encode("utf-8")
        header = b"\x00" * 20
        footer = b"\x00" * 8
        return header + json_bytes + footer

    def test_handle_broadcast_sets_device_type(self):
        listener = UDPDiscoveryListener()
        packet = self._make_broadcast_packet({
            "gwId": "YOUR_DEVICE_ID_HERE",
            "ip": "192.168.1.100",
            "version": "3.3",
            "productKey": "jtc6fpl3",
        })

        listener._handle_broadcast(packet, ("192.168.1.100", 12345), 6666)

        assert "YOUR_DEVICE_ID_HERE" in listener.devices
        dev = listener.devices["YOUR_DEVICE_ID_HERE"]
        assert dev.device_type == DEVICE_TYPE_DOORBELL
        assert dev.product_key == "jtc6fpl3"

    def test_handle_broadcast_unknown_product_key(self):
        listener = UDPDiscoveryListener()
        packet = self._make_broadcast_packet({
            "gwId": "some_other_device_id_here",
            "ip": "192.168.1.101",
            "version": "3.4",
            "productKey": "unknown_key",
        })

        listener._handle_broadcast(packet, ("192.168.1.101", 12345), 6666)

        dev = listener.devices["some_other_device_id_here"]
        assert dev.device_type == DEVICE_TYPE_UNKNOWN

    def test_handle_broadcast_no_product_key(self):
        listener = UDPDiscoveryListener()
        packet = self._make_broadcast_packet({
            "gwId": "device_no_pk",
            "ip": "192.168.1.102",
            "version": "3.3",
        })

        listener._handle_broadcast(packet, ("192.168.1.102", 12345), 6666)

        dev = listener.devices["device_no_pk"]
        assert dev.device_type == DEVICE_TYPE_UNKNOWN
        assert dev.product_key == ""

    def test_handle_broadcast_callback_receives_device_type(self):
        listener = UDPDiscoveryListener()
        received = []
        listener.on_device_found(lambda d: received.append(d))

        packet = self._make_broadcast_packet({
            "gwId": "doorbell_device_22char",
            "ip": "192.168.1.103",
            "version": "3.3",
            "productKey": "jtc6fpl3",
        })
        listener._handle_broadcast(packet, ("192.168.1.103", 12345), 6666)

        assert len(received) == 1
        assert received[0].device_type == DEVICE_TYPE_DOORBELL


def make_broadcast_packet(payload: dict) -> bytes:
    """Build a fake UDP broadcast packet with 20-byte header + JSON + 8-byte footer."""
    return b"\x00" * 20 + json.dumps(payload).encode("utf-8") + b"\x00" * 8


def doorbell_packet(device_id: str = "doorbell_1", ip: str = "192.168.1.50") -> bytes:
    return make_broadcast_packet({
        "gwId": device_id,
        "ip": ip,
        "version": "3.3",
        "productKey": "jtc6fpl3",
    })


class FakeHass:
    """Minimal stand-in for HomeAssistant: data store + executor bridge."""

    def __init__(self) -> None:
        self.data: dict = {}
        self.executor_calls: list = []

    async def async_add_executor_job(self, target, *args):
        self.executor_calls.append(target)
        return target(*args)


class TestDiscoveredDeviceVersionHint:
    """The broadcast version is a hint until a handshake proves it."""

    def test_version_hint_mirrors_broadcast_version(self):
        dev = DiscoveredDevice(device_id="abc123", ip="1.2.3.4", version="3.3")
        assert dev.version_hint == "3.3"

    def test_version_is_not_confirmed_by_default(self):
        dev = DiscoveredDevice(device_id="abc123", ip="1.2.3.4", version="3.3")
        assert dev.version_confirmed is False

    def test_version_hint_documents_itself_as_unreliable(self):
        doc = DiscoveredDevice.version_hint.__doc__ or ""
        assert "guess" in doc


class TestUDPListenerBind:
    """Port 6666/6667 can only be held once per host."""

    @pytest.mark.asyncio
    async def test_second_listener_cannot_bind_same_ports(self):
        """The root cause: a second bind on a held port always fails."""
        from custom_components.lsc_tuya_doorbell.discovery import udp_listener as mod

        with patch.object(mod, "UDP_PORT_PLAIN", 46666), \
             patch.object(mod, "UDP_PORT_ENCRYPTED", 46667):
            first = UDPDiscoveryListener()
            assert await first.start() is True
            try:
                second = UDPDiscoveryListener()
                assert await second.start() is False
                assert second.listening is False
            finally:
                await first.stop()

    @pytest.mark.asyncio
    async def test_failed_bind_logs_actionable_warning(self, caplog):
        listener = UDPDiscoveryListener()
        loop = asyncio.get_running_loop()
        with patch.object(
            loop, "create_datagram_endpoint",
            side_effect=OSError(98, "Address already in use"),
        ):
            with caplog.at_level("WARNING"):
                assert await listener.start() is False

        assert any(r.levelname == "WARNING" for r in caplog.records)
        assert "manually" in caplog.text and "6666" in caplog.text

    @pytest.mark.asyncio
    async def test_partial_bind_still_succeeds(self):
        listener = UDPDiscoveryListener()
        loop = asyncio.get_running_loop()
        calls = {"n": 0}
        real = loop.create_datagram_endpoint

        async def _one_fails(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError(98, "Address already in use")
            return await real(*args, **kwargs)

        with patch.object(loop, "create_datagram_endpoint", _one_fails):
            assert await listener.start() is True
        await listener.stop()

    @pytest.mark.asyncio
    async def test_scan_returns_empty_when_ports_busy(self):
        listener = UDPDiscoveryListener()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=False)):
            assert await listener.scan(timeout=5.0) == []


class TestListenerCallbacks:
    """Callback bookkeeping must not leak or explode."""

    def test_unregister_is_idempotent(self):
        listener = UDPDiscoveryListener()
        unregister = listener.on_device_found(lambda d: None)
        unregister()
        unregister()
        assert listener.callback_count == 0

    def test_clear_callbacks(self):
        listener = UDPDiscoveryListener()
        listener.on_device_found(lambda d: None)
        listener.on_device_found(lambda d: None)
        listener.clear_callbacks()
        assert listener.callback_count == 0

    def test_raising_callback_is_removed_and_warned(self, caplog):
        listener = UDPDiscoveryListener()
        survivor = []

        def _boom(device):
            raise RuntimeError("consumer bug")

        listener.on_device_found(_boom)
        listener.on_device_found(survivor.append)

        with caplog.at_level("WARNING"):
            listener._handle_broadcast(doorbell_packet(), ("192.168.1.50", 1), 6666)

        assert len(survivor) == 1
        assert listener.callback_count == 1
        assert any(r.levelname == "WARNING" for r in caplog.records)

    def test_undecryptable_packet_warns_once(self, caplog):
        listener = UDPDiscoveryListener()
        garbage = b"\x00" * 20 + b"\xff" * 32 + b"\x00" * 8

        with caplog.at_level("WARNING"):
            listener._handle_broadcast(garbage, ("192.168.1.9", 1), 6667)
            listener._handle_broadcast(garbage, ("192.168.1.9", 1), 6667)

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1

    def test_plaintext_json_on_encrypted_port_is_accepted(self):
        listener = UDPDiscoveryListener()
        listener._handle_broadcast(doorbell_packet("plain_on_6667"), ("1.2.3.4", 1), 6667)
        assert "plain_on_6667" in listener.devices


class TestDiscoveryManagerDiscover:
    """async_discover is the single entry point for device lists."""

    @pytest.mark.asyncio
    async def test_returns_cache_without_binding(self):
        manager = DiscoveryManager()
        manager._cache["cached_dev"] = DiscoveredDevice(
            device_id="cached_dev", ip="192.168.1.7", version="3.3"
        )
        never = AsyncMock(side_effect=AssertionError("must not bind"))
        with patch.object(UDPDiscoveryListener, "start", never):
            devices = await manager.async_discover(timeout=0.05)

        assert [d.device_id for d in devices] == ["cached_dev"]

    @pytest.mark.asyncio
    async def test_expired_cache_entries_are_not_returned(self):
        manager = DiscoveryManager(cache_ttl=1.0)
        manager._cache["stale"] = DiscoveredDevice(
            device_id="stale", ip="192.168.1.7", version="3.3",
            last_seen=time.monotonic() - 500,
        )
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=False)):
            assert await manager.async_discover(timeout=0.05) == []

    @pytest.mark.asyncio
    async def test_uses_running_background_listener_for_empty_cache(self):
        """The config-flow path: reuse the listener that owns the ports."""
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=True)):
            await manager.start_background_listener()
        assert manager.listening is True

        async def _broadcast_soon():
            await asyncio.sleep(0.01)
            manager._udp_listener._handle_broadcast(
                doorbell_packet("live_dev"), ("192.168.1.50", 1), 6666
            )

        task = asyncio.create_task(_broadcast_soon())
        devices = await manager.async_discover(timeout=0.5)
        await task

        assert [d.device_id for d in devices] == ["live_dev"]

    @pytest.mark.asyncio
    async def test_binds_own_listener_when_no_background_listener(self):
        manager = DiscoveryManager()
        started = AsyncMock(return_value=True)
        with patch.object(UDPDiscoveryListener, "start", started), \
             patch.object(UDPDiscoveryListener, "stop", AsyncMock()):
            devices = await manager.async_discover(timeout=0.05)

        assert started.await_count == 1
        assert devices == []

    @pytest.mark.asyncio
    async def test_returns_empty_when_own_bind_fails(self):
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=False)):
            assert await manager.async_discover(timeout=0.05) == []

    @pytest.mark.asyncio
    async def test_timeout_logs_actionable_warning(self, caplog):
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=True)), \
             patch.object(UDPDiscoveryListener, "stop", AsyncMock()), \
             caplog.at_level("WARNING"):
            await manager.async_discover(timeout=0.05)

        assert any(r.levelname == "WARNING" for r in caplog.records)
        assert "network" in caplog.text


class TestDiscoveryManagerLifecycle:
    """start -> stop -> start must not stack callbacks."""

    @pytest.mark.asyncio
    async def test_stop_unregisters_callback(self):
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=True)), \
             patch.object(UDPDiscoveryListener, "stop", AsyncMock()):
            await manager.start_background_listener()
            assert manager._udp_listener.callback_count == 1
            await manager.stop()
            assert manager._udp_listener.callback_count == 0

    @pytest.mark.asyncio
    async def test_restart_does_not_stack_callbacks(self):
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=True)), \
             patch.object(UDPDiscoveryListener, "stop", AsyncMock()):
            for _ in range(3):
                await manager.start_background_listener()
                await manager.stop()
            await manager.start_background_listener()

        assert manager._udp_listener.callback_count == 1

    @pytest.mark.asyncio
    async def test_failed_bind_leaves_manager_not_running(self):
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=False)):
            await manager.start_background_listener()

        assert manager.listening is False
        assert manager._udp_listener.callback_count == 0

    @pytest.mark.asyncio
    async def test_find_device_reuses_background_listener(self):
        manager = DiscoveryManager()
        with patch.object(UDPDiscoveryListener, "start", AsyncMock(return_value=True)):
            await manager.start_background_listener()

        never = AsyncMock(side_effect=AssertionError("must not bind a second socket"))

        async def _broadcast_soon():
            await asyncio.sleep(0.01)
            manager._udp_listener._handle_broadcast(
                doorbell_packet("wanted_dev"), ("192.168.1.50", 1), 6666
            )

        task = asyncio.create_task(_broadcast_soon())
        with patch.object(UDPDiscoveryListener, "start", never):
            found = await manager.find_device("wanted_dev", timeout=0.5)
        await task

        assert found is not None
        assert found.ip == "192.168.1.50"
        # The temporary lookup callback must be gone again.
        assert manager._udp_listener.callback_count == 1

    @pytest.mark.asyncio
    async def test_find_device_hits_cache_first(self):
        manager = DiscoveryManager()
        manager._cache["known"] = DiscoveredDevice(
            device_id="known", ip="10.0.0.5", version="3.3"
        )
        never = AsyncMock(side_effect=AssertionError("must not bind"))
        with patch.object(UDPDiscoveryListener, "start", never):
            found = await manager.find_device("known", timeout=0.05)
        assert found is not None and found.ip == "10.0.0.5"


class TestAsyncDiscoverDevicesHelper:
    """The helper the config flow calls."""

    @pytest.mark.asyncio
    async def test_uses_shared_manager_when_present(self):
        from custom_components.lsc_tuya_doorbell.const import DOMAIN

        hass = FakeHass()
        manager = DiscoveryManager()
        manager._cache["shared"] = DiscoveredDevice(
            device_id="shared", ip="192.168.1.30", version="3.3"
        )
        hass.data[DOMAIN] = {DISCOVERY_DATA_KEY: manager}

        assert async_get_manager(hass) is manager
        devices = await async_discover_devices(hass, timeout=0.05)
        assert [d.device_id for d in devices] == ["shared"]

    @pytest.mark.asyncio
    async def test_falls_back_to_own_listener_without_manager(self):
        hass = FakeHass()
        assert async_get_manager(hass) is None

        started = AsyncMock(return_value=True)
        with patch.object(UDPDiscoveryListener, "start", started), \
             patch.object(UDPDiscoveryListener, "stop", AsyncMock()):
            devices = await async_discover_devices(hass, timeout=0.05)

        assert started.await_count == 1
        assert devices == []


class TestScannerSubnetDetection:
    """Network detection goes through Home Assistant, not a raw socket."""

    @pytest.mark.asyncio
    async def test_uses_adapter_prefix_not_hardcoded_24(self):
        hass = FakeHass()
        scanner = TCPScanner(hass=hass)
        adapters = [{
            "name": "eth0", "enabled": True, "default": True, "auto": True,
            "index": 1, "ipv6": [],
            "ipv4": [{"address": "192.168.1.10", "network_prefix": 25}],
        }]
        with patch.dict(
            "sys.modules",
            {"homeassistant.components": MagicMock(
                network=MagicMock(async_get_adapters=AsyncMock(return_value=adapters))
            )},
        ):
            subnets = await scanner.async_detect_local_subnets()

        assert subnets == ["192.168.1.0/25"]
        assert hass.executor_calls == []

    @pytest.mark.asyncio
    async def test_collects_every_enabled_adapter(self):
        hass = FakeHass()
        scanner = TCPScanner(hass=hass)
        adapters = [
            {"name": "lo", "enabled": True, "ipv6": [],
             "ipv4": [{"address": "127.0.0.1", "network_prefix": 8}]},
            {"name": "eth0", "enabled": True, "ipv6": [],
             "ipv4": [{"address": "192.168.1.10", "network_prefix": 24}]},
            {"name": "eth1", "enabled": True, "ipv6": [],
             "ipv4": [{"address": "10.0.0.4", "network_prefix": 24}]},
            {"name": "eth2", "enabled": False, "ipv6": [],
             "ipv4": [{"address": "172.16.0.1", "network_prefix": 24}]},
            {"name": "zt", "enabled": True, "ipv6": [],
             "ipv4": [{"address": "169.254.3.4", "network_prefix": 16}]},
        ]
        with patch.dict(
            "sys.modules",
            {"homeassistant.components": MagicMock(
                network=MagicMock(async_get_adapters=AsyncMock(return_value=adapters))
            )},
        ):
            subnets = await scanner.async_detect_local_subnets()

        assert subnets == ["10.0.0.0/24", "192.168.1.0/24"]

    @pytest.mark.asyncio
    async def test_route_probe_runs_in_executor_and_warns(self, caplog):
        hass = FakeHass()
        scanner = TCPScanner(hass=hass)
        with patch(
            "custom_components.lsc_tuya_doorbell.discovery.scanner._probe_source_ip",
            return_value="192.168.5.20",
        ), caplog.at_level("WARNING"):
            subnets = await scanner._async_subnets_from_route_probe()

        assert subnets == ["192.168.5.0/24"]
        assert len(hass.executor_calls) == 1
        assert any(r.levelname == "WARNING" for r in caplog.records)

    @pytest.mark.asyncio
    async def test_adapter_lookup_failure_warns_and_falls_back(self, caplog):
        hass = FakeHass()
        scanner = TCPScanner(hass=hass)
        with patch.dict(
            "sys.modules",
            {"homeassistant.components": MagicMock(
                network=MagicMock(
                    async_get_adapters=AsyncMock(side_effect=RuntimeError("boom"))
                )
            )},
        ), caplog.at_level("WARNING"):
            subnets = await scanner._async_subnets_from_hass()

        assert subnets == []
        assert any(r.levelname == "WARNING" for r in caplog.records)

    @pytest.mark.asyncio
    async def test_scan_subnet_warns_when_nothing_detected(self, caplog):
        scanner = TCPScanner()
        with patch.object(
            TCPScanner, "async_detect_local_subnets", AsyncMock(return_value=[])
        ), caplog.at_level("WARNING"):
            assert await scanner.scan_subnet() == []

        assert any(r.levelname == "WARNING" for r in caplog.records)

    @pytest.mark.asyncio
    async def test_oversized_subnet_is_skipped(self, caplog):
        scanner = TCPScanner()
        never = AsyncMock(side_effect=AssertionError("must not probe 65k hosts"))
        with patch.object(TCPScanner, "_check_host", never), \
             caplog.at_level("WARNING"):
            assert await scanner.scan_subnet("10.0.0.0/16") == []

        assert "too large" in caplog.text

    @pytest.mark.asyncio
    async def test_invalid_subnet_warns(self, caplog):
        scanner = TCPScanner()
        with caplog.at_level("WARNING"):
            assert await scanner.scan_subnet("not-a-subnet") == []
        assert "Invalid subnet" in caplog.text

    @pytest.mark.asyncio
    async def test_scan_dedupes_overlapping_subnets(self):
        scanner = TCPScanner()
        probed: list[str] = []

        async def _record(_self, ip):
            probed.append(ip)
            return False

        with patch.object(
            TCPScanner, "async_detect_local_subnets",
            AsyncMock(return_value=["192.168.1.0/30", "192.168.1.0/29"]),
        ), patch.object(TCPScanner, "_check_host", _record):
            await scanner.scan_subnet()

        assert len(probed) == len(set(probed))


class TestScannerIdentifyDevice:
    """A failed probe is routine; an unexpected crash is not."""

    @pytest.mark.asyncio
    async def test_protocol_error_stays_at_debug(self, caplog):
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            DecryptionError,
        )

        conn = MagicMock()
        conn.connect = AsyncMock(side_effect=DecryptionError("wrong key"))
        conn.disconnect = AsyncMock()

        scanner = TCPScanner()
        with patch(
            "custom_components.lsc_tuya_doorbell.protocol.connection.TuyaConnection",
            return_value=conn,
        ), caplog.at_level("WARNING"):
            result = await scanner.identify_device("192.168.1.5", "dev", "key", "3.3")

        assert result is False
        assert not [r for r in caplog.records if r.levelname == "WARNING"]
        conn.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_timeout_stays_at_debug(self, caplog):
        conn = MagicMock()
        conn.connect = AsyncMock(side_effect=asyncio.TimeoutError())
        conn.disconnect = AsyncMock()

        scanner = TCPScanner()
        with patch(
            "custom_components.lsc_tuya_doorbell.protocol.connection.TuyaConnection",
            return_value=conn,
        ), caplog.at_level("WARNING"):
            assert await scanner.identify_device("192.168.1.5", "d", "k", "3.3") is False

        assert not [r for r in caplog.records if r.levelname == "WARNING"]

    @pytest.mark.asyncio
    async def test_unexpected_error_warns(self, caplog):
        conn = MagicMock()
        conn.connect = AsyncMock(side_effect=KeyError("bug"))
        conn.disconnect = AsyncMock()

        scanner = TCPScanner()
        with patch(
            "custom_components.lsc_tuya_doorbell.protocol.connection.TuyaConnection",
            return_value=conn,
        ), caplog.at_level("WARNING"):
            assert await scanner.identify_device("192.168.1.5", "d", "k", "3.3") is False

        assert any(r.levelname == "WARNING" for r in caplog.records)
