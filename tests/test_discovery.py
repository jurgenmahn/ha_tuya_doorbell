"""Tests for device discovery and device type classification."""

from __future__ import annotations

import json
import struct
import time

import pytest

from custom_components.lsc_tuya_doorbell.const import (
    DEVICE_TYPE_DOORBELL,
    DEVICE_TYPE_UNKNOWN,
)
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
