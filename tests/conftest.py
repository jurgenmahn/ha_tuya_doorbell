"""Shared test fixtures for LSC Tuya Doorbell tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def local_key() -> bytes:
    """A test local key (16 bytes)."""
    return b"0123456789abcdef"


@pytest.fixture
def local_key_hex() -> str:
    """A test local key as hex string."""
    return "YOUR_LOCAL_KEY_HERE"


@pytest.fixture
def real_local_key() -> bytes:
    """The real test device local key."""
    return bytes.fromhex("YOUR_LOCAL_KEY_HERE")


@pytest.fixture
def device_id() -> str:
    """The test device ID."""
    return "YOUR_DEVICE_ID_HERE"


@pytest.fixture
def sample_status_payload() -> dict:
    """A sample DPS status payload."""
    return {"dps": {"101": True, "103": "0", "104": True, "154": 5}}


@pytest.fixture
def sample_doorbell_payload() -> bytes:
    """A sample doorbell event payload (raw)."""
    return b'{"cmd":"ipc_doorbell","data":{"imgUrl":"https://example.com/image.jpg"}}'


@pytest.fixture
def sample_motion_payload() -> bytes:
    """A sample motion detection event payload (raw)."""
    return b'{"cmd":"ipc_motion","data":{"imgUrl":"https://example.com/motion.jpg"}}'
