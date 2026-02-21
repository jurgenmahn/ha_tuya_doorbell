"""Tests for Tuya TCP connection management."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.lsc_tuya_doorbell.protocol.connection import TuyaConnection
from custom_components.lsc_tuya_doorbell.protocol.constants import Command


@pytest.fixture
def connection() -> TuyaConnection:
    return TuyaConnection(
        host="192.168.1.100",
        port=6668,
        device_id="test_device_id",
        local_key="0123456789abcdef",
        version="3.3",
    )


class TestConnectionInit:
    def test_properties(self, connection: TuyaConnection) -> None:
        assert connection.host == "192.168.1.100"
        assert connection.port == 6668
        assert connection.device_id == "test_device_id"
        assert connection.version == "3.3"
        assert not connection.is_connected

    def test_host_setter(self, connection: TuyaConnection) -> None:
        connection.host = "192.168.1.200"
        assert connection.host == "192.168.1.200"


class TestCallbacks:
    def test_register_status_callback(self, connection: TuyaConnection) -> None:
        cb = MagicMock()
        unregister = connection.on_status_update(cb)
        assert cb in connection._on_status_update
        unregister()
        assert cb not in connection._on_status_update

    def test_register_disconnect_callback(self, connection: TuyaConnection) -> None:
        cb = MagicMock()
        unregister = connection.on_disconnect(cb)
        assert cb in connection._on_disconnect
        unregister()
        assert cb not in connection._on_disconnect


class TestSendWithoutConnection:
    @pytest.mark.asyncio
    async def test_send_raises_when_not_connected(self, connection: TuyaConnection) -> None:
        with pytest.raises(ConnectionError, match="Not connected"):
            await connection.send(Command.HEARTBEAT)


class TestDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, connection: TuyaConnection) -> None:
        # Should not raise
        await connection.disconnect()
        assert not connection.is_connected


class TestConnectMocked:
    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test connection with mocked socket."""
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.3")

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        # Make the read loop end gracefully by returning empty data
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            await conn.connect()
            assert conn.is_connected

            # Let the read loop run and exit on empty data
            await asyncio.sleep(0.1)

            await conn.disconnect()
            assert not conn.is_connected

    @pytest.mark.asyncio
    async def test_connect_timeout(self) -> None:
        """Test that connection timeout is handled."""
        conn = TuyaConnection("192.168.1.254", 6668, "test", "0123456789abcdef", "3.3")

        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
            with pytest.raises(ConnectionError, match="Failed to connect"):
                await conn.connect()


class TestMessageDispatch:
    def test_dispatch_status_update(self, connection: TuyaConnection) -> None:
        """Test that STATUS messages trigger status callbacks."""
        from custom_components.lsc_tuya_doorbell.protocol.messages import TuyaMessage

        cb = MagicMock()
        connection.on_status_update(cb)

        msg = TuyaMessage(
            seqno=99,
            command=Command.STATUS,
            retcode=None,
            payload=b'{"dps":{"101":true}}',
        )
        connection._dispatch_message(msg)

        cb.assert_called_once_with({"101": True})

    def test_dispatch_pending_response(self, connection: TuyaConnection) -> None:
        """Test that responses are correlated to pending futures."""
        from custom_components.lsc_tuya_doorbell.protocol.messages import TuyaMessage

        loop = asyncio.new_event_loop()
        future = loop.create_future()
        connection._pending_responses[42] = future

        msg = TuyaMessage(seqno=42, command=Command.HEARTBEAT, retcode=None, payload=b"")
        connection._dispatch_message(msg)

        assert future.done()
        assert future.result() == msg
        assert 42 not in connection._pending_responses
        loop.close()
