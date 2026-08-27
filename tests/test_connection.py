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


def make_streams(read_chunks: list[bytes] | None = None) -> tuple[AsyncMock, MagicMock, list[bytes]]:
    """Build a mocked reader/writer pair plus the list of bytes written."""
    written: list[bytes] = []

    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    if read_chunks is None:
        mock_reader.read = AsyncMock(return_value=b"")
    else:
        queue = list(read_chunks)

        async def _read(_n: int) -> bytes:
            if queue:
                return queue.pop(0)
            await asyncio.sleep(3600)
            return b""

        mock_reader.read = _read

    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.write = MagicMock(side_effect=written.append)
    mock_writer.drain = AsyncMock()
    return mock_reader, mock_writer, written


class TestForcedDisconnect:
    """A dead link must reach the disconnect callbacks; an unload must not."""

    @pytest.mark.asyncio
    async def test_requested_disconnect_is_silent(self) -> None:
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.3")
        reader, writer, _ = make_streams([])
        cb = MagicMock()
        conn.on_disconnect(cb)

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            await conn.connect()
        await conn.disconnect()

        assert not conn.is_connected
        cb.assert_not_called()

    @pytest.mark.asyncio
    async def test_forced_disconnect_fires_callbacks(self) -> None:
        """This is the path hub.py needs after repeated heartbeat failures."""
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.3")
        reader, writer, _ = make_streams([])
        cb = MagicMock()
        conn.on_disconnect(cb)

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            await conn.connect()
        await conn.force_disconnect("heartbeat lost")

        assert not conn.is_connected
        cb.assert_called_once()

    @pytest.mark.asyncio
    async def test_forced_disconnect_on_a_closed_connection_is_quiet(self) -> None:
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.3")
        cb = MagicMock()
        conn.on_disconnect(cb)
        await conn.force_disconnect("never connected")
        cb.assert_not_called()

    @pytest.mark.asyncio
    async def test_device_closing_the_socket_fires_callbacks(self) -> None:
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.3")
        reader, writer, _ = make_streams()  # read() returns b"" immediately
        cb = MagicMock()
        conn.on_disconnect(cb)

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            await conn.connect()
            await asyncio.sleep(0.05)

        assert not conn.is_connected
        cb.assert_called_once()
        await conn.disconnect()

    @pytest.mark.asyncio
    async def test_pending_request_fails_instead_of_being_cancelled(self) -> None:
        """send_and_wait must raise ConnectionError, not leak a CancelledError."""
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.3")
        reader, writer, _ = make_streams([])

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            await conn.connect()

        waiter = asyncio.ensure_future(conn.send_and_wait(Command.HEARTBEAT, timeout=10))
        await asyncio.sleep(0)
        await conn.force_disconnect("link down")

        with pytest.raises(ConnectionError):
            await waiter


class TestConnectFailsClosed:
    """A failed session negotiation must not leave a 'connected' socket behind."""

    @pytest.mark.asyncio
    async def test_negotiation_failure_leaves_disconnected(self) -> None:
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.4")
        reader, writer, _ = make_streams([b""])  # device hangs up during negotiation

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            with pytest.raises(ConnectionError):
                await conn.connect()

        assert not conn.is_connected
        assert conn._writer is None
        writer.close.assert_called_once()


class TestSessionKeyNegotiation:
    """v3.4/v3.5 negotiation must verify the device's HMAC."""

    @staticmethod
    def _neg_response(local_key: bytes, client_nonce: bytes, version: str) -> bytes:
        """Build the SESS_KEY_NEG_RESP frame a real device would send."""
        from custom_components.lsc_tuya_doorbell.protocol.encryption import TuyaCipher
        from custom_components.lsc_tuya_doorbell.protocol.messages import MessageCodec

        device_nonce = b"device_nonce_abc"
        body = device_nonce + TuyaCipher.calc_hmac(local_key, client_nonce)
        codec = MessageCodec(version, local_key)
        return codec.encode(Command.SESS_KEY_NEG_RESP, body, seqno=0)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("version", ["3.4", "3.5"])
    async def test_correct_key_completes_negotiation(self, version: str) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.encryption import TuyaCipher

        local_key = b"0123456789abcdef"
        client_nonce = b"client_nonce_abc"
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", version)
        reader, writer, written = make_streams(
            [self._neg_response(local_key, client_nonce, version)]
        )

        with patch.object(TuyaCipher, "generate_nonce", return_value=client_nonce):
            with patch("asyncio.open_connection", return_value=(reader, writer)):
                await conn.connect()

        assert conn.is_connected
        assert conn._codec.session_key is not None
        # NEG_START and NEG_FINISH were both sent.
        assert len(written) == 2
        await conn.disconnect()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("version", ["3.4", "3.5"])
    async def test_truncated_negotiation_response_is_rejected(self, version: str) -> None:
        """A short body must not be accepted as a valid device nonce."""
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            InvalidLocalKeyError,
        )
        from custom_components.lsc_tuya_doorbell.protocol.messages import MessageCodec

        codec = MessageCodec(version, b"0123456789abcdef")
        short = codec.encode(Command.SESS_KEY_NEG_RESP, b"only-16-bytes-ab", seqno=0)
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", version)
        reader, writer, _ = make_streams([short])

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            with pytest.raises(InvalidLocalKeyError):
                await conn.connect()
        assert not conn.is_connected

    @pytest.mark.asyncio
    async def test_wrong_key_is_reported_as_such(self) -> None:
        """A bad HMAC must name the local key, not look like a network problem."""
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            InvalidLocalKeyError,
        )
        from custom_components.lsc_tuya_doorbell.protocol.encryption import TuyaCipher

        client_nonce = b"client_nonce_abc"
        conn = TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.4")
        # The device answers with an HMAC computed over a different key.
        reader, writer, _ = make_streams(
            [self._neg_response(b"0123456789abcdef", b"a different nonce", "3.4")]
        )

        with patch.object(TuyaCipher, "generate_nonce", return_value=client_nonce):
            with patch("asyncio.open_connection", return_value=(reader, writer)):
                with pytest.raises(InvalidLocalKeyError, match="local key"):
                    await conn.connect()

        assert not conn.is_connected

    @pytest.mark.asyncio
    async def test_invalid_local_key_error_is_a_connection_error(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            InvalidLocalKeyError,
        )

        assert issubclass(InvalidLocalKeyError, ConnectionError)


class TestUnsupportedProtocolVersion:
    def test_construction_reports_a_readable_error(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            UnsupportedProtocolVersionError,
        )

        with pytest.raises(UnsupportedProtocolVersionError, match="not supported"):
            TuyaConnection("127.0.0.1", 6668, "test", "0123456789abcdef", "3.2")


class TestRequestCorrelation:
    """Two concurrent requests for the same command must not clobber each other."""

    def test_two_requests_for_one_command_resolve_independently(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.messages import TuyaMessage

        loop = asyncio.new_event_loop()
        try:
            conn = TuyaConnection("127.0.0.1", 6668, "t", "0123456789abcdef", "3.3")

            async def scenario() -> None:
                first = conn._register_request(Command.DP_QUERY, 1, (Command.DP_QUERY,))
                second = conn._register_request(Command.DP_QUERY, 2, (Command.DP_QUERY,))

                conn._dispatch_message(
                    TuyaMessage(seqno=2, command=Command.DP_QUERY, retcode=None,
                                payload=b'{"dps":{"2":2}}')
                )
                assert second.future.done()
                assert not first.future.done()

                conn._dispatch_message(
                    TuyaMessage(seqno=1, command=Command.DP_QUERY, retcode=None,
                                payload=b'{"dps":{"1":1}}')
                )
                assert first.future.result().data == {"dps": {"1": 1}}

            loop.run_until_complete(scenario())
        finally:
            loop.close()

    def test_seqno_zero_reply_matches_the_oldest_request(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.messages import TuyaMessage

        loop = asyncio.new_event_loop()
        try:
            conn = TuyaConnection("127.0.0.1", 6668, "t", "0123456789abcdef", "3.3")

            async def scenario() -> None:
                first = conn._register_request(Command.DP_QUERY, 1, (Command.DP_QUERY,))
                second = conn._register_request(Command.DP_QUERY, 2, (Command.DP_QUERY,))

                conn._dispatch_message(
                    TuyaMessage(seqno=0, command=Command.DP_QUERY, retcode=None,
                                payload=b'{"dps":{"9":9}}')
                )
                assert first.future.done()
                assert not second.future.done()

            loop.run_until_complete(scenario())
        finally:
            loop.close()

    def test_push_without_a_pending_request_reaches_the_status_callbacks(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.messages import TuyaMessage

        conn = TuyaConnection("127.0.0.1", 6668, "t", "0123456789abcdef", "3.3")
        cb = MagicMock()
        conn.on_status_update(cb)

        conn._dispatch_message(
            TuyaMessage(seqno=77, command=Command.STATUS, retcode=None,
                        payload=b'{"dps":{"185":"ring"}}')
        )
        cb.assert_called_once_with({"185": "ring"})
