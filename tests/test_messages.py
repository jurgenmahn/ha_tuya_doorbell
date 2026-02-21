"""Tests for Tuya protocol message encoding/decoding."""

from __future__ import annotations

import json
import struct

import pytest

from custom_components.lsc_tuya_doorbell.protocol.constants import (
    CRC32_SIZE,
    HEADER_SIZE,
    HMAC_SIZE,
    PREFIX_55AA,
    SUFFIX,
    SUFFIX_SIZE,
    Command,
    ProtocolVersion,
)
from custom_components.lsc_tuya_doorbell.protocol.messages import MessageCodec, TuyaMessage


class TestTuyaMessage:
    """Test the TuyaMessage dataclass."""

    def test_auto_parse_json_payload(self) -> None:
        payload = json.dumps({"dps": {"101": True}}).encode()
        msg = TuyaMessage(seqno=1, command=8, retcode=None, payload=payload)
        assert msg.data == {"dps": {"101": True}}

    def test_non_json_payload(self) -> None:
        msg = TuyaMessage(seqno=1, command=9, retcode=None, payload=b"\x00\x00")
        assert msg.data == {}

    def test_empty_payload(self) -> None:
        msg = TuyaMessage(seqno=1, command=9, retcode=None, payload=b"")
        assert msg.data == {}

    def test_explicit_data_overrides(self) -> None:
        msg = TuyaMessage(
            seqno=1,
            command=8,
            retcode=None,
            payload=b'{"dps":{"101":true}}',
            data={"custom": "data"},
        )
        assert msg.data == {"custom": "data"}


class TestMessageCodecV33:
    """Test MessageCodec with v3.3 protocol."""

    @pytest.fixture
    def codec(self, local_key: bytes) -> MessageCodec:
        return MessageCodec("3.3", local_key)

    def test_encode_heartbeat(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        assert packet[:4] == PREFIX_55AA
        assert packet[-4:] == SUFFIX
        # Heartbeat has no payload
        _, seqno, cmd, length = struct.unpack(">IIII", packet[:HEADER_SIZE])
        assert cmd == Command.HEARTBEAT

    def test_encode_dp_query(self, codec: MessageCodec) -> None:
        payload = {"devId": "test_device", "dps": {"101": None}}
        packet = codec.encode(Command.DP_QUERY, payload)
        assert packet[:4] == PREFIX_55AA
        assert packet[-4:] == SUFFIX

    def test_encode_decode_roundtrip(self, codec: MessageCodec) -> None:
        payload = {"dps": {"101": True, "103": "0"}}
        packet = codec.encode(Command.CONTROL, payload)
        msg = codec.decode(packet)
        assert msg.command == Command.CONTROL
        assert msg.data.get("dps") == {"101": True, "103": "0"}

    def test_sequence_numbers_increment(self, codec: MessageCodec) -> None:
        pkt1 = codec.encode(Command.HEARTBEAT)
        pkt2 = codec.encode(Command.HEARTBEAT)
        seq1 = struct.unpack(">I", pkt1[4:8])[0]
        seq2 = struct.unpack(">I", pkt2[4:8])[0]
        assert seq2 == seq1 + 1

    def test_encode_string_payload(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.DP_QUERY, '{"devId":"test"}')
        msg = codec.decode(packet)
        assert msg.data.get("devId") == "test"

    def test_encode_bytes_payload(self, codec: MessageCodec) -> None:
        raw = b'{"test": true}'
        packet = codec.encode(Command.CONTROL, raw)
        msg = codec.decode(packet)
        assert msg.data.get("test") is True


class TestMessageCodecV34:
    """Test MessageCodec with v3.4 protocol."""

    @pytest.fixture
    def codec(self, local_key: bytes) -> MessageCodec:
        c = MessageCodec("3.4", local_key)
        # Simulate session key for v3.4
        c.session_key = b"sessionkey123456"
        return c

    def test_encode_decode_roundtrip(self, codec: MessageCodec) -> None:
        payload = {"dps": {"101": False}}
        packet = codec.encode(Command.CONTROL, payload)
        assert packet[:4] == PREFIX_55AA
        msg = codec.decode(packet)
        assert msg.command == Command.CONTROL
        assert msg.data.get("dps") == {"101": False}

    def test_hmac_present(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        # For v3.4, packet should have HMAC (32 bytes) before suffix
        hmac_start = len(packet) - SUFFIX_SIZE - HMAC_SIZE
        assert hmac_start >= HEADER_SIZE


class TestMessageCodecV35:
    """Test MessageCodec with v3.5 protocol."""

    @pytest.fixture
    def codec(self, local_key: bytes) -> MessageCodec:
        from custom_components.lsc_tuya_doorbell.protocol.constants import PREFIX_6699
        c = MessageCodec("3.5", local_key)
        c.session_key = b"v35sessionkey!!!"  # 16 bytes
        return c

    def test_encode_uses_6699_prefix(self, codec: MessageCodec) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import PREFIX_6699
        packet = codec.encode(Command.HEARTBEAT)
        assert packet[:4] == PREFIX_6699

    def test_encode_decode_roundtrip(self, codec: MessageCodec) -> None:
        payload = {"dps": {"185": "event_data"}}
        packet = codec.encode(Command.STATUS, payload)
        msg = codec.decode(packet)
        assert msg.command == Command.STATUS
        assert msg.data.get("dps") == {"185": "event_data"}


class TestFeedBuffer:
    """Test TCP stream reassembly via feed()."""

    @pytest.fixture
    def codec(self, local_key: bytes) -> MessageCodec:
        return MessageCodec("3.3", local_key)

    def test_single_complete_message(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        # Reset seqno for decode codec
        decode_codec = MessageCodec("3.3", codec._cipher.local_key)
        messages = decode_codec.feed(packet)
        assert len(messages) == 1
        assert messages[0].command == Command.HEARTBEAT

    def test_partial_then_complete(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        decode_codec = MessageCodec("3.3", codec._cipher.local_key)

        # Feed first half
        half = len(packet) // 2
        messages = decode_codec.feed(packet[:half])
        assert len(messages) == 0

        # Feed second half
        messages = decode_codec.feed(packet[half:])
        assert len(messages) == 1

    def test_two_messages_in_one_read(self, codec: MessageCodec) -> None:
        pkt1 = codec.encode(Command.HEARTBEAT)
        pkt2 = codec.encode(Command.HEARTBEAT)
        decode_codec = MessageCodec("3.3", codec._cipher.local_key)

        messages = decode_codec.feed(pkt1 + pkt2)
        assert len(messages) == 2

    def test_garbage_before_prefix(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        decode_codec = MessageCodec("3.3", codec._cipher.local_key)

        # Add garbage before the valid packet
        messages = decode_codec.feed(b"\xff\xff\xff" + packet)
        assert len(messages) == 1

    def test_reset_buffer(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        decode_codec = MessageCodec("3.3", codec._cipher.local_key)

        # Feed partial
        decode_codec.feed(packet[:5])
        assert len(decode_codec._buffer) > 0

        decode_codec.reset_buffer()
        assert len(decode_codec._buffer) == 0

    def test_empty_feed(self, codec: MessageCodec) -> None:
        decode_codec = MessageCodec("3.3", codec._cipher.local_key)
        messages = decode_codec.feed(b"")
        assert len(messages) == 0
