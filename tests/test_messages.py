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


# Golden 6699 frames produced by tinytuya's pack_message() with
# local_key=b"0123456789abcdef" and iv=b"0123456789ab". These are the reference
# for protocol 3.5 framing: 18-byte >IHIII header, 9966 suffix, header[4:18]
# as GCM additional authenticated data.
GOLDEN_KEY = b"0123456789abcdef"
GOLDEN_IV = b"0123456789ab"

# seqno=1 cmd=STATUS, payload = "3.5" version header + {"dps":{"101":true}},
# no retcode (this is what an outgoing frame looks like).
GOLDEN_OUT_NO_RETCODE = bytes.fromhex(
    "00006699000000000001000000080000003f303132333435363738396162516c38fb2e60"
    "2d89030377e484daa388b4ec061b48813e2155af40524de6a9fb9e84d399de996b8edf5d"
    "a5cf02095e0f9d8d1300009966"
)
# seqno=2 cmd=HEARTBEAT, empty payload, no version header.
GOLDEN_HEARTBEAT = bytes.fromhex(
    "00006699000000000002000000090000001c303132333435363738396162f28df03faa16"
    "2b9531caedd705489a8700009966"
)
# seqno=0 cmd=STATUS with a retcode of 0 inside the ciphertext, as devices send.
GOLDEN_DEVICE_RETCODE = bytes.fromhex(
    "00006699000000000000000000080000003430313233343536373839616262420dfb5542"
    "49f970214d9fa6eb93c2b4b2021a1fde387edf51a6a74e28ce08cb673362f68d6a1d0000"
    "9966"
)
# seqno=3 cmd=SESS_KEY_NEG_RESP: retcode 0 + 48 binary bytes (nonce + HMAC).
GOLDEN_NEG_RESP = bytes.fromhex(
    "00006699000000000003000000040000005030313233343536373839616262420dfb2e61"
    "2f8a070671e38cd3a9f89a8578676aba4700609a77777f9bd185f7f4a008939d9bcb143f"
    "deb7c9688e9230acf07ff27a6e1c3ddeda96dbb08182787a90a800009966"
)


@pytest.fixture
def fixed_iv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the GCM nonce so encoded 3.5 frames are byte-for-byte reproducible."""
    from custom_components.lsc_tuya_doorbell.protocol import messages as messages_module

    monkeypatch.setattr(messages_module.os, "urandom", lambda n: GOLDEN_IV[:n])


class TestProtocol35Framing:
    """Protocol 3.5 (6699) checked against frames produced by tinytuya."""

    @pytest.fixture
    def codec(self) -> MessageCodec:
        return MessageCodec("3.5", GOLDEN_KEY)

    def test_encode_matches_tinytuya_frame(self, codec: MessageCodec, fixed_iv: None) -> None:
        packet = codec.encode(Command.STATUS, {"dps": {"101": True}}, seqno=1)
        assert packet == GOLDEN_OUT_NO_RETCODE

    def test_encode_heartbeat_matches_tinytuya_frame(
        self, codec: MessageCodec, fixed_iv: None
    ) -> None:
        packet = codec.encode(Command.HEARTBEAT, seqno=2)
        assert packet == GOLDEN_HEARTBEAT

    def test_header_is_18_bytes_with_a_2_byte_gap(self, codec: MessageCodec) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            HEADER_SIZE_6699,
            PREFIX_6699,
        )

        packet = codec.encode(Command.STATUS, {"dps": {"1": 1}}, seqno=7)
        prefix, unknown, seqno, cmd, length = struct.unpack(
            ">IHIII", packet[:HEADER_SIZE_6699]
        )
        assert packet[:4] == PREFIX_6699
        assert unknown == 0
        assert seqno == 7
        assert cmd == Command.STATUS
        # length covers iv(12) + ciphertext + tag(16); the frame adds header + suffix
        assert len(packet) == HEADER_SIZE_6699 + length + 4

    def test_suffix_is_9966_not_aa55(self, codec: MessageCodec) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            SUFFIX_55AA,
            SUFFIX_6699,
        )

        packet = codec.encode(Command.HEARTBEAT)
        assert packet[-4:] == SUFFIX_6699
        assert packet[-4:] != SUFFIX_55AA

    def test_decode_device_frame_with_retcode(self, codec: MessageCodec) -> None:
        msg = codec.decode(GOLDEN_DEVICE_RETCODE)
        assert msg.command == Command.STATUS
        assert msg.seqno == 0
        assert msg.data == {"dps": {"101": True}}

    def test_decode_frame_without_retcode(self, codec: MessageCodec) -> None:
        msg = codec.decode(GOLDEN_OUT_NO_RETCODE)
        assert msg.seqno == 1
        assert msg.command == Command.STATUS
        assert msg.data == {"dps": {"101": True}}

    def test_decode_binary_negotiation_payload(self, codec: MessageCodec) -> None:
        msg = codec.decode(GOLDEN_NEG_RESP)
        assert msg.command == Command.SESS_KEY_NEG_RESP
        assert msg.payload == bytes(range(16)) + bytes(range(32))

    def test_decode_empty_heartbeat(self, codec: MessageCodec) -> None:
        msg = codec.decode(GOLDEN_HEARTBEAT)
        assert msg.command == Command.HEARTBEAT
        assert msg.payload == b""
        assert msg.data == {}

    def test_header_is_authenticated_as_aad(self, codec: MessageCodec) -> None:
        """Flipping a header byte must break the GCM tag, proving the AAD is used."""
        from custom_components.lsc_tuya_doorbell.protocol.constants import DecryptionError

        tampered = bytearray(GOLDEN_DEVICE_RETCODE)
        tampered[9] ^= 0xFF  # inside the seqno field, part of header[4:18]
        with pytest.raises(DecryptionError):
            codec.decode(bytes(tampered))

    def test_wrong_local_key_raises(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import DecryptionError

        codec = MessageCodec("3.5", b"wrongkeywrongkey")
        with pytest.raises(DecryptionError):
            codec.decode(GOLDEN_DEVICE_RETCODE)

    def test_feed_reassembles_6699_frames(self, codec: MessageCodec) -> None:
        stream = GOLDEN_HEARTBEAT + GOLDEN_DEVICE_RETCODE
        messages = codec.feed(stream[:20])
        assert messages == []
        messages = codec.feed(stream[20:])
        assert [m.command for m in messages] == [Command.HEARTBEAT, Command.STATUS]

    def test_session_key_is_used_when_set(self, fixed_iv: None) -> None:
        """A session key replaces the local key for 3.5 frames after negotiation."""
        codec = MessageCodec("3.5", GOLDEN_KEY)
        codec.session_key = b"sessionkey123456"
        packet = codec.encode(Command.STATUS, {"dps": {"101": True}}, seqno=1)
        assert packet != GOLDEN_OUT_NO_RETCODE
        assert codec.decode(packet).data == {"dps": {"101": True}}


class TestFrameLengthBounds:
    """A nonsense length must never stall reassembly forever."""

    @pytest.fixture
    def codec(self) -> MessageCodec:
        return MessageCodec("3.3", b"0123456789abcdef")

    @staticmethod
    def _frame_with_length(length: int) -> bytes:
        from custom_components.lsc_tuya_doorbell.protocol.constants import PREFIX_55AA

        return PREFIX_55AA + struct.pack(">III", 1, Command.HEARTBEAT, length) + b"\x00" * 8

    def test_absurd_length_is_dropped_and_stream_resyncs(
        self, codec: MessageCodec, caplog: pytest.LogCaptureFixture
    ) -> None:
        good = codec.encode(Command.HEARTBEAT)
        with caplog.at_level("WARNING"):
            messages = codec.feed(self._frame_with_length(0xFFFFFFF) + good)

        assert len(messages) == 1
        assert messages[0].command == Command.HEARTBEAT
        assert any("implausible length" in r.message for r in caplog.records)

    def test_too_small_length_is_dropped(self, codec: MessageCodec) -> None:
        good = codec.encode(Command.HEARTBEAT)
        messages = codec.feed(self._frame_with_length(2) + good)
        assert len(messages) == 1

    def test_buffer_does_not_grow_without_bound(self, codec: MessageCodec) -> None:
        """A frame that never completes must not grow the buffer forever.

        The old code waited for `total_len` bytes with no upper bound and no
        suffix check, so a desynchronised stream grew until the process died.
        """
        from custom_components.lsc_tuya_doorbell.protocol.constants import MAX_BUFFER_SIZE

        header = self._frame_with_length(16000)
        peak = 0
        for _ in range(200):
            codec.feed(header + b"\x00" * 1000)
            peak = max(peak, codec.buffered_bytes)

        # 200 KB was fed in; the buffer must never have held more than one
        # oversized frame's worth of it.
        assert peak <= MAX_BUFFER_SIZE

    def test_a_stalled_buffer_still_recovers_a_later_frame(
        self, codec: MessageCodec
    ) -> None:
        """Reassembly recovers on its own, without an external buffer reset."""
        header = self._frame_with_length(16000)
        for _ in range(50):
            codec.feed(header + b"\x00" * 1000)

        good = codec.encode(Command.HEARTBEAT)
        # Pad until the stalled frame's declared length is satisfied, then send
        # a real frame: the codec must resynchronise and deliver it.
        messages = codec.feed(b"\x00" * 20000 + good)
        assert [m.command for m in messages] == [Command.HEARTBEAT]

    def test_wrong_suffix_triggers_resync(self, codec: MessageCodec) -> None:
        good = codec.encode(Command.HEARTBEAT)
        broken = bytearray(codec.encode(Command.HEARTBEAT))
        broken[-1] ^= 0xFF
        messages = codec.feed(bytes(broken) + good)
        # The broken frame is dropped, the intact one behind it still arrives.
        assert len(messages) == 1
        assert messages[0].command == Command.HEARTBEAT


class TestResynchronisation:
    """Reassembly must survive garbage and split prefixes."""

    @pytest.fixture
    def codec(self) -> MessageCodec:
        return MessageCodec("3.3", b"0123456789abcdef")

    def test_split_prefix_across_two_reads_is_kept(self, codec: MessageCodec) -> None:
        packet = codec.encode(Command.HEARTBEAT)
        # Junk, then the first two prefix bytes; the rest arrives next read.
        assert codec.feed(b"\xde\xad\xbe\xef" + packet[:2]) == []
        messages = codec.feed(packet[2:])
        assert len(messages) == 1

    def test_bad_frame_does_not_hold_up_the_next_one(self, codec: MessageCodec) -> None:
        """A frame that fails to decode must not delay a valid frame behind it."""
        corrupt = bytearray(codec.encode(Command.CONTROL, {"dps": {"1": 1}}))
        corrupt[30] ^= 0xFF  # breaks the CRC over the payload
        good = codec.encode(Command.HEARTBEAT)

        messages = codec.feed(bytes(corrupt) + good)
        assert [m.command for m in messages] == [Command.HEARTBEAT]

    def test_crc_mismatch_is_reported_at_warning(
        self, codec: MessageCodec, caplog: pytest.LogCaptureFixture
    ) -> None:
        corrupt = bytearray(codec.encode(Command.CONTROL, {"dps": {"1": 1}}))
        corrupt[30] ^= 0xFF
        with caplog.at_level("WARNING"):
            assert codec.feed(bytes(corrupt)) == []
        assert any("CRC32 mismatch" in r.message for r in caplog.records)

    def test_repeated_failures_warn_only_once(
        self, codec: MessageCodec, caplog: pytest.LogCaptureFixture
    ) -> None:
        corrupt = bytearray(codec.encode(Command.CONTROL, {"dps": {"1": 1}}))
        corrupt[30] ^= 0xFF
        with caplog.at_level("WARNING"):
            for _ in range(5):
                codec.feed(bytes(corrupt))
        warnings = [r for r in caplog.records if "CRC32 mismatch" in r.message]
        assert len(warnings) == 1


class TestHmacMismatch:
    """v3.4 frames must not be accepted with a bad HMAC."""

    def test_hmac_mismatch_drops_the_frame(self, caplog: pytest.LogCaptureFixture) -> None:
        sender = MessageCodec("3.4", b"0123456789abcdef")
        packet = sender.encode(Command.CONTROL, {"dps": {"1": 1}})

        receiver = MessageCodec("3.4", b"0123456789abcdef")
        receiver.session_key = b"differentkey!!!!"
        with caplog.at_level("WARNING"):
            assert receiver.feed(packet) == []
        assert any("HMAC mismatch" in r.message for r in caplog.records)
        assert any("local key" in r.message for r in caplog.records)


class TestPayloadParsing:
    """TuyaMessage must never hand a non-dict to the rest of the integration."""

    def test_json_scalar_does_not_become_data(self) -> None:
        msg = TuyaMessage(seqno=1, command=8, retcode=None, payload=b"12345")
        assert msg.data == {}

    def test_json_list_does_not_become_data(self) -> None:
        msg = TuyaMessage(seqno=1, command=8, retcode=None, payload=b"[1,2,3]")
        assert msg.data == {}

    def test_broken_json_object_is_reported(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            msg = TuyaMessage(seqno=1, command=8, retcode=None, payload=b'{"dps":')
        assert msg.data == {}
        assert any("local key" in r.message for r in caplog.records)


class TestUnsupportedVersion:
    """A device announcing 3.1/3.2 must produce a readable error, not a ValueError."""

    def test_unsupported_version_message_names_the_alternatives(self) -> None:
        from custom_components.lsc_tuya_doorbell.protocol.constants import (
            UnsupportedProtocolVersionError,
        )

        with pytest.raises(UnsupportedProtocolVersionError) as excinfo:
            MessageCodec("3.1", b"0123456789abcdef")
        assert "3.3" in str(excinfo.value)
        assert "not supported" in str(excinfo.value)

    def test_it_is_still_a_value_error(self) -> None:
        with pytest.raises(ValueError):
            MessageCodec("3.2", b"0123456789abcdef")
