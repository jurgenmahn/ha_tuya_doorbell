"""Tuya protocol message encoding/decoding with TCP stream reassembly."""

from __future__ import annotations

import json
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Any

from .constants import (
    CRC32_SIZE,
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    HEADER_SIZE,
    HEADER_SIZE_6699,
    HMAC_SIZE,
    MAX_BUFFER_SIZE,
    MAX_PAYLOAD_LENGTH,
    NO_PAYLOAD_COMMANDS,
    NO_PROTOCOL_HEADER_CMDS,
    PREFIX_55AA,
    PREFIX_6699,
    SUFFIX_55AA,
    SUFFIX_6699,
    SUFFIX_SIZE,
    VERSION_HEADERS,
    DecryptionError,
    FrameError,
    ProtocolVersion,
)
from .encryption import TuyaCipher

_LOGGER = logging.getLogger(__name__)

# Version headers a payload may be prefixed with, in decrypted form.
_VERSION_PREFIXES = (b"3.1", b"3.2", b"3.3", b"3.4", b"3.5")
_VERSION_HEADER_SIZE = 15

# Smallest length field a frame can legitimately carry, per format.
_MIN_LENGTH_55AA_CRC = CRC32_SIZE + SUFFIX_SIZE
_MIN_LENGTH_55AA_HMAC = HMAC_SIZE + SUFFIX_SIZE
_MIN_LENGTH_6699 = GCM_NONCE_SIZE + GCM_TAG_SIZE

# Sentinel telling feed() that the buffer holds no further complete frame.
_NEED_MORE_DATA = object()


def _looks_like_payload_start(data: bytes) -> bool:
    """Return True if data starts where a Tuya payload plausibly starts."""
    return data[:1] in (b"{", b"[") or data[:3] in _VERSION_PREFIXES


@dataclass
class TuyaMessage:
    """Represents a decoded Tuya protocol message."""

    seqno: int
    command: int
    retcode: int | None
    payload: bytes
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Parse payload JSON into data dict if possible."""
        if not self.payload or self.data:
            return

        text = self.payload.decode("utf-8", errors="ignore").strip("\x00").strip()
        if not text:
            return

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            # Plenty of payloads are legitimately not JSON (nonces, acks). Only
            # something that opens like JSON and then fails is a real problem.
            if _looks_like_payload_start(self.payload):
                _LOGGER.warning(
                    "Command %s carried a payload that starts like JSON but does not "
                    "parse (%s). This usually means the local key or the protocol "
                    "version is wrong; check both in the integration options.",
                    self.command, err,
                )
            else:
                _LOGGER.debug("Command %s payload is not JSON", self.command)
            return

        if not isinstance(parsed, dict):
            # A scalar or list would break every `msg.data.get(...)` downstream.
            _LOGGER.debug(
                "Command %s payload decoded to %s, not an object — ignoring",
                self.command, type(parsed).__name__,
            )
            return

        self.data = parsed


class MessageCodec:
    """Encodes and decodes Tuya protocol messages with TCP stream reassembly."""

    def __init__(self, version: str, local_key: bytes) -> None:
        self._version = ProtocolVersion.parse(version)
        self._cipher = TuyaCipher(local_key)
        self._seqno = 0
        self._session_key: bytes | None = None
        self._buffer = bytearray()
        self._version_header = VERSION_HEADERS[self._version]
        # Failure kind -> whether we already warned about it, so a permanently
        # wrong key produces one warning instead of one per frame.
        self._failing: set[str] = set()

    @property
    def version(self) -> ProtocolVersion:
        """Return the protocol version."""
        return self._version

    @property
    def buffered_bytes(self) -> int:
        """Number of bytes still waiting for the rest of their frame."""
        return len(self._buffer)

    @property
    def session_key(self) -> bytes | None:
        """Return the current session key."""
        return self._session_key

    @session_key.setter
    def session_key(self, key: bytes | None) -> None:
        """Set the session key (after negotiation)."""
        self._session_key = key

    def next_seqno(self) -> int:
        """Get next sequence number."""
        self._seqno += 1
        return self._seqno

    # --- Throttled failure reporting -------------------------------------

    def _report_failure(self, kind: str, message: str, *args: Any) -> None:
        """Warn on the first failure of a kind, then stay quiet until it clears."""
        if kind in self._failing:
            _LOGGER.debug(message, *args)
            return
        self._failing.add(kind)
        _LOGGER.warning(message, *args)

    def _report_recovered(self, kind: str) -> None:
        """Announce that a previously reported failure stopped happening."""
        if kind in self._failing:
            self._failing.discard(kind)
            _LOGGER.info("Protocol issue '%s' cleared: frames are decoding again", kind)

    # --- Encoding ---------------------------------------------------------

    def encode(
        self,
        command: int,
        payload: dict | str | bytes | None = None,
        seqno: int | None = None,
    ) -> bytes:
        """Encode a command + payload into a wire-format Tuya packet."""
        if seqno is None:
            seqno = self.next_seqno()

        _LOGGER.debug(
            "Encode: cmd=%d seqno=%d version=%s payload_type=%s",
            command, seqno, self._version, type(payload).__name__,
        )

        if self._version == ProtocolVersion.V35:
            result = self._encode_v35(command, payload, seqno)
        else:
            result = self._encode_v33_v34(command, payload, seqno)

        _LOGGER.debug("Encode: %d bytes packet", len(result))
        return result

    @staticmethod
    def _payload_bytes(command: int, payload: dict | str | bytes | None) -> bytes:
        """Normalise a payload argument to the bytes that go on the wire."""
        if command in NO_PAYLOAD_COMMANDS or payload is None:
            return b""
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def _encode_v33_v34(
        self,
        command: int,
        payload: dict | str | bytes | None,
        seqno: int,
    ) -> bytes:
        """Encode for v3.3 and v3.4 protocol (55AA frame format).

        v3.3: encrypt payload, then add version header only for commands NOT in
              NO_PROTOCOL_HEADER_CMDS (e.g. CONTROL, CONTROL_NEW get header;
              DP_QUERY, UPDATEDPS, HEARTBEAT do not).
        v3.4: add version header before encryption for non-query commands,
              then encrypt everything.
        No retcode in outgoing packets (retcode is only in device responses).
        """
        payload_bytes = self._payload_bytes(command, payload)

        if payload_bytes:
            key = self._session_key if self._version == ProtocolVersion.V34 and self._session_key else None

            if self._version == ProtocolVersion.V34:
                # v3.4: version header goes BEFORE encryption for non-query commands
                if command not in NO_PROTOCOL_HEADER_CMDS:
                    payload_bytes = self._version_header + payload_bytes
                encrypted = self._cipher.encrypt_ecb(payload_bytes, key)
            else:
                # v3.3: encrypt first, then conditionally add version header
                encrypted = self._cipher.encrypt_ecb(payload_bytes, key)
                if command not in NO_PROTOCOL_HEADER_CMDS:
                    encrypted = self._version_header + encrypted
        else:
            encrypted = b""

        # Length covers payload + integrity check + suffix (no retcode outgoing)
        if self._version == ProtocolVersion.V33:
            total_len = len(encrypted) + CRC32_SIZE + SUFFIX_SIZE
        else:
            total_len = len(encrypted) + HMAC_SIZE + SUFFIX_SIZE

        header = PREFIX_55AA + struct.pack(">III", seqno, command, total_len)
        body = header + encrypted

        if self._version == ProtocolVersion.V33:
            crc = self._cipher.calc_crc32(body)
            return body + crc + SUFFIX_55AA

        hmac_key = self._session_key or self._cipher.local_key
        hmac_val = self._cipher.calc_hmac(hmac_key, body)
        return body + hmac_val + SUFFIX_55AA

    def _encode_v35(
        self,
        command: int,
        payload: dict | str | bytes | None,
        seqno: int,
    ) -> bytes:
        """Encode for v3.5 protocol (6699 frame format with AES-GCM).

        Frame layout, verified against tinytuya's pack_message():
            prefix(4) unknown(2) seqno(4) cmd(4) length(4)  <- 18-byte header
            iv(12) ciphertext tag(16) suffix(4)
        `length` covers iv + ciphertext + tag. The 14 header bytes after the
        prefix are the GCM additional authenticated data, so a tampered header
        fails the tag check.
        """
        payload_bytes = self._payload_bytes(command, payload)
        if command not in NO_PROTOCOL_HEADER_CMDS:
            payload_bytes = self._version_header + payload_bytes

        key = self._session_key or self._cipher.local_key
        iv = os.urandom(GCM_NONCE_SIZE)

        # GCM is a stream mode: ciphertext length equals plaintext length.
        length = GCM_NONCE_SIZE + len(payload_bytes) + GCM_TAG_SIZE
        header = PREFIX_6699 + struct.pack(">HIII", 0, seqno, command, length)

        ciphertext, tag = self._cipher.encrypt_gcm(
            payload_bytes, key, iv, aad=header[4:HEADER_SIZE_6699]
        )
        return header + iv + ciphertext + tag + SUFFIX_6699

    # --- Decoding ---------------------------------------------------------

    def decode(self, data: bytes) -> TuyaMessage:
        """Decode a single complete Tuya packet."""
        if data[:4] == PREFIX_6699:
            return self._decode_v35(data)
        return self._decode_v33_v34(data)

    def _decode_v33_v34(self, data: bytes) -> TuyaMessage:
        """Decode a v3.3 or v3.4 packet."""
        _prefix, seqno, command, _total_len = struct.unpack(">IIII", data[:HEADER_SIZE])

        # Auto-detect retcode: device responses include retcode (0 or 1),
        # outgoing packets we encode don't have retcode.
        retcode_candidate = struct.unpack(">I", data[HEADER_SIZE : HEADER_SIZE + 4])[0]
        if retcode_candidate <= 1:
            retcode = retcode_candidate
            payload_start = HEADER_SIZE + 4
        else:
            retcode = 0
            payload_start = HEADER_SIZE

        if self._version == ProtocolVersion.V33:
            integrity_size = CRC32_SIZE
        else:
            integrity_size = HMAC_SIZE

        payload_end = len(data) - integrity_size - SUFFIX_SIZE
        if payload_end < payload_start:
            raise FrameError(
                f"Frame for command {command} is {len(data)} bytes, too short to hold "
                f"its own integrity check"
            )
        encrypted = data[payload_start:payload_end]

        self._verify_integrity_55aa(data, payload_end, command, integrity_size)

        if not encrypted:
            payload = b""
        else:
            key = self._session_key if self._version == ProtocolVersion.V34 and self._session_key else None

            if self._version == ProtocolVersion.V34:
                # v3.4 encrypts the version header along with the payload.
                payload = self._decrypt_ecb_or_fail(encrypted, key, command)
                if payload[:3] in _VERSION_PREFIXES:
                    payload = payload[_VERSION_HEADER_SIZE:]
            else:
                # v3.3 keeps the version header outside the ciphertext.
                if encrypted[:3] in _VERSION_PREFIXES:
                    encrypted = encrypted[_VERSION_HEADER_SIZE:]
                payload = self._decrypt_ecb_or_fail(encrypted, key, command)

        msg = TuyaMessage(
            seqno=seqno,
            command=command,
            retcode=retcode if retcode != 0 else None,
            payload=payload,
        )
        _LOGGER.debug(
            "Decode v33/v34: seqno=%d cmd=%d retcode=%s payload=%d bytes data_keys=%s",
            msg.seqno, msg.command, msg.retcode, len(msg.payload),
            list(msg.data.keys()) if msg.data else [],
        )
        return msg

    def _verify_integrity_55aa(
        self, data: bytes, payload_end: int, command: int, integrity_size: int
    ) -> None:
        """Check the CRC32 (v3.3) or HMAC (v3.4) trailer, raising on mismatch."""
        check_data = data[:payload_end]
        received = data[payload_end : payload_end + integrity_size]

        if self._version == ProtocolVersion.V33:
            expected = self._cipher.calc_crc32(check_data)
            if received != expected:
                self._report_failure(
                    "crc",
                    "CRC32 mismatch on a frame for command %s (got %s, expected %s). "
                    "The frame is corrupt or the device is not speaking protocol 3.3; "
                    "check the protocol version in the integration options.",
                    command, received.hex(), expected.hex(),
                )
                raise FrameError(f"CRC32 mismatch on command {command}")
            self._report_recovered("crc")
            return

        hmac_key = self._session_key or self._cipher.local_key
        expected = self._cipher.calc_hmac(hmac_key, check_data)
        if received != expected:
            self._report_failure(
                "hmac",
                "HMAC mismatch on a frame for command %s. This usually means the "
                "local key is wrong — re-copy it from the Tuya developer portal and "
                "update the integration options.",
                command,
            )
            raise FrameError(f"HMAC mismatch on command {command}")
        self._report_recovered("hmac")

    def _decrypt_ecb_or_fail(self, encrypted: bytes, key: bytes | None, command: int) -> bytes:
        """Decrypt an AES-ECB payload, reporting a wrong key instead of hiding it."""
        try:
            payload = self._cipher.decrypt_ecb(encrypted, key)
        except DecryptionError as err:
            self._report_failure(
                "decrypt",
                "Could not decrypt the payload of command %s (%s). This usually means "
                "the local key is wrong, or the device speaks a different protocol "
                "version than the one configured.",
                command, err,
            )
            raise
        self._report_recovered("decrypt")
        return payload

    def _decode_v35(self, data: bytes) -> TuyaMessage:
        """Decode a v3.5 (6699) packet."""
        _prefix, _unknown, seqno, command, length = struct.unpack(
            ">IHIII", data[:HEADER_SIZE_6699]
        )

        aad = data[4:HEADER_SIZE_6699]
        iv = data[HEADER_SIZE_6699 : HEADER_SIZE_6699 + GCM_NONCE_SIZE]
        ct_start = HEADER_SIZE_6699 + GCM_NONCE_SIZE
        ct_end = HEADER_SIZE_6699 + length - GCM_TAG_SIZE
        if ct_end < ct_start:
            raise FrameError(
                f"6699 frame for command {command} declares length {length}, too short "
                f"to hold a nonce and a tag"
            )
        ciphertext = data[ct_start:ct_end]
        tag = data[ct_end : ct_end + GCM_TAG_SIZE]

        key = self._session_key or self._cipher.local_key
        try:
            plaintext = self._cipher.decrypt_gcm(ciphertext, key, iv, tag, aad)
        except DecryptionError as err:
            self._report_failure(
                "decrypt",
                "Could not decrypt a protocol 3.5 frame for command %s (%s). This "
                "usually means the local key is wrong — re-copy it from the Tuya "
                "developer portal and update the integration options.",
                command, err,
            )
            raise
        self._report_recovered("decrypt")

        retcode, payload = self._split_retcode_v35(plaintext)
        if payload[:3] in _VERSION_PREFIXES:
            payload = payload[_VERSION_HEADER_SIZE:]

        msg = TuyaMessage(
            seqno=seqno,
            command=command,
            retcode=retcode if retcode else None,
            payload=payload,
        )
        _LOGGER.debug(
            "Decode v35: seqno=%d cmd=%d retcode=%s payload=%d bytes data_keys=%s",
            msg.seqno, msg.command, msg.retcode, len(msg.payload),
            list(msg.data.keys()) if msg.data else [],
        )
        return msg

    @staticmethod
    def _split_retcode_v35(plaintext: bytes) -> tuple[int | None, bytes]:
        """Separate the optional 4-byte retcode that 6699 hides inside the ciphertext.

        Device responses prepend a retcode; the frames we send ourselves do not.
        The length field cannot tell the two apart, so decide on the shape of the
        plaintext, the same way tinytuya's `no_retcode=None` mode does.
        """
        if _looks_like_payload_start(plaintext):
            return None, plaintext
        if len(plaintext) < 4:
            return None, plaintext
        rest = plaintext[4:]
        candidate = struct.unpack(">I", plaintext[:4])[0]
        if _looks_like_payload_start(rest) or candidate <= 1:
            return candidate, rest
        return None, plaintext

    # --- Stream reassembly ------------------------------------------------

    def feed(self, data: bytes) -> list[TuyaMessage]:
        """Feed raw TCP data into the reassembly buffer.

        Returns a list of zero or more complete decoded messages. A frame that
        fails to decode is dropped and reassembly continues, so a single bad
        frame never holds up the valid ones behind it.
        """
        _LOGGER.debug("Feed: %d bytes received, buffer=%d bytes", len(data), len(self._buffer))
        self._buffer.extend(data)
        messages: list[TuyaMessage] = []

        while True:
            result = self._try_extract_message()
            if result is _NEED_MORE_DATA:
                break
            if result is not None:
                messages.append(result)

        if len(self._buffer) > MAX_BUFFER_SIZE:
            _LOGGER.warning(
                "Dropping %d buffered bytes from the device stream: no complete frame "
                "could be recovered. The connection will be re-established; if this "
                "repeats, the configured protocol version is probably wrong.",
                len(self._buffer),
            )
            self._buffer.clear()

        if messages:
            _LOGGER.debug(
                "Feed: extracted %d message(s), buffer=%d bytes remaining",
                len(messages), len(self._buffer),
            )
        return messages

    def _try_extract_message(self) -> TuyaMessage | object | None:
        """Extract one frame from the buffer.

        Returns a message, None when a frame was dropped and scanning should
        continue, or _NEED_MORE_DATA when the buffer holds no complete frame.
        """
        if not self._align_to_prefix():
            return _NEED_MORE_DATA

        is_6699 = bytes(self._buffer[:4]) == PREFIX_6699
        header_size = HEADER_SIZE_6699 if is_6699 else HEADER_SIZE
        if len(self._buffer) < header_size:
            return _NEED_MORE_DATA

        if is_6699:
            length = struct.unpack(">I", bytes(self._buffer[14:18]))[0]
            packet_size = header_size + length + SUFFIX_SIZE
            min_length = _MIN_LENGTH_6699
            suffix = SUFFIX_6699
        else:
            length = struct.unpack(">I", bytes(self._buffer[12:16]))[0]
            packet_size = header_size + length
            min_length = (
                _MIN_LENGTH_55AA_CRC
                if self._version == ProtocolVersion.V33
                else _MIN_LENGTH_55AA_HMAC
            )
            suffix = SUFFIX_55AA

        if length < min_length or length > MAX_PAYLOAD_LENGTH:
            self._report_failure(
                "framing",
                "Device frame declares an implausible length of %d bytes (allowed "
                "%d-%d). Resynchronising on the next frame; if this keeps happening "
                "the configured protocol version does not match the device.",
                length, min_length, MAX_PAYLOAD_LENGTH,
            )
            del self._buffer[:4]
            return None

        if len(self._buffer) < packet_size:
            return _NEED_MORE_DATA

        if bytes(self._buffer[packet_size - SUFFIX_SIZE : packet_size]) != suffix:
            self._report_failure(
                "framing",
                "Device frame of %d bytes does not end in the expected suffix %s. "
                "The stream is out of sync; resynchronising on the next frame.",
                packet_size, suffix.hex(),
            )
            del self._buffer[:4]
            return None

        self._report_recovered("framing")

        packet = bytes(self._buffer[:packet_size])
        del self._buffer[:packet_size]

        try:
            return self.decode(packet)
        except (FrameError, DecryptionError):
            # Already reported with an actionable message by the decoder.
            return None
        except (struct.error, ValueError) as err:
            self._report_failure(
                "decode",
                "Dropping an undecodable %d-byte frame (%s): %s",
                len(packet), err, packet[:32].hex(),
            )
            return None

    def _align_to_prefix(self) -> bool:
        """Drop leading bytes until the buffer starts on a frame prefix.

        Returns False when there is nothing left that could still become a
        frame. The trailing bytes of a possible split prefix are kept, so a
        prefix straddling two TCP reads is not thrown away.
        """
        if len(self._buffer) < 4:
            return False

        buf = bytes(self._buffer)
        pos_55aa = buf.find(PREFIX_55AA)
        pos_6699 = buf.find(PREFIX_6699)
        if pos_55aa < 0:
            prefix_pos = pos_6699
        elif pos_6699 < 0:
            prefix_pos = pos_55aa
        else:
            prefix_pos = min(pos_55aa, pos_6699)

        if prefix_pos < 0:
            # Keep the last 3 bytes: they may be the head of a prefix whose
            # remaining byte arrives in the next TCP read.
            dropped = len(self._buffer) - 3
            if dropped > 0:
                self._report_failure(
                    "framing",
                    "Discarded %d bytes from the device stream without a frame header. "
                    "The stream is out of sync; resynchronising.",
                    dropped,
                )
                del self._buffer[:dropped]
            return False

        if prefix_pos > 0:
            self._report_failure(
                "framing",
                "Skipped %d bytes of junk before a frame header; resynchronising.",
                prefix_pos,
            )
            del self._buffer[:prefix_pos]

        return len(self._buffer) >= 4

    def reset_buffer(self) -> None:
        """Clear the reassembly buffer and forget any reported failure state."""
        self._buffer.clear()
        self._failing.clear()
