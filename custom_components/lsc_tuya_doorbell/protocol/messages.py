"""Tuya protocol message encoding/decoding with TCP stream reassembly."""

from __future__ import annotations

import json
import logging
import struct
from dataclasses import dataclass, field
from typing import Any

from .constants import (
    CRC32_SIZE,
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    HEADER_SIZE,
    HMAC_SIZE,
    NO_PAYLOAD_COMMANDS,
    NO_PROTOCOL_HEADER_CMDS,
    PREFIX_55AA,
    PREFIX_6699,
    SUFFIX,
    SUFFIX_SIZE,
    Command,
    ProtocolVersion,
    VERSION_33_HEADER,
)
from .encryption import TuyaCipher

_LOGGER = logging.getLogger(__name__)


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
        if self.payload and not self.data:
            try:
                text = self.payload.decode("utf-8", errors="ignore").strip("\x00")
                if text:
                    self.data = json.loads(text)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass


class MessageCodec:
    """Encodes and decodes Tuya protocol messages with TCP stream reassembly."""

    def __init__(self, version: str, local_key: bytes) -> None:
        self._version = ProtocolVersion(version)
        self._cipher = TuyaCipher(local_key)
        self._seqno = 0
        self._session_key: bytes | None = None
        self._buffer = bytearray()
        # Version header: "3.x" + 12 zero bytes
        self._version_header = self._version.encode("ascii") + b"\x00" * 12

    @property
    def version(self) -> ProtocolVersion:
        """Return the protocol version."""
        return self._version

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

    def encode(
        self,
        command: int,
        payload: dict | str | bytes | None = None,
        seqno: int | None = None,
    ) -> bytes:
        """Encode a command + payload into a wire-format Tuya packet."""
        if seqno is None:
            seqno = self.next_seqno()

        if self._version == ProtocolVersion.V35:
            return self._encode_v35(command, payload, seqno)
        return self._encode_v33_v34(command, payload, seqno)

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
        # Build payload bytes
        if command in NO_PAYLOAD_COMMANDS or payload is None:
            payload_bytes = b""
        elif isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        # Encrypt payload
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

        # Calculate total length: payload + CRC/HMAC + suffix (NO retcode in outgoing)
        if self._version == ProtocolVersion.V33:
            total_len = len(encrypted) + CRC32_SIZE + SUFFIX_SIZE
        else:
            total_len = len(encrypted) + HMAC_SIZE + SUFFIX_SIZE

        # Build header
        header = PREFIX_55AA + struct.pack(">III", seqno, command, total_len)

        # No retcode in outgoing packets
        body = header + encrypted

        # Add integrity check
        if self._version == ProtocolVersion.V33:
            crc = self._cipher.calc_crc32(body)
            return body + crc + SUFFIX
        else:
            hmac_key = self._session_key or self._cipher.local_key
            hmac_val = self._cipher.calc_hmac(hmac_key, body)
            return body + hmac_val + SUFFIX

    def _encode_v35(
        self,
        command: int,
        payload: dict | str | bytes | None,
        seqno: int,
    ) -> bytes:
        """Encode for v3.5 protocol (6699 frame format with AES-GCM)."""
        # Build payload bytes
        if command in NO_PAYLOAD_COMMANDS or payload is None:
            payload_bytes = b""
        elif isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        key = self._session_key or self._cipher.local_key
        iv = self._cipher.generate_nonce()[:GCM_NONCE_SIZE]

        if payload_bytes:
            ciphertext, tag = self._cipher.encrypt_gcm(payload_bytes, key, iv)
        else:
            ciphertext, tag = b"", b"\x00" * GCM_TAG_SIZE

        # 6699 format: header(4) + padding(4) + seq(4) + cmd(4) + length(4) + iv(12) + ct + tag(16) + suffix(4)
        inner_len = GCM_NONCE_SIZE + len(ciphertext) + GCM_TAG_SIZE + 4  # +4 for retcode
        header = PREFIX_6699 + struct.pack(">III", seqno, command, inner_len)
        body = header + b"\x00\x00\x00\x00" + iv + ciphertext + tag

        return body + SUFFIX

    def decode(self, data: bytes) -> TuyaMessage:
        """Decode a single complete Tuya packet."""
        if data[:4] == PREFIX_6699:
            return self._decode_v35(data)
        return self._decode_v33_v34(data)

    def _decode_v33_v34(self, data: bytes) -> TuyaMessage:
        """Decode a v3.3 or v3.4 packet."""
        # Parse header
        _prefix, seqno, command, total_len = struct.unpack(">IIII", data[:HEADER_SIZE])

        # Auto-detect retcode: device responses include retcode (0 or 1),
        # outgoing packets we encode don't have retcode.
        retcode_candidate = struct.unpack(">I", data[HEADER_SIZE : HEADER_SIZE + 4])[0]
        if retcode_candidate <= 1:
            # Valid retcode (0=success, 1=error)
            retcode = retcode_candidate
            payload_start = HEADER_SIZE + 4
        else:
            # Not a retcode — data starts right after header
            retcode = 0
            payload_start = HEADER_SIZE

        # Determine integrity check size
        if self._version == ProtocolVersion.V33:
            integrity_size = CRC32_SIZE
        else:
            integrity_size = HMAC_SIZE

        # Extract encrypted payload (between header/retcode and integrity+suffix)
        payload_end = len(data) - integrity_size - SUFFIX_SIZE
        encrypted = data[payload_start:payload_end]

        # Verify integrity
        if self._version == ProtocolVersion.V33:
            expected_crc = data[payload_end : payload_end + CRC32_SIZE]
            check_data = data[: payload_end]
            actual_crc = self._cipher.calc_crc32(check_data)
            if expected_crc != actual_crc:
                _LOGGER.debug("CRC32 mismatch: expected %s, got %s", expected_crc.hex(), actual_crc.hex())
        else:
            expected_hmac = data[payload_end : payload_end + HMAC_SIZE]
            check_data = data[: payload_end]
            hmac_key = self._session_key or self._cipher.local_key
            actual_hmac = self._cipher.calc_hmac(hmac_key, check_data)
            if expected_hmac != actual_hmac:
                _LOGGER.debug("HMAC mismatch")

        # Decrypt payload
        if not encrypted:
            payload = b""
        else:
            key = self._session_key if self._version == ProtocolVersion.V34 and self._session_key else None

            if self._version == ProtocolVersion.V34:
                # v3.4: decrypt first, then strip version header from decrypted data
                try:
                    payload = self._cipher.decrypt_ecb(encrypted, key)
                except Exception:
                    _LOGGER.debug("Decryption failed, returning raw payload")
                    payload = encrypted
                # Strip version header from decrypted payload if present
                if payload[:3] in (b"3.3", b"3.4", b"3.5"):
                    payload = payload[15:]
            else:
                # v3.3: strip version header from raw data, then decrypt
                if encrypted[:3] in (b"3.3", b"3.4", b"3.5"):
                    encrypted = encrypted[15:]
                try:
                    payload = self._cipher.decrypt_ecb(encrypted, key)
                except Exception:
                    _LOGGER.debug("Decryption failed, returning raw payload")
                    payload = encrypted

        return TuyaMessage(
            seqno=seqno,
            command=command,
            retcode=retcode if retcode != 0 else None,
            payload=payload,
        )

    def _decode_v35(self, data: bytes) -> TuyaMessage:
        """Decode a v3.5 (6699) packet."""
        _prefix, seqno, command, total_len = struct.unpack(">IIII", data[:HEADER_SIZE])

        # After header: retcode(4) + iv(12) + ciphertext + tag(16) + suffix(4)
        offset = HEADER_SIZE
        retcode = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4

        iv = data[offset : offset + GCM_NONCE_SIZE]
        offset += GCM_NONCE_SIZE

        # Ciphertext is between iv and tag+suffix
        ct_end = len(data) - GCM_TAG_SIZE - SUFFIX_SIZE
        ciphertext = data[offset:ct_end]
        tag = data[ct_end : ct_end + GCM_TAG_SIZE]

        key = self._session_key or self._cipher.local_key
        try:
            payload = self._cipher.decrypt_gcm(ciphertext, key, iv, tag)
        except Exception:
            _LOGGER.debug("GCM decryption failed, returning raw payload")
            payload = ciphertext

        return TuyaMessage(
            seqno=seqno,
            command=command,
            retcode=retcode if retcode != 0 else None,
            payload=payload,
        )

    def feed(self, data: bytes) -> list[TuyaMessage]:
        """Feed raw TCP data into the reassembly buffer.

        Returns a list of zero or more complete decoded messages.
        Handles partial reads and multiple messages in a single read.
        """
        self._buffer.extend(data)
        messages = []

        while True:
            msg = self._try_extract_message()
            if msg is None:
                break
            messages.append(msg)

        return messages

    def _try_extract_message(self) -> TuyaMessage | None:
        """Try to extract a single complete message from the buffer."""
        if len(self._buffer) < HEADER_SIZE:
            return None

        # Find a valid prefix
        prefix_pos = -1
        for i in range(len(self._buffer) - 3):
            if bytes(self._buffer[i : i + 4]) in (PREFIX_55AA, PREFIX_6699):
                prefix_pos = i
                break

        if prefix_pos == -1:
            # No valid prefix found, discard buffer
            self._buffer.clear()
            return None

        # Discard data before prefix
        if prefix_pos > 0:
            del self._buffer[:prefix_pos]

        if len(self._buffer) < HEADER_SIZE:
            return None

        # Parse length from header
        _prefix, _seqno, _command, total_len = struct.unpack(">IIII", bytes(self._buffer[:HEADER_SIZE]))

        # Total packet size: header + total_len (which includes payload + integrity + suffix for 55AA)
        is_6699 = bytes(self._buffer[:4]) == PREFIX_6699
        if is_6699:
            # 6699: header(16) + retcode(4) + iv(12) + ciphertext + tag(16) + suffix(4)
            # total_len covers: retcode(4) + iv(12) + ct + tag(16)
            packet_size = HEADER_SIZE + total_len + SUFFIX_SIZE
        else:
            # 55AA: header(16) + total_len (includes retcode + payload + integrity + suffix)
            packet_size = HEADER_SIZE + total_len

        if len(self._buffer) < packet_size:
            return None  # Incomplete packet

        # Extract complete packet
        packet = bytes(self._buffer[:packet_size])
        del self._buffer[:packet_size]

        try:
            return self.decode(packet)
        except Exception:
            _LOGGER.debug("Failed to decode packet: %s", packet[:32].hex())
            return None

    def reset_buffer(self) -> None:
        """Clear the reassembly buffer."""
        self._buffer.clear()
