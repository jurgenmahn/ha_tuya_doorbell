"""Tuya local protocol constants."""

from __future__ import annotations

import hashlib
from enum import IntEnum, StrEnum


# Packet framing
PREFIX_55AA = b"\x00\x00\x55\xaa"
PREFIX_6699 = b"\x00\x00\x66\x99"
SUFFIX = b"\x00\x00\xaa\x55"

# Header: prefix(4) + sequence(4) + command(4) + length(4) = 16 bytes
HEADER_SIZE = 16
SUFFIX_SIZE = 4
CRC32_SIZE = 4
HMAC_SIZE = 32
GCM_TAG_SIZE = 16
GCM_NONCE_SIZE = 12

# Version header for v3.3 packets (version string + 12 zero bytes)
VERSION_33_HEADER = b"3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
VERSION_34_HEADER = b"3.4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
VERSION_35_HEADER = b"3.5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# Fixed UDP discovery key
UDP_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()


class ProtocolVersion(StrEnum):
    """Supported Tuya protocol versions."""

    V33 = "3.3"
    V34 = "3.4"
    V35 = "3.5"


class Command(IntEnum):
    """Tuya protocol command IDs."""

    SESS_KEY_NEG_START = 3
    SESS_KEY_NEG_RESP = 4
    SESS_KEY_NEG_FINISH = 5
    CONTROL = 7
    STATUS = 8
    HEARTBEAT = 9
    DP_QUERY = 10
    CONTROL_NEW = 13
    UPDATEDPS = 18


# Mapping of version to header bytes
VERSION_HEADERS = {
    ProtocolVersion.V33: VERSION_33_HEADER,
    ProtocolVersion.V34: VERSION_34_HEADER,
    ProtocolVersion.V35: VERSION_35_HEADER,
}

# Commands that don't include payload
NO_PAYLOAD_COMMANDS = {Command.HEARTBEAT}

# Commands that don't get a protocol version header (v3.3 specific)
NO_PROTOCOL_HEADER_CMDS = {
    Command.DP_QUERY, Command.UPDATEDPS, Command.HEARTBEAT,
    Command.SESS_KEY_NEG_START, Command.SESS_KEY_NEG_RESP, Command.SESS_KEY_NEG_FINISH,
}

# Commands that return data
DATA_COMMANDS = {Command.STATUS, Command.DP_QUERY, Command.CONTROL, Command.UPDATEDPS, Command.CONTROL_NEW}
