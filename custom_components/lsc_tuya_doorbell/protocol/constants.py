"""Tuya local protocol constants."""

from __future__ import annotations

import hashlib
from enum import IntEnum, StrEnum


# Packet framing. The two frame formats do not share a suffix: 55AA frames end
# in AA55, 6699 frames end in 9966.
PREFIX_55AA = b"\x00\x00\x55\xaa"
PREFIX_6699 = b"\x00\x00\x66\x99"
SUFFIX_55AA = b"\x00\x00\xaa\x55"
SUFFIX_6699 = b"\x00\x00\x99\x66"

# Kept as the 55AA suffix so existing imports keep working.
SUFFIX = SUFFIX_55AA

# 55AA header: prefix(4) + sequence(4) + command(4) + length(4) = 16 bytes
HEADER_SIZE = 16
# 6699 header: prefix(4) + unknown(2) + sequence(4) + command(4) + length(4) = 18 bytes
HEADER_SIZE_6699 = 18
SUFFIX_SIZE = 4
CRC32_SIZE = 4
HMAC_SIZE = 32
GCM_TAG_SIZE = 16
GCM_NONCE_SIZE = 12

# Framing sanity limits. tinytuya rejects anything over 1000 bytes; camera
# datapoints carry cloud URLs and base64 blobs, so we allow more headroom but
# still refuse to wait for a length that no real device produces. Without an
# upper bound a single desynchronised byte stalls reassembly forever.
MAX_PAYLOAD_LENGTH = 16384
# Hard ceiling on the reassembly buffer: a full frame plus a second one that is
# still arriving. Anything beyond this is garbage we must not accumulate.
MAX_BUFFER_SIZE = 4 * MAX_PAYLOAD_LENGTH

# Version header for v3.3 packets (version string + 12 zero bytes)
VERSION_33_HEADER = b"3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
VERSION_34_HEADER = b"3.4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
VERSION_35_HEADER = b"3.5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# Fixed UDP discovery key
UDP_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()


class TuyaProtocolError(Exception):
    """Base class for every protocol-level failure this package reports."""


class UnsupportedProtocolVersionError(TuyaProtocolError, ValueError):
    """The device announced a protocol version this integration cannot speak."""


class FrameError(TuyaProtocolError):
    """A frame is malformed: bad length, bad suffix, or a failed integrity check."""


class DecryptionError(TuyaProtocolError):
    """A frame could not be decrypted, which almost always means a wrong key."""


class InvalidLocalKeyError(ConnectionError, TuyaProtocolError):
    """The device proved that our local key is wrong.

    Subclasses ConnectionError so callers that only handle connection failures
    keep working; catch this first to tell the user what to actually fix.
    """


class ProtocolVersion(StrEnum):
    """Supported Tuya protocol versions."""

    V33 = "3.3"
    V34 = "3.4"
    V35 = "3.5"

    @classmethod
    def parse(cls, version: str) -> ProtocolVersion:
        """Convert a version string, with an error that names the alternatives."""
        try:
            return cls(version)
        except ValueError as err:
            supported = ", ".join(v.value for v in cls)
            raise UnsupportedProtocolVersionError(
                f"Protocol version {version!r} is not supported by this integration "
                f"(supported: {supported}). Devices reporting 3.1 or 3.2 need a "
                f"firmware update, or must be used through the Tuya cloud integration."
            ) from err


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
