"""Constants for the LSC Tuya Doorbell integration."""

from __future__ import annotations

DOMAIN = "lsc_tuya_doorbell"
VERSION = "2.6.0"

# Connection defaults
DEFAULT_PORT = 6668
HEARTBEAT_INTERVAL = 10  # seconds
HEARTBEAT_MAX_FAILURES = 3

# Reconnect backoff sequence (seconds)
RECONNECT_BACKOFF = [10, 20, 40, 80, 160, 300]
RECONNECT_INITIAL_WAIT = 5  # seconds before first retry
RECONNECT_RETRY_COUNT = 3  # retries on known IP before discovery
RECONNECT_RETRY_INTERVAL = 5  # seconds between known-IP retries

# Event reset timeout
DEFAULT_EVENT_RESET_TIMEOUT = 5  # seconds

# DP discovery
DP_SCAN_START = 1
DP_SCAN_END = 255
DP_SCAN_BATCH_SIZE = 20
DP_SCAN_TIMEOUT = 120  # seconds — overall timeout for scan_all()
DP_SCAN_MAX_RETRIES = 3  # max retry attempts when scan interrupted by disconnect
DP_SCAN_RECONNECT_WAIT = 30  # seconds to wait for reconnect between retries

# Discovery
DISCOVERY_UDP_PORTS = [6666, 6667]
DISCOVERY_CACHE_TTL = 300  # seconds (5 min)
DISCOVERY_SCAN_TIMEOUT = 10  # seconds
DISCOVERY_RECONNECT_TIMEOUT = 30  # seconds
TCP_SCANNER_MAX_CONCURRENT = 50
TCP_SCANNER_TIMEOUT = 1.0  # seconds per host

# Config entry keys
CONF_DEVICE_ID = "device_id"
CONF_LOCAL_KEY = "local_key"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_PROTOCOL_VERSION = "protocol_version"
CONF_DEVICE_NAME = "device_name"
CONF_DP_OVERRIDES = "dp_overrides"
CONF_EVENT_RESET_TIMEOUT = "event_reset_timeout"
CONF_ONVIF_USERNAME = "onvif_username"
CONF_ONVIF_PASSWORD = "onvif_password"
CONF_RTSP_PORT = "rtsp_port"
CONF_RTSP_PATH = "rtsp_path"
CONF_SNAPSHOT_PATH = "snapshot_path"

DEFAULT_ONVIF_USERNAME = "admin"
DEFAULT_RTSP_PORT = 8554
DEFAULT_RTSP_PATH = "/Streaming/Channels/101"
DEFAULT_SNAPSHOT_PATH = "/config/www/doorbell"
MAX_SNAPSHOTS = 10

# DP types
DP_TYPE_BOOL = "bool"
DP_TYPE_INT = "int"
DP_TYPE_ENUM = "enum"
DP_TYPE_STRING = "string"
DP_TYPE_RAW = "raw"

# Entity types
ENTITY_SWITCH = "switch"
ENTITY_SELECT = "select"
ENTITY_NUMBER = "number"
ENTITY_SENSOR = "sensor"
ENTITY_BINARY_SENSOR = "binary_sensor"
ENTITY_EVENT = "event"

# Device types (for discovery classification)
DEVICE_TYPE_DOORBELL = "doorbell"
DEVICE_TYPE_CAMERA = "camera"
DEVICE_TYPE_UNKNOWN = "unknown"

DEVICE_TYPE_LABELS = {
    DEVICE_TYPE_DOORBELL: "Video Doorbell",
    DEVICE_TYPE_CAMERA: "Camera",
    DEVICE_TYPE_UNKNOWN: "Unknown Device",
}

# Product key → device type mapping (from known LSC / Tuya devices)
PRODUCT_KEY_DEVICE_TYPE: dict[str, str] = {
    "jtc6fpl3": DEVICE_TYPE_DOORBELL,
    # Add more product keys as they are discovered
}

# Well-known DP IDs
DP_DOORBELL_BUTTON = 185
DP_MOTION_DETECTION = 115

# Event types
EVENT_BUTTON_PRESS = f"{DOMAIN}_button_press"
EVENT_MOTION_DETECT = f"{DOMAIN}_motion_detect"
EVENT_CONNECTED = f"{DOMAIN}_connected"
EVENT_DISCONNECTED = f"{DOMAIN}_disconnected"
EVENT_IP_CHANGED = f"{DOMAIN}_ip_changed"
EVENT_DP_DISCOVERED = f"{DOMAIN}_dp_discovered"

# Platforms
PLATFORMS = ["binary_sensor", "sensor", "switch", "select", "number", "camera"]

# SD Card status mapping
SD_STATUS_MAP = {
    1: "normal",
    2: "no_card",
    3: "abnormal",
    4: "insufficient_space",
    5: "formatting",
}

# Known DP definitions: {dp_id: (name, dp_type, entity_type, options)}
# Firmware v4 mappings
KNOWN_DPS_V4: dict[int, dict] = {
    101: {"name": "Record Switch", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    103: {
        "name": "Night Vision",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "auto", "1": "on", "2": "off"},
    },
    104: {"name": "Indicator Light", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    106: {
        "name": "Motion Sensitivity",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "low", "1": "medium", "2": "high"},
    },
    108: {
        "name": "Basic OSD",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "off", "1": "on"},
    },
    109: {"name": "SD Storage Info", "dp_type": DP_TYPE_STRING, "entity_type": ENTITY_SENSOR},
    110: {"name": "SD Card Status", "dp_type": DP_TYPE_INT, "entity_type": ENTITY_SENSOR},
    115: {"name": "Motion Detection", "dp_type": DP_TYPE_RAW, "entity_type": ENTITY_BINARY_SENSOR, "is_event": True},
    134: {"name": "Vision Flip", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    150: {"name": "Chime Switch", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    151: {
        "name": "Recording Mode",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"1": "event", "2": "continuous"},
    },
    154: {
        "name": "Device Volume",
        "dp_type": DP_TYPE_INT,
        "entity_type": ENTITY_NUMBER,
        "min": 1,
        "max": 10,
    },
    185: {"name": "Doorbell Button", "dp_type": DP_TYPE_RAW, "entity_type": ENTITY_BINARY_SENSOR, "is_event": True},
}

# Firmware v5 mappings (different DP numbers for some controls)
KNOWN_DPS_V5: dict[int, dict] = {
    101: {"name": "Record Switch", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    103: {
        "name": "Night Vision",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "auto", "1": "on", "2": "off"},
    },
    104: {"name": "Indicator Light", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    105: {"name": "Vision Flip", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    106: {
        "name": "Motion Sensitivity",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "low", "1": "medium", "2": "high"},
    },
    109: {"name": "SD Card Status", "dp_type": DP_TYPE_INT, "entity_type": ENTITY_SENSOR},
    110: {"name": "Basic OSD", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    115: {"name": "Motion Detection", "dp_type": DP_TYPE_RAW, "entity_type": ENTITY_BINARY_SENSOR, "is_event": True},
    134: {"name": "Chime Switch", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    135: {
        "name": "Chime Volume",
        "dp_type": DP_TYPE_INT,
        "entity_type": ENTITY_NUMBER,
        "min": 0,
        "max": 10,
    },
    139: {
        "name": "Device Volume",
        "dp_type": DP_TYPE_INT,
        "entity_type": ENTITY_NUMBER,
        "min": 1,
        "max": 10,
    },
    151: {
        "name": "Recording Mode",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"1": "event", "2": "continuous"},
    },
    185: {"name": "Doorbell Button", "dp_type": DP_TYPE_RAW, "entity_type": ENTITY_BINARY_SENSOR, "is_event": True},
}

# Combined known DPs (union of v4 and v5 — used as fallback)
KNOWN_DPS: dict[int, dict] = {**KNOWN_DPS_V4, **KNOWN_DPS_V5}


def mask_credential(value: str) -> str:
    """Mask a credential string for safe logging (show first 3 + last 3 chars)."""
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-3:]}"
