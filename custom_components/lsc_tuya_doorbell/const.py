"""Constants for the LSC Tuya Doorbell integration."""

from __future__ import annotations

from collections.abc import Iterable

DOMAIN = "lsc_tuya_doorbell"

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

# Debug event stream (off by default). When on, every datapoint the device
# reports is mirrored to the bus as it arrives, with a monotonic timestamp,
# so the exact timing of a doorbell press can be watched live in
# Developer Tools -> Events. See EVENT_DEBUG_DP.
DEFAULT_DEBUG_EVENTS = False

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
CONF_DEBUG_EVENTS = "debug_events"
CONF_ONVIF_USERNAME = "onvif_username"
CONF_ONVIF_PASSWORD = "onvif_password"
CONF_RTSP_PORT = "rtsp_port"
CONF_RTSP_PATH = "rtsp_path"
# Optional full RTSP URL that replaces the one built from host/port/path.
# Useful when the stream is served by a restreamer such as go2rtc, which
# keeps a single connection to the doorbell and fans it out to multiple
# consumers. Cameras typically accept only a handful of simultaneous RTSP
# sessions, so this avoids "connection reset by peer" once Home Assistant,
# HomeKit and any detection service all want the stream at the same time.
# Leave empty to keep the default behaviour.
CONF_STREAM_URL_OVERRIDE = "stream_url_override"
# Optional HTTP(S) URL that returns a single JPEG. When set, snapshots are
# fetched from it instead of being pulled off the RTSP stream with ffmpeg.
# Restreamers expose such an endpoint (go2rtc: /api/frame.jpeg?src=NAME), and
# using it avoids spinning up a decode -- or a hardware transcode -- for every
# still. Leave empty to keep grabbing frames from the stream.
CONF_STILL_IMAGE_URL_OVERRIDE = "still_image_url_override"
CONF_SNAPSHOT_PATH = "snapshot_path"
CONF_FORCE_ONVIF = "force_onvif"
# Older config entries stored this option under its former name. Read at
# runtime as a fallback so upgrading does not silently disable ONVIF forcing.
LEGACY_FORCE_RECORD_OPTION = "force_record_on"
CONF_SNAPSHOT_TRIGGER_DPS = "snapshot_trigger_dps"

DEFAULT_ONVIF_USERNAME = "admin"
DEFAULT_RTSP_PORT = 8554
DEFAULT_RTSP_PATH = "/Streaming/Channels/101"
DEFAULT_SNAPSHOT_PATH = "/config/www/doorbell"
MAX_SNAPSHOTS = 10

# Home Assistant serves <config>/www as /local. Only files below that directory
# can be published as a URL; anything else gets a path and no URL, instead of a
# /local/ link that resolves to nothing.
WWW_DIRECTORY = "www"
LOCAL_URL_PREFIX = "/local/"
DEFAULT_WWW_ROOT = "/config/www"

# Fetching a configured still-image URL sits in front of a notification, so it
# fails fast rather than hanging the snapshot task.
STILL_IMAGE_TIMEOUT = 10  # seconds

# How long to wait before pushing the ONVIF switch back on after the device
# turned it off by itself (which also drops the RTSP stream).
ONVIF_RECOVERY_DELAY = 2  # seconds

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

# Well-known DP IDs.
#
# These are seeds, not behaviour. They are the numbers this integration was
# first written against, on one LSC model with one firmware. Datapoint numbers
# move between firmware revisions and between models -- which is exactly why
# the integration used to do nothing at all on other people's doorbells. Use
# them to propose roles after a scan; never to decide what a datapoint means.
DP_RECORD_SWITCH = 101
DP_DOORBELL_BUTTON = 185
DP_MOTION_DETECTION = 115

# Roles: what a datapoint *does*, as opposed to the number it happens to carry.
# Everything that used to compare a DP number now asks the device profile which
# datapoint currently holds a role. A role that is not in the profile means the
# behaviour is off -- there is no falling back to a number, because guessing is
# what broke this in the first place.
ROLE_DOORBELL_BUTTON = "doorbell_button"
ROLE_MOTION = "motion"
# The switch that enables ONVIF (and with it the RTSP stream). Some devices
# turn it off by themselves; "force ONVIF" pushes it back on. Formerly, and
# misleadingly, called the "record switch".
ROLE_ONVIF = "onvif"
# Its former role name, migrated to ROLE_ONVIF when an old profile loads.
LEGACY_ONVIF_ROLE = "record_switch"

ROLES: tuple[str, ...] = (ROLE_DOORBELL_BUTTON, ROLE_MOTION, ROLE_ONVIF)

# Used to propose roles after a scan, and to give profiles written before roles
# existed something sensible on first load. Nothing reads this at runtime.
DEFAULT_ROLE_DPS: dict[str, int] = {
    ROLE_DOORBELL_BUTTON: DP_DOORBELL_BUTTON,
    ROLE_MOTION: DP_MOTION_DETECTION,
    # ROLE_ONVIF deliberately absent. DP 101 was assumed to be the ONVIF/record
    # switch and is verified to be the indicator light, so seeding it would point
    # "force ONVIF" at an LED and toggle it forever. A role nobody assigned is
    # off; a role pointed at the wrong datapoint acts.
}

# Snapshot configuration.
#
# Defaults live in video.py, which deliberately imports nothing from here, so
# there is one source of truth and no cycle.
CONF_SNAPSHOT_MODE = "snapshot_mode"
# Where the recording modes read video from, when that should not be the same
# place the camera entity streams from. Empty means: use the camera's source.
CONF_SNAPSHOT_SOURCE_URL = "snapshot_source_url"
CONF_SNAPSHOT_BUFFER_PATH = "snapshot_buffer_path"
CONF_SNAPSHOT_BUFFER_SECONDS = "snapshot_buffer_seconds"
CONF_SNAPSHOT_DELAY_MS = "snapshot_delay_ms"

# How far back a snapshot may reach. The device reports a press several seconds
# late, so a picture of "now" shows whoever pressed it already leaving; this is
# the compensation for that, and only the buffer mode can honour it.
MAX_SNAPSHOT_DELAY_MS = 8000

MIN_BUFFER_SECONDS = 5
MAX_BUFFER_SECONDS = 300

# Event types
EVENT_BUTTON_PRESS = f"{DOMAIN}_button_press"
EVENT_MOTION_DETECT = f"{DOMAIN}_motion_detect"
EVENT_CONNECTED = f"{DOMAIN}_connected"
EVENT_DISCONNECTED = f"{DOMAIN}_disconnected"
EVENT_IP_CHANGED = f"{DOMAIN}_ip_changed"
EVENT_DP_DISCOVERED = f"{DOMAIN}_dp_discovered"
EVENT_SNAPSHOT_READY = f"{DOMAIN}_snapshot_ready"

# Fired by the service handler, which carries a different payload than the hub's
# own EVENT_DP_DISCOVERED. They used to share a name, so an automation listening
# for one could receive either shape depending on where it came from.
EVENT_DP_SCAN_RESULTS = f"{DOMAIN}_dp_scan_results"

# Fired for a datapoint whose definition says is_event but that holds no role.
# Without it such a datapoint would only ever move an entity and stay invisible
# to automations.
EVENT_DP_EVENT = f"{DOMAIN}_dp_event"

# A realtime mirror of every datapoint update, fired only while the debug
# switch is on. Unlike the events above it carries no meaning about roles;
# it exists purely to time what the device sends. Payload: dp, value, raw,
# old_value, monotonic (time.monotonic() at arrival), plus device_id.
EVENT_DEBUG_DP = f"{DOMAIN}_debug_dp"

# Every device event is fired twice: once under the stable name above, and once
# under "<name>_<device slug>". The slug comes from the editable device name, so
# renaming a device silently breaks every automation built on it. New
# automations filter on device_id in the payload instead.
DEPRECATED_SLUG_EVENTS = True

# Repair issue raised when no datapoint claims the doorbell-button role: without
# it the hub cannot know which datapoint is the bell, so the button press event
# and its snapshot stay off. The fix is a datapoint scan.
ISSUE_NO_DOORBELL_ROLE = "no_doorbell_role"

# Platforms. "event" is Home Assistant's own event entity, which is what an
# automation should trigger on; the binary sensor stays for dashboards that show
# a momentary "someone is at the door".
PLATFORMS = [
    "binary_sensor",
    "event",
    "sensor",
    "switch",
    "select",
    "number",
    "camera",
    "image",
    "button",
]

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
    # Verified on hardware 2026-08-27: the indicator light. Not the ONVIF/record
    # switch, which is what made this number dangerous -- see DEFAULT_ROLE_DPS.
    101: {"verified": True, "name": "Indicator Light", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    # Verified on hardware 2026-08-27: flips the image. The table did know about
    # an image flip -- it had it on DP 134, which actually arms the motion alarm.
    # Right concept, wrong number, and it called this one a three-state night
    # vision enum while the device reports a plain boolean.
    103: {"verified": True, "name": "Image Flip", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    # Verified on hardware 2026-08-27: the timestamp burned into the image. The
    # indicator light the table put here is DP 101.
    104: {"verified": True, "name": "Time Watermark", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    106: {
        "name": "Motion Sensitivity",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "low", "1": "medium", "2": "high"},
    },
    # Verified on hardware 2026-08-27: infrared night vision, not an OSD toggle.
    # Note the order -- 1 is off and 2 is on, which is the reverse of what DP 103
    # claims for the same three states. One of the two is mislabelled; this one
    # was checked against the device.
    108: {"verified": True, 
        "name": "IR Night Vision",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"0": "auto", "1": "off", "2": "on"},
    },
    109: {"name": "SD Storage Info", "dp_type": DP_TYPE_STRING, "entity_type": ENTITY_SENSOR},
    110: {
        "name": "SD Card Status",
        "dp_type": DP_TYPE_INT,
        "entity_type": ENTITY_SENSOR,
        "value_map": SD_STATUS_MAP,
    },
    115: {"verified": True, 
        "name": "Motion Detection",
        "dp_type": DP_TYPE_RAW,
        "entity_type": ENTITY_BINARY_SENSOR,
        "is_event": True,
        "carries_image_url": True,
    },
    # Verified on hardware 2026-08-27: device volume. Observed carrying 1, 7 and
    # 10, which is what the range is taken from -- if a device ever reports
    # outside it, the bounds are wrong rather than the device.
    160: {"verified": True, "name": "Device Volume", "dp_type": DP_TYPE_INT, "entity_type": ENTITY_NUMBER,
          "min": 1, "max": 10},
    # Verified on hardware 2026-08-27: starts chime pairing. Reported as an
    # enum carrying "1" then "0", so it behaves as an action rather than a
    # setting that stays put.
    155: {"verified": True, "name": "Chime Pairing", "dp_type": DP_TYPE_ENUM, "entity_type": ENTITY_SELECT,
          "options": {"0": "idle", "1": "pairing"}},
    # Verified on hardware 2026-08-27: this toggles the motion detection alarm,
    # not the image flip the table claimed. Both generations had it wrong, which
    # is the argument for the live capture in one line.
    134: {"verified": True, "name": "Motion Alarm", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    # Verified on hardware 2026-08-27: enables and disables video recording.
    # Not the chime. This is the third v4 entry found to be wrong on a device
    # the table is supposed to describe -- treat the tables as a starting point
    # for names, never as a statement about what a datapoint does.
    150: {"verified": True, "name": "Video Recording", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    151: {"verified": True, 
        "name": "Recording Mode",
        "dp_type": DP_TYPE_ENUM,
        "entity_type": ENTITY_SELECT,
        "options": {"1": "event", "2": "continuous"},
    },
    # Claim withdrawn. This was listed as the device volume, and DP 160 is
    # verified to be that on the same generation -- two volume controls on one
    # firmware is not credible, and only one of the two was checked. Kept
    # because the datapoint exists; named so it does not collide with the one
    # that was measured.
    154: {"name": "DP 154 (number)", "dp_type": DP_TYPE_INT, "entity_type": ENTITY_NUMBER},
    # No device_class here on purpose: a doorbell is "occupancy" to a binary
    # sensor and "doorbell" to an event entity, so a single string would be
    # wrong on one of the two. The role tables in entity_meta.py pick the right
    # one per platform.
    # Verified on hardware 2026-08-27: switches the ONVIF service on and off.
    255: {"verified": True, "name": "ONVIF", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    185: {"verified": True, 
        "name": "Doorbell Button",
        "dp_type": DP_TYPE_RAW,
        "entity_type": ENTITY_BINARY_SENSOR,
        "is_event": True,
        "carries_image_url": True,
    },
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
    109: {
        "name": "SD Card Status",
        "dp_type": DP_TYPE_INT,
        "entity_type": ENTITY_SENSOR,
        "value_map": SD_STATUS_MAP,
    },
    110: {"name": "Basic OSD", "dp_type": DP_TYPE_BOOL, "entity_type": ENTITY_SWITCH},
    115: {
        "name": "Motion Detection",
        "dp_type": DP_TYPE_RAW,
        "entity_type": ENTITY_BINARY_SENSOR,
        "is_event": True,
        "carries_image_url": True,
    },
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
    # No device_class here on purpose: a doorbell is "occupancy" to a binary
    # sensor and "doorbell" to an event entity, so a single string would be
    # wrong on one of the two. The role tables in entity_meta.py pick the right
    # one per platform.
    185: {
        "name": "Doorbell Button",
        "dp_type": DP_TYPE_RAW,
        "entity_type": ENTITY_BINARY_SENSOR,
        "is_event": True,
        "carries_image_url": True,
    },
}

# Firmware generation -> known DP table.
KNOWN_DPS_BY_FIRMWARE: dict[str, dict[int, dict]] = {
    "4": KNOWN_DPS_V4,
    "5": KNOWN_DPS_V5,
}

# Union of both generations, kept only as a last resort for a device whose
# firmware is unknown.
#
# Be careful with it: where v4 and v5 disagree, v5 wins silently. DP 110 is
# "SD Card Status" on v4 and "Basic OSD" on v5; DP 134 is "Vision Flip" against
# "Chime Switch". A v4 device read through this table therefore gets the wrong
# name, the wrong type and the wrong entity. Prefer known_dps_for().
KNOWN_DPS: dict[int, dict] = {**KNOWN_DPS_V4, **KNOWN_DPS_V5}

# Where the two generations disagree, so callers can say so instead of picking.
AMBIGUOUS_DPS: frozenset[int] = frozenset(
    dp_id
    for dp_id in KNOWN_DPS_V4.keys() & KNOWN_DPS_V5.keys()
    if KNOWN_DPS_V4[dp_id] != KNOWN_DPS_V5[dp_id]
)


def infer_firmware_generation(dp_ids: Iterable[int]) -> str | None:
    """Work out which known-DP table a device follows, from what it reports.

    Judged only on datapoints that exist in one generation and not the other:
    those are evidence, while a datapoint both tables share says nothing. If the
    evidence points both ways, or nowhere, this returns None and the caller
    keeps guessing rather than pretending to know.

    Worth the trouble because the fallback is the union of both tables, where v5
    silently wins every disagreement -- which is how a v4 device ends up with two
    datapoints both called "Basic OSD" and two called "Chime Switch".
    """
    reported = set(dp_ids)
    scores: dict[str, int] = {}
    for generation, table in KNOWN_DPS_BY_FIRMWARE.items():
        others: set[int] = set()
        for other_generation, other_table in KNOWN_DPS_BY_FIRMWARE.items():
            if other_generation != generation:
                others |= set(other_table)
        exclusive = set(table) - others
        scores[generation] = len(reported & exclusive)

    best = max(scores.values(), default=0)
    if not best:
        return None
    winners = [gen for gen, score in scores.items() if score == best]
    return winners[0] if len(winners) == 1 else None


def verified_dps_for(firmware_version: str | None) -> dict[int, dict]:
    """Only the entries someone has checked against real hardware.

    This is what names a datapoint. The rest of the table is kept for
    known_dps_for(), which needs to know which datapoints a generation *has* in
    order to tell the generations apart -- presence is reliable in a way that
    meaning is not.

    Nine v4 entries were checked against one doorbell and eight were wrong,
    usually with the right concept on the wrong number: an image flip filed
    under the motion alarm, an indicator light filed under the timestamp
    overlay. At that rate an unchecked name is likelier to mislead than to help,
    and "DP 110" is understood by everyone while "Basic OSD" on a datapoint that
    reports SD card status is understood by no one.

    Contributions welcome: verify one against your device and mark it.
    """
    return {
        dp_id: entry
        for dp_id, entry in known_dps_for(firmware_version).items()
        if entry.get("verified")
    }


def known_dps_for(firmware_version: str | None) -> dict[int, dict]:
    """Return the known-DP table for a firmware generation.

    Falls back to the union when the generation is unknown, which is a guess --
    see AMBIGUOUS_DPS for the datapoints where that guess can be wrong.
    """
    if firmware_version:
        generation = str(firmware_version).strip().lstrip("vV").split(".")[0]
        table = KNOWN_DPS_BY_FIRMWARE.get(generation)
        if table is not None:
            return table
    return KNOWN_DPS


def mask_credential(value: str) -> str:
    """Mask a credential string for safe logging (show first 3 + last 3 chars)."""
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}***{value[-3:]}"
