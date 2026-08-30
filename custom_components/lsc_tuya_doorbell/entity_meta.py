"""Presentation rules for datapoints, with no Home Assistant imports.

Every function here answers a question that used to be answered by comparing a
datapoint number against a constant: what a datapoint means, how it should be
shown, and which datapoints turn into which platform. A datapoint describes
itself now, and a role describes what it does; a number describes nothing.

Keeping this module free of Home Assistant is what makes those rules testable
without a Home Assistant install, which is the only reason they are out here
instead of inside the entity classes.
"""

from __future__ import annotations

import logging
from typing import Any

from .const import (
    CONF_EVENT_RESET_TIMEOUT,
    CONF_ONVIF_PASSWORD,
    CONF_ONVIF_USERNAME,
    CONF_RTSP_PATH,
    CONF_RTSP_PORT,
    CONF_STREAM_URL_OVERRIDE,
    DEFAULT_EVENT_RESET_TIMEOUT,
    DEFAULT_ONVIF_USERNAME,
    DEFAULT_RTSP_PATH,
    DEFAULT_RTSP_PORT,
    ENTITY_EVENT,
    ROLE_DOORBELL_BUTTON,
    ROLE_MOTION,
    ROLE_ONVIF,
)
from .dp_registry import DeviceProfile, DPDefinition
from .video import build_rtsp_url

_LOGGER = logging.getLogger(__name__)

# The auto-reset timer turns an event sensor back off. Below a second it is
# invisible to anything polling; above a few minutes it stops being an event.
MIN_EVENT_RESET_TIMEOUT = 1
MAX_EVENT_RESET_TIMEOUT = 300

# What a role implies, used only where the datapoint definition itself is
# silent. A datapoint without a definition and without a role gets nothing --
# no device class at all is honest, while a wrong one is not.
# Roles that describe something happening rather than something being. A
# datapoint holding one of these is an event by definition -- the role is the
# statement -- so it gets an event entity whether or not the stored definition
# says so. Profiles written by older versions have is_event set to False on
# exactly these datapoints, because the old "add selected datapoints" step
# rebuilt every definition from scratch and dropped the flag.
EVENT_ROLES: frozenset[str] = frozenset({ROLE_DOORBELL_BUTTON, ROLE_MOTION})

ROLE_BINARY_DEVICE_CLASS: dict[str, str] = {
    ROLE_DOORBELL_BUTTON: "occupancy",
    ROLE_MOTION: "motion",
}

ROLE_EVENT_DEVICE_CLASS: dict[str, str] = {
    ROLE_DOORBELL_BUTTON: "doorbell",
    ROLE_MOTION: "motion",
}

ROLE_ICONS: dict[str, str] = {
    ROLE_DOORBELL_BUTTON: "mdi:doorbell-video",
    ROLE_MOTION: "mdi:motion-sensor",
    ROLE_ONVIF: "mdi:cctv",
}

# Event types are part of an event entity's identity: renaming one breaks every
# automation that triggers on it, so they are pinned per role here.
ROLE_EVENT_TYPES: dict[str, str] = {
    ROLE_DOORBELL_BUTTON: "ring",
    ROLE_MOTION: "motion",
}

DEFAULT_EVENT_TYPE = "triggered"


def device_class_for(
    dp_def: DPDefinition,
    role: str | None = None,
    role_map: dict[str, str] | None = None,
) -> str | None:
    """Device class for a datapoint, or None when nothing is known.

    Order: what the definition says, then what the role implies, then nothing.
    """
    if dp_def.device_class:
        return dp_def.device_class
    if role and role_map:
        return role_map.get(role)
    return None


def icon_for(dp_def: DPDefinition, role: str | None = None) -> str | None:
    """Icon for a datapoint: the definition first, then the role, else None."""
    if dp_def.icon:
        return dp_def.icon
    if role:
        return ROLE_ICONS.get(role)
    return None


def event_type_for(role: str | None) -> str:
    """The single event type an event datapoint fires."""
    if role:
        return ROLE_EVENT_TYPES.get(role, DEFAULT_EVENT_TYPE)
    return DEFAULT_EVENT_TYPE


def _as_code(value: Any) -> int | None:
    """Read a value_map key out of a device value, or None if it is not one.

    Booleans are excluded on purpose: True is an int in Python, but a boolean
    datapoint is not a status code. Numeric strings are accepted because that
    is what a restored state looks like coming back out of storage.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def maps_value(dp_def: DPDefinition, value: Any) -> bool:
    """Whether this value will be translated by the definition's value map."""
    return bool(dp_def.value_map) and _as_code(value) is not None


def apply_value_map(dp_def: DPDefinition, value: Any) -> Any:
    """Translate a status code into its label, if the definition has a map.

    An unmapped code is shown as such rather than hidden: a code the device
    reports and we do not know about is information, not noise.
    """
    if value is None or not dp_def.value_map:
        return value
    code = _as_code(value)
    if code is None:
        return value
    return dp_def.value_map.get(code, f"unknown ({code})")


def definitions_for_platform(
    profile: DeviceProfile | None, entity_type: str
) -> list[DPDefinition]:
    """Datapoints of a profile that belong to one platform, ordered by DP id.

    No profile means no entities. Creating a fixed set of entities for a device
    we have not looked at is what made this integration produce sensors wired
    to datapoints the device never sends.
    """
    if profile is None:
        return []
    return [
        dp_def
        for _, dp_def in sorted(profile.discovered_dps.items())
        if dp_def.entity_type == entity_type
    ]


def event_definitions(profile: DeviceProfile | None) -> list[DPDefinition]:
    """Datapoints that fire an event entity, ordered by DP id.

    Three things qualify: the explicit event entity type, the ``is_event`` flag,
    and holding an event role. The last one matters for profiles written before
    roles existed, where the flag was dropped -- without it a doorbell that works
    perfectly well would get no event entity at all.

    A qualifying datapoint that also has its own entity keeps it: the event
    entity carries the moment, the binary sensor carries the state that follows.
    """
    if profile is None:
        return []
    return [
        dp_def
        for dp_id, dp_def in sorted(profile.discovered_dps.items())
        if dp_def.entity_type == ENTITY_EVENT
        or dp_def.is_event
        or profile.role_of(dp_id) in EVENT_ROLES
    ]


def resolve_event_reset_timeout(
    options: dict[str, Any] | None, data: dict[str, Any] | None = None
) -> float:
    """How long an event sensor stays on, from the config entry.

    The option existed but was never read, so changing it did nothing at all.
    Out-of-range and unreadable values are clamped and logged rather than
    silently ignored.
    """
    raw = None
    for source in (options, data):
        if source and CONF_EVENT_RESET_TIMEOUT in source:
            raw = source[CONF_EVENT_RESET_TIMEOUT]
            break

    if raw is None:
        return float(DEFAULT_EVENT_RESET_TIMEOUT)

    try:
        value = float(raw)
    except (TypeError, ValueError):
        _LOGGER.warning(
            "Ignoring unreadable %s value %r; using %s seconds",
            CONF_EVENT_RESET_TIMEOUT,
            raw,
            DEFAULT_EVENT_RESET_TIMEOUT,
        )
        return float(DEFAULT_EVENT_RESET_TIMEOUT)

    clamped = min(MAX_EVENT_RESET_TIMEOUT, max(MIN_EVENT_RESET_TIMEOUT, value))
    if clamped != value:
        _LOGGER.warning(
            "%s of %s s is outside %s-%s s; using %s s",
            CONF_EVENT_RESET_TIMEOUT,
            value,
            MIN_EVENT_RESET_TIMEOUT,
            MAX_EVENT_RESET_TIMEOUT,
            clamped,
        )
    return float(clamped)


def resolve_stream_source(
    options: dict[str, Any] | None,
    data: dict[str, Any] | None,
    host: str | None,
) -> str | None:
    """The RTSP URL for the camera, or None when there is nothing to stream.

    A configured stream URL wins over the one built from host, port and path,
    so the stream can come from a restreamer while the hub keeps talking to the
    doorbell itself. The built URL escapes its credentials; an unescaped ``@``
    or ``/`` in a password produces a URL pointing at another host entirely.
    """
    options = options or {}
    data = data or {}

    override = (options.get(CONF_STREAM_URL_OVERRIDE) or "").strip()
    if override:
        return override

    password = options.get(CONF_ONVIF_PASSWORD, data.get(CONF_ONVIF_PASSWORD, "")) or ""
    if not password or not host:
        return None

    username = options.get(
        CONF_ONVIF_USERNAME, data.get(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME)
    )
    port = options.get(CONF_RTSP_PORT, data.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT))
    path = options.get(CONF_RTSP_PATH, data.get(CONF_RTSP_PATH, DEFAULT_RTSP_PATH))

    return build_rtsp_url(host, int(port), str(path), str(username), str(password))
