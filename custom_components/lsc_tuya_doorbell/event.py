"""Event platform for LSC Tuya Doorbell.

A press is a moment, not a state. The binary sensor models it as a state that
has to be switched back off by a timer, which loses a second press inside the
reset window and shows "off" as if nothing happened. An event entity records
the moment itself, keeps its timestamp, and is what Home Assistant's own
doorbell automations and dashboards trigger on.

The binary sensor stays: it is what existing automations and history are
attached to, and removing it would break them silently.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .entity_meta import (
    ROLE_EVENT_DEVICE_CLASS,
    device_class_for,
    event_definitions,
    event_type_for,
)
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up event entities from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    definitions = event_definitions(hub.profile)
    entities = [LscTuyaEvent(hub, dp_def) for dp_def in definitions]

    _LOGGER.debug(
        "Event setup: creating %d entities: %s",
        len(entities),
        [dp_def.dp_id for dp_def in definitions],
    )
    async_add_entities(entities)


def _event_device_class(
    dp_def: DPDefinition, role: str | None
) -> EventDeviceClass | None:
    """Device class for an event datapoint, or None when nothing is known."""
    name = device_class_for(dp_def, role, ROLE_EVENT_DEVICE_CLASS)
    if not name:
        return None
    try:
        return EventDeviceClass(name)
    except ValueError:
        _LOGGER.warning(
            "DP %d declares device class %r, which Home Assistant does not know "
            "for an event; showing it without one",
            dp_def.dp_id,
            name,
        )
        return None


class LscTuyaEvent(LscTuyaEntity, EventEntity):
    """Event entity for a datapoint that reports a moment."""

    def __init__(self, hub: DeviceHub, dp_definition: DPDefinition) -> None:
        super().__init__(hub, dp_definition)
        # A separate id from the binary sensor on the same datapoint. Entity ids
        # are unique per domain, so this is not required — it is here so the two
        # never get confused for one another in storage or in a bug report.
        self._attr_unique_id = f"{hub.device_id}_{dp_definition.dp_id}_event"
        self._event_type = event_type_for(self._role)
        self._attr_event_types = [self._event_type]
        self._attr_device_class = _event_device_class(dp_definition, self._role)

    def _handle_dp_update(self, value: Any) -> None:
        """Record the moment the datapoint reported."""
        _LOGGER.debug(
            "Event DP %d: firing %s (value=%r)", self._dp_id, self._event_type, value
        )
        self._trigger_event(
            self._event_type,
            {
                "dp_id": self._dp_id,
                "role": self._role,
                "event_counter": self._hub.event_count(self._dp_id),
                "snapshot_url": self._hub.last_snapshot_url,
            },
        )
        self.async_write_ha_state()
