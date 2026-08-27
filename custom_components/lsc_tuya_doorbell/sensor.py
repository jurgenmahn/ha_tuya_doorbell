"""Sensor platform for LSC Tuya Doorbell."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN, ENTITY_SENSOR
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .entity_meta import (
    apply_value_map,
    definitions_for_platform,
    device_class_for,
    maps_value,
)
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up sensors from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    definitions = definitions_for_platform(hub.profile, ENTITY_SENSOR)
    entities = [LscTuyaSensor(hub, dp_def) for dp_def in definitions]

    _LOGGER.debug(
        "Sensor setup: creating %d entities: %s",
        len(entities),
        [dp_def.dp_id for dp_def in definitions],
    )
    async_add_entities(entities)


def _sensor_device_class(dp_def: DPDefinition) -> SensorDeviceClass | None:
    """Device class straight from the definition, dropped if unknown."""
    name = device_class_for(dp_def)
    if not name:
        return None
    try:
        return SensorDeviceClass(name)
    except ValueError:
        _LOGGER.warning(
            "DP %d declares device class %r, which Home Assistant does not know "
            "for a sensor; showing it without one",
            dp_def.dp_id,
            name,
        )
        return None


class LscTuyaSensor(LscTuyaEntity, SensorEntity):
    """Sensor for Tuya device status values."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, hub: DeviceHub, dp_definition: DPDefinition) -> None:
        super().__init__(hub, dp_definition)
        self._attr_device_class = _sensor_device_class(dp_definition)

    @property
    def native_value(self) -> Any:
        """Return the sensor value, translated through the definition's map.

        Which datapoints are status codes used to be decided by looking for
        "sd card" in the entity name -- a name the user is free to change, so
        renaming it to anything else quietly turned the translation off.
        """
        return apply_value_map(self._dp_def, self._state_value)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs: dict[str, Any] = {"dp_id": self._dp_id}
        if maps_value(self._dp_def, self._state_value):
            attrs["raw_value"] = self._state_value
        return attrs

    def _restore_state(self, last_state: Any) -> None:
        """Restore the raw value, not the label it was shown as.

        The state Home Assistant kept is the mapped string, so restoring that
        made the raw value disappear and the next map lookup miss. The raw
        value is in the attributes precisely so this round trip works.
        """
        attributes = last_state.attributes or {}
        if "raw_value" in attributes:
            self._state_value = attributes["raw_value"]
        elif last_state.state not in (None, "unknown", "unavailable"):
            self._state_value = last_state.state
        else:
            return
        _LOGGER.debug("Sensor DP %d: restored value=%r", self._dp_id, self._state_value)
