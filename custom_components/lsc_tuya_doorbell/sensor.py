"""Sensor platform for LSC Tuya Doorbell."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, ENTITY_SENSOR, SD_STATUS_MAP
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensors from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    entities = []

    if hub.profile:
        for dp_id, dp_def in hub.profile.discovered_dps.items():
            if dp_def.entity_type == ENTITY_SENSOR:
                entities.append(LscTuyaSensor(hub, dp_def))

    _LOGGER.debug("Sensor setup: creating %d entities: %s", len(entities), [e._dp_id for e in entities])
    async_add_entities(entities)


class LscTuyaSensor(LscTuyaEntity, SensorEntity):
    """Sensor for Tuya device status values."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, hub: DeviceHub, dp_definition: DPDefinition) -> None:
        super().__init__(hub, dp_definition)
        self._is_sd_status = "sd card" in dp_definition.name.lower()

    @property
    def native_value(self) -> Any:
        """Return the sensor value."""
        value = self._state_value
        if value is None:
            return None

        # Map SD card status codes to readable strings
        if self._is_sd_status and isinstance(value, int):
            return SD_STATUS_MAP.get(value, f"unknown ({value})")

        return value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = {"dp_id": self._dp_id}
        if self._is_sd_status and isinstance(self._state_value, int):
            attrs["raw_value"] = self._state_value
        return attrs

    def _restore_state(self, last_state: Any) -> None:
        """Restore previous sensor state."""
        if last_state.state not in (None, "unknown", "unavailable"):
            self._state_value = last_state.state
            _LOGGER.debug("Sensor DP %d: restored value=%s", self._dp_id, self._state_value)
