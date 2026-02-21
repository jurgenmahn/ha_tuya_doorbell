"""Number platform for LSC Tuya Doorbell."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, ENTITY_NUMBER
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up numbers from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    entities = []

    if hub.profile:
        for dp_id, dp_def in hub.profile.discovered_dps.items():
            if dp_def.entity_type == ENTITY_NUMBER:
                entities.append(LscTuyaNumber(hub, dp_def))

    async_add_entities(entities)


class LscTuyaNumber(LscTuyaEntity, NumberEntity):
    """Number entity for numeric Tuya datapoints."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, hub: DeviceHub, dp_definition: DPDefinition) -> None:
        super().__init__(hub, dp_definition)
        self._attr_native_min_value = float(dp_definition.min_value or 0)
        self._attr_native_max_value = float(dp_definition.max_value or 100)
        self._attr_native_step = 1.0

    @property
    def native_value(self) -> float | None:
        """Return the current value."""
        if self._state_value is None:
            return None
        try:
            return float(self._state_value)
        except (ValueError, TypeError):
            return None

    async def async_set_native_value(self, value: float) -> None:
        """Set a new value."""
        int_value = int(value)
        self._set_manual_update()
        self._state_value = int_value
        self.async_write_ha_state()
        await self._hub.set_dp(self._dp_id, int_value)

    def _restore_state(self, last_state: Any) -> None:
        """Restore previous number state."""
        if last_state.state not in (None, "unknown", "unavailable"):
            try:
                self._state_value = int(float(last_state.state))
            except (ValueError, TypeError):
                pass
