"""Switch platform for LSC Tuya Doorbell."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN, ENTITY_SWITCH
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .entity_meta import definitions_for_platform
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up switches from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    definitions = definitions_for_platform(hub.profile, ENTITY_SWITCH)
    entities = [LscTuyaSwitch(hub, dp_def) for dp_def in definitions]

    _LOGGER.debug(
        "Switch setup: creating %d entities: %s",
        len(entities),
        [dp_def.dp_id for dp_def in definitions],
    )
    async_add_entities(entities)


class LscTuyaSwitch(LscTuyaEntity, SwitchEntity):
    """Switch entity for boolean Tuya datapoints."""

    _attr_entity_category = EntityCategory.CONFIG

    @property
    def is_on(self) -> bool | None:
        """Return True if the switch is on."""
        if self._state_value is None:
            return None
        return bool(self._state_value)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on."""
        _LOGGER.debug("Switch DP %d: turning ON", self._dp_id)
        self._set_manual_update()
        self._state_value = True
        self.async_write_ha_state()
        await self._hub.set_dp(self._dp_id, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off."""
        _LOGGER.debug("Switch DP %d: turning OFF", self._dp_id)
        self._set_manual_update()
        self._state_value = False
        self.async_write_ha_state()
        await self._hub.set_dp(self._dp_id, False)

    def _restore_state(self, last_state: Any) -> None:
        """Restore previous switch state."""
        if last_state.state == "on":
            self._state_value = True
        elif last_state.state == "off":
            self._state_value = False
        _LOGGER.debug("Switch DP %d: restored state=%s", self._dp_id, self._state_value)
