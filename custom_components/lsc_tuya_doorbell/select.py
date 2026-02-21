"""Select platform for LSC Tuya Doorbell."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, ENTITY_SELECT
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up selects from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    entities = []

    if hub.profile:
        for dp_id, dp_def in hub.profile.discovered_dps.items():
            if dp_def.entity_type == ENTITY_SELECT:
                entities.append(LscTuyaSelect(hub, dp_def))

    _LOGGER.debug("Select setup: creating %d entities: %s", len(entities), [e._dp_id for e in entities])
    async_add_entities(entities)


class LscTuyaSelect(LscTuyaEntity, SelectEntity):
    """Select entity for enum Tuya datapoints."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, hub: DeviceHub, dp_definition: DPDefinition) -> None:
        super().__init__(hub, dp_definition)

        # Build option mappings: tuya_value -> human_label and reverse
        self._tuya_to_label: dict[str, str] = {}
        self._label_to_tuya: dict[str, str] = {}

        if dp_definition.options:
            for tuya_val, label in dp_definition.options.items():
                self._tuya_to_label[str(tuya_val)] = label
                self._label_to_tuya[label] = str(tuya_val)
        elif dp_definition.enum_values:
            for val in dp_definition.enum_values:
                self._tuya_to_label[val] = val
                self._label_to_tuya[val] = val

    @property
    def options(self) -> list[str]:
        """Return the list of available options."""
        return list(self._label_to_tuya.keys()) or ["unknown"]

    @property
    def current_option(self) -> str | None:
        """Return the currently selected option."""
        if self._state_value is None:
            return None
        tuya_val = str(self._state_value)
        return self._tuya_to_label.get(tuya_val, tuya_val)

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        tuya_val = self._label_to_tuya.get(option, option)
        _LOGGER.debug("Select DP %d: selecting '%s' (tuya_val=%s)", self._dp_id, option, tuya_val)

        self._set_manual_update()
        self._state_value = tuya_val
        self.async_write_ha_state()
        await self._hub.set_dp(self._dp_id, tuya_val)

    def _restore_state(self, last_state: Any) -> None:
        """Restore previous select state."""
        if last_state.state not in (None, "unknown", "unavailable"):
            # Convert label back to tuya value
            tuya_val = self._label_to_tuya.get(last_state.state, last_state.state)
            self._state_value = tuya_val
            _LOGGER.debug("Select DP %d: restored state=%s (tuya_val=%s)", self._dp_id, last_state.state, tuya_val)
