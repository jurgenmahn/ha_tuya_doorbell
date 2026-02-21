"""Base entity class for LSC Tuya Doorbell entities."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .dp_registry import DPDefinition

_LOGGER = logging.getLogger(__name__)

# Manual update protection: ignore echo-backs for this duration
MANUAL_UPDATE_TIMEOUT = 3.0


class LscTuyaEntity(RestoreEntity):
    """Base entity for LSC Tuya Doorbell datapoints."""

    _attr_has_entity_name = True

    def __init__(self, hub: Any, dp_definition: DPDefinition) -> None:
        """Initialize the entity."""
        from .hub import DeviceHub

        self._hub: DeviceHub = hub
        self._dp_def = dp_definition
        self._dp_id = dp_definition.dp_id
        self._attr_name = dp_definition.name
        self._attr_unique_id = f"{hub.device_id}_{dp_definition.dp_id}"
        self._state_value: Any = None
        self._is_manual_update = False
        self._manual_update_handle: asyncio.TimerHandle | None = None

    @property
    def device_info(self):
        """Return device info to link this entity to the device."""
        return self._hub.device_info

    @property
    def available(self) -> bool:
        """Return True if the device is available."""
        return self._hub.available

    async def async_added_to_hass(self) -> None:
        """Called when entity is added to HA."""
        # Register callback with hub
        self._hub.register_entity(self._dp_id, self._handle_dp_update)

        # Restore previous state
        last_state = await self.async_get_last_state()
        if last_state is not None:
            self._restore_state(last_state)

        # Get current value from hub
        current = self._hub.get_dp_state(self._dp_id)
        if current is not None:
            self._state_value = current

    async def async_will_remove_from_hass(self) -> None:
        """Called when entity is being removed."""
        self._hub.unregister_entity(self._dp_id, self._handle_dp_update)
        if self._manual_update_handle:
            self._manual_update_handle.cancel()
            self._manual_update_handle = None

    def _handle_dp_update(self, value: Any) -> None:
        """Handle a DP value update from the hub."""
        if self._is_manual_update:
            _LOGGER.debug(
                "Ignoring echo-back for DP %s (manual update in progress)", self._dp_id
            )
            return

        self._state_value = value
        self.async_write_ha_state()

    def _set_manual_update(self) -> None:
        """Start manual update protection to prevent echo-back overwrites."""
        self._is_manual_update = True
        if self._manual_update_handle:
            self._manual_update_handle.cancel()

        loop = asyncio.get_event_loop()
        self._manual_update_handle = loop.call_later(
            MANUAL_UPDATE_TIMEOUT,
            self._clear_manual_update,
        )

    def _clear_manual_update(self) -> None:
        """Clear manual update protection flag."""
        self._is_manual_update = False
        self._manual_update_handle = None

    def _restore_state(self, last_state: Any) -> None:
        """Restore entity state — override in subclasses for specific behavior."""
        pass
