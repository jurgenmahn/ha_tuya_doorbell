"""Base entity class for LSC Tuya Doorbell entities."""

from __future__ import annotations

import logging
from typing import Any, Callable

from homeassistant.core import callback
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.restore_state import RestoreEntity

from .dp_registry import DPDefinition
from .entity_meta import icon_for

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
        self._role = hub.role_of(dp_definition.dp_id)
        self._attr_name = dp_definition.name
        # Stable across restarts and renames. Changing this format costs every
        # user their history and every automation its target.
        self._attr_unique_id = f"{hub.device_id}_{dp_definition.dp_id}"
        self._attr_icon = icon_for(dp_definition, self._role)
        self._state_value: Any = None
        self._is_manual_update = False
        self._cancel_manual_update: Callable[[], None] | None = None

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
        _LOGGER.debug("Entity added: %s (DP %d)", self._attr_unique_id, self._dp_id)
        self.async_on_remove(
            self._hub.on_dp_change(self._dp_id, self._handle_dp_update)
        )

        # Without this the entity keeps showing its last value after the device
        # drops off, because the only thing that ever refreshed availability was
        # an incoming datapoint update -- and an offline device sends none.
        self.async_on_remove(
            self._hub.on_connection_change(self._handle_connection_change)
        )

        # Restore previous state
        last_state = await self.async_get_last_state()
        if last_state is not None:
            _LOGGER.debug("Entity %s: restoring previous state", self._attr_unique_id)
            self._restore_state(last_state)

        # Get current value from hub
        current = self._hub.get_dp_state(self._dp_id)
        if current is not None:
            _LOGGER.debug("Entity %s: current DP state = %r", self._attr_unique_id, current)
            self._state_value = current

    async def async_will_remove_from_hass(self) -> None:
        """Called when entity is being removed."""
        _LOGGER.debug("Entity removed: %s (DP %d)", self._attr_unique_id, self._dp_id)
        self._clear_manual_update()

    @callback
    def _handle_connection_change(self, connected: bool) -> None:
        """Redraw when the device connects or drops."""
        _LOGGER.debug(
            "Entity %s: connection now %s",
            self._attr_unique_id,
            "up" if connected else "down",
        )
        self.async_write_ha_state()

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
        self._clear_manual_update()
        self._is_manual_update = True
        self._cancel_manual_update = async_call_later(
            self.hass,
            MANUAL_UPDATE_TIMEOUT,
            self._expire_manual_update,
        )

    @callback
    def _expire_manual_update(self, _now: Any = None) -> None:
        """Manual update protection ran its course."""
        self._is_manual_update = False
        self._cancel_manual_update = None

    def _clear_manual_update(self) -> None:
        """Drop manual update protection and any pending timer."""
        if self._cancel_manual_update is not None:
            self._cancel_manual_update()
            self._cancel_manual_update = None
        self._is_manual_update = False

    def _restore_state(self, last_state: Any) -> None:
        """Restore entity state — override in subclasses for specific behavior."""
        pass
