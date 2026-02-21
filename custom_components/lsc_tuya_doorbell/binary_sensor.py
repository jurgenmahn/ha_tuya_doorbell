"""Binary sensor platform for LSC Tuya Doorbell."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import (
    DEFAULT_EVENT_RESET_TIMEOUT,
    DOMAIN,
    DP_DOORBELL_BUTTON,
    DP_MOTION_DETECTION,
    ENTITY_BINARY_SENSOR,
)
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensors from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    entities = []

    if hub.profile:
        for dp_id, dp_def in hub.profile.discovered_dps.items():
            if dp_def.entity_type == ENTITY_BINARY_SENSOR:
                entities.append(LscTuyaBinarySensor(hub, dp_def))
    else:
        # Fallback: always create doorbell and motion sensors
        from .dp_registry import DPRegistry
        registry = DPRegistry()
        for dp_id in [DP_DOORBELL_BUTTON, DP_MOTION_DETECTION]:
            dp_def = registry.get_known_dp(dp_id)
            if dp_def:
                entities.append(LscTuyaBinarySensor(hub, dp_def))

    async_add_entities(entities)


class LscTuyaBinarySensor(LscTuyaEntity, BinarySensorEntity):
    """Binary sensor for doorbell press and motion detection events."""

    def __init__(self, hub: DeviceHub, dp_definition: DPDefinition) -> None:
        super().__init__(hub, dp_definition)
        self._is_on = False
        self._reset_handle: Any = None
        self._event_counter = 0
        self._last_image_url: str | None = None

        # Set device class based on DP
        if dp_definition.dp_id == DP_DOORBELL_BUTTON:
            self._attr_device_class = BinarySensorDeviceClass.OCCUPANCY
            self._attr_icon = "mdi:doorbell-video"
        elif dp_definition.dp_id == DP_MOTION_DETECTION:
            self._attr_device_class = BinarySensorDeviceClass.MOTION
        else:
            self._attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    @property
    def is_on(self) -> bool:
        """Return True if the binary sensor is on."""
        return self._is_on

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = {
            "event_counter": self._event_counter,
            "dp_id": self._dp_id,
        }
        if self._last_image_url:
            attrs["last_image_url"] = self._last_image_url
        return attrs

    def _handle_dp_update(self, value: Any) -> None:
        """Handle event DP update — turn on and schedule auto-reset."""
        self._is_on = True
        self._event_counter += 1

        # Extract image URL if available
        image_url = self._hub._extract_image_url(value)
        if image_url:
            self._last_image_url = image_url

        # Cancel existing reset timer
        if self._reset_handle:
            self._reset_handle()
            self._reset_handle = None

        # Schedule auto-reset
        self._reset_handle = async_call_later(
            self._hub._hass,
            DEFAULT_EVENT_RESET_TIMEOUT,
            self._auto_reset,
        )

        self.async_write_ha_state()

    def _auto_reset(self, _now: Any = None) -> None:
        """Reset binary sensor to off after timeout."""
        self._is_on = False
        self._reset_handle = None
        self.async_write_ha_state()

    def _restore_state(self, last_state: Any) -> None:
        """Restore state — binary sensors always start as off."""
        self._is_on = False
        if last_state.attributes:
            self._event_counter = last_state.attributes.get("event_counter", 0)
            self._last_image_url = last_state.attributes.get("last_image_url")
