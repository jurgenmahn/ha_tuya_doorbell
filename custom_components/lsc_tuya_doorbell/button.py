"""Button platform: take a test snapshot without ringing anything.

Pressing it runs the same grab-and-store path a doorbell event would, so the
snapshot configuration can be validated straight from Home Assistant -- the
result appears in the snapshot image entity -- without pressing the physical
button or tripping any automation.
"""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the test-snapshot button."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([LscTuyaTestSnapshotButton(hub)])


class LscTuyaTestSnapshotButton(ButtonEntity):
    """Captures a snapshot on demand to test the snapshot settings."""

    _attr_has_entity_name = True
    _attr_name = "Test snapshot"
    _attr_icon = "mdi:camera-iris"

    def __init__(self, hub: DeviceHub) -> None:
        self._hub = hub
        self._attr_unique_id = f"{hub.device_id}_test_snapshot"

    @property
    def device_info(self):
        """Link this entity to the device."""
        return self._hub.device_info

    @property
    def available(self) -> bool:
        return self._hub.available

    async def async_press(self) -> None:
        """Take a snapshot now; the result shows up in the snapshot image entity."""
        ok = await self._hub.async_capture_test_snapshot()
        if not ok:
            _LOGGER.warning(
                "Test snapshot did not produce an image; check the snapshot mode "
                "and stream/still settings"
            )
