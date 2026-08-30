"""Image platform: the last doorbell snapshot, shown as a picture in Home Assistant.

The snapshot used to exist only as a file on disk and a URL buried in an
attribute; nothing rendered it. This entity is where the picture of who rang
actually shows up -- on a dashboard, in a notification, in the logbook.
"""

from __future__ import annotations

import logging
from pathlib import Path

from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the snapshot image entity."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([LscTuyaSnapshotImage(hass, hub)])


class LscTuyaSnapshotImage(ImageEntity):
    """Shows the most recent snapshot the integration captured."""

    _attr_has_entity_name = True
    _attr_name = "Snapshot"

    def __init__(self, hass: HomeAssistant, hub: DeviceHub) -> None:
        super().__init__(hass)
        self._hub = hub
        self._attr_unique_id = f"{hub.device_id}_snapshot"
        # A reload should not blank a picture the hub already has.
        if hub.last_snapshot_path:
            self._attr_image_last_updated = dt_util.utcnow()

    @property
    def device_info(self):
        """Link this entity to the device."""
        return self._hub.device_info

    async def async_added_to_hass(self) -> None:
        """Follow snapshot updates so the picture refreshes when one arrives."""
        await super().async_added_to_hass()
        self.async_on_remove(self._hub.on_snapshot_change(self._handle_snapshot))

    @callback
    def _handle_snapshot(self, url: str | None) -> None:
        """A new snapshot was written; mark the image as freshly updated.

        Home Assistant re-fetches through ``async_image`` when this timestamp
        moves, so this is all it takes to push the new picture to the frontend.
        """
        self._attr_image_last_updated = dt_util.utcnow()
        self.async_write_ha_state()

    async def async_image(self) -> bytes | None:
        """Return the bytes of the most recent snapshot, or None if there is none."""
        path = self._hub.last_snapshot_path
        if not path:
            return None
        try:
            return await self.hass.async_add_executor_job(Path(path).read_bytes)
        except OSError as err:
            _LOGGER.warning("Could not read snapshot %s: %s", path, err)
            return None
