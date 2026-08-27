"""Camera platform for LSC Tuya Doorbell — RTSP stream and shared snapshots."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import CONF_STILL_IMAGE_URL_OVERRIDE, DOMAIN
from .entity_meta import resolve_stream_source
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the camera entity when there is anything to show."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]

    stream_source = resolve_stream_source(
        config_entry.options, config_entry.data, hub.host
    )
    still_url = (config_entry.options.get(CONF_STILL_IMAGE_URL_OVERRIDE) or "").strip()

    if not stream_source and not still_url:
        _LOGGER.debug(
            "No stream URL and no still image URL for %s — skipping camera entity",
            hub.device_id,
        )
        return

    async_add_entities([LscTuyaCamera(hub, config_entry)])


class LscTuyaCamera(Camera):
    """Camera entity providing the RTSP live stream and snapshots."""

    _attr_has_entity_name = True
    _attr_name = "Camera"
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, hub: DeviceHub, config_entry: ConfigEntry) -> None:
        super().__init__()
        self._hub = hub
        self._config_entry = config_entry
        self._attr_unique_id = f"{hub.device_id}_camera"

    @property
    def device_info(self):
        """Link this entity to the device."""
        return self._hub.device_info

    @property
    def available(self) -> bool:
        return self._hub.available

    @property
    def is_streaming(self) -> bool:
        return self._hub.available

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose what the snapshot subsystem is actually doing.

        Without this, a degraded mode (buffer that could not start, a still URL
        answering 500) is only visible in the log.
        """
        return {"snapshot_status": self._hub.snapshots.status}

    async def async_added_to_hass(self) -> None:
        """Follow the connection so availability is not stuck on a stale value."""
        await super().async_added_to_hass()
        self.async_on_remove(
            self._hub.on_connection_change(self._handle_connection_change)
        )

    @callback
    def _handle_connection_change(self, connected: bool) -> None:
        self.async_write_ha_state()

    async def stream_source(self) -> str | None:
        """Return the RTSP stream URL."""
        return resolve_stream_source(
            self._config_entry.options, self._config_entry.data, self._hub.host
        )

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the newest frame from the shared snapshot provider.

        The camera used to fetch a still URL and, when that failed, start its
        own ffmpeg per thumbnail refresh: 5.9 s for a single grab and 15.9 s
        when a second one followed shortly after, with no backoff between the
        failures. The provider keeps one warm source and one grab at a time.
        """
        return await self._hub.snapshots.async_grab()
