"""Camera platform for LSC Tuya Doorbell — RTSP stream with ffmpeg snapshot."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_ONVIF_PASSWORD,
    CONF_ONVIF_USERNAME,
    CONF_RTSP_PATH,
    CONF_RTSP_PORT,
    DEFAULT_ONVIF_USERNAME,
    DEFAULT_RTSP_PATH,
    DEFAULT_RTSP_PORT,
    DOMAIN,
)
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the camera entity if ONVIF password is configured."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]

    # Check for ONVIF password in options first, then entry data
    password = config_entry.options.get(
        CONF_ONVIF_PASSWORD,
        config_entry.data.get(CONF_ONVIF_PASSWORD, ""),
    )

    if not password:
        _LOGGER.debug("No ONVIF password configured — skipping camera entity")
        return

    async_add_entities([LscTuyaCamera(hub, config_entry)])


class LscTuyaCamera(Camera):
    """Camera entity providing RTSP live stream and ffmpeg snapshots."""

    _attr_has_entity_name = True

    def __init__(self, hub: DeviceHub, config_entry: ConfigEntry) -> None:
        super().__init__()
        self._hub = hub
        self._config_entry = config_entry
        self._attr_name = "Camera"
        self._attr_unique_id = f"{hub.device_id}_camera"
        self._attr_supported_features = CameraEntityFeature.STREAM

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

    async def stream_source(self) -> str | None:
        """Return the RTSP stream URL."""
        return self._build_rtsp_url()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Grab a single frame from the RTSP stream using ffmpeg."""
        rtsp_url = self._build_rtsp_url()
        if not rtsp_url:
            return None

        try:
            process = await asyncio.create_subprocess_exec(
                "ffmpeg",
                "-rtsp_transport", "tcp",
                "-i", rtsp_url,
                "-vframes", "1",
                "-f", "image2",
                "pipe:1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=15.0
            )
            if process.returncode == 0 and stdout:
                return stdout
            _LOGGER.debug(
                "ffmpeg snapshot failed (rc=%s): %s",
                process.returncode,
                stderr.decode(errors="replace")[:200] if stderr else "no output",
            )
        except asyncio.TimeoutError:
            _LOGGER.warning("ffmpeg snapshot timed out for %s", self._hub.device_id)
        except FileNotFoundError:
            _LOGGER.error("ffmpeg not found — install ffmpeg for camera snapshots")
        except Exception:
            _LOGGER.debug("Camera snapshot error", exc_info=True)

        return None

    def _build_rtsp_url(self) -> str | None:
        """Construct the RTSP URL from config."""
        opts = self._config_entry.options
        data = self._config_entry.data

        password = opts.get(CONF_ONVIF_PASSWORD, data.get(CONF_ONVIF_PASSWORD, ""))
        if not password:
            return None

        username = opts.get(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME)
        port = opts.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT)
        path = opts.get(CONF_RTSP_PATH, DEFAULT_RTSP_PATH)
        host = self._hub.host

        return f"rtsp://{username}:{password}@{host}:{port}{path}"
