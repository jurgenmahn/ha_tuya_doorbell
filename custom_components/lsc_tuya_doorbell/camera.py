"""Camera platform for LSC Tuya Doorbell — RTSP stream with ffmpeg snapshot."""

from __future__ import annotations

import asyncio
import logging

import aiohttp
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_ONVIF_PASSWORD,
    CONF_ONVIF_USERNAME,
    CONF_RTSP_PATH,
    CONF_RTSP_PORT,
    CONF_STILL_IMAGE_URL_OVERRIDE,
    CONF_STREAM_URL_OVERRIDE,
    DEFAULT_ONVIF_USERNAME,
    DEFAULT_RTSP_PATH,
    DEFAULT_RTSP_PORT,
    DOMAIN,
)
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)

# Snapshots sit in front of notifications, so fail fast rather than hang.
CLIENT_TIMEOUT = aiohttp.ClientTimeout(total=10)


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
        """Return a single frame.

        Prefers a configured still image URL, which lets a restreamer hand
        over a ready-made JPEG. Without it the frame is pulled off the RTSP
        stream with ffmpeg, which costs a decode per snapshot and opens an
        extra session on a camera that may only allow a few.
        """
        still_url = (
            self._config_entry.options.get(CONF_STILL_IMAGE_URL_OVERRIDE) or ""
        ).strip()
        if still_url:
            try:
                session = async_get_clientsession(self.hass)
                async with session.get(still_url, timeout=CLIENT_TIMEOUT) as resp:
                    resp.raise_for_status()
                    return await resp.read()
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning(
                    "Still image URL %s failed (%s), falling back to RTSP",
                    still_url,
                    err,
                )

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
        """Construct the RTSP URL from config.

        A configured stream URL override wins over the URL built from
        host, port and path. That lets the stream come from a restreamer
        (go2rtc, mediamtx, ...) while the hub keeps talking to the
        doorbell directly on the local Tuya port, including its own IP
        rediscovery.
        """
        opts = self._config_entry.options
        data = self._config_entry.data

        override = (opts.get(CONF_STREAM_URL_OVERRIDE) or "").strip()
        if override:
            return override

        password = opts.get(CONF_ONVIF_PASSWORD, data.get(CONF_ONVIF_PASSWORD, ""))
        if not password:
            return None

        username = opts.get(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME)
        port = opts.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT)
        path = opts.get(CONF_RTSP_PATH, DEFAULT_RTSP_PATH)
        host = self._hub.host

        return f"rtsp://{username}:{password}@{host}:{port}{path}"
