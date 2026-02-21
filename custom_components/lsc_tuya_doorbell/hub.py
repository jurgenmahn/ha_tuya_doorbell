"""DeviceHub — central connection and state management for a single doorbell device."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo

from .const import (
    CONF_DEVICE_ID,
    CONF_DEVICE_NAME,
    CONF_HOST,
    CONF_LOCAL_KEY,
    CONF_PORT,
    CONF_PROTOCOL_VERSION,
    DEFAULT_EVENT_RESET_TIMEOUT,
    DEFAULT_PORT,
    DOMAIN,
    DP_DOORBELL_BUTTON,
    DP_MOTION_DETECTION,
    EVENT_BUTTON_PRESS,
    EVENT_CONNECTED,
    EVENT_DISCONNECTED,
    EVENT_DP_DISCOVERED,
    EVENT_IP_CHANGED,
    EVENT_MOTION_DETECT,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_MAX_FAILURES,
    RECONNECT_BACKOFF,
    RECONNECT_INITIAL_WAIT,
    RECONNECT_RETRY_COUNT,
    RECONNECT_RETRY_INTERVAL,
    mask_credential,
)
from .discovery.manager import DiscoveryManager
from .dp_discovery import DPDiscoveryEngine, DiscoveredDP
from .dp_registry import DPDefinition, DPRegistry, DeviceProfile
from .protocol.connection import TuyaConnection

_LOGGER = logging.getLogger(__name__)


class DeviceHub:
    """Manages the connection and state for a single Tuya doorbell device."""

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        discovery_manager: DiscoveryManager,
    ) -> None:
        self._hass = hass
        self._config_entry = config_entry
        self._discovery_manager = discovery_manager

        # Config
        self._device_id: str = config_entry.data[CONF_DEVICE_ID]
        self._local_key: str = config_entry.data[CONF_LOCAL_KEY]
        self._host: str = config_entry.data[CONF_HOST]
        self._port: int = config_entry.data.get(CONF_PORT, DEFAULT_PORT)
        self._version: str = config_entry.data.get(CONF_PROTOCOL_VERSION, "3.3")
        self._device_name: str = config_entry.data.get(CONF_DEVICE_NAME, self._device_id)

        # Connection
        self._connection = TuyaConnection(
            self._host, self._port, self._device_id, self._local_key, self._version
        )

        # DP Registry
        self._dp_registry = DPRegistry()
        self._profile: DeviceProfile | None = None

        # State
        self._dps_state: dict[str, Any] = {}
        self._available = False
        self._heartbeat_failures = 0

        # Entity callbacks: dp_id -> list of callbacks
        self._entity_callbacks: dict[int, list[Callable[[Any], None]]] = {}

        # Event counters
        self._event_counters: dict[int, int] = {}

        # Tasks
        self._heartbeat_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._unregister_disconnect: Callable | None = None
        self._unregister_status: Callable | None = None

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def device_name(self) -> str:
        return self._device_name

    @property
    def host(self) -> str:
        return self._host

    @property
    def available(self) -> bool:
        return self._available

    @property
    def profile(self) -> DeviceProfile | None:
        return self._profile

    @property
    def dp_registry(self) -> DPRegistry:
        return self._dp_registry

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            name=self._device_name,
            manufacturer="LSC Smart Connect (Tuya)",
            model="Video Doorbell",
            sw_version=self._version,
        )

    def get_dp_state(self, dp_id: int) -> Any:
        """Get the current state of a datapoint."""
        return self._dps_state.get(str(dp_id))

    def register_entity(self, dp_id: int, callback: Callable[[Any], None]) -> None:
        """Register an entity callback for a specific DP."""
        self._entity_callbacks.setdefault(dp_id, []).append(callback)

    def unregister_entity(self, dp_id: int, callback: Callable[[Any], None]) -> None:
        """Unregister an entity callback."""
        callbacks = self._entity_callbacks.get(dp_id, [])
        if callback in callbacks:
            callbacks.remove(callback)

    async def async_setup(self) -> bool:
        """Set up the device hub: connect, load profile, start heartbeat."""
        _LOGGER.info(
            "Setting up device %s at %s:%s (key: %s)",
            self._device_id, self._host, self._port,
            mask_credential(self._local_key),
        )

        # Load existing profile
        try:
            self._profile = await self._dp_registry.load_profile(
                self._hass, self._device_id
            )
        except Exception:
            _LOGGER.debug("Could not load DP profile", exc_info=True)

        # Register callbacks
        self._unregister_status = self._connection.on_status_update(
            self._handle_status_update
        )
        self._unregister_disconnect = self._connection.on_disconnect(
            self._handle_disconnect
        )

        # Connect
        try:
            await self._connection.connect()
            self._available = True
            self._heartbeat_failures = 0
            self._fire_event(EVENT_CONNECTED)

            # Start heartbeat
            self._heartbeat_task = asyncio.ensure_future(self._heartbeat_loop())

            # Query initial state
            try:
                dps = await self._connection.query_dps()
                if dps:
                    self._handle_status_update(dps)
            except Exception:
                _LOGGER.debug("Initial DP query failed", exc_info=True)

            return True

        except ConnectionError:
            _LOGGER.warning(
                "Could not connect to %s:%s, will retry",
                self._host, self._port,
            )
            self._available = False
            self._reconnect_task = asyncio.ensure_future(self._reconnect())
            return True  # Still return True so entities can be created

    async def async_teardown(self) -> None:
        """Tear down the hub: disconnect, stop all tasks."""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

        if self._unregister_status:
            self._unregister_status()
        if self._unregister_disconnect:
            self._unregister_disconnect()

        await self._connection.disconnect()
        self._available = False
        _LOGGER.debug("Hub teardown complete for %s", self._device_id)

    async def set_dp(self, dp_id: int, value: Any) -> None:
        """Set a datapoint value on the device."""
        if not self._available:
            _LOGGER.warning("Cannot set DP %s: device not available", dp_id)
            return

        dps = {str(dp_id): value}
        result = await self._connection.set_dps(dps)
        if result:
            self._handle_status_update(result)

    async def discover_dps(self) -> list[DiscoveredDP]:
        """Run a full DP discovery scan."""
        if not self._connection.is_connected:
            raise ConnectionError("Not connected")

        engine = DPDiscoveryEngine(self._connection)
        discovered = await engine.scan_all()

        # Update profile
        dp_defs = self._dp_registry.merge_discovered(discovered)
        self._profile = DeviceProfile(
            device_id=self._device_id,
            discovered_dps=dp_defs,
            protocol_version=self._version,
        )

        # Save profile
        try:
            await self._dp_registry.save_profile(self._hass, self._profile)
        except Exception:
            _LOGGER.debug("Could not save DP profile", exc_info=True)

        self._fire_event(EVENT_DP_DISCOVERED, {
            "dp_count": len(discovered),
            "dp_ids": [dp.dp_id for dp in discovered],
        })

        return discovered

    # --- Internal methods ---

    def _handle_status_update(self, dps: dict) -> None:
        """Process incoming DPS updates from the device."""
        for dp_str, raw_value in dps.items():
            dp_id = int(dp_str)
            value = self._normalize_value(dp_id, raw_value)
            self._dps_state[dp_str] = value

            # Check for event DPs
            if dp_id == DP_DOORBELL_BUTTON:
                self._handle_event(dp_id, value, EVENT_BUTTON_PRESS)
            elif dp_id == DP_MOTION_DETECTION:
                self._handle_event(dp_id, value, EVENT_MOTION_DETECT)

            # Notify entity callbacks
            for callback in self._entity_callbacks.get(dp_id, []):
                try:
                    callback(value)
                except Exception:
                    _LOGGER.debug("Entity callback error for DP %s", dp_id, exc_info=True)

    def _handle_event(self, dp_id: int, value: Any, event_type: str) -> None:
        """Handle a doorbell/motion event."""
        counter = self._event_counters.get(dp_id, 0) + 1
        self._event_counters[dp_id] = counter

        image_url = self._extract_image_url(value)
        slug = self._device_name_slug()

        self._fire_event(f"{event_type}_{slug}", {
            "device_id": self._device_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "image_url": image_url,
            "event_counter": counter,
            "dp_id": dp_id,
            "raw_value": str(value) if not isinstance(value, (str, int, float, bool)) else value,
        })

    def _handle_disconnect(self) -> None:
        """Handle connection loss."""
        self._available = False
        self._fire_event(EVENT_DISCONNECTED)
        _LOGGER.warning("Connection lost to %s (%s)", self._device_name, self._host)

        # Start reconnect
        if not self._reconnect_task or self._reconnect_task.done():
            self._reconnect_task = asyncio.ensure_future(self._reconnect())

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        try:
            while self._available:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if not self._available:
                    break

                ok = await self._connection.heartbeat()
                if ok:
                    self._heartbeat_failures = 0
                else:
                    self._heartbeat_failures += 1
                    _LOGGER.debug(
                        "Heartbeat failure %s/%s for %s",
                        self._heartbeat_failures, HEARTBEAT_MAX_FAILURES, self._device_id,
                    )
                    if self._heartbeat_failures >= HEARTBEAT_MAX_FAILURES:
                        _LOGGER.warning("Max heartbeat failures reached, disconnecting %s", self._device_id)
                        await self._connection.disconnect()
                        break
        except asyncio.CancelledError:
            return

    async def _reconnect(self) -> None:
        """Reconnect sequence with discovery fallback."""
        try:
            await asyncio.sleep(RECONNECT_INITIAL_WAIT)

            backoff_index = 0

            while True:
                # Step 1: Try known IP
                for attempt in range(RECONNECT_RETRY_COUNT):
                    _LOGGER.info(
                        "Reconnect attempt %s/%s to %s:%s",
                        attempt + 1, RECONNECT_RETRY_COUNT, self._host, self._port,
                    )
                    try:
                        await self._connection.disconnect()
                        self._connection.host = self._host
                        await self._connection.connect()
                        self._available = True
                        self._heartbeat_failures = 0
                        self._fire_event(EVENT_CONNECTED)
                        _LOGGER.info("Reconnected to %s at %s", self._device_id, self._host)

                        # Restart heartbeat
                        if self._heartbeat_task and not self._heartbeat_task.done():
                            self._heartbeat_task.cancel()
                        self._heartbeat_task = asyncio.ensure_future(self._heartbeat_loop())

                        # Refresh state
                        try:
                            dps = await self._connection.query_dps()
                            if dps:
                                self._handle_status_update(dps)
                        except Exception:
                            pass
                        return

                    except ConnectionError:
                        if attempt < RECONNECT_RETRY_COUNT - 1:
                            await asyncio.sleep(RECONNECT_RETRY_INTERVAL)

                # Step 2: Try discovery
                _LOGGER.info("Trying discovery for %s", self._device_id)
                new_ip = await self._discovery_manager.full_scan(
                    self._device_id, self._local_key, self._version
                )

                if new_ip and new_ip != self._host:
                    _LOGGER.info(
                        "Device %s found at new IP: %s (was %s)",
                        self._device_id, new_ip, self._host,
                    )
                    old_ip = self._host
                    self._host = new_ip
                    self._connection.host = new_ip

                    # Persist new IP
                    new_data = dict(self._config_entry.data)
                    new_data[CONF_HOST] = new_ip
                    self._hass.config_entries.async_update_entry(
                        self._config_entry, data=new_data
                    )

                    self._fire_event(f"{EVENT_IP_CHANGED}_{self._device_name_slug()}", {
                        "device_id": self._device_id,
                        "old_ip": old_ip,
                        "new_ip": new_ip,
                    })

                    # Try connecting on new IP
                    try:
                        await self._connection.disconnect()
                        await self._connection.connect()
                        self._available = True
                        self._heartbeat_failures = 0
                        self._fire_event(EVENT_CONNECTED)
                        if self._heartbeat_task and not self._heartbeat_task.done():
                            self._heartbeat_task.cancel()
                        self._heartbeat_task = asyncio.ensure_future(self._heartbeat_loop())
                        return
                    except ConnectionError:
                        pass

                elif new_ip:
                    # Same IP but discovery found it — try again
                    pass

                # Exponential backoff
                delay = RECONNECT_BACKOFF[min(backoff_index, len(RECONNECT_BACKOFF) - 1)]
                _LOGGER.info("Reconnect backoff: waiting %ss", delay)
                await asyncio.sleep(delay)
                backoff_index += 1

        except asyncio.CancelledError:
            return

    def _normalize_value(self, dp_id: int, value: Any) -> Any:
        """Normalize a DP value to a canonical Python type."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() == "true":
                return True
            if value.lower() == "false":
                return False
            try:
                return int(value)
            except ValueError:
                pass
            try:
                return float(value)
            except ValueError:
                pass
        return value

    def _extract_image_url(self, raw_value: Any) -> str | None:
        """Extract image URL from a Tuya event payload using chain of decoders."""
        decoders = [
            self._decode_direct_url,
            self._decode_json_with_url,
            self._decode_base64_json,
            self._decode_bucket_path,
        ]
        for decoder in decoders:
            try:
                result = decoder(raw_value)
                if result:
                    return result
            except Exception:
                continue
        return None

    @staticmethod
    def _decode_direct_url(value: Any) -> str | None:
        """Check if value is directly a URL string."""
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            return value
        return None

    @staticmethod
    def _decode_json_with_url(value: Any) -> str | None:
        """Extract URL from a JSON payload."""
        data = value if isinstance(value, dict) else None
        if isinstance(value, str):
            try:
                data = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                return None

        if not isinstance(data, dict):
            return None

        # Try common key paths
        for key in ("imgUrl", "image_url", "url", "pic"):
            if key in data:
                return data[key]

        # Nested in "data" dict
        inner = data.get("data", {})
        if isinstance(inner, dict):
            for key in ("imgUrl", "image_url", "url", "pic"):
                if key in inner:
                    return inner[key]

        return None

    @staticmethod
    def _decode_base64_json(value: Any) -> str | None:
        """Decode base64-encoded JSON and extract URL."""
        if not isinstance(value, str) or len(value) < 20:
            return None
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            data = json.loads(decoded)
            if isinstance(data, dict):
                for key in ("imgUrl", "image_url", "url", "pic"):
                    if key in data:
                        return data[key]
        except Exception:
            pass
        return None

    @staticmethod
    def _decode_bucket_path(value: Any) -> str | None:
        """Construct URL from bucket + path format."""
        data = value if isinstance(value, dict) else None
        if isinstance(value, str):
            try:
                data = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                return None

        if not isinstance(data, dict):
            return None

        bucket = data.get("bucket", "")
        path = data.get("path", "") or data.get("key", "")
        if bucket and path:
            return f"https://{bucket}.s3.amazonaws.com/{path}"

        return None

    def _fire_event(self, event_type: str, data: dict | None = None) -> None:
        """Fire a Home Assistant event."""
        event_data = {"device_id": self._device_id}
        if data:
            event_data.update(data)
        self._hass.bus.async_fire(event_type, event_data)

    def _device_name_slug(self) -> str:
        """Return a slugified device name for event naming."""
        import re
        slug = self._device_name.lower()
        slug = re.sub(r"[^a-z0-9]+", "_", slug)
        return slug.strip("_")
