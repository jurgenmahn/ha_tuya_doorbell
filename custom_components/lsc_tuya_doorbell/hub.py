"""DeviceHub — central connection and state management for a single doorbell device."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
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
    CONF_ONVIF_PASSWORD,
    CONF_ONVIF_USERNAME,
    CONF_PORT,
    CONF_PROTOCOL_VERSION,
    CONF_RTSP_PATH,
    CONF_RTSP_PORT,
    CONF_SNAPSHOT_PATH,
    DEFAULT_EVENT_RESET_TIMEOUT,
    DEFAULT_ONVIF_USERNAME,
    DEFAULT_PORT,
    DEFAULT_RTSP_PATH,
    DEFAULT_RTSP_PORT,
    DEFAULT_SNAPSHOT_PATH,
    DOMAIN,
    DP_DOORBELL_BUTTON,
    DP_MOTION_DETECTION,
    DP_SCAN_MAX_RETRIES,
    DP_SCAN_RECONNECT_WAIT,
    DP_SCAN_START,
    DP_SCAN_TIMEOUT,
    EVENT_BUTTON_PRESS,
    EVENT_CONNECTED,
    EVENT_DISCONNECTED,
    EVENT_DP_DISCOVERED,
    EVENT_IP_CHANGED,
    EVENT_MOTION_DETECT,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_MAX_FAILURES,
    MAX_SNAPSHOTS,
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

        # Snapshot state
        self._last_snapshot_path: str | None = None
        self._last_snapshot_url: str | None = None

        # DP scan state (persists across options dialog open/close)
        self._scan_task: asyncio.Task | None = None
        self._scan_results: list[DiscoveredDP] | None = None
        self._scan_error: str | None = None
        self._scan_progress: dict[str, str] = {
            "status": "Starting scan...",
            "found_count": "0",
            "found_dps": "none yet",
        }

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

    @property
    def rtsp_url(self) -> str | None:
        """Construct full RTSP URL from config entry data/options."""
        opts = self._config_entry.options
        data = self._config_entry.data
        password = opts.get(CONF_ONVIF_PASSWORD, data.get(CONF_ONVIF_PASSWORD, ""))
        if not password:
            return None
        username = opts.get(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME)
        port = opts.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT)
        path = opts.get(CONF_RTSP_PATH, DEFAULT_RTSP_PATH)
        return f"rtsp://{username}:{password}@{self._host}:{port}{path}"

    @property
    def last_snapshot_path(self) -> str | None:
        return self._last_snapshot_path

    @property
    def last_snapshot_url(self) -> str | None:
        return self._last_snapshot_url

    @property
    def scan_task(self) -> asyncio.Task | None:
        return self._scan_task

    @property
    def scan_results(self) -> list[DiscoveredDP] | None:
        return self._scan_results

    @property
    def scan_error(self) -> str | None:
        return self._scan_error

    @property
    def scan_progress(self) -> dict[str, str]:
        return self._scan_progress

    @property
    def scan_running(self) -> bool:
        return self._scan_task is not None and not self._scan_task.done()

    def reset_scan_state(self) -> None:
        """Reset scan state for a fresh scan."""
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
        self._scan_task = None
        self._scan_results = None
        self._scan_error = None
        self._scan_progress = {
            "status": "Starting scan...",
            "found_count": "0",
            "found_dps": "none yet",
        }

    def get_dp_state(self, dp_id: int) -> Any:
        """Get the current state of a datapoint."""
        return self._dps_state.get(str(dp_id))

    def register_entity(self, dp_id: int, callback: Callable[[Any], None]) -> None:
        """Register an entity callback for a specific DP."""
        self._entity_callbacks.setdefault(dp_id, []).append(callback)
        _LOGGER.debug("Entity registered for DP %d (total callbacks: %d)", dp_id, len(self._entity_callbacks[dp_id]))

    def unregister_entity(self, dp_id: int, callback: Callable[[Any], None]) -> None:
        """Unregister an entity callback."""
        callbacks = self._entity_callbacks.get(dp_id, [])
        if callback in callbacks:
            callbacks.remove(callback)
            _LOGGER.debug("Entity unregistered for DP %d (remaining: %d)", dp_id, len(callbacks))

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
            _LOGGER.debug("Connected to %s:%s, firing connected event", self._host, self._port)
            self._fire_event(EVENT_CONNECTED)

            # Start heartbeat
            self._heartbeat_task = asyncio.ensure_future(self._heartbeat_loop())
            _LOGGER.debug("Heartbeat loop started")

            # Query initial state
            try:
                _LOGGER.debug("Querying initial DP state")
                dps = await self._connection.query_dps()
                if dps:
                    _LOGGER.debug("Initial DPS: %s", dps)
                    self._handle_status_update(dps)
                else:
                    _LOGGER.debug("Initial DP query returned empty")
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

        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
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

        _LOGGER.debug("SetDP: dp=%d value=%r (%s)", dp_id, value, type(value).__name__)
        dps = {str(dp_id): value}
        result = await self._connection.set_dps(dps)
        if result:
            _LOGGER.debug("SetDP: device confirmed DPS=%s", result)
            self._handle_status_update(result)
        else:
            _LOGGER.debug("SetDP: no confirmation data from device")

    async def discover_dps(
        self,
        progress_callback: Callable[[int, int, int, int, list[int]], None] | None = None,
        clear_existing: bool = False,
    ) -> list[DiscoveredDP]:
        """Run a full DP discovery scan.

        Args:
            progress_callback: Optional callback (current, total, batch_start, batch_end, found_dp_ids).
            clear_existing: If True, replace all profile DPs with scan results.
                If False (default), merge scan results into existing profile.
        """
        if not self._connection.is_connected:
            raise ConnectionError("Not connected")

        _LOGGER.info("Starting DP discovery scan (timeout=%ds, clear_existing=%s)", DP_SCAN_TIMEOUT, clear_existing)
        engine = DPDiscoveryEngine(self._connection)

        # Wrap progress callback to also update hub state
        def _progress_wrapper(
            current: int, total: int, batch_start: int, batch_end: int, found_dp_ids: list[int]
        ) -> None:
            self._scan_progress = {
                "status": f"Scanning DPs {batch_start}-{batch_end} ({current}/{total})",
                "found_count": str(len(found_dp_ids)),
                "found_dps": ", ".join(str(d) for d in found_dp_ids) if found_dp_ids else "none yet",
            }
            if progress_callback:
                progress_callback(current, total, batch_start, batch_end, found_dp_ids)

        engine.set_progress_callback(_progress_wrapper)

        # Retry loop: if device disconnects mid-scan, wait for reconnect and resume
        scan_start = DP_SCAN_START
        all_found: dict[int, DiscoveredDP] = {}

        async def _scan_with_retries() -> list[DiscoveredDP]:
            nonlocal scan_start, all_found
            for attempt in range(DP_SCAN_MAX_RETRIES + 1):
                result = await engine.scan_all(range_start=scan_start)

                # Merge newly discovered DPs
                for dp in result.discovered:
                    all_found[dp.dp_id] = dp

                if result.completed:
                    break

                # Scan was interrupted by disconnect
                if attempt >= DP_SCAN_MAX_RETRIES:
                    _LOGGER.warning(
                        "DP scan interrupted at DP %d, max retries (%d) exhausted",
                        result.last_batch_end, DP_SCAN_MAX_RETRIES,
                    )
                    break

                _LOGGER.warning(
                    "DP scan interrupted at DP %d (found %d DPs so far), "
                    "waiting up to %ds for reconnect (attempt %d/%d)",
                    result.last_batch_end,
                    len(all_found),
                    DP_SCAN_RECONNECT_WAIT,
                    attempt + 1,
                    DP_SCAN_MAX_RETRIES,
                )

                # Wait for reconnect by polling is_connected
                reconnected = False
                for _ in range(DP_SCAN_RECONNECT_WAIT // 2):
                    await asyncio.sleep(2)
                    if self._connection.is_connected:
                        reconnected = True
                        break

                if not reconnected:
                    _LOGGER.warning(
                        "Device did not reconnect within %ds, stopping scan",
                        DP_SCAN_RECONNECT_WAIT,
                    )
                    break

                _LOGGER.info(
                    "Device reconnected, resuming DP scan from DP %d",
                    result.last_batch_end + 1,
                )
                scan_start = result.last_batch_end + 1

            return sorted(all_found.values(), key=lambda dp: dp.dp_id)

        discovered = await asyncio.wait_for(
            _scan_with_retries(), timeout=DP_SCAN_TIMEOUT
        )
        _LOGGER.info("DP discovery scan returned %d DPs", len(discovered))

        # Update profile
        dp_defs = self._dp_registry.merge_discovered(discovered)

        if clear_existing:
            # Replace all — only keep scan results
            self._profile = DeviceProfile(
                device_id=self._device_id,
                discovered_dps=dp_defs,
                protocol_version=self._version,
            )
        else:
            # Merge — preserve existing DPs not found in scan
            existing = {}
            if self._profile:
                existing = dict(self._profile.discovered_dps)
            existing.update(dp_defs)
            self._profile = DeviceProfile(
                device_id=self._device_id,
                discovered_dps=existing,
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

    async def add_manual_dp(
        self, dp_id: int, name: str, dp_type: str, entity_type: str
    ) -> None:
        """Add a manually-defined datapoint to the device profile."""
        if self._profile is None:
            self._profile = DeviceProfile(
                device_id=self._device_id,
                protocol_version=self._version,
            )

        definition = DPDefinition(
            dp_id=dp_id,
            name=name,
            dp_type=dp_type,
            entity_type=entity_type,
        )
        self._profile.discovered_dps[dp_id] = definition
        await self._dp_registry.save_profile(self._hass, self._profile)
        _LOGGER.info("Added manual DP %d (%s) as %s/%s", dp_id, name, dp_type, entity_type)

    async def remove_dp(self, dp_id: int) -> None:
        """Remove a datapoint from the device profile."""
        if self._profile and dp_id in self._profile.discovered_dps:
            del self._profile.discovered_dps[dp_id]
            await self._dp_registry.save_profile(self._hass, self._profile)
            _LOGGER.info("Removed DP %d from profile", dp_id)

    async def update_dp(
        self,
        dp_id: int,
        name: str | None = None,
        entity_type: str | None = None,
    ) -> None:
        """Update an existing datapoint definition."""
        if not self._profile or dp_id not in self._profile.discovered_dps:
            _LOGGER.warning("Cannot update DP %d: not in profile", dp_id)
            return

        definition = self._profile.discovered_dps[dp_id]
        if name is not None:
            definition.name = name
        if entity_type is not None:
            definition.entity_type = entity_type
        await self._dp_registry.save_profile(self._hass, self._profile)
        _LOGGER.info("Updated DP %d: name=%s entity_type=%s", dp_id, definition.name, definition.entity_type)

    # --- Internal methods ---

    def _handle_status_update(self, dps: dict) -> None:
        """Process incoming DPS updates from the device."""
        _LOGGER.debug("StatusUpdate: received DPS=%s", dps)
        for dp_str, raw_value in dps.items():
            dp_id = int(dp_str)
            value = self._normalize_value(dp_id, raw_value)
            old_value = self._dps_state.get(dp_str)
            self._dps_state[dp_str] = value
            _LOGGER.debug("StatusUpdate: DP %s: %r -> %r (raw=%r)", dp_str, old_value, value, raw_value)

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
        _LOGGER.debug("Event: type=%s dp=%d counter=%d image_url=%s", event_type, dp_id, counter, image_url)

        event_data = {
            "device_id": self._device_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "image_url": image_url,
            "event_counter": counter,
            "dp_id": dp_id,
            "raw_value": str(value) if not isinstance(value, (str, int, float, bool)) else value,
        }

        # Capture RTSP snapshot on doorbell press
        if dp_id == DP_DOORBELL_BUTTON and self.rtsp_url:
            asyncio.ensure_future(self._capture_snapshot_for_event(event_data, slug, event_type))
        else:
            self._fire_event(f"{event_type}_{slug}", event_data)

    async def _capture_snapshot_for_event(
        self, event_data: dict, slug: str, event_type: str
    ) -> None:
        """Capture snapshot and then fire the event with snapshot URL included."""
        snapshot_url = await self._capture_snapshot()
        if snapshot_url:
            event_data["snapshot_url"] = snapshot_url
        self._fire_event(f"{event_type}_{slug}", event_data)

    async def _capture_snapshot(self) -> str | None:
        """Capture a frame from RTSP stream and save to disk."""
        rtsp_url = self.rtsp_url
        if not rtsp_url:
            return None

        opts = self._config_entry.options
        snapshot_dir = opts.get(CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH)
        slug = self._device_name_slug()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{slug}_{timestamp}.jpg"

        # Ensure directory exists
        path = Path(snapshot_dir)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            _LOGGER.error("Cannot create snapshot directory: %s", snapshot_dir)
            return None

        filepath = path / filename

        try:
            process = await asyncio.create_subprocess_exec(
                "ffmpeg",
                "-rtsp_transport", "tcp",
                "-i", rtsp_url,
                "-vframes", "1",
                "-f", "image2",
                str(filepath),
                "-y",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=15.0)

            if process.returncode != 0:
                _LOGGER.debug(
                    "Snapshot ffmpeg failed (rc=%s): %s",
                    process.returncode,
                    stderr.decode(errors="replace")[:200] if stderr else "",
                )
                return None

            if not filepath.exists():
                return None

            self._last_snapshot_path = str(filepath)

            # Build HA-accessible URL: /local/doorbell/filename
            # snapshot_dir is expected to be under /config/www/
            rel = str(filepath)
            www_prefix = "/config/www/"
            if rel.startswith(www_prefix):
                self._last_snapshot_url = f"/local/{rel[len(www_prefix):]}"
            else:
                self._last_snapshot_url = f"/local/doorbell/{filename}"

            _LOGGER.info("Snapshot saved: %s (url: %s)", filepath, self._last_snapshot_url)

            # Cleanup old snapshots
            self._cleanup_snapshots(path, slug)

            return self._last_snapshot_url

        except asyncio.TimeoutError:
            _LOGGER.warning("Snapshot capture timed out")
        except FileNotFoundError:
            _LOGGER.error("ffmpeg not found — install ffmpeg for doorbell snapshots")
        except Exception:
            _LOGGER.debug("Snapshot capture error", exc_info=True)

        return None

    @staticmethod
    def _cleanup_snapshots(directory: Path, slug: str) -> None:
        """Keep only the most recent MAX_SNAPSHOTS snapshots for this device."""
        try:
            files = sorted(
                directory.glob(f"{slug}_*.jpg"),
                key=lambda f: f.stat().st_mtime,
            )
            if len(files) > MAX_SNAPSHOTS:
                for old_file in files[: len(files) - MAX_SNAPSHOTS]:
                    old_file.unlink(missing_ok=True)
                    _LOGGER.debug("Deleted old snapshot: %s", old_file)
        except OSError:
            _LOGGER.debug("Snapshot cleanup error", exc_info=True)

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
        _LOGGER.debug("FireEvent: %s data=%s", event_type, event_data)
        self._hass.bus.async_fire(event_type, event_data)

    def _device_name_slug(self) -> str:
        """Return a slugified device name for event naming."""
        import re
        slug = self._device_name.lower()
        slug = re.sub(r"[^a-z0-9]+", "_", slug)
        return slug.strip("_")
