"""DeviceHub — central connection and state management for a single doorbell device.

Two things in here are deliberate and easy to undo by accident.

*Roles, not numbers.* What a datapoint means comes from the device profile:
``role_dp()`` says which datapoint currently rings the bell, moves on motion or
holds the record switch. A role nobody claims means that behaviour is off. There
is no falling back to DP 185/115/101 — those numbers are one model on one
firmware, and assuming them is why this integration used to do nothing at all on
other people's doorbells.

*The event never waits for the picture.* Entity callbacks and the button-press
event fire the moment the device reports the press, with ``snapshot_url`` present
but possibly ``None``. Fetching the image happens in a background task that,
when it succeeds, writes the state again and fires a second event. Measured
against the real camera the picture takes four to seven seconds; firing the event
after it meant every automation ran late and every sensor attribute showed the
*previous* visitor.

Home Assistant is imported lazily, the way ``video.py`` does it, so the logic in
here can be tested without a running Home Assistant.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
import re
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Callable, Coroutine

from . import video
from .const import (
    CONF_DEVICE_ID,
    CONF_DEVICE_NAME,
    CONF_FORCE_RECORD_ON,
    CONF_HOST,
    CONF_LOCAL_KEY,
    CONF_ONVIF_PASSWORD,
    CONF_ONVIF_USERNAME,
    CONF_PORT,
    CONF_PROTOCOL_VERSION,
    CONF_RTSP_PATH,
    CONF_RTSP_PORT,
    CONF_SNAPSHOT_BUFFER_PATH,
    CONF_SNAPSHOT_BUFFER_SECONDS,
    CONF_SNAPSHOT_DELAY_MS,
    CONF_SNAPSHOT_MODE,
    CONF_SNAPSHOT_PATH,
    CONF_SNAPSHOT_TRIGGER_DPS,
    CONF_STILL_IMAGE_URL_OVERRIDE,
    CONF_STREAM_URL_OVERRIDE,
    DEFAULT_ONVIF_USERNAME,
    DEFAULT_PORT,
    DEFAULT_RTSP_PATH,
    DEFAULT_RTSP_PORT,
    DEFAULT_SNAPSHOT_PATH,
    DEFAULT_WWW_ROOT,
    DEPRECATED_SLUG_EVENTS,
    DOMAIN,
    DP_SCAN_MAX_RETRIES,
    DP_SCAN_RECONNECT_WAIT,
    DP_SCAN_START,
    DP_SCAN_TIMEOUT,
    DP_TYPE_BOOL,
    DP_TYPE_ENUM,
    DP_TYPE_INT,
    DP_TYPE_RAW,
    DP_TYPE_STRING,
    EVENT_BUTTON_PRESS,
    EVENT_CONNECTED,
    EVENT_DISCONNECTED,
    EVENT_DP_DISCOVERED,
    EVENT_DP_EVENT,
    EVENT_IP_CHANGED,
    EVENT_MOTION_DETECT,
    EVENT_SNAPSHOT_READY,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_MAX_FAILURES,
    ISSUE_NO_DOORBELL_ROLE,
    LOCAL_URL_PREFIX,
    MAX_BUFFER_SECONDS,
    MAX_SNAPSHOTS,
    MAX_SNAPSHOT_DELAY_MS,
    MIN_BUFFER_SECONDS,
    RECONNECT_BACKOFF,
    RECONNECT_INITIAL_WAIT,
    RECONNECT_RETRY_COUNT,
    RECONNECT_RETRY_INTERVAL,
    RECORD_RECOVERY_DELAY,
    ROLE_DOORBELL_BUTTON,
    ROLE_MOTION,
    ROLE_RECORD_SWITCH,
    STILL_IMAGE_TIMEOUT,
    WWW_DIRECTORY,
    mask_credential,
)
from .discovery.manager import DiscoveryManager
from .dp_discovery import DPDiscoveryEngine, DiscoveredDP, LiveCapture
from .dp_registry import DPDefinition, DPRegistry, DeviceProfile
from .protocol.connection import TuyaConnection

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.device_registry import DeviceInfo

_LOGGER = logging.getLogger(__name__)

#: Event names that fire a device event. Kept together so a reader can see at a
#: glance which role produces which event.
ROLE_EVENTS: dict[str, str] = {
    ROLE_DOORBELL_BUTTON: EVENT_BUTTON_PRESS,
    ROLE_MOTION: EVENT_MOTION_DETECT,
}

_SLUG_PATTERN = re.compile(r"[^a-z0-9]+")


# --- Pure helpers (no Home Assistant, no event loop) ------------------------


def normalize_dp_value(value: Any, dp_type: str | None) -> Any:
    """Coerce a datapoint value to the type its definition promises.

    The old version guessed per value, which turned a raw payload consisting of
    digits into an integer and made the image-URL decoders below useless. A raw
    payload is therefore never converted, and a value without a definition is
    left exactly as the device sent it rather than guessed at.
    """
    if value is None or dp_type is None or dp_type == DP_TYPE_RAW:
        return value

    if dp_type == DP_TYPE_BOOL:
        return _to_bool(value)
    if dp_type == DP_TYPE_INT:
        return _to_int(value)
    if dp_type in (DP_TYPE_ENUM, DP_TYPE_STRING):
        return value if isinstance(value, str) else str(value)
    return value


def _to_bool(value: Any) -> Any:
    """Return a bool, or the untouched value when it clearly is not one."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "on", "1"):
            return True
        if lowered in ("false", "off", "0"):
            return False
    _LOGGER.debug("Value %r is typed bool but does not look like one", value)
    return value


def _to_int(value: Any) -> Any:
    """Return an int, or the untouched value when it clearly is not one."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            try:
                return int(float(value.strip()))
            except ValueError:
                pass
    _LOGGER.debug("Value %r is typed int but does not look like one", value)
    return value


def local_url_for(file_path: str, www_root: str) -> str | None:
    """Return the /local/ URL for a file, or None when it has none.

    Home Assistant only serves ``<config>/www``. Handing out a /local/ URL for a
    file outside it produced a link that always 404s, which is worse than
    admitting there is no URL.
    """
    try:
        relative = Path(file_path).relative_to(Path(www_root))
    except ValueError:
        return None
    return f"{LOCAL_URL_PREFIX}{relative.as_posix()}"


def write_snapshot(
    directory: str, filename: str, data: bytes, slug: str, keep: int
) -> str:
    """Write a snapshot and prune older ones. Runs in an executor thread.

    mkdir, glob, stat and unlink all block, and Home Assistant's blocking-call
    detector covers none of them — doing this on the event loop produces no
    warning at all, only a stuttering loop.
    """
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    file_path = target / filename
    # Uniqueness must not depend on the clock: two events close enough together
    # share a name, and the first picture disappears before anyone sees it.
    index = 1
    while file_path.exists():
        file_path = target / f"{Path(filename).stem}-{index}{Path(filename).suffix}"
        index += 1
    file_path.write_bytes(data)

    existing = sorted(
        (f for f in target.glob(f"{slug}_*.jpg") if f.is_file()),
        key=lambda f: f.stat().st_mtime,
    )
    for old in existing[: max(0, len(existing) - keep)]:
        try:
            old.unlink()
        except OSError as err:
            _LOGGER.warning("Could not delete old snapshot %s: %s", old, err)

    return str(file_path)


def snapshot_filename(slug: str, moment: float) -> str:
    """Build a snapshot filename with sub-second precision.

    Second precision was enough to make two presses inside the same second
    overwrite each other, so the first picture was gone before anyone saw it.
    """
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(moment))
    return f"{slug}_{stamp}_{int(moment * 1_000_000) % 1_000_000:06d}.jpg"


def device_name_slug(device_name: str) -> str:
    """Slugify a device name for the deprecated per-device event names."""
    return _SLUG_PATTERN.sub("_", device_name.lower()).strip("_")


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

        # Connection state callbacks. Every entity registers one; without that a
        # disconnect leaves switches, selects and sensors showing their last
        # value forever, because an offline device never sends an update.
        self._connection_callbacks: list[Callable[[bool], None]] = []

        # Snapshot listeners, so an entity can rewrite its state when the
        # picture belonging to an already-fired event finally arrives.
        self._snapshot_callbacks: list[Callable[[str | None], None]] = []

        # Event counters
        self._event_counters: dict[int, int] = {}

        # Snapshot state. The provider exists from construction on, so entities
        # can read its status before (and after) setup ran.
        self._last_snapshot_path: str | None = None
        self._last_snapshot_url: str | None = None
        self._snapshots = self._build_snapshot_provider()
        self._warned_no_www = False

        # DP scan state (persists across options dialog open/close)
        self._live_capture: LiveCapture | None = None
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
        self._background_tasks: set[asyncio.Task] = set()
        self._record_recovery_handle: Callable[[], None] | None = None
        self._unregister_disconnect: Callable | None = None
        self._unregister_status: Callable | None = None

        # Set just before the hub rewrites its own config entry after an IP
        # change, so the update listener does not reload the entry and cancel
        # the reconnect task that is doing the rewriting.
        self._self_written_update = False

    # --- Identity ---

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
    def entry_id(self) -> str:
        return self._config_entry.entry_id

    @property
    def config_entry(self) -> ConfigEntry:
        return self._config_entry

    @property
    def connection(self) -> TuyaConnection:
        """The live protocol connection, for the datapoint scan and monitor."""
        return self._connection

    @property
    def device_info(self) -> DeviceInfo:
        from homeassistant.helpers.device_registry import DeviceInfo

        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            name=self._device_name,
            manufacturer="LSC Smart Connect (Tuya)",
            model="Video Doorbell",
            sw_version=self._version,
        )

    # --- Profile, roles and definitions ---

    @property
    def profile(self) -> DeviceProfile | None:
        return self._profile

    @property
    def dp_registry(self) -> DPRegistry:
        return self._dp_registry

    def role_dp(self, role: str) -> int | None:
        """Which datapoint currently holds this role, if any."""
        return self._profile.role_dp(role) if self._profile else None

    def role_of(self, dp_id: int) -> str | None:
        """Which role this datapoint holds, if any."""
        return self._profile.role_of(dp_id) if self._profile else None

    def definition_for(self, dp_id: int) -> DPDefinition | None:
        """The profile's definition for a datapoint, if the profile has one."""
        if not self._profile:
            return None
        return self._profile.discovered_dps.get(dp_id)

    def get_dp_state(self, dp_id: int) -> Any:
        """Get the current state of a datapoint."""
        return self._dps_state.get(str(dp_id))

    def event_count(self, dp_id: int) -> int:
        """How often this datapoint has fired since Home Assistant started.

        The same counter that goes into the event payload. There used to be two
        -- one here and one restored by the binary sensor -- and they drifted
        apart the moment either side missed an event.
        """
        return self._event_counters.get(dp_id, 0)

    def seed_event_count(self, dp_id: int, count: int) -> None:
        """Restore a counter from an entity's stored state.

        Only ever raises it: entities restore at their own pace, and a
        restore arriving after a fresh press must not undo that press.
        """
        if count > self._event_counters.get(dp_id, 0):
            self._event_counters[dp_id] = count
            _LOGGER.debug("Event counter for DP %d restored to %d", dp_id, count)

    # --- Streams and snapshots ---

    @property
    def snapshots(self) -> video.SnapshotProvider:
        """The snapshot subsystem. Always present, even when the mode is off."""
        return self._snapshots

    @property
    def snapshot_status(self) -> str:
        """Short, showable snapshot state — the only place a rewind that was
        ignored or a buffer path that is too small becomes visible."""
        return self._snapshots.status

    @property
    def last_snapshot_path(self) -> str | None:
        return self._last_snapshot_path

    @property
    def last_snapshot_url(self) -> str | None:
        return self._last_snapshot_url

    @property
    def stream_url(self) -> str | None:
        """The stream to pull frames from: the override, else the built URL.

        The override exists so frames come from a restreamer instead of opening
        yet another session on a camera that tolerates a handful.
        """
        override = (self._option(CONF_STREAM_URL_OVERRIDE, "") or "").strip()
        if override:
            return override

        password = self._option(CONF_ONVIF_PASSWORD, "")
        if not password:
            return None

        return video.build_rtsp_url(
            self._host,
            self._option(CONF_RTSP_PORT, DEFAULT_RTSP_PORT),
            self._option(CONF_RTSP_PATH, DEFAULT_RTSP_PATH),
            self._option(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME),
            password,
        )

    @property
    def still_image_url(self) -> str | None:
        """A configured URL that returns a single JPEG, if any."""
        return (self._option(CONF_STILL_IMAGE_URL_OVERRIDE, "") or "").strip() or None

    @property
    def rtsp_url(self) -> str | None:
        """Deprecated alias of ``stream_url``, kept for existing callers."""
        return self.stream_url

    @property
    def diagnostics(self) -> dict[str, Any]:
        """Everything an entity can show as diagnostic attributes."""
        return {
            "available": self._available,
            "host": self._host,
            "protocol_version": self._version,
            "snapshot_mode": self._snapshots.active_mode,
            "snapshot_status": self._snapshots.status,
            "last_snapshot_url": self._last_snapshot_url,
            "last_snapshot_path": self._last_snapshot_path,
            "roles": dict(self._profile.roles) if self._profile else {},
        }

    # --- DP scan state (driven by the options flow) ---

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

    def set_scan_task(self, task: asyncio.Task | None) -> None:
        """Hand the hub the task running a scan, so teardown can cancel it."""
        self._scan_task = task

    def set_scan_outcome(
        self, results: list[DiscoveredDP] | None, error: str | None
    ) -> None:
        """Record how a scan ended; the options flow shows either one."""
        self._scan_results = results
        self._scan_error = error

    def start_scan_task(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task:
        """Run a scan coroutine as the hub's scan task, and keep it cancellable."""
        task = self._spawn(coro, f"dp_scan_{self._device_id}")
        self._scan_task = task
        return task

    # --- Live capture (learning an unknown firmware) ---

    @property
    def live_capture(self) -> LiveCapture | None:
        """The most recent live capture session, running or finished.

        Stays readable after it stopped, so the options flow can still show what
        was seen; a new session replaces it.
        """
        return self._live_capture

    async def async_start_live_capture(self) -> LiveCapture:
        """Start recording everything the device reports.

        Rides on the existing connection: no second session, and no second
        engine when one is already listening.
        """
        if self._live_capture is not None and self._live_capture.running:
            _LOGGER.debug("Live capture already running for %s", self._device_id)
            return self._live_capture

        if not self._connection.is_connected:
            raise ConnectionError("Not connected")

        engine = DPDiscoveryEngine(
            self._connection,
            firmware_version=self._profile.firmware_version if self._profile else None,
        )
        capture = engine.start_live_capture()
        capture.start()
        self._live_capture = capture
        return capture

    async def async_stop_live_capture(self) -> LiveCapture | None:
        """Stop recording and hand back the session. Safe to call twice."""
        capture = self._live_capture
        if capture is None:
            return None
        capture.stop()
        return capture

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

    # --- Listener registration ---

    def register_entity(self, dp_id: int, callback: Callable[[Any], None]) -> None:
        """Register an entity callback for a specific DP."""
        self._entity_callbacks.setdefault(dp_id, []).append(callback)
        _LOGGER.debug(
            "Entity registered for DP %d (total callbacks: %d)",
            dp_id, len(self._entity_callbacks[dp_id]),
        )

    def unregister_entity(self, dp_id: int, callback: Callable[[Any], None]) -> None:
        """Unregister an entity callback."""
        callbacks = self._entity_callbacks.get(dp_id, [])
        if callback in callbacks:
            callbacks.remove(callback)
            _LOGGER.debug("Entity unregistered for DP %d (remaining: %d)", dp_id, len(callbacks))

    def on_dp_change(
        self, dp_id: int, callback: Callable[[Any], None]
    ) -> Callable[[], None]:
        """Register a datapoint callback and return its unregister function."""
        self.register_entity(dp_id, callback)

        def _unregister() -> None:
            self.unregister_entity(dp_id, callback)

        return _unregister

    def on_connection_change(
        self, callback: Callable[[bool], None]
    ) -> Callable[[], None]:
        """Register a connection state callback; returns its unregister function.

        Every entity should hold one. Without it a disconnect goes unnoticed and
        the entity keeps showing its last value until an update arrives — which,
        for a device that is offline, is never.
        """
        self._connection_callbacks.append(callback)

        def _unregister() -> None:
            if callback in self._connection_callbacks:
                self._connection_callbacks.remove(callback)

        return _unregister

    def on_snapshot_change(
        self, callback: Callable[[str | None], None]
    ) -> Callable[[], None]:
        """Register a snapshot callback; returns its unregister function.

        Called with the new /local/ URL (or None) once the picture belonging to
        an already-fired event has been written, so an entity that exposes it can
        write its state a second time.
        """
        self._snapshot_callbacks.append(callback)

        def _unregister() -> None:
            if callback in self._snapshot_callbacks:
                self._snapshot_callbacks.remove(callback)

        return _unregister

    def register_connection_callback(self, callback: Callable[[bool], None]) -> None:
        """Deprecated: use ``on_connection_change``, which returns an unregister."""
        self._connection_callbacks.append(callback)

    def unregister_connection_callback(self, callback: Callable[[bool], None]) -> None:
        """Deprecated: use the function returned by ``on_connection_change``."""
        if callback in self._connection_callbacks:
            self._connection_callbacks.remove(callback)

    def _notify_connection_callbacks(self, connected: bool) -> None:
        for callback in list(self._connection_callbacks):
            try:
                callback(connected)
            except Exception:  # noqa: BLE001 - one bad listener must not stop the rest
                _LOGGER.warning(
                    "Connection listener failed for %s; the entity behind it may "
                    "show a stale availability", self._device_id, exc_info=True,
                )

    def _notify_entity_callbacks(self, dp_id: int, value: Any) -> None:
        for callback in list(self._entity_callbacks.get(dp_id, [])):
            try:
                callback(value)
            except Exception:  # noqa: BLE001 - one bad listener must not stop the rest
                _LOGGER.warning(
                    "Entity listener for DP %s failed; its state was not updated",
                    dp_id, exc_info=True,
                )

    def _notify_snapshot_callbacks(self, url: str | None) -> None:
        for callback in list(self._snapshot_callbacks):
            try:
                callback(url)
            except Exception:  # noqa: BLE001 - one bad listener must not stop the rest
                _LOGGER.warning(
                    "Snapshot listener failed for %s; its state still shows the "
                    "previous picture", self._device_id, exc_info=True,
                )

    # --- Lifecycle ---

    async def async_setup(self) -> bool:
        """Set up the device hub: connect, load profile, start heartbeat."""
        _LOGGER.info(
            "Setting up device %s at %s:%s (key: %s)",
            self._device_id, self._host, self._port,
            mask_credential(self._local_key),
        )

        try:
            self._profile = await self._dp_registry.load_profile(
                self._hass, self._device_id
            )
        except Exception:  # noqa: BLE001 - a broken profile must not block setup
            _LOGGER.warning(
                "Could not load the datapoint profile for %s; the device starts "
                "without one, so run the datapoint scan from the options dialog",
                self._device_id, exc_info=True,
            )

        self._enrich_profile_from_known_table()
        self._review_roles()

        # The provider is rebuilt here because the stream URL depends on the
        # host, which discovery may have changed since construction.
        self._snapshots = self._build_snapshot_provider()
        await self._snapshots.async_start()
        _LOGGER.debug("Snapshot provider: %s", self._snapshots.status)

        self._unregister_status = self._connection.on_status_update(
            self._handle_status_update
        )
        self._unregister_disconnect = self._connection.on_disconnect(
            self._handle_disconnect
        )

        try:
            await self._connection.connect()
            self._available = True
            self._heartbeat_failures = 0
            _LOGGER.debug("Connected to %s:%s, firing connected event", self._host, self._port)
            self._fire_event(EVENT_CONNECTED)
            self._notify_connection_callbacks(True)

            self._heartbeat_task = self._spawn(self._heartbeat_loop(), "heartbeat")
            _LOGGER.debug("Heartbeat loop started")

            try:
                _LOGGER.debug("Querying initial DP state")
                dps = await self._connection.query_dps()
                if dps:
                    _LOGGER.debug("Initial DPS: %s", dps)
                    self._handle_status_update(dps)
                else:
                    _LOGGER.debug("Initial DP query returned empty")
            except Exception:  # noqa: BLE001 - the heartbeat will pick state up later
                _LOGGER.warning(
                    "Initial datapoint query failed for %s; entities stay unknown "
                    "until the device reports by itself", self._device_id, exc_info=True,
                )

            return True

        except ConnectionError:
            _LOGGER.warning(
                "Could not connect to %s:%s, will retry",
                self._host, self._port,
            )
            self._available = False
            self._reconnect_task = self._spawn(self._reconnect(), "reconnect")
            return True  # Still return True so entities can be created

    async def async_teardown(self) -> None:
        """Tear down the hub: disconnect, stop all tasks, drop all listeners."""
        if self._record_recovery_handle is not None:
            self._record_recovery_handle()
            self._record_recovery_handle = None

        tasks = [
            self._heartbeat_task,
            self._reconnect_task,
            self._scan_task,
            *self._background_tasks,
        ]
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        for task in tasks:
            if task is None:
                continue
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001 - report, then keep tearing down
                _LOGGER.warning(
                    "Background task %s ended with an error during teardown",
                    task.get_name(), exc_info=True,
                )
        self._heartbeat_task = None
        self._reconnect_task = None
        self._scan_task = None
        self._background_tasks.clear()

        await self._snapshots.async_stop()

        if self._unregister_status:
            self._unregister_status()
            self._unregister_status = None
        if self._unregister_disconnect:
            self._unregister_disconnect()
            self._unregister_disconnect = None

        await self._connection.disconnect()
        self._available = False

        self._entity_callbacks.clear()
        self._connection_callbacks.clear()
        self._snapshot_callbacks.clear()
        _LOGGER.debug("Hub teardown complete for %s", self._device_id)

    def absorb_entry_update(self) -> bool:
        """True when the pending config entry update is the hub's own IP rewrite.

        Storing a rediscovered IP updates the config entry, which fires the
        update listener, which reloads the entry, which cancels the reconnect
        task that is in the middle of doing exactly that. The reload is
        pointless — the hub has already applied the new host itself.
        """
        if not self._self_written_update:
            return False
        self._self_written_update = False
        return True

    # --- Commands ---

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
        """Run a full DP discovery scan and return what it found.

        Deliberately does not touch the profile: a scan is a proposal, not a
        decision. Writing it here stored datapoints the user had not chosen yet,
        and everything the user did choose afterwards was written a second time
        as a bare definition. ``async_apply_discovered_dps`` does the writing.

        Args:
            progress_callback: Optional callback (current, total, batch_start, batch_end, found_dp_ids).
            clear_existing: Ignored, kept so existing callers still work; pass it
                to ``async_apply_discovered_dps`` instead.
        """
        if clear_existing:
            _LOGGER.debug(
                "discover_dps(clear_existing=True) no longer writes the profile; "
                "pass it to async_apply_discovered_dps"
            )
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

        self._fire_event(EVENT_DP_DISCOVERED, {
            "dp_count": len(discovered),
            "dp_ids": [dp.dp_id for dp in discovered],
        })

        return discovered

    async def async_apply_discovered_dps(
        self,
        dps: Sequence[DiscoveredDP],
        *,
        clear_existing: bool = False,
        roles: Mapping[str, int | None] | None = None,
    ) -> None:
        """Write the datapoints the user picked, with their roles, to the profile.

        The single place the profile is written. Saving straight after a scan
        wrote datapoints nobody had chosen yet, and the per-datapoint save that
        followed replaced the full definitions with bare ones -- which is why a
        scanned select came back as a switch without options.
        """
        merged = self._dp_registry.merge_discovered(list(dps))

        if clear_existing or self._profile is None:
            definitions = dict(merged)
        else:
            definitions = dict(self._profile.discovered_dps)
            definitions.update(merged)

        # Roles survive: they are the user's answer to "what does this datapoint
        # do", and a scan only re-reads which datapoints exist. A role pointing
        # at a datapoint that no longer exists is dropped, because it would keep
        # a behaviour "on" that nothing can trigger.
        previous = dict(self._profile.roles) if self._profile else {}
        profile = DeviceProfile(
            device_id=self._device_id,
            discovered_dps=definitions,
            firmware_version=self._profile.firmware_version if self._profile else None,
            protocol_version=self._version,
            roles={role: dp for role, dp in previous.items() if dp in definitions},
        )

        for role, dp_id in (roles or {}).items():
            if dp_id is not None and dp_id not in definitions:
                _LOGGER.warning(
                    "Role %s was asked to point at DP %s, which this device does "
                    "not report; leaving the role unset", role, dp_id,
                )
                continue
            try:
                profile.set_role(role, dp_id)
            except ValueError:
                _LOGGER.warning("Ignoring unknown role %r", role)

        self._profile = profile
        await self._dp_registry.save_profile(self._hass, profile)
        self._review_roles()
        _LOGGER.info(
            "Applied %d datapoint(s) to %s, roles: %s",
            len(definitions), self._device_id, profile.roles or "none",
        )

    async def add_manual_dp(
        self,
        dp_id: int,
        name: str,
        dp_type: str,
        entity_type: str,
        *,
        options: dict | None = None,
        min_value: int | None = None,
        max_value: int | None = None,
        enum_values: list[str] | None = None,
        is_event: bool = False,
        icon: str | None = None,
        device_class: str | None = None,
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
            options=options,
            min_value=min_value,
            max_value=max_value,
            enum_values=enum_values,
            is_event=is_event,
            icon=icon,
            device_class=device_class,
        )
        self._profile.discovered_dps[dp_id] = definition
        await self._dp_registry.save_profile(self._hass, self._profile)
        _LOGGER.info("Added manual DP %d (%s) as %s/%s", dp_id, name, dp_type, entity_type)

    async def remove_dp(self, dp_id: int) -> None:
        """Remove a datapoint from the device profile."""
        if self._profile and dp_id in self._profile.discovered_dps:
            del self._profile.discovered_dps[dp_id]
            role = self._profile.role_of(dp_id)
            if role is not None:
                # A role pointing at a datapoint that no longer exists would keep
                # the behaviour "on" while nothing can ever trigger it.
                self._profile.set_role(role, None)
                _LOGGER.info("DP %d also gave up the %s role", dp_id, role)
            await self._dp_registry.save_profile(self._hass, self._profile)
            self._review_roles()
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

    async def async_set_role(self, role: str, dp_id: int | None) -> None:
        """Give a role to a datapoint, or take it away with None."""
        if self._profile is None:
            self._profile = DeviceProfile(
                device_id=self._device_id,
                protocol_version=self._version,
            )
        self._profile.set_role(role, dp_id)
        await self._dp_registry.save_profile(self._hass, self._profile)
        self._review_roles()
        _LOGGER.info("Role %s now belongs to DP %s", role, dp_id)

    # --- Incoming device state ---

    def _handle_status_update(self, dps: dict) -> None:
        """Process incoming DPS updates from the device."""
        _LOGGER.debug("StatusUpdate: received DPS=%s", dps)
        for dp_str, raw_value in dps.items():
            try:
                dp_id = int(dp_str)
            except (TypeError, ValueError):
                _LOGGER.warning(
                    "Device %s reported datapoint %r, which is not a number; "
                    "ignoring it", self._device_id, dp_str,
                )
                continue

            definition = self.definition_for(dp_id)
            value = normalize_dp_value(
                raw_value, definition.dp_type if definition else None
            )
            old_value = self._dps_state.get(dp_str)
            self._dps_state[dp_str] = value
            _LOGGER.debug("StatusUpdate: DP %s: %r -> %r (raw=%r)", dp_str, old_value, value, raw_value)

            # Contract order: entities first, then the event, both at t=0.
            self._notify_entity_callbacks(dp_id, value)

            role = self.role_of(dp_id)
            event_type = self._event_type_for(role, definition)
            if event_type:
                self._handle_event(dp_id, value, event_type, role, definition)

            if (
                role == ROLE_RECORD_SWITCH
                and value is False
                and self._option(CONF_FORCE_RECORD_ON, False)
            ):
                self._schedule_record_recovery(dp_id)

    @staticmethod
    def _event_type_for(role: str | None, definition: DPDefinition | None) -> str | None:
        """Which event a datapoint fires, decided by role and definition only."""
        if role in ROLE_EVENTS:
            return ROLE_EVENTS[role]
        if definition is not None and definition.is_event:
            return EVENT_DP_EVENT
        return None

    def _handle_event(
        self,
        dp_id: int,
        value: Any,
        event_type: str,
        role: str | None,
        definition: DPDefinition | None,
    ) -> None:
        """Fire a device event now, and go looking for a picture afterwards."""
        counter = self._event_counters.get(dp_id, 0) + 1
        self._event_counters[dp_id] = counter

        payload = self._event_payload(dp_id, value, counter, role, definition)
        _LOGGER.debug(
            "Event: type=%s dp=%d counter=%d image_url=%s",
            event_type, dp_id, counter, payload["image_url"],
        )
        self._fire_device_event(event_type, payload)

        if dp_id not in self._snapshot_trigger_dps():
            return

        if not self._snapshots.available:
            _LOGGER.warning(
                "No snapshot for the %s event on %s: %s",
                event_type, self._device_name, self._snapshots.status,
            )
            return

        self._spawn(
            self._async_snapshot_for_event(payload),
            f"snapshot_{self._device_id}_{counter}",
            track=True,
        )

    def _event_payload(
        self,
        dp_id: int,
        value: Any,
        counter: int,
        role: str | None,
        definition: DPDefinition | None,
    ) -> dict[str, Any]:
        """Build a complete event payload.

        Every key is always present. An automation that has to test whether a
        field exists before reading it is an automation that breaks on the first
        event that leaves the field out.
        """
        return {
            "device_id": self._device_id,
            "device_name": self._device_name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "dp_id": dp_id,
            "role": role,
            "event_counter": counter,
            "image_url": self.extract_image_url(value, definition),
            "snapshot_url": None,
            "snapshot_path": None,
            "raw_value": (
                value if isinstance(value, (str, int, float, bool)) else str(value)
            ),
        }

    async def _async_snapshot_for_event(self, payload: dict[str, Any]) -> None:
        """Fetch the picture for an event that has already fired."""
        age = self._snapshot_delay_ms() / 1000.0
        try:
            image = await self._snapshots.async_grab(age)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed grab must not kill the hub
            _LOGGER.warning(
                "Snapshot for %s failed (%s); check the stream URL and that "
                "ffmpeg is installed", self._device_name, self._snapshots.status,
                exc_info=True,
            )
            return

        if not image:
            _LOGGER.warning(
                "No snapshot could be taken for %s: %s",
                self._device_name, self._snapshots.status,
            )
            return

        stored = await self._async_store_snapshot(image)
        if stored is None:
            return

        file_path, url = stored
        self._last_snapshot_path = file_path
        self._last_snapshot_url = url
        _LOGGER.info("Snapshot saved: %s (url: %s)", file_path, url)

        self._notify_snapshot_callbacks(url)
        self._fire_device_event(
            EVENT_SNAPSHOT_READY,
            {**payload, "snapshot_url": url, "snapshot_path": file_path},
        )

    async def _async_store_snapshot(self, image: bytes) -> tuple[str, str | None] | None:
        """Write a snapshot to disk and return its path and /local/ URL."""
        directory = self._option(CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH)
        slug = self._device_name_slug()
        filename = snapshot_filename(slug, time.time())

        try:
            file_path = await self._run_in_executor(
                write_snapshot, directory, filename, image, slug, MAX_SNAPSHOTS
            )
        except OSError as err:
            _LOGGER.warning(
                "Could not write the snapshot to %s (%s); create the directory or "
                "point the snapshot path somewhere writable", directory, err,
            )
            return None

        url = local_url_for(file_path, self._www_root())
        if url is None and not self._warned_no_www:
            self._warned_no_www = True
            _LOGGER.warning(
                "Snapshots are written to %s, which is not below %s, so Home "
                "Assistant cannot serve them; events carry the file path but no "
                "URL", directory, self._www_root(),
            )
        return file_path, url

    def _schedule_record_recovery(self, dp_id: int) -> None:
        """Push the record switch back on after the device turned it off."""
        _LOGGER.warning(
            "Record switch (DP %d) turned off by the device — scheduling "
            "auto-recovery in %ds", dp_id, RECORD_RECOVERY_DELAY,
        )
        if self._record_recovery_handle is not None:
            self._record_recovery_handle()
            self._record_recovery_handle = None

        def _recover(_now: Any = None) -> None:
            self._record_recovery_handle = None
            self._spawn(self.set_dp(dp_id, True), f"record_recovery_{dp_id}", track=True)

        self._record_recovery_handle = self._call_later(
            RECORD_RECOVERY_DELAY, _recover
        )

    # --- Connection lifecycle ---

    def _handle_disconnect(self) -> None:
        """Handle connection loss."""
        self._available = False
        self._fire_event(EVENT_DISCONNECTED)
        self._notify_connection_callbacks(False)
        _LOGGER.warning("Connection lost to %s (%s)", self._device_name, self._host)

        if not self._reconnect_task or self._reconnect_task.done():
            self._reconnect_task = self._spawn(self._reconnect(), "reconnect")

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
                        _LOGGER.warning(
                            "No heartbeat response from %s after %d attempts, "
                            "dropping the connection so it can be rebuilt",
                            self._device_id, HEARTBEAT_MAX_FAILURES,
                        )
                        # force_disconnect, not disconnect: a plain disconnect is
                        # the "we meant to do this" path and notifies nobody, so
                        # nothing ever reconnected while every entity kept
                        # reporting itself available.
                        await self._connection.force_disconnect(
                            f"no heartbeat response after {HEARTBEAT_MAX_FAILURES} attempts"
                        )
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
                        self._after_reconnect()
                        _LOGGER.info("Reconnected to %s at %s", self._device_id, self._host)

                        try:
                            dps = await self._connection.query_dps()
                            if dps:
                                self._handle_status_update(dps)
                        except Exception:  # noqa: BLE001 - state follows on the next push
                            _LOGGER.warning(
                                "Could not refresh datapoints after reconnecting "
                                "to %s; entities keep their last value until the "
                                "device reports", self._device_id, exc_info=True,
                            )
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

                    connected = False
                    try:
                        await self._connection.disconnect()
                        await self._connection.connect()
                        self._after_reconnect()
                        connected = True
                    except ConnectionError:
                        _LOGGER.warning(
                            "Device %s answered discovery at %s but the "
                            "connection failed; retrying", self._device_id, new_ip,
                        )

                    # Persisting comes last, and only after the new address has
                    # proven itself: writing the entry reloads the integration,
                    # which would otherwise cancel this very task mid-recovery.
                    self._persist_host(new_ip, old_ip)

                    if connected:
                        return

                # Exponential backoff
                delay = RECONNECT_BACKOFF[min(backoff_index, len(RECONNECT_BACKOFF) - 1)]
                _LOGGER.info("Reconnect backoff: waiting %ss", delay)
                await asyncio.sleep(delay)
                backoff_index += 1

        except asyncio.CancelledError:
            return

    def _after_reconnect(self) -> None:
        """Shared bookkeeping for both successful reconnect paths."""
        self._available = True
        self._heartbeat_failures = 0
        self._fire_event(EVENT_CONNECTED)
        self._notify_connection_callbacks(True)
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        self._heartbeat_task = self._spawn(self._heartbeat_loop(), "heartbeat")

    def _persist_host(self, new_ip: str, old_ip: str) -> None:
        """Store a rediscovered IP without triggering a reload of ourselves."""
        new_data = dict(self._config_entry.data)
        new_data[CONF_HOST] = new_ip

        self._self_written_update = True
        try:
            changed = self._hass.config_entries.async_update_entry(
                self._config_entry, data=new_data
            )
        except Exception:  # noqa: BLE001 - the hub already runs on the new IP
            self._self_written_update = False
            _LOGGER.warning(
                "Could not store the new IP %s for %s; it will be rediscovered "
                "after a restart", new_ip, self._device_id, exc_info=True,
            )
        else:
            # No update means no listener, so the flag would sit there and
            # swallow the next genuine options change.
            if changed is False:
                self._self_written_update = False

        self._fire_device_event(EVENT_IP_CHANGED, {
            "device_id": self._device_id,
            "device_name": self._device_name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "old_ip": old_ip,
            "new_ip": new_ip,
        })

    # --- Roles and repairs ---

    def _enrich_profile_from_known_table(self) -> None:
        """Fill in self-describing fields a profile was stored without.

        device_class, value_map and carries_image_url only started being filled
        in recently, so a profile written before that says nothing about itself
        and would keep saying nothing until the next scan. Only fields still at
        their default are filled, and only for a datapoint whose stored name and
        type still match the table -- a datapoint that means something else on
        this firmware must not be relabelled from a table it does not follow.
        """
        if self._profile is None:
            return

        firmware = self._profile.firmware_version
        enriched: list[int] = []
        for dp_id, definition in self._profile.discovered_dps.items():
            known = self._dp_registry.get_known_dp(dp_id, firmware)
            if known is None:
                continue
            if known.name != definition.name or known.dp_type != definition.dp_type:
                continue

            changed = False
            if definition.device_class is None and known.device_class is not None:
                definition.device_class = known.device_class
                changed = True
            if definition.value_map is None and known.value_map is not None:
                definition.value_map = known.value_map
                changed = True
            if not definition.carries_image_url and known.carries_image_url:
                definition.carries_image_url = True
                changed = True
            if definition.icon is None and known.icon is not None:
                definition.icon = known.icon
                changed = True
            if changed:
                enriched.append(dp_id)

        if enriched:
            _LOGGER.debug(
                "Filled in stored definitions for DP %s from the known table",
                ", ".join(str(dp) for dp in enriched),
            )

    def _review_roles(self) -> None:
        """Raise or clear the repair issue about a missing doorbell button.

        Without that role the hub does not know which datapoint is the bell, so
        the press event and its snapshot stay off. That is a decision the user
        has to make, in the datapoint scan — not something to guess at.
        """
        missing = self.role_dp(ROLE_DOORBELL_BUTTON) is None
        try:
            from homeassistant.helpers import issue_registry as ir
        except ImportError:  # running without Home Assistant, e.g. in tests
            _LOGGER.debug("No issue registry available; skipping the repair issue")
            return

        issue_id = f"{ISSUE_NO_DOORBELL_ROLE}_{self._device_id}"
        try:
            if missing:
                _LOGGER.warning(
                    "No datapoint claims the doorbell button role for %s, so no "
                    "button press event will fire; run the datapoint scan from "
                    "the options dialog", self._device_id,
                )
                ir.async_create_issue(
                    self._hass,
                    DOMAIN,
                    issue_id,
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key=ISSUE_NO_DOORBELL_ROLE,
                    translation_placeholders={
                        "device_name": self._device_name,
                        "device_id": self._device_id,
                    },
                )
            else:
                ir.async_delete_issue(self._hass, DOMAIN, issue_id)
        except Exception:  # noqa: BLE001 - a repair issue must never block setup
            _LOGGER.warning(
                "Could not update the repair issue for %s; the missing doorbell "
                "role is only visible in this log", self._device_id, exc_info=True,
            )

    # --- Snapshot plumbing ---

    def _build_snapshot_provider(self) -> video.SnapshotProvider:
        """Assemble the snapshot provider from the entry's configuration."""
        config = video.SnapshotConfig(
            mode=self._option(CONF_SNAPSHOT_MODE, video.DEFAULT_SNAPSHOT_MODE),
            source_url=self.stream_url,
            still_url=self.still_image_url,
            buffer_path=self._option(
                CONF_SNAPSHOT_BUFFER_PATH, video.DEFAULT_BUFFER_PATH
            ),
            buffer_seconds=self._buffer_seconds(),
            delay_ms=self._snapshot_delay_ms(),
            ffmpeg_bin=self._ffmpeg_binary(),
        )
        return video.SnapshotProvider(
            self._hass,
            config,
            still_fetcher=self._async_fetch_still,
            task_factory=lambda coro, name: self._spawn(coro, name),
        )

    async def _async_fetch_still(self, url: str) -> bytes | None:
        """Fetch a single JPEG from the configured still-image URL.

        Errors are left to the provider, which logs them and falls back to
        ffmpeg; swallowing them here would hide a broken URL forever.
        """
        import aiohttp
        from homeassistant.helpers.aiohttp_client import async_get_clientsession

        session = async_get_clientsession(self._hass)
        timeout = aiohttp.ClientTimeout(total=STILL_IMAGE_TIMEOUT)
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            return await response.read()

    def _snapshot_trigger_dps(self) -> set[int]:
        """The datapoints that should produce a snapshot.

        Falls back to whichever datapoint holds the doorbell button role — and to
        nothing at all when no datapoint holds it, rather than to a DP number
        that may mean something else entirely on this firmware.
        """
        raw = self._option(CONF_SNAPSHOT_TRIGGER_DPS, [])
        if raw:
            try:
                if isinstance(raw, list):
                    return {int(x) for x in raw if str(x).strip()}
                return {int(x.strip()) for x in str(raw).split(",") if x.strip()}
            except (ValueError, AttributeError):
                _LOGGER.warning(
                    "Snapshot trigger datapoints %r are unreadable; using the "
                    "doorbell button role instead", raw,
                )

        dp_id = self.role_dp(ROLE_DOORBELL_BUTTON)
        return {dp_id} if dp_id is not None else set()

    def _snapshot_delay_ms(self) -> int:
        """How far back in time a snapshot should reach, in milliseconds."""
        raw = self._option(CONF_SNAPSHOT_DELAY_MS, video.DEFAULT_SNAPSHOT_DELAY_MS)
        try:
            return min(MAX_SNAPSHOT_DELAY_MS, max(0, int(raw)))
        except (TypeError, ValueError):
            _LOGGER.warning(
                "Snapshot delay %r is not a number; taking the picture without "
                "looking back", raw,
            )
            return 0

    def _buffer_seconds(self) -> int:
        raw = self._option(CONF_SNAPSHOT_BUFFER_SECONDS, video.DEFAULT_BUFFER_SECONDS)
        try:
            return min(MAX_BUFFER_SECONDS, max(MIN_BUFFER_SECONDS, int(raw)))
        except (TypeError, ValueError):
            _LOGGER.warning(
                "Snapshot buffer length %r is not a number; using %ss",
                raw, video.DEFAULT_BUFFER_SECONDS,
            )
            return video.DEFAULT_BUFFER_SECONDS

    def _ffmpeg_binary(self) -> str:
        """The ffmpeg Home Assistant itself uses, or plain ffmpeg on PATH."""
        try:
            from homeassistant.components.ffmpeg import get_ffmpeg_manager

            return get_ffmpeg_manager(self._hass).binary
        except ImportError:
            _LOGGER.debug("No Home Assistant ffmpeg component; using ffmpeg on PATH")
        except Exception:  # noqa: BLE001 - ffmpeg on PATH is a fine second choice
            _LOGGER.warning(
                "Could not read the ffmpeg binary from Home Assistant; falling "
                "back to 'ffmpeg' on PATH", exc_info=True,
            )
        return "ffmpeg"

    def _www_root(self) -> str:
        """Absolute path of the directory Home Assistant serves as /local."""
        config = getattr(self._hass, "config", None)
        path = getattr(config, "path", None)
        if callable(path):
            try:
                return str(path(WWW_DIRECTORY))
            except Exception:  # noqa: BLE001 - a wrong root only costs the URL
                _LOGGER.warning(
                    "Could not resolve the Home Assistant config directory; "
                    "assuming %s for snapshot URLs", DEFAULT_WWW_ROOT, exc_info=True,
                )
        return DEFAULT_WWW_ROOT

    # --- Value decoding ---

    def extract_image_url(
        self, raw_value: Any, definition: DPDefinition | None = None
    ) -> str | None:
        """Extract a cloud image URL from an event payload, if it carries one.

        Raw payloads are where these URLs live; a profile can mark any other
        datapoint as carrying one with ``carries_image_url``.
        """
        if definition is not None and not (
            definition.carries_image_url or definition.dp_type == DP_TYPE_RAW
        ):
            return None

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
            except Exception:  # noqa: BLE001 - the next decoder gets its turn
                _LOGGER.debug("Decoder %s could not read the payload", decoder.__name__)
        return None

    def _extract_image_url(
        self, raw_value: Any, definition: DPDefinition | None = None
    ) -> str | None:
        """Deprecated: use ``extract_image_url``."""
        return self.extract_image_url(raw_value, definition)

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
        if isinstance(value, (str, bytes)):
            try:
                data = json.loads(value)
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
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
        if not isinstance(value, (str, bytes)) or len(value) < 20:
            return None
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            data = json.loads(decoded)
        except Exception:  # noqa: BLE001 - not base64 JSON, the caller tries the next
            return None
        if isinstance(data, dict):
            for key in ("imgUrl", "image_url", "url", "pic"):
                if key in data:
                    return data[key]
        return None

    @staticmethod
    def _decode_bucket_path(value: Any) -> str | None:
        """Construct URL from bucket + path format."""
        data = value if isinstance(value, dict) else None
        if isinstance(value, (str, bytes)):
            try:
                data = json.loads(value)
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                return None

        if not isinstance(data, dict):
            return None

        bucket = data.get("bucket", "")
        path = data.get("path", "") or data.get("key", "")
        if bucket and path:
            return f"https://{bucket}.s3.amazonaws.com/{path}"

        return None

    # --- Events and plumbing ---

    def _fire_event(self, event_type: str, data: dict | None = None) -> None:
        """Fire a Home Assistant event."""
        event_data = {"device_id": self._device_id}
        if data:
            event_data.update(data)
        _LOGGER.debug("FireEvent: %s data=%s", event_type, event_data)
        self._hass.bus.async_fire(event_type, event_data)

    def _fire_device_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Fire an event under its stable name and its deprecated slug name.

        The slug comes from the editable device name, so an automation built on
        the slug name breaks the moment somebody renames the device. New
        automations listen for the stable name and filter on device_id.
        """
        self._fire_event(event_type, data)
        if DEPRECATED_SLUG_EVENTS:
            self._fire_event(f"{event_type}_{self._device_name_slug()}", data)

    def _device_name_slug(self) -> str:
        """Return a slugified device name for event naming."""
        return device_name_slug(self._device_name)

    def _option(self, key: str, default: Any = None) -> Any:
        """Read a setting: options win over entry data, then the default."""
        options = self._config_entry.options or {}
        if key in options:
            return options[key]
        data = self._config_entry.data or {}
        return data.get(key, default)

    def _spawn(
        self, coro: Coroutine[Any, Any, Any], name: str, *, track: bool = False
    ) -> asyncio.Task:
        """Start a background task that keeps a strong reference.

        ``asyncio.ensure_future`` without a reference is how a doorbell press
        could disappear entirely: the garbage collector is free to drop a task
        nobody holds, and the snapshot and its event went with it.
        """
        factory = getattr(self._config_entry, "async_create_background_task", None)
        if factory is not None:
            task = factory(self._hass, coro, f"{DOMAIN}_{name}")
        else:
            # No config entry helper: a bare loop (tests) or a very old core.
            task = asyncio.get_running_loop().create_task(coro, name=f"{DOMAIN}_{name}")

        if track:
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        return task

    def _call_later(self, delay: float, action: Callable[[Any], None]) -> Callable[[], None]:
        """Schedule a call on the event loop and return a cancel function."""
        try:
            from homeassistant.helpers.event import async_call_later
        except ImportError:  # running without Home Assistant, e.g. in tests
            handle = asyncio.get_running_loop().call_later(delay, action, None)
            return handle.cancel
        return async_call_later(self._hass, delay, action)

    async def _run_in_executor(self, func: Callable[..., Any], *args: Any) -> Any:
        """Run blocking filesystem work off the event loop."""
        runner = getattr(self._hass, "async_add_executor_job", None)
        if runner is not None:
            return await runner(func, *args)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args)
