"""Config flow for LSC Tuya Doorbell integration."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Iterable, Mapping, Sequence

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from . import video
from .const import (
    KNOWN_DPS_BY_FIRMWARE,
    infer_firmware_generation,
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
    CONF_SNAPSHOT_SOURCE_URL,
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
    DEVICE_TYPE_LABELS,
    DISCOVERY_SCAN_TIMEOUT,
    DOMAIN,
    DP_TYPE_BOOL,
    DP_TYPE_ENUM,
    DP_TYPE_INT,
    DP_TYPE_RAW,
    DP_TYPE_STRING,
    ENTITY_BINARY_SENSOR,
    ENTITY_NUMBER,
    ENTITY_SELECT,
    ENTITY_SENSOR,
    ENTITY_SWITCH,
    MAX_BUFFER_SECONDS,
    MAX_SNAPSHOT_DELAY_MS,
    MIN_BUFFER_SECONDS,
    ROLE_RECORD_SWITCH,
    ROLES,
)
from .discovery import DiscoveredDevice, async_discover_devices
from .protocol.connection import TuyaConnection
from .protocol.constants import (
    DecryptionError,
    FrameError,
    InvalidLocalKeyError,
    TuyaProtocolError,
    UnsupportedProtocolVersionError,
)

_LOGGER = logging.getLogger(__name__)

# The versions this integration can actually speak over TCP. A device may
# broadcast something else entirely -- see DiscoveredDevice.version_hint.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("3.3", "3.4", "3.5")

DEFAULT_PROTOCOL_VERSION = "3.3"

LOCAL_KEY_LENGTH = 16

# Sentinel for "this role is not assigned to any datapoint". voluptuous cannot
# express an empty selection in a dropdown, so it needs a value of its own.
ROLE_NONE = "__none__"

ENTITY_TYPES: tuple[str, ...] = (
    ENTITY_SWITCH,
    ENTITY_SENSOR,
    ENTITY_SELECT,
    ENTITY_NUMBER,
    ENTITY_BINARY_SENSOR,
)

DP_TYPES: tuple[str, ...] = (
    DP_TYPE_BOOL,
    DP_TYPE_INT,
    DP_TYPE_ENUM,
    DP_TYPE_STRING,
    DP_TYPE_RAW,
)

MENU_CONNECTION = "connection"
MENU_CAMERA = "camera_settings"
MENU_SNAPSHOTS = "snapshot_settings"
MENU_DATAPOINTS = "dp_list"
MENU_SCAN = "dp_scan_mode"
MENU_CAPTURE = "live_capture"
MENU_CAPTURE_REVIEW = "capture_review"
MENU_ROLES = "assign_roles"
MENU_FIRMWARE = "firmware_generation"
MENU_FINISH = "finish"

# Menu option ids double as step ids: Home Assistant dispatches a chosen menu
# entry straight to async_step_<option>.
MENU_OPTIONS: tuple[str, ...] = (
    MENU_CONNECTION,
    MENU_CAMERA,
    MENU_SNAPSHOTS,
    MENU_DATAPOINTS,
    MENU_SCAN,
    MENU_CAPTURE,
    MENU_CAPTURE_REVIEW,
    MENU_ROLES,
    MENU_FIRMWARE,
    MENU_FINISH,
)

# --- Navigation ------------------------------------------------------------
#
# Home Assistant has no conditional fields inside a form. A schema is built
# once on the server, handed to the frontend as one FORM result, and held there
# until submit; nothing pushes an update into an open dialog
# (``async_notify_flow_changed`` only re-renders a SHOW_PROGRESS step, see
# ``data_entry_flow.py``). "Show field X only when Y is chosen" is therefore
# always more than one step: ask the question, then show a follow-up carrying
# only the fields that apply.
#
# It has no back button either. A sub-step that wants to be leavable has to
# offer the way out itself, which is what this checkbox is. It is read before
# anything is written, so going back really does change nothing.
NAV_BACK = "back"

# The menu entry that ends the options flow. An options flow has to finish
# through async_create_entry, but the sub-steps do not have to be the ones
# doing it -- see LscTuyaDoorbellOptionsFlow._async_save_options.
NAV_FINISH = MENU_FINISH


def _with_back(schema: dict[Any, Any]) -> dict[Any, Any]:
    """Append the "back to the menu" escape to a sub-step schema."""
    schema[vol.Optional(NAV_BACK, default=False)] = bool
    return schema


def going_back(user_input: Mapping[str, Any] | None) -> bool:
    """Whether the user asked to leave this step without saving anything."""
    return bool(user_input and user_input.get(NAV_BACK))


# --- Where the video comes from --------------------------------------------

VIDEO_SOURCE_DIRECT = "direct"
VIDEO_SOURCE_RESTREAM = "restream"
VIDEO_SOURCES: tuple[str, ...] = (VIDEO_SOURCE_DIRECT, VIDEO_SOURCE_RESTREAM)

#: Form field only. The stored options say which route is in use all by
#: themselves, so there is nothing extra to persist.
CONF_VIDEO_SOURCE = "video_source"


def video_source_of(options: Mapping[str, Any]) -> str:
    """Which of the two routes the stored options already describe.

    A stream URL override is only ever set by someone who put a restreamer in
    front of the camera, so its presence is the answer -- no extra option to
    store, and nothing to keep in sync with the settings it describes.
    """
    if str(options.get(CONF_STREAM_URL_OVERRIDE) or "").strip():
        return VIDEO_SOURCE_RESTREAM
    return VIDEO_SOURCE_DIRECT


# --- Which snapshot settings a mode actually uses --------------------------


def snapshot_fields_for(mode: str) -> tuple[str, ...]:
    """The settings that mean something in this snapshot mode.

    Offering the buffer directory to someone running 'on demand' is offering a
    setting that is read and then ignored; the buffer is the only mode that
    keeps video around, and 'off' takes no pictures at all so it has nothing to
    be triggered by.
    """
    if mode == video.MODE_OFF:
        return ()
    if mode == video.MODE_BUFFER:
        return (
            CONF_SNAPSHOT_TRIGGER_DPS,
            CONF_STILL_IMAGE_URL_OVERRIDE,
            CONF_SNAPSHOT_SOURCE_URL,
            CONF_SNAPSHOT_BUFFER_PATH,
            CONF_SNAPSHOT_BUFFER_SECONDS,
            CONF_SNAPSHOT_DELAY_MS,
        )
    if mode == video.MODE_WARM:
        return (
            CONF_SNAPSHOT_TRIGGER_DPS,
            CONF_STILL_IMAGE_URL_OVERRIDE,
            CONF_SNAPSHOT_SOURCE_URL,
        )
    return (CONF_SNAPSHOT_TRIGGER_DPS, CONF_STILL_IMAGE_URL_OVERRIDE)


# --- Live capture pacing ---------------------------------------------------

#: How long each refresh of the live-capture screen waits. A progress step
#: resumes when its task finishes, so this is the redraw interval.
LIVE_CAPTURE_TICK_SECONDS = 2.0

#: Stop by ourselves once the device has gone quiet for this long. Only starts
#: counting after something has actually arrived: someone who opened the
#: capture and is still walking to the front door has reported nothing yet, and
#: cutting them off would be exactly the wrong moment.
LIVE_CAPTURE_IDLE_SECONDS = 120.0

#: And stop regardless after this long, so a forgotten session does not sit on
#: the connection forever.
LIVE_CAPTURE_MAX_SECONDS = 300.0

# Which diagnosis wins when several attempts failed for different reasons.
# A rejected key is the most actionable thing we can tell someone, so it is
# never hidden behind a generic "could not connect".
_ERROR_PRECEDENCE: tuple[str, ...] = (
    "invalid_local_key",
    "unsupported_protocol_version",
    "decryption_failed",
    "protocol_error",
    "heartbeat_failed",
    "timeout",
    "cannot_connect",
    "unknown",
)


def error_key_for(err: BaseException) -> str:
    """Translate an exception into the translation key that names the real cause.

    The protocol layer reports what went wrong instead of going quiet, so a
    rejected local key must not arrive at the user as "check the IP address".
    Order matters: InvalidLocalKeyError is also a ConnectionError.
    """
    if isinstance(err, InvalidLocalKeyError):
        return "invalid_local_key"
    if isinstance(err, UnsupportedProtocolVersionError):
        return "unsupported_protocol_version"
    if isinstance(err, DecryptionError):
        return "decryption_failed"
    if isinstance(err, FrameError):
        return "protocol_error"
    if isinstance(err, TimeoutError):
        return "timeout"
    if isinstance(err, ConnectionError):
        return "cannot_connect"
    if isinstance(err, TuyaProtocolError):
        return "protocol_error"
    return "unknown"


def worst_error(keys: Iterable[str]) -> str | None:
    """Pick the most informative of several failures, or None when there were none."""
    seen = set(keys)
    if not seen:
        return None
    for key in _ERROR_PRECEDENCE:
        if key in seen:
            return key
    return next(iter(seen))


def version_candidates(preferred: str | None) -> list[str]:
    """The preferred protocol version first, then the rest.

    A version read off a UDP broadcast is what the device claims, not what it
    speaks; trying the alternatives afterwards turns a dead end into a working
    connection without asking the user to guess.
    """
    ordered = [v for v in SUPPORTED_PROTOCOL_VERSIONS]
    if preferred in ordered:
        ordered.remove(preferred)
        return [preferred, *ordered]
    return ordered


def device_choice_options(
    devices: Sequence[DiscoveredDevice],
    configured_ids: Iterable[str] = (),
) -> dict[str, str]:
    """Build the discovery pick list, leaving out devices already set up.

    Offering an entry that can only ever abort with "already configured" is a
    dead end dressed up as a choice.
    """
    already = set(configured_ids)
    options = {
        device.device_id: (
            f"{DEVICE_TYPE_LABELS.get(device.device_type, device.device_type)} — "
            f"{device.device_id} ({device.ip}, reports v{device.version_hint})"
        )
        for device in devices
        if device.device_id not in already
    }
    options["manual"] = "Configure manually..."
    return options


def dp_label(dp: Any, *, suffix: str = "") -> str:
    """One line describing a discovered datapoint, as shown in a pick list."""
    name = getattr(dp, "name", None) or f"DP {dp.dp_id}"
    label = f"DP {dp.dp_id}: {name} ({dp.dp_type})"
    if getattr(dp, "looks_like_an_event", False):
        label += " ⟳"
    return label + suffix


def dp_choice_options(
    discovered: Sequence[Any],
    existing_ids: Iterable[int] = (),
) -> dict[str, str]:
    """Multi-select options for a set of discovered datapoints."""
    already = set(existing_ids)
    return {
        str(dp.dp_id): dp_label(
            dp, suffix=" [already configured]" if dp.dp_id in already else ""
        )
        for dp in discovered
    }


def snapshot_trigger_options(profile: Any | None) -> dict[str, str]:
    """Datapoints that may trigger a snapshot — strictly what the profile holds.

    This used to fall back to DP 185 and DP 115 when the profile was empty.
    Those two numbers are true for one model and invented for every other, so
    an empty profile now yields an empty list and the step points at the scan.
    """
    if profile is None:
        return {}
    return {
        str(dp_id): f"DP {dp_id}: {profile.discovered_dps[dp_id].name}"
        for dp_id in sorted(profile.discovered_dps)
    }


def capture_summary(found: Sequence[Any]) -> str:
    """One line listing what a live capture has seen, marking event candidates."""
    if not found:
        return "Nothing reported yet — press the doorbell to make it say something."
    return ", ".join(
        f"DP {dp.dp_id}" + (" ⟳" if getattr(dp, "looks_like_an_event", False) else "")
        for dp in found
    )


def safe_placeholder(text: str) -> str:
    """Make a string safe to hand to Home Assistant as a description placeholder.

    Placeholders are substituted by the frontend's message formatter, which
    treats ``{`` and ``}`` as its own syntax. Datapoint values are whatever the
    device felt like sending -- JSON payloads included -- so a raw value can
    blank out the entire screen it was meant to explain.
    """
    return text.replace("{", "(").replace("}", ")")


def short_value(value: Any, limit: int = 40) -> str:
    """One datapoint value, short enough to sit in a list of them."""
    text = repr(value)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return safe_placeholder(text)


def last_reported_dps(capture: Any, found: Sequence[Any]) -> set[int]:
    """The datapoints that moved most recently, so the screen can point at them.

    While hunting for the doorbell button you press it several times, and a
    press often lands several datapoints in one status frame. Without a marker
    a list of a dozen datapoints says nothing about which one just answered.

    ``LiveCapture`` has no "last seen" field yet; until it grows one this is
    derived from the observation timestamps, which gives the same answer
    because a whole frame is recorded with a single timestamp.
    """
    claimed = getattr(capture, "last_dp_ids", None)
    if claimed:
        return {int(dp_id) for dp_id in claimed}
    claimed_one = getattr(capture, "last_dp_id", None)
    if isinstance(claimed_one, int):
        return {claimed_one}

    latest: float | None = None
    for dp in found:
        observations = getattr(dp, "observations", None) or []
        if not observations:
            continue
        at = observations[-1].at
        if latest is None or at > latest:
            latest = at
    if latest is None:
        return set()
    return {
        dp.dp_id
        for dp in found
        if (getattr(dp, "observations", None) or [])
        and dp.observations[-1].at == latest
    }


def capture_detail(found: Sequence[Any], just_now: Iterable[int] = ()) -> str:
    """What every captured datapoint actually carried, newest activity marked.

    The numbers alone do not identify anything. What a datapoint carried is the
    evidence: a button reports a fresh payload per press, a setting reports one
    value and stays there, and a counter climbs.
    """
    if not found:
        return (
            "Nothing reported yet — press the doorbell, or toggle something in "
            "the Tuya app, to make the device say something."
        )

    marked = set(just_now)
    lines: list[str] = []
    for dp in found:
        values = getattr(dp, "distinct_values", None) or []
        shown = ", ".join(short_value(value) for value in values[:6])
        if len(values) > 6:
            shown += ", …"
        name = safe_placeholder(str(getattr(dp, "name", "") or dp.dp_type))
        count = len(getattr(dp, "observations", None) or [])
        line = f"- **DP {dp.dp_id}** ({name}) — {count}×: {shown or '—'}"
        if getattr(dp, "looks_like_an_event", False):
            line += " ⟳"
        if dp.dp_id in marked:
            line += "  ← just now"
        lines.append(line)
    return "\n".join(lines)


def capture_idle_seconds(found: Sequence[Any], now: float) -> float | None:
    """Seconds since the last thing arrived, or None when nothing has yet.

    None is not zero: it is the difference between "the device has gone quiet"
    and "the user has not reached the doorbell yet", and only the first is a
    reason to stop.
    """
    latest: float | None = None
    for dp in found:
        observations = getattr(dp, "observations", None) or []
        if not observations:
            continue
        at = observations[-1].at
        if latest is None or at > latest:
            latest = at
    if latest is None:
        return None
    return max(0.0, now - latest)


def capture_should_stop(
    found: Sequence[Any], elapsed: float, now: float
) -> str | None:
    """Why a capture should end by itself, or None to keep it running."""
    if elapsed >= LIVE_CAPTURE_MAX_SECONDS:
        return "time_limit"
    idle = capture_idle_seconds(found, now)
    if idle is not None and idle >= LIVE_CAPTURE_IDLE_SECONDS:
        return "gone_quiet"
    return None


def role_choice_options(
    discovered: Sequence[Any],
    profile: Any | None = None,
    *,
    clear_existing: bool = False,
) -> dict[str, str]:
    """Options for assigning one role to one datapoint, including "not assigned".

    Offers everything the device will have afterwards, not only what this round
    turned up. A second capture run to catch one missing datapoint would
    otherwise leave the roles pointing at datapoints the select cannot offer,
    and a select that cannot offer a value submits "not assigned" -- silently
    clearing roles the user set up earlier and never touched.

    With clear_existing the old datapoints are on their way out, so they are not
    offered: assigning a role to one would be assigning it to nothing.
    """
    options = {ROLE_NONE: "Not assigned"}
    options.update({str(dp.dp_id): dp_label(dp) for dp in discovered})

    if profile is not None and not clear_existing:
        chosen = {dp.dp_id for dp in discovered}
        for dp_id, definition in sorted(getattr(profile, "discovered_dps", {}).items()):
            if dp_id not in chosen:
                options[str(dp_id)] = dp_label(
                    definition, suffix=" — already configured"
                )

    return options


def suggested_role_dp(
    role: str,
    options: Mapping[str, str],
    current: Mapping[str, int] | None = None,
) -> str:
    """Pre-fill a role select: whatever the profile already says, else nothing.

    Deliberately does not guess from datapoint numbers. Guessing is what put
    two dead sensors on every doorbell that was not the author's.
    """
    if current and role in current:
        claimed = str(current[role])
        if claimed in options:
            return claimed
    return ROLE_NONE


def _select(
    options: Sequence[str], translation_key: str, *, multiple: bool = False
) -> SelectSelector:
    """A dropdown whose labels come from strings.json instead of being hardcoded."""
    return SelectSelector(
        SelectSelectorConfig(
            options=list(options),
            translation_key=translation_key,
            mode=SelectSelectorMode.DROPDOWN,
            multiple=multiple,
        )
    )


class LscTuyaDoorbellConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for LSC Tuya Doorbell."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovered_devices: dict[str, DiscoveredDevice] = {}
        self._discovery_task: asyncio.Task | None = None
        self._discovery_error: str | None = None
        self._selected_device: DiscoveredDevice | None = None
        self._device_id: str = ""
        self._local_key: str = ""
        self._host: str = ""
        self._port: int = DEFAULT_PORT
        self._version: str = DEFAULT_PROTOCOL_VERSION
        self._version_confirmed: bool = False
        self._device_name: str = ""
        self._onvif_password: str = ""
        self._existing_entry: ConfigEntry | None = None

    # --- Entry points ---

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 1: Start discovery or manual entry."""
        if user_input is not None:
            if user_input.get("method") == "manual":
                return await self.async_step_manual()
            return await self.async_step_discover()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("method", default="discover"): _select(
                        ("discover", "manual"), "setup_method"
                    ),
                }
            ),
        )

    async def async_step_discover(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Listen for Tuya broadcasts, with a spinner instead of a frozen dialog.

        Discovery goes through the shared manager: it owns UDP 6666/6667, and a
        second listener on a port it already holds hears nothing at all.
        """
        if self._discovery_task is None:
            self._discovery_task = self.hass.async_create_task(
                async_discover_devices(self.hass, timeout=float(DISCOVERY_SCAN_TIMEOUT)),
                name="lsc_tuya_doorbell config flow discovery",
            )

        if not self._discovery_task.done():
            return self.async_show_progress(
                step_id="discover",
                progress_action="discovering",
                progress_task=self._discovery_task,
            )

        return self.async_show_progress_done(next_step_id="pick_device")

    async def async_step_pick_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show what discovery found and let the user pick one.

        Named `pick_device` rather than `discovery`: the base class reserves
        `async_step_discovery` for a discovery source and passes it the
        discovery info, so overriding it with a different signature breaks the
        moment the manifest gains a discovery method.
        """
        if user_input is not None:
            selected_id = user_input.get("device")
            if selected_id in self._discovered_devices:
                self._selected_device = self._discovered_devices[selected_id]
                self._device_id = self._selected_device.device_id
                self._host = self._selected_device.ip
                # A hint, not a fact: shown as an editable default further on.
                self._version = self._selected_device.version_hint
                self._version_confirmed = self._selected_device.version_confirmed
                return await self.async_step_credentials()
            return await self.async_step_manual()

        devices, error = self._collect_discovery_result()
        configured = self._configured_device_ids()
        options = device_choice_options(devices, configured)
        selectable = len(options) - 1  # "manual" is not a device

        # Only pre-select "configure manually" when there is nothing else to pick.
        device_key = (
            vol.Required("device", default="manual")
            if not selectable
            else vol.Required("device")
        )

        return self.async_show_form(
            step_id="pick_device",
            data_schema=vol.Schema({device_key: vol.In(options)}),
            errors={"base": error} if error else {},
            description_placeholders={
                "count": str(selectable),
                "skipped": str(len(devices) - selectable),
            },
        )

    def _collect_discovery_result(self) -> tuple[list[DiscoveredDevice], str | None]:
        """Read the finished discovery task, remembering what it found."""
        task = self._discovery_task
        if task is None or not task.done():
            return [], None

        error = task.exception()
        if error is not None:
            _LOGGER.warning(
                "Device discovery failed (%s). Add the doorbell manually with its "
                "IP address and device ID from the Tuya developer portal.",
                error,
            )
            return [], "discovery_failed"

        devices = list(task.result())
        self._discovered_devices = {d.device_id: d for d in devices}
        _LOGGER.debug("Config flow discovery found %d device(s)", len(devices))
        return devices, None

    def _configured_device_ids(self) -> set[str]:
        """Device IDs that already have a config entry."""
        return {
            entry.unique_id or entry.data.get(CONF_DEVICE_ID, "")
            for entry in self._async_current_entries()
        }

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manual device configuration."""
        if user_input is not None:
            self._host = user_input[CONF_HOST]
            self._device_id = user_input[CONF_DEVICE_ID]
            self._port = user_input.get(CONF_PORT, DEFAULT_PORT)
            self._version = user_input.get(
                CONF_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION
            )
            return await self.async_step_credentials()

        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST): str,
                    vol.Required(CONF_DEVICE_ID): str,
                    vol.Optional(CONF_PORT, default=DEFAULT_PORT): vol.Coerce(int),
                    vol.Optional(
                        CONF_PROTOCOL_VERSION, default=DEFAULT_PROTOCOL_VERSION
                    ): vol.In(list(SUPPORTED_PROTOCOL_VERSIONS)),
                }
            ),
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 2: Enter credentials and confirm the protocol version."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._local_key = user_input[CONF_LOCAL_KEY].strip()
            self._device_name = user_input.get(CONF_DEVICE_NAME, self._device_id)
            self._onvif_password = user_input.get(CONF_ONVIF_PASSWORD, "")
            self._version = user_input.get(CONF_PROTOCOL_VERSION, self._version)

            if len(self._local_key) != LOCAL_KEY_LENGTH:
                errors[CONF_LOCAL_KEY] = "invalid_local_key_length"
            else:
                return await self.async_step_connect()

        return self._credentials_form(errors)

    def _credentials_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        """The credentials form, reused after a failed connection test."""
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_LOCAL_KEY, default=self._local_key): str,
                    vol.Optional(
                        CONF_DEVICE_NAME,
                        default=self._device_name or self._device_id,
                    ): str,
                    vol.Optional(
                        CONF_ONVIF_PASSWORD, default=self._onvif_password
                    ): str,
                    vol.Required(
                        CONF_PROTOCOL_VERSION, default=self._version
                    ): vol.In(list(SUPPORTED_PROTOCOL_VERSIONS)),
                }
            ),
            errors=errors,
            description_placeholders={
                "device_id": self._device_id,
                "host": self._host,
                "version": self._version,
                "version_source": (
                    "confirmed by a successful handshake"
                    if self._version_confirmed
                    else "as announced by the device, which is often wrong"
                ),
            },
        )

    async def async_step_connect(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 3: Test the connection, then create the entry."""
        # Outside the connection test on purpose. _abort_if_unique_id_configured
        # raises AbortFlow, which inherits from Exception; inside a broad
        # `except Exception` it was swallowed and re-surfaced as "an unexpected
        # error occurred", forever, while the correct "already configured"
        # message was never reachable.
        await self.async_set_unique_id(self._device_id)
        self._abort_if_unique_id_configured()

        version, error = await self._async_test_connection()
        if error is not None:
            return self._credentials_form({"base": error})

        self._version = version or self._version
        self._version_confirmed = True

        data = {
            CONF_DEVICE_ID: self._device_id,
            CONF_LOCAL_KEY: self._local_key,
            CONF_HOST: self._host,
            CONF_PORT: self._port,
            CONF_PROTOCOL_VERSION: self._version,
            CONF_DEVICE_NAME: self._device_name,
        }
        if self._onvif_password:
            data[CONF_ONVIF_PASSWORD] = self._onvif_password
        return self.async_create_entry(title=self._device_name, data=data)

    async def _async_test_connection(self) -> tuple[str | None, str | None]:
        """Try the chosen protocol version, then the others.

        Returns (working_version, None) or (None, error_translation_key). Every
        candidate is tried because devices routinely announce a version they do
        not speak; the user is told which one actually worked.
        """
        failures: list[str] = []
        candidates = version_candidates(self._version)

        for version in candidates:
            conn = TuyaConnection(
                self._host, self._port, self._device_id, self._local_key, version
            )
            try:
                await conn.connect()
                if not await conn.heartbeat():
                    _LOGGER.debug("Protocol %s: no heartbeat response", version)
                    failures.append("heartbeat_failed")
                    continue
                await conn.query_dps()
            except Exception as err:  # noqa: BLE001 - mapped to a user-facing cause
                key = error_key_for(err)
                if key == "unknown":
                    _LOGGER.warning(
                        "Connection test to %s:%s with protocol %s failed in an "
                        "unexpected way: %s",
                        self._host,
                        self._port,
                        version,
                        err,
                        exc_info=True,
                    )
                else:
                    _LOGGER.debug(
                        "Protocol %s failed: %s (%s)", version, err, key
                    )
                failures.append(key)
                continue
            finally:
                await conn.disconnect()

            if version != candidates[0]:
                _LOGGER.info(
                    "Device %s does not speak protocol %s but does speak %s; "
                    "using %s",
                    self._device_id,
                    self._version,
                    version,
                    version,
                )
            return version, None

        return None, worst_error(failures) or "cannot_connect"

    # --- Reauth / reconfigure ---

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Tuya rotates the local key whenever a device is re-paired.

        Without this step the only way out was deleting the entry and adding it
        again, which renames every entity.
        """
        self._existing_entry = self._entry_from_context()
        if self._existing_entry is None:
            return self.async_abort(reason="entry_not_found")
        self._load_from_entry(self._existing_entry)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for a fresh local key and prove it works before storing it."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._local_key = user_input[CONF_LOCAL_KEY].strip()
            if len(self._local_key) != LOCAL_KEY_LENGTH:
                errors[CONF_LOCAL_KEY] = "invalid_local_key_length"
            else:
                version, error = await self._async_test_connection()
                if error is None:
                    return await self._async_apply_to_entry(
                        {
                            CONF_LOCAL_KEY: self._local_key,
                            CONF_PROTOCOL_VERSION: version or self._version,
                        },
                        reason="reauth_successful",
                    )
                errors["base"] = error

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_LOCAL_KEY): str}),
            errors=errors,
            description_placeholders={
                "device_id": self._device_id,
                "host": self._host,
                "name": self._device_name,
            },
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change host, port, protocol version and local key without re-adding."""
        self._existing_entry = self._entry_from_context()
        if self._existing_entry is None:
            return self.async_abort(reason="entry_not_found")

        errors: dict[str, str] = {}
        if user_input is None:
            self._load_from_entry(self._existing_entry)
        else:
            self._host = user_input[CONF_HOST]
            self._port = user_input.get(CONF_PORT, DEFAULT_PORT)
            self._version = user_input.get(
                CONF_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION
            )
            self._local_key = user_input[CONF_LOCAL_KEY].strip()

            if len(self._local_key) != LOCAL_KEY_LENGTH:
                errors[CONF_LOCAL_KEY] = "invalid_local_key_length"
            else:
                version, error = await self._async_test_connection()
                if error is None:
                    return await self._async_apply_to_entry(
                        {
                            CONF_HOST: self._host,
                            CONF_PORT: self._port,
                            CONF_LOCAL_KEY: self._local_key,
                            CONF_PROTOCOL_VERSION: version or self._version,
                        },
                        reason="reconfigure_successful",
                    )
                errors["base"] = error

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST, default=self._host): str,
                    vol.Required(CONF_PORT, default=self._port): vol.Coerce(int),
                    vol.Required(CONF_LOCAL_KEY, default=self._local_key): str,
                    vol.Required(
                        CONF_PROTOCOL_VERSION, default=self._version
                    ): vol.In(list(SUPPORTED_PROTOCOL_VERSIONS)),
                }
            ),
            errors=errors,
            description_placeholders={"device_id": self._device_id},
        )

    def _entry_from_context(self) -> ConfigEntry | None:
        """The entry a reauth or reconfigure flow was started for."""
        entry_id = self.context.get("entry_id")
        if entry_id is None:
            _LOGGER.error(
                "Flow started without an entry_id in its context; there is "
                "nothing to re-authenticate or reconfigure"
            )
            return None
        return self.hass.config_entries.async_get_entry(entry_id)

    def _load_from_entry(self, entry: ConfigEntry) -> None:
        """Seed the flow state from an existing config entry."""
        self._device_id = entry.data.get(CONF_DEVICE_ID, "")
        self._host = entry.data.get(CONF_HOST, "")
        self._port = entry.data.get(CONF_PORT, DEFAULT_PORT)
        self._version = entry.data.get(
            CONF_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION
        )
        self._local_key = entry.data.get(CONF_LOCAL_KEY, "")
        self._device_name = entry.data.get(CONF_DEVICE_NAME, self._device_id)

    async def _async_apply_to_entry(
        self, updates: dict[str, Any], *, reason: str
    ) -> ConfigFlowResult:
        """Write verified settings back onto the existing entry and reload it."""
        entry = self._existing_entry
        if entry is None:
            return self.async_abort(reason="entry_not_found")
        self.hass.config_entries.async_update_entry(
            entry, data={**entry.data, **updates}
        )
        await self.hass.config_entries.async_reload(entry.entry_id)
        return self.async_abort(reason=reason)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Create the options flow."""
        return LscTuyaDoorbellOptionsFlow(config_entry)


class LscTuyaDoorbellOptionsFlow(OptionsFlow):
    """Handle options for LSC Tuya Doorbell."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._config_entry = config_entry
        self._editing_dp_id: int | None = None
        self._scan_clear_existing: bool = False
        self._scan_progress_shown: bool = False
        # Datapoints the user picked, carried into the role assignment step.
        self._pending_dps: list[Any] = []
        self._pending_clear_existing: bool = False
        # Answers to a "which kind is this?" step, carried into its follow-up.
        self._pending_video_source: str = VIDEO_SOURCE_DIRECT
        self._pending_camera: dict[str, Any] = {}
        self._pending_snapshot_mode: str | None = None

    def _get_hub(self):
        """Get the DeviceHub for this config entry."""
        if self.hass is None:
            return None
        return self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)

    @callback
    def async_remove(self) -> None:
        """Clean up when the dialog goes away.

        Closing the dialog is the documented way to end a live capture, so this
        is the normal path and not an edge case. What the session saw lives on
        the hub, not in this flow, so stopping it here loses nothing: "Review
        capture results" picks it up again afterwards.

        ``LiveCapture.stop()`` only unregisters a listener, so there is nothing
        to await -- which matters, because this hook is a callback and cannot
        await anything. ``hub.async_stop_live_capture()`` is a coroutine around
        that same call and would need a task scheduled for no benefit at all.
        """
        hub = self._get_hub()
        capture = getattr(hub, "live_capture", None) if hub is not None else None
        if capture is not None and capture.running:
            _LOGGER.debug("Options dialog closed; stopping the live capture")
            capture.stop()

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Main menu.

        A menu rather than a dropdown of hardcoded English strings: menu entries
        are translated from strings.json, a vol.In mapping is not.
        """
        return self.async_show_menu(step_id="init", menu_options=list(MENU_OPTIONS))

    async def async_step_finish(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Close the dialog.

        Everything a sub-step changed was already written when it was submitted,
        so this hands back the options exactly as they stand: Home Assistant
        stores them again, sees no difference, and does not reload.
        """
        return self.async_create_entry(title="", data=dict(self._config_entry.options))

    async def _async_save_options(
        self, new_options: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Store options and stay in the flow, instead of closing the dialog.

        An options flow saves by ending: ``async_create_entry`` hands its data
        to ``OptionsFlowManager.async_finish_flow``, which does nothing more
        than ``async_update_entry(entry, options=...)``. Calling that ourselves
        is the same write without the ending, which is what lets editing three
        datapoints in a row be three submits instead of three trips through the
        integration page. The flow still ends properly, via the menu's "Close".
        """
        self.hass.config_entries.async_update_entry(
            self._config_entry, options=dict(new_options)
        )
        return await self.async_step_init()

    # --- Connection ---

    async def async_step_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Connection settings (host, port, protocol)."""
        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            new_data = dict(self._config_entry.data)
            for key in (CONF_HOST, CONF_PORT, CONF_PROTOCOL_VERSION):
                if key in user_input:
                    new_data[key] = user_input[key]

            self.hass.config_entries.async_update_entry(
                self._config_entry, data=new_data
            )
            return await self.async_step_init()

        current = self._config_entry.data
        return self.async_show_form(
            step_id="connection",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            CONF_HOST, default=current.get(CONF_HOST, "")
                        ): str,
                        vol.Optional(
                            CONF_PORT, default=current.get(CONF_PORT, DEFAULT_PORT)
                        ): vol.Coerce(int),
                        vol.Optional(
                            CONF_PROTOCOL_VERSION,
                            default=current.get(
                                CONF_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION
                            ),
                        ): vol.In(list(SUPPORTED_PROTOCOL_VERSIONS)),
                    }
                )
            ),
        )

    # --- Camera ---

    async def async_step_camera_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask where the video comes from, before asking anything about it.

        Host/port/path and a stream URL override describe two different setups
        and only one of them can win, but the old single form offered all of
        them at once -- so it was possible to fill in an RTSP path, save, and
        wonder why an override entered months earlier was still being used.
        Asking first means the follow-up can show only what applies.
        """
        opts = self._config_entry.options

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            self._pending_video_source = user_input.get(
                CONF_VIDEO_SOURCE, VIDEO_SOURCE_DIRECT
            )
            # Settings that apply either way, carried into the follow-up so the
            # whole screen is saved in one write instead of two reloads.
            self._pending_camera = {
                CONF_SNAPSHOT_PATH: user_input.get(
                    CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH
                ),
                CONF_FORCE_RECORD_ON: user_input.get(CONF_FORCE_RECORD_ON, False),
            }
            if self._pending_video_source == VIDEO_SOURCE_RESTREAM:
                return await self.async_step_camera_restream()
            return await self.async_step_camera_direct()

        return self.async_show_form(
            step_id="camera_settings",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Required(
                            CONF_VIDEO_SOURCE, default=video_source_of(opts)
                        ): _select(VIDEO_SOURCES, "video_source"),
                        vol.Optional(
                            CONF_SNAPSHOT_PATH,
                            default=opts.get(
                                CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH
                            ),
                        ): str,
                        vol.Optional(
                            CONF_FORCE_RECORD_ON,
                            default=opts.get(CONF_FORCE_RECORD_ON, False),
                        ): bool,
                    }
                )
            ),
            description_placeholders={
                "record_role": self._role_state(ROLE_RECORD_SWITCH),
            },
        )

    def _role_state(self, role: str) -> str:
        """Whether a role is pointed at a datapoint, in words.

        'Force recording on' does nothing at all without the record_switch
        role, and there is no way to tell from the checkbox itself.
        """
        hub = self._get_hub()
        profile = getattr(hub, "profile", None) if hub is not None else None
        claimed = (getattr(profile, "roles", None) or {}).get(role)
        if claimed is None:
            return (
                "no datapoint has the 'record switch' role yet, so this "
                "setting will do nothing"
            )
        return f"the 'record switch' role points at DP {claimed}"

    async def async_step_camera_direct(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """The camera's own RTSP server: host from the connection, plus port and path."""
        opts = self._config_entry.options
        data = self._config_entry.data

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            new_options = dict(opts)
            new_options.update(self._pending_camera)
            new_options[CONF_ONVIF_USERNAME] = user_input.get(
                CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME
            )
            new_options[CONF_ONVIF_PASSWORD] = user_input.get(CONF_ONVIF_PASSWORD, "")
            new_options[CONF_RTSP_PORT] = user_input.get(
                CONF_RTSP_PORT, DEFAULT_RTSP_PORT
            )
            new_options[CONF_RTSP_PATH] = user_input.get(
                CONF_RTSP_PATH, DEFAULT_RTSP_PATH
            )
            # Choosing this route is choosing against the other one. Leaving a
            # stream override in place would keep it winning over everything
            # just entered here, which is the confusion this split exists for.
            new_options[CONF_STREAM_URL_OVERRIDE] = ""
            return await self._async_save_options(new_options)

        return self.async_show_form(
            step_id="camera_direct",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            CONF_ONVIF_USERNAME,
                            default=opts.get(
                                CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME
                            ),
                        ): str,
                        vol.Optional(
                            CONF_ONVIF_PASSWORD,
                            default=opts.get(
                                CONF_ONVIF_PASSWORD, data.get(CONF_ONVIF_PASSWORD, "")
                            ),
                        ): str,
                        vol.Optional(
                            CONF_RTSP_PORT,
                            default=opts.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT),
                        ): vol.Coerce(int),
                        vol.Optional(
                            CONF_RTSP_PATH,
                            default=opts.get(CONF_RTSP_PATH, DEFAULT_RTSP_PATH),
                        ): str,
                    }
                )
            ),
            description_placeholders={"host": data.get(CONF_HOST, "?")},
        )

    async def async_step_camera_restream(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """A restreamer in front of the camera: one URL replaces host, port and path."""
        opts = self._config_entry.options
        errors: dict[str, str] = {}

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            stream_url = user_input.get(CONF_STREAM_URL_OVERRIDE, "").strip()
            if not stream_url:
                # Saving an empty override here would silently put the device
                # back on the direct route it was just moved off.
                errors[CONF_STREAM_URL_OVERRIDE] = "stream_url_required"
            else:
                new_options = dict(opts)
                new_options.update(self._pending_camera)
                new_options[CONF_STREAM_URL_OVERRIDE] = stream_url
                return await self._async_save_options(new_options)

        return self.async_show_form(
            step_id="camera_restream",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            CONF_STREAM_URL_OVERRIDE,
                            default=(user_input or {}).get(
                                CONF_STREAM_URL_OVERRIDE,
                                opts.get(CONF_STREAM_URL_OVERRIDE, ""),
                            ),
                        ): str,
                    }
                )
            ),
            errors=errors,
        )

    # --- Snapshots ---

    async def async_step_snapshot_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask which snapshot mode applies, before asking about the mode's settings.

        The four modes need different things -- 'off' needs nothing, only
        'buffer' keeps video around -- and showing all of them at once meant
        offering a buffer directory to someone who would never have a buffer.
        """
        opts = self._config_entry.options

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            mode = user_input[CONF_SNAPSHOT_MODE]
            if not snapshot_fields_for(mode):
                # 'off' has nothing left to ask, so do not invent a screen.
                new_options = dict(opts)
                new_options[CONF_SNAPSHOT_MODE] = mode
                return await self._async_save_options(new_options)
            self._pending_snapshot_mode = mode
            return await self.async_step_snapshot_options()

        return self.async_show_form(
            step_id="snapshot_settings",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Required(
                            CONF_SNAPSHOT_MODE,
                            default=opts.get(
                                CONF_SNAPSHOT_MODE, video.DEFAULT_SNAPSHOT_MODE
                            ),
                        ): _select(video.SNAPSHOT_MODES, "snapshot_mode"),
                    }
                )
            ),
        )

    async def async_step_snapshot_options(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """The settings the chosen snapshot mode actually reads."""
        opts = self._config_entry.options
        mode = self._pending_snapshot_mode
        if mode is None:
            # Nothing was chosen, so there is nothing to configure. Reachable
            # only by URL-poking a step id; ask the question again.
            return await self.async_step_snapshot_settings()

        fields = snapshot_fields_for(mode)
        hub = self._get_hub()
        trigger_options = snapshot_trigger_options(
            getattr(hub, "profile", None) if hub is not None else None
        )

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            new_options = dict(opts)
            new_options[CONF_SNAPSHOT_MODE] = mode
            # Absent because there was nothing to choose from: keep what is
            # stored rather than silently clearing the user's triggers.
            if CONF_SNAPSHOT_TRIGGER_DPS in fields and trigger_options:
                new_options[CONF_SNAPSHOT_TRIGGER_DPS] = user_input.get(
                    CONF_SNAPSHOT_TRIGGER_DPS, []
                )
            if CONF_STILL_IMAGE_URL_OVERRIDE in fields:
                new_options[CONF_STILL_IMAGE_URL_OVERRIDE] = user_input.get(
                    CONF_STILL_IMAGE_URL_OVERRIDE, ""
                ).strip()

            if CONF_SNAPSHOT_SOURCE_URL in fields:
                new_options[CONF_SNAPSHOT_SOURCE_URL] = user_input.get(
                    CONF_SNAPSHOT_SOURCE_URL, ""
                ).strip()

            if CONF_SNAPSHOT_BUFFER_PATH in fields:
                new_options[CONF_SNAPSHOT_BUFFER_PATH] = user_input[
                    CONF_SNAPSHOT_BUFFER_PATH
                ].strip()
                new_options[CONF_SNAPSHOT_BUFFER_SECONDS] = int(
                    user_input[CONF_SNAPSHOT_BUFFER_SECONDS]
                )
                new_options[CONF_SNAPSHOT_DELAY_MS] = int(
                    user_input[CONF_SNAPSHOT_DELAY_MS]
                )
            return await self._async_save_options(new_options)

        schema: dict[Any, Any] = {}
        if CONF_SNAPSHOT_TRIGGER_DPS in fields and trigger_options:
            schema[
                vol.Optional(
                    CONF_SNAPSHOT_TRIGGER_DPS,
                    default=self._current_triggers(trigger_options),
                )
            ] = cv.multi_select(trigger_options)
        if CONF_STILL_IMAGE_URL_OVERRIDE in fields:
            schema[
                vol.Optional(
                    CONF_STILL_IMAGE_URL_OVERRIDE,
                    default=opts.get(CONF_STILL_IMAGE_URL_OVERRIDE, ""),
                )
            ] = str
        if CONF_SNAPSHOT_SOURCE_URL in fields:
            schema[
                vol.Optional(
                    CONF_SNAPSHOT_SOURCE_URL,
                    default=opts.get(CONF_SNAPSHOT_SOURCE_URL, ""),
                )
            ] = str
        if CONF_SNAPSHOT_BUFFER_PATH in fields:
            schema[
                vol.Required(
                    CONF_SNAPSHOT_BUFFER_PATH,
                    default=opts.get(
                        CONF_SNAPSHOT_BUFFER_PATH, video.DEFAULT_BUFFER_PATH
                    ),
                )
            ] = str
            schema[
                vol.Required(
                    CONF_SNAPSHOT_BUFFER_SECONDS,
                    default=opts.get(
                        CONF_SNAPSHOT_BUFFER_SECONDS, video.DEFAULT_BUFFER_SECONDS
                    ),
                )
            ] = NumberSelector(
                NumberSelectorConfig(
                    min=MIN_BUFFER_SECONDS,
                    max=MAX_BUFFER_SECONDS,
                    step=5,
                    mode=NumberSelectorMode.BOX,
                    unit_of_measurement="s",
                )
            )
            schema[
                vol.Required(
                    CONF_SNAPSHOT_DELAY_MS,
                    default=opts.get(
                        CONF_SNAPSHOT_DELAY_MS, video.DEFAULT_SNAPSHOT_DELAY_MS
                    ),
                )
            ] = NumberSelector(
                NumberSelectorConfig(
                    min=0,
                    max=MAX_SNAPSHOT_DELAY_MS,
                    step=100,
                    mode=NumberSelectorMode.BOX,
                    unit_of_measurement="ms",
                )
            )

        return self.async_show_form(
            step_id="snapshot_options",
            data_schema=vol.Schema(_with_back(schema)),
            description_placeholders={
                "mode": mode,
                "buffer_note": (
                    ""
                    if CONF_SNAPSHOT_BUFFER_PATH not in fields
                    else (
                        "\n\nThe buffer directory holds the recent video. /dev/shm "
                        "is RAM, so nothing is written to your SD card or SSD — but "
                        "Docker gives /dev/shm only 64 MB by default, which you "
                        "raise with shm_size. Budget roughly 15 MB per minute at "
                        "2 Mbit/s; 60 seconds is about "
                        + str(round(video.estimate_buffer_bytes(60) / (1024 * 1024)))
                        + " MB."
                    )
                ),
                "trigger_hint": (
                    ""
                    if trigger_options
                    else (
                        "\n\nNo datapoints are known for this device yet, so there "
                        "is nothing to trigger a snapshot on. Run 'Scan for "
                        "datapoints' or 'Live capture' first."
                    )
                ),
            },
        )

    def _current_triggers(self, trigger_options: Mapping[str, str]) -> list[str]:
        """The stored snapshot triggers, minus any the device no longer reports."""
        current = self._config_entry.options.get(CONF_SNAPSHOT_TRIGGER_DPS, [])
        if isinstance(current, str):
            # Legacy format: a comma-separated string.
            current = [x.strip() for x in current.split(",") if x.strip()]
        return [str(trigger) for trigger in current if str(trigger) in trigger_options]

    # --- Datapoint management ---

    async def async_step_dp_list(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show configured DPs as a selectable list."""
        hub = self._get_hub()

        if user_input is not None:
            selected = user_input.get("dp_select")
            if selected == "__back__":
                return await self.async_step_init()
            if selected == "__add__":
                return await self.async_step_dp_add()
            if selected is not None:
                self._editing_dp_id = int(selected)
                return await self.async_step_dp_edit()

        dp_options: dict[str, str] = {}
        if hub and hub.profile:
            for dp_id in sorted(hub.profile.discovered_dps):
                dp_def = hub.profile.discovered_dps[dp_id]
                role = hub.profile.role_of(dp_id)
                dp_options[str(dp_id)] = (
                    f"DP {dp_id}: {dp_def.name} ({dp_def.entity_type})"
                    + (f" [{role}]" if role else "")
                )

        dp_options["__add__"] = "Add new datapoint..."
        dp_options["__back__"] = "← Back to the options menu"
        count = len(dp_options) - 2

        return self.async_show_form(
            step_id="dp_list",
            data_schema=vol.Schema({vol.Required("dp_select"): vol.In(dp_options)}),
            description_placeholders={"count": str(count)},
        )

    async def async_step_dp_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit or delete a DP."""
        hub = self._get_hub()
        dp_id = self._editing_dp_id

        if dp_id is None or not hub or not hub.profile:
            return await self.async_step_dp_list()

        dp_def = hub.profile.discovered_dps.get(dp_id)
        if dp_def is None:
            return await self.async_step_dp_list()

        if going_back(user_input):
            return await self.async_step_dp_list()

        if user_input is not None:
            if user_input.get("delete", False):
                await hub.remove_dp(dp_id)
            else:
                await hub.update_dp(
                    dp_id,
                    name=user_input.get("name"),
                    entity_type=user_input.get("entity_type"),
                    is_event=user_input.get("is_event", False),
                )
            await self.hass.config_entries.async_reload(self._config_entry.entry_id)
            # Back to the list, not out of the dialog: editing datapoints is
            # something people do several of in a row, and closing after each
            # one meant reopening the options in between.
            return await self.async_step_dp_list()

        return self.async_show_form(
            step_id="dp_edit",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Required("name", default=dp_def.name): str,
                        vol.Required(
                            "entity_type", default=dp_def.entity_type
                        ): _select(ENTITY_TYPES, "entity_type"),
                        vol.Optional(
                            "is_event", default=dp_def.is_event
                        ): bool,
                        vol.Optional("delete", default=False): bool,
                    }
                )
            ),
            description_placeholders={
                "dp_id": str(dp_id),
                "name": dp_def.name,
                "role": hub.profile.role_of(dp_id) or "none",
            },
        )

    async def async_step_dp_add(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Add a new custom datapoint."""
        errors: dict[str, str] = {}
        hub = self._get_hub()

        if going_back(user_input):
            return await self.async_step_dp_list()

        if user_input is not None:
            dp_id = user_input["dp_id"]
            if hub is None:
                # Used to fall through and re-render the empty form, which read
                # as "nothing happened" while nothing had been saved.
                _LOGGER.warning(
                    "Cannot add DP %s: the integration is not loaded for %s. "
                    "Reload the entry and try again.",
                    dp_id,
                    self._config_entry.title,
                )
                errors["base"] = "hub_unavailable"
            elif hub.profile and dp_id in hub.profile.discovered_dps:
                errors["dp_id"] = "dp_already_exists"
            elif dp_id < 1 or dp_id > 255:
                errors["dp_id"] = "dp_id_out_of_range"
            else:
                await hub.add_manual_dp(
                    dp_id=dp_id,
                    name=user_input["name"],
                    dp_type=user_input["dp_type"],
                    entity_type=user_input["entity_type"],
                )
                await self.hass.config_entries.async_reload(
                    self._config_entry.entry_id
                )
                return await self.async_step_dp_list()

        return self.async_show_form(
            step_id="dp_add",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Required("dp_id"): vol.Coerce(int),
                        vol.Required("name"): str,
                        vol.Required("dp_type", default=DP_TYPE_BOOL): _select(
                            DP_TYPES, "dp_type"
                        ),
                        vol.Required("entity_type", default=ENTITY_SWITCH): _select(
                            ENTITY_TYPES, "entity_type"
                        ),
                    }
                )
            ),
            errors=errors,
        )

    # --- DP scan ---

    async def async_step_dp_scan_mode(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose scan mode before starting the scan.

        If a scan is already running, jump straight to the progress view.
        If results from a previous scan exist, show them with a force rescan option.
        """
        hub = self._get_hub()

        if going_back(user_input):
            return await self.async_step_init()

        if hub and hub.scan_running:
            return await self.async_step_dp_scan()

        if hub and hub.scan_results is not None and not hub.scan_running:
            if user_input is not None:
                if user_input.get("force_rescan"):
                    hub.reset_scan_state()
                    self._scan_clear_existing = user_input.get(
                        "clear_existing", False
                    )
                    return await self.async_step_dp_scan()
                return await self.async_step_dp_scan_results()

            return self.async_show_form(
                step_id="dp_scan_mode",
                data_schema=vol.Schema(
                    _with_back(
                        {
                            vol.Optional("force_rescan", default=False): bool,
                            vol.Optional("clear_existing", default=False): bool,
                        }
                    )
                ),
                description_placeholders={
                    "has_results": "true",
                    "found_count": str(len(hub.scan_results)),
                },
            )

        if user_input is not None:
            self._scan_clear_existing = user_input.get("clear_existing", False)
            return await self.async_step_dp_scan()

        return self.async_show_form(
            step_id="dp_scan_mode",
            data_schema=vol.Schema(
                _with_back({vol.Optional("clear_existing", default=False): bool})
            ),
            description_placeholders={"has_results": "false", "found_count": "0"},
        )

    async def async_step_dp_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Start DP scan — show progress spinner while scanning in background."""
        hub = self._get_hub()

        if not hub or not hub.available:
            return await self.async_step_dp_scan_failed()

        if not hub.scan_running and hub.scan_task is None:
            hub.reset_scan_state()
            hub.start_scan_task(self._run_dp_scan(hub))

        if hub.scan_running:
            self._scan_progress_shown = True
            return self.async_show_progress(
                step_id="dp_scan",
                progress_action="dp_scan",
                progress_task=hub.scan_task,
                description_placeholders=hub.scan_progress,
            )

        if self._scan_progress_shown:
            self._scan_progress_shown = False
            if hub.scan_error:
                return self.async_show_progress_done(next_step_id="dp_scan_failed")
            return self.async_show_progress_done(next_step_id="dp_scan_results")

        # The scan finished before a progress screen was ever shown.
        if hub.scan_error:
            return await self.async_step_dp_scan_failed()
        return await self.async_step_dp_scan_results()

    async def _run_dp_scan(self, hub) -> None:
        """Background task: run the actual DP discovery. Stores results on hub."""
        _LOGGER.info(
            "DP scan task started (clear_existing=%s)", self._scan_clear_existing
        )
        try:
            hub._scan_results = await hub.discover_dps()
            hub._scan_error = None
            _LOGGER.info(
                "DP scan task completed: found %d DPs", len(hub._scan_results)
            )
        except asyncio.CancelledError:
            # Cancellation is not a scan failure, it is this task being torn
            # down; swallowing it leaves the event loop believing it survived.
            hub._scan_results = []
            hub._scan_error = "scan_failed"
            _LOGGER.warning("DP scan task was cancelled")
            raise
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "DP scan timed out. The device answers slowly or dropped the "
                "connection; try again with the doorbell awake."
            )
            hub._scan_results = []
            hub._scan_error = "scan_timeout"
        except Exception as err:  # noqa: BLE001 - mapped to a user-facing cause
            key = error_key_for(err)
            if key == "unknown":
                _LOGGER.exception("DP scan failed with an unexpected error")
                key = "scan_failed"
            else:
                _LOGGER.warning("DP scan failed: %s (%s)", err, key)
            hub._scan_results = []
            hub._scan_error = key

    async def async_step_dp_scan_failed(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show why the scan failed, and offer a way out.

        This step used to render an empty form whose only button re-entered the
        same step: a dead end you could only leave by closing the dialog.
        """
        hub = self._get_hub()
        error = (hub.scan_error if hub else None) or (
            "device_unavailable" if not hub or not hub.available else "scan_failed"
        )

        if user_input is not None:
            if user_input.get("action") == "retry":
                if hub:
                    hub.reset_scan_state()
                return await self.async_step_dp_scan_mode()
            return await self.async_step_init()

        return self.async_show_form(
            step_id="dp_scan_failed",
            data_schema=vol.Schema(
                {
                    vol.Required("action", default="back"): _select(
                        ("retry", "back"), "scan_failed_action"
                    ),
                }
            ),
            errors={"base": error},
            description_placeholders={"count": "0"},
        )

    async def async_step_dp_scan_results(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show scan results and let the user pick which DPs to keep.

        Nothing is written to the profile before this point. The scan used to
        save itself first, so unticking a datapoint here still left an entity
        behind, and ticking one replaced its full definition with a bare stub.
        """
        hub = self._get_hub()
        if hub is None:
            return await self.async_step_dp_scan_failed()

        discovered = hub.scan_results or []

        if hub.scan_error:
            return await self.async_step_dp_scan_failed()

        existing_ids = set(hub.profile.discovered_dps) if hub.profile else set()
        dp_options = dp_choice_options(discovered, existing_ids)

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            selected_ids = set(user_input.get("selected_dps", []))
            self._pending_dps = [
                dp for dp in discovered if str(dp.dp_id) in selected_ids
            ]
            self._pending_clear_existing = self._scan_clear_existing
            if not self._pending_dps:
                return self.async_show_form(
                    step_id="dp_scan_results",
                    data_schema=vol.Schema(
                        _with_back(
                            {
                                vol.Optional(
                                    "selected_dps", default=[]
                                ): cv.multi_select(dp_options)
                            }
                        )
                    ),
                    errors={"base": "no_dps_selected"},
                    description_placeholders={"count": str(len(discovered))},
                )
            return await self.async_step_assign_roles()

        if not dp_options:
            return await self.async_step_dp_scan_failed()

        default_selected = [
            str(dp.dp_id) for dp in discovered if dp.dp_id not in existing_ids
        ]

        return self.async_show_form(
            step_id="dp_scan_results",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            "selected_dps", default=default_selected
                        ): cv.multi_select(dp_options),
                    }
                )
            ),
            description_placeholders={"count": str(len(discovered))},
        )


    async def async_step_firmware_generation(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose which datapoint-name table applies to this device.

        The two generations disagree about what several datapoints are called,
        and without knowing which one applies the integration falls back to the
        union of both -- where v5 wins every disagreement. That is how a v4
        device ends up showing two switches both called "Chime Switch".
        """
        hub = self._get_hub()
        if hub is None or hub.profile is None:
            return self.async_abort(reason="hub_unavailable")

        current = hub.profile.firmware_version
        suggested = infer_firmware_generation(hub.profile.discovered_dps) or ""

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            chosen = user_input.get("generation") or None
            changed = await hub.async_set_firmware_generation(chosen)
            _LOGGER.info(
                "Firmware generation set to %s; renamed %d datapoint(s)",
                chosen or "unknown", changed,
            )
            await self.hass.config_entries.async_reload(self._config_entry.entry_id)
            return await self.async_step_init()

        options = {"": "Unknown — use both tables"}
        options.update({gen: f"Generation {gen}" for gen in sorted(KNOWN_DPS_BY_FIRMWARE)})

        return self.async_show_form(
            step_id="firmware_generation",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            "generation", default=current or suggested or ""
                        ): vol.In(options),
                    }
                )
            ),
            description_placeholders={
                "current": current or "unknown",
                "suggested": suggested or "no clear match",
            },
        )

    # --- Live capture ---

    async def async_step_live_capture(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Record everything the device reports, refreshing the screen as it comes in.

        An event datapoint cannot be found by querying: it only carries a value
        at the moment someone presses the button. So the screen has to keep
        updating while the user is at the front door, and there is exactly one
        way to do that. A FORM is fetched once and held by the frontend until
        it is submitted; nothing pushes into it. A SHOW_PROGRESS step is the
        only result Home Assistant re-renders on its own, and it does so when
        its progress task finishes -- so a two-second sleep, replaced each
        round, is the refresh loop.

        The price is that a progress step takes no input, so there is no Stop
        button and closing the dialog is how you stop. That costs nothing,
        because the session lives on the hub: ``async_remove`` stops it and
        leaves what it saw for "Review capture results".
        """
        hub = self._get_hub()

        if hub is None or not hub.available:
            # Reachable only on the way in, straight from the menu, so a form
            # is still allowed here: once a progress step has been shown the
            # only legal successors are progress and progress-done.
            if user_input is not None:
                return await self.async_step_init()
            return self.async_show_form(
                step_id="live_capture",
                data_schema=vol.Schema(_with_back({})),
                errors={"base": "device_unavailable"},
            )

        capture = hub.live_capture
        if capture is None or not capture.running:
            try:
                capture = await hub.async_start_live_capture()
            except Exception as err:  # noqa: BLE001 - mapped to a user-facing cause
                _LOGGER.warning("Could not start a live capture: %s", err)
                if user_input is not None:
                    return await self.async_step_init()
                return self.async_show_form(
                    step_id="live_capture",
                    data_schema=vol.Schema(_with_back({})),
                    errors={"base": error_key_for(err)},
                )

        found = capture.found
        reason = capture_should_stop(found, capture.elapsed, time.time())
        if reason is not None:
            _LOGGER.info(
                "Live capture stopping by itself (%s) after %.0fs with %d "
                "datapoint(s)",
                reason,
                capture.elapsed,
                len(found),
            )
            await hub.async_stop_live_capture()
            return self.async_show_progress_done(next_step_id="capture_review")

        events = [dp for dp in found if dp.looks_like_an_event]
        # A fresh task every round: Home Assistant only re-registers its
        # "call me back when this finishes" callback when the task changed.
        tick = self.hass.async_create_task(
            asyncio.sleep(LIVE_CAPTURE_TICK_SECONDS),
            name=f"lsc_tuya_doorbell live capture refresh {self._config_entry.entry_id}",
        )
        return self.async_show_progress(
            step_id="live_capture",
            progress_action="live_capture",
            progress_task=tick,
            description_placeholders={
                "elapsed": str(int(capture.elapsed)),
                "count": str(len(found)),
                "detail": capture_detail(found, last_reported_dps(capture, found)),
                "events": ", ".join(f"DP {dp.dp_id}" for dp in events) or "none yet",
                "idle": str(int(LIVE_CAPTURE_IDLE_SECONDS)),
                "limit": str(int(LIVE_CAPTURE_MAX_SECONDS // 60)),
            },
        )

    async def async_step_capture_review(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick which of the captured datapoints to keep.

        Also a menu entry of its own, because closing the dialog is how a
        capture is stopped: without a way back to the results, stopping would
        throw away what the session had just spent minutes collecting.
        """
        hub = self._get_hub()
        if hub is None:
            return self.async_abort(reason="hub_unavailable")

        if going_back(user_input):
            return await self.async_step_init()

        capture = hub.live_capture
        if capture is not None and capture.running:
            # Arrived here from the menu while a session was still listening.
            await hub.async_stop_live_capture()

        if capture is None:
            return self.async_show_form(
                step_id="capture_review",
                data_schema=vol.Schema(_with_back({})),
                errors={"base": "no_capture_session"},
                description_placeholders={"count": "0", "detail": ""},
            )

        found = list(capture.found)
        existing_ids = set(hub.profile.discovered_dps) if hub.profile else set()
        dp_options = dp_choice_options(found, existing_ids)

        if user_input is not None:
            selected_ids = set(user_input.get("selected_dps", []))
            self._pending_dps = [dp for dp in found if str(dp.dp_id) in selected_ids]
            self._pending_clear_existing = False
            if not self._pending_dps:
                return self.async_show_form(
                    step_id="capture_review",
                    data_schema=vol.Schema(
                        _with_back(
                            {
                                vol.Optional(
                                    "selected_dps", default=[]
                                ): cv.multi_select(dp_options)
                            }
                        )
                    ),
                    errors={"base": "no_dps_selected"},
                    description_placeholders={
                        "count": str(len(found)),
                        "detail": capture_detail(found),
                    },
                )
            return await self.async_step_assign_roles()

        if not dp_options:
            return self.async_show_form(
                step_id="capture_review",
                data_schema=vol.Schema(_with_back({})),
                errors={"base": "capture_found_nothing"},
                description_placeholders={"count": "0", "detail": ""},
            )

        return self.async_show_form(
            step_id="capture_review",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            "selected_dps",
                            default=[
                                str(dp.dp_id)
                                for dp in found
                                if dp.dp_id not in existing_ids
                            ],
                        ): cv.multi_select(dp_options),
                    }
                )
            ),
            description_placeholders={
                "count": str(len(found)),
                "detail": capture_detail(found),
            },
        )

    # --- Roles ---

    async def async_step_assign_roles(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Say what the datapoints *do*.

        Reachable straight from the menu as well as at the end of a capture:
        deciding which datapoint is the button is a decision, not a side effect
        of discovering datapoints, and changing your mind should not require
        finding them all over again.

        The rest of the integration reads roles, not datapoint numbers, so a
        datapoint without a role is just a sensor: no doorbell, no motion.
        """
        hub = self._get_hub()
        if hub is None:
            return self.async_abort(reason="hub_unavailable")

        options = role_choice_options(
            self._pending_dps,
            hub.profile,
            clear_existing=self._pending_clear_existing,
        )
        current = dict(hub.profile.roles) if hub.profile else {}

        if going_back(user_input):
            return await self.async_step_init()

        if user_input is not None:
            roles: dict[str, int | None] = {}
            for role in ROLES:
                choice = user_input.get(role, ROLE_NONE)
                roles[role] = None if choice == ROLE_NONE else int(choice)

            await hub.async_apply_discovered_dps(
                self._pending_dps,
                clear_existing=self._pending_clear_existing,
                roles=roles,
            )
            await self.hass.config_entries.async_reload(self._config_entry.entry_id)
            return await self.async_step_init()

        return self.async_show_form(
            step_id="assign_roles",
            data_schema=vol.Schema(
                _with_back(
                    {
                        vol.Optional(
                            role,
                            default=suggested_role_dp(role, options, current),
                        ): vol.In(options)
                        for role in ROLES
                    }
                )
            ),
            description_placeholders={"count": str(len(self._pending_dps))},
        )
