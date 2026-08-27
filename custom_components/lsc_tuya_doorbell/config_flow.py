"""Config flow for LSC Tuya Doorbell integration."""

from __future__ import annotations

import asyncio
import logging
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

# Menu option ids double as step ids: Home Assistant dispatches a chosen menu
# entry straight to async_step_<option>.
MENU_OPTIONS: tuple[str, ...] = (
    MENU_CONNECTION,
    MENU_CAMERA,
    MENU_SNAPSHOTS,
    MENU_DATAPOINTS,
    MENU_SCAN,
    MENU_CAPTURE,
)

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

    def _get_hub(self):
        """Get the DeviceHub for this config entry."""
        return self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Main menu.

        A menu rather than a dropdown of hardcoded English strings: menu entries
        are translated from strings.json, a vol.In mapping is not.
        """
        return self.async_show_menu(step_id="init", menu_options=list(MENU_OPTIONS))

    # --- Connection ---

    async def async_step_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Connection settings (host, port, protocol)."""
        if user_input is not None:
            new_data = dict(self._config_entry.data)
            for key in (CONF_HOST, CONF_PORT, CONF_PROTOCOL_VERSION):
                if key in user_input:
                    new_data[key] = user_input[key]

            self.hass.config_entries.async_update_entry(
                self._config_entry, data=new_data
            )
            return self.async_create_entry(title="", data=self._config_entry.options)

        current = self._config_entry.data
        return self.async_show_form(
            step_id="connection",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_HOST, default=current.get(CONF_HOST, "")): str,
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
            ),
        )

    # --- Camera ---

    async def async_step_camera_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Camera / RTSP settings."""
        opts = self._config_entry.options
        data = self._config_entry.data
        hub = self._get_hub()
        trigger_options = snapshot_trigger_options(hub.profile if hub else None)

        if user_input is not None:
            new_options = dict(opts)
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
            new_options[CONF_STREAM_URL_OVERRIDE] = user_input.get(
                CONF_STREAM_URL_OVERRIDE, ""
            ).strip()
            new_options[CONF_STILL_IMAGE_URL_OVERRIDE] = user_input.get(
                CONF_STILL_IMAGE_URL_OVERRIDE, ""
            ).strip()
            new_options[CONF_SNAPSHOT_PATH] = user_input.get(
                CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH
            )
            new_options[CONF_FORCE_RECORD_ON] = user_input.get(
                CONF_FORCE_RECORD_ON, False
            )
            # Absent because there was nothing to choose from: keep what is
            # stored rather than silently clearing the user's triggers.
            if trigger_options:
                new_options[CONF_SNAPSHOT_TRIGGER_DPS] = user_input.get(
                    CONF_SNAPSHOT_TRIGGER_DPS, []
                )
            return self.async_create_entry(title="", data=new_options)

        current_triggers = opts.get(CONF_SNAPSHOT_TRIGGER_DPS, [])
        if isinstance(current_triggers, str):
            # Legacy format: a comma-separated string.
            current_triggers = [
                x.strip() for x in current_triggers.split(",") if x.strip()
            ]
        current_triggers = [t for t in current_triggers if t in trigger_options]

        schema: dict[Any, Any] = {
            vol.Optional(
                CONF_ONVIF_USERNAME,
                default=opts.get(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME),
            ): str,
            vol.Optional(
                CONF_ONVIF_PASSWORD,
                default=opts.get(
                    CONF_ONVIF_PASSWORD, data.get(CONF_ONVIF_PASSWORD, "")
                ),
            ): str,
            vol.Optional(
                CONF_RTSP_PORT, default=opts.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT)
            ): vol.Coerce(int),
            vol.Optional(
                CONF_RTSP_PATH, default=opts.get(CONF_RTSP_PATH, DEFAULT_RTSP_PATH)
            ): str,
            vol.Optional(
                CONF_STREAM_URL_OVERRIDE,
                default=opts.get(CONF_STREAM_URL_OVERRIDE, ""),
            ): str,
            vol.Optional(
                CONF_STILL_IMAGE_URL_OVERRIDE,
                default=opts.get(CONF_STILL_IMAGE_URL_OVERRIDE, ""),
            ): str,
            vol.Optional(
                CONF_SNAPSHOT_PATH,
                default=opts.get(CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH),
            ): str,
            vol.Optional(
                CONF_FORCE_RECORD_ON,
                default=opts.get(CONF_FORCE_RECORD_ON, False),
            ): bool,
        }
        if trigger_options:
            schema[
                vol.Optional(CONF_SNAPSHOT_TRIGGER_DPS, default=current_triggers)
            ] = cv.multi_select(trigger_options)

        return self.async_show_form(
            step_id="camera_settings",
            data_schema=vol.Schema(schema),
            description_placeholders={
                "trigger_hint": (
                    ""
                    if trigger_options
                    else (
                        "No datapoints are known for this device yet, so there is "
                        "nothing to trigger a snapshot. Run 'Scan for datapoints' "
                        "or 'Live capture' first."
                    )
                )
            },
        )

    # --- Snapshots ---

    async def async_step_snapshot_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """How snapshots are produced, and how far back they may reach."""
        opts = self._config_entry.options

        if user_input is not None:
            new_options = dict(opts)
            new_options[CONF_SNAPSHOT_MODE] = user_input[CONF_SNAPSHOT_MODE]
            new_options[CONF_SNAPSHOT_BUFFER_PATH] = user_input[
                CONF_SNAPSHOT_BUFFER_PATH
            ].strip()
            new_options[CONF_SNAPSHOT_BUFFER_SECONDS] = int(
                user_input[CONF_SNAPSHOT_BUFFER_SECONDS]
            )
            new_options[CONF_SNAPSHOT_DELAY_MS] = int(
                user_input[CONF_SNAPSHOT_DELAY_MS]
            )
            return self.async_create_entry(title="", data=new_options)

        return self.async_show_form(
            step_id="snapshot_settings",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SNAPSHOT_MODE,
                        default=opts.get(
                            CONF_SNAPSHOT_MODE, video.DEFAULT_SNAPSHOT_MODE
                        ),
                    ): _select(video.SNAPSHOT_MODES, "snapshot_mode"),
                    vol.Required(
                        CONF_SNAPSHOT_BUFFER_PATH,
                        default=opts.get(
                            CONF_SNAPSHOT_BUFFER_PATH, video.DEFAULT_BUFFER_PATH
                        ),
                    ): str,
                    vol.Required(
                        CONF_SNAPSHOT_BUFFER_SECONDS,
                        default=opts.get(
                            CONF_SNAPSHOT_BUFFER_SECONDS,
                            video.DEFAULT_BUFFER_SECONDS,
                        ),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=MIN_BUFFER_SECONDS,
                            max=MAX_BUFFER_SECONDS,
                            step=5,
                            mode=NumberSelectorMode.BOX,
                            unit_of_measurement="s",
                        )
                    ),
                    vol.Required(
                        CONF_SNAPSHOT_DELAY_MS,
                        default=opts.get(
                            CONF_SNAPSHOT_DELAY_MS, video.DEFAULT_SNAPSHOT_DELAY_MS
                        ),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=0,
                            max=MAX_SNAPSHOT_DELAY_MS,
                            step=100,
                            mode=NumberSelectorMode.BOX,
                            unit_of_measurement="ms",
                        )
                    ),
                }
            ),
            description_placeholders={
                "buffer_estimate": str(
                    round(video.estimate_buffer_bytes(60) / (1024 * 1024))
                ),
            },
        )

    # --- Datapoint management ---

    async def async_step_dp_list(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show configured DPs as a selectable list."""
        hub = self._get_hub()

        if user_input is not None:
            selected = user_input.get("dp_select")
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
        count = len(dp_options) - 1

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

        if user_input is not None:
            if user_input.get("delete", False):
                await hub.remove_dp(dp_id)
            else:
                await hub.update_dp(
                    dp_id,
                    name=user_input.get("name"),
                    entity_type=user_input.get("entity_type"),
                )
            await self.hass.config_entries.async_reload(self._config_entry.entry_id)
            return self.async_create_entry(title="", data=self._config_entry.options)

        return self.async_show_form(
            step_id="dp_edit",
            data_schema=vol.Schema(
                {
                    vol.Required("name", default=dp_def.name): str,
                    vol.Required(
                        "entity_type", default=dp_def.entity_type
                    ): _select(ENTITY_TYPES, "entity_type"),
                    vol.Optional("delete", default=False): bool,
                }
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
                return self.async_create_entry(
                    title="", data=self._config_entry.options
                )

        return self.async_show_form(
            step_id="dp_add",
            data_schema=vol.Schema(
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
                    {
                        vol.Optional("force_rescan", default=False): bool,
                        vol.Optional("clear_existing", default=False): bool,
                    }
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
                {vol.Optional("clear_existing", default=False): bool}
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
                        {
                            vol.Optional("selected_dps", default=[]): cv.multi_select(
                                dp_options
                            )
                        }
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
                {
                    vol.Optional(
                        "selected_dps", default=default_selected
                    ): cv.multi_select(dp_options),
                }
            ),
            description_placeholders={"count": str(len(discovered))},
        )

    # --- Live capture ---

    async def async_step_live_capture(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Record everything the device reports until the user says stop.

        Deliberately a repeating form and not async_show_progress: a progress
        step only resumes when its task finishes, and its single control is the
        close button, which aborts the flow. An event datapoint cannot be found
        by querying — it only carries a value at the moment someone presses the
        button — so the session has to last as long as the user needs.
        """
        hub = self._get_hub()
        if hub is None or not hub.available:
            return self.async_show_form(
                step_id="live_capture",
                data_schema=vol.Schema({vol.Optional("done", default=True): bool}),
                errors={"base": "device_unavailable"},
                description_placeholders={
                    "elapsed": "0",
                    "count": "0",
                    "summary": "",
                    "events": "",
                },
            )

        capture = hub.live_capture
        if capture is None or not capture.running:
            capture = await hub.async_start_live_capture()

        if user_input is not None and user_input.get("done"):
            await hub.async_stop_live_capture()
            return await self.async_step_capture_review()

        found = capture.found
        events = [dp for dp in found if dp.looks_like_an_event]
        return self.async_show_form(
            step_id="live_capture",
            data_schema=vol.Schema({vol.Optional("done", default=False): bool}),
            description_placeholders={
                "elapsed": str(int(capture.elapsed)),
                "count": str(len(found)),
                "summary": capture_summary(found),
                "events": ", ".join(f"DP {dp.dp_id}" for dp in events) or "none yet",
            },
        )

    async def async_step_capture_review(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick which of the captured datapoints to keep."""
        hub = self._get_hub()
        if hub is None:
            return self.async_abort(reason="hub_unavailable")

        capture = hub.live_capture
        found = list(capture.found) if capture else []
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
                        {
                            vol.Optional("selected_dps", default=[]): cv.multi_select(
                                dp_options
                            )
                        }
                    ),
                    errors={"base": "no_dps_selected"},
                    description_placeholders={"count": str(len(found))},
                )
            return await self.async_step_assign_roles()

        if not dp_options:
            return self.async_show_form(
                step_id="capture_review",
                data_schema=vol.Schema({}),
                errors={"base": "capture_found_nothing"},
                description_placeholders={"count": "0"},
            )

        return self.async_show_form(
            step_id="capture_review",
            data_schema=vol.Schema(
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
            ),
            description_placeholders={"count": str(len(found))},
        )

    # --- Roles ---

    async def async_step_assign_roles(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Say what the chosen datapoints *do*.

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
            return self.async_create_entry(title="", data=self._config_entry.options)

        return self.async_show_form(
            step_id="assign_roles",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        role,
                        default=suggested_role_dp(role, options, current),
                    ): vol.In(options)
                    for role in ROLES
                }
            ),
            description_placeholders={"count": str(len(self._pending_dps))},
        )
