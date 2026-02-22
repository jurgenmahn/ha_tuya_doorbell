"""Config flow for LSC Tuya Doorbell integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

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
    DEFAULT_ONVIF_USERNAME,
    DEFAULT_PORT,
    DEFAULT_RTSP_PATH,
    DEFAULT_RTSP_PORT,
    DEFAULT_SNAPSHOT_PATH,
    DEVICE_TYPE_LABELS,
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
)
from .discovery.udp_listener import DiscoveredDevice, UDPDiscoveryListener
from .protocol.connection import TuyaConnection

_LOGGER = logging.getLogger(__name__)


class LscTuyaDoorbellConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for LSC Tuya Doorbell."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovered_devices: dict[str, DiscoveredDevice] = {}
        self._selected_device: DiscoveredDevice | None = None
        self._device_id: str = ""
        self._local_key: str = ""
        self._host: str = ""
        self._port: int = DEFAULT_PORT
        self._version: str = "3.3"
        self._device_name: str = ""
        self._onvif_password: str = ""

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 1: Start discovery or manual entry."""
        if user_input is not None:
            if user_input.get("method") == "manual":
                return await self.async_step_manual()
            return await self.async_step_discovery()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("method", default="discover"): vol.In({
                    "discover": "Auto-discover devices on network",
                    "manual": "Manual configuration",
                }),
            }),
        )

    async def async_step_discovery(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Run UDP discovery and show found devices."""
        if user_input is not None:
            selected_id = user_input.get("device")
            if selected_id == "manual":
                return await self.async_step_manual()
            if selected_id in self._discovered_devices:
                self._selected_device = self._discovered_devices[selected_id]
                self._device_id = self._selected_device.device_id
                self._host = self._selected_device.ip
                self._version = self._selected_device.version
                return await self.async_step_credentials()
            return await self.async_step_manual()

        # Run UDP discovery
        _LOGGER.debug("ConfigFlow: starting UDP discovery scan (10s)")
        listener = UDPDiscoveryListener()
        devices = await listener.scan(timeout=10.0)
        _LOGGER.debug("ConfigFlow: discovery found %d device(s)", len(devices))

        if not devices:
            return self.async_show_form(
                step_id="discovery",
                data_schema=vol.Schema({
                    vol.Required("device", default="manual"): vol.In({
                        "manual": "No devices found — configure manually",
                    }),
                }),
                description_placeholders={"count": "0"},
            )

        self._discovered_devices = {d.device_id: d for d in devices}
        options = {
            d.device_id: (
                f"{DEVICE_TYPE_LABELS.get(d.device_type, d.device_type)} — "
                f"{d.device_id} ({d.ip}, v{d.version})"
            )
            for d in devices
        }
        options["manual"] = "Configure manually..."

        return self.async_show_form(
            step_id="discovery",
            data_schema=vol.Schema({
                vol.Required("device"): vol.In(options),
            }),
            description_placeholders={"count": str(len(devices))},
        )

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manual device configuration."""
        errors = {}

        if user_input is not None:
            self._host = user_input[CONF_HOST]
            self._device_id = user_input[CONF_DEVICE_ID]
            self._port = user_input.get(CONF_PORT, DEFAULT_PORT)
            self._version = user_input.get(CONF_PROTOCOL_VERSION, "3.3")
            return await self.async_step_credentials()

        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema({
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_DEVICE_ID): str,
                vol.Optional(CONF_PORT, default=DEFAULT_PORT): vol.Coerce(int),
                vol.Optional(CONF_PROTOCOL_VERSION, default="3.3"): vol.In(
                    {"3.3": "3.3", "3.4": "3.4", "3.5": "3.5"}
                ),
            }),
            errors=errors,
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: Enter credentials."""
        errors = {}

        if user_input is not None:
            self._local_key = user_input[CONF_LOCAL_KEY]
            self._device_name = user_input.get(CONF_DEVICE_NAME, self._device_id)
            self._onvif_password = user_input.get(CONF_ONVIF_PASSWORD, "")

            # Validate local key
            if len(self._local_key) != 16:
                errors[CONF_LOCAL_KEY] = "invalid_local_key"
            else:
                return await self.async_step_connect()

        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema({
                vol.Required(CONF_LOCAL_KEY): str,
                vol.Optional(CONF_DEVICE_NAME, default=self._device_id): str,
                vol.Optional(CONF_ONVIF_PASSWORD, default=""): str,
            }),
            errors=errors,
            description_placeholders={
                "device_id": self._device_id,
                "host": self._host,
                "version": self._version,
            },
        )

    async def async_step_connect(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 3: Test connection and run DP discovery."""
        errors = {}

        # Test connection
        _LOGGER.debug("ConfigFlow: testing connection to %s:%s (device=%s, version=%s)", self._host, self._port, self._device_id, self._version)
        conn = TuyaConnection(
            self._host, self._port, self._device_id, self._local_key, self._version
        )
        try:
            await conn.connect()
            _LOGGER.debug("ConfigFlow: connected, testing heartbeat")
            ok = await conn.heartbeat()
            if not ok:
                _LOGGER.debug("ConfigFlow: heartbeat failed")
                errors["base"] = "heartbeat_failed"
            else:
                # Quick DP query
                _LOGGER.debug("ConfigFlow: heartbeat OK, querying DPs")
                dps = await conn.query_dps()
                _LOGGER.debug("ConfigFlow: query returned %d DPs", len(dps) if dps else 0)
                await conn.disconnect()

                # Check unique ID
                await self.async_set_unique_id(self._device_id)
                self._abort_if_unique_id_configured()

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
                return self.async_create_entry(
                    title=self._device_name,
                    data=data,
                )
        except ConnectionError:
            errors["base"] = "cannot_connect"
        except Exception:
            _LOGGER.debug("Connection test failed", exc_info=True)
            errors["base"] = "unknown"
        finally:
            await conn.disconnect()

        if errors:
            return self.async_show_form(
                step_id="credentials",
                data_schema=vol.Schema({
                    vol.Required(CONF_LOCAL_KEY, default=self._local_key): str,
                    vol.Optional(CONF_DEVICE_NAME, default=self._device_name): str,
                    vol.Optional(CONF_ONVIF_PASSWORD, default=self._onvif_password): str,
                }),
                errors=errors,
                description_placeholders={
                    "device_id": self._device_id,
                    "host": self._host,
                    "version": self._version,
                },
            )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Create the options flow."""
        return LscTuyaDoorbellOptionsFlow(config_entry)


ENTITY_TYPE_OPTIONS = {
    ENTITY_SWITCH: "Switch",
    ENTITY_SENSOR: "Sensor",
    ENTITY_SELECT: "Select",
    ENTITY_NUMBER: "Number",
    ENTITY_BINARY_SENSOR: "Binary Sensor",
}

DP_TYPE_OPTIONS = {
    DP_TYPE_BOOL: "Boolean",
    DP_TYPE_INT: "Integer",
    DP_TYPE_ENUM: "Enum",
    DP_TYPE_STRING: "String",
    DP_TYPE_RAW: "Raw",
}

MENU_CONNECTION = "connection"
MENU_CAMERA = "camera"
MENU_DATAPOINTS = "datapoints"
MENU_SCAN = "scan"

MENU_OPTIONS = {
    MENU_CONNECTION: "Connection Settings",
    MENU_CAMERA: "Camera Settings",
    MENU_DATAPOINTS: "Manage Datapoints",
    MENU_SCAN: "Scan for Datapoints",
}


class LscTuyaDoorbellOptionsFlow(OptionsFlow):
    """Handle options for LSC Tuya Doorbell."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._config_entry = config_entry
        self._editing_dp_id: int | None = None
        self._scan_clear_existing: bool = False
        self._scan_progress_shown: bool = False

    def _get_hub(self):
        """Get the DeviceHub for this config entry."""
        return self.hass.data.get(DOMAIN, {}).get(self._config_entry.entry_id)

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Main menu: choose connection settings, manage DPs, or scan."""
        if user_input is not None:
            menu = user_input.get("menu")
            if menu == MENU_CONNECTION:
                return await self.async_step_connection()
            if menu == MENU_CAMERA:
                return await self.async_step_camera_settings()
            if menu == MENU_DATAPOINTS:
                return await self.async_step_dp_list()
            if menu == MENU_SCAN:
                return await self.async_step_dp_scan_mode()

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Required("menu", default=MENU_CONNECTION): vol.In(MENU_OPTIONS),
            }),
        )

    async def async_step_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Connection settings (host, port, protocol)."""
        if user_input is not None:
            new_data = dict(self._config_entry.data)
            if CONF_HOST in user_input:
                new_data[CONF_HOST] = user_input[CONF_HOST]
            if CONF_PORT in user_input:
                new_data[CONF_PORT] = user_input[CONF_PORT]
            if CONF_PROTOCOL_VERSION in user_input:
                new_data[CONF_PROTOCOL_VERSION] = user_input[CONF_PROTOCOL_VERSION]

            self.hass.config_entries.async_update_entry(
                self._config_entry, data=new_data
            )
            return self.async_create_entry(title="", data=self._config_entry.options)

        current = self._config_entry.data
        return self.async_show_form(
            step_id="connection",
            data_schema=vol.Schema({
                vol.Optional(
                    CONF_HOST, default=current.get(CONF_HOST, "")
                ): str,
                vol.Optional(
                    CONF_PORT, default=current.get(CONF_PORT, DEFAULT_PORT)
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_PROTOCOL_VERSION,
                    default=current.get(CONF_PROTOCOL_VERSION, "3.3"),
                ): vol.In({"3.3": "3.3", "3.4": "3.4", "3.5": "3.5"}),
            }),
        )

    async def async_step_camera_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Camera / RTSP settings."""
        if user_input is not None:
            # Store camera settings in options
            new_options = dict(self._config_entry.options)
            new_options[CONF_ONVIF_USERNAME] = user_input.get(
                CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME
            )
            new_options[CONF_ONVIF_PASSWORD] = user_input.get(
                CONF_ONVIF_PASSWORD, ""
            )
            new_options[CONF_RTSP_PORT] = user_input.get(
                CONF_RTSP_PORT, DEFAULT_RTSP_PORT
            )
            new_options[CONF_RTSP_PATH] = user_input.get(
                CONF_RTSP_PATH, DEFAULT_RTSP_PATH
            )
            new_options[CONF_SNAPSHOT_PATH] = user_input.get(
                CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH
            )
            return self.async_create_entry(title="", data=new_options)

        # Get current values from options or entry data
        opts = self._config_entry.options
        data = self._config_entry.data
        return self.async_show_form(
            step_id="camera_settings",
            data_schema=vol.Schema({
                vol.Optional(
                    CONF_ONVIF_USERNAME,
                    default=opts.get(CONF_ONVIF_USERNAME, DEFAULT_ONVIF_USERNAME),
                ): str,
                vol.Optional(
                    CONF_ONVIF_PASSWORD,
                    default=opts.get(
                        CONF_ONVIF_PASSWORD,
                        data.get(CONF_ONVIF_PASSWORD, ""),
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
                vol.Optional(
                    CONF_SNAPSHOT_PATH,
                    default=opts.get(CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH),
                ): str,
            }),
        )

    async def async_step_dp_list(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show configured DPs as a selectable list."""
        hub = self._get_hub()

        if user_input is not None:
            selected = user_input.get("dp_select")
            if selected == "__add__":
                return await self.async_step_dp_add()
            if selected is not None:
                self._editing_dp_id = int(selected)
                return await self.async_step_dp_edit()

        # Build list of DPs from profile
        dp_options: dict[str, str] = {}
        if hub and hub.profile:
            for dp_id in sorted(hub.profile.discovered_dps):
                dp_def = hub.profile.discovered_dps[dp_id]
                dp_options[str(dp_id)] = (
                    f"DP {dp_id}: {dp_def.name} ({dp_def.entity_type})"
                )

        dp_options["__add__"] = "Add new datapoint..."
        count = len(dp_options) - 1  # exclude the "add" option

        return self.async_show_form(
            step_id="dp_list",
            data_schema=vol.Schema({
                vol.Required("dp_select"): vol.In(dp_options),
            }),
            description_placeholders={"count": str(count)},
        )

    async def async_step_dp_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
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
            await self.hass.config_entries.async_reload(
                self._config_entry.entry_id
            )
            return self.async_create_entry(title="", data=self._config_entry.options)

        return self.async_show_form(
            step_id="dp_edit",
            data_schema=vol.Schema({
                vol.Required("name", default=dp_def.name): str,
                vol.Required(
                    "entity_type", default=dp_def.entity_type
                ): vol.In(ENTITY_TYPE_OPTIONS),
                vol.Optional("delete", default=False): bool,
            }),
            description_placeholders={
                "dp_id": str(dp_id),
                "name": dp_def.name,
            },
        )

    async def async_step_dp_add(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Add a new custom datapoint."""
        errors: dict[str, str] = {}
        hub = self._get_hub()

        if user_input is not None and hub:
            dp_id = user_input["dp_id"]
            if hub.profile and dp_id in hub.profile.discovered_dps:
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
                return self.async_create_entry(title="", data=self._config_entry.options)

        return self.async_show_form(
            step_id="dp_add",
            data_schema=vol.Schema({
                vol.Required("dp_id"): vol.Coerce(int),
                vol.Required("name"): str,
                vol.Required("dp_type", default=DP_TYPE_BOOL): vol.In(
                    DP_TYPE_OPTIONS
                ),
                vol.Required("entity_type", default=ENTITY_SWITCH): vol.In(
                    ENTITY_TYPE_OPTIONS
                ),
            }),
            errors=errors,
        )

    async def async_step_dp_scan_mode(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Choose scan mode before starting the scan.

        If a scan is already running, jump straight to the progress view.
        If results from a previous scan exist, show them with a force rescan option.
        """
        hub = self._get_hub()

        # If a scan is currently running on the hub, jump to progress
        if hub and hub.scan_running:
            return await self.async_step_dp_scan()

        # If there are completed results from a previous scan, show them
        if hub and hub.scan_results is not None and not hub.scan_running:
            if user_input is not None:
                if user_input.get("force_rescan"):
                    hub.reset_scan_state()
                    self._scan_clear_existing = user_input.get("clear_existing", False)
                    return await self.async_step_dp_scan()
                # User wants to view existing results
                return await self.async_step_dp_scan_results()

            return self.async_show_form(
                step_id="dp_scan_mode",
                data_schema=vol.Schema({
                    vol.Optional("force_rescan", default=False): bool,
                    vol.Optional("clear_existing", default=False): bool,
                }),
                description_placeholders={
                    "has_results": "true",
                    "found_count": str(len(hub.scan_results)),
                },
            )

        # No scan running, no results — show normal scan start form
        if user_input is not None:
            self._scan_clear_existing = user_input.get("clear_existing", False)
            return await self.async_step_dp_scan()

        return self.async_show_form(
            step_id="dp_scan_mode",
            data_schema=vol.Schema({
                vol.Optional("clear_existing", default=False): bool,
            }),
            description_placeholders={
                "has_results": "false",
                "found_count": "0",
            },
        )

    async def async_step_dp_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Start DP scan — show progress spinner while scanning in background."""
        hub = self._get_hub()

        if not hub or not hub.available:
            return self.async_show_form(
                step_id="dp_scan_failed",
                data_schema=vol.Schema({}),
                errors={"base": "device_unavailable"},
                description_placeholders={"count": "0"},
            )

        # Start a new scan task if none is running
        if not hub.scan_running and hub.scan_task is None:
            hub.reset_scan_state()
            hub._scan_task = self.hass.async_create_task(
                self._run_dp_scan(hub)
            )

        # Task still running — show spinner
        if hub.scan_running:
            self._scan_progress_shown = True
            return self.async_show_progress(
                step_id="dp_scan",
                progress_action="dp_scan",
                progress_task=hub.scan_task,
                description_placeholders=hub.scan_progress,
            )

        # Task finished
        if self._scan_progress_shown:
            # Normal flow: HA re-invoked us after progress completed
            self._scan_progress_shown = False
            if hub.scan_error:
                return self.async_show_progress_done(next_step_id="dp_scan_failed")
            return self.async_show_progress_done(next_step_id="dp_scan_results")

        # Scan finished before we could show progress (race condition)
        # Go directly to results without progress_done
        if hub.scan_error:
            return await self.async_step_dp_scan_failed()
        return await self.async_step_dp_scan_results()

    async def _run_dp_scan(self, hub) -> None:
        """Background task: run the actual DP discovery. Stores results on hub."""
        _LOGGER.info("DP scan task started (clear_existing=%s)", self._scan_clear_existing)
        try:
            hub._scan_results = await hub.discover_dps(
                clear_existing=self._scan_clear_existing,
            )
            hub._scan_error = None
            _LOGGER.info("DP scan task completed: found %d DPs", len(hub._scan_results))
        except asyncio.TimeoutError:
            _LOGGER.warning("DP scan timed out")
            hub._scan_results = []
            hub._scan_error = "scan_timeout"
        except asyncio.CancelledError:
            _LOGGER.warning("DP scan task was cancelled")
            hub._scan_results = []
            hub._scan_error = "scan_failed"
        except ConnectionError as err:
            _LOGGER.warning("DP scan connection error: %s", err)
            hub._scan_results = []
            hub._scan_error = "cannot_connect"
        except Exception:
            _LOGGER.exception("DP scan failed with unexpected error")
            hub._scan_results = []
            hub._scan_error = "scan_failed"

    async def async_step_dp_scan_failed(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show scan failure."""
        hub = self._get_hub()
        error = (hub.scan_error if hub else None) or "scan_failed"
        return self.async_show_form(
            step_id="dp_scan_failed",
            data_schema=vol.Schema({}),
            errors={"base": error},
            description_placeholders={"count": "0"},
        )

    async def async_step_dp_scan_results(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show scan results and let user pick which DPs to add."""
        hub = self._get_hub()
        discovered = (hub.scan_results if hub else None) or []

        if user_input is not None and hub:
            selected_ids = user_input.get("selected_dps", [])
            if selected_ids:
                for dp in discovered:
                    if str(dp.dp_id) in selected_ids:
                        await hub.add_manual_dp(
                            dp_id=dp.dp_id,
                            name=dp.name or f"DP {dp.dp_id}",
                            dp_type=dp.dp_type,
                            entity_type=self._scan_entity_type(dp),
                        )
                await self.hass.config_entries.async_reload(
                    self._config_entry.entry_id
                )
            return self.async_create_entry(title="", data=self._config_entry.options)

        # Check for scan error
        scan_error = hub.scan_error if hub else None
        if scan_error:
            return self.async_show_form(
                step_id="dp_scan_results",
                data_schema=vol.Schema({}),
                errors={"base": scan_error},
                description_placeholders={"count": "0"},
            )

        # Build multi-select options (exclude already-configured DPs)
        existing_ids = set()
        if hub and hub.profile:
            existing_ids = set(hub.profile.discovered_dps.keys())

        dp_options: dict[str, str] = {}
        for dp in discovered:
            label = f"DP {dp.dp_id}: {dp.name or 'Unknown'} ({dp.dp_type})"
            if dp.dp_id in existing_ids:
                label += " [already configured]"
            dp_options[str(dp.dp_id)] = label

        if not dp_options:
            return self.async_show_form(
                step_id="dp_scan_results",
                data_schema=vol.Schema({}),
                description_placeholders={"count": "0"},
            )

        # Pre-select DPs that are NOT already configured
        default_selected = [
            str(dp.dp_id) for dp in discovered
            if dp.dp_id not in existing_ids
        ]

        return self.async_show_form(
            step_id="dp_scan_results",
            data_schema=vol.Schema({
                vol.Optional(
                    "selected_dps", default=default_selected
                ): vol.All(
                    vol.Ensure(list),
                    [vol.In(dp_options)],
                ),
            }),
            description_placeholders={"count": str(len(discovered))},
        )

    @staticmethod
    def _scan_entity_type(dp) -> str:
        """Derive default entity type from a DiscoveredDP."""
        from .dp_registry import _dp_type_to_entity_type
        if dp.is_known:
            from .const import KNOWN_DPS
            known = KNOWN_DPS.get(dp.dp_id, {})
            return known.get("entity_type", _dp_type_to_entity_type(dp.dp_type))
        return _dp_type_to_entity_type(dp.dp_type)
