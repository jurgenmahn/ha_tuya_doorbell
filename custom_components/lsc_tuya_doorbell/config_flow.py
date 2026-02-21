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
    CONF_PORT,
    CONF_PROTOCOL_VERSION,
    DEFAULT_PORT,
    DEVICE_TYPE_LABELS,
    DOMAIN,
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
        listener = UDPDiscoveryListener()
        devices = await listener.scan(timeout=10.0)

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
        conn = TuyaConnection(
            self._host, self._port, self._device_id, self._local_key, self._version
        )
        try:
            await conn.connect()
            ok = await conn.heartbeat()
            if not ok:
                errors["base"] = "heartbeat_failed"
            else:
                # Quick DP query
                dps = await conn.query_dps()
                await conn.disconnect()

                # Check unique ID
                await self.async_set_unique_id(self._device_id)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=self._device_name,
                    data={
                        CONF_DEVICE_ID: self._device_id,
                        CONF_LOCAL_KEY: self._local_key,
                        CONF_HOST: self._host,
                        CONF_PORT: self._port,
                        CONF_PROTOCOL_VERSION: self._version,
                        CONF_DEVICE_NAME: self._device_name,
                    },
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


class LscTuyaDoorbellOptionsFlow(OptionsFlow):
    """Handle options for LSC Tuya Doorbell."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage options."""
        if user_input is not None:
            # Update host if changed
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
            return self.async_create_entry(title="", data=user_input)

        current = self._config_entry.data
        return self.async_show_form(
            step_id="init",
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
