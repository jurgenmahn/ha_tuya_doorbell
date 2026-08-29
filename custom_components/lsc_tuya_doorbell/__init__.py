"""LSC Tuya Doorbell integration for Home Assistant."""

from __future__ import annotations

import logging

import homeassistant.helpers.config_validation as cv
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall

    from .hub import DeviceHub

from .const import (
    DOMAIN,
    ENTITY_BINARY_SENSOR,
    ENTITY_NUMBER,
    ENTITY_SELECT,
    ENTITY_SENSOR,
    ENTITY_SWITCH,
    EVENT_DP_SCAN_RESULTS,
    DP_SCAN_END,
    DP_SCAN_START,
    DP_TYPE_BOOL,
    DP_TYPE_ENUM,
    DP_TYPE_INT,
    DP_TYPE_RAW,
    DP_TYPE_STRING,
    PLATFORMS,
)
from .discovery import DISCOVERY_DATA_KEY

_LOGGER = logging.getLogger(__name__)

# There is nothing to configure in YAML: a doorbell is added through the UI and
# everything about it lives in its config entry. Saying so explicitly is what
# hassfest asks for, and it makes a stray lsc_tuya_doorbell: block in
# configuration.yaml an error rather than something silently ignored.
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

#: Default duration of the passive monitor service, in seconds.
DEFAULT_MONITOR_DURATION = 30
MIN_MONITOR_DURATION = 5
MAX_MONITOR_DURATION = 300


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration itself (config entries do the actual work).

    Services live here, not in async_setup_entry: they are registered against
    the domain, not against a device, so registering them per entry meant a
    second doorbell re-registered all six and unloading an entry removed none.
    """
    hass.data.setdefault(DOMAIN, {})
    _register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LSC Tuya Doorbell from a config entry."""
    from .discovery.manager import DiscoveryManager
    from .hub import DeviceHub

    _LOGGER.debug("Setting up config entry %s", entry.entry_id)
    hass.data.setdefault(DOMAIN, {})

    # Shared discovery manager (singleton per HA instance): UDP ports 6666/6667
    # can only be held by one listener.
    if DISCOVERY_DATA_KEY not in hass.data[DOMAIN]:
        _LOGGER.debug("Creating shared discovery manager")
        discovery = DiscoveryManager(hass)
        await discovery.start_background_listener()
        hass.data[DOMAIN][DISCOVERY_DATA_KEY] = discovery
    discovery = hass.data[DOMAIN][DISCOVERY_DATA_KEY]

    _LOGGER.debug("Creating hub for device %s", entry.data.get("device_id", "?"))
    hub = DeviceHub(hass, entry, discovery)
    await hub.async_setup()

    hass.data[DOMAIN][entry.entry_id] = hub

    _LOGGER.debug("Forwarding platform setup: %s", PLATFORMS)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    _LOGGER.debug("Config entry %s setup complete", entry.entry_id)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry when its configuration changed.

    Not every write to the entry is a configuration change: the hub stores a
    rediscovered IP in the entry itself, and reloading on that would cancel the
    reconnect task that is doing the storing — self-cancelling recovery.
    """
    hub = _get_hub(hass, entry.entry_id)
    if hub is not None and hub.absorb_entry_update():
        _LOGGER.debug(
            "Config entry %s was updated by the hub itself, not reloading",
            entry.entry_id,
        )
        return

    _LOGGER.debug("Options changed for %s, reloading", entry.entry_id)
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    from .discovery.manager import DiscoveryManager

    _LOGGER.debug("Unloading config entry %s", entry.entry_id)

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    _LOGGER.debug("Platform unload: %s", "OK" if unload_ok else "FAILED")

    if unload_ok:
        # A setup that failed halfway never stored a hub; popping without a
        # default turned that into a KeyError and left the entry unloadable.
        hub = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        if hub is not None:
            await hub.async_teardown()
        else:
            _LOGGER.debug("No hub stored for %s, nothing to tear down", entry.entry_id)

    if not list(_iter_hubs(hass)):
        discovery: DiscoveryManager | None = hass.data.get(DOMAIN, {}).pop(
            DISCOVERY_DATA_KEY, None
        )
        if discovery is not None:
            _LOGGER.debug("No more entries, stopping discovery manager")
            await discovery.stop()

    return unload_ok


def _get_hub(hass: HomeAssistant, entry_id: str) -> DeviceHub | None:
    """Return the hub for an entry, if it is set up."""
    from .hub import DeviceHub

    hub = hass.data.get(DOMAIN, {}).get(entry_id)
    return hub if isinstance(hub, DeviceHub) else None


def _iter_hubs(hass: HomeAssistant) -> Iterator[DeviceHub]:
    """Iterate over the hubs currently set up.

    hass.data[DOMAIN] also holds the shared discovery manager, which is why
    every service used to carry its own `if entry_id == "discovery": continue`.
    """
    from .hub import DeviceHub

    for value in list(hass.data.get(DOMAIN, {}).values()):
        if isinstance(value, DeviceHub):
            yield value


def _find_hub(hass: HomeAssistant, device_id: str) -> DeviceHub | None:
    """Return the hub for a device id, or None with a log line saying so."""
    for hub in _iter_hubs(hass):
        if hub.device_id == device_id:
            return hub
    _LOGGER.warning(
        "No device with id %s is set up; check the device id in the service call",
        device_id,
    )
    return None


def _register_services(hass: HomeAssistant) -> None:
    """Register the integration's services, once per Home Assistant."""
    import voluptuous as vol

    if hass.services.has_service(DOMAIN, "discover_devices"):
        return

    _LOGGER.debug("Registering integration services")

    # services.yaml marks these fields as required; without a schema the
    # promise was only in the documentation and a missing field surfaced as an
    # AttributeError deep inside the handler.
    device_schema = vol.Schema({vol.Required("device_id"): vol.Coerce(str)})
    dp_id_validator = vol.All(vol.Coerce(int), vol.Range(min=DP_SCAN_START, max=DP_SCAN_END))

    monitor_schema = vol.Schema(
        {
            vol.Required("device_id"): vol.Coerce(str),
            vol.Optional("duration", default=DEFAULT_MONITOR_DURATION): vol.All(
                vol.Coerce(int),
                vol.Range(min=MIN_MONITOR_DURATION, max=MAX_MONITOR_DURATION),
            ),
        }
    )
    add_schema = vol.Schema(
        {
            vol.Required("device_id"): vol.Coerce(str),
            vol.Required("dp_id"): dp_id_validator,
            vol.Required("name"): vol.Coerce(str),
            vol.Required("dp_type"): vol.In(
                [DP_TYPE_BOOL, DP_TYPE_INT, DP_TYPE_ENUM, DP_TYPE_STRING, DP_TYPE_RAW]
            ),
            vol.Required("entity_type"): vol.In(
                [
                    ENTITY_SWITCH,
                    ENTITY_SENSOR,
                    ENTITY_SELECT,
                    ENTITY_NUMBER,
                    ENTITY_BINARY_SENSOR,
                ]
            ),
        }
    )
    remove_schema = vol.Schema(
        {
            vol.Required("device_id"): vol.Coerce(str),
            vol.Required("dp_id"): dp_id_validator,
        }
    )

    async def handle_discover_devices(call: ServiceCall) -> None:
        """Scan the network for Tuya devices."""
        from .discovery import async_discover_devices

        # Goes through the shared manager: the background listener holds the
        # UDP ports, so a private listener of our own would find nothing.
        devices = await async_discover_devices(hass, timeout=10.0)
        _LOGGER.info("Discovered %s devices", len(devices))
        for device in devices:
            _LOGGER.info(
                "Discovered device %s at %s (broadcast says protocol %s)",
                device.device_id, device.ip, device.version_hint,
            )

    async def handle_discover_datapoints(call: ServiceCall) -> None:
        """Scan a device for all available datapoints."""
        device_id = call.data["device_id"]
        hub = _find_hub(hass, device_id)
        if hub is None:
            return

        discovered = await hub.discover_dps()
        for dp in discovered:
            _LOGGER.info(
                "Discovered DP %d: %s (type=%s, value=%r)",
                dp.dp_id, dp.name, dp.dp_type, dp.value,
            )
        hass.bus.async_fire(EVENT_DP_SCAN_RESULTS, {
            "device_id": device_id,
            "source": "scan",
            "count": len(discovered),
            "dps": _dp_summary(discovered),
        })

    async def handle_export_dp_profile(call: ServiceCall) -> None:
        """Export a device's DP profile as JSON."""
        from .dp_registry import DPRegistry

        hub = _find_hub(hass, call.data["device_id"])
        if hub is None:
            return
        if not hub.profile:
            _LOGGER.warning(
                "Device %s has no datapoint profile yet; run the datapoint scan "
                "from the options dialog first", hub.device_id,
            )
            return
        _LOGGER.info("DP Profile export:\n%s", DPRegistry.export_profile(hub.profile))

    async def handle_monitor_datapoints(call: ServiceCall) -> None:
        """Monitor a device for passive DP updates."""
        from .dp_discovery import DPDiscoveryEngine

        device_id = call.data["device_id"]
        duration = call.data["duration"]
        hub = _find_hub(hass, device_id)
        if hub is None:
            return
        if not hub.available:
            _LOGGER.warning(
                "Device %s is not connected, so there is nothing to monitor",
                device_id,
            )
            return

        engine = DPDiscoveryEngine(hub.connection)
        _LOGGER.info("Starting passive DP monitor for %s (%ds)", device_id, duration)
        discovered = await engine.monitor_passive(duration=float(duration))
        for dp in discovered:
            _LOGGER.info(
                "Monitor found DP %d: %s (type=%s, value=%r)",
                dp.dp_id, dp.name, dp.dp_type, dp.value,
            )
        hass.bus.async_fire(EVENT_DP_SCAN_RESULTS, {
            "device_id": device_id,
            "source": "monitor",
            "count": len(discovered),
            "dps": _dp_summary(discovered),
        })

    async def handle_add_datapoint(call: ServiceCall) -> None:
        """Add a manual datapoint to a device."""
        hub = _find_hub(hass, call.data["device_id"])
        if hub is None:
            return
        await hub.add_manual_dp(
            call.data["dp_id"],
            call.data["name"],
            call.data["dp_type"],
            call.data["entity_type"],
        )
        await hass.config_entries.async_reload(hub.entry_id)

    async def handle_remove_datapoint(call: ServiceCall) -> None:
        """Remove a datapoint from a device."""
        hub = _find_hub(hass, call.data["device_id"])
        if hub is None:
            return
        await hub.remove_dp(call.data["dp_id"])
        await hass.config_entries.async_reload(hub.entry_id)

    hass.services.async_register(
        DOMAIN, "discover_devices", handle_discover_devices, schema=vol.Schema({})
    )
    hass.services.async_register(
        DOMAIN, "discover_datapoints", handle_discover_datapoints, schema=device_schema
    )
    hass.services.async_register(
        DOMAIN, "export_dp_profile", handle_export_dp_profile, schema=device_schema
    )
    hass.services.async_register(
        DOMAIN, "monitor_datapoints", handle_monitor_datapoints, schema=monitor_schema
    )
    hass.services.async_register(
        DOMAIN, "add_datapoint", handle_add_datapoint, schema=add_schema
    )
    hass.services.async_register(
        DOMAIN, "remove_datapoint", handle_remove_datapoint, schema=remove_schema
    )


def _dp_summary(discovered: list[Any]) -> dict[int, dict[str, Any]]:
    """Shape discovered datapoints for an event payload."""
    return {
        dp.dp_id: {
            "name": dp.name,
            "type": dp.dp_type,
            "value": str(dp.value),
            "is_known": dp.is_known,
        }
        for dp in discovered
    }
