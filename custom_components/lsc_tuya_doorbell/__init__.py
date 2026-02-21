"""LSC Tuya Doorbell integration for Home Assistant."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall

from .const import DOMAIN, PLATFORMS

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up LSC Tuya Doorbell from yaml (not supported, config flow only)."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up LSC Tuya Doorbell from a config entry."""
    from .discovery.manager import DiscoveryManager
    from .hub import DeviceHub

    _LOGGER.debug("Setting up config entry %s", entry.entry_id)
    hass.data.setdefault(DOMAIN, {})

    # Shared discovery manager (singleton per HA instance)
    if "discovery" not in hass.data[DOMAIN]:
        _LOGGER.debug("Creating shared discovery manager")
        discovery = DiscoveryManager()
        await discovery.start_background_listener()
        hass.data[DOMAIN]["discovery"] = discovery
    discovery = hass.data[DOMAIN]["discovery"]

    # Create hub for this device
    _LOGGER.debug("Creating hub for device %s", entry.data.get("device_id", "?"))
    hub = DeviceHub(hass, entry, discovery)
    await hub.async_setup()

    hass.data[DOMAIN][entry.entry_id] = hub

    # Forward platform setup
    _LOGGER.debug("Forwarding platform setup: %s", PLATFORMS)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register services (only once)
    if not hass.services.has_service(DOMAIN, "discover_devices"):
        _LOGGER.debug("Registering integration services")
        _register_services(hass)

    _LOGGER.debug("Config entry %s setup complete", entry.entry_id)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    from .discovery.manager import DiscoveryManager
    from .hub import DeviceHub

    _LOGGER.debug("Unloading config entry %s", entry.entry_id)

    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    _LOGGER.debug("Platform unload: %s", "OK" if unload_ok else "FAILED")

    if unload_ok:
        hub: DeviceHub = hass.data[DOMAIN].pop(entry.entry_id)
        await hub.async_teardown()

    # Stop discovery if no more entries
    remaining = [
        eid for eid in hass.data[DOMAIN]
        if eid != "discovery"
    ]
    if not remaining and "discovery" in hass.data[DOMAIN]:
        _LOGGER.debug("No more entries, stopping discovery manager")
        discovery: DiscoveryManager = hass.data[DOMAIN].pop("discovery")
        await discovery.stop()

    return unload_ok


def _register_services(hass: HomeAssistant) -> None:
    """Register integration services."""

    async def handle_discover_devices(call: ServiceCall) -> None:
        """Scan the network for Tuya devices."""
        from .discovery.manager import DiscoveryManager
        discovery: DiscoveryManager | None = hass.data.get(DOMAIN, {}).get("discovery")
        if discovery:
            devices = await discovery._udp_listener.scan(timeout=10.0)
            _LOGGER.info("Discovered %s devices", len(devices))

    async def handle_discover_datapoints(call: ServiceCall) -> None:
        """Scan a device for all available datapoints."""
        from .hub import DeviceHub
        device_id = call.data.get("device_id", "")
        for entry_id, hub in hass.data.get(DOMAIN, {}).items():
            if entry_id == "discovery":
                continue
            if isinstance(hub, DeviceHub) and hub.device_id == device_id:
                discovered = await hub.discover_dps()
                for dp in discovered:
                    _LOGGER.info(
                        "Discovered DP %d: %s (type=%s, value=%r)",
                        dp.dp_id, dp.name, dp.dp_type, dp.value,
                    )
                hass.bus.async_fire(f"{DOMAIN}_scan_results", {
                    "device_id": device_id,
                    "count": len(discovered),
                    "dps": {
                        dp.dp_id: {
                            "name": dp.name,
                            "type": dp.dp_type,
                            "value": str(dp.value),
                            "is_known": dp.is_known,
                        }
                        for dp in discovered
                    },
                })
                return
        _LOGGER.warning("Device %s not found for DP discovery", device_id)

    async def handle_export_dp_profile(call: ServiceCall) -> None:
        """Export a device's DP profile as JSON."""
        from .dp_registry import DPRegistry
        from .hub import DeviceHub
        device_id = call.data.get("device_id", "")
        for entry_id, hub in hass.data.get(DOMAIN, {}).items():
            if entry_id == "discovery":
                continue
            if isinstance(hub, DeviceHub) and hub.device_id == device_id:
                if hub.profile:
                    json_str = DPRegistry.export_profile(hub.profile)
                    _LOGGER.info("DP Profile export:\n%s", json_str)
                return

    async def handle_monitor_datapoints(call: ServiceCall) -> None:
        """Monitor a device for passive DP updates."""
        from .dp_discovery import DPDiscoveryEngine
        from .hub import DeviceHub
        device_id = call.data.get("device_id", "")
        duration = call.data.get("duration", 30)
        for entry_id, hub in hass.data.get(DOMAIN, {}).items():
            if entry_id == "discovery":
                continue
            if isinstance(hub, DeviceHub) and hub.device_id == device_id:
                if not hub.available:
                    _LOGGER.warning("Device %s not available for monitoring", device_id)
                    return
                engine = DPDiscoveryEngine(hub._connection)
                _LOGGER.info("Starting passive DP monitor for %s (%ds)", device_id, duration)
                discovered = await engine.monitor_passive(duration=float(duration))
                for dp in discovered:
                    _LOGGER.info(
                        "Monitor found DP %d: %s (type=%s, value=%r)",
                        dp.dp_id, dp.name, dp.dp_type, dp.value,
                    )
                hass.bus.async_fire(f"{DOMAIN}_dp_discovered", {
                    "device_id": device_id,
                    "source": "monitor",
                    "count": len(discovered),
                    "dps": {
                        dp.dp_id: {
                            "name": dp.name,
                            "type": dp.dp_type,
                            "value": str(dp.value),
                        }
                        for dp in discovered
                    },
                })
                return
        _LOGGER.warning("Device %s not found for DP monitoring", device_id)

    async def handle_add_datapoint(call: ServiceCall) -> None:
        """Add a manual datapoint to a device."""
        from .hub import DeviceHub
        device_id = call.data.get("device_id", "")
        dp_id = call.data.get("dp_id")
        name = call.data.get("name", f"DP {dp_id}")
        dp_type = call.data.get("dp_type", "bool")
        entity_type = call.data.get("entity_type", "switch")
        for entry_id, hub in hass.data.get(DOMAIN, {}).items():
            if entry_id == "discovery":
                continue
            if isinstance(hub, DeviceHub) and hub.device_id == device_id:
                await hub.add_manual_dp(dp_id, name, dp_type, entity_type)
                await hass.config_entries.async_reload(hub._config_entry.entry_id)
                return
        _LOGGER.warning("Device %s not found for add_datapoint", device_id)

    async def handle_remove_datapoint(call: ServiceCall) -> None:
        """Remove a datapoint from a device."""
        from .hub import DeviceHub
        device_id = call.data.get("device_id", "")
        dp_id = call.data.get("dp_id")
        for entry_id, hub in hass.data.get(DOMAIN, {}).items():
            if entry_id == "discovery":
                continue
            if isinstance(hub, DeviceHub) and hub.device_id == device_id:
                await hub.remove_dp(dp_id)
                await hass.config_entries.async_reload(hub._config_entry.entry_id)
                return
        _LOGGER.warning("Device %s not found for remove_datapoint", device_id)

    hass.services.async_register(DOMAIN, "discover_devices", handle_discover_devices)
    hass.services.async_register(DOMAIN, "discover_datapoints", handle_discover_datapoints)
    hass.services.async_register(DOMAIN, "export_dp_profile", handle_export_dp_profile)
    hass.services.async_register(DOMAIN, "monitor_datapoints", handle_monitor_datapoints)
    hass.services.async_register(DOMAIN, "add_datapoint", handle_add_datapoint)
    hass.services.async_register(DOMAIN, "remove_datapoint", handle_remove_datapoint)
