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
                await hub.discover_dps()
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

    hass.services.async_register(DOMAIN, "discover_devices", handle_discover_devices)
    hass.services.async_register(DOMAIN, "discover_datapoints", handle_discover_datapoints)
    hass.services.async_register(DOMAIN, "export_dp_profile", handle_export_dp_profile)
