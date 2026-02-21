"""DP profile storage and known DP definitions registry."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .const import (
    DOMAIN,
    DP_TYPE_BOOL,
    DP_TYPE_ENUM,
    DP_TYPE_INT,
    DP_TYPE_RAW,
    ENTITY_BINARY_SENSOR,
    ENTITY_EVENT,
    ENTITY_NUMBER,
    ENTITY_SELECT,
    ENTITY_SENSOR,
    ENTITY_SWITCH,
    KNOWN_DPS,
)
from .dp_discovery import DiscoveredDP

_LOGGER = logging.getLogger(__name__)

STORAGE_KEY = f"{DOMAIN}.profiles"
STORAGE_VERSION = 1


@dataclass
class DPDefinition:
    """Definition of a single datapoint and its associated entity."""

    dp_id: int
    name: str
    dp_type: str
    entity_type: str
    icon: str | None = None
    options: dict | None = None  # enum values, min/max for numbers
    is_event: bool = False
    min_value: int | None = None
    max_value: int | None = None
    enum_values: list[str] | None = None


@dataclass
class DeviceProfile:
    """Complete DP profile for a device."""

    device_id: str
    discovered_dps: dict[int, DPDefinition] = field(default_factory=dict)
    firmware_version: str | None = None
    discovery_timestamp: str = ""
    protocol_version: str = "3.3"

    def __post_init__(self) -> None:
        if not self.discovery_timestamp:
            self.discovery_timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")


class DPRegistry:
    """Registry of known DP definitions with profile persistence."""

    def __init__(self) -> None:
        self._profiles: dict[str, DeviceProfile] = {}

    def get_known_dp(self, dp_id: int) -> DPDefinition | None:
        """Look up a DP in the known definitions table."""
        known = KNOWN_DPS.get(dp_id)
        if not known:
            return None
        return DPDefinition(
            dp_id=dp_id,
            name=known["name"],
            dp_type=known["dp_type"],
            entity_type=known["entity_type"],
            is_event=known.get("is_event", False),
            min_value=known.get("min"),
            max_value=known.get("max"),
            enum_values=list(known["options"].values()) if "options" in known else None,
            options=known.get("options"),
        )

    def merge_discovered(
        self,
        discovered: list[DiscoveredDP],
        overrides: dict[int, str] | None = None,
    ) -> dict[int, DPDefinition]:
        """Combine auto-detected types with known definitions and user overrides."""
        result: dict[int, DPDefinition] = {}

        for dp in discovered:
            # Check known DPs first
            known = self.get_known_dp(dp.dp_id)
            if known:
                definition = known
            else:
                # Create definition from discovered info
                entity_type = _dp_type_to_entity_type(dp.dp_type)
                definition = DPDefinition(
                    dp_id=dp.dp_id,
                    name=dp.name or f"DP {dp.dp_id}",
                    dp_type=dp.dp_type,
                    entity_type=entity_type,
                    min_value=dp.min_value,
                    max_value=dp.max_value,
                    enum_values=dp.enum_values,
                )

            # Apply user overrides
            if overrides and dp.dp_id in overrides:
                override_type = overrides[dp.dp_id]
                definition.entity_type = override_type

            result[dp.dp_id] = definition

        return result

    async def save_profile(self, hass: Any, profile: DeviceProfile) -> None:
        """Persist a device profile to HA storage."""
        store = self._get_store(hass)
        self._profiles[profile.device_id] = profile

        # Save all profiles
        data = {}
        for dev_id, prof in self._profiles.items():
            data[dev_id] = {
                "device_id": prof.device_id,
                "firmware_version": prof.firmware_version,
                "discovery_timestamp": prof.discovery_timestamp,
                "protocol_version": prof.protocol_version,
                "dps": {
                    str(dp_id): asdict(dp_def)
                    for dp_id, dp_def in prof.discovered_dps.items()
                },
            }

        await store.async_save(data)
        _LOGGER.debug("Saved DP profile for device %s", profile.device_id)

    async def load_profile(self, hass: Any, device_id: str) -> DeviceProfile | None:
        """Load a device profile from HA storage."""
        if device_id in self._profiles:
            return self._profiles[device_id]

        store = self._get_store(hass)
        data = await store.async_load()
        if not data or device_id not in data:
            return None

        prof_data = data[device_id]
        profile = DeviceProfile(
            device_id=prof_data["device_id"],
            firmware_version=prof_data.get("firmware_version"),
            discovery_timestamp=prof_data.get("discovery_timestamp", ""),
            protocol_version=prof_data.get("protocol_version", "3.3"),
        )

        for dp_str, dp_data in prof_data.get("dps", {}).items():
            dp_id = int(dp_str)
            profile.discovered_dps[dp_id] = DPDefinition(**dp_data)

        self._profiles[device_id] = profile
        return profile

    async def load_all_profiles(self, hass: Any) -> None:
        """Load all profiles from storage."""
        store = self._get_store(hass)
        data = await store.async_load()
        if not data:
            return

        for dev_id, prof_data in data.items():
            profile = DeviceProfile(
                device_id=prof_data["device_id"],
                firmware_version=prof_data.get("firmware_version"),
                discovery_timestamp=prof_data.get("discovery_timestamp", ""),
                protocol_version=prof_data.get("protocol_version", "3.3"),
            )
            for dp_str, dp_data in prof_data.get("dps", {}).items():
                dp_id = int(dp_str)
                profile.discovered_dps[dp_id] = DPDefinition(**dp_data)
            self._profiles[dev_id] = profile

    @staticmethod
    def export_profile(profile: DeviceProfile) -> str:
        """Export a device profile as JSON string."""
        data = {
            "device_id": profile.device_id,
            "firmware_version": profile.firmware_version,
            "discovery_timestamp": profile.discovery_timestamp,
            "protocol_version": profile.protocol_version,
            "dps": {
                str(dp_id): asdict(dp_def)
                for dp_id, dp_def in profile.discovered_dps.items()
            },
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def import_profile(json_str: str) -> DeviceProfile:
        """Import a device profile from JSON string."""
        data = json.loads(json_str)
        profile = DeviceProfile(
            device_id=data["device_id"],
            firmware_version=data.get("firmware_version"),
            discovery_timestamp=data.get("discovery_timestamp", ""),
            protocol_version=data.get("protocol_version", "3.3"),
        )
        for dp_str, dp_data in data.get("dps", {}).items():
            dp_id = int(dp_str)
            profile.discovered_dps[dp_id] = DPDefinition(**dp_data)
        return profile

    @staticmethod
    def _get_store(hass: Any) -> Any:
        """Get or create the HA storage helper."""
        from homeassistant.helpers.storage import Store
        return Store(hass, STORAGE_VERSION, STORAGE_KEY)


def _dp_type_to_entity_type(dp_type: str) -> str:
    """Map a DP type to a default entity type."""
    mapping = {
        DP_TYPE_BOOL: ENTITY_SWITCH,
        DP_TYPE_INT: ENTITY_NUMBER,
        DP_TYPE_ENUM: ENTITY_SELECT,
        DP_TYPE_RAW: ENTITY_SENSOR,
    }
    return mapping.get(dp_type, ENTITY_SENSOR)
