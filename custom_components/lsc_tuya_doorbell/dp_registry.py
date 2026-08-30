"""DP profile storage and known DP definitions registry."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from dataclasses import fields as dataclass_fields
from typing import Any

from .const import (
    DEFAULT_ROLE_DPS,
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
    ROLES,
    ROLE_ONVIF,
    LEGACY_ONVIF_ROLE,
    verified_dps_for,
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
    # Everything below used to be decided by comparing dp_id against a constant,
    # which is why the integration only ever worked on one firmware.
    device_class: str | None = None
    value_map: dict[int, str] | None = None
    carries_image_url: bool = False
    # Whether a person typed this name. Nothing automatic may overwrite it.
    #
    # This used to be inferred -- "is the name one the tables use?" -- which
    # quietly means a user who names a datapoint after what it actually does,
    # using the same words the tables happen to use, loses that name the next
    # time the firmware generation is saved. Guessing from a string is the
    # class of bug this whole profile exists to end.
    user_named: bool = False


@dataclass
class DeviceProfile:
    """Complete DP profile for a device."""

    device_id: str
    discovered_dps: dict[int, DPDefinition] = field(default_factory=dict)
    firmware_version: str | None = None
    discovery_timestamp: str = ""
    protocol_version: str = "3.3"
    # Role name -> dp_id. The single place that says what this device's
    # datapoints mean. Empty is a valid state: it means nothing is claimed, and
    # the behaviour that depends on a role stays off rather than guessing.
    roles: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.discovery_timestamp:
            self.discovery_timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")

    def role_dp(self, role: str) -> int | None:
        """Which datapoint currently holds this role, if any."""
        return self.roles.get(role)

    def role_of(self, dp_id: int) -> str | None:
        """Which role this datapoint holds, if any."""
        for role, claimed in self.roles.items():
            if claimed == dp_id:
                return role
        return None

    def set_role(self, role: str, dp_id: int | None) -> None:
        """Assign a role to a datapoint, or clear it with None.

        A role belongs to exactly one datapoint, so assigning it takes it away
        from whichever datapoint held it before.
        """
        if role not in ROLES:
            raise ValueError(f"unknown role: {role}")
        if dp_id is None:
            self.roles.pop(role, None)
            return
        self.roles[role] = dp_id

    def seed_roles(self) -> list[str]:
        """Propose roles for datapoints that match the original LSC numbering.

        Only fills roles that are still unclaimed, and only when the profile
        actually contains that datapoint -- a number this device never reports
        is not evidence of anything. Returns the roles that were filled, so the
        caller can tell the user what was assumed.
        """
        filled: list[str] = []
        for role, dp_id in DEFAULT_ROLE_DPS.items():
            if role in self.roles or dp_id not in self.discovered_dps:
                continue
            self.roles[role] = dp_id
            filled.append(role)
        return filled


def _definition_from_dict(data: dict[str, Any]) -> DPDefinition:
    """Rebuild a DPDefinition from stored JSON.

    Unknown keys are dropped rather than raising: a profile written by a newer
    version must not make an older one refuse to start. Integer keys in
    value_map are restored, because JSON has no integer keys and a datapoint
    reporting 1 would otherwise never match the string "1".
    """
    fields = {f.name for f in dataclass_fields(DPDefinition)}
    unknown = set(data) - fields
    if unknown:
        _LOGGER.debug(
            "Ignoring unknown key(s) %s in stored definition for DP %s",
            ", ".join(sorted(unknown)), data.get("dp_id"),
        )
    clean = {k: v for k, v in data.items() if k in fields}

    value_map = clean.get("value_map")
    if isinstance(value_map, dict):
        restored: dict[int, str] = {}
        for key, label in value_map.items():
            try:
                restored[int(key)] = label
            except (TypeError, ValueError):
                _LOGGER.debug("Dropping non-numeric value_map key %r", key)
        clean["value_map"] = restored or None

    return DPDefinition(**clean)


def _migrate_role(role: str) -> str:
    """Rename a role stored under a former name to its current one."""
    return ROLE_ONVIF if role == LEGACY_ONVIF_ROLE else role


def _profile_from_dict(data: dict[str, Any]) -> DeviceProfile:
    """Rebuild a DeviceProfile from stored JSON, roles included."""
    profile = DeviceProfile(
        device_id=data["device_id"],
        firmware_version=data.get("firmware_version"),
        discovery_timestamp=data.get("discovery_timestamp", ""),
        protocol_version=data.get("protocol_version", "3.3"),
        # Migrate the pre-3.4.0 role name: what was stored as "record_switch"
        # is the ONVIF switch, now called ROLE_ONVIF.
        roles={
            _migrate_role(role): int(dp_id)
            for role, dp_id in (data.get("roles") or {}).items()
            if _migrate_role(role) in ROLES
        },
    )
    for dp_str, dp_data in data.get("dps", {}).items():
        profile.discovered_dps[int(dp_str)] = _definition_from_dict(dp_data)

    if not profile.roles:
        # Written before roles existed. Seeding keeps a working install working;
        # without it the doorbell would go quiet on upgrade.
        filled = profile.seed_roles()
        if filled:
            _LOGGER.info(
                "Device %s had no roles stored; assumed %s from the original "
                "LSC numbering. Re-run the datapoint scan if that is wrong.",
                profile.device_id, ", ".join(filled),
            )
    return profile


def _profile_to_dict(profile: DeviceProfile) -> dict[str, Any]:
    """Serialise a DeviceProfile for storage or export."""
    return {
        "device_id": profile.device_id,
        "firmware_version": profile.firmware_version,
        "discovery_timestamp": profile.discovery_timestamp,
        "protocol_version": profile.protocol_version,
        "roles": dict(profile.roles),
        "dps": {
            str(dp_id): asdict(dp_def)
            for dp_id, dp_def in profile.discovered_dps.items()
        },
    }


class DPRegistry:
    """Registry of known DP definitions with profile persistence."""

    def __init__(self) -> None:
        self._profiles: dict[str, DeviceProfile] = {}

    def get_known_dp(
        self, dp_id: int, firmware_version: str | None = None
    ) -> DPDefinition | None:
        """Look up a DP in the known definitions table for this firmware.

        Only entries verified against real hardware lend a name. An unchecked
        one is likelier to mislead than to help: of the nine checked so far,
        eight were wrong. A datapoint nobody has confirmed stays "DP 110",
        which is honest and understood, rather than carrying a label from
        another model.
        """
        known = verified_dps_for(firmware_version).get(dp_id)
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
            # The self-describing fields. Without forwarding them, a known
            # datapoint arrives at the entity platforms saying nothing about
            # itself -- which is the situation those fields were added to end.
            icon=known.get("icon"),
            device_class=known.get("device_class"),
            value_map=known.get("value_map"),
            carries_image_url=known.get("carries_image_url", False),
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

        data = {
            dev_id: _profile_to_dict(prof)
            for dev_id, prof in self._profiles.items()
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

        profile = _profile_from_dict(data[device_id])
        self._profiles[device_id] = profile
        return profile

    async def load_all_profiles(self, hass: Any) -> None:
        """Load all profiles from storage."""
        store = self._get_store(hass)
        data = await store.async_load()
        if not data:
            return

        for dev_id, prof_data in data.items():
            self._profiles[dev_id] = _profile_from_dict(prof_data)

    @staticmethod
    def export_profile(profile: DeviceProfile) -> str:
        """Export a device profile as JSON string."""
        return json.dumps(_profile_to_dict(profile), indent=2)

    @staticmethod
    def import_profile(json_str: str) -> DeviceProfile:
        """Import a device profile from JSON string."""
        return _profile_from_dict(json.loads(json_str))

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
