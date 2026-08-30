"""Tests for the device profile: roles, persistence and firmware-aware lookup.

The integration used to decide what a datapoint meant by comparing its number
against a constant. That worked on exactly one model with one firmware, and did
nothing at all on anyone else's doorbell. These tests pin down the replacement:
a profile that carries roles, and a lookup that knows which firmware it is
talking about.
"""

from __future__ import annotations

import json

import pytest

from custom_components.lsc_tuya_doorbell.const import (
    AMBIGUOUS_DPS,
    KNOWN_DPS_V4,
    KNOWN_DPS_V5,
    ROLE_DOORBELL_BUTTON,
    ROLE_MOTION,
    ROLE_ONVIF,
    known_dps_for,
)
from custom_components.lsc_tuya_doorbell.dp_registry import (
    DPDefinition,
    DeviceProfile,
    DPRegistry,
    _definition_from_dict,
    _profile_from_dict,
    _profile_to_dict,
)


def _profile_with(*dp_ids: int, **kwargs) -> DeviceProfile:
    """A profile carrying the given datapoints, all as plain sensors."""
    profile = DeviceProfile(device_id="dev1", **kwargs)
    for dp_id in dp_ids:
        profile.discovered_dps[dp_id] = DPDefinition(
            dp_id=dp_id, name=f"DP {dp_id}", dp_type="raw", entity_type="sensor"
        )
    return profile


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------


def test_role_is_absent_until_claimed() -> None:
    profile = _profile_with(185)
    assert profile.role_dp(ROLE_DOORBELL_BUTTON) is None
    assert profile.role_of(185) is None


def test_role_round_trips() -> None:
    profile = _profile_with(185)
    profile.set_role(ROLE_DOORBELL_BUTTON, 185)
    assert profile.role_dp(ROLE_DOORBELL_BUTTON) == 185
    assert profile.role_of(185) == ROLE_DOORBELL_BUTTON


def test_role_moves_rather_than_duplicates() -> None:
    """A role belongs to one datapoint; reassigning takes it away from the old."""
    profile = _profile_with(185, 200)
    profile.set_role(ROLE_DOORBELL_BUTTON, 185)
    profile.set_role(ROLE_DOORBELL_BUTTON, 200)

    assert profile.role_dp(ROLE_DOORBELL_BUTTON) == 200
    assert profile.role_of(185) is None


def test_role_can_be_cleared() -> None:
    profile = _profile_with(185)
    profile.set_role(ROLE_DOORBELL_BUTTON, 185)
    profile.set_role(ROLE_DOORBELL_BUTTON, None)
    assert profile.role_dp(ROLE_DOORBELL_BUTTON) is None


def test_unknown_role_is_refused() -> None:
    profile = _profile_with(185)
    with pytest.raises(ValueError):
        profile.set_role("chime_volume", 185)


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------


def test_seeding_only_claims_datapoints_the_device_actually_has() -> None:
    """A number this device never reports is not evidence of anything.

    This is the bug that made the integration look like it worked: every scan
    result had 115 and 185 bolted on regardless of the device.
    """
    profile = _profile_with(185)  # no 115, no 101
    filled = profile.seed_roles()

    assert filled == [ROLE_DOORBELL_BUTTON]
    assert profile.role_dp(ROLE_DOORBELL_BUTTON) == 185
    assert profile.role_dp(ROLE_MOTION) is None
    assert profile.role_dp(ROLE_ONVIF) is None


def test_seeding_leaves_a_claimed_role_alone() -> None:
    profile = _profile_with(101, 115, 185)
    profile.set_role(ROLE_DOORBELL_BUTTON, 101)  # deliberate, odd, and the user's

    filled = profile.seed_roles()

    assert ROLE_DOORBELL_BUTTON not in filled
    assert profile.role_dp(ROLE_DOORBELL_BUTTON) == 101


def test_seeding_a_device_with_none_of_the_known_numbers_claims_nothing() -> None:
    profile = _profile_with(7, 8, 9)
    assert profile.seed_roles() == []
    assert profile.roles == {}


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_roles_survive_a_round_trip() -> None:
    profile = _profile_with(185, 115)
    profile.set_role(ROLE_DOORBELL_BUTTON, 185)
    profile.set_role(ROLE_MOTION, 115)

    restored = _profile_from_dict(json.loads(json.dumps(_profile_to_dict(profile))))

    assert restored.roles == {ROLE_DOORBELL_BUTTON: 185, ROLE_MOTION: 115}


def test_value_map_keeps_integer_keys_through_json() -> None:
    """JSON has no integer keys, so a device reporting 1 must still match."""
    profile = DeviceProfile(device_id="dev1")
    profile.discovered_dps[109] = DPDefinition(
        dp_id=109, name="SD status", dp_type="enum", entity_type="sensor",
        value_map={1: "normal", 2: "no_card"},
    )

    restored = _profile_from_dict(json.loads(json.dumps(_profile_to_dict(profile))))

    assert restored.discovered_dps[109].value_map == {1: "normal", 2: "no_card"}


def test_a_profile_without_roles_is_seeded_on_load() -> None:
    """Profiles written before roles existed must keep working after upgrade."""
    stored = {
        "device_id": "dev1",
        "protocol_version": "3.3",
        "dps": {
            "185": {"dp_id": 185, "name": "Doorbell Button", "dp_type": "raw",
                    "entity_type": "binary_sensor"},
        },
    }

    profile = _profile_from_dict(stored)

    assert profile.role_dp(ROLE_DOORBELL_BUTTON) == 185
    assert profile.role_dp(ROLE_MOTION) is None


def test_an_unknown_stored_key_is_dropped_not_raised() -> None:
    """A profile from a newer version must not stop an older one from starting."""
    definition = _definition_from_dict({
        "dp_id": 185, "name": "Doorbell Button", "dp_type": "raw",
        "entity_type": "binary_sensor", "invented_by_a_later_version": True,
    })

    assert definition.dp_id == 185
    assert not hasattr(definition, "invented_by_a_later_version")


def test_new_fields_default_rather_than_break_old_profiles() -> None:
    definition = _definition_from_dict({
        "dp_id": 1, "name": "x", "dp_type": "bool", "entity_type": "switch",
    })

    assert definition.device_class is None
    assert definition.value_map is None
    assert definition.carries_image_url is False


# --------------------------------------------------------------------------
# Firmware-aware lookup
# --------------------------------------------------------------------------


def test_the_two_generations_really_do_disagree() -> None:
    """Guards the premise: without this, firmware-aware lookup is pointless."""
    assert AMBIGUOUS_DPS, "expected v4 and v5 to disagree on at least one DP"
    for dp_id in AMBIGUOUS_DPS:
        assert KNOWN_DPS_V4[dp_id] != KNOWN_DPS_V5[dp_id]


@pytest.mark.parametrize("firmware,expected", [("4", "SD Card Status"), ("5", "Basic OSD")])
def test_lookup_follows_the_firmware(firmware: str, expected: str) -> None:
    assert known_dps_for(firmware)[110]["name"] == expected


@pytest.mark.parametrize("firmware", ["v4", "4.1.7", "V4.0"])
def test_firmware_strings_are_parsed_leniently(firmware: str) -> None:
    assert known_dps_for(firmware)[110]["name"] == "SD Card Status"


def test_only_verified_entries_lend_a_name() -> None:
    """Eight of the nine entries checked against hardware were wrong, so an
    unchecked one is likelier to mislead than to help."""
    registry = DPRegistry()

    assert registry.get_known_dp(110, firmware_version="4") is None
    assert registry.get_known_dp(110, firmware_version="5") is None

    verified = registry.get_known_dp(134, firmware_version="4")
    assert verified is not None and verified.name == "Motion Alarm"


def test_presence_still_distinguishes_the_generations() -> None:
    """Naming is withheld, but which datapoints a generation has is not in
    doubt -- that is what firmware inference runs on."""
    from custom_components.lsc_tuya_doorbell.const import known_dps_for

    assert known_dps_for("4")[110]["name"] != known_dps_for("5")[110]["name"]


def test_unknown_firmware_falls_back_to_the_union() -> None:
    """Documented behaviour, not an accident: the fallback is a guess."""
    assert known_dps_for(None)[110]["name"] == KNOWN_DPS_V5[110]["name"]
    assert known_dps_for("99")[110]["name"] == KNOWN_DPS_V5[110]["name"]


# --------------------------------------------------------------------------
# Which firmware generation a device follows
# --------------------------------------------------------------------------


def test_generation_is_inferred_from_datapoints_only_one_table_has() -> None:
    """A real v4 doorbell: DP 108 and 150 exist in v4 and nowhere else."""
    from custom_components.lsc_tuya_doorbell.const import infer_firmware_generation

    assert infer_firmware_generation(
        [101, 103, 104, 108, 109, 110, 134, 150, 151, 160, 185, 244, 253]
    ) == "4"


def test_shared_datapoints_are_no_evidence_either_way() -> None:
    from custom_components.lsc_tuya_doorbell.const import (
        KNOWN_DPS_V4,
        KNOWN_DPS_V5,
        infer_firmware_generation,
    )

    shared = set(KNOWN_DPS_V4) & set(KNOWN_DPS_V5)
    assert infer_firmware_generation(shared) is None


def test_nothing_recognisable_infers_nothing() -> None:
    from custom_components.lsc_tuya_doorbell.const import infer_firmware_generation

    assert infer_firmware_generation([]) is None
    assert infer_firmware_generation([7, 8, 9]) is None


def test_the_union_is_what_makes_inference_worth_doing() -> None:
    """Guards the premise: without a generation, v4 devices get v5 names."""
    from custom_components.lsc_tuya_doorbell.const import (
        KNOWN_DPS_V4,
        KNOWN_DPS_V5,
        known_dps_for,
    )

    assert KNOWN_DPS_V4[110]["name"] != KNOWN_DPS_V5[110]["name"]
    assert known_dps_for(None)[110]["name"] == KNOWN_DPS_V5[110]["name"]
    assert known_dps_for("4")[110]["name"] == KNOWN_DPS_V4[110]["name"]


def test_the_record_switch_role_is_never_seeded() -> None:
    """DP 101 was assumed to be the record switch and is the indicator light.

    Seeding it would point "force recording on" at an LED and have the
    integration toggle it back on forever. A role nobody assigned does nothing;
    a role pointed at the wrong datapoint acts on it.
    """
    from custom_components.lsc_tuya_doorbell.const import (
        DEFAULT_ROLE_DPS,
        ROLE_DOORBELL_BUTTON,
        ROLE_ONVIF,
    )

    assert ROLE_ONVIF not in DEFAULT_ROLE_DPS
    assert ROLE_DOORBELL_BUTTON in DEFAULT_ROLE_DPS


def test_a_legacy_profile_gets_no_record_switch_even_though_101_is_present() -> None:
    from custom_components.lsc_tuya_doorbell.const import ROLE_ONVIF

    profile = _profile_with(101, 185)
    profile.seed_roles()

    assert profile.role_dp(ROLE_ONVIF) is None


def test_a_pre_3_4_0_record_switch_role_loads_as_onvif() -> None:
    """The role was renamed; a profile stored under the old name must not lose it.

    'record_switch' pointed at the ONVIF switch all along, so it migrates to the
    ROLE_ONVIF name rather than being dropped as an unknown role.
    """
    stored = {
        "device_id": "dev1",
        "protocol_version": "3.3",
        "roles": {"record_switch": 255, "doorbell_button": 185},
        "dps": {
            "255": {"dp_id": 255, "name": "ONVIF", "dp_type": "bool",
                    "entity_type": "switch"},
            "185": {"dp_id": 185, "name": "Doorbell Button", "dp_type": "raw",
                    "entity_type": "binary_sensor"},
        },
    }

    profile = _profile_from_dict(stored)

    assert profile.role_dp(ROLE_ONVIF) == 255
    assert profile.role_of(255) == ROLE_ONVIF
    assert "record_switch" not in profile.roles
