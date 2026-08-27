"""Tests for the rules the entity platforms run on.

Home Assistant is not installed here, and the platform modules import it
heavily, so the rules they depend on live in ``entity_meta`` -- a module with
no Home Assistant imports at all. What is pinned down below is exactly what
used to be decided by comparing a datapoint number against a constant, or by
looking for a substring in a name the user is free to change:

* what a datapoint means (device class, icon, event type),
* how its value should be shown (the value map, and the round trip back),
* which datapoints become entities at all (an empty profile makes none).
"""

from __future__ import annotations

import pytest

from custom_components.lsc_tuya_doorbell.const import (
    DP_DOORBELL_BUTTON,
    DP_MOTION_DETECTION,
    ENTITY_BINARY_SENSOR,
    ENTITY_EVENT,
    ENTITY_SENSOR,
    ENTITY_SWITCH,
    ROLE_DOORBELL_BUTTON,
    ROLE_MOTION,
    ROLE_RECORD_SWITCH,
    SD_STATUS_MAP,
)
from custom_components.lsc_tuya_doorbell.dp_registry import (
    DeviceProfile,
    DPDefinition,
    DPRegistry,
)
from custom_components.lsc_tuya_doorbell.entity_meta import (
    DEFAULT_EVENT_TYPE,
    MAX_EVENT_RESET_TIMEOUT,
    MIN_EVENT_RESET_TIMEOUT,
    ROLE_BINARY_DEVICE_CLASS,
    ROLE_EVENT_DEVICE_CLASS,
    apply_value_map,
    definitions_for_platform,
    device_class_for,
    event_definitions,
    event_type_for,
    icon_for,
    maps_value,
    resolve_event_reset_timeout,
    resolve_stream_source,
)


def make_dp(dp_id: int = 1, **kwargs) -> DPDefinition:
    """A definition with only the fields a test cares about spelled out."""
    fields = {
        "dp_id": dp_id,
        "name": f"DP {dp_id}",
        "dp_type": "bool",
        "entity_type": ENTITY_BINARY_SENSOR,
    }
    fields.update(kwargs)
    return DPDefinition(**fields)


def make_profile(*definitions: DPDefinition, roles: dict | None = None) -> DeviceProfile:
    return DeviceProfile(
        device_id="dev1",
        discovered_dps={d.dp_id: d for d in definitions},
        roles=roles or {},
    )


class TestDeviceClass:
    """What a datapoint is, from the datapoint -- never from its number."""

    def test_definition_wins(self):
        dp = make_dp(device_class="moisture")
        assert device_class_for(dp, ROLE_MOTION, ROLE_BINARY_DEVICE_CLASS) == "moisture"

    def test_role_fills_in_where_the_definition_is_silent(self):
        assert (
            device_class_for(make_dp(), ROLE_DOORBELL_BUTTON, ROLE_BINARY_DEVICE_CLASS)
            == "occupancy"
        )
        assert (
            device_class_for(make_dp(), ROLE_MOTION, ROLE_BINARY_DEVICE_CLASS)
            == "motion"
        )

    def test_unknown_datapoint_gets_nothing_rather_than_connectivity(self):
        # The old code labelled every other binary datapoint CONNECTIVITY, which
        # is wrong for anything that is not a connection.
        assert device_class_for(make_dp(dp_id=42), None, ROLE_BINARY_DEVICE_CLASS) is None

    def test_role_without_a_mapping_gets_nothing(self):
        assert (
            device_class_for(make_dp(), ROLE_RECORD_SWITCH, ROLE_BINARY_DEVICE_CLASS)
            is None
        )

    def test_the_original_numbers_carry_no_meaning_by_themselves(self):
        for dp_id in (DP_DOORBELL_BUTTON, DP_MOTION_DETECTION):
            assert device_class_for(make_dp(dp_id), None, ROLE_BINARY_DEVICE_CLASS) is None

    def test_event_roles_map_to_event_device_classes(self):
        assert (
            device_class_for(make_dp(), ROLE_DOORBELL_BUTTON, ROLE_EVENT_DEVICE_CLASS)
            == "doorbell"
        )
        assert (
            device_class_for(make_dp(), ROLE_MOTION, ROLE_EVENT_DEVICE_CLASS) == "motion"
        )

    def test_no_role_map_means_no_guessing(self):
        assert device_class_for(make_dp(), ROLE_MOTION) is None


class TestIcon:
    def test_definition_wins(self):
        assert icon_for(make_dp(icon="mdi:custom"), ROLE_MOTION) == "mdi:custom"

    def test_role_fallback(self):
        assert icon_for(make_dp(), ROLE_DOORBELL_BUTTON) == "mdi:doorbell-video"

    def test_nothing_known(self):
        assert icon_for(make_dp()) is None


class TestEventType:
    def test_doorbell_role_rings(self):
        assert event_type_for(ROLE_DOORBELL_BUTTON) == "ring"

    def test_motion_role(self):
        assert event_type_for(ROLE_MOTION) == "motion"

    def test_unknown_role_still_fires_something(self):
        assert event_type_for(None) == DEFAULT_EVENT_TYPE
        assert event_type_for(ROLE_RECORD_SWITCH) == DEFAULT_EVENT_TYPE


class TestValueMap:
    """Status codes are translated by the definition, not by the entity name."""

    def test_code_becomes_label(self):
        dp = make_dp(entity_type=ENTITY_SENSOR, value_map=dict(SD_STATUS_MAP))
        assert apply_value_map(dp, 1) == "normal"
        assert apply_value_map(dp, 2) == "no_card"

    def test_renaming_the_entity_changes_nothing(self):
        # The old rule was `"sd card" in name.lower()`, so this rename silently
        # turned the translation off.
        dp = make_dp(
            name="Status SD-kaart",
            entity_type=ENTITY_SENSOR,
            value_map=dict(SD_STATUS_MAP),
        )
        assert apply_value_map(dp, 1) == "normal"

    def test_unknown_code_is_shown_not_hidden(self):
        dp = make_dp(value_map=dict(SD_STATUS_MAP))
        assert apply_value_map(dp, 9) == "unknown (9)"

    def test_restored_string_still_maps(self):
        # A restored raw value comes back out of storage as a string.
        dp = make_dp(value_map=dict(SD_STATUS_MAP))
        assert apply_value_map(dp, "1") == "normal"
        assert maps_value(dp, "1") is True

    def test_booleans_are_not_status_codes(self):
        dp = make_dp(value_map={1: "normal"})
        assert apply_value_map(dp, True) is True
        assert maps_value(dp, True) is False

    def test_without_a_map_the_value_passes_through(self):
        dp = make_dp()
        assert apply_value_map(dp, 1) == 1
        assert maps_value(dp, 1) is False

    def test_none_stays_none(self):
        dp = make_dp(value_map={1: "normal"})
        assert apply_value_map(dp, None) is None
        assert maps_value(dp, None) is False

    def test_non_numeric_text_passes_through(self):
        dp = make_dp(value_map={1: "normal"})
        assert apply_value_map(dp, "gibberish") == "gibberish"


class TestWhichEntitiesAProfileProduces:
    def test_no_profile_means_no_entities(self):
        assert definitions_for_platform(None, ENTITY_BINARY_SENSOR) == []
        assert event_definitions(None) == []

    def test_empty_profile_means_no_entities(self):
        # Not "the two datapoints we happen to know a number for".
        profile = make_profile()
        assert definitions_for_platform(profile, ENTITY_BINARY_SENSOR) == []

    def test_only_datapoints_of_that_platform(self):
        profile = make_profile(
            make_dp(101, entity_type=ENTITY_SWITCH),
            make_dp(110, entity_type=ENTITY_SENSOR),
            make_dp(185, entity_type=ENTITY_BINARY_SENSOR),
        )
        assert [d.dp_id for d in definitions_for_platform(profile, ENTITY_SWITCH)] == [101]
        assert [d.dp_id for d in definitions_for_platform(profile, ENTITY_SENSOR)] == [110]
        assert [
            d.dp_id for d in definitions_for_platform(profile, ENTITY_BINARY_SENSOR)
        ] == [185]

    def test_ordered_by_datapoint_number(self):
        profile = make_profile(
            make_dp(185, entity_type=ENTITY_SENSOR),
            make_dp(101, entity_type=ENTITY_SENSOR),
            make_dp(115, entity_type=ENTITY_SENSOR),
        )
        assert [d.dp_id for d in definitions_for_platform(profile, ENTITY_SENSOR)] == [
            101,
            115,
            185,
        ]

    def test_event_entities_come_from_the_flag_or_the_type(self):
        profile = make_profile(
            make_dp(101, entity_type=ENTITY_SWITCH),
            make_dp(115, entity_type=ENTITY_BINARY_SENSOR, is_event=True),
            make_dp(185, entity_type=ENTITY_EVENT),
        )
        assert [d.dp_id for d in event_definitions(profile)] == [115, 185]

    def test_an_event_datapoint_keeps_its_binary_sensor(self):
        # The event entity is added alongside; removing the sensor would break
        # every automation already pointing at it.
        profile = make_profile(make_dp(185, entity_type=ENTITY_BINARY_SENSOR, is_event=True))
        assert [d.dp_id for d in definitions_for_platform(profile, ENTITY_BINARY_SENSOR)] == [185]
        assert [d.dp_id for d in event_definitions(profile)] == [185]


class TestEventResetTimeout:
    """The option existed but was never read; setting it did nothing."""

    def test_default_when_unset(self):
        assert resolve_event_reset_timeout({}, {}) == 5.0

    def test_read_from_options(self):
        assert resolve_event_reset_timeout({"event_reset_timeout": 12}, {}) == 12.0

    def test_options_win_over_entry_data(self):
        assert (
            resolve_event_reset_timeout(
                {"event_reset_timeout": 12}, {"event_reset_timeout": 30}
            )
            == 12.0
        )

    def test_entry_data_used_when_options_are_empty(self):
        assert resolve_event_reset_timeout({}, {"event_reset_timeout": 30}) == 30.0

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, MIN_EVENT_RESET_TIMEOUT),
            (-5, MIN_EVENT_RESET_TIMEOUT),
            (10_000, MAX_EVENT_RESET_TIMEOUT),
        ],
    )
    def test_out_of_range_is_clamped(self, value, expected):
        assert resolve_event_reset_timeout({"event_reset_timeout": value}, {}) == expected

    def test_unreadable_value_falls_back_to_the_default(self):
        assert resolve_event_reset_timeout({"event_reset_timeout": "soon"}, {}) == 5.0


class TestStreamSource:
    HOST = "192.168.1.50"

    def test_override_wins(self):
        assert (
            resolve_stream_source(
                {"stream_url_override": "rtsp://go2rtc:8554/bell"},
                {"onvif_password": "x"},
                self.HOST,
            )
            == "rtsp://go2rtc:8554/bell"
        )

    def test_password_is_escaped(self):
        # An unescaped '@' points the URL at another host entirely, and this
        # user's password contains '!@'.
        url = resolve_stream_source(
            {"onvif_password": "pa!@ss/word"}, {}, self.HOST
        )
        assert url == (
            "rtsp://admin:pa%21%40ss%2Fword@192.168.1.50:8554"
            "/Streaming/Channels/101"
        )
        assert "@192.168.1.50" in url
        assert url.count("@") == 1

    def test_no_password_means_no_stream(self):
        assert resolve_stream_source({}, {}, self.HOST) is None

    def test_no_host_means_no_stream(self):
        assert resolve_stream_source({"onvif_password": "x"}, {}, None) is None

    def test_password_from_entry_data(self):
        url = resolve_stream_source({}, {"onvif_password": "secret"}, self.HOST)
        assert url is not None and url.startswith("rtsp://admin:secret@")

    def test_port_and_path_are_honoured(self):
        url = resolve_stream_source(
            {
                "onvif_password": "secret",
                "onvif_username": "user",
                "rtsp_port": 554,
                "rtsp_path": "stream1",
            },
            {},
            self.HOST,
        )
        assert url == "rtsp://user:secret@192.168.1.50:554/stream1"


class TestKnownDefinitionsCarryTheirMetadata:
    """A known datapoint must arrive at the platform describing itself."""

    def test_registry_forwards_the_self_describing_fields(self, monkeypatch):
        table = {
            42: {"verified": True, 
                "name": "SD Card Status",
                "dp_type": "int",
                "entity_type": ENTITY_SENSOR,
                "value_map": dict(SD_STATUS_MAP),
                "device_class": "enum",
                "icon": "mdi:sd",
                "carries_image_url": True,
            }
        }
        monkeypatch.setattr(
            "custom_components.lsc_tuya_doorbell.dp_registry.verified_dps_for",
            lambda firmware_version=None: table,
        )

        definition = DPRegistry().get_known_dp(42)

        assert definition is not None
        assert definition.value_map == SD_STATUS_MAP
        assert definition.device_class == "enum"
        assert definition.icon == "mdi:sd"
        assert definition.carries_image_url is True
        assert apply_value_map(definition, 3) == "abnormal"


# --------------------------------------------------------------------------
# Event entities follow the role, not only the stored flag
# --------------------------------------------------------------------------


def test_an_event_role_produces_an_event_entity_even_without_the_flag() -> None:
    """Profiles written before roles existed have is_event set to False.

    The old "add selected datapoints" step rebuilt every definition from scratch
    and dropped the flag, so a doorbell that works fine would otherwise get no
    event entity at all. The role is the statement; the flag is bookkeeping.
    """
    from custom_components.lsc_tuya_doorbell.const import ROLE_DOORBELL_BUTTON
    from custom_components.lsc_tuya_doorbell.dp_registry import (
        DeviceProfile,
        DPDefinition,
    )
    from custom_components.lsc_tuya_doorbell.entity_meta import event_definitions

    profile = DeviceProfile(device_id="dev1")
    profile.discovered_dps[185] = DPDefinition(
        dp_id=185, name="Doorbell Button", dp_type="raw",
        entity_type="binary_sensor", is_event=False,
    )
    profile.set_role(ROLE_DOORBELL_BUTTON, 185)

    assert [d.dp_id for d in event_definitions(profile)] == [185]


def test_a_role_that_is_not_an_event_produces_no_event_entity() -> None:
    from custom_components.lsc_tuya_doorbell.const import ROLE_RECORD_SWITCH
    from custom_components.lsc_tuya_doorbell.dp_registry import (
        DeviceProfile,
        DPDefinition,
    )
    from custom_components.lsc_tuya_doorbell.entity_meta import event_definitions

    profile = DeviceProfile(device_id="dev1")
    profile.discovered_dps[101] = DPDefinition(
        dp_id=101, name="Record Switch", dp_type="bool", entity_type="switch",
    )
    profile.set_role(ROLE_RECORD_SWITCH, 101)

    assert event_definitions(profile) == []
