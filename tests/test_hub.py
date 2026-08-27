"""Tests for the device hub.

Home Assistant is not installed here, and hub.py is written so it does not need
to be: the config entry, the bus, the executor and the snapshot provider are all
stand-ins. What cannot be proven without a running core -- that
``async_create_background_task`` really survives a reload, that a repair issue
shows up in the UI -- is left to the integration test, not faked into a green
test that proves nothing.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Any

import pytest

from custom_components.lsc_tuya_doorbell import hub as hub_module
from custom_components.lsc_tuya_doorbell.const import (
    CONF_DEVICE_ID,
    CONF_FORCE_RECORD_ON,
    CONF_HOST,
    CONF_LOCAL_KEY,
    CONF_ONVIF_PASSWORD,
    CONF_SNAPSHOT_PATH,
    CONF_SNAPSHOT_TRIGGER_DPS,
    CONF_STREAM_URL_OVERRIDE,
    DP_TYPE_BOOL,
    DP_TYPE_ENUM,
    DP_TYPE_INT,
    DP_TYPE_RAW,
    DP_TYPE_STRING,
    ENTITY_BINARY_SENSOR,
    ENTITY_SWITCH,
    EVENT_BUTTON_PRESS,
    EVENT_DP_EVENT,
    EVENT_IP_CHANGED,
    EVENT_MOTION_DETECT,
    EVENT_SNAPSHOT_READY,
    ROLE_DOORBELL_BUTTON,
    ROLE_MOTION,
)
from custom_components.lsc_tuya_doorbell.dp_discovery import DiscoveredDP, ScanResult
from custom_components.lsc_tuya_doorbell.dp_registry import (
    DPDefinition,
    DPRegistry,
    DeviceProfile,
)
from custom_components.lsc_tuya_doorbell.hub import (
    DeviceHub,
    device_name_slug,
    local_url_for,
    normalize_dp_value,
    snapshot_filename,
    write_snapshot,
)

JPEG = b"\xff\xd8" + b"body" + b"\xff\xd9"
DOORBELL_DP = 185
MOTION_DP = 115
RECORD_DP = 101


# --- Test doubles ----------------------------------------------------------


class FakeBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def async_fire(self, event_type: str, data: dict) -> None:
        self.events.append((event_type, data))

    def names(self) -> list[str]:
        return [name for name, _ in self.events]

    def payload(self, event_type: str) -> dict:
        for name, data in self.events:
            if name == event_type:
                return data
        raise AssertionError(f"event {event_type} was never fired: {self.names()}")


class FakeConfigEntries:
    def __init__(self) -> None:
        self.updates: list[dict] = []
        self.result: bool | None = True

    def async_update_entry(self, entry: Any, data: dict) -> bool | None:
        self.updates.append(data)
        entry.data = data
        return self.result


class FakeHass:
    def __init__(self, config_dir: Path) -> None:
        self.bus = FakeBus()
        self.config = SimpleNamespace(path=lambda *parts: str(Path(config_dir, *parts)))
        self.config_entries = FakeConfigEntries()

    async def async_add_executor_job(self, func, *args):
        return func(*args)


class FakeEntry:
    entry_id = "entry_1"

    def __init__(self, data: dict, options: dict | None = None) -> None:
        self.data = data
        self.options = options or {}
        self.tasks: list[asyncio.Task] = []

    def async_create_background_task(self, hass, coro, name):
        task = asyncio.get_running_loop().create_task(coro, name=name)
        self.tasks.append(task)
        return task

    async def wait(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()


class FakeProvider:
    """Stands in for video.SnapshotProvider."""

    def __init__(self, image: bytes | None = JPEG, available: bool = True) -> None:
        self.image = image
        self._available = available
        self.error: Exception | None = None
        self.grabs: list[float] = []
        self.started = False
        self.stopped = False
        self.active_mode = "fake"

    async def async_start(self) -> None:
        self.started = True

    async def async_stop(self) -> None:
        self.stopped = True

    async def async_grab(self, age_seconds: float = 0.0) -> bytes | None:
        self.grabs.append(age_seconds)
        if self.error is not None:
            raise self.error
        return self.image

    @property
    def available(self) -> bool:
        return self._available

    @property
    def status(self) -> str:
        return "fake: ready"


class FakeConnection:
    def __init__(self) -> None:
        self.heartbeats: list[bool] = []
        self.heartbeat_results: list[bool] = []
        self.forced: list[str] = []
        self.disconnects = 0
        self.host = "192.168.1.10"
        self.is_connected = True
        self.set_calls: list[dict] = []

    def on_status_update(self, callback):
        return lambda: None

    def on_disconnect(self, callback):
        return lambda: None

    async def heartbeat(self) -> bool:
        result = self.heartbeat_results.pop(0) if self.heartbeat_results else False
        self.heartbeats.append(result)
        return result

    async def disconnect(self) -> None:
        self.disconnects += 1

    async def force_disconnect(self, reason: str) -> None:
        self.forced.append(reason)

    async def set_dps(self, dps: dict) -> dict:
        self.set_calls.append(dps)
        return {}


class FakeRegistry(DPRegistry):
    """The real registry, minus the Home Assistant store behind it."""

    def __init__(self) -> None:
        super().__init__()
        self.saved: list[DeviceProfile] = []

    async def save_profile(self, hass, profile) -> None:
        self.saved.append(profile)

    async def load_profile(self, hass, device_id):
        return None


def make_hub(
    tmp_path: Path,
    *,
    options: dict | None = None,
    profile: DeviceProfile | None = None,
    provider: FakeProvider | None = None,
) -> DeviceHub:
    hass = FakeHass(tmp_path)
    entry = FakeEntry(
        {
            CONF_DEVICE_ID: "dev123",
            CONF_LOCAL_KEY: "0123456789abcdef",
            CONF_HOST: "192.168.1.10",
        },
        options or {},
    )
    hub = DeviceHub(hass, entry, discovery_manager=None)
    hub._connection = FakeConnection()
    hub._dp_registry = FakeRegistry()
    hub._snapshots = provider or FakeProvider()
    hub._profile = profile
    hub._available = True
    return hub


def doorbell_profile(**roles: int) -> DeviceProfile:
    profile = DeviceProfile(device_id="dev123")
    profile.discovered_dps[DOORBELL_DP] = DPDefinition(
        dp_id=DOORBELL_DP, name="Doorbell Button", dp_type=DP_TYPE_RAW,
        entity_type=ENTITY_BINARY_SENSOR, is_event=True,
    )
    profile.discovered_dps[MOTION_DP] = DPDefinition(
        dp_id=MOTION_DP, name="Motion", dp_type=DP_TYPE_RAW,
        entity_type=ENTITY_BINARY_SENSOR, is_event=True,
    )
    profile.discovered_dps[RECORD_DP] = DPDefinition(
        dp_id=RECORD_DP, name="Record Switch", dp_type=DP_TYPE_BOOL,
        entity_type=ENTITY_SWITCH,
    )
    for role, dp_id in roles.items():
        profile.set_role(role, dp_id)
    return profile


# --- Value normalisation ---------------------------------------------------


class TestNormalizeValue:
    def test_raw_is_never_converted(self):
        # The bug: a raw payload of digits became an int and the image URL
        # decoders could no longer read it.
        assert normalize_dp_value("123456", DP_TYPE_RAW) == "123456"
        assert normalize_dp_value("true", DP_TYPE_RAW) == "true"
        assert normalize_dp_value(b"\x00\x01", DP_TYPE_RAW) == b"\x00\x01"

    def test_bool_from_strings_and_numbers(self):
        assert normalize_dp_value("true", DP_TYPE_BOOL) is True
        assert normalize_dp_value("FALSE", DP_TYPE_BOOL) is False
        assert normalize_dp_value("on", DP_TYPE_BOOL) is True
        assert normalize_dp_value(1, DP_TYPE_BOOL) is True
        assert normalize_dp_value(False, DP_TYPE_BOOL) is False

    def test_bool_keeps_a_value_that_is_not_one(self):
        assert normalize_dp_value("maybe", DP_TYPE_BOOL) == "maybe"

    def test_int_from_string(self):
        assert normalize_dp_value("5", DP_TYPE_INT) == 5
        assert normalize_dp_value(" 7 ", DP_TYPE_INT) == 7
        assert normalize_dp_value("3.7", DP_TYPE_INT) == 3
        assert normalize_dp_value("high", DP_TYPE_INT) == "high"

    def test_enum_and_string_become_strings(self):
        assert normalize_dp_value(0, DP_TYPE_ENUM) == "0"
        assert normalize_dp_value("2", DP_TYPE_ENUM) == "2"
        assert normalize_dp_value(12, DP_TYPE_STRING) == "12"

    def test_without_a_definition_nothing_is_guessed(self):
        assert normalize_dp_value("00123", None) == "00123"
        assert normalize_dp_value("true", None) == "true"

    def test_none_stays_none(self):
        assert normalize_dp_value(None, DP_TYPE_BOOL) is None

    def test_hub_uses_the_definition_type(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        hub._handle_status_update({str(RECORD_DP): "true", str(DOORBELL_DP): "998877"})
        assert hub.get_dp_state(RECORD_DP) is True
        assert hub.get_dp_state(DOORBELL_DP) == "998877"

    def test_non_numeric_dp_id_is_reported(self, tmp_path, caplog):
        hub = make_hub(tmp_path)
        hub._handle_status_update({"weird": 1})
        assert "not a number" in caplog.text


# --- Snapshot file helpers -------------------------------------------------


class TestSnapshotFiles:
    def test_local_url_only_below_www(self):
        assert (
            local_url_for("/config/www/doorbell/a.jpg", "/config/www")
            == "/local/doorbell/a.jpg"
        )
        # A path outside www gets no URL: /local/... would always 404.
        assert local_url_for("/media/doorbell/a.jpg", "/config/www") is None

    def test_filename_has_sub_second_precision(self):
        first = snapshot_filename("bell", 1_700_000_000.100)
        second = snapshot_filename("bell", 1_700_000_000.900)
        assert first != second

    def test_write_and_prune(self, tmp_path):
        directory = str(tmp_path / "snaps")
        written = []
        for index in range(5):
            path = write_snapshot(
                directory, f"bell_{index}.jpg", JPEG, "bell", keep=3
            )
            written.append(path)
            # Distinct mtimes, so pruning has a defined order.
            Path(path).touch()
            time.sleep(0.01)

        remaining = sorted(p.name for p in Path(directory).glob("*.jpg"))
        assert remaining == ["bell_2.jpg", "bell_3.jpg", "bell_4.jpg"]
        assert Path(written[-1]).read_bytes() == JPEG

    def test_write_leaves_other_devices_alone(self, tmp_path):
        directory = str(tmp_path / "snaps")
        write_snapshot(directory, "other_1.jpg", JPEG, "other", keep=1)
        write_snapshot(directory, "bell_1.jpg", JPEG, "bell", keep=1)
        write_snapshot(directory, "bell_2.jpg", JPEG, "bell", keep=1)
        names = sorted(p.name for p in Path(directory).glob("*.jpg"))
        assert names == ["bell_2.jpg", "other_1.jpg"]

    def test_slug(self):
        assert device_name_slug("Front Door!") == "front_door"


# --- Roles decide behaviour ------------------------------------------------


class TestRoles:
    @pytest.mark.asyncio
    async def test_event_type_comes_from_the_role(self, tmp_path):
        hub = make_hub(
            tmp_path,
            profile=doorbell_profile(
                doorbell_button=DOORBELL_DP, motion=MOTION_DP
            ),
        )
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) == DOORBELL_DP
        assert hub.role_of(MOTION_DP) == ROLE_MOTION

        hub._handle_status_update({str(DOORBELL_DP): "x"})
        assert EVENT_BUTTON_PRESS in hub._hass.bus.names()

        hub._hass.bus.events.clear()
        hub._handle_status_update({str(MOTION_DP): "x"})
        assert EVENT_MOTION_DETECT in hub._hass.bus.names()
        await hub._config_entry.wait()

    def test_without_a_role_no_doorbell_event(self, tmp_path):
        # DP 185 is present and is even the historical doorbell number: without
        # the role it must not be treated as one.
        hub = make_hub(tmp_path, profile=doorbell_profile())
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        assert EVENT_BUTTON_PRESS not in hub._hass.bus.names()

    @pytest.mark.asyncio
    async def test_a_role_on_another_dp_moves_the_event(self, tmp_path):
        profile = doorbell_profile()
        profile.discovered_dps[7] = DPDefinition(
            dp_id=7, name="Bell", dp_type=DP_TYPE_RAW, entity_type=ENTITY_BINARY_SENSOR
        )
        profile.set_role(ROLE_DOORBELL_BUTTON, 7)
        hub = make_hub(tmp_path, profile=profile)
        hub._handle_status_update({"7": "x"})
        assert hub._hass.bus.payload(EVENT_BUTTON_PRESS)["dp_id"] == 7
        await hub._config_entry.wait()

    def test_is_event_without_a_role_fires_the_generic_event(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        hub._handle_status_update({str(MOTION_DP): "x"})
        assert EVENT_DP_EVENT in hub._hass.bus.names()

    def test_plain_datapoint_fires_nothing(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        hub._handle_status_update({str(RECORD_DP): True})
        assert hub._hass.bus.events == []

    def test_no_profile_means_no_events(self, tmp_path):
        hub = make_hub(tmp_path)
        hub._handle_status_update({str(DOORBELL_DP): "x", str(MOTION_DP): "x"})
        assert hub._hass.bus.events == []

    def test_definition_for(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        assert hub.definition_for(RECORD_DP).name == "Record Switch"
        assert hub.definition_for(999) is None

    @pytest.mark.asyncio
    async def test_removing_a_dp_takes_its_role_with_it(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        await hub.remove_dp(DOORBELL_DP)
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) is None

    @pytest.mark.asyncio
    async def test_set_role_persists(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        await hub.async_set_role(ROLE_DOORBELL_BUTTON, 42)
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) == 42
        assert hub._dp_registry.saved


# --- Event payload and timing ----------------------------------------------


class TestEventTiming:
    @pytest.mark.asyncio
    async def test_event_fires_before_the_snapshot(self, tmp_path):
        provider = FakeProvider()
        hub = make_hub(
            tmp_path,
            options={CONF_SNAPSHOT_PATH: str(tmp_path / "www" / "doorbell")},
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
            provider=provider,
        )

        hub._handle_status_update({str(DOORBELL_DP): "x"})

        # t=0: the press event is already out, with an explicit empty snapshot.
        payload = hub._hass.bus.payload(EVENT_BUTTON_PRESS)
        assert payload["snapshot_url"] is None
        assert EVENT_SNAPSHOT_READY not in hub._hass.bus.names()

        await hub._config_entry.wait()

        ready = hub._hass.bus.payload(EVENT_SNAPSHOT_READY)
        assert ready["snapshot_url"] == "/local/doorbell/" + Path(
            hub.last_snapshot_path
        ).name
        assert hub.last_snapshot_url == ready["snapshot_url"]
        assert Path(hub.last_snapshot_path).read_bytes() == JPEG

    @pytest.mark.asyncio
    async def test_snapshot_listener_is_notified(self, tmp_path):
        hub = make_hub(
            tmp_path,
            options={CONF_SNAPSHOT_PATH: str(tmp_path / "www" / "doorbell")},
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
        )
        seen: list[str | None] = []
        unregister = hub.on_snapshot_change(seen.append)

        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()
        assert seen == [hub.last_snapshot_url]

        unregister()
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()
        assert len(seen) == 1

    @pytest.mark.asyncio
    async def test_entity_callback_runs_before_the_event(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        order: list[str] = []
        hub.register_entity(DOORBELL_DP, lambda value: order.append("entity"))
        original = hub._fire_event

        def _record(event_type, data=None):
            order.append("event")
            original(event_type, data)

        hub._fire_event = _record
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        assert order[0] == "entity"
        await hub._config_entry.wait()

    @pytest.mark.asyncio
    async def test_payload_is_always_complete(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        payload_json = json.dumps(
            {"cmd": "ipc_doorbell", "data": {"imgUrl": "https://example.com/a.jpg"}}
        )
        hub._handle_status_update({str(DOORBELL_DP): payload_json})

        payload = hub._hass.bus.payload(EVENT_BUTTON_PRESS)
        for key in (
            "device_id", "device_name", "timestamp", "dp_id", "role",
            "event_counter", "image_url", "snapshot_url", "snapshot_path",
            "raw_value",
        ):
            assert key in payload
        assert payload["image_url"] == "https://example.com/a.jpg"
        assert payload["role"] == ROLE_DOORBELL_BUTTON
        assert payload["event_counter"] == 1

    @pytest.mark.asyncio
    async def test_stable_and_deprecated_event_names(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        hub._device_name = "Front Door"
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()
        names = hub._hass.bus.names()
        assert EVENT_BUTTON_PRESS in names
        assert f"{EVENT_BUTTON_PRESS}_front_door" in names

    @pytest.mark.asyncio
    async def test_failed_snapshot_is_reported_and_fires_nothing(
        self, tmp_path, caplog
    ):
        provider = FakeProvider(image=None)
        hub = make_hub(
            tmp_path,
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
            provider=provider,
        )
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()

        assert EVENT_SNAPSHOT_READY not in hub._hass.bus.names()
        assert hub.last_snapshot_url is None
        assert "No snapshot could be taken" in caplog.text

    @pytest.mark.asyncio
    async def test_grab_error_is_reported(self, tmp_path, caplog):
        provider = FakeProvider()
        provider.error = RuntimeError("ffmpeg exploded")
        hub = make_hub(
            tmp_path,
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
            provider=provider,
        )
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()
        assert "failed" in caplog.text.lower()
        assert EVENT_SNAPSHOT_READY not in hub._hass.bus.names()

    @pytest.mark.asyncio
    async def test_unavailable_provider_says_so(self, tmp_path, caplog):
        provider = FakeProvider(available=False)
        hub = make_hub(
            tmp_path,
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
            provider=provider,
        )
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        assert provider.grabs == []
        assert "No snapshot for" in caplog.text

    @pytest.mark.asyncio
    async def test_snapshot_outside_www_has_a_path_but_no_url(self, tmp_path, caplog):
        hub = make_hub(
            tmp_path,
            options={CONF_SNAPSHOT_PATH: str(tmp_path / "elsewhere")},
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
        )
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()

        ready = hub._hass.bus.payload(EVENT_SNAPSHOT_READY)
        assert ready["snapshot_url"] is None
        assert ready["snapshot_path"].endswith(".jpg")
        assert "cannot serve them" in caplog.text

    @pytest.mark.asyncio
    async def test_snapshot_delay_is_passed_as_age(self, tmp_path):
        provider = FakeProvider()
        hub = make_hub(
            tmp_path,
            options={
                "snapshot_delay_ms": 3000,
                CONF_SNAPSHOT_PATH: str(tmp_path / "www" / "doorbell"),
            },
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
            provider=provider,
        )
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        await hub._config_entry.wait()
        assert provider.grabs == [3.0]

    @pytest.mark.asyncio
    async def test_two_presses_in_one_second_keep_both_pictures(self, tmp_path):
        hub = make_hub(
            tmp_path,
            options={CONF_SNAPSHOT_PATH: str(tmp_path / "www" / "doorbell")},
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
        )
        hub._handle_status_update({str(DOORBELL_DP): "a"})
        await hub._config_entry.wait()
        first = hub.last_snapshot_path
        hub._handle_status_update({str(DOORBELL_DP): "b"})
        await hub._config_entry.wait()
        assert hub.last_snapshot_path != first
        assert Path(first).exists()


# --- Snapshot trigger selection --------------------------------------------


class TestSnapshotTriggers:
    def test_defaults_to_the_doorbell_role(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=7)
        )
        assert hub._snapshot_trigger_dps() == {7}

    def test_no_role_means_no_trigger(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        assert hub._snapshot_trigger_dps() == set()

    def test_configured_list_wins(self, tmp_path):
        hub = make_hub(
            tmp_path,
            options={CONF_SNAPSHOT_TRIGGER_DPS: ["3", 4]},
            profile=doorbell_profile(doorbell_button=7),
        )
        assert hub._snapshot_trigger_dps() == {3, 4}

    def test_legacy_comma_string(self, tmp_path):
        hub = make_hub(
            tmp_path, options={CONF_SNAPSHOT_TRIGGER_DPS: "3, 4"}
        )
        assert hub._snapshot_trigger_dps() == {3, 4}

    def test_unreadable_option_falls_back_to_the_role(self, tmp_path, caplog):
        hub = make_hub(
            tmp_path,
            options={CONF_SNAPSHOT_TRIGGER_DPS: ["nonsense"]},
            profile=doorbell_profile(doorbell_button=7),
        )
        assert hub._snapshot_trigger_dps() == {7}
        assert "unreadable" in caplog.text


# --- Connection listeners and lifecycle ------------------------------------


class TestConnectionListeners:
    def test_on_connection_change_returns_an_unregister(self, tmp_path):
        hub = make_hub(tmp_path)
        seen: list[bool] = []
        unregister = hub.on_connection_change(seen.append)

        hub._notify_connection_callbacks(True)
        unregister()
        hub._notify_connection_callbacks(False)

        assert seen == [True]

    def test_a_broken_listener_does_not_stop_the_others(self, tmp_path, caplog):
        hub = make_hub(tmp_path)
        seen: list[bool] = []

        def _boom(_connected: bool) -> None:
            raise RuntimeError("entity is gone")

        hub.on_connection_change(_boom)
        hub.on_connection_change(seen.append)
        hub._notify_connection_callbacks(False)

        assert seen == [False]
        assert "Connection listener failed" in caplog.text

    def test_disconnect_notifies_every_listener(self, tmp_path):
        hub = make_hub(tmp_path)
        seen: list[bool] = []
        hub.on_connection_change(seen.append)
        hub._reconnect_task = SimpleNamespace(done=lambda: False)

        hub._handle_disconnect()

        assert seen == [False]
        assert hub.available is False

    def test_on_dp_change_unregisters(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        seen: list[Any] = []
        unregister = hub.on_dp_change(RECORD_DP, seen.append)
        hub._handle_status_update({str(RECORD_DP): True})
        unregister()
        hub._handle_status_update({str(RECORD_DP): False})
        assert seen == [True]


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_three_failures_force_a_disconnect(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hub_module, "HEARTBEAT_INTERVAL", 0)
        hub = make_hub(tmp_path)
        hub._connection.heartbeat_results = [False, False, False]

        await hub._heartbeat_loop()

        # A plain disconnect() notifies nobody, so nothing would ever reconnect
        # while every entity kept reporting itself available.
        assert hub._connection.forced == [
            "no heartbeat response after 3 attempts"
        ]
        assert hub._connection.disconnects == 0

    @pytest.mark.asyncio
    async def test_a_good_beat_resets_the_counter(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hub_module, "HEARTBEAT_INTERVAL", 0)
        hub = make_hub(tmp_path)
        hub._connection.heartbeat_results = [False, False, True, False, False]

        async def _stop_after(n: int) -> None:
            await asyncio.sleep(0)

        hub._connection.heartbeat_results += [False]
        await hub._heartbeat_loop()
        assert hub._connection.forced


class TestRecordRecovery:
    @pytest.mark.asyncio
    async def test_recovery_follows_the_role(self, tmp_path):
        hub = make_hub(
            tmp_path,
            options={CONF_FORCE_RECORD_ON: True},
            profile=doorbell_profile(record_switch=RECORD_DP),
        )
        calls: list[tuple[float, Any]] = []

        def _immediate(delay, action):
            calls.append((delay, action))
            action(None)
            return lambda: None

        hub._call_later = _immediate
        hub._handle_status_update({str(RECORD_DP): False})
        await hub._config_entry.wait()

        assert calls and calls[0][0] == hub_module.RECORD_RECOVERY_DELAY
        assert hub._connection.set_calls == [{str(RECORD_DP): True}]

    @pytest.mark.asyncio
    async def test_no_role_means_no_recovery(self, tmp_path):
        hub = make_hub(
            tmp_path,
            options={CONF_FORCE_RECORD_ON: True},
            profile=doorbell_profile(),
        )
        hub._call_later = lambda delay, action: pytest.fail("should not schedule")
        hub._handle_status_update({str(RECORD_DP): False})
        assert hub._connection.set_calls == []


class TestHostPersistence:
    def test_the_hub_absorbs_its_own_write(self, tmp_path):
        hub = make_hub(tmp_path)
        hub._persist_host("192.168.1.20", "192.168.1.10")

        # The reload triggered by this write would cancel the reconnect task
        # that is doing the writing.
        assert hub.absorb_entry_update() is True
        assert hub.absorb_entry_update() is False
        assert hub._config_entry.data[CONF_HOST] == "192.168.1.20"

        names = hub._hass.bus.names()
        assert EVENT_IP_CHANGED in names
        assert any(name.startswith(f"{EVENT_IP_CHANGED}_") for name in names)

    def test_an_ignored_write_does_not_swallow_the_next_reload(self, tmp_path):
        hub = make_hub(tmp_path)
        hub._hass.config_entries.result = False
        hub._persist_host("192.168.1.20", "192.168.1.10")
        assert hub.absorb_entry_update() is False


class TestTeardown:
    @pytest.mark.asyncio
    async def test_teardown_clears_everything(self, tmp_path):
        provider = FakeProvider()
        hub = make_hub(tmp_path, provider=provider)
        hub.on_connection_change(lambda connected: None)
        hub.on_snapshot_change(lambda url: None)
        hub.register_entity(1, lambda value: None)

        await hub.async_teardown()

        assert provider.stopped is True
        assert hub._connection.disconnects == 1
        assert hub._connection_callbacks == []
        assert hub._snapshot_callbacks == []
        assert hub._entity_callbacks == {}
        assert hub.available is False

    @pytest.mark.asyncio
    async def test_teardown_cancels_a_running_snapshot(self, tmp_path):
        class SlowProvider(FakeProvider):
            async def async_grab(self, age_seconds: float = 0.0):
                await asyncio.sleep(30)
                return JPEG

        hub = make_hub(
            tmp_path,
            profile=doorbell_profile(doorbell_button=DOORBELL_DP),
            provider=SlowProvider(),
        )
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        assert hub._background_tasks

        await hub.async_teardown()
        assert all(task.done() for task in hub._config_entry.tasks)


# --- Configuration reading -------------------------------------------------


class TestConfiguration:
    def test_stream_url_prefers_the_override(self, tmp_path):
        hub = make_hub(
            tmp_path,
            options={
                CONF_STREAM_URL_OVERRIDE: "rtsp://go2rtc:8554/bell",
                CONF_ONVIF_PASSWORD: "secret",
            },
        )
        assert hub.stream_url == "rtsp://go2rtc:8554/bell"

    def test_stream_url_escapes_the_password(self, tmp_path):
        hub = make_hub(tmp_path, options={CONF_ONVIF_PASSWORD: "p@ss/word"})
        # Unescaped, "p@ss/word" would point the URL at host "ss".
        assert "p%40ss%2Fword" in hub.stream_url
        assert "@192.168.1.10:" in hub.stream_url

    def test_no_password_no_stream(self, tmp_path):
        hub = make_hub(tmp_path)
        assert hub.stream_url is None

    def test_options_win_over_entry_data(self, tmp_path):
        hub = make_hub(tmp_path, options={CONF_ONVIF_PASSWORD: "from-options"})
        hub._config_entry.data[CONF_ONVIF_PASSWORD] = "from-data"
        assert "from-options" in hub.stream_url

    def test_buffer_seconds_are_clamped(self, tmp_path):
        hub = make_hub(tmp_path, options={"snapshot_buffer_seconds": 9999})
        assert hub._buffer_seconds() == hub_module.MAX_BUFFER_SECONDS
        hub._config_entry.options = {"snapshot_buffer_seconds": 1}
        assert hub._buffer_seconds() == hub_module.MIN_BUFFER_SECONDS

    def test_delay_is_clamped(self, tmp_path):
        hub = make_hub(tmp_path, options={"snapshot_delay_ms": 999999})
        assert hub._snapshot_delay_ms() == hub_module.MAX_SNAPSHOT_DELAY_MS
        hub._config_entry.options = {"snapshot_delay_ms": "nonsense"}
        assert hub._snapshot_delay_ms() == 0

    def test_diagnostics_expose_the_snapshot_status(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile(motion=MOTION_DP))
        diagnostics = hub.diagnostics
        assert diagnostics["snapshot_status"] == "fake: ready"
        assert diagnostics["roles"] == {ROLE_MOTION: MOTION_DP}


# --- Profile writing, live capture and counters -----------------------------


class FakeEngine:
    """Stands in for DPDiscoveryEngine during a scan."""

    instances: list["FakeEngine"] = []

    def __init__(self, connection, firmware_version=None) -> None:
        self.connection = connection
        self.firmware_version = firmware_version
        FakeEngine.instances.append(self)

    def set_progress_callback(self, callback) -> None:
        self.callback = callback

    async def scan_all(self, range_start: int = 1) -> ScanResult:
        return ScanResult(
            discovered=[DiscoveredDP(dp_id=103, value="1", dp_type=DP_TYPE_ENUM, name="Night Vision")],
            last_batch_end=255,
            completed=True,
        )


class TestProfileWriting:
    @pytest.mark.asyncio
    async def test_a_scan_does_not_write_the_profile(self, tmp_path, monkeypatch):
        # Writing here stored datapoints nobody had chosen yet, and the
        # per-datapoint save that followed stripped them back to bare ones.
        monkeypatch.setattr(hub_module, "DPDiscoveryEngine", FakeEngine)
        hub = make_hub(tmp_path)

        found = await hub.discover_dps()

        assert [dp.dp_id for dp in found] == [103]
        assert hub.profile is None
        assert hub._dp_registry.saved == []

    @pytest.mark.asyncio
    async def test_apply_writes_full_definitions(self, tmp_path):
        hub = make_hub(tmp_path)
        await hub.async_apply_discovered_dps(
            [DiscoveredDP(dp_id=103, value="1", dp_type=DP_TYPE_ENUM, name="Night Vision")],
            roles={ROLE_DOORBELL_BUTTON: None},
        )

        definition = hub.definition_for(103)
        assert definition.entity_type == "select"
        assert definition.options == {"0": "auto", "1": "on", "2": "off"}
        assert hub._dp_registry.saved

    @pytest.mark.asyncio
    async def test_apply_sets_and_clears_roles(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        await hub.async_apply_discovered_dps(
            [DiscoveredDP(dp_id=MOTION_DP, value="x", dp_type=DP_TYPE_RAW, name="Motion")],
            roles={ROLE_MOTION: MOTION_DP, ROLE_DOORBELL_BUTTON: None},
        )
        assert hub.role_dp(ROLE_MOTION) == MOTION_DP
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) is None

    @pytest.mark.asyncio
    async def test_apply_keeps_roles_that_still_have_a_datapoint(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        await hub.async_apply_discovered_dps(
            [DiscoveredDP(dp_id=DOORBELL_DP, value="x", dp_type=DP_TYPE_RAW, name="Doorbell")]
        )
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) == DOORBELL_DP

    @pytest.mark.asyncio
    async def test_clear_existing_drops_a_role_without_a_datapoint(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        await hub.async_apply_discovered_dps(
            [DiscoveredDP(dp_id=7, value=True, dp_type=DP_TYPE_BOOL, name="Something")],
            clear_existing=True,
        )
        assert hub.definition_for(DOORBELL_DP) is None
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) is None

    @pytest.mark.asyncio
    async def test_a_role_on_an_unknown_datapoint_is_refused(self, tmp_path, caplog):
        hub = make_hub(tmp_path)
        await hub.async_apply_discovered_dps(
            [DiscoveredDP(dp_id=7, value=True, dp_type=DP_TYPE_BOOL, name="Something")],
            roles={ROLE_DOORBELL_BUTTON: 99},
        )
        assert hub.role_dp(ROLE_DOORBELL_BUTTON) is None
        assert "does not report" in caplog.text


class TestLiveCapture:
    @pytest.mark.asyncio
    async def test_capture_stays_readable_after_it_stops(self, tmp_path):
        hub = make_hub(tmp_path)
        assert hub.live_capture is None

        capture = await hub.async_start_live_capture()
        assert capture.running is True

        stopped = await hub.async_stop_live_capture()
        assert stopped is capture
        assert hub.live_capture is capture
        assert capture.found == []
        assert isinstance(capture.summary(), str)

    @pytest.mark.asyncio
    async def test_starting_twice_reuses_the_session(self, tmp_path):
        hub = make_hub(tmp_path)
        first = await hub.async_start_live_capture()
        second = await hub.async_start_live_capture()
        assert first is second

    @pytest.mark.asyncio
    async def test_no_connection_no_capture(self, tmp_path):
        hub = make_hub(tmp_path)
        hub._connection.is_connected = False
        with pytest.raises(ConnectionError):
            await hub.async_start_live_capture()

    @pytest.mark.asyncio
    async def test_stopping_without_a_session_is_fine(self, tmp_path):
        hub = make_hub(tmp_path)
        assert await hub.async_stop_live_capture() is None


class TestEventCounters:
    def test_counter_is_shared_with_the_payload(self, tmp_path):
        hub = make_hub(
            tmp_path, profile=doorbell_profile(doorbell_button=DOORBELL_DP)
        )
        hub._snapshots = FakeProvider(available=False)
        hub._handle_status_update({str(DOORBELL_DP): "x"})
        assert hub.event_count(DOORBELL_DP) == 1
        assert hub._hass.bus.payload(EVENT_BUTTON_PRESS)["event_counter"] == 1

    def test_seeding_only_raises_the_counter(self, tmp_path):
        hub = make_hub(tmp_path)
        hub.seed_event_count(DOORBELL_DP, 12)
        assert hub.event_count(DOORBELL_DP) == 12
        # A restore arriving after a fresh press must not undo that press.
        hub.seed_event_count(DOORBELL_DP, 3)
        assert hub.event_count(DOORBELL_DP) == 12


class TestImageUrl:
    def test_public_extractor_reads_a_raw_payload(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        payload = json.dumps({"data": {"imgUrl": "https://example.com/x.jpg"}})
        definition = hub.definition_for(DOORBELL_DP)
        assert (
            hub.extract_image_url(payload, definition) == "https://example.com/x.jpg"
        )

    def test_a_definition_that_carries_no_url_is_not_decoded(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        definition = hub.definition_for(RECORD_DP)
        assert hub.extract_image_url("https://example.com/x.jpg", definition) is None

    def test_carries_image_url_opens_a_non_raw_datapoint(self, tmp_path):
        hub = make_hub(tmp_path, profile=doorbell_profile())
        definition = hub.definition_for(RECORD_DP)
        definition.carries_image_url = True
        assert (
            hub.extract_image_url("https://example.com/x.jpg", definition)
            == "https://example.com/x.jpg"
        )


class TestProfileEnrichment:
    def test_stored_definitions_gain_the_new_fields(self, tmp_path):
        profile = DeviceProfile(device_id="dev123", firmware_version="4")
        profile.discovered_dps[110] = DPDefinition(
            dp_id=110, name="SD Card Status", dp_type=DP_TYPE_INT,
            entity_type="sensor",
        )
        profile.discovered_dps[DOORBELL_DP] = DPDefinition(
            dp_id=DOORBELL_DP, name="Doorbell Button", dp_type=DP_TYPE_RAW,
            entity_type=ENTITY_BINARY_SENSOR, is_event=True,
        )
        hub = make_hub(tmp_path, profile=profile)

        hub._enrich_profile_from_known_table()

        assert hub.definition_for(110).value_map[2] == "no_card"
        assert hub.definition_for(DOORBELL_DP).carries_image_url is True

    def test_a_renamed_datapoint_is_left_alone(self, tmp_path):
        profile = DeviceProfile(device_id="dev123", firmware_version="4")
        profile.discovered_dps[110] = DPDefinition(
            dp_id=110, name="Something else entirely", dp_type=DP_TYPE_INT,
            entity_type="sensor",
        )
        hub = make_hub(tmp_path, profile=profile)

        hub._enrich_profile_from_known_table()

        assert hub.definition_for(110).value_map is None


def test_relabelling_moves_the_descriptive_fields_too():
    """Found on a real profile: DP 109 kept the SD card status codes it carried
    under its previous meaning while being a plain string sensor in the
    generation actually in use. The numbers were gone; the labels for them were
    not."""
    from custom_components.lsc_tuya_doorbell.const import KNOWN_DPS_V4, KNOWN_DPS_V5

    v4, v5 = KNOWN_DPS_V4.get(109), KNOWN_DPS_V5.get(109)
    assert v4 and v5, "expected both generations to define DP 109"
    # The premise: the two disagree about whether it carries a status map.
    assert bool(v4.get("value_map")) != bool(v5.get("value_map"))
