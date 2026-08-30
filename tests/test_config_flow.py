"""Tests for the config and options flow.

Home Assistant is not installed here (and there is no network to fetch
``pytest-homeassistant-custom-component``), so the handful of Home Assistant
and voluptuous names the flow imports are stubbed just faithfully enough to
import the module and read back what a step *would* show. That is enough to
test the parts that used to be wrong: which devices end up in a pick list,
which datapoints may trigger a snapshot, which exception turns into which
message, and whether every key the code emits actually exists in strings.json.

What it cannot test is Home Assistant's own behaviour -- that a menu renders,
that ``async_show_progress`` resumes, that an aborted flow really aborts. Those
need a running Home Assistant.
"""

from __future__ import annotations

import ast
import asyncio
import json
import pathlib
import sys
import time
import types

import pytest

COMPONENT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "custom_components"
    / "lsc_tuya_doorbell"
)


# --------------------------------------------------------------------------
# Minimal stand-ins for the imports config_flow needs.
# --------------------------------------------------------------------------


def _module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


class _Marker:
    """Stand-in for vol.Required / vol.Optional: a dict key that remembers its default."""

    def __init__(self, schema, default=None, **_kwargs):
        self.schema = schema
        self.default = default

    def __hash__(self):
        return hash(self.schema)

    def __eq__(self, other):
        return self.schema == getattr(other, "schema", other)

    def __repr__(self):
        return f"{type(self).__name__}({self.schema!r})"


class _Required(_Marker):
    pass


class _Optional(_Marker):
    pass


class _In:
    def __init__(self, container):
        self.container = container


class _Coerce:
    def __init__(self, type_):
        self.type = type_


class _Schema:
    def __init__(self, schema):
        self.schema = schema

    def defaults(self) -> dict:
        return {key.schema: key.default for key in self.schema}

    def value_for(self, key: str):
        for marker, value in self.schema.items():
            if marker.schema == key:
                return value
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return any(marker.schema == key for marker in self.schema)


class _Selector:
    def __init__(self, config):
        self.config = config


class _SelectorConfig:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _MultiSelect:
    def __init__(self, options):
        self.options = options


class AbortFlow(Exception):
    """Stand-in for homeassistant.data_entry_flow.AbortFlow."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _FlowBase:
    hass = None
    context: dict = {}

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    def async_show_menu(self, **kwargs):
        return {"type": "menu", **kwargs}

    def async_show_progress(self, **kwargs):
        return {"type": "progress", **kwargs}

    def async_show_progress_done(self, **kwargs):
        return {"type": "progress_done", **kwargs}

    def async_create_entry(self, **kwargs):
        return {"type": "create_entry", **kwargs}

    def async_abort(self, **kwargs):
        return {"type": "abort", **kwargs}


class _ConfigFlow(_FlowBase):
    entries: list = []
    unique_id = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__()

    def _async_current_entries(self):
        return self.entries

    async def async_set_unique_id(self, unique_id):
        self.unique_id = unique_id
        return None

    def _abort_if_unique_id_configured(self):
        for entry in self.entries:
            if entry.unique_id == self.unique_id:
                raise AbortFlow("already_configured")


def _install_stubs() -> None:
    voluptuous = _module("voluptuous")
    voluptuous.Schema = _Schema
    voluptuous.Required = _Required
    voluptuous.Optional = _Optional
    voluptuous.In = _In
    voluptuous.Coerce = _Coerce
    voluptuous.UNDEFINED = object()

    config_entries = _module("homeassistant.config_entries")
    config_entries.ConfigFlow = _ConfigFlow
    config_entries.OptionsFlow = _FlowBase
    config_entries.ConfigFlowResult = dict

    class _ConfigEntry:
        def __init__(self, entry_id="1", unique_id=None, data=None, options=None):
            self.entry_id = entry_id
            self.unique_id = unique_id
            self.data = data or {}
            self.options = options or {}
            self.title = "test"

    config_entries.ConfigEntry = _ConfigEntry

    core = _module("homeassistant.core")
    core.callback = lambda func: func
    core.HomeAssistant = object

    flow_module = _module("homeassistant.data_entry_flow")
    flow_module.AbortFlow = AbortFlow

    helpers = _module("homeassistant.helpers")
    cv = _module("homeassistant.helpers.config_validation")
    # Declared by __init__ to say this integration has no YAML configuration.
    cv.config_entry_only_config_schema = lambda domain: object()
    cv.multi_select = _MultiSelect
    helpers.config_validation = cv

    selector = _module("homeassistant.helpers.selector")
    for name in ("SelectSelector", "NumberSelector"):
        setattr(selector, name, _Selector)
    for name in ("SelectSelectorConfig", "NumberSelectorConfig"):
        setattr(selector, name, _SelectorConfig)
    selector.SelectSelectorMode = types.SimpleNamespace(DROPDOWN="dropdown")
    selector.NumberSelectorMode = types.SimpleNamespace(BOX="box")
    helpers.selector = selector

    homeassistant = sys.modules.setdefault(
        "homeassistant", types.ModuleType("homeassistant")
    )
    homeassistant.config_entries = config_entries
    homeassistant.core = core
    homeassistant.helpers = helpers
    homeassistant.data_entry_flow = flow_module


_install_stubs()

from custom_components.lsc_tuya_doorbell import config_flow  # noqa: E402
from custom_components.lsc_tuya_doorbell.discovery.udp_listener import (  # noqa: E402
    DiscoveredDevice,
)
from custom_components.lsc_tuya_doorbell.dp_discovery import (  # noqa: E402
    DiscoveredDP,
)
from custom_components.lsc_tuya_doorbell.protocol.constants import (  # noqa: E402
    DecryptionError,
    FrameError,
    InvalidLocalKeyError,
    TuyaProtocolError,
    UnsupportedProtocolVersionError,
)


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------


def _device(device_id: str, ip: str = "192.168.1.10", version: str = "3.3"):
    return DiscoveredDevice(device_id=device_id, ip=ip, version=version)


def _dp(dp_id: int, dp_type: str = "bool", name: str | None = None, values=()):
    dp = DiscoveredDP(
        dp_id=dp_id, value=None, dp_type=dp_type, name=name or f"DP {dp_id}"
    )
    for index, value in enumerate(values):
        dp.record(value, at=float(index))
    return dp


class _Profile:
    def __init__(self, dps: dict, roles: dict | None = None):
        self.discovered_dps = dps
        self.roles = roles or {}

    def role_of(self, dp_id):
        for role, claimed in self.roles.items():
            if claimed == dp_id:
                return role
        return None


class _NamedDP:
    def __init__(self, name):
        self.name = name


@pytest.fixture
def strings() -> dict:
    return json.loads((COMPONENT / "strings.json").read_text())


# --------------------------------------------------------------------------
# Translations
# --------------------------------------------------------------------------


class TestTranslations:
    def test_english_translation_matches_strings(self, strings):
        """translations/en.json is the shipped copy of strings.json."""
        english = json.loads((COMPONENT / "translations" / "en.json").read_text())
        assert english == strings

    def test_progress_sits_beside_step_not_inside_it(self, strings):
        """A progress action nested in a step never resolves.

        ``progress_action`` used to live inside ``options.step.dp_scan``, where
        Home Assistant does not look for it: the spinner then showed no text at
        all for the two minutes a scan takes.
        """
        for section in ("config", "options"):
            for step_id, step in strings.get(section, {}).get("step", {}).items():
                assert "progress_action" not in step, (
                    f"{section}.step.{step_id} carries progress_action; it belongs "
                    f"in {section}.progress"
                )

    def test_every_error_key_exists(self, strings):
        emitted = _emitted(_source_tree(), "errors")
        known = set(strings["config"]["error"]) | set(strings["options"]["error"])
        assert emitted <= known, f"missing from strings.json: {sorted(emitted - known)}"

    def test_every_abort_reason_exists(self, strings):
        reasons = _abort_reasons(_source_tree())
        known = set(strings["config"]["abort"]) | set(strings["options"]["abort"])
        assert reasons <= known, f"missing from strings.json: {sorted(reasons - known)}"

    def test_every_step_id_exists(self, strings):
        steps = _step_ids(_source_tree())
        known = set(strings["config"]["step"]) | set(strings["options"]["step"])
        assert steps <= known, f"missing from strings.json: {sorted(steps - known)}"

    def test_every_progress_action_exists(self, strings):
        actions = _progress_actions(_source_tree())
        known = set(strings["config"].get("progress", {})) | set(
            strings["options"].get("progress", {})
        )
        assert actions <= known, f"missing from strings.json: {sorted(actions - known)}"

    def test_menu_options_are_translated(self, strings):
        """A menu entry without a translation renders as its raw step id."""
        labels = strings["options"]["step"]["init"]["menu_options"]
        assert set(config_flow.MENU_OPTIONS) == set(labels)

    def test_selector_translation_keys_exist(self, strings):
        """Every dropdown built by _select() must have translated option labels."""
        selectors = strings["selector"]
        for key, options in _selector_usage(_source_tree()).items():
            assert key in selectors, f"selector.{key} missing from strings.json"
            assert options <= set(selectors[key]["options"]), (
                f"selector.{key} is missing options "
                f"{sorted(options - set(selectors[key]['options']))}"
            )


def _source_tree() -> ast.Module:
    return ast.parse((COMPONENT / "config_flow.py").read_text())


def _emitted(tree: ast.Module, container: str) -> set[str]:
    """Every literal error key the flow can put in front of a user."""
    found: set[str] = set()
    for node in ast.walk(tree):
        # errors["base"] = "cannot_connect"
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == container
                    and isinstance(node.value.value, str)
                ):
                    found.add(node.value.value)
        # errors={"base": "cannot_connect"}
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "base"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    found.add(value.value)
    return found


def _keyword_constants(tree: ast.Module, func_names: set[str], keyword: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "attr", getattr(node.func, "id", None))
        if name not in func_names:
            continue
        for kw in node.keywords:
            if kw.arg == keyword and isinstance(kw.value, ast.Constant):
                found.add(kw.value.value)
    return found


def _abort_reasons(tree: ast.Module) -> set[str]:
    return _keyword_constants(tree, {"async_abort"}, "reason")


def _step_ids(tree: ast.Module) -> set[str]:
    return _keyword_constants(
        tree,
        {"async_show_form", "async_show_progress", "async_show_menu"},
        "step_id",
    ) | _keyword_constants(tree, {"async_show_progress_done"}, "next_step_id")


def _progress_actions(tree: ast.Module) -> set[str]:
    return _keyword_constants(tree, {"async_show_progress"}, "progress_action")


def _selector_usage(tree: ast.Module) -> dict[str, set[str]]:
    """Map every _select(options, "key") call to the option values it offers."""
    usage: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", None) != "_select" or len(node.args) != 2:
            continue
        options, key = node.args
        if not isinstance(key, ast.Constant):
            continue
        if isinstance(options, ast.Tuple):
            values = {
                element.value
                for element in options.elts
                if isinstance(element, ast.Constant)
            }
        elif isinstance(options, ast.Name):
            values = set(getattr(config_flow, options.id, ()))
        elif isinstance(options, ast.Attribute):
            values = set(getattr(config_flow.video, options.attr, ()))
        else:
            continue
        usage.setdefault(key.value, set()).update(values)
    return usage


# --------------------------------------------------------------------------
# Error mapping
# --------------------------------------------------------------------------


class TestErrorMapping:
    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            (InvalidLocalKeyError("no"), "invalid_local_key"),
            (UnsupportedProtocolVersionError("no"), "unsupported_protocol_version"),
            (DecryptionError("no"), "decryption_failed"),
            (FrameError("no"), "protocol_error"),
            (TuyaProtocolError("no"), "protocol_error"),
            (TimeoutError(), "timeout"),
            (ConnectionError("refused"), "cannot_connect"),
            (RuntimeError("what"), "unknown"),
        ],
    )
    def test_exception_names_the_real_cause(self, error, expected):
        assert config_flow.error_key_for(error) == expected

    def test_a_rejected_key_is_not_reported_as_a_network_problem(self):
        """InvalidLocalKeyError is also a ConnectionError; order decides."""
        assert isinstance(InvalidLocalKeyError("x"), ConnectionError)
        assert config_flow.error_key_for(InvalidLocalKeyError("x")) != "cannot_connect"

    def test_worst_error_prefers_the_actionable_one(self):
        assert (
            config_flow.worst_error(["cannot_connect", "invalid_local_key"])
            == "invalid_local_key"
        )
        assert config_flow.worst_error([]) is None
        assert config_flow.worst_error(["cannot_connect"]) == "cannot_connect"


# --------------------------------------------------------------------------
# Protocol version handling
# --------------------------------------------------------------------------


class TestVersionCandidates:
    def test_preferred_version_goes_first(self):
        assert config_flow.version_candidates("3.5") == ["3.5", "3.3", "3.4"]

    def test_every_supported_version_is_tried(self):
        for version in config_flow.SUPPORTED_PROTOCOL_VERSIONS:
            assert set(config_flow.version_candidates(version)) == set(
                config_flow.SUPPORTED_PROTOCOL_VERSIONS
            )

    def test_an_unknown_version_does_not_vanish_the_list(self):
        assert config_flow.version_candidates("3.1") == list(
            config_flow.SUPPORTED_PROTOCOL_VERSIONS
        )
        assert config_flow.version_candidates(None) == list(
            config_flow.SUPPORTED_PROTOCOL_VERSIONS
        )


class _FakeConnection:
    """Records which protocol versions were tried, and fails all but one."""

    attempts: list[str] = []

    def __init__(self, host, port, device_id, local_key, version):
        self.version = version
        type(self).attempts.append(version)

    async def connect(self):
        if self.version not in self.works:
            raise self.failure

    async def heartbeat(self):
        return True

    async def query_dps(self):
        return {}

    async def disconnect(self):
        return None


def _connection_factory(works, failure):
    return type(
        "Connection",
        (_FakeConnection,),
        {"attempts": [], "works": works, "failure": failure},
    )


class TestConnectionTest:
    @pytest.mark.asyncio
    async def test_falls_back_to_a_version_the_device_actually_speaks(
        self, monkeypatch
    ):
        connection = _connection_factory({"3.5"}, ConnectionError("nope"))
        monkeypatch.setattr(config_flow, "TuyaConnection", connection)

        flow = config_flow.LscTuyaDoorbellConfigFlow()
        flow._version = "3.3"  # what the broadcast claimed
        version, error = await flow._async_test_connection()

        assert (version, error) == ("3.5", None)
        assert connection.attempts[0] == "3.3", "the stated version must be tried first"
        assert "3.5" in connection.attempts

    @pytest.mark.asyncio
    async def test_a_wrong_key_is_reported_as_a_wrong_key(self, monkeypatch):
        connection = _connection_factory(set(), InvalidLocalKeyError("rejected"))
        monkeypatch.setattr(config_flow, "TuyaConnection", connection)

        flow = config_flow.LscTuyaDoorbellConfigFlow()
        version, error = await flow._async_test_connection()

        assert version is None
        assert error == "invalid_local_key"

    @pytest.mark.asyncio
    async def test_an_unreachable_device_still_says_cannot_connect(self, monkeypatch):
        connection = _connection_factory(set(), ConnectionError("no route"))
        monkeypatch.setattr(config_flow, "TuyaConnection", connection)

        flow = config_flow.LscTuyaDoorbellConfigFlow()
        _, error = await flow._async_test_connection()
        assert error == "cannot_connect"


# --------------------------------------------------------------------------
# Device pick list
# --------------------------------------------------------------------------


class TestDeviceChoice:
    def test_already_configured_devices_are_left_out(self):
        options = config_flow.device_choice_options(
            [_device("aaa"), _device("bbb")], configured_ids={"aaa"}
        )
        assert "aaa" not in options
        assert "bbb" in options

    def test_manual_is_always_offered(self):
        assert "manual" in config_flow.device_choice_options([], [])

    def test_the_broadcast_version_is_labelled_as_a_claim(self):
        options = config_flow.device_choice_options([_device("aaa", version="3.3")], [])
        assert "reports v3.3" in options["aaa"]

    @pytest.mark.asyncio
    async def test_pick_device_step_hides_configured_entries(self):
        flow = config_flow.LscTuyaDoorbellConfigFlow()
        flow._discovery_task = _done_task([_device("aaa"), _device("bbb")])
        flow.entries = [
            types.SimpleNamespace(unique_id="aaa", data={"device_id": "aaa"})
        ]

        result = await flow.async_step_pick_device()

        options = result["data_schema"].value_for("device").container
        assert set(options) == {"bbb", "manual"}
        assert result["description_placeholders"]["count"] == "1"
        assert result["description_placeholders"]["skipped"] == "1"

    @pytest.mark.asyncio
    async def test_a_failed_discovery_says_so(self):
        flow = config_flow.LscTuyaDoorbellConfigFlow()
        flow._discovery_task = _failed_task(OSError("no socket"))
        flow.entries = []

        result = await flow.async_step_pick_device()
        assert result["errors"] == {"base": "discovery_failed"}


def _done_task(result):
    loop = asyncio.new_event_loop()
    try:
        future = loop.create_future()
        future.set_result(result)
        return future
    finally:
        loop.close()


def _failed_task(error):
    loop = asyncio.new_event_loop()
    try:
        future = loop.create_future()
        future.set_exception(error)
        return future
    finally:
        loop.close()


# --------------------------------------------------------------------------
# The already-configured abort
# --------------------------------------------------------------------------


class TestAlreadyConfigured:
    @pytest.mark.asyncio
    async def test_abort_is_not_swallowed_as_an_unknown_error(self, monkeypatch):
        """AbortFlow inherits from Exception.

        The unique-id check used to sit inside a ``try`` with a bare
        ``except Exception``, so adding a device twice produced "an unexpected
        error occurred" over and over while the correct message was unreachable.
        """
        connection = _connection_factory({"3.3"}, ConnectionError("unused"))
        monkeypatch.setattr(config_flow, "TuyaConnection", connection)

        flow = config_flow.LscTuyaDoorbellConfigFlow()
        flow._device_id = "aaa"
        flow.entries = [types.SimpleNamespace(unique_id="aaa")]

        with pytest.raises(AbortFlow) as raised:
            await flow.async_step_connect()

        assert raised.value.reason == "already_configured"
        assert connection.attempts == [], "no connection should be attempted"


# --------------------------------------------------------------------------
# Snapshot trigger datapoints
# --------------------------------------------------------------------------


class TestSnapshotTriggers:
    def test_no_profile_means_no_choices(self):
        """It used to invent DP 185 and DP 115 here.

        Those numbers are right for exactly one model, so every other user was
        offered two datapoints their doorbell never sends.
        """
        assert config_flow.snapshot_trigger_options(None) == {}

    def test_choices_come_from_the_profile(self):
        profile = _Profile({7: _NamedDP("Button"), 9: _NamedDP("Motion")})
        options = config_flow.snapshot_trigger_options(profile)
        assert set(options) == {"7", "9"}
        assert options["7"] == "DP 7: Button"

    def test_an_empty_profile_does_not_fall_back_to_hardcoded_numbers(self):
        assert config_flow.snapshot_trigger_options(_OptionsProfile({})) == {}


# --------------------------------------------------------------------------
# Datapoint labelling and roles
# --------------------------------------------------------------------------


class TestDatapointChoices:
    def test_event_candidates_are_marked(self):
        event = _dp(185, "raw", values=["a", "b"])
        setting = _dp(101, "bool", values=[True, True])
        options = config_flow.dp_choice_options([event, setting])
        assert options["185"].endswith("⟳")
        assert not options["101"].endswith("⟳")

    def test_configured_datapoints_are_flagged_not_hidden(self):
        options = config_flow.dp_choice_options([_dp(101)], existing_ids={101})
        assert "already configured" in options["101"]

    def test_capture_summary_lists_what_was_seen(self):
        summary = config_flow.capture_summary(
            [_dp(101, values=[1, 1]), _dp(185, values=["a", "b"])]
        )
        assert summary == "DP 101, DP 185 ⟳"

    def test_capture_summary_says_something_when_nothing_arrived(self):
        assert "Nothing reported yet" in config_flow.capture_summary([])



class _FakeProfile:
    """A profile stand-in carrying only what the role screen reads."""

    def __init__(self, dps):
        self.discovered_dps = dps
        self.roles = {}


def _profile(names):
    return _FakeProfile({
        dp_id: type("D", (), {"dp_id": dp_id, "name": name, "dp_type": "bool"})()
        for dp_id, name in names.items()
    })

class TestRoles:
    def test_every_role_can_be_left_unassigned(self):
        options = config_flow.role_choice_options([_dp(101)])
        assert config_flow.ROLE_NONE in options

    def test_a_role_defaults_to_what_the_profile_already_says(self):
        options = config_flow.role_choice_options([_dp(101), _dp(185)])
        assert (
            config_flow.suggested_role_dp(
                "doorbell_button", options, {"doorbell_button": 185}
            )
            == "185"
        )

    def test_a_role_is_never_guessed_from_a_datapoint_number(self):
        """DP 185 is the doorbell button on one model, and nothing on the rest."""
        options = config_flow.role_choice_options([_dp(185)])
        assert (
            config_flow.suggested_role_dp("doorbell_button", options, {})
            == config_flow.ROLE_NONE
        )

    def test_a_stale_role_pointing_at_nothing_is_dropped(self):
        options = config_flow.role_choice_options([_dp(101)])
        assert (
            config_flow.suggested_role_dp("motion", options, {"motion": 999})
            == config_flow.ROLE_NONE
        )

    # --- A second capture must not wipe the roles from the first ---

    def test_a_later_capture_still_offers_the_datapoints_already_configured(self):
        """The bug: rescanning for one missing datapoint cleared the other roles.

        A role select that cannot offer the datapoint a role points at submits
        "not assigned", so the assignment was actively erased -- not merely left
        alone.
        """
        profile = _profile({101: "Record Switch", 185: "Doorbell Button"})
        options = config_flow.role_choice_options([_dp(244)], profile)

        assert "244" in options
        assert "185" in options and "101" in options
        assert "already configured" in options["185"]

    def test_an_existing_role_survives_a_capture_that_did_not_see_it(self):
        profile = _profile({185: "Doorbell Button"})
        options = config_flow.role_choice_options([_dp(244)], profile)

        assert (
            config_flow.suggested_role_dp(
                "doorbell_button", options, {"doorbell_button": 185}
            )
            == "185"
        )

    def test_clearing_the_profile_stops_offering_the_old_datapoints(self):
        """With clear_existing they are on their way out; a role there is a role at nothing."""
        profile = _profile({185: "Doorbell Button"})
        options = config_flow.role_choice_options(
            [_dp(244)], profile, clear_existing=True
        )

        assert "185" not in options
        assert (
            config_flow.suggested_role_dp(
                "doorbell_button", options, {"doorbell_button": 185}
            )
            == config_flow.ROLE_NONE
        )


# --------------------------------------------------------------------------
# Options flow: the pieces that need a Home Assistant to talk to
# --------------------------------------------------------------------------

from homeassistant.config_entries import ConfigEntry as _StubEntry  # noqa: E402


class _FakeConfigEntries:
    """Records what the flow wrote, and applies it like Home Assistant would."""

    def __init__(self) -> None:
        self.option_writes: list[dict] = []
        self.data_writes: list[dict] = []
        self.reloads: list[str] = []

    def async_update_entry(self, entry, *, data=None, options=None):
        if data is not None:
            entry.data = dict(data)
            self.data_writes.append(dict(data))
        if options is not None:
            entry.options = dict(options)
            self.option_writes.append(dict(options))
        return True

    async def async_reload(self, entry_id):
        self.reloads.append(entry_id)


class _FakeHass:
    def __init__(self) -> None:
        self.config_entries = _FakeConfigEntries()
        self.data: dict = {}
        self.tasks: list[str] = []

    def async_create_task(self, coro, name=None):
        # The flow only needs something to hand to async_show_progress; running
        # a two-second sleep in a unit test would be two seconds wasted.
        coro.close()
        self.tasks.append(name or "")
        return f"task:{name}"


class _FakeHub:
    def __init__(self, profile=None, capture=None, available=True):
        self.profile = profile
        self.live_capture = capture
        self.available = available
        self.scan_running = False
        self.scan_results = None
        self.scan_error = None
        self.scan_task = None
        self.updated: list[tuple] = []
        self.removed: list[int] = []

    async def update_dp(self, dp_id, name=None, entity_type=None, is_event=None):
        self.updated.append((dp_id, name, entity_type))

    async def remove_dp(self, dp_id):
        self.removed.append(dp_id)

    async def async_stop_live_capture(self):
        if self.live_capture is not None:
            self.live_capture.stop()
        return self.live_capture

    async def async_apply_discovered_dps(self, dps, clear_existing=False, roles=None):
        self.applied = (list(dps), clear_existing, roles)


class _OptionsProfile:
    """A profile stand-in carrying everything the options steps read."""

    def __init__(self, names: dict, roles: dict | None = None):
        self.discovered_dps = {
            dp_id: types.SimpleNamespace(
                dp_id=dp_id,
                name=name,
                dp_type="bool",
                entity_type="sensor",
            )
            for dp_id, name in names.items()
        }
        self.roles = roles or {}
        self.firmware_version = None

    def role_of(self, dp_id):
        for role, claimed in self.roles.items():
            if claimed == dp_id:
                return role
        return None


def _options_flow(options=None, data=None, hub=None):
    entry = _StubEntry(entry_id="1", data=dict(data or {}), options=dict(options or {}))
    flow = config_flow.LscTuyaDoorbellOptionsFlow(entry)
    flow.hass = _FakeHass()
    flow.hass.data[config_flow.DOMAIN] = {"1": hub}
    return flow


def _fields(result) -> set[str]:
    return set(result["data_schema"].defaults())


# --------------------------------------------------------------------------
# Camera settings split by where the video comes from
# --------------------------------------------------------------------------


class TestVideoSourceSplit:
    def test_a_stream_override_means_a_restreamer(self):
        assert (
            config_flow.video_source_of({"stream_url_override": "rtsp://go2rtc/x"})
            == config_flow.VIDEO_SOURCE_RESTREAM
        )

    def test_nothing_configured_means_the_camera_itself(self):
        assert config_flow.video_source_of({}) == config_flow.VIDEO_SOURCE_DIRECT

    def test_whitespace_is_not_a_stream_url(self):
        assert (
            config_flow.video_source_of({"stream_url_override": "   "})
            == config_flow.VIDEO_SOURCE_DIRECT
        )

    @pytest.mark.asyncio
    async def test_the_choice_is_preselected_from_what_is_stored(self):
        flow = _options_flow({"stream_url_override": "rtsp://go2rtc/doorbell"})
        result = await flow.async_step_camera_settings()
        assert result["data_schema"].defaults()["video_source"] == "restream"

        flow = _options_flow({})
        result = await flow.async_step_camera_settings()
        assert result["data_schema"].defaults()["video_source"] == "direct"

    @pytest.mark.asyncio
    async def test_the_direct_route_never_shows_the_stream_url(self):
        flow = _options_flow({})
        result = await flow.async_step_camera_settings({"video_source": "direct"})

        assert result["step_id"] == "camera_direct"
        assert _fields(result) == {
            "onvif_username",
            "onvif_password",
            "rtsp_port",
            "rtsp_path",
            "back",
        }

    @pytest.mark.asyncio
    async def test_the_restreamer_route_never_shows_port_or_path(self):
        flow = _options_flow({})
        result = await flow.async_step_camera_settings({"video_source": "restream"})

        assert result["step_id"] == "camera_restream"
        assert _fields(result) == {
            "stream_url_override",
            "back",
        }

    @pytest.mark.asyncio
    async def test_choosing_direct_clears_the_override_that_would_outrank_it(self):
        """The bug this split exists for: an override kept winning silently."""
        flow = _options_flow({"stream_url_override": "rtsp://go2rtc/doorbell"})
        await flow.async_step_camera_settings({"video_source": "direct"})
        await flow.async_step_camera_direct({"rtsp_port": 8554, "rtsp_path": "/live"})

        assert flow._config_entry.options["stream_url_override"] == ""
        assert flow._config_entry.options["rtsp_path"] == "/live"

    @pytest.mark.asyncio
    async def test_a_restreamer_without_a_url_is_not_a_restreamer(self):
        flow = _options_flow({})
        await flow.async_step_camera_settings({"video_source": "restream"})
        result = await flow.async_step_camera_restream({"stream_url_override": "  "})

        assert result["errors"] == {"stream_url_override": "stream_url_required"}
        assert flow.hass.config_entries.option_writes == []

    @pytest.mark.asyncio
    async def test_the_snapshot_trigger_left_the_camera_screens(self):
        """It belongs with the snapshots it triggers, not with the stream."""
        profile = _OptionsProfile({7: "Button"})
        flow = _options_flow({}, hub=_FakeHub(profile))

        chooser = await flow.async_step_camera_settings()
        direct = await flow.async_step_camera_direct()
        restream = await flow.async_step_camera_restream()

        for result in (chooser, direct, restream):
            assert "snapshot_trigger_dps" not in _fields(result)


# --------------------------------------------------------------------------
# Snapshot settings split by mode
# --------------------------------------------------------------------------


class TestSnapshotModeSplit:
    def test_off_asks_nothing(self):
        assert config_flow.snapshot_fields_for("off") == ()

    def test_on_demand_asks_for_triggers_and_a_still_url(self):
        assert set(config_flow.snapshot_fields_for("on_demand")) == {
            "snapshot_trigger_dps",
            "still_image_url_override",
        }

    def test_the_recording_modes_can_read_from_somewhere_else(self):
        """A restreamer already running for other reasons should be usable
        without also routing the camera entity through it."""
        for mode in ("warm", "buffer"):
            assert "snapshot_source_url" in config_flow.snapshot_fields_for(mode)
        assert "snapshot_source_url" not in config_flow.snapshot_fields_for("on_demand")
        assert "snapshot_source_url" not in config_flow.snapshot_fields_for("off")

    def test_only_buffer_mode_has_a_buffer(self):
        fields = config_flow.snapshot_fields_for("buffer")
        assert set(fields) == {
            "snapshot_trigger_dps",
            "snapshot_source_url",
            "snapshot_buffer_path",
            "snapshot_buffer_seconds",
            "snapshot_delay_ms",
        }

    def test_every_mode_the_video_module_offers_is_covered(self):
        for mode in config_flow.video.SNAPSHOT_MODES:
            config_flow.snapshot_fields_for(mode)

    @pytest.mark.asyncio
    async def test_the_mode_is_preselected_from_what_is_stored(self):
        flow = _options_flow({"snapshot_mode": "buffer"})
        result = await flow.async_step_snapshot_settings()
        assert result["data_schema"].defaults()["snapshot_mode"] == "buffer"

    @pytest.mark.asyncio
    async def test_the_mode_screen_asks_only_the_mode(self):
        flow = _options_flow({})
        result = await flow.async_step_snapshot_settings()
        assert _fields(result) == {"snapshot_mode", "back"}

    @pytest.mark.asyncio
    async def test_off_saves_straight_away_and_has_no_follow_up(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({7: "Button"})))
        result = await flow.async_step_snapshot_settings({"snapshot_mode": "off"})

        assert result["type"] == "menu"
        assert flow._config_entry.options["snapshot_mode"] == "off"

    @pytest.mark.asyncio
    async def test_warm_asks_for_triggers_and_nothing_about_a_buffer(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({7: "Button"})))
        result = await flow.async_step_snapshot_settings({"snapshot_mode": "warm"})

        assert result["step_id"] == "snapshot_options"
        assert _fields(result) == {
            "snapshot_trigger_dps",
            "snapshot_source_url",
            "back",
        }

    @pytest.mark.asyncio
    async def test_buffer_asks_for_everything_a_buffer_needs(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({7: "Button"})))
        result = await flow.async_step_snapshot_settings({"snapshot_mode": "buffer"})

        assert _fields(result) == {
            "snapshot_trigger_dps",
            "snapshot_source_url",
            "snapshot_buffer_path",
            "snapshot_buffer_seconds",
            "snapshot_delay_ms",
            "back",
        }

    @pytest.mark.asyncio
    async def test_a_device_without_datapoints_is_not_offered_a_trigger_list(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({})))
        result = await flow.async_step_snapshot_settings({"snapshot_mode": "warm"})
        # No datapoints means no trigger list; the picture settings still apply.
        assert _fields(result) == {
            "snapshot_source_url",
            "back",
        }

    @pytest.mark.asyncio
    async def test_the_follow_up_saves_the_mode_it_was_reached_with(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({7: "Button"})))
        await flow.async_step_snapshot_settings({"snapshot_mode": "buffer"})
        result = await flow.async_step_snapshot_options(
            {
                "snapshot_trigger_dps": ["7"],
                "snapshot_buffer_path": " /dev/shm/x ",
                "snapshot_buffer_seconds": 90,
                "snapshot_delay_ms": 3000,
            }
        )

        assert result["type"] == "menu"
        stored = flow._config_entry.options
        assert stored["snapshot_mode"] == "buffer"
        assert stored["snapshot_buffer_path"] == "/dev/shm/x"
        assert stored["snapshot_delay_ms"] == 3000
        assert stored["snapshot_trigger_dps"] == ["7"]


# --------------------------------------------------------------------------
# Navigation: getting back, and staying in the dialog
# --------------------------------------------------------------------------


class TestNavigation:
    def test_the_menu_offers_a_way_out_and_a_way_back_to_a_capture(self):
        assert config_flow.MENU_FINISH in config_flow.MENU_OPTIONS
        assert config_flow.MENU_CAPTURE_REVIEW in config_flow.MENU_OPTIONS

    @pytest.mark.asyncio
    async def test_only_the_close_entry_ends_the_flow(self):
        flow = _options_flow({"snapshot_mode": "warm"})
        result = await flow.async_step_finish()
        assert result["type"] == "create_entry"
        assert result["data"] == {"snapshot_mode": "warm"}

    @pytest.mark.parametrize(
        "step",
        [
            "connection",
            "camera_settings",
            "camera_direct",
            "camera_restream",
            "snapshot_settings",
            "dp_scan_mode",
            "assign_roles",
            "capture_review",
            "debug_settings",
        ],
    )
    @pytest.mark.asyncio
    async def test_every_sub_step_offers_a_way_back(self, step):
        hub = _FakeHub(_OptionsProfile({7: "Button"}))
        flow = _options_flow({}, hub=hub)
        result = await getattr(flow, f"async_step_{step}")()
        assert "back" in result["data_schema"], f"{step} has no way back"

    @pytest.mark.parametrize(
        "step",
        [
            "connection",
            "camera_settings",
            "camera_direct",
            "camera_restream",
            "snapshot_settings",
            "dp_scan_mode",
            "firmware_generation",
            "debug_settings",
        ],
    )
    @pytest.mark.asyncio
    async def test_going_back_changes_nothing(self, step):
        hub = _FakeHub(_OptionsProfile({7: "Button"}))
        hub.profile.firmware_version = "v5"
        flow = _options_flow({}, hub=hub)

        result = await getattr(flow, f"async_step_{step}")({"back": True})

        assert result["type"] == "menu"
        assert flow.hass.config_entries.option_writes == []
        assert flow.hass.config_entries.data_writes == []

    @pytest.mark.asyncio
    async def test_editing_a_datapoint_returns_to_the_list_not_to_nothing(self):
        """Submitting used to close the whole dialog, one datapoint at a time."""
        hub = _FakeHub(_OptionsProfile({7: "Button"}))
        flow = _options_flow({}, hub=hub)
        flow._editing_dp_id = 7

        result = await flow.async_step_dp_edit(
            {"name": "Doorbell", "entity_type": "binary_sensor"}
        )

        assert result["step_id"] == "dp_list"
        assert hub.updated == [(7, "Doorbell", "binary_sensor")]
        assert flow.hass.config_entries.reloads == ["1"]

    @pytest.mark.asyncio
    async def test_the_datapoint_list_offers_a_way_back(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({})))
        result = await flow.async_step_dp_list()
        assert "__back__" in result["data_schema"].value_for("dp_select").container

        back = await flow.async_step_dp_list({"dp_select": "__back__"})
        assert back["type"] == "menu"

    @pytest.mark.asyncio
    async def test_assigning_roles_returns_to_the_menu(self):
        hub = _FakeHub(_OptionsProfile({185: "Button"}))
        flow = _options_flow({}, hub=hub)
        flow._pending_dps = [_dp(185)]

        result = await flow.async_step_assign_roles(
            {"doorbell_button": "185", "motion": config_flow.ROLE_NONE,
             "onvif": config_flow.ROLE_NONE}
        )

        assert result["type"] == "menu"
        assert hub.applied[2]["doorbell_button"] == 185

    @pytest.mark.asyncio
    async def test_a_saved_screen_writes_options_without_closing(self):
        """Saving mid-flow is the same write async_create_entry would have done."""
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({})))
        result = await flow._async_save_options({"snapshot_mode": "warm"})

        assert result["type"] == "menu"
        assert flow.hass.config_entries.option_writes == [{"snapshot_mode": "warm"}]
        assert flow._config_entry.options == {"snapshot_mode": "warm"}

    @pytest.mark.asyncio
    async def test_debug_switch_saves_the_option_and_returns_to_the_menu(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({})))
        result = await flow.async_step_debug_settings({"debug_events": True})

        assert result["type"] == "menu"
        assert flow.hass.config_entries.option_writes == [{"debug_events": True}]
        assert flow._config_entry.options == {"debug_events": True}

    @pytest.mark.asyncio
    async def test_debug_switch_defaults_to_off(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({})))
        result = await flow.async_step_debug_settings()

        assert result["data_schema"].defaults()["debug_events"] is False


# --------------------------------------------------------------------------
# The live capture screen
# --------------------------------------------------------------------------


class _FakeCapture:
    def __init__(self, found, elapsed=1.0, running=True):
        self.found = list(found)
        self.elapsed = elapsed
        self.running = running
        self.stopped = 0

    def stop(self):
        self.stopped += 1
        self.running = False


class TestCaptureScreen:
    def test_a_value_with_braces_cannot_blank_the_screen(self):
        """Placeholders go through a message formatter that owns { and }."""
        assert "{" not in config_flow.safe_placeholder('{"cmd": 1}')
        assert "}" not in config_flow.safe_placeholder('{"cmd": 1}')

    def test_a_long_value_is_cut_down_to_a_list_item(self):
        assert len(config_flow.short_value("x" * 200)) <= 42

    def test_the_detail_shows_what_each_datapoint_carried(self):
        detail = config_flow.capture_detail([_dp(185, "raw", values=["aa", "bb"])])
        assert "DP 185" in detail
        assert "'aa'" in detail and "'bb'" in detail

    def test_the_datapoint_that_just_moved_is_marked(self):
        quiet = _dp(101, values=[1, 1])
        loud = _dp(185, "raw", values=["a", "b"])
        loud.observations[-1].at = 99.0
        detail = config_flow.capture_detail(
            [quiet, loud], config_flow.last_reported_dps(None, [quiet, loud])
        )
        assert "← just now" in detail.splitlines()[1]
        assert "← just now" not in detail.splitlines()[0]

    def test_everything_from_the_same_frame_is_marked_together(self):
        """A press often lands several datapoints in one status frame."""
        first = _dp(101, values=[1, 1])
        second = _dp(102, values=[1, 1])
        assert config_flow.last_reported_dps(None, [first, second]) == {101, 102}

    def test_a_capture_that_knows_its_own_answer_is_believed(self):
        capture = types.SimpleNamespace(last_dp_ids=[185])
        assert config_flow.last_reported_dps(capture, [_dp(101, values=[1, 1])]) == {185}

    def test_nothing_reported_is_not_the_same_as_gone_quiet(self):
        assert config_flow.capture_idle_seconds([], now=100.0) is None
        assert config_flow.capture_should_stop([], elapsed=30.0, now=100.0) is None

    def test_a_device_that_has_gone_quiet_ends_the_session(self):
        found = [_dp(185, values=["a", "b"])]  # last observation at t=1.0
        assert config_flow.capture_should_stop(found, elapsed=60.0, now=2.0) is None
        assert (
            config_flow.capture_should_stop(
                found, elapsed=60.0, now=1.0 + config_flow.LIVE_CAPTURE_IDLE_SECONDS
            )
            == "gone_quiet"
        )

    def test_a_forgotten_session_ends_anyway(self):
        assert (
            config_flow.capture_should_stop(
                [], elapsed=config_flow.LIVE_CAPTURE_MAX_SECONDS, now=0.0
            )
            == "time_limit"
        )

    @pytest.mark.asyncio
    async def test_the_screen_refreshes_itself_instead_of_waiting_for_a_click(self):
        capture = _FakeCapture([_dp(185, "raw", values=["a", "b"])], elapsed=4.0)
        # Recent enough that the "device has gone quiet" cut-off does not fire.
        capture.found[0].observations[-1].at = time.time()
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({}), capture=capture))

        result = await flow.async_step_live_capture()

        assert result["type"] == "progress"
        assert result["progress_action"] == "live_capture"
        assert result["progress_task"], "a progress step without a task never resumes"
        assert "DP 185" in result["description_placeholders"]["detail"]

    @pytest.mark.asyncio
    async def test_a_quiet_device_moves_on_to_the_review(self):
        capture = _FakeCapture([_dp(185, "raw", values=["a", "b"])], elapsed=60.0)
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({}), capture=capture))

        result = await flow.async_step_live_capture()

        assert result["type"] == "progress_done"
        assert result["next_step_id"] == "capture_review"
        assert capture.stopped == 1

    @pytest.mark.asyncio
    async def test_a_disconnected_device_says_so_instead_of_starting(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({}), available=False))
        result = await flow.async_step_live_capture()
        assert result["errors"] == {"base": "device_unavailable"}

    def test_closing_the_dialog_stops_the_capture_without_losing_it(self):
        """Closing is how you stop, so it must not read as throwing away."""
        capture = _FakeCapture([_dp(185, "raw", values=["a", "b"])])
        hub = _FakeHub(_OptionsProfile({}), capture=capture)
        flow = _options_flow({}, hub=hub)

        flow.async_remove()

        assert capture.stopped == 1
        assert hub.live_capture is capture, "the session must survive the dialog"

    def test_removing_a_flow_with_no_capture_is_harmless(self):
        _options_flow({}, hub=_FakeHub(_OptionsProfile({}))).async_remove()
        _options_flow({}, hub=None).async_remove()

    @pytest.mark.asyncio
    async def test_the_review_can_be_reached_without_a_capture(self):
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({})))
        result = await flow.async_step_capture_review()
        assert result["errors"] == {"base": "no_capture_session"}

    @pytest.mark.asyncio
    async def test_the_review_stops_a_session_that_is_still_running(self):
        capture = _FakeCapture([_dp(185, "raw", values=["a", "b"])])
        flow = _options_flow({}, hub=_FakeHub(_OptionsProfile({}), capture=capture))

        result = await flow.async_step_capture_review()

        assert capture.stopped == 1
        assert "185" in result["data_schema"].value_for("selected_dps").options


# --------------------------------------------------------------------------
# The split has to be visible in the translations too
# --------------------------------------------------------------------------


class TestSplitTranslations:
    def test_the_snapshot_trigger_moved_to_the_snapshot_screen(self, strings):
        steps = strings["options"]["step"]
        for camera_step in ("camera_settings", "camera_direct", "camera_restream"):
            assert "snapshot_trigger_dps" not in steps[camera_step]["data"]
        assert "snapshot_trigger_dps" in steps["snapshot_options"]["data"]

    def test_the_camera_screens_do_not_offer_both_routes_at_once(self, strings):
        steps = strings["options"]["step"]
        assert "stream_url_override" not in steps["camera_direct"]["data"]
        assert "rtsp_port" not in steps["camera_restream"]["data"]

    def test_the_measured_numbers_are_where_the_choice_is_made(self, strings):
        """Nobody picks a restreamer, or a snapshot mode, without a reason."""
        assert "15.94" in strings["options"]["step"]["camera_settings"]["description"]
        assert "5.86" in strings["options"]["step"]["snapshot_settings"]["description"]

    def test_force_onvif_says_what_it_depends_on(self, strings):
        text = strings["options"]["step"]["camera_settings"]["data_description"][
            "force_onvif"
        ]
        assert "ONVIF switch" in text
        assert "{onvif_role}" in text

    def test_every_step_with_a_back_field_names_it(self, strings):
        steps = strings["options"]["step"]
        for step_id, step in steps.items():
            if "back" in step.get("data", {}):
                assert step["data"]["back"], f"{step_id} has an unlabelled back"

    def test_the_capture_screen_says_that_closing_is_how_you_stop(self, strings):
        text = strings["options"]["progress"]["live_capture"]
        assert "Close this dialog" in text
        assert "nothing is lost" in text


class TestTheStillUrlIsASnapshotSetting:
    """It configures how a picture is taken, not how video is streamed."""

    @pytest.mark.asyncio
    async def test_the_camera_pages_do_not_ask_for_it(self):
        for source, step in (("direct", "camera_direct"), ("restream", "camera_restream")):
            flow = _options_flow({})
            result = await flow.async_step_camera_settings({"video_source": source})
            assert result["step_id"] == step
            assert "still_image_url_override" not in _fields(result)

    def test_only_on_demand_asks_for_the_still_url(self):
        """A still URL returns the picture as it is now, so it only fits the mode
        that also takes the picture now. In buffer/warm it would quietly hand
        back a live frame in place of the past one they exist to provide."""
        assert "still_image_url_override" in config_flow.snapshot_fields_for("on_demand")
        for mode in ("warm", "buffer", "off"):
            assert "still_image_url_override" not in config_flow.snapshot_fields_for(mode)

    def test_the_mode_that_takes_no_pictures_does_not(self):
        assert config_flow.snapshot_fields_for("off") == ()
