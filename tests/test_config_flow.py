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
        assert config_flow.snapshot_trigger_options(_Profile({})) == {}


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


class TestRoles:
    def test_every_role_can_be_left_unassigned(self):
        options = config_flow.role_choice_options([_dp(101)])
        assert config_flow.ROLE_NONE in options

    def test_a_role_defaults_to_what_the_profile_already_says(self):
        dps = [_dp(101), _dp(185)]
        assert (
            config_flow.suggested_role_dp("doorbell_button", dps, {"doorbell_button": 185})
            == "185"
        )

    def test_a_role_is_never_guessed_from_a_datapoint_number(self):
        """DP 185 is the doorbell button on one model, and nothing on the rest."""
        assert (
            config_flow.suggested_role_dp("doorbell_button", [_dp(185)], {})
            == config_flow.ROLE_NONE
        )

    def test_a_stale_role_pointing_outside_the_selection_is_dropped(self):
        assert (
            config_flow.suggested_role_dp(
                "motion", [_dp(101)], {"motion": 999}
            )
            == config_flow.ROLE_NONE
        )
