"""Tests for datapoint discovery: observations, live capture, and no invention.

The scan used to bolt the known event datapoints onto every result, whether the
device reported them or not. That made it look like it worked on the one model
it was written for, and produced two sensors wired to nothing on everyone
else's. These tests pin down that it no longer invents datapoints, and that the
replacement -- watching a real device while the user presses the button -- can
find them for real.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest

from custom_components.lsc_tuya_doorbell.const import (
    DP_DOORBELL_BUTTON,
    DP_MOTION_DETECTION,
)
from custom_components.lsc_tuya_doorbell.dp_discovery import (
    DiscoveredDP,
    DPDiscoveryEngine,
    LiveCapture,
)


class FakeConnection:
    """Just enough connection to drive discovery without a device."""

    def __init__(self, query_result: dict | None = None) -> None:
        self.is_connected = True
        self._query_result = query_result or {}
        self._callbacks: list[Callable[[dict], None]] = []
        self.unregister_calls = 0

    def on_status_update(self, callback: Callable[[dict], None]) -> Callable[[], None]:
        self._callbacks.append(callback)

        def _unregister() -> None:
            self.unregister_calls += 1
            if callback in self._callbacks:
                self._callbacks.remove(callback)

        return _unregister

    async def query_dps(self, *args: Any, **kwargs: Any) -> dict:
        return dict(self._query_result)

    def push(self, dps: dict) -> None:
        """Pretend the device reported something."""
        for callback in list(self._callbacks):
            callback(dps)

    @property
    def listener_count(self) -> int:
        return len(self._callbacks)


@pytest.fixture
def engine() -> DPDiscoveryEngine:
    return DPDiscoveryEngine(FakeConnection(), firmware_version="4")


# --------------------------------------------------------------------------
# Observations
# --------------------------------------------------------------------------


def test_a_datapoint_remembers_every_value_it_carried() -> None:
    dp = DiscoveredDP(dp_id=185, value=None, dp_type="raw")
    dp.record("a", at=1.0)
    dp.record("b", at=2.0)

    assert [o.value for o in dp.observations] == ["a", "b"]
    assert dp.value == "b"


def test_distinct_values_keeps_first_appearance_order() -> None:
    dp = DiscoveredDP(dp_id=1, value=None, dp_type="int")
    for value in (3, 1, 3, 2, 1):
        dp.record(value)

    assert dp.distinct_values == [3, 1, 2]


def test_history_is_capped_so_a_chatty_datapoint_cannot_grow_forever() -> None:
    dp = DiscoveredDP(dp_id=1, value=None, dp_type="int")
    for i in range(DiscoveredDP.MAX_OBSERVATIONS + 25):
        dp.record(i)

    assert len(dp.observations) == DiscoveredDP.MAX_OBSERVATIONS
    assert dp.observations[-1].value == DiscoveredDP.MAX_OBSERVATIONS + 24


def test_one_sample_is_never_enough_to_call_something_an_event() -> None:
    dp = DiscoveredDP(dp_id=185, value=None, dp_type="raw")
    dp.record("press")
    assert dp.looks_like_an_event is False


def test_a_datapoint_that_keeps_changing_looks_like_an_event() -> None:
    dp = DiscoveredDP(dp_id=185, value=None, dp_type="raw")
    dp.record("press-1")
    dp.record("press-2")
    assert dp.looks_like_an_event is True


def test_a_datapoint_that_settles_does_not() -> None:
    """A setting reports a value and stays there. That is not an event."""
    dp = DiscoveredDP(dp_id=101, value=None, dp_type="bool")
    for _ in range(5):
        dp.record(True)
    assert dp.looks_like_an_event is False


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def test_the_table_wins_by_default(engine: DPDiscoveryEngine) -> None:
    dp = engine.classify_dp(101, 1)
    assert dp.is_known is True
    assert dp.name == "Record Switch"


def test_when_learning_the_observation_wins(engine: DPDiscoveryEngine) -> None:
    """A capture exists to learn firmware the tables do not describe."""
    from_table = engine.classify_dp(101, "some string payload")
    from_device = engine.classify_dp(101, "some string payload", trust_observation=True)

    assert from_table.dp_type == "bool"        # what the table claims
    assert from_device.dp_type != "bool"       # what the device actually sent
    assert from_device.name == "Record Switch"  # the table may still lend a name
    assert from_device.is_known is False


def test_classification_follows_the_firmware() -> None:
    v4 = DPDiscoveryEngine(FakeConnection(), firmware_version="4").classify_dp(110, 1)
    v5 = DPDiscoveryEngine(FakeConnection(), firmware_version="5").classify_dp(110, 1)

    assert v4.name != v5.name


# --------------------------------------------------------------------------
# The scan no longer invents datapoints
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_scan_does_not_add_event_datapoints_the_device_never_sent() -> None:
    """The bug that made this integration work on exactly one doorbell."""
    connection = FakeConnection(query_result={"101": True})
    connection.is_connected = False  # stop after the first phase; enough to check
    engine = DPDiscoveryEngine(connection, firmware_version="4")

    result = await engine.scan_all()

    found = {dp.dp_id for dp in result.discovered}
    assert DP_DOORBELL_BUTTON not in found
    assert DP_MOTION_DETECTION not in found


# --------------------------------------------------------------------------
# Live capture
# --------------------------------------------------------------------------


def test_capture_records_what_the_device_reports() -> None:
    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection, firmware_version="4"))

    capture.start()
    connection.push({"185": "press-1"})
    connection.push({"185": "press-2", "115": "motion"})
    capture.stop()

    found = {dp.dp_id: dp for dp in capture.found}
    assert set(found) == {115, 185}
    assert len(found[185].observations) == 2


def test_capture_singles_out_what_behaves_like_an_event() -> None:
    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection, firmware_version="4"))

    capture.start()
    connection.push({"185": "press-1", "101": True})
    connection.push({"185": "press-2", "101": True})
    capture.stop()

    assert [dp.dp_id for dp in capture.event_candidates] == [185]


def test_capture_stops_listening_when_stopped() -> None:
    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection))

    capture.start()
    assert connection.listener_count == 1
    capture.stop()

    assert connection.listener_count == 0
    connection.push({"185": "ignored"})
    assert capture.found == []


def test_start_and_stop_are_both_safe_to_repeat() -> None:
    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection))

    capture.start()
    capture.start()
    assert connection.listener_count == 1

    capture.stop()
    capture.stop()
    assert connection.unregister_calls == 1


def test_stopping_a_capture_that_never_started_is_harmless() -> None:
    capture = LiveCapture(DPDiscoveryEngine(FakeConnection()))
    capture.stop()
    assert capture.running is False


def test_a_nonsense_datapoint_key_is_reported_not_fatal() -> None:
    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection))

    capture.start()
    connection.push({"not-a-number": 1, "185": "press"})
    capture.stop()

    assert [dp.dp_id for dp in capture.found] == [185]


def test_summary_tells_the_user_when_nothing_arrived() -> None:
    capture = LiveCapture(DPDiscoveryEngine(FakeConnection()))
    assert "doorbell" in capture.summary().lower()


def test_summary_lists_what_was_seen() -> None:
    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection, firmware_version="4"))

    capture.start()
    connection.push({"185": "press-1"})
    connection.push({"185": "press-2"})
    capture.stop()

    assert "DP 185" in capture.summary()


def test_stopping_a_capture_records_what_each_datapoint_carried(caplog) -> None:
    """The values are the evidence; without them the session leaves no trace.

    Working out what an undocumented datapoint is for means knowing what it
    actually sent, and that only exists in memory while the session runs.
    """
    import logging

    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection, firmware_version="4"))

    capture.start()
    connection.push({"244": "0"})
    connection.push({"244": "1"})
    with caplog.at_level(logging.INFO):
        capture.stop()

    line = next(m for m in caplog.messages if "DP 244" in m)
    assert "'0'" in line and "'1'" in line
    assert "2 time(s)" in line
    assert "looks like an event" in line


def test_a_datapoint_that_never_changes_is_not_called_an_event(caplog) -> None:
    import logging

    connection = FakeConnection()
    capture = LiveCapture(DPDiscoveryEngine(connection, firmware_version="4"))

    capture.start()
    for _ in range(4):
        connection.push({"101": True})
    with caplog.at_level(logging.INFO):
        capture.stop()

    line = next(m for m in caplog.messages if "DP 101" in m)
    assert "looks like an event" not in line
