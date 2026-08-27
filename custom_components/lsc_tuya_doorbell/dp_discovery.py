"""Automatic DP (Data Point) discovery engine."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .const import (
    DP_SCAN_BATCH_SIZE,
    DP_SCAN_END,
    DP_SCAN_START,
    DP_TYPE_BOOL,
    DP_TYPE_ENUM,
    DP_TYPE_INT,
    DP_TYPE_RAW,
    DP_TYPE_STRING,
    KNOWN_DPS,
    known_dps_for,
)
from .protocol.connection import TuyaConnection
from .protocol.constants import Command

_LOGGER = logging.getLogger(__name__)


@dataclass
class DPObservation:
    """One value seen on a datapoint, and when."""

    value: Any
    at: float


@dataclass
class DiscoveredDP:
    """Represents a discovered datapoint.

    Keeps every value it was seen carrying, not just the last one. A single
    sample cannot tell a button press apart from a three-position enum apart
    from a heartbeat that ticks every few seconds -- the history can, and that
    is what makes learning an unknown firmware possible instead of guessing.
    """

    dp_id: int
    value: Any
    dp_type: str
    name: str | None = None
    is_known: bool = False
    min_value: int | None = None
    max_value: int | None = None
    enum_values: list[str] | None = None
    observations: list[DPObservation] = field(default_factory=list)

    # Enough to characterise a datapoint; a chatty one must not grow without
    # bound during a capture session the user leaves running.
    MAX_OBSERVATIONS = 50

    def record(self, value: Any, at: float | None = None) -> None:
        """Note that the datapoint carried this value."""
        self.value = value
        self.observations.append(DPObservation(value=value, at=at or time.time()))
        if len(self.observations) > self.MAX_OBSERVATIONS:
            del self.observations[0]

    @property
    def distinct_values(self) -> list[Any]:
        """The different values seen, in the order they first appeared."""
        seen: list[Any] = []
        for observation in self.observations:
            if observation.value not in seen:
                seen.append(observation.value)
        return seen

    @property
    def looks_like_an_event(self) -> bool:
        """Whether this behaves like something that fires rather than something that is.

        An event datapoint reports repeatedly without settling: the doorbell
        button carries a fresh payload on every press. A setting reports a value
        and then stays there. Two or more observations carrying different values
        is the cheapest signal that separates the two.
        """
        return len(self.observations) >= 2 and len(self.distinct_values) >= 2


@dataclass
class ScanResult:
    """Result of a DP scan, including progress info for resume."""

    discovered: list[DiscoveredDP]
    last_batch_end: int  # last DP ID that was scanned
    completed: bool  # True if full range was covered


class DPDiscoveryEngine:
    """Scans a Tuya device to discover all available datapoints."""

    def __init__(
        self, connection: TuyaConnection, firmware_version: str | None = None
    ) -> None:
        self._connection = connection
        # Which known-DP table applies. Without it the lookup falls back to the
        # union of both firmware generations, where v5 silently wins the three
        # datapoints the two disagree about.
        self.firmware_version = firmware_version
        self._on_progress: Callable[[int, int, int, int, list[int]], None] | None = None

    def set_progress_callback(
        self, callback: Callable[[int, int, int, int, list[int]], None]
    ) -> None:
        """Set callback for progress updates: (current, total, batch_start, batch_end, found_dp_ids)."""
        self._on_progress = callback

    async def scan_all(
        self,
        range_start: int = DP_SCAN_START,
        range_end: int = DP_SCAN_END,
    ) -> ScanResult:
        """Scan DP range to discover all available datapoints.

        Returns a ScanResult with progress info so the caller can resume
        if the scan was interrupted by a disconnect.
        """
        found: dict[int, DiscoveredDP] = {}
        total = range_end - range_start + 1
        completed = True
        last_batch_end = range_start - 1

        # Phase 1: Query all DPs to get current state
        _LOGGER.info("DP scan phase 1: querying current DP state")
        try:
            dps = await self._connection.query_dps()
            if dps:
                _LOGGER.info("DP scan phase 1: got %d DPs from query: %s", len(dps), list(dps.keys()))
                for dp_str, value in dps.items():
                    dp_id = int(dp_str)
                    found[dp_id] = self.classify_dp(dp_id, value)
            else:
                _LOGGER.info("DP scan phase 1: query returned empty")
        except Exception as err:
            _LOGGER.warning("DP scan phase 1: query failed: %s", err)

        # Phase 2: Sequential batch scan using UPDATEDPS
        num_batches = (total + DP_SCAN_BATCH_SIZE - 1) // DP_SCAN_BATCH_SIZE
        _LOGGER.info(
            "DP scan phase 2: scanning DP %d-%d in %d batches of %d (connected=%s)",
            range_start, range_end, num_batches, DP_SCAN_BATCH_SIZE,
            self._connection.is_connected,
        )
        collected: dict[str, Any] = {}

        def _on_update(dps: dict) -> None:
            collected.update(dps)

        unregister = self._connection.on_status_update(_on_update)

        try:
            progress = 0
            batch_num = 0
            for batch_start in range(range_start, range_end + 1, DP_SCAN_BATCH_SIZE):
                batch_end = min(batch_start + DP_SCAN_BATCH_SIZE, range_end + 1)
                dp_ids = list(range(batch_start, batch_end))
                batch_num += 1

                try:
                    _LOGGER.info(
                        "DP scan batch %d/%d: DPs %d-%d (connected=%s)",
                        batch_num, num_batches, batch_start, batch_end - 1,
                        self._connection.is_connected,
                    )
                    result = await self._connection.update_dps(dp_ids, max_retries=1)
                    if result:
                        _LOGGER.info("DP scan batch %d/%d: got %d DPs: %s", batch_num, num_batches, len(result), list(result.keys()))
                    for dp_str, value in result.items():
                        dp_id = int(dp_str)
                        if dp_id not in found:
                            found[dp_id] = self.classify_dp(dp_id, value)
                            _LOGGER.info(
                                "DP scan: discovered DP %d = %r (%s)",
                                dp_id, value, found[dp_id].dp_type,
                            )
                except Exception as err:
                    _LOGGER.warning("DP scan batch %d/%d failed: %s", batch_num, num_batches, err)

                last_batch_end = batch_end - 1

                # Check collected push updates
                for dp_str, value in list(collected.items()):
                    dp_id = int(dp_str)
                    if dp_id not in found:
                        found[dp_id] = self.classify_dp(dp_id, value)
                        _LOGGER.info("DP scan: discovered DP %d via push update", dp_id)
                collected.clear()

                progress += len(dp_ids)
                if self._on_progress:
                    self._on_progress(
                        progress,
                        total,
                        batch_start,
                        batch_end - 1,
                        sorted(found.keys()),
                    )

                # Small delay to avoid overwhelming the device
                await asyncio.sleep(0.1)

                # Bail early if the device disconnected
                if not self._connection.is_connected:
                    _LOGGER.warning(
                        "DP scan aborted after batch %d/%d: device disconnected (found %d DPs so far)",
                        batch_num, num_batches, len(found),
                    )
                    completed = False
                    break

        finally:
            unregister()

        # Event datapoints cannot be found by querying -- they only carry a value
        # when someone presses the button or walks past. They are deliberately
        # NOT added here from the known-DP table.
        #
        # That is what this code used to do, and it is why the integration
        # appeared to work: every scan result got DP 115 and 185 bolted on
        # whether the device reported them or not. On the one model it was
        # written for that guess was right. On anyone else's doorbell it
        # produced two sensors wired to datapoints their device never sends,
        # while the real event datapoints were never found at all.
        #
        # Use a live capture session instead: ask the user to press the button
        # while listening. That finds the real number on any firmware.
        missing_events = [
            dp_id
            for dp_id, dp_def in known_dps_for(self.firmware_version).items()
            if dp_def.get("is_event") and dp_id not in found
        ]
        if missing_events:
            _LOGGER.info(
                "DP scan: %s are event datapoints on known firmware and did not "
                "answer a query, which is expected. Run a live capture and press "
                "the button to find the ones this device actually uses.",
                ", ".join(f"DP {dp_id}" for dp_id in sorted(missing_events)),
            )

        result_list = sorted(found.values(), key=lambda dp: dp.dp_id)
        _LOGGER.info(
            "DP scan %s: found %d datapoints (last_batch_end=%d)",
            "complete" if completed else "interrupted",
            len(result_list),
            last_batch_end,
        )
        return ScanResult(
            discovered=result_list,
            last_batch_end=last_batch_end,
            completed=completed,
        )

    def start_live_capture(self) -> LiveCapture:
        """Begin listening for whatever the device says, until told to stop.

        This is how an unknown firmware is learned: the user presses the button,
        triggers motion and works through the app while everything the device
        reports is recorded. Querying can never find an event datapoint, because
        it only carries a value at the moment it fires.

        Listening rides on the existing connection, so nothing is disturbed and
        no second session is opened.
        """
        return LiveCapture(self)

    async def monitor_passive(self, duration: float = 30.0) -> list[DiscoveredDP]:
        """Listen for spontaneous DP updates for a fixed duration.

        Kept for the service call. Interactive use wants start_live_capture(),
        which ends when the user says so rather than on a timer.
        """
        capture = self.start_live_capture()
        capture.start()
        try:
            await asyncio.sleep(duration)
        finally:
            capture.stop()
        return capture.found

    def classify_dp(
        self, dp_id: int, value: Any, *, trust_observation: bool = False
    ) -> DiscoveredDP:
        """Classify a DP from its value and, where it helps, the known table.

        `trust_observation` is for learning an unknown firmware. The table then
        only lends a name; what the datapoint actually carried decides its type.
        Without that, a device whose DP 134 does something entirely different
        still gets labelled from the table it does not follow.
        """
        known = known_dps_for(self.firmware_version).get(dp_id)
        dp_type = self.detect_type(dp_id, value)

        if known and trust_observation:
            return DiscoveredDP(
                dp_id=dp_id,
                value=value,
                dp_type=dp_type,
                name=known["name"],
                is_known=False,
            )

        if known:
            return DiscoveredDP(
                dp_id=dp_id,
                value=value,
                dp_type=known["dp_type"],
                name=known["name"],
                is_known=True,
                min_value=known.get("min"),
                max_value=known.get("max"),
                enum_values=list(known["options"].values()) if "options" in known else None,
            )

        return DiscoveredDP(
            dp_id=dp_id,
            value=value,
            dp_type=dp_type,
            name=f"DP {dp_id}",
            is_known=False,
        )

    @staticmethod
    def detect_type(dp_id: int, value: Any) -> str:
        """Infer the DP type from its value."""
        if isinstance(value, bool):
            return DP_TYPE_BOOL

        if isinstance(value, int):
            if value in (0, 1) and dp_id not in _KNOWN_NUMERIC_DPS:
                return DP_TYPE_BOOL
            return DP_TYPE_INT

        if isinstance(value, str):
            # Check if it's a JSON/base64 payload (raw)
            if _is_raw_payload(value):
                return DP_TYPE_RAW
            # Check if it looks like an enum value (single digit or short string)
            if len(value) <= 3 and value.isdigit():
                return DP_TYPE_ENUM
            return DP_TYPE_STRING

        if isinstance(value, (dict, list)):
            return DP_TYPE_RAW

        if isinstance(value, bytes):
            return DP_TYPE_RAW

        return DP_TYPE_STRING


class LiveCapture:
    """A learning session that records everything the device reports.

    Runs until stopped, because the useful length is however long it takes the
    user to press the button and walk through the app -- not a number we can
    pick in advance. Every value is recorded, not just the first, so a datapoint
    that fires repeatedly can be told apart from one that holds a setting.
    """

    def __init__(self, engine: DPDiscoveryEngine) -> None:
        self._engine = engine
        self._found: dict[int, DiscoveredDP] = {}
        self._unregister: Callable[[], None] | None = None
        self._started_at: float | None = None

    def start(self) -> None:
        """Begin recording. Safe to call twice."""
        if self._unregister is not None:
            return
        self._started_at = time.time()
        self._unregister = self._engine._connection.on_status_update(self._on_update)
        _LOGGER.info(
            "Live capture started -- press the doorbell, trigger motion, and use "
            "the app; every datapoint the device reports is being recorded"
        )

    def stop(self) -> None:
        """Stop recording. Safe to call twice, and safe to call after start failed."""
        if self._unregister is None:
            return
        self._unregister()
        self._unregister = None
        _LOGGER.info(
            "Live capture stopped after %.0fs: %d datapoint(s) seen",
            self.elapsed, len(self._found),
        )
        # At info level, because this is the whole point of having run one: what
        # each datapoint carried is what tells you what it is for, and it is the
        # only trace that survives the session.
        for dp in self.found:
            _LOGGER.info(
                "Live capture: DP %d (%s) reported %d time(s), value(s): %s%s",
                dp.dp_id, dp.dp_type, len(dp.observations),
                ", ".join(repr(v) for v in dp.distinct_values[:6]),
                " -- looks like an event" if dp.looks_like_an_event else "",
            )

    def _on_update(self, dps: dict) -> None:
        now = time.time()
        for dp_str, value in dps.items():
            try:
                dp_id = int(dp_str)
            except (TypeError, ValueError):
                _LOGGER.warning("Live capture: ignoring non-numeric datapoint %r", dp_str)
                continue

            existing = self._found.get(dp_id)
            if existing is None:
                # trust_observation: the point of a capture is to learn a device
                # the tables do not describe, so what it does outranks what they say.
                existing = self._engine.classify_dp(dp_id, value, trust_observation=True)
                self._found[dp_id] = existing

            # Log the first sight of each distinct value. Without this the only
            # record of what a datapoint actually carried is in memory, and it
            # goes away when the session ends -- which is precisely the evidence
            # anyone needs to work out what an unknown datapoint is for.
            first_time = value not in existing.distinct_values
            existing.record(value, at=now)
            if first_time:
                _LOGGER.debug(
                    "Live capture: DP %d carried %r (%s)",
                    dp_id, value, existing.dp_type,
                )

    @property
    def running(self) -> bool:
        return self._unregister is not None

    @property
    def elapsed(self) -> float:
        return 0.0 if self._started_at is None else time.time() - self._started_at

    @property
    def found(self) -> list[DiscoveredDP]:
        """What has been seen so far, lowest datapoint first."""
        return sorted(self._found.values(), key=lambda dp: dp.dp_id)

    @property
    def event_candidates(self) -> list[DiscoveredDP]:
        """Datapoints behaving like something that fires rather than something that is."""
        return [dp for dp in self.found if dp.looks_like_an_event]

    def summary(self) -> str:
        """One line for the progress form, so the user can see it working."""
        if not self._found:
            return "Nothing reported yet — try pressing the doorbell."
        return ", ".join(
            f"DP {dp.dp_id}"
            + (f" ({dp.name})" if dp.name and not dp.name.startswith("DP ") else "")
            + (" ⟳" if dp.looks_like_an_event else "")
            for dp in self.found
        )


# DP IDs known to be numeric (not boolean) even when value is 0 or 1.
#
# A seed, not a fact: it was read off two firmware generations of one model. A
# capture that has watched a datapoint carry something other than 0 or 1 knows
# better than this list does.
_KNOWN_NUMERIC_DPS = {110, 109, 150, 135, 154, 139}


def _is_raw_payload(value: str) -> bool:
    """Check if a string value looks like a raw/complex payload."""
    if not value:
        return False
    # JSON object or array
    if (value.startswith("{") and value.endswith("}")) or (value.startswith("[") and value.endswith("]")):
        try:
            json.loads(value)
            return True
        except json.JSONDecodeError:
            pass
    # Base64 encoded data (common in image payloads)
    if len(value) > 20:
        try:
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) > 10:
                return True
        except Exception:
            pass
    return False
