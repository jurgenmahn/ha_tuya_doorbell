"""Automatic DP (Data Point) discovery engine."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
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
)
from .protocol.connection import TuyaConnection
from .protocol.constants import Command

_LOGGER = logging.getLogger(__name__)


@dataclass
class DiscoveredDP:
    """Represents a discovered datapoint."""

    dp_id: int
    value: Any
    dp_type: str
    name: str | None = None
    is_known: bool = False
    min_value: int | None = None
    max_value: int | None = None
    enum_values: list[str] | None = None


class DPDiscoveryEngine:
    """Scans a Tuya device to discover all available datapoints."""

    def __init__(self, connection: TuyaConnection) -> None:
        self._connection = connection
        self._on_progress: Callable[[int, int], None] | None = None

    def set_progress_callback(self, callback: Callable[[int, int], None]) -> None:
        """Set callback for progress updates: (current, total)."""
        self._on_progress = callback

    async def scan_all(
        self,
        range_start: int = DP_SCAN_START,
        range_end: int = DP_SCAN_END,
    ) -> list[DiscoveredDP]:
        """Scan DP range to discover all available datapoints."""
        found: dict[int, DiscoveredDP] = {}
        total = range_end - range_start + 1

        # Phase 1: Query all DPs to get current state
        _LOGGER.debug("DP scan phase 1: querying all DPs")
        try:
            dps = await self._connection.query_dps()
            for dp_str, value in dps.items():
                dp_id = int(dp_str)
                found[dp_id] = self.classify_dp(dp_id, value)
        except Exception:
            _LOGGER.debug("Initial DP query failed", exc_info=True)

        # Phase 2: Batch scan using UPDATEDPS
        _LOGGER.debug("DP scan phase 2: batch UPDATEDPS scan")
        collected: dict[str, Any] = {}

        def _on_update(dps: dict) -> None:
            collected.update(dps)

        unregister = self._connection.on_status_update(_on_update)

        try:
            progress = 0
            for batch_start in range(range_start, range_end + 1, DP_SCAN_BATCH_SIZE):
                batch_end = min(batch_start + DP_SCAN_BATCH_SIZE, range_end + 1)
                dp_ids = list(range(batch_start, batch_end))

                try:
                    result = await self._connection.update_dps(dp_ids)
                    for dp_str, value in result.items():
                        dp_id = int(dp_str)
                        if dp_id not in found:
                            found[dp_id] = self.classify_dp(dp_id, value)
                except Exception:
                    pass

                # Check collected push updates
                for dp_str, value in list(collected.items()):
                    dp_id = int(dp_str)
                    if dp_id not in found:
                        found[dp_id] = self.classify_dp(dp_id, value)
                collected.clear()

                progress += len(dp_ids)
                if self._on_progress:
                    self._on_progress(progress, total)

                # Small delay to avoid overwhelming the device
                await asyncio.sleep(0.2)

        finally:
            unregister()

        result_list = sorted(found.values(), key=lambda dp: dp.dp_id)
        _LOGGER.info("DP scan complete: found %s datapoints", len(result_list))
        return result_list

    async def monitor_passive(self, duration: float = 30.0) -> list[DiscoveredDP]:
        """Listen for spontaneous DP updates for a duration."""
        found: dict[int, DiscoveredDP] = {}

        def _on_update(dps: dict) -> None:
            for dp_str, value in dps.items():
                dp_id = int(dp_str)
                if dp_id not in found:
                    found[dp_id] = self.classify_dp(dp_id, value)
                    _LOGGER.debug("Passive discovery: DP %s = %r", dp_id, value)

        unregister = self._connection.on_status_update(_on_update)
        try:
            await asyncio.sleep(duration)
        finally:
            unregister()

        return sorted(found.values(), key=lambda dp: dp.dp_id)

    def classify_dp(self, dp_id: int, value: Any) -> DiscoveredDP:
        """Classify a DP based on its value and known mappings."""
        known = KNOWN_DPS.get(dp_id)
        dp_type = self.detect_type(dp_id, value)

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


# DP IDs known to be numeric (not boolean) even when value is 0 or 1
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
