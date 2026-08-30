"""Binary sensor platform for LSC Tuya Doorbell."""

from __future__ import annotations

import logging
from typing import Any, Callable

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN, ENTITY_BINARY_SENSOR
from .dp_registry import DPDefinition
from .entity import LscTuyaEntity
from .entity_meta import (
    ROLE_BINARY_DEVICE_CLASS,
    definitions_for_platform,
    device_class_for,
    resolve_event_reset_timeout,
)
from .hub import DeviceHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up binary sensors from a config entry."""
    hub: DeviceHub = hass.data[DOMAIN][config_entry.entry_id]

    reset_timeout = resolve_event_reset_timeout(config_entry.options, config_entry.data)
    definitions = definitions_for_platform(hub.profile, ENTITY_BINARY_SENSOR)

    entities: list[BinarySensorEntity] = [
        LscTuyaBinarySensor(hub, dp_def, reset_timeout) for dp_def in definitions
    ]

    if not definitions:
        # No profile, or a profile without binary datapoints. Creating a
        # doorbell and a motion sensor anyway is what used to leave people with
        # two entities wired to datapoints their device never sends.
        _LOGGER.warning(
            "No binary datapoints known for %s, so no event sensors were created. "
            "Run the datapoint scan (or the live capture, which watches the "
            "device while you press the button) to find them",
            hub.device_id,
        )

    # Always add the Connected sensor (not DP-based)
    entities.append(LscTuyaConnectedSensor(hub))

    _LOGGER.debug("BinarySensor setup: creating %d entities", len(entities))
    async_add_entities(entities)


def _binary_device_class(
    dp_def: DPDefinition, role: str | None
) -> BinarySensorDeviceClass | None:
    """Device class for a binary datapoint, or None when nothing is known.

    An unknown name is dropped with a warning rather than handed to Home
    Assistant, which would reject the entity outright.
    """
    name = device_class_for(dp_def, role, ROLE_BINARY_DEVICE_CLASS)
    if not name:
        return None
    try:
        return BinarySensorDeviceClass(name)
    except ValueError:
        _LOGGER.warning(
            "DP %d declares device class %r, which Home Assistant does not know "
            "for a binary sensor; showing it without one",
            dp_def.dp_id,
            name,
        )
        return None


class LscTuyaBinarySensor(LscTuyaEntity, BinarySensorEntity):
    """Binary sensor for event datapoints such as a button press or motion."""

    def __init__(
        self,
        hub: DeviceHub,
        dp_definition: DPDefinition,
        reset_timeout: float,
    ) -> None:
        super().__init__(hub, dp_definition)
        self._is_on = False
        self._reset_timeout = reset_timeout
        self._cancel_reset: Callable[[], None] | None = None
        self._last_image_url: str | None = None
        self._attr_device_class = _binary_device_class(dp_definition, self._role)

    @property
    def is_on(self) -> bool:
        """Return True if the binary sensor is on."""
        return self._is_on

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes.

        The counter comes from the hub, which is the same one the fired event
        carries. A second counter here drifted from it on every restart.
        """
        return {
            "dp_id": self._dp_id,
            "role": self._role,
            "event_counter": self._hub.event_count(self._dp_id),
            "last_image_url": self._last_image_url,
            "last_snapshot_url": self._hub.last_snapshot_url,
            "last_clip_url": self._hub.last_clip_url,
        }

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        # The state is written the moment the device reports the press, with
        # whatever snapshot URL exists at that point -- which is the previous
        # caller's. The picture arrives seconds later; this puts the new URL in
        # the attributes without disturbing the auto-reset timer.
        self.async_on_remove(
            self._hub.on_snapshot_change(self._handle_snapshot_ready)
        )

    async def async_will_remove_from_hass(self) -> None:
        await super().async_will_remove_from_hass()
        self._cancel_pending_reset()

    @callback
    def _handle_snapshot_ready(self, url: str | None) -> None:
        """Rewrite the state once the picture for the fired event exists."""
        _LOGGER.debug("BinarySensor DP %d: snapshot ready (%s)", self._dp_id, url)
        self.async_write_ha_state()

    def _handle_dp_update(self, value: Any) -> None:
        """Handle event DP update — turn on and schedule auto-reset."""
        _LOGGER.debug("BinarySensor DP %d: triggered (value=%r)", self._dp_id, value)
        self._is_on = True

        # The hub decides whether this payload can carry a URL at all, from the
        # definition -- running four decoders over a plain boolean is noise.
        image_url = self._hub.extract_image_url(value, self._dp_def)
        if image_url:
            self._last_image_url = image_url

        self._cancel_pending_reset()
        self._cancel_reset = async_call_later(
            self.hass,
            self._reset_timeout,
            self._auto_reset,
        )

        self.async_write_ha_state()

    @callback
    def _auto_reset(self, _now: Any = None) -> None:
        """Reset binary sensor to off after timeout."""
        _LOGGER.debug("BinarySensor DP %d: auto-reset to off", self._dp_id)
        self._is_on = False
        self._cancel_reset = None
        self.async_write_ha_state()

    def _cancel_pending_reset(self) -> None:
        """Drop a pending auto-reset, if any."""
        if self._cancel_reset is not None:
            self._cancel_reset()
            self._cancel_reset = None

    def _restore_state(self, last_state: Any) -> None:
        """Restore state — binary sensors always start as off."""
        self._is_on = False
        attributes = last_state.attributes or {}
        self._last_image_url = attributes.get("last_image_url")
        # The hub owns the counter; this only hands back what survived the
        # restart so the numbering continues instead of starting over.
        restored = attributes.get("event_counter")
        if isinstance(restored, int) and restored > 0:
            self._hub.seed_event_count(self._dp_id, restored)
        _LOGGER.debug("BinarySensor DP %d: restored (counter=%s)", self._dp_id, restored)


class LscTuyaConnectedSensor(RestoreEntity, BinarySensorEntity):
    """Binary sensor that reflects device connection state (hub.available)."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_name = "Connected"

    def __init__(self, hub: DeviceHub) -> None:
        super().__init__()
        self._hub = hub
        self._attr_unique_id = f"{hub.device_id}_connected"

    @property
    def device_info(self):
        return self._hub.device_info

    @property
    def is_on(self) -> bool:
        return self._hub.available

    @callback
    def _handle_connection_change(self, connected: bool) -> None:
        """Handle connection state change from hub."""
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register connection callback when added to HA."""
        await super().async_added_to_hass()
        self.async_on_remove(
            self._hub.on_connection_change(self._handle_connection_change)
        )
