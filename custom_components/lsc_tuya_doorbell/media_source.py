"""Media source: browse and play the doorbell's recorded clips in Home Assistant.

Clip mode writes an mp4 per event, but a clip has no native entity to show it.
This exposes the clips in the Media browser, so they can be played on any player
or straight in the browser.
"""

from __future__ import annotations

from pathlib import Path

from homeassistant.components.media_player import BrowseError, MediaClass, MediaType
from homeassistant.components.media_source import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
    Unresolvable,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH, DOMAIN
from .hub import local_url_for
from .media_helpers import clip_filenames

MIME_TYPE = "video/mp4"


async def async_get_media_source(hass: HomeAssistant) -> MediaSource:
    """Set up the doorbell clip media source."""
    return DoorbellClipsMediaSource(hass)


class DoorbellClipsMediaSource(MediaSource):
    """Browses the recorded clips of every configured doorbell."""

    name = "Doorbell clips"

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__(DOMAIN)
        self.hass = hass

    def _directory(self, entry: ConfigEntry) -> str:
        return entry.options.get(CONF_SNAPSHOT_PATH, DEFAULT_SNAPSHOT_PATH)

    async def async_resolve_media(self, item: MediaSourceItem) -> PlayMedia:
        entry_id, _, filename = item.identifier.partition("/")
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None or not filename or "/" in filename or filename.startswith("."):
            raise Unresolvable("Unknown clip")

        directory = self._directory(entry)
        path = Path(directory) / filename
        try:
            path.relative_to(Path(directory))
        except ValueError as err:
            raise Unresolvable("Clip is outside its directory") from err

        url = local_url_for(str(path), self.hass.config.path("www"))
        if url is None:
            raise Unresolvable(
                "Clips are stored outside <config>/www, so they have no URL to "
                "play; point the snapshot path below <config>/www"
            )
        return PlayMedia(url, MIME_TYPE)

    async def async_browse_media(self, item: MediaSourceItem) -> BrowseMediaSource:
        if not item.identifier:
            return self._browse_root()
        entry = self.hass.config_entries.async_get_entry(item.identifier)
        if entry is None:
            raise BrowseError("Unknown doorbell")
        return await self._browse_device(entry)

    def _browse_root(self) -> BrowseMediaSource:
        entries = self.hass.config_entries.async_entries(DOMAIN)
        children = [
            BrowseMediaSource(
                domain=DOMAIN,
                identifier=entry.entry_id,
                media_class=MediaClass.DIRECTORY,
                media_content_type=MediaType.VIDEO,
                title=entry.title or entry.entry_id,
                can_play=False,
                can_expand=True,
                children_media_class=MediaClass.VIDEO,
            )
            for entry in entries
        ]
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=None,
            media_class=MediaClass.APP,
            media_content_type=MediaType.VIDEO,
            title="Doorbell clips",
            can_play=False,
            can_expand=True,
            children=children,
            children_media_class=MediaClass.DIRECTORY,
        )

    async def _browse_device(self, entry: ConfigEntry) -> BrowseMediaSource:
        names = await self.hass.async_add_executor_job(
            clip_filenames, self._directory(entry)
        )
        children = [
            BrowseMediaSource(
                domain=DOMAIN,
                identifier=f"{entry.entry_id}/{name}",
                media_class=MediaClass.VIDEO,
                media_content_type=MIME_TYPE,
                title=name,
                can_play=True,
                can_expand=False,
            )
            for name in names
        ]
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=entry.entry_id,
            media_class=MediaClass.DIRECTORY,
            media_content_type=MediaType.VIDEO,
            title=entry.title or entry.entry_id,
            can_play=False,
            can_expand=True,
            children=children,
            children_media_class=MediaClass.VIDEO,
        )
