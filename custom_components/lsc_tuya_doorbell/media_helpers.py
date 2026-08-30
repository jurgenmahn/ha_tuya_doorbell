"""Pure helpers with no Home Assistant imports, so they stay unit-testable."""

from __future__ import annotations

from pathlib import Path


def clip_filenames(directory: str) -> list[str]:
    """The .mp4 clips in a directory, newest first.

    Blocking (stat/iterdir) -- call from an executor. A missing or unreadable
    directory is not an error here; it just means no clips yet.
    """
    try:
        files = [
            p for p in Path(directory).iterdir()
            if p.suffix == ".mp4" and p.is_file()
        ]
    except OSError:
        return []
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [p.name for p in files]
