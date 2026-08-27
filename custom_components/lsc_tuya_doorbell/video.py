"""Snapshot subsystem for the LSC Tuya Doorbell integration.

A doorbell snapshot is only useful if it arrives while the visitor is still
standing there. Starting an ffmpeg process per event does not achieve that:
measured against the real camera, the frame is decoded after 1 s but
``avformat_find_stream_info()`` keeps the process busy for another five to six
seconds, and a second concurrent grab pushes the total past 15 s. Neither
``-analyzeduration``/``-probesize``, ``-fflags nobuffer`` nor a go2rtc restream
changes that. A single long-lived ffmpeg does: a rolling JPEG is 1.0 s, flat.

So this module offers four modes, from "works everywhere without configuration"
to "can look back in time":

``off``        no snapshots at all.
``on_demand``  a still URL if configured, otherwise one ffmpeg per grab. The
               historic behaviour, and the default, because it needs nothing.
``warm``       one continuous ffmpeg writes a rolling JPEG; a grab is a file
               read.
``buffer``     one continuous ffmpeg writes a ring of ``-c:v copy`` segments on
               tmpfs; a grab seeks into the segment covering the wanted moment.
               The only mode that can genuinely look back, which matters because
               the device reports the button press three to five seconds late.

The module deliberately does not import Home Assistant at runtime: everything
that touches the outside world (spawning ffmpeg, the clock, sleeping, the
executor, fetching a still URL, creating tasks) is injectable, so the logic is
testable without Home Assistant and without a camera.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import shutil
import time
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Coroutine, Iterable, Sequence
from urllib.parse import quote

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


# --- Modes -----------------------------------------------------------------

MODE_OFF = "off"
MODE_ON_DEMAND = "on_demand"
MODE_WARM = "warm"
MODE_BUFFER = "buffer"

SNAPSHOT_MODES: tuple[str, ...] = (MODE_OFF, MODE_ON_DEMAND, MODE_WARM, MODE_BUFFER)

#: Modes that keep a long-running ffmpeg alive.
CONTINUOUS_MODES: tuple[str, ...] = (MODE_WARM, MODE_BUFFER)


# --- Defaults --------------------------------------------------------------

DEFAULT_SNAPSHOT_MODE = MODE_ON_DEMAND
DEFAULT_BUFFER_PATH = "/dev/shm/lsc_tuya_doorbell"
DEFAULT_BUFFER_SECONDS = 60
DEFAULT_SNAPSHOT_DELAY_MS = 0
MAX_SNAPSHOT_DELAY_MS = 8000

#: Segment length asked of the segment muxer. With ``-c:v copy`` ffmpeg can only
#: cut on keyframes, so the real length is the GOP (2-4 s on this camera). Every
#: segment therefore starts on a keyframe, which is exactly what a seek needs.
DEFAULT_SEGMENT_SECONDS = 1

#: Rolling-JPEG rate for warm mode. One frame per second is plenty for a
#: doorbell and keeps the JPEG encoder off the CPU for the other 24 frames.
DEFAULT_WARM_FPS = 1

#: Rough bitrate assumption for the space check. 2 Mbit/s is ~250 kB/s, so
#: ~15 MB per minute of buffer.
ESTIMATED_STREAM_KBPS = 2000

#: Ask for a bit more room than the raw estimate: bitrate spikes on motion.
SPACE_MARGIN = 1.25

#: Warm mode only needs room for a single JPEG, plus slack.
WARM_MIN_FREE_BYTES = 4 * 1024 * 1024

#: Restart delays after the long-running ffmpeg exits. Never a tight loop.
RESTART_BACKOFF: tuple[float, ...] = (1.0, 2.0, 5.0, 10.0, 30.0, 60.0)

#: A process that stayed up this long counts as healthy; its next crash starts
#: the backoff over from the beginning.
BACKOFF_RESET_SECONDS = 120.0

CLEANUP_INTERVAL = 5.0
GRAB_TIMEOUT = 15.0
SEGMENT_GRAB_TIMEOUT = 10.0
TERMINATE_TIMEOUT = 3.0

#: Stay this far behind the write head of the newest segment; ffmpeg is still
#: appending to it and a seek past the last written byte returns nothing.
WRITE_HEAD_MARGIN = 0.5

#: A rolling JPEG older than this is not "now" any more. Better to say so than
#: to hand an automation a picture of an empty porch.
WARM_MAX_AGE = 30.0

_JPEG_SOI = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"


# --- Injection points ------------------------------------------------------

ProcessLike = Any  # asyncio.subprocess.Process, or a fake in tests.
SpawnFunc = Callable[[Sequence[str]], Awaitable[ProcessLike]]
SleepFunc = Callable[[float], Awaitable[None]]
StillFetcher = Callable[[str], Awaitable[bytes | None]]
TaskFactory = Callable[[Coroutine[Any, Any, Any], str], "asyncio.Task[Any]"]


async def _default_spawn(args: Sequence[str]) -> ProcessLike:
    """Start ffmpeg with both pipes captured."""
    return await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


def _default_task_factory(coro: Coroutine[Any, Any, Any], name: str) -> asyncio.Task[Any]:
    return asyncio.create_task(coro, name=name)


@dataclass
class SnapshotConfig:
    """Everything the provider needs to know, resolved by the caller.

    ``source_url`` is taken as given. The provider must never rebuild it from
    host/port/path: the configured ``stream_url_override`` exists precisely so
    the frames come from a restreamer instead of opening yet another session on
    a camera that only tolerates a handful.
    """

    mode: str = DEFAULT_SNAPSHOT_MODE
    source_url: str | None = None
    still_url: str | None = None
    buffer_path: str = DEFAULT_BUFFER_PATH
    buffer_seconds: int = DEFAULT_BUFFER_SECONDS
    delay_ms: int = DEFAULT_SNAPSHOT_DELAY_MS
    ffmpeg_bin: str = "ffmpeg"
    segment_seconds: int = DEFAULT_SEGMENT_SECONDS
    warm_fps: int = DEFAULT_WARM_FPS
    estimated_kbps: int = ESTIMATED_STREAM_KBPS
    grab_timeout: float = GRAB_TIMEOUT
    #: Fall back to the on-demand path when the continuous mode cannot deliver
    #: (buffer still filling, rolling JPEG stale). The fallback only spawns a
    #: second ffmpeg when no long-running one is connected, so it never causes
    #: the session contention it is meant to avoid.
    fallback_on_demand: bool = True
    #: Remove our own files from the buffer directory on stop. tmpfs is RAM.
    purge_on_stop: bool = True

    def normalized(self) -> SnapshotConfig:
        """Return a copy with values clamped into their documented range."""
        mode = self.mode if self.mode in SNAPSHOT_MODES else DEFAULT_SNAPSHOT_MODE
        if mode != self.mode:
            _LOGGER.warning(
                "Unknown snapshot mode %r, falling back to %s", self.mode, mode
            )
        return SnapshotConfig(
            mode=mode,
            source_url=(self.source_url or "").strip() or None,
            still_url=(self.still_url or "").strip() or None,
            buffer_path=self.buffer_path or DEFAULT_BUFFER_PATH,
            buffer_seconds=max(1, int(self.buffer_seconds)),
            delay_ms=min(MAX_SNAPSHOT_DELAY_MS, max(0, int(self.delay_ms))),
            ffmpeg_bin=self.ffmpeg_bin or "ffmpeg",
            segment_seconds=max(1, int(self.segment_seconds)),
            warm_fps=max(1, int(self.warm_fps)),
            estimated_kbps=max(1, int(self.estimated_kbps)),
            grab_timeout=max(1.0, float(self.grab_timeout)),
            fallback_on_demand=self.fallback_on_demand,
            purge_on_stop=self.purge_on_stop,
        )


# --- Segment bookkeeping ---------------------------------------------------


@dataclass(frozen=True)
class Segment:
    """One ``<epoch>.ts`` file written by the segment muxer."""

    path: str
    start: float
    size: int


@dataclass(frozen=True)
class SegmentPick:
    """The segment chosen for a wanted moment, and where to seek in it."""

    segment: Segment
    offset: float
    #: True when the wanted moment lies outside the buffer and the offset was
    #: pulled back to what is actually available.
    clamped: bool = False


def estimate_buffer_bytes(seconds: float, kbps: int = ESTIMATED_STREAM_KBPS) -> int:
    """Bytes a buffer of ``seconds`` needs at ``kbps``, including margin."""
    return int(seconds * kbps * 1000 / 8 * SPACE_MARGIN)


def select_segment(
    segments: Sequence[Segment], target: float, now: float
) -> SegmentPick | None:
    """Pick the segment covering ``target`` and the offset to seek to.

    The file name is the epoch second the segment started, so the segment
    covering a moment is the one with the highest name at or below it. Empty
    files are ignored: the muxer creates the next segment before writing to it,
    so a zero-byte file is a name without content yet.

    Returns ``None`` only when there is nothing usable at all. A target before
    the oldest segment or beyond the write head is clamped rather than refused,
    because an almost-right frame beats no frame for a doorbell.
    """
    usable = sorted((s for s in segments if s.size > 0), key=lambda s: s.start)
    if not usable:
        return None

    newest = usable[-1]

    if target < usable[0].start:
        # Asked for a moment older than the buffer reaches.
        return SegmentPick(usable[0], 0.0, clamped=True)

    chosen = usable[0]
    for segment in usable:
        if segment.start <= target:
            chosen = segment
        else:
            break

    offset = target - chosen.start
    clamped = False

    if chosen.path == newest.path:
        # ffmpeg is still appending here; seeking past the last written byte
        # yields nothing at all.
        head = now - chosen.start - WRITE_HEAD_MARGIN
        if offset > head:
            offset = max(0.0, head)
            clamped = True

    return SegmentPick(chosen, max(0.0, offset), clamped=clamped)


def expired_segments(segments: Iterable[Segment], cutoff: float) -> list[Segment]:
    """Segments that lie entirely before ``cutoff``.

    A segment ends where the next one begins, so a segment is only outside the
    retention window once its successor starts at or before the cutoff. Deleting
    on the segment's own start would throw away the one segment that still
    covers the oldest moment the user asked to keep. The newest segment is never
    expired: ffmpeg is writing to it.
    """
    ordered = sorted(segments, key=lambda s: s.start)
    return [cur for cur, nxt in zip(ordered, ordered[1:]) if nxt.start <= cutoff]


def scan_segments(directory: str) -> list[Segment]:
    """List ``<epoch>.ts`` files. Blocking — call via an executor."""
    segments: list[Segment] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name
                if not name.endswith(".ts"):
                    continue
                stem = name[:-3]
                if not stem.isdigit():
                    continue
                try:
                    size = entry.stat().st_size
                except OSError:
                    continue
                segments.append(Segment(entry.path, float(stem), size))
    except FileNotFoundError:
        return []
    segments.sort(key=lambda s: s.start)
    return segments


def is_jpeg(data: bytes | None) -> bool:
    """Whether ``data`` looks like a complete JPEG.

    The rolling JPEG is overwritten in place, so a reader can catch it halfway
    through a write. A truncated file fails this check and the read is retried.
    """
    return bool(data) and data[:2] == _JPEG_SOI and data[-2:] == _JPEG_EOI


def build_rtsp_url(
    host: str, port: int, path: str, username: str, password: str
) -> str:
    """Build an RTSP URL with a properly escaped password.

    Offered for callers that have to assemble the URL themselves; the provider
    only ever uses ``SnapshotConfig.source_url``. An unescaped ``@`` or ``/`` in
    the password silently produces a URL pointing at the wrong host.
    """
    if not path.startswith("/"):
        path = f"/{path}"
    credentials = ""
    if username or password:
        credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"rtsp://{credentials}{host}:{port}{path}"


# --- ffmpeg command lines --------------------------------------------------

_COMMON_FLAGS = ("-nostdin", "-hide_banner", "-loglevel", "error")


def _input_flags(url: str) -> list[str]:
    # UDP is the RTSP default and drops packets on a busy network; TCP does not.
    return ["-rtsp_transport", "tcp"] if url.startswith("rtsp://") else []


def build_buffer_args(
    ffmpeg_bin: str, source_url: str, directory: str, segment_seconds: int
) -> list[str]:
    """The continuous segment recorder. Nothing is decoded, so CPU is idle."""
    return [
        ffmpeg_bin,
        *_COMMON_FLAGS,
        *_input_flags(source_url),
        # A re-encoded restream can arrive without usable timestamps, and the
        # segment muxer refuses it outright: "first pts and dts value must be
        # set", one segment written, exit. Measured against a VAAPI restream of
        # this doorbell -- generating timestamps and rebasing them to zero is
        # what makes it record, and it costs nothing on a stream that was
        # already fine.
        "-fflags", "+genpts",
        "-i", source_url,
        "-an",
        "-c:v", "copy",
        "-avoid_negative_ts", "make_zero",
        "-f", "segment",
        "-segment_time", str(segment_seconds),
        "-reset_timestamps", "1",
        "-strftime", "1",
        os.path.join(directory, "%s.ts"),
    ]


def build_warm_args(
    ffmpeg_bin: str, source_url: str, target: str, fps: int, atomic: bool = True
) -> list[str]:
    """The continuous rolling-JPEG writer."""
    args = [
        ffmpeg_bin,
        *_COMMON_FLAGS,
        *_input_flags(source_url),
        "-i", source_url,
        "-an",
        "-vf", f"fps={fps}",
        "-q:v", "2",
        "-update", "1",
    ]
    if atomic:
        # Write to a temp file and rename, so a reader never sees half a JPEG.
        args += ["-atomic_writing", "1"]
    args += ["-f", "image2", "-y", target]
    return args


def build_segment_grab_args(ffmpeg_bin: str, path: str, offset: float) -> list[str]:
    """Extract one frame from a segment at ``offset`` seconds.

    ``-ss`` goes *after* ``-i``. That is deliberately not the usual "seek fast
    by putting -ss first" advice, because it does not survive contact with these
    segments: ``-c:v copy`` can only cut on keyframes, so every segment holds
    exactly one, at position zero (verified with ffprobe: 1 keyframe, 59
    non-keyframes in a 4 s segment). An input seek looks for a keyframe at or
    after the target, finds none, and produces an empty output — measured, on
    every offset above zero.

    An output seek decodes from the single keyframe up to the target instead.
    Measured on a 4 s 720p segment: 0.09 s at offset 0 rising to 0.15 s at
    offset 3.9, against 5.86 s for a live grab. The decode is bounded by the GOP
    length, so this stays cheap no matter how far back the buffer reaches.
    """
    return [
        ffmpeg_bin,
        *_COMMON_FLAGS,
        "-i", path,
        "-ss", f"{offset:.3f}",
        "-frames:v", "1",
        "-q:v", "2",
        "-f", "image2",
        "pipe:1",
    ]


def build_live_grab_args(ffmpeg_bin: str, source_url: str) -> list[str]:
    """One frame straight off the stream. The slow path, ~6 s on this camera."""
    return [
        ffmpeg_bin,
        *_COMMON_FLAGS,
        *_input_flags(source_url),
        "-i", source_url,
        "-frames:v", "1",
        "-q:v", "2",
        "-f", "image2",
        "pipe:1",
    ]


# --- Blocking filesystem helpers (executor only) ---------------------------


def _prepare_directory(directory: str) -> None:
    Path(directory).mkdir(parents=True, exist_ok=True)


def _free_bytes(directory: str) -> int:
    return shutil.disk_usage(directory).free


def _delete_paths(paths: Sequence[str]) -> int:
    removed = 0
    for path in paths:
        try:
            os.unlink(path)
            removed += 1
        except FileNotFoundError:
            continue
        except OSError as err:
            _LOGGER.warning("Could not remove buffer file %s: %s", path, err)
    return removed


def _read_file(path: str) -> tuple[bytes, float] | None:
    try:
        data = Path(path).read_bytes()
        mtime = os.stat(path).st_mtime
    except (FileNotFoundError, OSError):
        return None
    return data, mtime


# --- The provider ----------------------------------------------------------


class SnapshotProvider:
    """Delivers doorbell snapshots, optionally from the recent past."""

    def __init__(
        self,
        hass: HomeAssistant | None,
        config: SnapshotConfig,
        *,
        spawn: SpawnFunc | None = None,
        time_fn: Callable[[], float] | None = None,
        sleep_fn: SleepFunc | None = None,
        still_fetcher: StillFetcher | None = None,
        task_factory: TaskFactory | None = None,
    ) -> None:
        self._hass = hass
        self._config = config.normalized()
        self._spawn: SpawnFunc = spawn or _default_spawn
        self._now: Callable[[], float] = time_fn or time.time
        self._sleep: SleepFunc = sleep_fn or asyncio.sleep
        self._still_fetcher = still_fetcher
        self._make_task: TaskFactory = task_factory or _default_task_factory

        # The mode actually in effect. Degrades to on_demand when a continuous
        # mode is configured without a usable source or writable directory,
        # rather than pretending to work.
        self._active_mode = self._config.mode
        self._detail = "not started"

        self._started = False
        self._stopping = False
        self._process: ProcessLike | None = None
        self._runner_task: asyncio.Task[Any] | None = None
        self._cleanup_task: asyncio.Task[Any] | None = None
        self._stderr_task: asyncio.Task[Any] | None = None
        self._last_stderr: str = ""
        self._warm_atomic = True
        self._process_started_at: float | None = None
        self._running_since: float | None = None
        self._segment_count = 0
        self._buffer_depth = 0.0
        self._rewind_ignored = False
        self._logged_once: set[str] = set()
        # One live grab at a time: a second concurrent RTSP session against this
        # camera measured 15.94 s instead of 5.86 s.
        self._live_lock = asyncio.Lock()

    # --- Public interface ---

    @property
    def mode(self) -> str:
        """The configured mode."""
        return self._config.mode

    @property
    def active_mode(self) -> str:
        """The mode actually in effect, which may have degraded."""
        return self._active_mode

    @property
    def available(self) -> bool:
        """Whether a grab has a realistic chance of returning an image."""
        if self._active_mode == MODE_OFF:
            return False
        if self._active_mode == MODE_WARM:
            return self._running_since is not None
        if self._active_mode == MODE_BUFFER:
            return self._running_since is not None and self._segment_count > 0
        return bool(self._config.still_url or self._config.source_url)

    @property
    def status(self) -> str:
        """Short, showable state for diagnostics."""
        parts = [f"{self._active_mode}: {self._detail}"]
        if self._active_mode != self._config.mode:
            parts.append(f"(configured: {self._config.mode})")
        if self._rewind_ignored:
            parts.append("(rewind ignored: mode cannot look back)")
        return " ".join(parts)

    async def async_start(self) -> None:
        """Start the subsystem. Idempotent."""
        if self._started:
            _LOGGER.debug("Snapshot provider already started")
            return
        self._started = True
        self._stopping = False
        self._rewind_ignored = False

        mode = self._config.mode
        if mode == MODE_OFF:
            self._active_mode = MODE_OFF
            self._detail = "disabled"
            return

        if mode == MODE_ON_DEMAND:
            self._active_mode = MODE_ON_DEMAND
            self._detail = self._on_demand_detail()
            return

        if not self._config.source_url:
            _LOGGER.error(
                "Snapshot mode '%s' needs a stream source but none is configured; "
                "set a stream URL override or ONVIF credentials, or switch the "
                "snapshot mode to '%s'",
                mode,
                MODE_ON_DEMAND,
            )
            self._degrade("no stream source configured")
            return

        if not await self._prepare_storage():
            return

        self._active_mode = mode
        self._detail = "starting"
        self._runner_task = self._make_task(
            self._runner_loop(), f"lsc_tuya_doorbell_snapshot_{mode}"
        )
        if mode == MODE_BUFFER:
            self._cleanup_task = self._make_task(
                self._cleanup_loop(), "lsc_tuya_doorbell_snapshot_cleanup"
            )

    async def async_stop(self) -> None:
        """Stop everything and leave no ffmpeg behind."""
        self._stopping = True
        self._started = False

        for task in (self._cleanup_task, self._runner_task, self._stderr_task):
            if task is not None:
                task.cancel()

        # Kill first, then await: a cancelled runner may be blocked in
        # proc.wait() and would only return once the process is gone.
        process, self._process = self._process, None
        if process is not None:
            await self._terminate(process)

        for task in (self._cleanup_task, self._runner_task, self._stderr_task):
            if task is None:
                continue
            with suppress(asyncio.CancelledError):
                await task
        self._cleanup_task = None
        self._runner_task = None
        self._stderr_task = None
        self._running_since = None

        if self._config.purge_on_stop and self._active_mode in CONTINUOUS_MODES:
            await self._purge_storage()

        self._detail = "stopped"

    async def async_grab(self, age_seconds: float = 0.0) -> bytes | None:
        """Return a JPEG of ``age_seconds`` ago, or the newest frame available.

        Only ``buffer`` can genuinely look back. The other modes ignore the age
        and say so, in ``status`` and once in the log — never silently.
        """
        if self._active_mode == MODE_OFF:
            _LOGGER.debug("Snapshot requested while snapshots are off")
            return None

        if self._active_mode == MODE_BUFFER:
            image = await self._grab_from_buffer(age_seconds)
            if image is not None:
                return image
            return await self._fallback_grab("buffer had no usable frame")

        if age_seconds > 0:
            self._rewind_ignored = True
            self._log_once(
                "rewind_ignored",
                logging.WARNING,
                "Snapshot mode '%s' cannot look back %.1f s; returning the newest "
                "frame instead. Switch to the '%s' mode for a true rewind",
                self._active_mode,
                age_seconds,
                MODE_BUFFER,
            )

        if self._active_mode == MODE_WARM:
            image = await self._grab_warm_frame()
            if image is not None:
                return image
            return await self._fallback_grab("rolling JPEG was missing or stale")

        return await self._grab_on_demand()

    # --- Storage ---

    async def _prepare_storage(self) -> bool:
        """Create the buffer directory and check that it has room."""
        directory = self._config.buffer_path
        try:
            await self._job(_prepare_directory, directory)
        except OSError as err:
            _LOGGER.error(
                "Cannot create snapshot buffer directory %s (%s); "
                "falling back to on-demand snapshots",
                directory,
                err,
            )
            self._degrade("buffer path not writable")
            return False

        try:
            free = await self._job(_free_bytes, directory)
        except OSError as err:
            _LOGGER.warning(
                "Cannot determine free space on %s (%s); continuing without the "
                "space check",
                directory,
                err,
            )
            return True

        if self._config.mode == MODE_BUFFER:
            needed = estimate_buffer_bytes(
                self._config.buffer_seconds, self._config.estimated_kbps
            )
            if free < needed:
                _LOGGER.warning(
                    "Snapshot buffer %s has %.1f MB free but %d s of video needs "
                    "about %.1f MB. The buffer will be cut short. In Docker /dev/shm "
                    "defaults to 64 MB — raise shm_size (reckon ~15 MB per minute at "
                    "2 Mbit/s), pick a different buffer path, or lower the buffer "
                    "length",
                    directory,
                    free / 1e6,
                    self._config.buffer_seconds,
                    needed / 1e6,
                )
        elif free < WARM_MIN_FREE_BYTES:
            _LOGGER.warning(
                "Snapshot path %s has only %.1f MB free; the rolling JPEG may fail "
                "to write",
                directory,
                free / 1e6,
            )
        return True

    async def _purge_storage(self) -> None:
        """Remove our own files. tmpfs is RAM; leaving 60 s of video costs it."""
        try:
            segments = await self._job(scan_segments, self._config.buffer_path)
            paths = [s.path for s in segments]
            warm = self._warm_path()
            if await self._job(os.path.exists, warm):
                paths.append(warm)
            if paths:
                await self._job(_delete_paths, paths)
        except OSError as err:
            _LOGGER.warning(
                "Could not clean up snapshot buffer %s: %s",
                self._config.buffer_path,
                err,
            )

    def _warm_path(self) -> str:
        return os.path.join(self._config.buffer_path, "latest.jpg")

    # --- Process management ---

    async def _runner_loop(self) -> None:
        """Keep one ffmpeg alive; restart it with backoff, never in a tight loop."""
        attempt = 0
        while not self._stopping:
            args = self._build_capture_args()
            _LOGGER.debug("Starting snapshot ffmpeg: %s", " ".join(args))
            try:
                process = await self._spawn(args)
            except FileNotFoundError:
                _LOGGER.error(
                    "ffmpeg not found — install ffmpeg, or set the snapshot mode "
                    "to '%s' with a still image URL",
                    MODE_ON_DEMAND,
                )
                self._degrade("ffmpeg not installed")
                return
            except OSError as err:
                _LOGGER.warning("Could not start ffmpeg: %s", err)
                attempt += 1
                await self._sleep(_backoff_delay(attempt))
                continue

            self._process = process
            self._process_started_at = self._now()
            self._running_since = self._process_started_at
            self._detail = "running"
            self._last_stderr = ""
            self._start_stderr_drain(process)

            try:
                returncode = await process.wait()
            except asyncio.CancelledError:
                await self._terminate(process)
                raise
            finally:
                self._process = None
                self._running_since = None

            uptime = self._now() - (self._process_started_at or self._now())
            if self._stopping:
                return

            # Give the drain a moment to hand over the last stderr line; the
            # process is gone, so EOF is imminent.
            await self._collect_stderr()

            if self._adapt_to_stderr(uptime):
                # A rejected ffmpeg option is a configuration problem, not a
                # flaky camera: retry immediately with the option dropped.
                attempt = 0
                continue

            if uptime >= BACKOFF_RESET_SECONDS:
                attempt = 0
            attempt += 1
            delay = _backoff_delay(attempt)
            _LOGGER.warning(
                "Snapshot ffmpeg exited (rc=%s) after %.1f s, restarting in %.0f s%s",
                returncode,
                uptime,
                delay,
                f": {self._last_stderr}" if self._last_stderr else "",
            )
            self._detail = f"restarting in {delay:.0f}s (exit {returncode})"
            await self._sleep(delay)

        self._detail = "stopped"

    def _build_capture_args(self) -> list[str]:
        source = self._config.source_url or ""
        if self._active_mode == MODE_BUFFER:
            return build_buffer_args(
                self._config.ffmpeg_bin,
                source,
                self._config.buffer_path,
                self._config.segment_seconds,
            )
        return build_warm_args(
            self._config.ffmpeg_bin,
            source,
            self._warm_path(),
            self._config.warm_fps,
            atomic=self._warm_atomic,
        )

    def _adapt_to_stderr(self, uptime: float) -> bool:
        """Drop ``-atomic_writing`` when this ffmpeg build rejects it."""
        if (
            self._active_mode == MODE_WARM
            and self._warm_atomic
            and uptime < 5.0
            and "atomic_writing" in self._last_stderr
        ):
            _LOGGER.info(
                "This ffmpeg build does not support -atomic_writing; retrying "
                "without it (a snapshot may occasionally be read mid-write)"
            )
            self._warm_atomic = False
            return True
        return False

    def _start_stderr_drain(self, process: ProcessLike) -> None:
        """Drain stderr so a full pipe cannot wedge ffmpeg, keeping the tail."""
        stream = getattr(process, "stderr", None)
        if stream is None:
            return

        async def _drain() -> None:
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        return
                    text = line.decode(errors="replace").strip()
                    if text:
                        self._last_stderr = text[:200]
                        _LOGGER.debug("ffmpeg: %s", text)
            except (asyncio.CancelledError, ValueError):
                raise
            except Exception as err:  # noqa: BLE001 - drain must never kill the runner
                _LOGGER.debug("Stopped reading ffmpeg stderr: %s", err)

        self._stderr_task = self._make_task(_drain(), "lsc_tuya_doorbell_ffmpeg_stderr")

    async def _collect_stderr(self) -> None:
        """Wait briefly for the stderr drain to finish after the process exited."""
        task, self._stderr_task = self._stderr_task, None
        if task is None:
            return
        with suppress(asyncio.TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(task, 0.5)

    async def _terminate(self, process: ProcessLike) -> None:
        """Make sure the process is gone. Never returns with it still running."""
        if getattr(process, "returncode", None) is not None:
            return
        try:
            process.terminate()
        except (ProcessLookupError, OSError):
            return
        try:
            await asyncio.wait_for(process.wait(), TERMINATE_TIMEOUT)
            return
        except asyncio.TimeoutError:
            _LOGGER.warning("ffmpeg ignored SIGTERM, killing it")
        except ProcessLookupError:
            return

        try:
            process.kill()
        except (ProcessLookupError, OSError):
            return
        with suppress(asyncio.TimeoutError, ProcessLookupError):
            await asyncio.wait_for(process.wait(), TERMINATE_TIMEOUT)

    # --- Cleanup loop ---

    async def _cleanup_loop(self) -> None:
        """Drop segments that fall outside the retention window."""
        while not self._stopping:
            try:
                await self._cleanup_once()
            except asyncio.CancelledError:
                raise
            except OSError as err:
                _LOGGER.warning("Snapshot buffer cleanup failed: %s", err)
            await self._sleep(CLEANUP_INTERVAL)

    async def _cleanup_once(self) -> None:
        segments = await self._job(scan_segments, self._config.buffer_path)
        now = self._now()
        cutoff = now - self._config.buffer_seconds
        stale = expired_segments(segments, cutoff)
        if stale:
            await self._job(_delete_paths, [s.path for s in stale])
            _LOGGER.debug("Removed %d expired buffer segments", len(stale))

        live = [s for s in segments if s not in stale]
        self._segment_count = len(live)
        if live:
            self._buffer_depth = max(0.0, now - min(s.start for s in live))
            if self._running_since is not None:
                self._detail = (
                    f"running, {self._segment_count} segments, "
                    f"{self._buffer_depth:.0f}s deep"
                )
        else:
            self._buffer_depth = 0.0

    # --- Grabbing ---

    async def _grab_from_buffer(self, age_seconds: float) -> bytes | None:
        delay = self._config.delay_ms / 1000.0
        now = self._now()
        target = now - max(0.0, age_seconds) - delay

        segments = await self._job(scan_segments, self._config.buffer_path)
        pick = select_segment(segments, target, now)
        if pick is None:
            _LOGGER.warning(
                "No buffered video available yet for a snapshot %.1f s back; the "
                "buffer needs a few seconds after startup",
                age_seconds + delay,
            )
            return None

        if pick.clamped:
            # Either the moment predates the buffer, or it is so recent that
            # ffmpeg has not written it yet. Both give the nearest usable frame.
            _LOGGER.info(
                "Wanted a frame from %.1f s ago; the buffer could only offer one "
                "from segment %s at offset %.1f s",
                now - target,
                os.path.basename(pick.segment.path),
                pick.offset,
            )

        image = await self._run_grab(
            build_segment_grab_args(
                self._config.ffmpeg_bin, pick.segment.path, pick.offset
            ),
            SEGMENT_GRAB_TIMEOUT,
        )
        if image is not None:
            return image

        # The chosen segment may have been rotated away between the scan and the
        # read, or be a keyframe-less tail. Its predecessor starts on a keyframe.
        previous = _previous_segment(segments, pick.segment)
        if previous is None:
            _LOGGER.warning(
                "Could not extract a frame from buffer segment %s", pick.segment.path
            )
            return None
        _LOGGER.debug("Retrying snapshot on previous segment %s", previous.path)
        return await self._run_grab(
            build_segment_grab_args(self._config.ffmpeg_bin, previous.path, 0.0),
            SEGMENT_GRAB_TIMEOUT,
        )

    async def _grab_warm_frame(self) -> bytes | None:
        path = self._warm_path()
        for attempt in range(2):
            result = await self._job(_read_file, path)
            if result is None:
                break
            data, mtime = result
            if not is_jpeg(data):
                # Caught mid-write; the next write is at most a second away.
                if attempt == 0:
                    await self._sleep(0.15)
                    continue
                break
            age = self._now() - mtime
            if age > WARM_MAX_AGE:
                _LOGGER.warning(
                    "Rolling snapshot is %.0f s old — the ffmpeg feeding it is not "
                    "keeping up with the stream",
                    age,
                )
                return None
            return data
        return None

    async def _grab_on_demand(self) -> bytes | None:
        still_url = self._config.still_url
        if still_url:
            if self._still_fetcher is None:
                self._log_once(
                    "no_still_fetcher",
                    logging.WARNING,
                    "A still image URL is configured but this provider was built "
                    "without an HTTP fetcher; falling back to ffmpeg",
                )
            else:
                try:
                    image = await self._still_fetcher(still_url)
                except Exception as err:  # noqa: BLE001 - any client error falls back
                    _LOGGER.warning(
                        "Still image URL failed (%s); falling back to ffmpeg", err
                    )
                else:
                    if image:
                        return image
                    _LOGGER.warning(
                        "Still image URL returned no image; falling back to ffmpeg"
                    )

        source = self._config.source_url
        if not source:
            _LOGGER.warning(
                "Cannot take a snapshot: no still image URL and no stream source "
                "is configured"
            )
            return None

        async with self._live_lock:
            image = await self._run_grab(
                build_live_grab_args(self._config.ffmpeg_bin, source),
                self._config.grab_timeout,
            )
        if image is None:
            _LOGGER.warning(
                "Could not grab a snapshot from the stream. Consider the '%s' or "
                "'%s' snapshot mode, which keep one ffmpeg running instead of "
                "starting one per event",
                MODE_WARM,
                MODE_BUFFER,
            )
        return image

    async def _fallback_grab(self, reason: str) -> bytes | None:
        """Last resort when a continuous mode came up empty."""
        if not self._config.fallback_on_demand:
            return None
        # Never open a second RTSP session next to the long-running one.
        if self._process is not None and not self._config.still_url:
            _LOGGER.warning(
                "Snapshot failed (%s) and no still image URL is configured to fall "
                "back on",
                reason,
            )
            return None
        _LOGGER.warning("Snapshot fell back to an on-demand grab: %s", reason)
        return await self._grab_on_demand()

    async def _run_grab(self, args: Sequence[str], timeout: float) -> bytes | None:
        """Run a one-shot ffmpeg, always killing it, also on timeout."""
        process: ProcessLike | None = None
        try:
            process = await self._spawn(args)
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
            if getattr(process, "returncode", None) == 0 and stdout:
                return bytes(stdout)
            _LOGGER.debug(
                "Snapshot ffmpeg failed (rc=%s): %s",
                getattr(process, "returncode", None),
                (stderr or b"").decode(errors="replace")[:200],
            )
        except asyncio.TimeoutError:
            _LOGGER.warning("Snapshot ffmpeg timed out after %.0f s", timeout)
        except FileNotFoundError:
            _LOGGER.error("ffmpeg not found — install ffmpeg to take snapshots")
        except OSError as err:
            _LOGGER.warning("Could not run ffmpeg for a snapshot: %s", err)
        finally:
            if process is not None:
                await self._terminate(process)
        return None

    # --- Small helpers ---

    def _degrade(self, reason: str) -> None:
        """Fall back to on-demand and make the reason visible."""
        self._active_mode = MODE_ON_DEMAND
        self._detail = f"{reason}, using {MODE_ON_DEMAND}"

    def _on_demand_detail(self) -> str:
        if self._config.still_url:
            return "ready (still image URL)"
        if self._config.source_url:
            return "ready (ffmpeg per snapshot)"
        return "no source configured"

    async def _job(self, func: Callable[..., Any], *args: Any) -> Any:
        """Run blocking filesystem work off the event loop.

        Home Assistant's blocking-call detector does not cover Path.mkdir, glob,
        stat or unlink, so getting this wrong produces no warning at all — only
        a stuttering event loop.
        """
        hass = self._hass
        if hass is not None and hasattr(hass, "async_add_executor_job"):
            return await hass.async_add_executor_job(func, *args)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args)

    def _log_once(self, key: str, level: int, msg: str, *args: Any) -> None:
        if key in self._logged_once:
            return
        self._logged_once.add(key)
        _LOGGER.log(level, msg, *args)


def _backoff_delay(attempt: int) -> float:
    index = min(max(attempt, 1) - 1, len(RESTART_BACKOFF) - 1)
    return RESTART_BACKOFF[index]


def _previous_segment(
    segments: Sequence[Segment], current: Segment
) -> Segment | None:
    ordered = sorted((s for s in segments if s.size > 0), key=lambda s: s.start)
    previous: Segment | None = None
    for segment in ordered:
        if segment.start >= current.start:
            return previous
        previous = segment
    return previous
