"""Tests for the snapshot subsystem.

Everything here runs without Home Assistant and without a camera: ffmpeg, the
clock, sleeping and the executor are all injected. The one exception is
``TestAgainstRealFfmpeg``, which builds a real segment file and pulls a frame
out of it to prove the command lines are not just plausible-looking strings.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess

import pytest

from custom_components.lsc_tuya_doorbell.video import (
    MODE_BUFFER,
    MODE_OFF,
    MODE_ON_DEMAND,
    MODE_WARM,
    RESTART_BACKOFF,
    Segment,
    SnapshotConfig,
    SnapshotProvider,
    build_buffer_args,
    build_live_grab_args,
    build_rtsp_url,
    build_segment_grab_args,
    build_warm_args,
    estimate_buffer_bytes,
    expired_segments,
    is_jpeg,
    scan_segments,
    select_segment,
)

JPEG = b"\xff\xd8" + b"body" + b"\xff\xd9"


# --- Test doubles ----------------------------------------------------------


class FakeHass:
    """Just enough Home Assistant to run executor jobs inline."""

    def __init__(self) -> None:
        self.jobs: list[str] = []

    async def async_add_executor_job(self, func, *args):
        self.jobs.append(getattr(func, "__name__", repr(func)))
        return func(*args)


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeProcess:
    """A stand-in for asyncio.subprocess.Process."""

    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
        ignore_terminate: bool = False,
        on_wait=None,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._returncode: int | None = None
        self._exit_code = returncode
        self._hang = hang
        self._ignore_terminate = ignore_terminate
        self._on_wait = on_wait
        self.stderr = None  # no drain task in tests
        self.terminated = False
        self.killed = False
        self._done = asyncio.Event()

    @property
    def returncode(self) -> int | None:
        return self._returncode

    def _finish(self) -> None:
        if self._returncode is None:
            self._returncode = self._exit_code
        self._done.set()

    async def wait(self) -> int:
        if self._on_wait is not None:
            self._on_wait()
        if self._hang:
            await self._done.wait()
        else:
            self._finish()
        return self._returncode if self._returncode is not None else 0

    async def communicate(self, input=None):
        if self._hang:
            await self._done.wait()
        self._finish()
        return self._stdout, self._stderr

    def terminate(self) -> None:
        self.terminated = True
        if not self._ignore_terminate:
            self._returncode = -15
            self._done.set()

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9
        self._done.set()


class FakeSpawn:
    """Hands out queued processes and records every command line."""

    def __init__(self, processes=None, factory=None) -> None:
        self.calls: list[list[str]] = []
        self._queue = list(processes or [])
        self._factory = factory

    async def __call__(self, args):
        self.calls.append(list(args))
        if self._queue:
            return self._queue.pop(0)
        if self._factory is not None:
            return self._factory(len(self.calls) - 1)
        return FakeProcess()

    @property
    def last(self) -> list[str]:
        return self.calls[-1]


class FakeSleep:
    """Records requested delays and yields instead of waiting."""

    def __init__(self, clock: FakeClock | None = None, on_sleep=None) -> None:
        self.delays: list[float] = []
        self._clock = clock
        self._on_sleep = on_sleep

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)
        if self._on_sleep is not None:
            self._on_sleep(len(self.delays))
        await asyncio.sleep(0)


def make_provider(tmp_path, **overrides):
    """Build a provider with all injection points wired to fakes."""
    clock = overrides.pop("clock", FakeClock())
    spawn = overrides.pop("spawn", FakeSpawn())
    sleep = overrides.pop("sleep", FakeSleep(clock))
    hass = overrides.pop("hass", FakeHass())
    still_fetcher = overrides.pop("still_fetcher", None)

    config = SnapshotConfig(
        mode=overrides.pop("mode", MODE_ON_DEMAND),
        source_url=overrides.pop("source_url", "rtsp://user:pw@10.0.0.5:8554/s"),
        buffer_path=str(tmp_path / "buffer"),
        **overrides,
    )
    provider = SnapshotProvider(
        hass,
        config,
        spawn=spawn,
        time_fn=clock,
        sleep_fn=sleep,
        still_fetcher=still_fetcher,
    )
    return provider, spawn, sleep, clock


def seg(start: float, size: int = 1000, directory: str = "/buf") -> Segment:
    return Segment(f"{directory}/{int(start)}.ts", float(start), size)


# --- Segment selection -----------------------------------------------------


class TestSelectSegment:
    """The heart of the rewind: which file, and how far into it."""

    def test_picks_highest_name_at_or_below_target(self):
        segments = [seg(100), seg(104), seg(108)]
        pick = select_segment(segments, target=105.5, now=200.0)
        assert pick is not None
        assert pick.segment.start == 104
        assert pick.offset == pytest.approx(1.5)
        assert pick.clamped is False

    def test_exact_boundary_belongs_to_the_new_segment(self):
        segments = [seg(100), seg(104)]
        pick = select_segment(segments, target=104.0, now=200.0)
        assert pick.segment.start == 104
        assert pick.offset == 0.0

    def test_no_segments_at_all(self):
        assert select_segment([], target=105.0, now=200.0) is None

    def test_only_empty_segments(self):
        # The muxer creates the next file before writing to it.
        assert select_segment([seg(100, size=0)], target=100.0, now=101.0) is None

    def test_empty_segment_is_skipped(self):
        segments = [seg(100), seg(104, size=0)]
        pick = select_segment(segments, target=104.5, now=105.0)
        assert pick.segment.start == 100

    def test_target_older_than_the_buffer_clamps_to_oldest(self):
        segments = [seg(100), seg(104)]
        pick = select_segment(segments, target=42.0, now=110.0)
        assert pick.segment.start == 100
        assert pick.offset == 0.0
        assert pick.clamped is True

    def test_target_beyond_the_write_head_is_pulled_back(self):
        # ffmpeg is still appending to the 108 segment; at now=109 only ~0.5 s
        # is safely readable.
        segments = [seg(100), seg(108)]
        pick = select_segment(segments, target=109.0, now=109.0)
        assert pick.segment.start == 108
        assert pick.offset == pytest.approx(0.5)
        assert pick.clamped is True

    def test_offset_inside_the_newest_segment_is_kept(self):
        segments = [seg(100), seg(108)]
        pick = select_segment(segments, target=110.0, now=115.0)
        assert pick.segment.start == 108
        assert pick.offset == pytest.approx(2.0)
        assert pick.clamped is False

    def test_write_head_never_goes_negative(self):
        segments = [seg(108)]
        pick = select_segment(segments, target=108.1, now=108.2)
        assert pick.offset == 0.0


class TestExpiredSegments:
    """Only whole segments outside the window may go."""

    def test_keeps_the_segment_covering_the_cutoff(self):
        segments = [seg(100), seg(110), seg(120)]
        # Cutoff at 115: the 110 segment still covers it, so only 100 goes.
        assert [s.start for s in expired_segments(segments, cutoff=115.0)] == [100]

    def test_newest_segment_is_never_expired(self):
        segments = [seg(100)]
        assert expired_segments(segments, cutoff=1e9) == []

    def test_nothing_expires_inside_the_window(self):
        segments = [seg(100), seg(110)]
        assert expired_segments(segments, cutoff=90.0) == []

    def test_multiple_expire_at_once(self):
        segments = [seg(100), seg(110), seg(120), seg(130)]
        # The 120 segment runs up to 130 and still covers the cutoff.
        assert [s.start for s in expired_segments(segments, cutoff=125.0)] == [100, 110]

    def test_empty_input(self):
        assert expired_segments([], cutoff=100.0) == []


class TestScanSegments:
    def test_reads_epoch_names_and_sizes(self, tmp_path):
        (tmp_path / "1700000001.ts").write_bytes(b"abc")
        (tmp_path / "1700000002.ts").write_bytes(b"")
        (tmp_path / "latest.jpg").write_bytes(b"x")
        (tmp_path / "notanepoch.ts").write_bytes(b"x")

        found = scan_segments(str(tmp_path))

        assert [(s.start, s.size) for s in found] == [
            (1700000001.0, 3),
            (1700000002.0, 0),
        ]

    def test_missing_directory_is_not_an_error(self, tmp_path):
        assert scan_segments(str(tmp_path / "nope")) == []


# --- Command lines ---------------------------------------------------------


class TestCommandLines:
    def test_buffer_args(self):
        args = build_buffer_args("ffmpeg", "rtsp://cam/s", "/buf", 1)
        assert "-rtsp_transport" in args and args[args.index("-rtsp_transport") + 1] == "tcp"
        assert args[-1] == "/buf/%s.ts"
        assert "copy" in args and "-strftime" in args

    def test_seek_comes_after_the_input(self):
        # An input seek finds no keyframe past position 0 in a copy-muxed
        # segment and returns nothing; see TestAgainstRealFfmpeg.
        args = build_segment_grab_args("ffmpeg", "/buf/100.ts", 1.25)
        assert args.index("-i") < args.index("-ss")
        assert args[args.index("-ss") + 1] == "1.250"

    def test_rtsp_transport_only_for_rtsp(self):
        assert "-rtsp_transport" not in build_live_grab_args("ffmpeg", "http://x/f.jpg")
        assert "-rtsp_transport" in build_live_grab_args("ffmpeg", "rtsp://x/s")

    def test_warm_args_can_drop_atomic_writing(self):
        assert "-atomic_writing" in build_warm_args("ffmpeg", "rtsp://x/s", "/a.jpg", 1)
        assert "-atomic_writing" not in build_warm_args(
            "ffmpeg", "rtsp://x/s", "/a.jpg", 1, atomic=False
        )

    def test_password_is_escaped(self):
        url = build_rtsp_url("10.0.0.5", 8554, "/Streaming", "admin", "p@ss/w:rd")
        assert url == "rtsp://admin:p%40ss%2Fw%3Ard@10.0.0.5:8554/Streaming"

    def test_missing_leading_slash_on_path(self):
        assert build_rtsp_url("h", 1, "s", "u", "p").endswith(":1/s")


class TestHelpers:
    def test_space_estimate_matches_15mb_per_minute(self):
        # 2 Mbit/s is ~15 MB per minute; the estimate adds a 25 % margin.
        assert estimate_buffer_bytes(60, 2000) == pytest.approx(18_750_000)

    def test_jpeg_validation(self):
        assert is_jpeg(JPEG)
        assert not is_jpeg(b"\xff\xd8truncated")
        assert not is_jpeg(b"")
        assert not is_jpeg(None)

    def test_unknown_mode_falls_back_to_on_demand(self, caplog):
        with caplog.at_level(logging.WARNING):
            config = SnapshotConfig(mode="turbo").normalized()
        assert config.mode == MODE_ON_DEMAND
        assert "turbo" in caplog.text

    def test_delay_is_clamped(self):
        assert SnapshotConfig(delay_ms=99999).normalized().delay_ms == 8000
        assert SnapshotConfig(delay_ms=-5).normalized().delay_ms == 0


# --- Start / stop ----------------------------------------------------------


class TestStart:
    @pytest.mark.asyncio
    async def test_off_starts_nothing(self, tmp_path):
        provider, spawn, _, _ = make_provider(tmp_path, mode=MODE_OFF)
        await provider.async_start()
        assert spawn.calls == []
        assert provider.status == "off: disabled"
        assert provider.available is False
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_on_demand_starts_nothing(self, tmp_path):
        provider, spawn, _, _ = make_provider(tmp_path, mode=MODE_ON_DEMAND)
        await provider.async_start()
        assert spawn.calls == []
        assert provider.available is True
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_continuous_mode_without_source_degrades_loudly(
        self, tmp_path, caplog
    ):
        provider, spawn, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, source_url=None
        )
        with caplog.at_level(logging.ERROR):
            await provider.async_start()
        assert spawn.calls == []
        assert provider.active_mode == MODE_ON_DEMAND
        assert "needs a stream source" in caplog.text
        assert "configured: buffer" in provider.status
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_buffer_creates_directory_and_spawns_once(self, tmp_path):
        provider, spawn, _, _ = make_provider(
            tmp_path,
            mode=MODE_BUFFER,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        await provider.async_start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert os.path.isdir(tmp_path / "buffer")
        assert len(spawn.calls) == 1
        assert spawn.last[-1] == str(tmp_path / "buffer" / "%s.ts")

        # Starting twice must not produce a second process.
        await provider.async_start()
        await asyncio.sleep(0)
        assert len(spawn.calls) == 1

        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_space_check_warns_with_an_actionable_hint(
        self, tmp_path, caplog, monkeypatch
    ):
        import custom_components.lsc_tuya_doorbell.video as video

        monkeypatch.setattr(video, "_free_bytes", lambda _d: 8_000_000)
        provider, _, _, _ = make_provider(
            tmp_path,
            mode=MODE_BUFFER,
            buffer_seconds=60,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        with caplog.at_level(logging.WARNING):
            await provider.async_start()

        assert "shm_size" in caplog.text
        assert "64 MB" in caplog.text
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_space_check_silent_when_there_is_room(
        self, tmp_path, caplog, monkeypatch
    ):
        import custom_components.lsc_tuya_doorbell.video as video

        monkeypatch.setattr(video, "_free_bytes", lambda _d: 500_000_000)
        provider, _, _, _ = make_provider(
            tmp_path,
            mode=MODE_BUFFER,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        with caplog.at_level(logging.WARNING):
            await provider.async_start()
        assert "shm_size" not in caplog.text
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_filesystem_work_goes_through_the_executor(self, tmp_path):
        hass = FakeHass()
        provider, _, _, _ = make_provider(
            tmp_path,
            mode=MODE_BUFFER,
            hass=hass,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        await provider.async_start()
        await provider.async_stop()

        # mkdir, disk_usage, and the purge scan/unlink all ran off the loop.
        assert "_prepare_directory" in hass.jobs
        assert "_free_bytes" in hass.jobs
        assert "scan_segments" in hass.jobs


class TestRestartAndStop:
    @pytest.mark.asyncio
    async def test_crashed_ffmpeg_is_restarted_with_backoff(self, tmp_path):
        stop = asyncio.Event()
        sleep = FakeSleep(on_sleep=lambda n: stop.set() if n >= 3 else None)
        spawn = FakeSpawn(factory=lambda _i: FakeProcess(returncode=1))
        # Warm mode so the only sleeper in play is the restart backoff.
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_WARM, spawn=spawn, sleep=sleep
        )

        await provider.async_start()
        await asyncio.wait_for(stop.wait(), 2.0)
        await provider.async_stop()

        assert len(spawn.calls) >= 3
        assert sleep.delays[:3] == list(RESTART_BACKOFF[:3])

    @pytest.mark.asyncio
    async def test_backoff_resets_after_a_healthy_run(self, tmp_path):
        clock = FakeClock()
        uptimes = [0.0, 0.0, 300.0, 0.0]
        stop = asyncio.Event()
        sleep = FakeSleep(on_sleep=lambda n: stop.set() if n >= 4 else None)

        def factory(index):
            uptime = uptimes[index] if index < len(uptimes) else 0.0
            return FakeProcess(returncode=1, on_wait=lambda: clock.advance(uptime))

        spawn = FakeSpawn(factory=factory)
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_WARM, spawn=spawn, sleep=sleep, clock=clock
        )

        await provider.async_start()
        await asyncio.wait_for(stop.wait(), 2.0)
        await provider.async_stop()

        # 1 s, 2 s, then a 300 s run resets the sequence back to 1 s.
        assert sleep.delays[:4] == [1.0, 2.0, 1.0, 2.0]

    @pytest.mark.asyncio
    async def test_missing_ffmpeg_stops_instead_of_hot_looping(self, tmp_path, caplog):
        async def spawn(_args):
            raise FileNotFoundError("ffmpeg")

        provider, _, sleep, _ = make_provider(
            tmp_path, mode=MODE_WARM, spawn=spawn
        )
        with caplog.at_level(logging.ERROR):
            await provider.async_start()
            await asyncio.sleep(0)
            await asyncio.sleep(0)

        assert sleep.delays == []
        assert provider.active_mode == MODE_ON_DEMAND
        assert "ffmpeg not found" in caplog.text
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_stop_terminates_the_process_and_the_tasks(self, tmp_path):
        process = FakeProcess(hang=True)
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, spawn=FakeSpawn([process])
        )
        await provider.async_start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        await provider.async_stop()

        assert process.terminated is True
        assert process.returncode is not None
        assert provider._runner_task is None
        assert provider._cleanup_task is None

    @pytest.mark.asyncio
    async def test_stop_kills_a_process_that_ignores_sigterm(
        self, tmp_path, monkeypatch, caplog
    ):
        import custom_components.lsc_tuya_doorbell.video as video

        monkeypatch.setattr(video, "TERMINATE_TIMEOUT", 0.05)
        process = FakeProcess(hang=True, ignore_terminate=True)
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, spawn=FakeSpawn([process])
        )
        await provider.async_start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        with caplog.at_level(logging.WARNING):
            await provider.async_stop()

        assert process.killed is True
        assert "killing it" in caplog.text

    @pytest.mark.asyncio
    async def test_stop_purges_the_buffer(self, tmp_path):
        provider, _, _, clock = make_provider(
            tmp_path, mode=MODE_BUFFER, spawn=FakeSpawn([FakeProcess(hang=True)])
        )
        await provider.async_start()
        await asyncio.sleep(0)
        buffer_dir = tmp_path / "buffer"
        (buffer_dir / "1700000001.ts").write_bytes(b"data")
        (buffer_dir / "keep.txt").write_bytes(b"data")

        await provider.async_stop()

        assert not (buffer_dir / "1700000001.ts").exists()
        assert (buffer_dir / "keep.txt").exists()


class TestCleanupLoop:
    @pytest.mark.asyncio
    async def test_only_removes_what_falls_outside_retention(self, tmp_path):
        clock = FakeClock(1_000_000.0)
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, clock=clock, buffer_seconds=30
        )
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        for offset in (100, 70, 40, 20, 5):
            (buffer_dir / f"{int(clock.now) - offset}.ts").write_bytes(b"x" * 10)

        await provider._cleanup_once()

        remaining = sorted(p.name for p in buffer_dir.iterdir())
        # Cutoff is now-30. The now-40 segment still covers it, so it stays.
        assert remaining == [
            f"{int(clock.now) - 40}.ts",
            f"{int(clock.now) - 20}.ts",
            f"{int(clock.now) - 5}.ts",
        ]

    @pytest.mark.asyncio
    async def test_cleanup_reports_depth_in_the_status(self, tmp_path):
        clock = FakeClock(1_000_000.0)
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, clock=clock, buffer_seconds=60
        )
        provider._running_since = clock.now
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        for offset in (20, 10, 0):
            (buffer_dir / f"{int(clock.now) - offset}.ts").write_bytes(b"x")

        await provider._cleanup_once()

        assert "3 segments" in provider.status
        assert "20s deep" in provider.status

    @pytest.mark.asyncio
    async def test_empty_directory_is_harmless(self, tmp_path):
        provider, _, _, _ = make_provider(tmp_path, mode=MODE_BUFFER)
        (tmp_path / "buffer").mkdir()
        await provider._cleanup_once()
        assert provider.available is False


# --- Grabbing --------------------------------------------------------------


class TestGrab:
    @pytest.mark.asyncio
    async def test_off_returns_nothing(self, tmp_path):
        provider, spawn, _, _ = make_provider(tmp_path, mode=MODE_OFF)
        await provider.async_start()
        assert await provider.async_grab(3.0) is None
        assert spawn.calls == []

    @pytest.mark.asyncio
    async def test_on_demand_ignores_age_and_says_so(self, tmp_path, caplog):
        spawn = FakeSpawn(factory=lambda _i: FakeProcess(stdout=JPEG))
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_ON_DEMAND, spawn=spawn
        )
        await provider.async_start()

        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab(4.0) == JPEG
            assert await provider.async_grab(4.0) == JPEG

        assert "cannot look back" in caplog.text
        # Announced once, not on every ring of the doorbell.
        assert caplog.text.count("cannot look back") == 1
        assert "rewind ignored" in provider.status
        # The age never reaches the command line.
        assert "-ss" not in spawn.last

    @pytest.mark.asyncio
    async def test_warm_ignores_age_and_reads_the_rolling_jpeg(self, tmp_path, caplog):
        clock = FakeClock()
        provider, spawn, _, _ = make_provider(
            tmp_path,
            mode=MODE_WARM,
            clock=clock,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        await provider.async_start()
        await asyncio.sleep(0)
        warm_file = tmp_path / "buffer" / "latest.jpg"
        warm_file.write_bytes(JPEG)
        os.utime(warm_file, (clock.now, clock.now))

        with caplog.at_level(logging.WARNING):
            image = await provider.async_grab(5.0)

        assert image == JPEG
        assert "cannot look back" in caplog.text
        # Only the long-running ffmpeg ran; the grab was a file read.
        assert len(spawn.calls) == 1
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_warm_rejects_a_stale_frame(self, tmp_path, caplog):
        clock = FakeClock()
        provider, _, _, _ = make_provider(
            tmp_path,
            mode=MODE_WARM,
            clock=clock,
            fallback_on_demand=False,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        await provider.async_start()
        await asyncio.sleep(0)
        warm_file = tmp_path / "buffer" / "latest.jpg"
        warm_file.write_bytes(JPEG)
        os.utime(warm_file, (clock.now - 300, clock.now - 300))

        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab() is None
        assert "not keeping up" in caplog.text
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_warm_retries_a_half_written_jpeg(self, tmp_path):
        clock = FakeClock()
        provider, _, _, _ = make_provider(tmp_path, mode=MODE_WARM, clock=clock)
        provider._active_mode = MODE_WARM
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        warm_file = buffer_dir / "latest.jpg"
        warm_file.write_bytes(b"\xff\xd8half")
        os.utime(warm_file, (clock.now, clock.now))

        # The provider sleeps and re-reads; complete the file in between.
        async def sleep(_delay):
            warm_file.write_bytes(JPEG)
            os.utime(warm_file, (clock.now, clock.now))

        provider._sleep = sleep
        assert await provider._grab_warm_frame() == JPEG

    @pytest.mark.asyncio
    async def test_buffer_seeks_to_the_right_segment(self, tmp_path):
        clock = FakeClock(1_000_000.0)
        spawn = FakeSpawn(factory=lambda _i: FakeProcess(stdout=JPEG))
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, clock=clock, spawn=spawn, delay_ms=0
        )
        provider._active_mode = MODE_BUFFER
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        for offset in (12, 8, 4, 0):
            (buffer_dir / f"{int(clock.now) - offset}.ts").write_bytes(b"x" * 100)

        image = await provider.async_grab(6.0)

        assert image == JPEG
        args = spawn.last
        assert args[args.index("-i") + 1] == str(buffer_dir / f"{int(clock.now) - 8}.ts")
        assert args[args.index("-ss") + 1] == "2.000"

    @pytest.mark.asyncio
    async def test_buffer_adds_the_configured_delay(self, tmp_path):
        clock = FakeClock(1_000_000.0)
        spawn = FakeSpawn(factory=lambda _i: FakeProcess(stdout=JPEG))
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, clock=clock, spawn=spawn, delay_ms=3000
        )
        provider._active_mode = MODE_BUFFER
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        (buffer_dir / f"{int(clock.now) - 20}.ts").write_bytes(b"x" * 100)

        await provider.async_grab(2.0)

        # 20 s of segment, minus 2 s of age and 3 s of device lag.
        assert spawn.last[spawn.last.index("-ss") + 1] == "15.000"
        assert "rewind ignored" not in provider.status

    @pytest.mark.asyncio
    async def test_buffer_falls_back_to_the_previous_segment(self, tmp_path):
        clock = FakeClock(1_000_000.0)
        spawn = FakeSpawn(
            factory=lambda i: FakeProcess(stdout=b"" if i == 0 else JPEG)
        )
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, clock=clock, spawn=spawn
        )
        provider._active_mode = MODE_BUFFER
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        for offset in (12, 6):
            (buffer_dir / f"{int(clock.now) - offset}.ts").write_bytes(b"x" * 100)

        assert await provider.async_grab(5.0) == JPEG
        assert len(spawn.calls) == 2
        second = spawn.calls[1]
        assert second[second.index("-i") + 1].endswith(f"{int(clock.now) - 12}.ts")
        assert second[second.index("-ss") + 1] == "0.000"

    @pytest.mark.asyncio
    async def test_empty_buffer_warns_and_falls_back(self, tmp_path, caplog):
        spawn = FakeSpawn(factory=lambda _i: FakeProcess(stdout=JPEG))
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_BUFFER, spawn=spawn
        )
        provider._active_mode = MODE_BUFFER
        (tmp_path / "buffer").mkdir()

        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab(2.0) == JPEG

        assert "No buffered video available" in caplog.text
        assert "fell back to an on-demand grab" in caplog.text

    @pytest.mark.asyncio
    async def test_fallback_refuses_a_second_rtsp_session(self, tmp_path, caplog):
        provider, spawn, _, _ = make_provider(
            tmp_path,
            mode=MODE_BUFFER,
            spawn=FakeSpawn(factory=lambda _i: FakeProcess(hang=True)),
        )
        await provider.async_start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab(2.0) is None

        # Only the recorder is running; no competing grab was started.
        assert len(spawn.calls) == 1
        assert "no still image URL" in caplog.text
        await provider.async_stop()

    @pytest.mark.asyncio
    async def test_still_url_is_preferred_in_on_demand(self, tmp_path):
        async def fetch(url):
            assert url == "http://go2rtc/api/frame.jpeg?src=bell"
            return JPEG

        provider, spawn, _, _ = make_provider(
            tmp_path,
            mode=MODE_ON_DEMAND,
            still_url="http://go2rtc/api/frame.jpeg?src=bell",
            still_fetcher=fetch,
        )
        await provider.async_start()
        assert await provider.async_grab() == JPEG
        assert spawn.calls == []

    @pytest.mark.asyncio
    async def test_still_url_failure_falls_back_to_ffmpeg(self, tmp_path, caplog):
        async def fetch(_url):
            raise RuntimeError("connection refused")

        spawn = FakeSpawn(factory=lambda _i: FakeProcess(stdout=JPEG))
        provider, _, _, _ = make_provider(
            tmp_path,
            mode=MODE_ON_DEMAND,
            still_url="http://go2rtc/frame.jpeg",
            still_fetcher=fetch,
            spawn=spawn,
        )
        await provider.async_start()
        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab() == JPEG
        assert "connection refused" in caplog.text

    @pytest.mark.asyncio
    async def test_grab_timeout_always_kills_the_process(self, tmp_path, caplog):
        process = FakeProcess(hang=True)
        provider, _, _, _ = make_provider(
            tmp_path,
            mode=MODE_ON_DEMAND,
            spawn=FakeSpawn([process]),
            grab_timeout=1.0,
        )
        await provider.async_start()
        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab() is None

        assert process.terminated is True
        assert "timed out" in caplog.text
        assert "keep one ffmpeg running" in caplog.text

    @pytest.mark.asyncio
    async def test_failed_grab_is_reported_not_swallowed(self, tmp_path, caplog):
        spawn = FakeSpawn(factory=lambda _i: FakeProcess(returncode=1, stderr=b"401"))
        provider, _, _, _ = make_provider(
            tmp_path, mode=MODE_ON_DEMAND, spawn=spawn
        )
        await provider.async_start()
        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab() is None
        assert "Could not grab a snapshot" in caplog.text

    @pytest.mark.asyncio
    async def test_no_source_at_all_warns(self, tmp_path, caplog):
        provider, spawn, _, _ = make_provider(
            tmp_path, mode=MODE_ON_DEMAND, source_url=None
        )
        await provider.async_start()
        with caplog.at_level(logging.WARNING):
            assert await provider.async_grab() is None
        assert spawn.calls == []
        assert "no still image URL and no stream source" in caplog.text


# --- One end-to-end check with the real binary -----------------------------


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")
class TestAgainstRealFfmpeg:
    """Prove the command lines work, not just that they look right."""

    @staticmethod
    def _write_segment(path, duration: int = 6) -> None:
        """Write a segment shaped like the ones ``-c:v copy`` produces.

        One keyframe, at position zero. That is what makes seeking into it
        subtle, so the test has to reproduce it.
        """
        subprocess.run(
            [
                "ffmpeg", "-loglevel", "error", "-y",
                "-f", "lavfi",
                "-i", f"testsrc=duration={duration}:size=160x120:rate=10",
                "-c:v", "libx264",
                "-g", "10000", "-keyint_min", "10000", "-sc_threshold", "0",
                "-pix_fmt", "yuv420p",
                "-f", "mpegts", str(path),
            ],
            check=True,
            capture_output=True,
        )

    def test_segment_really_has_a_single_keyframe(self, tmp_path):
        segment = tmp_path / "seg.ts"
        self._write_segment(segment)
        probe = subprocess.run(
            [
                "ffprobe", "-v", "error", "-select_streams", "v",
                "-show_entries", "frame=key_frame", "-of", "csv=p=0",
                str(segment),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        flags = [line.strip(", ") for line in probe.stdout.split()]
        assert flags.count("1") == 1
        assert flags.count("0") > 1

    @pytest.mark.asyncio
    async def test_frame_is_extracted_from_a_real_segment(self, tmp_path):
        clock = FakeClock(1_000_000.0)
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        # Segment started 10 s ago and runs 6 s; a 6 s rewind lands 4 s in.
        self._write_segment(buffer_dir / f"{int(clock.now) - 10}.ts")

        provider = SnapshotProvider(
            None,
            SnapshotConfig(
                mode=MODE_BUFFER,
                source_url="rtsp://unused/",
                buffer_path=str(buffer_dir),
                fallback_on_demand=False,
            ),
            time_fn=clock,
        )
        provider._active_mode = MODE_BUFFER

        image = await provider.async_grab(6.0)

        assert image is not None
        assert is_jpeg(image)

    @pytest.mark.asyncio
    async def test_the_frame_is_the_one_that_was_asked_for(self, tmp_path):
        """Two rewinds into the same segment must give different pictures."""
        clock = FakeClock(1_000_000.0)
        buffer_dir = tmp_path / "buffer"
        buffer_dir.mkdir()
        self._write_segment(buffer_dir / f"{int(clock.now) - 10}.ts")

        provider = SnapshotProvider(
            None,
            SnapshotConfig(
                mode=MODE_BUFFER,
                source_url="rtsp://unused/",
                buffer_path=str(buffer_dir),
                fallback_on_demand=False,
            ),
            time_fn=clock,
        )
        provider._active_mode = MODE_BUFFER

        early = await provider.async_grab(9.5)
        late = await provider.async_grab(5.0)

        assert is_jpeg(early) and is_jpeg(late)
        # testsrc counts up on screen, so a real seek changes the image.
        assert early != late
