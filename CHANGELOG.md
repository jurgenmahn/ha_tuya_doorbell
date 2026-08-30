# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.8.0] - 2026-08-30

### Changed

- Clip mode now also captures a **poster frame** into the snapshot image entity
  alongside the video. A clip has no native entity to display it, so the image
  entity now shows a still from the same buffer -- visible confirmation that a
  clip was made (the Test capture button in particular showed no visible result
  before), while the video stays available at `last_clip_url` and via the
  clip-ready event.

## [3.7.0] - 2026-08-30

### Fixed

- Clip mode no longer shows the still-only **"look back by"** setting. The field
  list already excluded it, but the form builder bolted it onto every mode with a
  buffer, so it appeared (and was saved) in clip mode too.
- The **Test capture** button in clip mode no longer leaves a **broken image** in
  the snapshot image entity. A clip is a video, so it now notifies its own
  listeners (refreshing `last_clip_url`) instead of poking the image entity, which
  had no still to show.

## [3.6.0] - 2026-08-30

### Changed

- The **Test** button now follows the snapshot mode: in clip mode it makes a
  clip (recorded to `last_clip_url`) instead of a still, so clip settings can be
  tested without ringing. Renamed to "Test capture" to match. In every other
  mode it still produces a still in the image entity, and still fires no event.
- The buffer-length setting is labelled "Buffer / clip length" and the snapshot
  mode description explains the clip mode, so the shared setting reads sensibly
  whichever of the two modes is chosen.

## [3.5.0] - 2026-08-30

### Added

- A **clip** snapshot mode. Like buffer, it keeps a rolling ring of video on
  tmpfs; but when the doorbell fires it stream-copies the whole buffer into a
  single mp4 (no re-encoding, so it is cheap even on a slow host) and fires a
  `lsc_tuya_doorbell_clip_ready` event carrying the clip URL, with `last_clip_url`
  also exposed as an attribute. Because the device reports a press a couple of
  seconds late, the moment of the press sits comfortably inside the saved clip.
  The existing buffer-length setting doubles as the clip length in this mode.

## [3.4.0] - 2026-08-30

### Changed

- The **record switch** role and the **"auto-enable the record switch"** option are
  renamed to **ONVIF**: the role is now `onvif` and the option is `force_onvif`.
  The switch was never about recording -- it enables ONVIF, and with it the RTSP
  stream, which some devices turn off by themselves (for instance after a reboot).
  The old "record" naming sat confusingly next to the genuine recording datapoints
  (video recording, recording mode). Behaviour is unchanged: the switch is still
  pushed back on when the device drops it.
- Existing configurations are migrated automatically. A profile that stored the
  role as `record_switch` loads it as `onvif`, and an entry that stored the option
  as `force_record_on` is still honoured, so upgrading does not silently stop ONVIF
  being kept on.

## [3.3.0] - 2026-08-30

### Added

- A snapshot **image entity**. The picture taken when the doorbell fires used to
  exist only as a file on disk and a URL in an attribute, with nothing to render
  it. It now shows as an image entity -- on dashboards, in notifications, in the
  logbook -- so the picture of who rang is actually visible.
- A **Test snapshot** button. It runs the exact same grab-and-store path a
  doorbell event would and updates the image entity, but fires no event, so the
  snapshot configuration can be validated without pressing the bell or tripping
  an automation.

### Changed

- The **still image URL** is now offered and used in the *on demand* mode only.
  It returns the picture as it is now, so it never fitted the *buffer* mode (a
  frame from the past) or *warm* mode (a pre-warmed stream); showing it there
  invited setting a source that silently could not do what the mode promised. In
  buffer/warm the fallback now grabs from the stream instead.

## [3.2.0] - 2026-08-30

### Added

- A realtime debug event stream. With "Debug: realtime datapoint events" turned
  on in the options, every datapoint the device reports is fired on the event bus
  as `lsc_tuya_doorbell_debug_dp` the instant it arrives, carrying the datapoint
  number, its value, the previous value, and a monotonic timestamp taken at
  arrival. Subscribing to it under Developer Tools → Events is how you measure the
  delay between a button press and anything reacting to it -- the options screen
  that refreshes on a timer never showed timing this precisely. Off by default;
  it is chatty and only meant for debugging.

## [3.1.0] - 2026-08-29

### Added

- The recording modes can read video from somewhere other than the camera. Anyone
  already running a restreamer for other reasons can point the ring buffer at it
  without routing the camera entity through it as well, which previously meant
  standing up a second restreamer to look two seconds into the past.
- A datapoint can be marked as firing an event. The live capture marks likely
  candidates, but it cannot be decided automatically: a volume slider moved
  twice reports two values exactly like a button pressed twice.
- Continuous integration. The HACS and hassfest validators run on every push and
  weekly, along with the test suite.

### Fixed

- An event entity is now judged stale by whether its datapoint still fires,
  rather than by its domain -- which is always "event", so it always looked
  correct while nothing would ever fire it again.
- Two manifest keys Home Assistant does not recognise, and a placeholder inside
  single quotes in the translations, both of which hassfest rejects.
- An integration implementing `async_setup` must declare a config schema. This
  one has no YAML configuration, and now says so.

### Changed

- DP 255 verified against hardware: it switches the ONVIF service.

## [3.0.0] - 2026-08-27

A datapoint number is not a meaning. Version 2.x treated DP 185 as "the doorbell
button", which is true of one LSC model with one firmware and of nothing else.
That single assumption is why the integration could connect perfectly and then
do nothing at all on somebody else's doorbell. 3.0 replaces it with roles the
device tells you about, adds a way to find those datapoints by watching the
device, and makes the failures visible that used to be swallowed on the way to
the user.

### Upgrading

- **A working 2.x installation keeps working.** Existing profiles are migrated
  when they are loaded: roles are seeded from the old hardcoded numbers, but
  only for datapoints your device actually reports. Nothing is invented, so an
  upgrade cannot add entities wired to datapoints that do not exist.
- **If you never got 2.x to react to the doorbell**, that is the case this
  release is for. Open **Configure → Live capture (find button and motion
  datapoints)**, press the doorbell while it listens, keep what it finds, and
  assign the datapoints to roles. Home Assistant also raises a repair issue when
  no datapoint claims the doorbell-button role.
- **Existing automations keep firing.** The device-slug event names
  (`lsc_tuya_doorbell_button_press_front_door`) still fire, but they are
  deprecated: the slug comes from the editable device name, so renaming a device
  silently broke every automation built on one. Move to the stable name
  (`lsc_tuya_doorbell_button_press`) and filter on `device_id` in the payload.
- **Minimum Home Assistant version is now 2025.3.**
- Snapshots keep working as they did without any configuration: the default mode
  is `on_demand`, which is the 2.x behaviour. `warm` and `buffer` are a
  deliberate choice, made under **Configure → Snapshot settings**.

### Added

- **Roles.** A device profile now maps `doorbell_button`, `motion` and
  `record_switch` to whichever datapoint holds them on your device. Everything
  that used to compare a DP number asks the profile instead. A role nobody
  claims means that behaviour is off, and a repair issue points at the fix.
- **Live capture.** A capture session that listens on the open connection while
  you press the doorbell, trigger motion and walk through the Tuya app. It runs
  until you stop it, keeps every value each datapoint was seen carrying (capped
  at 50 per datapoint), and marks the ones that behave like events. Event
  datapoints cannot be found by querying — they only carry a value at the moment
  of the event — so this is the only way to find them.
- **A role assignment step** after both the scan and the capture, and nothing is
  written to the profile before you have been through it.
- **Event entities** (`event` platform) with device class `doorbell` and event
  type `ring`, which is the contract Home Assistant has wanted since 2023.8. The
  binary sensors stay next to them, because history and existing automations are
  attached to those.
- **Stable event names without the device slug**, alongside the deprecated
  slugged ones.
- **A snapshot subsystem with four modes** — `off`, `on_demand`, `warm`,
  `buffer` — configurable buffer path and length, and a look-back compensation
  of up to 8 seconds for the fact that the device reports a press three to five
  seconds after it happened. Measured: a per-event ffmpeg grab costs 5.86 s and
  15.94 s when a second one overlaps it; a continuous ffmpeg writing a rolling
  JPEG is 1.00 s, flat.
- **A free-space check on the buffer path** at startup, with a warning naming
  the path and the shortfall. Docker gives `/dev/shm` 64 MB by default and a
  minute of buffer costs about 15 MB.
- **Reauthentication and reconfigure flows.** Tuya rotates the local key
  whenever a device is re-paired; until now the only way through that was
  deleting the entry, which renames every entity and breaks every automation.
- **Protocol version retry.** A failed handshake tries the other supported
  versions and stores — and logs — the one that worked.
- **Distinct, actionable setup errors**: wrong local key, unsupported protocol
  version, decryption failure, protocol error, timeout, discovery failure.
- **`lsc_tuya_doorbell_snapshot_ready`**, fired when the picture for an earlier
  event has been stored, and **`lsc_tuya_doorbell_dp_scan_results`** for the
  scan and monitor services.
- **Self-describing datapoint definitions**: `device_class`, `value_map` and
  `carries_image_url`, so the entity platforms read the definition instead of
  branching on the number.
- **`network` as an integration dependency**, so subnet detection can read the
  adapters Home Assistant already knows about, prefix included, instead of
  guessing a /24.

- **Datapoint names are only given when someone has verified them.** Nine v4
  table entries were checked against a real doorbell and eight were wrong,
  usually with the right concept on the wrong number. Unverified entries no
  longer name anything; the datapoint keeps its number, which is honest and
  understood. The entries stay, because knowing which datapoints a generation
  *has* is what tells the generations apart, and presence is reliable where
  meaning is not.
- **Roles can be assigned from the options menu** without running a capture
  first. Deciding which datapoint is the button is a decision, not a side
  effect of discovering datapoints.
- **The firmware generation can be set by hand**, and is inferred from the
  datapoints a device reports when a profile is written.
- **A name you type is recorded as yours** and nothing automatic overwrites it,
  including a name that happens to match a table entry.

### Changed

- **Known-datapoint tables are selected by firmware generation** instead of
  being merged. The union survives only as a last resort for a device whose
  generation is unknown, and says so.
- **Discovery goes through the shared manager.** It reads the live cache, only
  binds a socket when no listener is running, and stays open a few seconds past
  the first reply because Tuya devices broadcast about every five seconds and
  not in step — closing on the first answer meant seeing one doorbell out of two.
- **Adding a device by discovery is a progress step**, so the dialog no longer
  freezes for ten seconds, and devices you already configured are filtered out
  and counted.
- **The protocol version from a discovery broadcast is a hint, not a fact.** It
  is offered as an editable default with a label saying where it came from,
  because these devices routinely announce a version they do not speak.
- **The event never waits for the picture.** Entity callbacks and the event fire
  at t=0 with `snapshot_url` present and `null`; a tracked background task fills
  the picture in, rewrites the sensor attributes and fires a second event.
- **Every event payload has every key**, always, `null` where there is nothing.
  An automation that has to test whether a field exists breaks on the first
  event that leaves it out.
- **The snapshot source is whatever you configured.** The stream URL override is
  used by the camera, by the snapshot provider and by the continuous ffmpeg
  alike; passwords in URLs are escaped.
- **The camera entity appears when there is a stream URL or a still-image URL.**
  It used to demand an ONVIF password it does not need.
- **All file work goes through the executor.** Home Assistant's blocking-call
  detector does not cover `Path.mkdir`, `glob`, `stat` or `unlink`, so the old
  blocking calls on the event loop never produced a warning.
- **Presentation rules moved to `entity_meta.py`**, which imports no Home
  Assistant, so what a datapoint looks like can be tested instead of discovered
  in production.
- **Services are registered once for the integration**, with schemas, rather
  than per config entry and never removed.
- **Value normalisation reads the datapoint's declared type** instead of
  guessing from the value, and `raw` is never converted.
- **Profile deserialisation drops unknown keys** rather than raising, so a
  profile written by a newer version cannot stop an older one from starting.
- Minimum Home Assistant version raised to **2025.3**; `hacs.json` now declares
  the same minimum as the manifest.

- **Settings ask one question at a time.** Home Assistant has no conditional
  fields, so camera settings now start with where the video comes from and
  snapshot settings with the mode, and the follow-up shows only what applies.
  Submitting a sub-step returns to the menu instead of closing the dialog.
- **The still image URL moved to the snapshot settings**, where it is read.
  Behaviour is unchanged: it was always tried first, in every mode.
- **The live capture screen refreshes itself**, shows what each datapoint
  carried, and marks the ones that reported just now -- which is how you find a
  button: press it a few times and watch what moves. Closing the dialog ends the
  session and keeps what it found.
- Datapoint names verified against hardware: 101 indicator light, 103 image
  flip, 104 timestamp overlay, 108 infrared night vision, 115 motion, 134 motion
  alarm, 150 video recording, 151 recording mode, 155 chime pairing, 160 device
  volume, 185 doorbell button.

### Fixed

- **The scan invented datapoints.** Every scan result had the known event
  datapoints bolted on afterwards, whether the device reported them or not. On
  the one model this was written for the guess was right, which is why it looked
  like it worked; on any other doorbell it produced two sensors wired to
  datapoints that device never sends, while the real ones were never found.
- **Auto-discovery fought itself for the UDP ports.** Once any config entry
  existed the shared listener held ports 6666 and 6667, and the config flow
  built a second listener that tried to bind them again. Since Python 3.9
  `create_datagram_endpoint` no longer sets `SO_REUSEADDR`, so that bind could
  not succeed — it failed, was logged at debug level, and the user was told "no
  devices found", which points at the network instead of at us. `find_device()`
  had the same bug: every IP rediscovery hit a dead UDP step, waited out ten
  seconds and fell back to sweeping the whole subnet over TCP.
- **Protocol 3.5 never worked.** The 6699 frame carries an 18-byte header with a
  two-byte field between prefix and sequence number, its own suffix, GCM
  authentication over the header, a version header before the ciphertext, and a
  return code *inside* the encrypted payload. This implementation had none of
  that, and the config flow offered 3.5 anyway. The encoder is now verified
  against golden frames from tinytuya's own packer and reproduces them byte for
  byte. (The session handshake against real 3.5 hardware is still untested; see
  the README.)
- **A wrong local key was invisible.** It looked exactly like a working install:
  connected, every entity available, nothing ever happening. Not one bug but a
  stack of individually reasonable ones — a CRC mismatch logged at debug and the
  frame processed anyway, an HMAC mismatch likewise, a failed decrypt returning
  the raw ciphertext, invalid PKCS7 padding (the signature of a wrong key)
  returning the data unchanged, a JSON parse failure becoming an empty dict. By
  the time it reached the user there was nothing left to see. All of it now
  reaches the log with something to act on, throttled per kind, with a note when
  it recovers. The device's own HMAC in the 3.4/3.5 handshake is verified too,
  so a successful connect really does prove the key.
- **Losing the heartbeat killed the connection without reconnecting**, because
  the disconnect path skipped the callbacks that trigger recovery. There are now
  two disconnects: a quiet one for unload, and a forced one that says why and
  tells everything downstream. The read loop also gives up on a connection that
  has been silent for ninety seconds.
- **A frame claiming a nonsensical length stalled reassembly for good** — socket
  open, read loop running, nothing dispatched ever again, buffer growing without
  bound. Lengths are bounded per format, the suffix is checked at the computed
  boundary, and a desynchronised stream resynchronises instead of waiting
  forever.
- **Notifications showed the previous caller.** The binary sensor fired at once
  and carried `last_snapshot_url` with it, but that variable was only updated
  when a grab returned, so the picture in the notification was the one before.
  The press now fires with a `null` URL and the picture is delivered afterwards
  through `snapshot_ready` and updated attributes.
- **A doorbell press could disappear entirely.** Two background tasks ran on
  `asyncio.ensure_future` with nothing holding a reference, and the event was
  attached to one of them; a garbage collection at the wrong moment swallowed
  the whole press. Every background task is now created through the config entry
  and tracked.
- **Entities did not notice a disconnect.** Only the Connected sensor ever
  subscribed to connection changes; switches, selects, numbers, sensors and the
  camera kept showing their last value until a datapoint update arrived, which
  on an offline device is never. The integration reported a house full of
  working entities attached to a doorbell that had been unreachable for hours.
- **The v5 table silently overwrote the v4 table.** They genuinely disagree
  about DP 109, 110 and 134 — "SD Card Status" against "Basic OSD", "Vision
  Flip" against "Chime Switch" — and the merged table let v5 win every conflict,
  so v4 devices had been mislabelled all along. The disagreement is now pinned
  by a test.
- **An IP change cancelled its own recovery.** The new address was written
  before the connection was established, and the resulting config-entry reload
  tore down the task doing the reconnecting. It is written after the connection
  succeeds, and the reload it triggers is absorbed.
- **Choosing an already-configured device produced "an unexpected error
  occurred" forever.** `AbortFlow` inherits from `Exception` and was swallowed by
  a broad handler, so the correct "already configured" message was unreachable.
- **The scan saved before it asked.** Unticking a datapoint on the results screen
  still left an entity behind, and ticking one replaced its full definition with
  a bare stub, stripping the options, bounds and event flag the scan had just
  learned. The screen offering a choice was misleading in both directions.
- **The event counter existed twice** — once in the hub, once restored by the
  sensor — and the two drifted apart on every restart. There is one now, and the
  sensor feeds its restored value back on startup.
- **Device classes were assigned by datapoint number.** Every binary datapoint
  that was not 185 or 115 was labelled a connectivity sensor, which is simply
  untrue. A device class now comes from the definition, then from the role, and
  otherwise stays unset — no class at all is honest, a wrong one is not.
- **The SD card sensor identified itself by looking for "sd card" inside its own
  display name**, which broke the moment anyone renamed it.
- **Two different events shared one name.** `dp_discovered` was fired by the hub
  and by the service handler with different payloads, so an automation listening
  for it got whichever shape happened to arrive. The service now fires
  `dp_scan_results`.
- **`event_reset_timeout` was never read**, so changing it did nothing at all.
  It is read now, clamped to 1–300 seconds, and an unreadable value is logged
  rather than ignored.
- **Snapshots opened a fresh RTSP session per press**, even when a stream URL
  override pointed at a restreamer — which is how a camera that tolerates a
  handful of sessions ended up with four, and why a second grab took 15.94 s.
- **A `raw` payload made of digits was converted to an integer** by value
  guessing, after which it could no longer be decoded.
- **Subnet detection asked an outside address for its route and assumed a /24.**
  It reads Home Assistant's adapters now, prefix included; the old probe is a
  last resort, runs off the event loop, and says out loud that the /24 is a
  guess. A range larger than 1024 hosts is refused rather than turned into 65k
  probes.
- **The `discover_devices` service used the private UDP listener** and therefore
  hit the same port conflict as the config flow: it structurally found nothing.

- **The record switch role is no longer seeded from a datapoint number.** DP 101
  was assumed to be the record switch and is the indicator light, so "force
  recording on" would have watched an LED and switched it back on forever.
- **Entities left behind when a datapoint changes kind are removed.** A
  unique_id is only unique within a domain, so a datapoint that was a switch and
  became a number kept both entries and Home Assistant could not tell they were
  the same thing.
- **A video source that cannot be recorded is given up on** after six failures,
  with an error saying what to do, instead of restarting forever and never
  taking a picture.
- **Relabelling a datapoint carries its bounds, options and value map**, so a
  volume control described as 1-10 no longer sits on the 0-100 the number
  platform falls back to.
- **A second capture no longer clears the roles set by the first.** The role
  screen offered only that round's datapoints, and a select with nothing to
  select submits "not assigned".
- The scan result screen said "Datapoints to keep", which reads as though
  unticking one removes it. It never did.

### Removed

- Hardcoded datapoint numbers as behaviour. `DP_DOORBELL_BUTTON`,
  `DP_MOTION_DETECTION` and `DP_RECORD_SWITCH` survive only as seeds for
  proposing roles.
- Automatic inclusion of the "known" event datapoints in scan results.
- Per-event ffmpeg processes as the only way to get a picture; the snapshot
  provider owns that now, and `hub.py` no longer captures or cleans up
  snapshots itself.
- `domains` and `iot_class` from `hacs.json` — HACS rejects keys outside its
  schema, and neither was one of them.

## Earlier releases

Taken from the release notes in the 2.x README. No release dates were recorded
for these versions.

### 2.8.0 — Connected binary sensor, configurable snapshot triggers, improved labels

- New **Connected** diagnostic binary sensor (`device_class: connectivity`)
  reflecting real-time connection state.
- **Snapshot trigger DPs** made configurable in Camera Settings as a
  multi-select of discovered datapoints, instead of being hardcoded to DP 185.
- Clearer `force_record_on` label explaining the Tuya quirk where ONVIF and
  recording are randomly disabled.

### 2.7.0 — Auto-recovery for the record switch (DP 101)

- New **Auto-enable Record Switch** option that forces DP 101 back on when the
  device disables it, which breaks ONVIF/RTSP.
- Two-second delay before re-enabling, to avoid rapid toggle loops.

### 2.6.2 — Device identity validation fix

- v3.3 now requires actual DP data, not just a heartbeat, to confirm the local
  key matches.
- v3.4/v3.5 rely on session key negotiation during connect.

### 2.6.0 — DP scan reliability and UI improvements

- DP scan resumes after a disconnect: waits up to 30 s for reconnect and
  continues where it stopped, up to 3 retries.
- Event DPs (185, 115) automatically included in scan results — since replaced,
  see 3.0.0.
- Scan results survive closing the dialog; force-rescan checkbox added.
- Fixed a `progress_done` race and a `vol.Ensure` crash in the scan results.
- Fewer device22 query retries; cleaner disconnect logging; UDP decrypt noise
  from other Tuya devices suppressed.

### 2.5.1 — DP scanning fixes and ONVIF password persistence

- Fixed the ONVIF password being lost on reboot or on saving options.
- Fixed the DP scan hanging: reverted concurrent scanning in favour of
  sequential larger batches with a delay.
- Fixed a `CancelledError` crash in `query_dps` when the device disconnected
  during setup.

### 2.5.0 — DP scanning overhaul

- Real-time scan progress showing the current batch, found count and DP IDs.
- 120-second scan timeout.
- Merge or replace choice for scan results.
- Early abort when the device disconnects during a scan.

### 2.4.0 — HACS and packaging update

- Updated the HACS manifest.

### 2.3.0 — Custom DPs, video stream and snapshots

- Custom DP IDs can be added from the options UI.
- RTSP camera entity.
- Automatic snapshot capture on doorbell press.
- Fixed the config reload issue after saving settings.

### 2.0.0 — Complete rewrite

- Rebuilt with a clean async architecture.
- Tuya protocol 3.3, 3.4 and 3.5 with session key negotiation.
- Automatic DP discovery and dynamic entity creation.
- Heartbeat monitoring and exponential backoff reconnection.
- No external dependencies beyond `cryptography`.

[3.0.0]: https://github.com/jurgenmahn/ha_tuya_doorbell/releases/tag/v3.0.0
