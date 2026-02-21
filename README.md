# LSC Tuya Doorbell v2 — Home Assistant Integration

**Local-only control for your LSC Smart Connect video doorbell.** No cloud, no subscriptions, no data leaving your network.

This is a complete rewrite of the original integration, built from scratch with a clean async architecture, automatic datapoint discovery, and robust reconnection handling.

Available at Action stores across the Netherlands and other European countries, these affordable Tuya-based smart doorbells now integrate seamlessly with Home Assistant over your local network.

## What's new in v2

- **Complete protocol rewrite** — Clean async implementation supporting Tuya protocol 3.3, 3.4, and 3.5 with automatic session key negotiation
- **Automatic DP discovery** — No more guessing datapoints; the integration scans and classifies them automatically
- **Dynamic entity creation** — Switches, selects, numbers, sensors, binary sensors, and camera created based on what your device supports
- **RTSP camera entity** — Live video stream via RTSP with automatic snapshot capture on doorbell press
- **Doorbell snapshots** — Automatically captures and stores RTSP snapshots on button press, accessible via entity attributes and event data
- **DP management UI** — Add, edit, remove, and scan for datapoints directly from the options flow
- **Device type detection** — Identifies doorbells, cameras, and other Tuya devices during network discovery
- **Device22 support** — Handles 22-character device IDs that require the CONTROL_NEW protocol variant
- **Resilient connection** — Heartbeat monitoring, exponential backoff reconnection, automatic IP change detection with network rediscovery
- **Zero external dependencies** — Uses only `cryptography` (standard in most HA installs); no `tinytuya`, `pytuya`, or `netifaces` required

## Features

**Entities created automatically based on your device:**

| Entity | Example DPs | Description |
|--------|-------------|-------------|
| Camera | — | Live RTSP video stream with automatic doorbell snapshot capture |
| Binary Sensor | 185, 115 | Doorbell button press and motion detection with auto-reset, event counters, image URL extraction, and local snapshot URL |
| Switch | 101, 104, 134, 150 | Record switch, indicator light, vision flip, chime switch |
| Select | 103, 106, 108, 151 | Night vision mode, motion sensitivity, basic OSD, recording mode |
| Number | 135, 139, 154 | Chime volume, device volume |
| Sensor | 109, 110 | SD storage info, SD card status with human-readable state mapping |

**Camera and snapshots:**

- Live RTSP stream viewable in HA dashboard camera cards
- Automatic snapshot capture on doorbell button press via ffmpeg
- Snapshots saved to configurable directory (default `/config/www/doorbell/`)
- Latest snapshot URL exposed as `last_snapshot_url` attribute on the doorbell binary sensor
- Snapshot URL included in doorbell press event data for use in automations
- Automatic cleanup — only the last 10 snapshots per device are kept

**Protocol support:**

- Tuya protocol **3.3** — Standard encryption (AES-ECB + CRC32)
- Tuya protocol **3.4** — Enhanced encryption (AES-ECB + HMAC-SHA256 + session key negotiation)
- Tuya protocol **3.5** — Latest encryption (AES-GCM with 0x6699 packet prefix + session key negotiation)
- Automatic Device22 detection for 22-character device IDs (uses CONTROL_NEW command variant)

**Discovery and connectivity:**

- UDP broadcast listener (ports 6666/6667) with encrypted packet support
- TCP subnet scanner as fallback when UDP discovery fails
- Full DP scan (1-255) with batch processing and type classification
- Passive DP monitoring — listens for spontaneous device updates over a configurable duration
- Persistent device profiles — works across restarts even if the device is temporarily offline
- Fires Home Assistant events for doorbell presses, motion, connect/disconnect, IP changes, and DP discovery

## Requirements

- Home Assistant 2024.1.0 or newer
- LSC Smart Connect Video Doorbell (or compatible Tuya device)
- Device ID and Local Key (see [Finding your credentials](#finding-your-device-id-and-local-key))
- **For camera/snapshots:** `ffmpeg` installed on the HA host (included in HA OS by default)

## Installation

### HACS (Recommended)

1. Open [HACS](https://hacs.xyz/) in Home Assistant
2. Go to **Integrations** > three-dot menu > **Custom repositories**
3. Add the repository URL with category **Integration**
4. Search for "LSC Tuya Doorbell" and install
5. Restart Home Assistant

### Manual

1. Copy `custom_components/lsc_tuya_doorbell` to your Home Assistant `custom_components` directory
2. Restart Home Assistant

## Configuration

1. Go to **Settings** > **Devices & Services** > **Add Integration**
2. Search for **LSC Tuya Doorbell**
3. Choose **Auto-discover** (scans your network) or **Manual** entry
4. If manual: enter host IP, device ID, port (default 6668), and protocol version (3.3, 3.4, or 3.5)
5. Enter your 16-character local key and device name
6. Optionally enter your ONVIF/RTSP password to enable the camera entity and doorbell snapshots
7. The integration tests the connection and runs DP discovery automatically

That's it. Entities are created based on what the device reports.

### Options

After setup, go to the integration's **Configure** to access the options menu:

| Menu | Description |
|------|-------------|
| **Connection Settings** | Update host IP, port, or protocol version (3.3 / 3.4 / 3.5) |
| **Camera Settings** | Configure RTSP username, password, port, stream path, and snapshot directory |
| **Manage Datapoints** | View, edit, add, or remove configured datapoints |
| **Scan for Datapoints** | Run a full DP scan (1-255) and select which to add |

### Camera Settings

To enable the camera entity and doorbell snapshots, configure the ONVIF/RTSP password either during initial setup or via **Options > Camera Settings**. The default RTSP URL pattern is:

```
rtsp://admin:PASSWORD@DEVICE_IP:8554/Streaming/Channels/101
```

| Setting | Default | Description |
|---------|---------|-------------|
| ONVIF Username | `admin` | RTSP authentication username |
| ONVIF Password | *(empty)* | RTSP authentication password (required to enable camera) |
| RTSP Port | `8554` | RTSP server port on the doorbell |
| RTSP Path | `/Streaming/Channels/101` | Stream path (channel 101 = main stream) |
| Snapshot Path | `/config/www/doorbell` | Directory for doorbell press snapshots |

When the doorbell button is pressed (DP 185), the integration automatically:
1. Captures a snapshot from the RTSP stream using ffmpeg
2. Saves it to the snapshot directory as `{device_slug}_{timestamp}.jpg`
3. Exposes the URL as `last_snapshot_url` on the doorbell binary sensor entity
4. Includes `snapshot_url` in the fired event data
5. Cleans up old snapshots (keeps the last 10 per device)

### Datapoint Management

From **Options > Manage Datapoints** you can:
- **View** all configured DPs with their name, type, and entity type
- **Edit** a DP's name or entity type (switch, sensor, select, number, binary sensor)
- **Delete** a DP you no longer need
- **Add** a custom DP by specifying ID (1-255), name, data type, and entity type

From **Options > Scan for Datapoints** the integration:
- Queries the device for all active DPs
- Batch-scans DP range 1-255 using UPDATEDPS
- Shows discovered DPs with pre-selected new ones for easy import
- Already-configured DPs are marked and excluded from default selection

## Finding your Device ID and Local Key

### TinyTuya Wizard (Recommended)

```bash
pip install tinytuya
python -m tinytuya wizard
```

Follow the prompts to scan your network and retrieve device credentials.

### Tuya IoT Platform

1. Create an account at [iot.tuya.com](https://iot.tuya.com/)
2. Create a cloud project and link your devices
3. Find device IDs and local keys in the project's device list

### Alternative tools

- [Tuya Cloudcutter](https://github.com/tuya-cloudcutter/tuya-cloudcutter) — Unbind devices and generate local keys

## Automations

### Doorbell press notification with snapshot

When RTSP is configured, the doorbell binary sensor exposes `last_snapshot_url` as an attribute — a local URL pointing to the most recent doorbell snapshot:

```yaml
automation:
  - alias: "Doorbell notification with snapshot"
    trigger:
      platform: state
      entity_id: binary_sensor.front_door_doorbell_button
      to: "on"
    action:
      - service: notify.mobile_app
        data:
          title: "Doorbell"
          message: "Someone is at the front door"
          data:
            image: >
              {{ state_attr('binary_sensor.front_door_doorbell_button', 'last_snapshot_url') }}
```

### Doorbell snapshot via event data

Doorbell press events include both `snapshot_url` (local RTSP capture) and `image_url` (Tuya cloud image, if available):

```yaml
automation:
  - alias: "Doorbell event with snapshot"
    trigger:
      platform: event
      event_type: lsc_tuya_doorbell_button_press_front_door
    action:
      - service: notify.mobile_app
        data:
          title: "Doorbell"
          message: "Press #{{ trigger.event.data.event_counter }} at {{ trigger.event.data.timestamp }}"
          data:
            image: "{{ trigger.event.data.snapshot_url }}"
```

Snapshots are saved to `/config/www/doorbell/` and accessible via `/local/doorbell/filename.jpg`.

### Motion-activated porch light

```yaml
automation:
  - alias: "Porch light on motion"
    trigger:
      platform: state
      entity_id: binary_sensor.front_door_motion_detection
      to: "on"
    condition:
      condition: sun
      after: sunset
    action:
      - service: light.turn_on
        target:
          entity_id: light.porch
        data:
          brightness_pct: 100
      - delay: { minutes: 2 }
      - service: light.turn_off
        target:
          entity_id: light.porch
```

### Event-based trigger (advanced)

The integration fires device-specific events with rich data:

```yaml
automation:
  - alias: "Doorbell event with image"
    trigger:
      platform: event
      event_type: lsc_tuya_doorbell_button_press_front_door
    action:
      - service: notify.mobile_app
        data:
          title: "Doorbell"
          message: "Press #{{ trigger.event.data.event_counter }} at {{ trigger.event.data.timestamp }}"
          data:
            image: "{{ trigger.event.data.image_url }}"
```

**Event data fields:**

| Field | Description |
|-------|-------------|
| `device_id` | Tuya device ID |
| `timestamp` | ISO timestamp of the event |
| `event_counter` | Running count of events since last restart |
| `dp_id` | Datapoint ID that triggered the event |
| `raw_value` | Raw value from the device |
| `image_url` | Tuya cloud image URL (if available in the DP payload) |
| `snapshot_url` | Local RTSP snapshot URL (only on doorbell press when RTSP is configured) |

**Available event types:**

| Event | Trigger |
|-------|---------|
| `lsc_tuya_doorbell_button_press_{device_slug}` | Doorbell button pressed (DP 185) |
| `lsc_tuya_doorbell_motion_detect_{device_slug}` | Motion detected (DP 115) |
| `lsc_tuya_doorbell_connected` | Device connected |
| `lsc_tuya_doorbell_disconnected` | Device disconnected |
| `lsc_tuya_doorbell_ip_changed_{device_slug}` | Device IP changed (includes `old_ip` and `new_ip`) |
| `lsc_tuya_doorbell_dp_discovered` | New datapoints discovered |

### Disconnect alert

```yaml
automation:
  - alias: "Doorbell offline alert"
    trigger:
      platform: event
      event_type: lsc_tuya_doorbell_disconnected
    action:
      - service: persistent_notification.create
        data:
          title: "Doorbell offline"
          message: "The doorbell lost connection at {{ now().strftime('%H:%M') }}"
```

## Debug tool

A standalone CLI tool is included for testing and troubleshooting without Home Assistant:

```bash
# Discover devices on your network
python tools/debug_tuya.py discover

# Test connection and query datapoints
python tools/debug_tuya.py connect --ip 192.168.1.100 --device-id YOUR_ID --local-key YOUR_KEY

# Scan all DPs (1-255)
python tools/debug_tuya.py scan --ip 192.168.1.100 --device-id YOUR_ID --local-key YOUR_KEY

# Monitor live events
python tools/debug_tuya.py monitor --ip 192.168.1.100 --device-id YOUR_ID --local-key YOUR_KEY

# Set a value
python tools/debug_tuya.py set --ip 192.168.1.100 --device-id YOUR_ID --local-key YOUR_KEY 101 true
```

Add `--debug` to any command for verbose protocol-level logging.

## Services

| Service | Description |
|---------|-------------|
| `lsc_tuya_doorbell.discover_devices` | Scan the network for Tuya devices |
| `lsc_tuya_doorbell.discover_datapoints` | Run full DP discovery (1-255) on a specific device |
| `lsc_tuya_doorbell.export_dp_profile` | Export device profile as JSON |
| `lsc_tuya_doorbell.monitor_datapoints` | Passively monitor a device for DP updates over a given duration |
| `lsc_tuya_doorbell.add_datapoint` | Add a manual datapoint to a device profile (triggers reload) |
| `lsc_tuya_doorbell.remove_datapoint` | Remove a datapoint from a device profile (triggers reload) |

## Troubleshooting

**Enable debug logging:**

```yaml
logger:
  logs:
    custom_components.lsc_tuya_doorbell: debug
```

**Common issues:**

| Problem | Solution |
|---------|----------|
| Cannot connect | Verify local key is correct (exactly 16 characters). Try protocol version 3.3 first, then 3.4 or 3.5. |
| Heartbeat fails | Device may be connected to another client. Only one local connection is supported at a time. |
| No datapoints found | The DP scan may need a few seconds. Check debug logs for device22 detection. Try **Options > Scan for Datapoints**. |
| Device goes offline | Set a static IP in your router. The integration will rediscover the device if the IP changes, but static is more reliable. |
| Wrong entity types | Use **Options > Manage Datapoints** to edit the entity type, or re-scan with **Scan for Datapoints**. |
| No camera entity | Ensure ONVIF/RTSP password is configured (during initial setup or via **Options > Camera Settings**). |
| Camera stream not loading | Verify the RTSP URL works in VLC: `rtsp://admin:PASSWORD@IP:8554/Streaming/Channels/101`. Check port and path in Camera Settings. |
| Snapshot capture fails | Check that `ffmpeg` is installed. On HA OS it's pre-installed; on Docker/venv you may need to install it separately. |
| Protocol 3.4/3.5 fails | Session key negotiation requires a valid local key. If upgrading from 3.3, re-enter the local key in connection settings. |

## Known DP Mappings

The integration includes built-in mappings for firmware v4 and v5:

**Firmware v4:**

| DP | Name | Type | Entity |
|----|------|------|--------|
| 101 | Record Switch | bool | Switch |
| 103 | Night Vision | enum | Select (auto/on/off) |
| 104 | Indicator Light | bool | Switch |
| 106 | Motion Sensitivity | enum | Select (low/medium/high) |
| 108 | Basic OSD | enum | Select (off/on) |
| 109 | SD Storage Info | string | Sensor |
| 110 | SD Card Status | int | Sensor |
| 115 | Motion Detection | raw | Binary Sensor (event) |
| 134 | Vision Flip | bool | Switch |
| 150 | Chime Switch | bool | Switch |
| 151 | Recording Mode | enum | Select (event/continuous) |
| 154 | Device Volume | int (1-10) | Number |
| 185 | Doorbell Button | raw | Binary Sensor (event) |

**Firmware v5:**

| DP | Name | Type | Entity |
|----|------|------|--------|
| 101 | Record Switch | bool | Switch |
| 103 | Night Vision | enum | Select (auto/on/off) |
| 104 | Indicator Light | bool | Switch |
| 105 | Vision Flip | bool | Switch |
| 106 | Motion Sensitivity | enum | Select (low/medium/high) |
| 109 | SD Card Status | int | Sensor |
| 110 | Basic OSD | bool | Switch |
| 115 | Motion Detection | raw | Binary Sensor (event) |
| 134 | Chime Switch | bool | Switch |
| 135 | Chime Volume | int (0-10) | Number |
| 139 | Device Volume | int (1-10) | Number |
| 151 | Recording Mode | enum | Select (event/continuous) |
| 185 | Doorbell Button | raw | Binary Sensor (event) |

DPs not in the built-in table are auto-classified by their value type and can be customized via **Manage Datapoints**.

## Supported devices

Tested with:
- LSC Smart Connect Video Doorbell (product key: `jtc6fpl3`, firmware v4 and v5)

Should work with other Tuya-based doorbells and cameras that use protocol 3.3, 3.4, or 3.5. The dynamic DP discovery adapts to whatever datapoints your device exposes.

If you get a different LSC or Tuya device working, please open an issue with the product key and discovered DPs so we can expand the known device database.

## Technical overview

```
custom_components/lsc_tuya_doorbell/
  protocol/
    connection.py     # Async TCP connection with heartbeat, session negotiation (v3.3/3.4/3.5)
    messages.py       # Tuya packet encoding/decoding (v3.3, v3.4, v3.5)
    encryption.py     # AES-ECB, AES-GCM, HMAC-SHA256, session key negotiation
    constants.py      # Protocol constants and command definitions
  discovery/
    udp_listener.py   # UDP broadcast listener with device type classification
    scanner.py        # TCP subnet scanner (fallback)
    manager.py        # Discovery lifecycle and caching
  hub.py              # Central device manager (connection, state, events, snapshots)
  dp_discovery.py     # Automatic DP scanning and type classification
  dp_registry.py      # DP profile storage and management
  config_flow.py      # HA config flow with auto-discovery, options menu, DP management
  camera.py           # RTSP camera entity with ffmpeg snapshot support
  binary_sensor.py    # Doorbell button + motion detection entities
  switch.py           # Boolean DP entities
  select.py           # Enum DP entities
  number.py           # Integer range DP entities
  sensor.py           # Read-only DP entities (SD card status, etc.)
  entity.py           # Base entity class with DP callback management
  const.py            # Integration constants, known DP mappings (v4 + v5), device types
```

The protocol implementation is independent of Home Assistant and can be used standalone (see the `tools/` directory).

## Credits

Built by [Jurgen Mahn](https://github.com/jurgenmahn) with [Claude Code](https://claude.ai/code).

## License

MIT
