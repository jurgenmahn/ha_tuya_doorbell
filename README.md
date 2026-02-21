# LSC Tuya Doorbell v2 — Home Assistant Integration

**Local-only control for your LSC Smart Connect video doorbell.** No cloud, no subscriptions, no data leaving your network.

This is a complete rewrite of the original integration, built from scratch with a clean async architecture, automatic datapoint discovery, and robust reconnection handling.

Available at Action stores across the Netherlands and other European countries, these affordable Tuya-based smart doorbells now integrate seamlessly with Home Assistant over your local network.

## What's new in v2

- **Complete protocol rewrite** — Clean async implementation supporting Tuya protocol 3.3, 3.4, and 3.5
- **Automatic DP discovery** — No more guessing datapoints; the integration scans and classifies them automatically
- **Dynamic entity creation** — Switches, selects, numbers, sensors, and binary sensors are created based on what your device actually supports
- **Device type detection** — Identifies doorbells, cameras, and other Tuya devices during network discovery
- **Device22 support** — Handles 22-character device IDs that require the CONTROL_NEW protocol variant
- **Resilient connection** — Heartbeat monitoring, exponential backoff reconnection, automatic IP change detection with network rediscovery
- **Zero external dependencies** — Uses only `cryptography` (standard in most HA installs); no `tinytuya`, `pytuya`, or `netifaces` required

## Features

**Entities created automatically based on your device:**

| Entity | Example DPs | Description |
|--------|-------------|-------------|
| Binary Sensor | 185, 115 | Doorbell button press and motion detection with auto-reset, event counters, and image URL extraction |
| Switch | 101, 104, 134, 149 | Record switch, indicator light, vision flip, chime switch |
| Select | 103, 106, 151 | Night vision mode, motion sensitivity, recording mode |
| Number | 150, 154 | Chime volume, device volume |
| Sensor | 110 | SD card status with human-readable state mapping |

**Discovery and connectivity:**

- UDP broadcast listener (ports 6666/6667) with encrypted packet support
- TCP subnet scanner as fallback when UDP discovery fails
- Full DP scan (1-255) with batch processing and type classification
- Persistent device profiles — works across restarts even if the device is temporarily offline
- Fires Home Assistant events for doorbell presses, motion, connect/disconnect, and IP changes

## Requirements

- Home Assistant 2024.1.0 or newer
- LSC Smart Connect Video Doorbell (or compatible Tuya device)
- Device ID and Local Key (see [Finding your credentials](#finding-your-device-id-and-local-key))

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
4. Enter your 16-character local key
5. The integration tests the connection and runs DP discovery automatically

That's it. Entities are created based on what the device reports.

### Options

After setup, go to the integration's **Configure** to update host, port, or protocol version. Changes take effect immediately.

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

### Doorbell press notification

```yaml
automation:
  - alias: "Doorbell notification"
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
              {{ state_attr('binary_sensor.front_door_doorbell_button', 'last_image_url') }}
```

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
      event_type: lsc_tuya_doorbell_button_press
    action:
      - service: notify.mobile_app
        data:
          title: "Doorbell"
          message: "Press #{{ trigger.event.data.event_counter }} at {{ trigger.event.data.timestamp }}"
          data:
            image: "{{ trigger.event.data.image_url }}"
```

Available event types: `lsc_tuya_doorbell_button_press`, `lsc_tuya_doorbell_motion_detect`, `lsc_tuya_doorbell_connected`, `lsc_tuya_doorbell_disconnected`.

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
| `lsc_tuya_doorbell.discover_datapoints` | Run full DP discovery on a specific device |
| `lsc_tuya_doorbell.export_dp_profile` | Export device profile as JSON |

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
| Cannot connect | Verify local key is correct (exactly 16 characters). Try protocol version 3.3 first. |
| Heartbeat fails | Device may be connected to another client. Only one local connection is supported at a time. |
| No datapoints found | The DP scan may need a few seconds. Check debug logs for device22 detection. |
| Device goes offline | Set a static IP in your router. The integration will rediscover the device if the IP changes, but static is more reliable. |
| Wrong entity types | Use the `discover_datapoints` service to re-scan, or configure DP overrides in the options flow. |

## Supported devices

Tested with:
- LSC Smart Connect Video Doorbell (product key: `jtc6fpl3`, firmware v4 and v5)

Should work with other Tuya-based doorbells and cameras that use protocol 3.3-3.5. The dynamic DP discovery adapts to whatever datapoints your device exposes.

If you get a different LSC or Tuya device working, please open an issue with the product key and discovered DPs so we can expand the known device database.

## Technical overview

```
custom_components/lsc_tuya_doorbell/
  protocol/
    connection.py     # Async TCP connection with heartbeat and reconnect
    messages.py       # Tuya packet encoding/decoding (v3.3, v3.4, v3.5)
    encryption.py     # AES-ECB, HMAC-SHA256, session key negotiation
    constants.py      # Protocol constants and command definitions
  discovery/
    udp_listener.py   # UDP broadcast listener with device type classification
    scanner.py        # TCP subnet scanner (fallback)
    manager.py        # Discovery lifecycle and caching
  hub.py              # Central device manager (connection, state, events)
  dp_discovery.py     # Automatic DP scanning and type classification
  config_flow.py      # HA config flow with auto-discovery
  binary_sensor.py    # Doorbell button + motion detection entities
  switch.py           # Boolean DP entities
  select.py           # Enum DP entities
  number.py           # Integer range DP entities
  sensor.py           # Read-only DP entities (SD card status, etc.)
  const.py            # Integration constants, known DP mappings, device types
```

The protocol implementation is independent of Home Assistant and can be used standalone (see the `tools/` directory).

## Credits

🚀 Built with human ingenuity & a dash of AI wizardry
This project emerged from late-night coding sessions, unexpected inspiration, and the occasional debugging dance. Every line of code has a story behind it.

Found a bug? Have a wild idea? The issues tab is your canvas.

Authored By: 👨‍💻 Jurgen Mahn with some help from AI code monkies Claude & Manus.im

"Sometimes the code writes itself. Other times, we collaborate with the machines."

⚡ Happy hacking, fellow explorer ⚡

## License

MIT
