# Home Assistant Integration for LSC/Tuya Doorbell

Create a Home Assistant integration that adds support for LSC branded Tuya doorbells sold by Action stores in the Netherlands. I've already implemented this for Homey in JavaScript (pasted for reference) and now need a proper Home Assistant integration.

## Technical Details:
- Tuya API Version: 3.3
- Device ID: xxxxxxxxxx
- Local Key: xxxxxxxxxxxxx
- IP: xxxxxxxxxxxxxx
- Port: 6668 (default)
- Home Assistant Version: 2025.2.4

## Integration Requirements:

1. Use Tuya Local API to communicate directly with the doorbell (no cloud)
2. Detect two main events:
   - Doorbell button press (DPS 185)
   - Motion detection (DPS 115)
3. Create corresponding Home Assistant events for each:
   - `lsc_tuya_doorbell_button_press`
   - `lsc_tuya_doorbell_motion`
4. Support configuration via YAML with multiple devices:
   ```yaml
   lsc_tuya_doorbell:
     devices:
       - name: Front Door
         device_id: YOUR_DEVICE_ID
         local_key: YOUR_LOCAL_KEY
         host: 192.168.1.x  # Optional
   ```
5. Network discovery:
   - Store device MAC address on first configuration
   - If IP changes, scan network to find device by MAC
   - Update stored IP when found

## Code Structure:
1. Follow Home Assistant best practices and integration structure
2. Implement robust error handling and reconnection logic
3. Make it HACS-compliant for future submission
4. Implement proper config flow for UI setup (optional, YAML is primary)

## Event Payload Notes:
Both DPS 115 (motion) and DPS 185 (button press) contain Base64 encoded JSON with image links. The decoded JSON looks like:
```json
{
  "v": "3.0",
  "bucket": "ty-us-storage30-pic",
  "cmd": "ipc_doorbell",  // only for button press
  "type": "image",        // only for button press
  "with": "resources",    // only for button press
  "files": [
    ["/acc84e-53404544-pp01e25a0ef823011882/detect/1739487304.jpeg", "bb1625a850b6fe80"]
  ]
}
```

While the integration doesn't need to handle the images, include the decoded payload in the HA events for potential future use.

## Additional Considerations:
1. Reconnection with exponential backoff when connection is lost
2. Proper connection validation during setup
3. Make dps_map configurable for future compatibility with similar devices

## JavaScript Implementation Reference

### Device Handler
```javascript
const Homey = require('homey');
const TuyAPI = require('tuyapi');

class MyDevice extends Homey.Device {
  async onInit() {
    await this.initializeTuyaDevice();
    this.homey.app.log('Tuya Doorbell initialized');
  }

  async onDeleted() {
    this.tuyaDevice.disconnect();
    this.tuyaDevice = null;
  }

  async initializeTuyaDevice() {
    const settings = this.getSettings();

    this.homey.app.log("Device settings");
    this.homey.app.log(settings);

    this.tuyaDevice = new TuyAPI({
      id: settings.deviceId,
      key: settings.localKey,
      ip: settings.ipAddress,
      port: settings.port,
      version: '3.3',
      nullPayloadOnJSONError: true
    });

    // Setup device event listeners
    this.tuyaDevice
      .on('connected', () => {
        this.homey.app.log('Doorbell connected event fired');
        this.setAvailable();
      })
      .on('disconnected', () => {
        this.homey.app.log('Doorbell disconnected event fired');
        this.setUnavailable();

        // Implement reconnection strategy with exponential backoff
        let retryCount = 0;
        const maxRetries = 10;
        const baseDelay = 1000 * 10; // Start with 10 second delay

        const attemptReconnect = async () => {
          if (retryCount >= maxRetries) {
            this.homey.app.log('Max reconnection attempts reached');
            return;
          }

          const delay = baseDelay * Math.pow(2, retryCount);
          this.homey.app.log(`Attempting to reconnect in ${delay}ms (attempt ${retryCount + 1}/${maxRetries})`);

          await new Promise(resolve => setTimeout(resolve, delay));

          try {
            await this.tuyaDevice.connect();
            this.homey.app.log('Reconnection successful');
            retryCount = 0; // Reset counter on successful connection
          } catch (error) {
            this.homey.app.log('Reconnection failed:', error);
            retryCount++;
            attemptReconnect(); // Try again with increased delay
          }
        };

        attemptReconnect();
      })
      .on('error', error => {
        this.homey.app.log('Doorbell error event fired:', error);
      })
      .on('data', data => this.handleDeviceData(data))
      .on('heartbeat', () => {
        this.homey.app.log('Received doorbell heartbeat');
      })
      .on('dp-refresh', data => {
        this.homey.app.log('dp-refresh event fired', data);
      })

    this.homey.app.log('Attempting to connect to device...');
    await this.tuyaDevice.connect();

    const status = await Promise.race([
      this.tuyaDevice.get({
        schema: true
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Validation timeout')), 5000)
      )
    ]);
  }

  handleDeviceData(data) {
    this.homey.app.log('Received device data:', data);

    if (!data || !data.dps) {
      this.homey.app.log('Unexpected data or no data received');
      return;
    }

    // Handle each DPS value
    Object.entries(data.dps).forEach(([key, value]) => {
      switch (key) {
        case '115': // Motion detection
          try {
            const buffer = Buffer.from(value, 'base64');
            const responseData = JSON.parse(buffer.toString('utf-8'));
            this.homey.app.log('Motion detection event with media:', responseData);
            this.triggerFlow('motion_detected', {
              images: responseData.files.map(file => ({
                path: file[0],
                id: file[1],
                url: `https://${responseData.bucket}.oss-us-west-1.aliyuncs.com${file[0]}`
              }))
            });
            this.setCapabilityValue('alarm_motion', true)
              .then(() => this.setCapabilityValue('alarm_motion', false))
              .catch(this.error);
          } catch (error) {
            this.error('Error processing media payload:', error);
          }
          break;

        case '185': // Button pressed
          try {
            const buffer = Buffer.from(value, 'base64');
            const responseData = JSON.parse(buffer.toString('utf-8'));

            this.homey.app.log('Doorbell ring event with media:', responseData.files);
            this.triggerFlow('doorbell_pressed', {
              images: responseData.files.map(file => ({
                path: file[0],
                id: file[1],
                url: `https://${responseData.bucket}.oss-us-west-1.aliyuncs.com${file[0]}`
              }))
            });
            this.setCapabilityValue('button', true)
              .then(() => this.setCapabilityValue('button', false))
              .catch(this.error);

          } catch (error) {
            this.error('Error processing media payload:', error);
          }
          break;

        default:
          this.homey.app.log(`Unhandled DPS key ${key}:`, value);
      }
    });
  }

  triggerFlow(flowId) {
    const triggerCard = this.homey.flow.getDeviceTriggerCard(flowId);
    if (triggerCard) {
      triggerCard.trigger(this)
        .catch(error => this.homey.app.log('Flow trigger error:', error));
    } else {
      this.homey.app.log(`Trigger card ${flowId} not found`);
    }
  }

  async onSettings(oldSettings, newSettings) {
    if (newSettings.ipAddress !== oldSettings.ipAddress ||
      newSettings.port !== oldSettings.port) {
      this.initializeTuyaDevice();
    }
    return super.onSettings(oldSettings, newSettings);
  }
}

module.exports = MyDevice;
```

### Driver Implementation
```javascript
const Homey = require('homey');
const TuyAPI = require('tuyapi');
const net = require('net');
const os = require('os');

class TuyaLocalDriver extends Homey.Driver {
  async onInit() {
    this.homey.app.log('Tuya Doorbell Driver initialized');
  }

  async onPair(session) {
    let pairingDevice = {};

    session.setHandler('search_device', async (data) => {
      this.homey.app.log('Received settings:', data);

      pairingDevice = {
        name: 'Tuya Doorbell',
        data: {
          id: data.deviceId
        },
        settings: {
          deviceId: data.deviceId,
          localKey: data.localKey,
          ipAddress: data.ipAddress,
          port: data.port || 6668
        },
        icon: "/img/devices/doorbell.svg"
      };

      let ips = [];
      if (pairingDevice.settings.ipAddress != "") {
        ips = [pairingDevice.settings.ipAddress];
      } else {
        this.homey.app.log("No ipaddress received, scanning network for open port " + pairingDevice.settings.port);
        ips = await this.scanNetwork(pairingDevice.settings.port);
        this.homey.app.log("Found devices:", ips);
      }

      let deviceFound = false;
      for (const ip of ips) {
        pairingDevice.settings.ipAddress = ip;
        if (await this.validateDevice(pairingDevice)) {
          this.homey.app.log("Doorbell found");
          this.homey.app.log('get device MACaddress');
          pairingDevice.data.id = await this.homey.arp.getMAC(ip);
          deviceFound = true;
          session.showView('list_devices');
          break;
        }
      }

      if (!deviceFound) {
        session.showView('start');
        throw new Error(this.homey.__('errors.no_devices_found'));
      }
    });

    // Handle discovered devices list
    session.setHandler('list_devices', async () => {
      this.homey.app.log('List devices handler called with pairingDevice:', pairingDevice);
      if (!pairingDevice || Object.keys(pairingDevice).length === 0) {
        throw new Error(this.homey.__('errors.no_devices_found'));
      }
      return [pairingDevice];
    });

    session.setHandler('add_device', async (data) => {
      console.log("add_device, data:")
      console.log(data)

      const devices = this.getDevices();

      // Find the device by its ID
      const device = devices.find(device => device.getData().id === data.data.id);
  
      if (device) {
        this.log(`Device found: ${device.getName()}`);
        device.onInit();
      } else {
        this.log('Device not found');
      } 
    });       
  }

  async validateDevice(device) {
    try {
      this.homey.app.log('Validating device:', device);
      const testDevice = new TuyAPI({
        id: device.settings.deviceId,
        key: device.settings.localKey,
        ip: device.settings.ipAddress,
        port: device.settings.port,
        version: 3.3,
        nullPayloadOnJSONError: true
      });

      // Set up error handler
      testDevice.on('error', err => {
        this.homey.app.log('Validation device error:', err);
      });

      this.homey.app.log('Attempting to connect to device...');
      await testDevice.connect();
      this.homey.app.log('Connected successfully');

      // Try to get device info
      const status = await Promise.race([
        testDevice.get({
          schema: true
        }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Validation timeout')), 5000)
        )
      ]);
      this.homey.app.log('Got device status:', status);

      if (status && status.dps && (status.dps['101'] !== undefined || status.dps['103'] !== undefined)) {
        this.homey.app.log('Found matching doorbell device');
      } else {
        this.homey.app.log('Found a tuya device, but not a supported doorbell');
        this.homey.app.log('Validation failed');
        await testDevice.disconnect();
        return false;
      }

      await testDevice.disconnect();
      this.homey.app.log('Validation successful');
      return true;
    } catch (error) {
      this.homey.app.log('Validation failed:', error);
      return false;
    }
  }

  async scanNetwork(port) {
    const foundIPs = [];
    const BATCH_SIZE = 25;
    let scannedCount = 0;

    // Get all network interfaces
    const interfaces = os.networkInterfaces();
    const networks = [];

    // Find all IPv4 interfaces that aren't internal
    Object.values(interfaces).forEach(iface => {
      iface.forEach(addr => {
        if (addr.family === 'IPv4' && !addr.internal) {
          const baseAddr = addr.address.split('.').slice(0, 3).join('.');
          networks.push(baseAddr);
        }
      });
    });

    if (networks.length === 0) {
      this.homey.app.log("No valid network interfaces found");
      return foundIPs;
    }

    // Scan each network
    for (const baseAddr of networks) {
      this.homey.app.log("Starting port scan on network:", baseAddr);

      // Scan in batches to avoid overwhelming the network
      for (let start = 1; start < 255; start += BATCH_SIZE) {
        const end = Math.min(start + BATCH_SIZE, 255);
        const batchPromises = [];

        for (let i = start; i < end; i++) {
          const ip = `${baseAddr}.${i}`;
          batchPromises.push(
            new Promise((resolve) => {
              const socket = new net.Socket();
              socket.setTimeout(1000);

              socket.on('connect', () => {
                this.homey.app.log(`Found device at ${ip}`);
                foundIPs.push(ip);
                socket.destroy();
                resolve();
              });

              socket.on('error', () => {
                socket.destroy();
                resolve();
              });

              socket.on('timeout', () => {
                socket.destroy();
                resolve();
              });

              socket.connect(port, ip);
            })
          );
        }

        await Promise.all(batchPromises);
        scannedCount += BATCH_SIZE;
        this.homey.app.log(`Scanned ${scannedCount}/254 addresses...`);
      }
    }
    this.homey.app.log(`Found ${foundIPs.length} devices listening on port ${port}`);
    return foundIPs;
  }
}

module.exports = TuyaLocalDriver;
```

Make sure to adapt these JavaScript implementations to proper Home Assistant integration patterns using Python, following HA best practices.