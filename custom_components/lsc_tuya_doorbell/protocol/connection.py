"""Async TCP connection manager for Tuya devices."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from .constants import Command, ProtocolVersion
from .encryption import TuyaCipher
from .messages import MessageCodec, TuyaMessage

_LOGGER = logging.getLogger(__name__)

# Timeouts
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
RESPONSE_TIMEOUT = 5.0


class TuyaConnection:
    """Manages an async TCP connection to a Tuya device."""

    def __init__(
        self,
        host: str,
        port: int,
        device_id: str,
        local_key: str,
        version: str,
    ) -> None:
        self._host = host
        self._port = port
        self._device_id = device_id
        self._local_key = local_key
        self._local_key_bytes = local_key.encode("ascii") if isinstance(local_key, str) else local_key
        self._version = version
        self._codec = MessageCodec(version, self._local_key_bytes)
        self._cipher = TuyaCipher(self._local_key_bytes)

        # Device22 detection: 22-char device IDs use CONTROL_NEW for queries
        self._is_device22 = len(device_id) == 22

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._write_lock = asyncio.Lock()

        # Response correlation: seqno -> Future
        self._pending_responses: dict[int, asyncio.Future[TuyaMessage]] = {}

        # Callbacks
        self._on_status_update: list[Callable[[dict], None]] = []
        self._on_disconnect: list[Callable[[], None]] = []

        # Read loop task
        self._read_task: asyncio.Task | None = None

        # Last heartbeat time
        self._last_heartbeat: float = 0

    @property
    def host(self) -> str:
        return self._host

    @host.setter
    def host(self, value: str) -> None:
        self._host = value

    @property
    def port(self) -> int:
        return self._port

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def version(self) -> str:
        return self._version

    def on_status_update(self, callback: Callable[[dict], None]) -> Callable[[], None]:
        """Register a callback for status updates. Returns unregister function."""
        self._on_status_update.append(callback)
        return lambda: self._on_status_update.remove(callback)

    def on_disconnect(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a callback for disconnect events. Returns unregister function."""
        self._on_disconnect.append(callback)
        return lambda: self._on_disconnect.remove(callback)

    async def connect(self) -> None:
        """Establish TCP connection and perform session negotiation if needed."""
        _LOGGER.debug("Connecting to %s:%s", self._host, self._port)

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=CONNECT_TIMEOUT,
            )
        except (asyncio.TimeoutError, OSError) as err:
            raise ConnectionError(f"Failed to connect to {self._host}:{self._port}: {err}") from err

        self._connected = True
        self._codec.reset_buffer()
        self._codec.session_key = None

        # Session key negotiation for v3.4 and v3.5
        if self._version in (ProtocolVersion.V34, ProtocolVersion.V35):
            await self._negotiate_session_key()

        # Start background read loop
        self._read_task = asyncio.ensure_future(self._read_loop())

        _LOGGER.info("Connected to %s:%s (protocol %s)", self._host, self._port, self._version)

    async def disconnect(self) -> None:
        """Gracefully close the connection."""
        self._connected = False

        # Cancel read loop
        if self._read_task and not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass
            self._read_task = None

        # Close TCP connection
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

        # Cancel pending responses
        for fut in self._pending_responses.values():
            if not fut.done():
                fut.cancel()
        self._pending_responses.clear()

        _LOGGER.debug("Disconnected from %s:%s", self._host, self._port)

    async def send(self, command: int, payload: dict | str | bytes | None = None) -> int:
        """Send a command to the device. Returns the sequence number."""
        if not self._connected or not self._writer:
            raise ConnectionError("Not connected")

        async with self._write_lock:
            seqno = self._codec.next_seqno()
            packet = self._codec.encode(command, payload, seqno=seqno)

            try:
                self._writer.write(packet)
                await self._writer.drain()
            except (OSError, ConnectionError) as err:
                self._connected = False
                raise ConnectionError(f"Send failed: {err}") from err

        return seqno

    async def send_and_wait(
        self,
        command: int,
        payload: dict | str | bytes | None = None,
        timeout: float = RESPONSE_TIMEOUT,
    ) -> TuyaMessage:
        """Send a command and wait for the response.

        Matches response by sequence number first, falls back to command type
        (many devices return seqno=0 regardless of the request seqno).
        """
        loop = asyncio.get_event_loop()
        future: asyncio.Future[TuyaMessage] = loop.create_future()

        seqno = await self.send(command, payload)
        self._pending_responses[seqno] = future

        # Also register by command type for devices that don't echo seqno
        cmd_key = f"cmd_{command}"
        self._pending_responses[cmd_key] = future

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"No response for command {command} (seq {seqno})")
        finally:
            self._pending_responses.pop(seqno, None)
            self._pending_responses.pop(cmd_key, None)

    async def heartbeat(self) -> bool:
        """Send a heartbeat and wait for response. Returns True if successful."""
        try:
            msg = await self.send_and_wait(Command.HEARTBEAT, timeout=RESPONSE_TIMEOUT)
            self._last_heartbeat = time.monotonic()
            return msg.command == Command.HEARTBEAT
        except (TimeoutError, ConnectionError):
            return False

    async def query_dps(self, dp_ids: list[int] | None = None) -> dict:
        """Query datapoint values from the device.

        device22 (22-char IDs) use CONTROL_NEW instead of DP_QUERY and require
        a dps dict in the payload with the requested DP IDs set to None.
        The device22 responds with an empty ack, then sends DPS data as
        STATUS (cmd 8) pushes.
        """
        if self._is_device22:
            payload: dict[str, Any] = {
                "devId": self._device_id,
                "uid": self._device_id,
                "t": str(int(time.time())),
                "dps": {str(dp): None for dp in (dp_ids or [1])},
            }
            cmd = Command.CONTROL_NEW
        else:
            payload = {
                "gwId": self._device_id,
                "devId": self._device_id,
                "uid": self._device_id,
                "t": str(int(time.time())),
            }
            if dp_ids:
                payload["dps"] = {str(dp): None for dp in dp_ids}
            cmd = Command.DP_QUERY

        try:
            if self._is_device22:
                # device22: send CONTROL_NEW, then wait for STATUS push with DPS.
                # The device sends an empty ack first, then a separate STATUS push.
                # Retry if no STATUS push arrives (device can be intermittent).
                for attempt in range(3):
                    loop = asyncio.get_event_loop()
                    status_future: asyncio.Future[TuyaMessage] = loop.create_future()
                    status_key = f"cmd_{Command.STATUS}"
                    self._pending_responses[status_key] = status_future
                    if attempt == 0:
                        await self.send(cmd, payload)
                    try:
                        msg = await asyncio.wait_for(
                            status_future, timeout=RESPONSE_TIMEOUT + attempt * 2,
                        )
                        return msg.data.get("dps", {})
                    except asyncio.TimeoutError:
                        _LOGGER.debug(
                            "No STATUS response for device22 query (attempt %d/3)",
                            attempt + 1,
                        )
                    finally:
                        self._pending_responses.pop(status_key, None)
                    if not self._connected:
                        break
                return {}
            else:
                msg = await self.send_and_wait(cmd, payload)
                return msg.data.get("dps", {})
        except (TimeoutError, ConnectionError) as err:
            _LOGGER.debug("DP query failed: %s", err)
            return {}

    async def set_dps(self, dps: dict[str, Any]) -> dict | None:
        """Set datapoint values on the device."""
        if self._is_device22:
            payload: dict[str, Any] = {
                "devId": self._device_id,
                "uid": self._device_id,
                "t": str(int(time.time())),
                "dps": dps,
            }
            cmd = Command.CONTROL_NEW
        else:
            payload = {
                "gwId": self._device_id,
                "devId": self._device_id,
                "uid": self._device_id,
                "t": str(int(time.time())),
                "dps": dps,
            }
            cmd = Command.CONTROL

        try:
            msg = await self.send_and_wait(cmd, payload)
            return msg.data.get("dps")
        except (TimeoutError, ConnectionError) as err:
            _LOGGER.debug("Set DPS failed: %s", err)
            return None

    async def update_dps(self, dp_ids: list[int]) -> dict:
        """Request a DPS refresh for specific datapoints.

        For device22, we use CONTROL_NEW with dps:{id:null} since these
        devices respond to that format. For standard devices, use UPDATEDPS
        with dpId list.
        """
        if self._is_device22:
            return await self.query_dps(dp_ids)

        payload: dict[str, Any] = {
            "dpId": dp_ids,
        }

        try:
            msg = await self.send_and_wait(Command.UPDATEDPS, payload, timeout=RESPONSE_TIMEOUT)
            return msg.data.get("dps", {})
        except (TimeoutError, ConnectionError) as err:
            _LOGGER.debug("Update DPS failed: %s", err)
            return {}

    async def _negotiate_session_key(self) -> None:
        """Perform session key negotiation for v3.4/v3.5."""
        _LOGGER.debug("Starting session key negotiation (protocol %s)", self._version)

        client_nonce = TuyaCipher.generate_nonce()

        # Step 1: Send client nonce
        async with self._write_lock:
            seqno = self._codec.next_seqno()
            packet = self._codec.encode(Command.SESS_KEY_NEG_START, client_nonce, seqno=seqno)
            self._writer.write(packet)
            await self._writer.drain()

        # Step 2: Read device nonce response
        try:
            raw = await asyncio.wait_for(self._reader.read(4096), timeout=RESPONSE_TIMEOUT)
        except asyncio.TimeoutError:
            raise ConnectionError("Session key negotiation timeout")

        if not raw:
            raise ConnectionError("Connection closed during session negotiation")

        messages = self._codec.feed(raw)
        if not messages:
            raise ConnectionError("No valid message in session key response")

        device_msg = messages[0]
        device_nonce = device_msg.payload

        if not device_nonce or len(device_nonce) < 16:
            raise ConnectionError(f"Invalid device nonce (length {len(device_nonce) if device_nonce else 0})")

        device_nonce = device_nonce[:16]

        # Derive session key
        if self._version == ProtocolVersion.V35:
            session_key = self._cipher.derive_session_key_v35(client_nonce, device_nonce)
        else:
            session_key = self._cipher.derive_session_key_v34(client_nonce, device_nonce)

        self._codec.session_key = session_key

        # Step 3: Send HMAC of device nonce to confirm
        hmac_val = TuyaCipher.calc_hmac(session_key, device_nonce)

        async with self._write_lock:
            seqno = self._codec.next_seqno()
            packet = self._codec.encode(Command.SESS_KEY_NEG_FINISH, hmac_val, seqno=seqno)
            self._writer.write(packet)
            await self._writer.drain()

        # Read confirmation (optional — some devices don't respond)
        try:
            raw = await asyncio.wait_for(self._reader.read(4096), timeout=2.0)
            if raw:
                self._codec.feed(raw)  # Process but don't require specific response
        except asyncio.TimeoutError:
            pass

        _LOGGER.debug("Session key negotiation complete")

    async def _read_loop(self) -> None:
        """Background task that continuously reads from the socket."""
        try:
            while self._connected and self._reader:
                try:
                    data = await asyncio.wait_for(self._reader.read(4096), timeout=READ_TIMEOUT)
                except asyncio.TimeoutError:
                    continue

                if not data:
                    _LOGGER.debug("Connection closed by device")
                    break

                messages = self._codec.feed(data)
                for msg in messages:
                    self._dispatch_message(msg)

        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.debug("Read loop error", exc_info=True)

        # Connection lost
        if self._connected:
            self._connected = False
            for callback in self._on_disconnect:
                try:
                    callback()
                except Exception:
                    _LOGGER.debug("Disconnect callback error", exc_info=True)

    def _dispatch_message(self, msg: TuyaMessage) -> None:
        """Route a received message to the appropriate handler."""
        # Check if this is a response to a pending request (by seqno)
        if msg.seqno in self._pending_responses:
            fut = self._pending_responses.pop(msg.seqno)
            # Also clean up the command-based key
            cmd_key = f"cmd_{msg.command}"
            self._pending_responses.pop(cmd_key, None)
            if not fut.done():
                fut.set_result(msg)
            return

        # Check by command type (fallback for devices that return seqno=0)
        cmd_key = f"cmd_{msg.command}"
        if cmd_key in self._pending_responses:
            fut = self._pending_responses.pop(cmd_key)
            if not fut.done():
                fut.set_result(msg)
            return

        # Handle push updates (STATUS messages from device)
        if msg.command in (Command.STATUS, Command.CONTROL, Command.CONTROL_NEW, Command.UPDATEDPS, Command.DP_QUERY):
            dps = msg.data.get("dps", {})
            if dps:
                for callback in self._on_status_update:
                    try:
                        callback(dps)
                    except Exception:
                        _LOGGER.debug("Status update callback error", exc_info=True)

        # Heartbeat responses without a pending future (device-initiated)
        elif msg.command == Command.HEARTBEAT:
            self._last_heartbeat = time.monotonic()
