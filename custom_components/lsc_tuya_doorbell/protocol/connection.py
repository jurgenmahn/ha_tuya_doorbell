"""Async TCP connection manager for Tuya devices."""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .constants import (
    Command,
    InvalidLocalKeyError,
    ProtocolVersion,
    TuyaProtocolError,
)
from .encryption import TuyaCipher
from .messages import MessageCodec, TuyaMessage

_LOGGER = logging.getLogger(__name__)

# Timeouts
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
RESPONSE_TIMEOUT = 5.0

# The read loop declares the link dead when nothing at all arrives for this
# long. The hub heartbeats every 10 s, so this only trips on a link that is
# silently gone (NAT timeout, device reboot) rather than merely idle.
IDLE_TIMEOUT = 90.0

# Length of a v3.4/v3.5 SESS_KEY_NEG_RESP body: remote nonce + HMAC-SHA256.
_NONCE_SIZE = 16
_NEG_RESP_SIZE = _NONCE_SIZE + 32


@dataclass
class _PendingRequest:
    """A request waiting for its reply.

    `command` is kept so a device that answers with seqno 0 — many do — can
    still be matched. Requests are held in a FIFO list rather than a dict keyed
    by command, so two concurrent requests for the same command cannot
    overwrite each other's slot.
    """

    seqno: int
    command: int
    future: asyncio.Future[TuyaMessage]
    match_commands: tuple[int, ...] = field(default_factory=tuple)

    def accepts(self, msg: TuyaMessage) -> bool:
        """Return True if msg may be treated as this request's reply."""
        return msg.command in self.match_commands


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
        self._version = ProtocolVersion.parse(version)
        self._codec = MessageCodec(version, self._local_key_bytes)
        self._cipher = TuyaCipher(self._local_key_bytes)

        # Device22 detection: 22-char device IDs use CONTROL_NEW for queries
        self._is_device22 = len(device_id) == 22

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._write_lock = asyncio.Lock()

        # Response correlation: seqno -> Future, plus a FIFO of the same
        # requests for the seqno-0 fallback.
        self._pending_responses: dict[int, asyncio.Future[TuyaMessage]] = {}
        self._pending_requests: list[_PendingRequest] = []

        # Callbacks
        self._on_status_update: list[Callable[[dict], None]] = []
        self._on_disconnect: list[Callable[[], None]] = []

        # Read loop task
        self._read_task: asyncio.Task | None = None

        # Monotonic timestamp of the last byte received, used by the idle
        # watchdog in the read loop.
        self._last_activity: float = 0.0

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
        return str(self._version)

    @property
    def seconds_since_last_message(self) -> float:
        """Seconds since the device last sent anything, for diagnostics."""
        if not self._last_activity:
            return 0.0
        return time.monotonic() - self._last_activity

    def on_status_update(self, callback: Callable[[dict], None]) -> Callable[[], None]:
        """Register a callback for status updates. Returns unregister function."""
        self._on_status_update.append(callback)
        return lambda: self._on_status_update.remove(callback)

    def on_disconnect(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a callback for disconnect events. Returns unregister function."""
        self._on_disconnect.append(callback)
        return lambda: self._on_disconnect.remove(callback)

    async def connect(self) -> None:
        """Establish TCP connection and perform session negotiation if needed.

        `is_connected` only becomes True once the device is actually usable: a
        failed session negotiation closes the socket and raises, rather than
        leaving a half-open connection that reports itself as healthy.
        """
        _LOGGER.debug("Connecting to %s:%s", self._host, self._port)

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=CONNECT_TIMEOUT,
            )
        except (asyncio.TimeoutError, OSError) as err:
            raise ConnectionError(f"Failed to connect to {self._host}:{self._port}: {err}") from err

        self._codec.reset_buffer()
        self._codec.session_key = None
        self._last_activity = time.monotonic()

        if self._version in (ProtocolVersion.V34, ProtocolVersion.V35):
            try:
                await self._negotiate_session_key()
            except BaseException:
                await self._close_socket()
                raise

        self._connected = True
        self._read_task = asyncio.get_running_loop().create_task(self._read_loop())

        _LOGGER.info("Connected to %s:%s (protocol %s)", self._host, self._port, self._version)

    async def disconnect(self) -> None:
        """Close the connection because we asked for it.

        Silent by design: unloading the integration must not trigger the
        reconnect logic. Use force_disconnect() when the link is considered
        dead and listeners have to hear about it.
        """
        await self._shutdown(notify=False)

    async def force_disconnect(self, reason: str) -> None:
        """Drop a connection that is no longer usable and notify listeners.

        This is what a heartbeat watchdog needs: the socket goes away *and* the
        registered disconnect callbacks fire, so a reconnect is scheduled.
        """
        if self._connected:
            _LOGGER.warning(
                "Dropping the connection to %s (%s:%s): %s. A reconnect will be "
                "attempted; if it keeps failing, check that the device is powered "
                "on and reachable on the network.",
                self._device_id, self._host, self._port, reason,
            )
        await self._shutdown(notify=True)

    async def _shutdown(self, *, notify: bool) -> None:
        """Tear the connection down, optionally firing the disconnect callbacks."""
        _LOGGER.debug(
            "Disconnecting from %s:%s (notify=%s)", self._host, self._port, notify
        )
        was_connected = self._connected
        self._connected = False

        if self._read_task is asyncio.current_task():
            # Called from inside the read loop's own callback chain; cancelling
            # ourselves here would deadlock on the await below.
            self._read_task = None
        elif self._read_task and not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                # Our own cancellation, not an outer one: the task is gone.
                pass
        self._read_task = None

        await self._close_socket()
        self._fail_pending("Connection closed")

        if notify and was_connected:
            self._notify_disconnect()

        _LOGGER.debug("Disconnected from %s:%s", self._host, self._port)

    async def _close_socket(self) -> None:
        """Close the stream writer, tolerating a socket that is already gone."""
        writer, self._writer = self._writer, None
        self._reader = None
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, ConnectionError) as err:
            _LOGGER.debug("Ignoring error while closing the socket: %s", err)

    def _fail_pending(self, reason: str) -> None:
        """Resolve every waiting request with a ConnectionError.

        Failing rather than cancelling keeps CancelledError meaning exactly one
        thing — *we* were cancelled — so callers can re-raise it safely.
        """
        pending = list(self._pending_requests)
        self._pending_requests.clear()
        self._pending_responses.clear()
        for req in pending:
            if not req.future.done():
                req.future.set_exception(ConnectionError(reason))

    def _notify_disconnect(self) -> None:
        """Run the registered disconnect callbacks."""
        for callback in list(self._on_disconnect):
            try:
                callback()
            except Exception:
                _LOGGER.warning(
                    "A disconnect callback raised; the remaining callbacks still run",
                    exc_info=True,
                )

    async def send(self, command: int, payload: dict | str | bytes | None = None) -> int:
        """Send a command to the device. Returns the sequence number."""
        if not self._connected:
            raise ConnectionError("Not connected")

        async with self._write_lock:
            # Re-read the writer inside the lock: disconnect() may have run
            # while we were waiting for it.
            writer = self._writer
            if not self._connected or writer is None:
                raise ConnectionError("Not connected")

            seqno = self._codec.next_seqno()
            packet = self._codec.encode(command, payload, seqno=seqno)

            _LOGGER.debug(
                "Send: cmd=%d seqno=%d (%d bytes) to %s:%s",
                command, seqno, len(packet), self._host, self._port,
            )
            try:
                writer.write(packet)
                await writer.drain()
            except (OSError, ConnectionError) as err:
                _LOGGER.debug("Send failed: %s", err)
                self._connected = False
                raise ConnectionError(f"Send failed: {err}") from err

        return seqno

    def _register_request(
        self, command: int, seqno: int, match_commands: tuple[int, ...]
    ) -> _PendingRequest:
        """Create and register a pending request for the given seqno."""
        future: asyncio.Future[TuyaMessage] = asyncio.get_running_loop().create_future()
        req = _PendingRequest(
            seqno=seqno, command=command, future=future, match_commands=match_commands
        )
        self._pending_requests.append(req)
        if seqno:
            self._pending_responses[seqno] = future
        return req

    def _unregister_request(self, req: _PendingRequest) -> None:
        """Remove a pending request, whether it completed, timed out or failed."""
        if req in self._pending_requests:
            self._pending_requests.remove(req)
        if self._pending_responses.get(req.seqno) is req.future:
            del self._pending_responses[req.seqno]
        if req.future.done() and not req.future.cancelled():
            # Consume any exception we set ourselves, so asyncio does not log it
            # as "never retrieved" when the waiter timed out at the same moment.
            req.future.exception()

    async def send_and_wait(
        self,
        command: int,
        payload: dict | str | bytes | None = None,
        timeout: float = RESPONSE_TIMEOUT,
    ) -> TuyaMessage:
        """Send a command and wait for the response.

        Matches the response by sequence number first, and falls back to the
        command type for devices that answer with seqno 0.
        """
        seqno = await self.send(command, payload)
        req = self._register_request(command, seqno, (command,))

        _LOGGER.debug(
            "SendAndWait: waiting for response cmd=%d seqno=%d timeout=%.1fs",
            command, seqno, timeout,
        )
        try:
            msg = await asyncio.wait_for(req.future, timeout=timeout)
            _LOGGER.debug(
                "SendAndWait: got response cmd=%d seqno=%d retcode=%s",
                msg.command, msg.seqno, msg.retcode,
            )
            return msg
        except asyncio.TimeoutError:
            _LOGGER.debug("SendAndWait: timeout for cmd=%d seqno=%d", command, seqno)
            raise TimeoutError(f"No response for command {command} (seq {seqno})") from None
        finally:
            self._unregister_request(req)

    async def heartbeat(self) -> bool:
        """Send a heartbeat and wait for response. Returns True if successful."""
        _LOGGER.debug("Heartbeat: sending to %s:%s", self._host, self._port)
        try:
            msg = await self.send_and_wait(Command.HEARTBEAT, timeout=RESPONSE_TIMEOUT)
            ok = msg.command == Command.HEARTBEAT
            if not ok:
                _LOGGER.debug("Heartbeat: unexpected response cmd=%d", msg.command)
            return ok
        except (TimeoutError, ConnectionError) as err:
            _LOGGER.debug("Heartbeat: failed — %s", err)
            return False

    async def query_dps(
        self, dp_ids: list[int] | None = None, max_retries: int = 1,
    ) -> dict:
        """Query datapoint values from the device.

        device22 (22-char IDs) use CONTROL_NEW instead of DP_QUERY and require
        a dps dict in the payload with the requested DP IDs set to None.
        The device22 responds with an empty ack, then sends DPS data as
        STATUS (cmd 8) pushes.

        Args:
            dp_ids: List of DP IDs to query. None queries all.
            max_retries: Number of attempts for device22 STATUS wait.
                Use 1 during DP scanning to avoid overloading the device.
        """
        if self._is_device22:
            payload: dict[str, Any] = {
                "devId": self._device_id,
                "uid": self._device_id,
                "t": str(int(time.time())),
                "dps": {str(dp): None for dp in (dp_ids or [1])},
            }
            cmd = Command.CONTROL_NEW
            _LOGGER.debug("QueryDPS: device22 mode, using CONTROL_NEW, dps=%s", list(payload["dps"].keys()))
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
            _LOGGER.debug("QueryDPS: standard mode, using DP_QUERY, dp_ids=%s", dp_ids)

        try:
            if self._is_device22:
                return await self._query_dps_device22(cmd, payload, max_retries)
            msg = await self.send_and_wait(cmd, payload)
            return msg.data.get("dps", {})
        except (TimeoutError, ConnectionError) as err:
            _LOGGER.debug("DP query failed: %s", err)
            return {}

    async def _query_dps_device22(
        self, cmd: int, payload: dict[str, Any], max_retries: int
    ) -> dict:
        """Send CONTROL_NEW and wait for the STATUS push that carries the DPS.

        The device acks empty first and only then pushes STATUS, so this waits
        on the push rather than on the ack.
        """
        for attempt in range(max_retries):
            req = self._register_request(cmd, 0, (Command.STATUS,))
            try:
                if attempt == 0:
                    await self.send(cmd, payload)
                msg = await asyncio.wait_for(
                    req.future, timeout=RESPONSE_TIMEOUT + attempt * 2,
                )
                return msg.data.get("dps", {})
            except asyncio.TimeoutError:
                _LOGGER.debug(
                    "No STATUS response for device22 query (attempt %d/%d)",
                    attempt + 1, max_retries,
                )
            finally:
                self._unregister_request(req)

            if not self._connected:
                break
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

    async def update_dps(self, dp_ids: list[int], max_retries: int = 1) -> dict:
        """Request a DPS refresh for specific datapoints.

        For device22, we use CONTROL_NEW with dps:{id:null} since these
        devices respond to that format. For standard devices, use UPDATEDPS
        with dpId list.
        """
        if self._is_device22:
            return await self.query_dps(dp_ids, max_retries=max_retries)

        payload: dict[str, Any] = {"dpId": dp_ids}

        try:
            msg = await self.send_and_wait(Command.UPDATEDPS, payload, timeout=RESPONSE_TIMEOUT)
            return msg.data.get("dps", {})
        except (TimeoutError, ConnectionError) as err:
            _LOGGER.debug("Update DPS failed: %s", err)
            return {}

    # --- Session key negotiation -----------------------------------------

    async def _negotiate_session_key(self) -> None:
        """Perform session key negotiation for v3.4/v3.5.

        The device's reply carries HMAC-SHA256(local_key, client_nonce). We
        verify it, so a successful connect really does prove the local key is
        correct — callers elsewhere rely on that.
        """
        _LOGGER.debug("Starting session key negotiation (protocol %s)", self._version)

        client_nonce = TuyaCipher.generate_nonce()

        await self._write_raw(Command.SESS_KEY_NEG_START, client_nonce)
        device_msg = await self._read_negotiation_response()

        if device_msg.command != Command.SESS_KEY_NEG_RESP:
            raise ConnectionError(
                f"Device {self._device_id} answered the session key request with "
                f"command {device_msg.command} instead of "
                f"{int(Command.SESS_KEY_NEG_RESP)}; it is probably not speaking "
                f"protocol {self._version}"
            )

        body = device_msg.payload
        if len(body) < _NEG_RESP_SIZE:
            raise InvalidLocalKeyError(
                f"Session key negotiation with {self._device_id} returned "
                f"{len(body)} bytes instead of {_NEG_RESP_SIZE}. This usually means "
                f"the local key is wrong; re-copy it from the Tuya developer portal."
            )

        device_nonce = body[:_NONCE_SIZE]
        expected_hmac = TuyaCipher.calc_hmac(self._local_key_bytes, client_nonce)
        if not hmac.compare_digest(expected_hmac, body[_NONCE_SIZE:_NEG_RESP_SIZE]):
            raise InvalidLocalKeyError(
                f"Device {self._device_id} at {self._host} failed the session key "
                f"check. The local key configured for this device is wrong — copy it "
                f"again from the Tuya developer portal (or the Smart Life app export) "
                f"and update it in the integration options."
            )

        if self._version == ProtocolVersion.V35:
            session_key = self._cipher.derive_session_key_v35(client_nonce, device_nonce)
        else:
            session_key = self._cipher.derive_session_key_v34(client_nonce, device_nonce)

        self._codec.session_key = session_key

        # The device does not answer this; the read loop picks up whatever it
        # sends next. Reading here would swallow the first status push.
        confirm_hmac = TuyaCipher.calc_hmac(session_key, device_nonce)
        await self._write_raw(Command.SESS_KEY_NEG_FINISH, confirm_hmac)

        _LOGGER.debug("Session key negotiation complete for %s", self._device_id)

    async def _write_raw(self, command: int, payload: bytes) -> None:
        """Write a packet before the connection is marked usable."""
        writer = self._writer
        if writer is None:
            raise ConnectionError("Socket closed during session key negotiation")
        async with self._write_lock:
            packet = self._codec.encode(command, payload, seqno=self._codec.next_seqno())
            writer.write(packet)
            await writer.drain()

    async def _read_negotiation_response(self) -> TuyaMessage:
        """Read until the device's session key response is complete."""
        if self._reader is None:
            raise ConnectionError("Socket closed during session key negotiation")

        deadline = time.monotonic() + RESPONSE_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectionError(
                    f"Session key negotiation with {self._device_id} at {self._host} "
                    f"timed out; the device did not answer within "
                    f"{RESPONSE_TIMEOUT:.0f}s"
                )
            try:
                raw = await asyncio.wait_for(self._reader.read(4096), timeout=remaining)
            except asyncio.TimeoutError:
                continue

            if not raw:
                raise ConnectionError(
                    f"Device {self._device_id} closed the connection during session "
                    f"key negotiation"
                )

            try:
                messages = self._codec.feed(raw)
            except TuyaProtocolError as err:
                raise InvalidLocalKeyError(
                    f"Could not read the session key response from {self._device_id} "
                    f"({err}). Check the local key and the protocol version."
                ) from err

            if messages:
                return messages[0]

            if not self._codec.buffered_bytes:
                # feed() consumed everything and produced nothing: the frame was
                # dropped because it did not decode.
                raise InvalidLocalKeyError(
                    f"The session key response from {self._device_id} at "
                    f"{self._host} could not be decoded. This usually means the "
                    f"local key is wrong, or the device does not speak protocol "
                    f"{self._version}."
                )

    # --- Read loop --------------------------------------------------------

    async def _read_loop(self) -> None:
        """Background task that continuously reads from the socket."""
        reason = "the device closed the connection"
        try:
            while self._connected and self._reader:
                try:
                    data = await asyncio.wait_for(self._reader.read(4096), timeout=READ_TIMEOUT)
                except asyncio.TimeoutError:
                    if self.seconds_since_last_message > IDLE_TIMEOUT:
                        reason = (
                            f"no data received for {self.seconds_since_last_message:.0f}s"
                        )
                        break
                    continue

                if not data:
                    _LOGGER.debug("ReadLoop: connection closed by device (empty read)")
                    break

                self._last_activity = time.monotonic()
                _LOGGER.debug("ReadLoop: received %d bytes from %s:%s", len(data), self._host, self._port)
                for msg in self._codec.feed(data):
                    self._dispatch_message(msg)

        except asyncio.CancelledError:
            # A requested disconnect: _shutdown() decides who gets told.
            raise
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as err:
            reason = f"the socket failed ({err})"
        except Exception as err:  # noqa: BLE001 - last line of defence for the read task
            reason = f"an unexpected protocol error occurred ({err})"
            _LOGGER.exception("Read loop for %s failed unexpectedly", self._device_id)

        if self._connected:
            self._connected = False
            _LOGGER.warning(
                "Lost the connection to %s (%s:%s): %s. Reconnecting; if this "
                "repeats, check the device's network connection.",
                self._device_id, self._host, self._port, reason,
            )
            self._fail_pending(f"Connection lost: {reason}")
            self._notify_disconnect()

    def _dispatch_message(self, msg: TuyaMessage) -> None:
        """Route a received message to the appropriate handler."""
        _LOGGER.debug(
            "Dispatch: seqno=%d cmd=%d retcode=%s payload=%d bytes pending=%d",
            msg.seqno, msg.command, msg.retcode, len(msg.payload),
            len(self._pending_requests),
        )

        if self._resolve_pending(msg):
            return

        if msg.command in (
            Command.STATUS, Command.CONTROL, Command.CONTROL_NEW,
            Command.UPDATEDPS, Command.DP_QUERY,
        ):
            dps = msg.data.get("dps", {})
            if dps:
                _LOGGER.debug("Dispatch: push update with DPS=%s", dps)
                for callback in list(self._on_status_update):
                    try:
                        callback(dps)
                    except Exception:
                        _LOGGER.warning(
                            "A status update callback raised; the remaining callbacks "
                            "still run",
                            exc_info=True,
                        )
            else:
                _LOGGER.debug("Dispatch: push cmd=%d with empty DPS (ack)", msg.command)

        elif msg.command == Command.HEARTBEAT:
            _LOGGER.debug("Dispatch: device-initiated heartbeat response")
        else:
            _LOGGER.debug("Dispatch: unhandled cmd=%d (no pending, not a push)", msg.command)

    def _resolve_pending(self, msg: TuyaMessage) -> bool:
        """Hand the message to a waiting request. Returns True if it was consumed."""
        future = self._pending_responses.pop(msg.seqno, None) if msg.seqno else None
        if future is not None:
            _LOGGER.debug("Dispatch: matched by seqno=%d", msg.seqno)
            for req in list(self._pending_requests):
                if req.future is future:
                    self._pending_requests.remove(req)
                    break
            if not future.done():
                future.set_result(msg)
            return True

        # Fallback for devices that answer with seqno 0: give the message to
        # the oldest request that asked for this command, and only that one.
        for req in self._pending_requests:
            if req.accepts(msg):
                _LOGGER.debug(
                    "Dispatch: matched cmd=%d to the request sent as seqno=%d",
                    msg.command, req.seqno,
                )
                self._unregister_request(req)
                if not req.future.done():
                    req.future.set_result(msg)
                return True

        return False
