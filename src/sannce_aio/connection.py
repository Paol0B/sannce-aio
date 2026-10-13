import asyncio
import logging
from collections.abc import Callable

from .audio import G711A, SUBFRAME_PCM_BYTES, frame_talk_audio
from .errors import AuthError, ConnectError, ProtocolError, TalkBusyError
from .events import Event, parse_event
from .login import LoginStep
from .protocol import Frame, build_command, parse_frame

_log = logging.getLogger(__name__)

_READ_SIZE = 0x10000
_MAX_BUFFER = 0x10000
_SEQ_WRAP = 0x10000
_SESSION_ID_WRAP = 999
_FINISHED = "FINISHED"
# camera messages lead with device ip and route (protocol.md, Field lists)
_ALARM_HEAD = ["INNER", "ALARM"]
_TALK_HEAD = ["INNER", "NVR"]
# indexes of BEGIN/END and OK/ERROR: 6 and 7 from INNER, plus the ip and route
# (protocol.md, Request, accept and refuse)
_TALK_ACTION = 8
_TALK_RESULT = 9
_TALK_ROUTE = "NVR"
_BEGIN = "BEGIN"
_END = "END"
_OK = "OK"
# audio.frame_talk_audio only builds channel 0 payloads
_TALK_CHANNEL = 0
_TALK_CODEC = G711A
_DATA_SEQ_WRAP = 0x100000000


class NvsConnection:
    def __init__(
        self,
        host: str,
        port: int,
        login: LoginStep,
        *,
        on_event: Callable[[Event], None],
        on_availability: Callable[[bool], None],
        request_timeout: float = 10.0,
        heartbeat_interval: float = 3.0,
        login_timeout: float = 10.0,
        backoff_start: float = 1.0,
        backoff_max: float = 60.0,
        auth_failure_limit: int = 3,
    ) -> None:
        self._host = host
        self._port = port
        self._login = login
        self._on_event = on_event
        self._on_availability = on_availability
        self._request_timeout = request_timeout
        self._heartbeat_interval = heartbeat_interval
        self._login_timeout = login_timeout
        self._backoff_start = backoff_start
        self._backoff_max = backoff_max
        self._auth_failure_limit = auth_failure_limit
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._rx_buffer = bytearray()
        self._pending: dict[int, asyncio.Future[list[str]]] = {}
        self._talk_pending: dict[str, asyncio.Future[list[str]]] = {}
        self._talk_lock = asyncio.Lock()
        self._talking = False
        self._seq = 0
        self._audio_seq = 0
        self._session_id = 1
        self._available = False
        self._closing = False
        self._username = ""
        self._password = ""
        self._run_task: asyncio.Task[None] | None = None
        self.device: dict[str, str] = {}

    async def connect(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._closing = False
        try:
            await self._connect_once()
        except BaseException:
            await self._close_transport()
            raise
        self._set_available(True)
        self._run_task = asyncio.create_task(self._run())

    async def request(self, fields: list[str], *, timeout: float | None = None) -> list[str]:
        session_id = self._next_session_id()
        message = [*fields, str(session_id)]
        return await self._exchange(self._pending, session_id, message, timeout)

    async def start_talk(self, channel: int) -> None:
        if channel != _TALK_CHANNEL:
            raise ValueError(
                f"talk supports wire channel {_TALK_CHANNEL}, not {channel}"
            )
        async with self._talk_lock:
            if self._talking:
                raise TalkBusyError("talk is already active on this connection")
            reply = await self._talk_exchange(_BEGIN)
            if reply[_TALK_RESULT] != _OK:
                raise TalkBusyError(f"the camera refused talk on channel {channel}")
            self._talking = True

    async def send_audio(self, pcm_chunk: bytes) -> None:
        writer = self._writer
        if not self._talking or writer is None:
            raise ConnectError("talk is not active")
        count = len(pcm_chunk) // SUBFRAME_PCM_BYTES
        seq = self._audio_seq
        if seq + count > _DATA_SEQ_WRAP:
            seq = 0
        packets = frame_talk_audio(pcm_chunk, _TALK_CODEC, seq, self._peer_ip())
        self._audio_seq = seq + count
        try:
            writer.write(packets)
            await writer.drain()
        except (OSError, ConnectionError) as exc:
            raise ConnectError(f"audio send failed: {exc}") from exc

    async def stop_talk(self) -> None:
        async with self._talk_lock:
            if not self._talking:
                return
            self._talking = False
            await self._talk_exchange(_END)

    async def close(self) -> None:
        self._closing = True
        task = self._run_task
        self._run_task = None
        if task is not None:
            await _cancel(task)
        self._fail_pending(ConnectError("connection closed"))
        self._set_available(False)
        await self._close_transport()

    async def _run(self) -> None:
        while not self._closing:
            heartbeat = asyncio.create_task(self._heartbeat_loop())
            try:
                await self._receive_loop()
            finally:
                await _cancel(heartbeat)
            if self._closing:
                break
            self._set_available(False)
            self._fail_pending(ConnectError("connection dropped"))
            await self._close_transport()
            if not await self._reconnect():
                break

    async def _reconnect(self) -> bool:
        delay = self._backoff_start
        auth_failures = 0
        while not self._closing:
            try:
                await self._connect_once()
            except ConnectError as exc:
                _log.warning("reconnect failed (%s); retrying in %.1fs", exc, delay)
            except AuthError as exc:
                auth_failures += 1
                if auth_failures >= self._auth_failure_limit:
                    _log.error(
                        "giving up reconnect after %d auth failures: %s",
                        auth_failures,
                        exc,
                    )
                    return False
                _log.warning(
                    "reconnect login failed (%s), attempt %d of %d; retrying in %.1fs",
                    exc,
                    auth_failures,
                    self._auth_failure_limit,
                    delay,
                )
            else:
                _log.info("reconnected to %s:%d", self._host, self._port)
                self._set_available(True)
                return True
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._backoff_max)
        return False

    async def _connect_once(self) -> None:
        try:
            reader, writer = await asyncio.open_connection(self._host, self._port)
        except OSError as exc:
            raise ConnectError(f"cannot reach {self._host}:{self._port}: {exc}") from exc
        self._reader = reader
        self._writer = writer
        self._rx_buffer = bytearray()
        self._seq = 0
        self._audio_seq = 0
        self._session_id = 1
        try:
            await self._login_exchange()
        except BaseException:
            await self._close_transport()
            raise

    async def _login_exchange(self) -> None:
        try:
            logon = self._login.build_logon(
                self._username, self._password, self._next_seq()
            )
        except ProtocolError as exc:
            raise AuthError(f"cannot build the logon message: {exc}") from exc
        assert self._writer is not None and self._reader is not None
        try:
            self._writer.write(logon)
            await self._writer.drain()
        except (OSError, ConnectionError) as exc:
            raise ConnectError(f"cannot send the logon message: {exc}") from exc
        buffer = self._rx_buffer
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._login_timeout
        while True:
            frame = _take_frame(buffer)
            if frame is not None:
                if frame.fields is not None:
                    result = self._login.interpret_reply(frame.fields)
                    if result.success:
                        self.device = result.device
                        return
                continue
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise AuthError("login did not finish before the timeout")
            try:
                chunk = await asyncio.wait_for(self._reader.read(_READ_SIZE), remaining)
            except (asyncio.TimeoutError, TimeoutError) as exc:
                raise AuthError("login did not finish before the timeout") from exc
            if not chunk:
                raise AuthError("the camera closed the connection during login")
            buffer += chunk
            if len(buffer) > _MAX_BUFFER:
                buffer.clear()

    async def _receive_loop(self) -> None:
        buffer = self._rx_buffer
        while not self._closing:
            while True:
                frame = _take_frame(buffer)
                if frame is None:
                    break
                self._route(frame)
            reader = self._reader
            if reader is None:
                return
            try:
                chunk = await reader.read(_READ_SIZE)
            except (OSError, ConnectionError):
                return
            if not chunk:
                return
            buffer += chunk
            # drop an oversized unparseable buffer and resync (protocol.md, Framing)
            if len(buffer) > _MAX_BUFFER:
                buffer.clear()

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self._heartbeat_interval)
            writer = self._writer
            if writer is None:
                return
            try:
                # empty command packet, header only (protocol.md, Heartbeat)
                writer.write(build_command([], self._next_seq()))
                await writer.drain()
            except (OSError, ConnectionError):
                return

    async def _talk_exchange(self, action: str) -> list[str]:
        message = [
            self._peer_ip(),
            _TALK_ROUTE,
            str(_TALK_CHANNEL),
            "",
            "CMD",
            "TALK",
            action,
        ]
        return await self._exchange(self._talk_pending, action, message, None)

    async def _exchange(
        self, pending: dict, key: object, message: list[str], timeout: float | None
    ) -> list[str]:
        writer = self._writer
        if not self._available or writer is None:
            raise ConnectError("not connected")
        limit = self._request_timeout if timeout is None else timeout
        future: asyncio.Future[list[str]] = asyncio.get_running_loop().create_future()
        pending[key] = future
        try:
            try:
                writer.write(build_command(message, self._next_seq()))
                await writer.drain()
            except (OSError, ConnectionError) as exc:
                raise ConnectError(f"request send failed: {exc}") from exc
            try:
                return await asyncio.wait_for(future, limit)
            except TimeoutError as exc:
                raise ConnectError(f"no reply within {limit:g} seconds") from exc
        finally:
            pending.pop(key, None)

    def _route(self, frame: Frame) -> None:
        fields = frame.fields
        if fields is None:
            return
        if fields[2:4] == _ALARM_HEAD:
            event = parse_event(fields)
            if event is not None:
                self._emit(self._on_event, event, "event")
            return
        if fields[2:4] == _TALK_HEAD:
            self._route_talk(fields)
            return
        session_id = _reply_session_id(fields)
        if session_id is None:
            return
        future = self._pending.pop(session_id, None)
        if future is not None and not future.done():
            future.set_result(fields)

    def _route_talk(self, fields: list[str]) -> None:
        # talk replies carry no session id, so BEGIN and END are told apart by name
        if len(fields) <= _TALK_RESULT:
            return
        future = self._talk_pending.pop(fields[_TALK_ACTION], None)
        if future is not None and not future.done():
            future.set_result(fields)

    def _fail_pending(self, error: Exception) -> None:
        for future in [*self._pending.values(), *self._talk_pending.values()]:
            if not future.done():
                future.set_exception(error)
        self._pending.clear()
        self._talk_pending.clear()
        # a new connection needs a new BEGIN
        self._talking = False

    def _set_available(self, state: bool) -> None:
        if state == self._available:
            return
        self._available = state
        self._emit(self._on_availability, state, "availability")

    def _emit(self, callback: Callable, arg: object, label: str) -> None:
        # a raising callback must not kill the receive loop or supervisor
        try:
            callback(arg)
        except Exception:
            _log.exception("%s callback raised", label)

    async def _close_transport(self) -> None:
        writer = self._writer
        self._writer = None
        self._reader = None
        if writer is None:
            return
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass

    def _peer_ip(self) -> str:
        writer = self._writer
        peer = writer.get_extra_info("peername") if writer is not None else None
        if not peer:
            raise ConnectError("not connected")
        return peer[0]

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) % _SEQ_WRAP
        return seq

    def _next_session_id(self) -> int:
        # counter starts at 1, so the first id is 2 and it wraps at 999 (protocol.md)
        self._session_id += 1
        if self._session_id > _SESSION_ID_WRAP:
            self._session_id = 1
        return self._session_id


def _take_frame(buffer: bytearray) -> Frame | None:
    while True:
        try:
            frame, consumed = parse_frame(bytes(buffer))
        except ProtocolError:
            # valid header, bad payload: skip a byte and resync (protocol.md, Framing)
            if not buffer:
                return None
            del buffer[0]
            continue
        if frame is None:
            return None
        del buffer[:consumed]
        return frame


def _reply_session_id(fields: list[str]) -> int | None:
    try:
        marker = fields.index(_FINISHED)
    except ValueError:
        return None
    if marker + 1 >= len(fields):
        return None
    try:
        return int(fields[marker + 1])
    except ValueError:
        return None


async def _cancel(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:
        _log.exception("background task failed")
