import asyncio
import logging
from collections import deque
from collections.abc import Callable
from typing import TypeVar

import aiohttp

from .errors import AuthError, ConnectError, ProtocolError
from .events import Event, parse_event
from .login import LoginStep
from .protocol import Frame, build_command, parse_frame
from .transport import WsTransport

_log = logging.getLogger(__name__)

_T = TypeVar("_T")

_MAX_BUFFER = 0x10000
_SEQ_WRAP = 0x10000
_SESSION_ID_WRAP = 999
_FINISHED = "FINISHED"
# camera messages lead with device ip and route (protocol.md, Field lists)
_ALARM_HEAD = ["INNER", "ALARM"]


class NvsConnection:
    def __init__(
        self,
        host: str,
        port: int,
        login: LoginStep,
        *,
        on_event: Callable[[Event], None],
        on_availability: Callable[[bool], None],
        on_login_failed: Callable[[AuthError], None] | None = None,
        session: aiohttp.ClientSession | None = None,
        request_timeout: float = 10.0,
        heartbeat_interval: float = 5.0,
        idle_timeout: float = 20.0,
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
        self._on_login_failed = on_login_failed
        self._request_timeout = request_timeout
        self._heartbeat_interval = heartbeat_interval
        self._idle_timeout = idle_timeout
        self._login_timeout = login_timeout
        self._backoff_start = backoff_start
        self._backoff_max = backoff_max
        self._auth_failure_limit = auth_failure_limit
        self._session = session
        self._owns_session = session is None
        self._transport: WsTransport | None = None
        self._rx_buffer = bytearray()
        self._commands: deque[list[str]] = deque()
        self._pending: dict[int, asyncio.Future[list[str]]] = {}
        self._seq = 0
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

    async def close(self) -> None:
        self._closing = True
        task = self._run_task
        self._run_task = None
        if task is not None:
            await _cancel(task)
        self._fail_pending(ConnectError("connection closed"))
        self._set_available(False)
        await self._close_transport()
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

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
                _log.debug("reconnect failed (%s); retrying in %.1fs", exc, delay)
            except AuthError as exc:
                auth_failures += 1
                if auth_failures >= self._auth_failure_limit:
                    _log.error(
                        "giving up reconnect after %d auth failures: %s",
                        auth_failures,
                        exc,
                    )
                    if self._on_login_failed is not None:
                        self._emit(self._on_login_failed, exc, "login failure")
                    return False
                _log.debug(
                    "reconnect login failed (%s), attempt %d of %d; retrying in %.1fs",
                    exc,
                    auth_failures,
                    self._auth_failure_limit,
                    delay,
                )
            else:
                _log.debug("reconnected to %s:%d", self._host, self._port)
                self._set_available(True)
                return True
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._backoff_max)
        return False

    async def _connect_once(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession()
        host = f"[{self._host}]" if ":" in self._host else self._host
        self._transport = await WsTransport.open(
            self._session, f"ws://{host}:{self._port}", self._login_timeout
        )
        self._rx_buffer = bytearray()
        self._commands.clear()
        self._seq = 0
        self._session_id = 1
        try:
            await self._login_exchange()
        except BaseException:
            await self._close_transport()
            raise

    async def _login_exchange(self) -> None:
        try:
            first = self._login.first_fields(self._username, self._password)
        except ProtocolError as exc:
            raise AuthError(f"cannot build the logon message: {exc}") from exc
        await self._send(first)
        buffer = self._rx_buffer
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._login_timeout
        while True:
            fields = self._take_command()
            if fields is not None:
                result = self._login.interpret_reply(fields)
                if result.success:
                    self.device = result.device
                    return
                if result.next_fields is not None:
                    await self._send(result.next_fields)
                continue
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ConnectError("login did not finish before the timeout")
            assert self._transport is not None
            try:
                chunk = await asyncio.wait_for(self._transport.read(), remaining)
            except TimeoutError as exc:
                raise ConnectError("login did not finish before the timeout") from exc
            if not chunk:
                raise ConnectError("the camera closed the connection during login")
            buffer += chunk
            if len(buffer) > _MAX_BUFFER:
                buffer.clear()

    async def _receive_loop(self) -> None:
        buffer = self._rx_buffer
        while not self._closing:
            while (fields := self._take_command()) is not None:
                self._route(fields)
            transport = self._transport
            if transport is None:
                return
            try:
                chunk = await asyncio.wait_for(transport.read(), self._idle_timeout)
            except TimeoutError:
                _log.debug(
                    "no data from %s for %.0fs; reconnecting",
                    self._host,
                    self._idle_timeout,
                )
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
            try:
                # empty command packet, header only (protocol.md, Heartbeat)
                await self._send([])
            except ConnectError:
                return

    async def _send(self, fields: list[str]) -> None:
        transport = self._transport
        if transport is None:
            raise ConnectError("not connected")
        await transport.write(build_command(fields, self._next_seq()))

    async def _exchange(
        self,
        pending: dict[_T, asyncio.Future[list[str]]],
        key: _T,
        message: list[str],
        timeout: float | None,
    ) -> list[str]:
        if not self._available or self._transport is None:
            raise ConnectError("not connected")
        limit = self._request_timeout if timeout is None else timeout
        future: asyncio.Future[list[str]] = asyncio.get_running_loop().create_future()
        pending[key] = future
        try:
            await self._send(message)
            try:
                return await asyncio.wait_for(future, limit)
            except TimeoutError as exc:
                raise ConnectError(f"no reply within {limit:g} seconds") from exc
        finally:
            pending.pop(key, None)

    def _take_command(self) -> list[str] | None:
        while not self._commands:
            frame = _take_frame(self._rx_buffer)
            if frame is None:
                return None
            self._commands.extend(frame.commands or [])
        return self._commands.popleft()

    def _route(self, fields: list[str]) -> None:
        if fields[2:4] == _ALARM_HEAD:
            event = parse_event(fields)
            if event is not None:
                self._emit(self._on_event, event, "event")
            return
        session_id = _reply_session_id(fields)
        if session_id is None:
            return
        future = self._pending.pop(session_id, None)
        if future is not None and not future.done():
            future.set_result(fields)

    def _fail_pending(self, error: Exception) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    def _set_available(self, state: bool) -> None:
        if state == self._available:
            return
        self._available = state
        self._emit(self._on_availability, state, "availability")

    def _emit(self, callback: Callable[[_T], None], arg: _T, label: str) -> None:
        # a raising callback must not kill the receive loop or supervisor
        try:
            callback(arg)
        except Exception:
            _log.exception("%s callback raised", label)

    async def _close_transport(self) -> None:
        transport, self._transport = self._transport, None
        if transport is not None:
            await transport.close()

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


async def _cancel(task: asyncio.Task[None]) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:
        _log.exception("background task failed")
