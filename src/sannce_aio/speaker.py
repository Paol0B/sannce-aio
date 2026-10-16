import asyncio
import logging
from collections.abc import AsyncIterable, Callable
from typing import ClassVar, Literal

from .backchannel import FRAME_BYTES, Backchannel
from .errors import ConnectError, SannceError

LINGER = 3.0
HANGOVER = 1.0
TALK_BUFFER = 1.0
VOICE_LEVEL = 16
Owner = Literal["talk", "play"]

_log = logging.getLogger(__name__)


class _Source:
    kind: ClassVar[Owner]


class _Play(_Source):
    kind = "play"


class Speaker:
    def __init__(
        self,
        open_channel: Callable[[], Backchannel],
        *,
        linger: float = LINGER,
        hangover: float = HANGOVER,
        talk_buffer: float = TALK_BUFFER,
    ) -> None:
        self._open_channel = open_channel
        self._linger = linger
        self._hangover = hangover
        self._talk_buffer = talk_buffer
        self._owner: _Source | None = None
        self._subscribers: dict[object, Callable[[Owner | None], None]] = {}
        self._channel: Backchannel | None = None
        self._opening: asyncio.Task[None] | None = None
        self._session_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._expiry: asyncio.TimerHandle | None = None
        self._closers: set[asyncio.Task[None]] = set()
        self._closed = False

    @property
    def owner(self) -> Owner | None:
        return None if self._owner is None else self._owner.kind

    def subscribe(self, callback: Callable[[Owner | None], None]) -> Callable[[], None]:
        token = object()
        self._subscribers[token] = callback

        def unsubscribe() -> None:
            self._subscribers.pop(token, None)

        return unsubscribe

    async def play(self, pcm: AsyncIterable[bytes]) -> bool:
        if self._closed:
            return False
        source = _Play()
        self._take(source)
        try:
            return await self._stream(source, pcm)
        finally:
            self._free(source)

    async def close(self) -> None:
        self._closed = True
        self._cancel_expiry()
        if self._owner is not None:
            self._set_owner(None)
        if self._opening is not None:
            self._opening.cancel()
        async with self._write_lock, self._session_lock:
            await self._close_channel()
        closers = list(self._closers)
        for task in closers:
            task.cancel()
        await asyncio.gather(*closers, return_exceptions=True)

    async def _stream(self, source: _Source, pcm: AsyncIterable[bytes]) -> bool:
        buffer = bytearray()
        async for chunk in pcm:
            buffer += chunk
            while len(buffer) >= FRAME_BYTES:
                if not await self._send(source, bytes(buffer[:FRAME_BYTES])):
                    return False
                del buffer[:FRAME_BYTES]
            if self._owner is not source:
                return False
        if buffer:
            return await self._send(source, bytes(buffer) + bytes(FRAME_BYTES - len(buffer)))
        return True

    async def _send(self, source: _Source, frame: bytes) -> bool:
        while True:
            channel = await self._session(source)
            if channel is None:
                return False
            async with self._write_lock:
                if self._owner is not source:
                    return False
                if self._channel is not channel:
                    continue
                try:
                    await channel.send(frame)
                except ConnectError as exc:
                    async with self._session_lock:
                        if self._channel is channel:
                            await self._close_channel()
                    if self._owner is not source:
                        _log.debug(
                            "a %s that lost the speaker failed to write: %s", source.kind, exc
                        )
                        return False
                    raise
                return True

    async def _session(self, source: _Source) -> Backchannel | None:
        async with self._session_lock:
            if self._owner is not source:
                return None
            if self._channel is None:
                channel = self._open_channel()
                self._opening = asyncio.create_task(channel.open())
                try:
                    await self._opening
                except asyncio.CancelledError:
                    # close() cancels the open; a cancel of our own task must propagate
                    task = asyncio.current_task()
                    if task is not None and task.cancelling():
                        raise
                    return None
                except SannceError as exc:
                    if self._owner is not source:
                        _log.debug(
                            "a %s that lost the speaker failed to open: %s", source.kind, exc
                        )
                        return None
                    raise
                finally:
                    self._opening = None
                self._channel = channel
            return self._channel

    def _take(self, source: _Source) -> None:
        self._cancel_expiry()
        if self._owner is not None:
            _log.debug("a %s took the speaker from a %s", source.kind, self._owner.kind)
        self._set_owner(source)

    def _free(self, source: _Source) -> None:
        if self._owner is not source:
            return
        self._set_owner(None)
        self._expiry = asyncio.get_running_loop().call_later(self._linger, self._expire)

    def _set_owner(self, source: _Source | None) -> None:
        self._owner = source
        kind = self.owner
        for callback in list(self._subscribers.values()):
            try:
                callback(kind)
            except Exception:
                _log.exception("speaker subscriber raised")

    def _cancel_expiry(self) -> None:
        if self._expiry is not None:
            self._expiry.cancel()
            self._expiry = None

    def _expire(self) -> None:
        self._expiry = None
        task = asyncio.create_task(self._close_idle())
        self._closers.add(task)
        task.add_done_callback(self._closers.discard)

    async def _close_idle(self) -> None:
        async with self._write_lock, self._session_lock:
            if self._owner is None:
                await self._close_channel()

    async def _close_channel(self) -> None:
        channel, self._channel = self._channel, None
        if channel is not None:
            await channel.close()
