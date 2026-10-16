import asyncio
import logging
import math
import struct
from collections import deque
from collections.abc import AsyncIterable, Callable
from typing import ClassVar, Literal

from .backchannel import FRAME_BYTES, SAMPLE_RATE, Backchannel
from .errors import ConnectError, SannceError

LINGER = 3.0
HANGOVER = 1.0
TALK_BUFFER = 1.0
VOICE_LEVEL = 16
Owner = Literal["talk", "play"]
_FRAME_SECONDS = FRAME_BYTES / 2 / SAMPLE_RATE

_log = logging.getLogger(__name__)


class _Source:
    kind: ClassVar[Owner]


class _Play(_Source):
    kind = "play"


class _Talk(_Source):
    kind = "talk"

    def __init__(self, frames: int) -> None:
        self.queue: deque[bytes] = deque(maxlen=frames)
        self.pending = bytearray()
        self.last_frame = 0.0
        self.last_voice = -math.inf
        self.muted = False

    def push(self, pcm: bytes) -> None:
        self.pending += pcm
        while len(self.pending) >= FRAME_BYTES:
            self.queue.append(bytes(self.pending[:FRAME_BYTES]))
            del self.pending[:FRAME_BYTES]

    def drop(self) -> None:
        self.queue.clear()
        self.pending.clear()


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
        self._talk_frames = max(1, round(talk_buffer / _FRAME_SECONDS))
        self._owner: _Source | None = None
        self._subscribers: dict[object, Callable[[Owner | None], None]] = {}
        self._channel: Backchannel | None = None
        self._opening: asyncio.Task[None] | None = None
        self._session_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._expiry: asyncio.TimerHandle | None = None
        self._closers: set[asyncio.Task[None]] = set()
        self._talks: dict[int, _Talk] = {}
        self._talk_check: asyncio.TimerHandle | None = None
        self._pump: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._failing = False
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

    def feed_talk(self, ssrc: int, pcm: bytes) -> None:
        if self._closed or len(pcm) % 2:
            return
        now = asyncio.get_running_loop().time()
        talk = self._talks.get(ssrc)
        if talk is None:
            talk = self._talks[ssrc] = _Talk(self._talk_frames)
            if self._talk_check is None:
                self._schedule_talk_check()
        talk.last_frame = now
        if _is_voice(pcm):
            started = now - talk.last_voice >= self._hangover
            talk.last_voice = now
            if self._owner is not talk and (started or (talk.muted and self._owner is None)):
                self._take_talk(talk)
        if self._owner is talk:
            talk.push(pcm)
            self._wake.set()

    async def close(self) -> None:
        self._closed = True
        self._cancel_expiry()
        if self._talk_check is not None:
            self._talk_check.cancel()
            self._talk_check = None
        self._talks.clear()
        if self._owner is not None:
            self._set_owner(None)
        if self._opening is not None:
            self._opening.cancel()
        pump, self._pump = self._pump, None
        if pump is not None:
            # the pump can hold the write lock in a stalled write
            pump.cancel()
            await asyncio.gather(pump, return_exceptions=True)
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
                self._failing = False
            return self._channel

    def _take_talk(self, talk: _Talk) -> None:
        talk.muted = False
        self._take(talk)
        if self._pump is None or self._pump.done():
            self._pump = asyncio.create_task(self._pump_talk())

    async def _pump_talk(self) -> None:
        while isinstance(talk := self._owner, _Talk):
            if not talk.queue:
                self._wake.clear()
                await self._wake.wait()
                continue
            try:
                await self._send(talk, talk.queue.popleft())
            except SannceError as exc:
                if self._failing:
                    _log.debug("talk still cannot reach the camera: %s", exc)
                else:
                    self._failing = True
                    _log.warning("talk cannot reach the camera: %s", exc)
                self._end_talk(talk)

    def _end_talk(self, talk: _Talk) -> None:
        talk.drop()
        self._free(talk)

    def _schedule_talk_check(self) -> None:
        self._talk_check = asyncio.get_running_loop().call_later(
            self._hangover / 4, self._check_talks
        )

    def _check_talks(self) -> None:
        now = asyncio.get_running_loop().time()
        for ssrc, talk in list(self._talks.items()):
            if talk is self._owner and now - talk.last_voice >= self._hangover:
                self._end_talk(talk)
            if now - talk.last_frame >= self._hangover:
                del self._talks[ssrc]
        self._talk_check = None
        if self._talks:
            self._schedule_talk_check()

    def _take(self, source: _Source) -> None:
        self._cancel_expiry()
        previous = self._owner
        if previous is not None:
            _log.debug("a %s took the speaker from a %s", source.kind, previous.kind)
        if isinstance(previous, _Talk):
            previous.muted = True
            previous.drop()
        self._set_owner(source)

    def _free(self, source: _Source) -> None:
        if self._owner is not source:
            return
        self._set_owner(None)
        self._expiry = asyncio.get_running_loop().call_later(self._linger, self._expire)

    def _set_owner(self, source: _Source | None) -> None:
        self._owner = source
        self._wake.set()
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


def _is_voice(pcm: bytes) -> bool:
    samples = struct.unpack(f"<{len(pcm) // 2}h", pcm)
    return max(samples, default=0) > VOICE_LEVEL or min(samples, default=0) < -VOICE_LEVEL
