import asyncio
import contextlib
import logging
from collections.abc import AsyncIterable, Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import quote

import aiohttp

from .audio import SUBFRAME_PCM_BYTES
from .connection import NvsConnection
from .errors import AuthError, SannceError
from .events import Event
from .http import Detection, HttpClient
from .login import PlaintextLogin

_log = logging.getLogger(__name__)

_TALK_CHANNEL = 0
# 160 PCM bytes = 80 samples = 10 ms at 8 kHz
_FRAME_SECONDS = 0.01
# cap a burst so one large chunk cannot flood the camera
_MAX_PACE_FRAMES = 32
_BAD_HOST_CHARS = "/?#@"
_RTSP_PATHS = {"main": "/1/1", "sub": "/1/2"}


@dataclass(frozen=True)
class CameraInfo:
    model: str | None = None
    serial: str | None = None
    firmware: str | None = None
    mac: str | None = None


class SannceCamera:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        nvs_port: int = 3000,
        http_port: int = 80,
        rtsp_port: int = 554,
        session: aiohttp.ClientSession | None = None,
        event_timeout: float = 10.0,
    ) -> None:
        _check_host(host)
        self._host = host
        self._username = username
        self._password = password
        self._rtsp_port = rtsp_port
        self._event_timeout = event_timeout
        self._http = HttpClient(host, username, password, port=http_port, session=session)
        self._conn = NvsConnection(
            host,
            nvs_port,
            PlaintextLogin(host),
            on_event=self._handle_event,
            on_availability=self._handle_availability,
            on_login_failed=self._handle_login_failed,
        )
        self._subscribers: list[Callable[[Event], None]] = []
        self._availability_subs: list[Callable[[bool], None]] = []
        self._login_failed_subs: list[Callable[[AuthError], None]] = []
        self._event_timers: dict[tuple[str, int], asyncio.TimerHandle] = {}
        self._info = CameraInfo()
        self._caps: frozenset[str] = frozenset()
        self._play_lock = asyncio.Lock()

    @property
    def info(self) -> CameraInfo:
        return self._info

    @property
    def caps(self) -> frozenset[str]:
        return self._caps

    async def connect(self) -> None:
        try:
            features = await self._http.get_capabilities()
            await self._conn.connect(self._username, self._password)
            light_caps = await self._probe_light_caps()
            self._caps = _build_caps(features, light_caps)
            self._info = await self._read_info()
        except BaseException:
            # the HTTP client only closes a session the facade owns
            await self.close()
            raise

    async def close(self) -> None:
        for timer in self._event_timers.values():
            timer.cancel()
        self._event_timers.clear()
        await self._conn.close()
        await self._http.close()

    def rtsp_url(self, stream: str = "main") -> str:
        try:
            path = _RTSP_PATHS[stream]
        except KeyError:
            raise ValueError(f"stream must be 'main' or 'sub', got {stream!r}") from None
        user = quote(self._username, safe="")
        password = quote(self._password, safe="")
        host = f"[{self._host}]" if ":" in self._host else self._host
        return f"rtsp://{user}:{password}@{host}:{self._rtsp_port}{path}"

    def subscribe(self, callback: Callable[[Event], None]) -> Callable[[], None]:
        self._subscribers.append(callback)
        return lambda: _discard(self._subscribers, callback)

    def on_availability(self, callback: Callable[[bool], None]) -> None:
        self._availability_subs.append(callback)

    def on_login_failed(self, callback: Callable[[AuthError], None]) -> None:
        self._login_failed_subs.append(callback)

    async def get_light(self) -> bool:
        return (await self._http.get_light()).on

    async def set_light(self, on: bool) -> None:
        await self._http.set_light(on)

    async def get_light_mode(self) -> str:
        return await self._http.get_light_mode()

    async def set_light_mode(self, mode: str) -> None:
        await self._http.set_light_mode(mode)

    async def get_detection(self) -> Detection:
        return await self._http.get_detection()

    async def set_detection(
        self,
        *,
        person: bool | None = None,
        vehicle: bool | None = None,
        motion: bool | None = None,
    ) -> None:
        await self._http.set_detection(person=person, vehicle=vehicle, motion=motion)

    async def play_audio(self, pcm: AsyncIterable[bytes]) -> None:
        async with self._play_lock:
            await self._conn.start_talk(_TALK_CHANNEL)
            try:
                buffer = bytearray()
                async for chunk in pcm:
                    buffer += chunk
                    await self._stream_frames(buffer)
                tail = len(buffer) % SUBFRAME_PCM_BYTES
                if tail:
                    buffer += bytes(SUBFRAME_PCM_BYTES - tail)
                    await self._stream_frames(buffer)
            finally:
                await self._stop_talk()

    async def _stream_frames(self, buffer: bytearray) -> None:
        while len(buffer) >= SUBFRAME_PCM_BYTES:
            frames = min(len(buffer) // SUBFRAME_PCM_BYTES, _MAX_PACE_FRAMES)
            size = frames * SUBFRAME_PCM_BYTES
            await self._conn.send_audio(bytes(buffer[:size]))
            del buffer[:size]
            await asyncio.sleep(frames * _FRAME_SECONDS)

    async def _stop_talk(self) -> None:
        try:
            await self._conn.stop_talk()
        except SannceError:
            _log.exception("stopping talk failed")

    async def _probe_light_caps(self) -> set[str]:
        caps = set()
        if await _probe(self._http.get_light):
            caps.add("white_light")
        if await _probe(self._http.get_light_mode):
            caps.add("light_mode")
        return caps

    async def _read_info(self) -> CameraInfo:
        try:
            raw = await self._http.get_device_info()
        except SannceError:
            return CameraInfo()
        return CameraInfo(
            model=raw["model"],
            serial=raw["serial"],
            firmware=raw["firmware"],
            mac=raw["mac"],
        )

    def _handle_event(self, event: Event) -> None:
        key = (event.kind, event.channel)
        self._cancel_timer(key)
        if event.active:
            loop = asyncio.get_running_loop()
            self._event_timers[key] = loop.call_later(
                self._event_timeout, self._autoclear, key
            )
        self._dispatch(event)

    def _autoclear(self, key: tuple[str, int]) -> None:
        self._event_timers.pop(key, None)
        kind, channel = key
        self._dispatch(Event(kind, False, channel))

    def _cancel_timer(self, key: tuple[str, int]) -> None:
        timer = self._event_timers.pop(key, None)
        if timer is not None:
            timer.cancel()

    def _dispatch(self, event: Event) -> None:
        for callback in list(self._subscribers):
            _safe_call(callback, event, "event subscriber")

    def _handle_availability(self, available: bool) -> None:
        for callback in list(self._availability_subs):
            _safe_call(callback, available, "availability subscriber")

    def _handle_login_failed(self, error: AuthError) -> None:
        for callback in list(self._login_failed_subs):
            _safe_call(callback, error, "login failure subscriber")


def _check_host(host: str) -> None:
    if not host or any(char in _BAD_HOST_CHARS for char in host):
        raise ValueError(f"host must not be empty or contain any of {_BAD_HOST_CHARS!r}")


def _build_caps(features: dict[str, bool], light_caps: set[str]) -> frozenset[str]:
    caps = set(light_caps)
    caps.update(name for name in ("person", "vehicle", "motion") if features.get(name))
    caps.add("talk")
    return frozenset(caps)


async def _probe(call: Callable[[], Awaitable[object]]) -> bool:
    try:
        await call()
    except SannceError:
        return False
    return True


def _safe_call(callback: Callable, arg: object, label: str) -> None:
    try:
        callback(arg)
    except Exception:
        _log.exception("%s raised", label)


def _discard(items: list, item: object) -> None:
    with contextlib.suppress(ValueError):
        items.remove(item)
