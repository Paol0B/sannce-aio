import asyncio
import contextlib
import logging
from collections.abc import AsyncIterable, Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar
from urllib.parse import quote

import aiohttp

from .backchannel import Backchannel
from .connection import NvsConnection
from .errors import AuthError, ConnectError, SannceError
from .events import Event
from .http import Detection, HttpClient
from .login import SaltedLogin

_log = logging.getLogger(__name__)

_T = TypeVar("_T")

_BAD_HOST_CHARS = "/?#@"
_RTSP_PATHS = {"main": "/1/1", "sub": "/1/2"}
_LAMP_MODES = frozenset({"color", "custom"})
_FULL_POWER = 100


@dataclass(frozen=True)
class CameraInfo:
    model: str | None = None
    serial: str | None = None
    firmware: str | None = None
    mac: str | None = None


@dataclass(frozen=True)
class Floodlight:
    on: bool
    brightness: int | None


class SannceCamera:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        nvs_port: int = 3002,
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
            SaltedLogin(host),
            session=session,
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
        self._sound_count = 0

    @property
    def info(self) -> CameraInfo:
        return self._info

    @property
    def caps(self) -> frozenset[str]:
        return self._caps

    @property
    def sound_count(self) -> int:
        return self._sound_count

    async def connect(self) -> None:
        try:
            features = await self._http.get_capabilities()
            await self._conn.connect(self._username, self._password)
            probed = await self._probe_caps()
            self._caps = _build_caps(features, probed)
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

    async def get_floodlight(self) -> Floodlight:
        mode = await self._http.get_light_mode()
        light = await self._http.get_light()
        return Floodlight(on=mode in _LAMP_MODES and light.forced_on, brightness=light.power)

    async def set_floodlight(
        self, on: bool, *, brightness: int | None = None, base_mode: str = "smart"
    ) -> None:
        if not on:
            await self._http.set_light_mode(base_mode)
            if base_mode == "color":
                await self._http.release_light()
            return
        # the camera refuses a manual on; a full-day timed window in color mode lights
        # the lamp instead (protocol.md, White light)
        previous = await self._http.get_light_mode()
        if previous in _LAMP_MODES:
            await self._force_on(brightness)
            return
        await self._http.set_light_mode("color")
        try:
            await self._force_on(brightness)
        except Exception:
            # color mode lights the lamp at night by itself
            await self._restore_light_mode(previous)
            raise

    async def _force_on(self, brightness: int | None) -> None:
        if brightness is None:
            brightness = (await self._http.get_light()).power or _FULL_POWER
        await self._http.force_light_on(brightness)

    async def _restore_light_mode(self, mode: str) -> None:
        try:
            await self._http.set_light_mode(mode)
        except SannceError as exc:
            _log.warning("cannot restore light mode %s on %s: %s", mode, self._host, exc)

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

    async def set_sensitivity(self, level: int) -> None:
        await self._http.set_sensitivity(level)

    async def play_sound(self, sample: int) -> None:
        await self._http.play_sound(sample)

    async def stop_sound(self, sample: int) -> None:
        await self._http.stop_sound(sample)

    async def get_volume(self) -> int:
        return await self._http.get_volume()

    async def set_volume(self, volume: int) -> None:
        await self._http.set_volume(volume)

    async def get_siren_on_event(self) -> bool:
        return await self._http.get_siren_on_event()

    async def set_siren_on_event(self, on: bool) -> None:
        await self._http.set_siren_on_event(on)

    async def play_audio(self, pcm: AsyncIterable[bytes]) -> None:
        async with self._play_lock:
            channel = self._backchannel()
            await channel.open()
            try:
                await channel.stream(pcm)
            finally:
                await channel.close()

    def _backchannel(self) -> Backchannel:
        return Backchannel(
            self._host, self._rtsp_port, _RTSP_PATHS["main"], self._username, self._password
        )

    async def _probe_caps(self) -> set[str]:
        reads: tuple[tuple[str, Callable[[], Awaitable[object]]], ...] = (
            ("white_light", self._http.get_light),
            ("light_mode", self._http.get_light_mode),
            ("volume", self._http.get_volume),
            ("siren_on_event", self._http.get_siren_on_event),
        )
        caps = {cap for cap, read in reads if await self._probe(cap, read) is not None}
        self._sound_count = await self._probe("siren", self._http.get_sound_count) or 0
        if self._sound_count:
            caps.add("siren")
        if await self._probe("speaker", self._backchannel().has_backchannel):
            caps.add("speaker")
        return caps

    async def _probe(self, cap: str, read: Callable[[], Awaitable[_T]]) -> _T | None:
        # an unreachable camera fails the connect: a cap left out stays out until the next one
        try:
            return await read()
        except ConnectError:
            raise
        except SannceError as exc:
            _log.debug("%s has no %s: %s", self._host, cap, exc)
            return None

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


def _build_caps(features: dict[str, bool], probed: set[str]) -> frozenset[str]:
    caps = set(probed)
    caps.update(name for name in ("person", "vehicle", "motion") if features.get(name))
    return frozenset(caps)


def _safe_call(callback: Callable[[_T], None], arg: _T, label: str) -> None:
    try:
        callback(arg)
    except Exception:
        _log.exception("%s raised", label)


def _discard(items: list[_T], item: _T) -> None:
    with contextlib.suppress(ValueError):
        items.remove(item)
