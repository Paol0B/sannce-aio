import asyncio
import base64
import contextlib
import hashlib
import itertools
import logging
import os
import re
import socket
import xml.etree.ElementTree as ET
from typing import cast

from aiohttp import WSMsgType, web
from aiohttp.typedefs import Handler

from .discovery import (
    DiscoveredCamera,
    build_seek_reply,
    is_seek_request,
    join_groups,
)
from .errors import ProtocolError
from .protocol import (
    TERMINATOR,
    Frame,
    build_command,
    encode_fields,
    pack_command,
    parse_frame,
)

_log = logging.getLogger(__name__)

DEFAULT_MODEL = "I91FW-SIM"
DEFAULT_SERIAL = "SIM0000000001"
# RFC 7042 documentation address, so it never matches a real device
DEFAULT_MAC = "00:00:5E:00:53:01"
MAC_SHAPE = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")

_SEQ_WRAP = 0x10000
_DEVICE_IP = "192.168.1.10"
_ROUTE = "IP"
_PROXY = "PROXY"
_COMMAND_ID = "1"
_OK = "0"
_FAILED = "1"
_SALT_BYTES = 8
_ALARM_ID = "0012310019100435"
# RFC 2606 domain: the real camera sends the owner's e-mail here
_OWNER_EMAIL = "owner@example.com"

_EVENT_CHANNEL = "0"
_EVENT_NAMES = {
    "motion": "MOTIONDETECT",
    "vehicle": "MOTIONDETECT_CAR",
    "tamper": "VIDEOCOVER",
    "video_loss": "VIDEOLOST",
}
# VCA A4 rule values (protocol.md, Message to library kind)
_VCA_RULES = {"line": "0", "intrusion": "2"}
# A5 onward, no targets and no rules (protocol.md, Event messages and their fields)
_VCA_TAIL = ["0", "0", "0:0:0:0", "0", "0", "0,0,0,0,0,0,0", "0", "0", "0", "", ""]

_SESSION_CHECK = "/CGI/Security/SessionCheck"
_LOGON = "/CGI/Security/Logon"
_DEVICE_INFO = "/CGI/System/deviceInfo"
_CAPABILITIES = "/CGI/System/channels/1/capabilities"
_LIGHT = "/ISAPI/Image/channels/1/WhiteLight"
_MODE = "/CGI/System/CommonEnable/channels/1/Type/4120"
_DETECTION = "/ISAPI/System/Video/inputs/channels/1/motionDetection"
_PLAY_AUDIO = "/CGI/Event/PlayAudio"
_TWO_WAY_AUDIO = "/ISAPI/System/TwoWayAudio/channels/1"
_VMD_TRIGGER = "/ISAPI/Event/triggers/VMD/channels/1"
_TEMP_SESSION = "TMP"
_KEY = "K3Y"
_ROUNDS = 3
_MOTION_QUERY = "00125-MDMotionDetectionSubList"
_SOUND_QUERY = "guardSound"
_SAMPLES = 3
_LIGHT_CONTROLS = frozenset({0, 2, 3})
_SENSITIVITY = "MotionDetectionLayout/sensitivityLevel"
_DETECTION_ELEMENTS = {
    "enabled": "person",
    "carEnabled": "vehicle",
    "allEnabled": "motion",
}

_DEVICE_INFO_XML = (
    "<DeviceInfo><firmwareVersion>1.0.0</firmwareVersion>"
    "<hardwareVersion>1.0.0</hardwareVersion><mediaVersion>1.0.0</mediaVersion>"
    "<platformVersionList><platformInfo><name>platform</name>"
    "<version>1.0.0</version></platformInfo></platformVersionList>"
    "<sdkVersion>1.0.0</sdkVersion><uiVersion>1.0.0</uiVersion>"
    "<webVersion>1.0.0</webVersion></DeviceInfo>"
)
_CAPABILITIES_XML = (
    "<ChanBasicCapList><capTypeList><capType>00125-MDMotionDetectionSubList</capType>"
    "<subCap><supportType>people</supportType><supportType>car</supportType>"
    "<supportType>all</supportType></subCap><support>true</support></capTypeList>"
    "</ChanBasicCapList>"
)
_SOUND_CAPS_XML = (
    "<ChanBasicCapList><capTypeList><capType>guardSound</capType><support>true</support>"
    f"<subCap><supportSoundSampleNum>{_SAMPLES}</supportSoundSampleNum>"
    "<supportSoundCustomNum>2</supportSoundCustomNum></subCap></capTypeList></ChanBasicCapList>"
)
_LIGHT_XML = (
    '<WhiteLight><contrltype opt="0,2,3">{control}</contrltype>'
    "<sunRiseTime>{off}</sunRiseTime><sunSetTime>{on}</sunSetTime>"
    "<infraredLampPower>{power}</infraredLampPower>"
    "<infraredFarLampPower>{power}</infraredFarLampPower></WhiteLight>"
)
_MODE_XML = (
    "<CommonEnable><enable>true</enable><type>4120</type>"
    "<value>{}</value></CommonEnable>"
)
_TWO_WAY_AUDIO_XML = (
    "<TwoWayAudioChannel><id>1</id>"
    '<audioCompressionType opt="G.711A,G.711U">G.711A</audioCompressionType>'
    "<speakerVolume>80</speakerVolume><enabled>true</enabled>"
    '<audioOutputType opt="close,innerspeaker">innerspeaker</audioOutputType>'
    "<outputVolume>{}</outputVolume></TwoWayAudioChannel>"
)
_DETECTION_XML = (
    "<MotionDetection><allEnabled>{}</allEnabled><carEnabled>{}</carEnabled>"
    "<enabled>{}</enabled><regionType>grid</regionType><MotionDetectionLayout>"
    "<sensitivityLevel>{}</sensitivityLevel><layout><gridMap>0</gridMap></layout>"
    "</MotionDetectionLayout></MotionDetection>"
)
_WRITE_OK = (
    "<ResponseStatus><statusCode>1</statusCode>"
    "<statusString>OK</statusString></ResponseStatus>"
)
_DEVICE_ERROR = (
    "<ResponseStatus><statusCode>3</statusCode><statusString>Device Error</statusString>"
    "<subStatusCode>deviceError</subStatusCode></ResponseStatus>"
)


def event_fields(kind: str, active: bool, event_id: str = "") -> list[str]:
    state = "1" if active else "0"
    if kind in _EVENT_NAMES:
        fields = ["INNER", "ALARM", _EVENT_NAMES[kind], _EVENT_CHANNEL, state]
        return [*fields, event_id] if event_id else fields
    if kind in _VCA_RULES:
        rule = _VCA_RULES[kind]
        return ["INNER", "ALARM", "VCA", _EVENT_CHANNEL, state, "0", rule, *_VCA_TAIL]
    raise ValueError(f"unknown event kind {kind!r}")


class _Session:
    def __init__(self, ws: web.WebSocketResponse) -> None:
        self.ws = ws
        self.logged_in = False
        self.salt = b""
        self._seq = 0
        self._lock = asyncio.Lock()

    async def send(
        self, *commands: list[str], route: str = _ROUTE, doubled: bool = False
    ) -> None:
        async with self._lock:
            await self.ws.send_bytes(_camera_frame(commands, self._seq, route, doubled))
            self._seq = (self._seq + 1) % _SEQ_WRAP


class _SeekResponder(asyncio.DatagramProtocol):
    def __init__(self, simulator: "CameraSimulator") -> None:
        self._simulator = simulator
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # on Python 3.11 the selector datagram transport is not a DatagramTransport
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # a dropped camera is rebooting, so it answers no search either
        if self._simulator._ws_runner is None:
            return
        if self._transport is not None and is_seek_request(data):
            reply = build_seek_reply(self._simulator.identity())
            self._transport.sendto(reply, addr)


class CameraSimulator:
    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        username: str = "admin",
        password: str = "admin123",
        port: int = 0,
        http_port: int = 0,
        search_ports: tuple[int, ...] = (),
        model: str = DEFAULT_MODEL,
        serial: str = DEFAULT_SERIAL,
        mac: str = DEFAULT_MAC,
        keepalive_interval: float = 10.0,
        alarm_interval: float = 1.0,
    ) -> None:
        if not MAC_SHAPE.fullmatch(mac):
            raise ValueError(f"{mac!r} is not a MAC like {DEFAULT_MAC}")
        self.host = host
        self.username = username
        self.port = port
        self.http_port = http_port
        self.search_ports = search_ports
        self.model = model
        self.serial = serial
        self.mac = mac
        self.keepalive_interval = keepalive_interval
        self.alarm_interval = alarm_interval
        self._start_password = password
        self._restore_start_state()
        self._sessions: set[_Session] = set()
        self._handlers: set[asyncio.Task[None]] = set()
        self._ws_runner: web.AppRunner | None = None
        self._alarms: dict[str, asyncio.Task[None]] = {}
        self._reopen: asyncio.Task[None] | None = None
        # drop, reset, stop and the reopen await mid-change, so they take turns
        self._server_lock = asyncio.Lock()
        self._runner: web.AppRunner | None = None
        self._search: list[asyncio.DatagramTransport] = []
        self._http_sessions: set[str] = set()
        self._http_session_ids = itertools.count(1)

    def _restore_start_state(self) -> None:
        self.password = self._start_password
        self.params: dict[str, list[str]] = {}
        self.requests: list[list[str]] = []
        self.heartbeats = 0
        self.light_mode = 2
        self.light_control = 2
        self.light_on_time = "17:00:00"
        self.light_off_time = "07:00:00"
        self.light_power = 100
        self.sounds: list[tuple[int, int]] = []
        self.volume = 80
        self.vmd_links: list[dict[str, str]] = [
            {"id": "whiteLampForBody", "notificationMethod": "whiteLampForBody"}
        ]
        self.detection = {"person": True, "vehicle": True, "motion": False}
        self.sensitivity = 76

    @property
    def clients(self) -> int:
        return len(self._sessions)

    @property
    def lamp_on(self) -> bool:
        return (
            self.light_mode in (3, 4)
            and self.light_control == 3
            and (self.light_on_time, self.light_off_time) == ("00:00:00", "23:59:00")
        )

    @property
    def siren_on_event(self) -> bool:
        return any(link.get("notificationMethod") == "guardsound" for link in self.vmd_links)

    def identity(self) -> DiscoveredCamera:
        # no ip: the client takes the reply's source address (protocol.md, Seek reply)
        return DiscoveredCamera(
            ip="",
            mac=self.mac,
            serial=self.serial,
            model=self.model,
            http_port=self.http_port,
            server_port=self.port,
            channels=1,
        )

    async def start(self) -> tuple[str, int, int]:
        try:
            await self._open_server()
            self._runner = web.AppRunner(self._http_app(), access_log=None)
            await self._runner.setup()
            await web.TCPSite(self._runner, self.host, self.http_port).start()
            self.http_port = self._runner.addresses[0][1]
            await self._open_search()
        except BaseException:
            await self.stop()
            raise
        return self.host, self.port, self.http_port

    async def stop(self) -> None:
        for kind in list(self._alarms):
            await self._cancel_alarm(kind)
        async with self._server_lock:
            await self._cancel_reopen()
            await self._close_server()
        for transport in self._search:
            transport.close()
        self._search.clear()
        runner, self._runner = self._runner, None
        if runner is not None:
            await runner.cleanup()

    async def drop(self, seconds: float) -> None:
        async with self._server_lock:
            await self._cancel_reopen()
            await self._close_server()
            self._http_sessions.clear()
            self._reopen = asyncio.create_task(self._reopen_after(seconds))

    async def reset(self) -> None:
        for kind in list(self._alarms):
            await self._cancel_alarm(kind)
        async with self._server_lock:
            if await self._cancel_reopen() and self._ws_runner is None:
                await self._open_server()
            self._restore_start_state()

    async def push_event(self, fields: list[str]) -> None:
        for session in list(self._sessions):
            if session.logged_in:
                with contextlib.suppress(OSError, ConnectionError, RuntimeError):
                    await session.send(fields, route=_PROXY, doubled=True)

    async def start_alarm(self, kind: str) -> None:
        event_fields(kind, True)
        await self._cancel_alarm(kind)
        self._alarms[kind] = asyncio.create_task(self._repeat_alarm(kind))

    async def stop_alarm(self, kind: str) -> None:
        await self._cancel_alarm(kind)
        await self.push_event(event_fields(kind, False, self._alarm_id(kind)))

    async def _repeat_alarm(self, kind: str) -> None:
        # the camera repeats an active alarm every second (protocol.md, Start and stop)
        while True:
            await self.push_event(event_fields(kind, True, self._alarm_id(kind)))
            await asyncio.sleep(self.alarm_interval)

    async def _cancel_alarm(self, kind: str) -> None:
        task = self._alarms.pop(kind, None)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    @staticmethod
    def _alarm_id(kind: str) -> str:
        return _ALARM_ID if kind in _EVENT_NAMES else ""

    async def _open_server(self) -> None:
        app = web.Application()
        app.router.add_get("/", self._handle)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        try:
            await web.TCPSite(runner, self.host, self.port).start()
        except BaseException:
            await runner.cleanup()
            raise
        self._ws_runner = runner
        self.port = runner.addresses[0][1]

    async def _close_server(self) -> None:
        runner, self._ws_runner = self._ws_runner, None
        if runner is None:
            return
        for session in list(self._sessions):
            await session.ws.close()
        await asyncio.gather(*self._handlers, return_exceptions=True)
        await runner.cleanup()

    async def _reopen_after(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
        async with self._server_lock:
            try:
                await self._open_server()
            except OSError as exc:
                _log.warning("cannot reopen port %d after the drop: %s", self.port, exc)

    async def _cancel_reopen(self) -> bool:
        reopen, self._reopen = self._reopen, None
        if reopen is None:
            return False
        reopen.cancel()
        await asyncio.gather(reopen, return_exceptions=True)
        return True

    async def _open_search(self) -> None:
        loop = asyncio.get_running_loop()
        bound = []
        for port in self.search_ports:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SeekResponder(self), sock=_search_socket(self.host, port)
            )
            self._search.append(transport)
            bound.append(transport.get_extra_info("sockname")[1])
        self.search_ports = tuple(bound)

    async def _handle(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=0)
        await ws.prepare(request)
        session = _Session(ws)
        task = asyncio.current_task()
        assert task is not None
        self._sessions.add(session)
        self._handlers.add(task)
        buffer = bytearray()
        keepalive: asyncio.Task[None] | None = None
        try:
            async for message in ws:
                if message.type is not WSMsgType.BINARY:
                    continue
                buffer += message.data
                while (frame := _take_frame(buffer)) is not None:
                    await self._react(session, frame)
                if session.logged_in and keepalive is None:
                    keepalive = asyncio.create_task(self._keepalive(session))
        except (OSError, ConnectionError):
            pass
        finally:
            if keepalive is not None:
                keepalive.cancel()
            self._sessions.discard(session)
            self._handlers.discard(task)
        return ws

    async def _keepalive(self, session: _Session) -> None:
        # the camera sends these about every 10 s on an idle session (protocol.md, Heartbeat)
        while True:
            await asyncio.sleep(self.keepalive_interval)
            with contextlib.suppress(OSError, ConnectionError, RuntimeError):
                await session.send(
                    ["INNER", "CMD", "EXCEPTION", "0", "0"], route=_PROXY, doubled=True
                )

    async def _react(self, session: _Session, frame: Frame) -> None:
        commands = frame.commands
        if commands is None:
            return
        if not commands:
            self.heartbeats += 1
            # the real answer is unknown; any packet resets the SDK idle counter
            # (protocol.md, Camera reply)
            await session.send()
        for fields in commands:
            if fields[2:4] == ["USER", "LOGON"]:
                await self._logon(session, fields)
            elif session.logged_in:
                self.requests.append(fields)
                await self._command(session, fields)

    async def _logon(self, session: _Session, fields: list[str]) -> None:
        if not session.salt:
            session.salt = os.urandom(_SALT_BYTES)
            await session.send(
                ["INNER", "USER", "LOGONFAILED", "3", "1", "1", self._salt(session), "0", "0"]
            )
            return
        expected = [_salted(self.username, session.salt), _salted(self.password, session.salt)]
        if fields[4:6] != expected:
            await session.send(
                ["INNER", "USER", "LOGONFAILED", "2", "1", "1", self._salt(session), "1", "0"]
            )
            return
        await session.send(["INNER", "CMDID", _COMMAND_ID])
        await session.send(["INNER", "LOGON", "CHANNELDATA", "FINISHED"])
        session.logged_in = True
        await session.send(["INNER", "LOGON", "FINISHED"])
        await session.send(["INNER", "USER", "ACTIVATION", "1"], doubled=True)
        await session.send(
            ["INNER", "USER", "RESERVEPHONE", "2", "0", _OWNER_EMAIL, ""],
            ["INNER", "SUPER", "GETUSERNUM", "2"],
        )

    @staticmethod
    def _salt(session: _Session) -> str:
        return base64.b64encode(session.salt).decode("ascii")

    async def _command(self, session: _Session, fields: list[str]) -> None:
        match fields[1:]:
            case [_, *body, session_id] if session_id.isdigit():
                await self._answer(session, body, session_id)

    async def _answer(
        self, session: _Session, body: list[str], session_id: str
    ) -> None:
        ok = False
        match body:
            case ["PARAGET", name, *_] if name in self.params:
                await session.send(["INNER", "PARAGET", name, *self.params[name]])
                ok = True
            case ["PARASET", name, *values]:
                self.params[name] = values
                ok = True
        result = _OK if ok else _FAILED
        await session.send(["INNER", *body[:2], "FINISHED", session_id, result])

    def _http_app(self) -> web.Application:
        app = web.Application(middlewares=[self._require_session])
        app.add_routes(
            [
                web.get(_SESSION_CHECK, self._session_check),
                web.post(_LOGON, self._http_logon),
                web.get(_DEVICE_INFO, self._device_info),
                web.post(_CAPABILITIES, self._capabilities),
                web.get(_LIGHT, self._get_light),
                web.put(_LIGHT, self._put_light),
                web.get(_MODE, self._get_mode),
                web.put(_MODE, self._put_mode),
                web.get(_DETECTION, self._get_detection),
                web.put(_DETECTION, self._put_detection),
                web.put(_PLAY_AUDIO, self._play_audio),
                web.get(_TWO_WAY_AUDIO, self._get_audio),
                web.put(_TWO_WAY_AUDIO, self._put_audio),
                web.get(_VMD_TRIGGER, self._get_vmd),
                web.put(_VMD_TRIGGER, self._put_vmd),
            ]
        )
        return app

    @web.middleware
    async def _require_session(
        self, request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        if (
            request.path in (_SESSION_CHECK, _LOGON)
            or request.headers.get("HttpSession") in self._http_sessions
        ):
            return await handler(request)
        return web.Response(status=401)

    async def _session_check(self, request: web.Request) -> web.Response:
        return _xml(
            f"<SessionCheck><session>{_TEMP_SESSION}</session><key>{_KEY}</key>"
            f"<iterations>{_ROUNDS}</iterations></SessionCheck>"
        )

    async def _http_logon(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "User")
        accepted = fields.get("passwd") == self._expected_passwd()
        session = ""
        if accepted:
            # never reused, so a session dropped by drop() stays dead
            session = f"SESSION-{next(self._http_session_ids)}"
            self._http_sessions.add(session)
        status = "OK" if accepted else "PASSWD ERROR"
        return _xml(
            f"<UserLogon><statusString>{status}</statusString>"
            "<statusValue>200</statusValue><passwdLeftValue>5</passwdLeftValue>"
            f"<session>{session}</session></UserLogon>"
        )

    def _expected_passwd(self) -> str:
        # SHA-256 chain (protocol.md, Authentication)
        digest = _sha256(self.username + self.password)
        for _ in range(_ROUNDS):
            digest = _sha256(digest + _KEY)
        return digest

    async def _device_info(self, request: web.Request) -> web.Response:
        return _xml(_DEVICE_INFO_XML)

    async def _capabilities(self, request: web.Request) -> web.Response:
        query = await request.text()
        if _SOUND_QUERY in query:
            return _xml(_SOUND_CAPS_XML)
        if _MOTION_QUERY in query:
            return _xml(_CAPABILITIES_XML)
        raise web.HTTPNotFound(text="this capability query is not simulated")

    async def _get_light(self, request: web.Request) -> web.Response:
        return _xml(
            _LIGHT_XML.format(
                control=self.light_control,
                on=self.light_on_time,
                off=self.light_off_time,
                power=self.light_power,
            )
        )

    async def _put_light(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "WhiteLight")
        control = _number(fields, "contrltype")
        if control not in _LIGHT_CONTROLS:
            return _xml(_DEVICE_ERROR)
        self.light_control = control
        self.light_on_time = fields.get("sunSetTime", self.light_on_time)
        self.light_off_time = fields.get("sunRiseTime", self.light_off_time)
        if "infraredLampPower" in fields:
            self.light_power = _number(fields, "infraredLampPower")
        return _xml(_WRITE_OK)

    async def _get_mode(self, request: web.Request) -> web.Response:
        return _xml(_MODE_XML.format(self.light_mode))

    async def _put_mode(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "CommonEnable")
        self.light_mode = _number(fields, "value")
        # measured on the I91FX: infrared and smart turn the lamp off, color and custom to auto
        self.light_control = 2 if self.light_mode in (1, 2) else 0
        return _xml(_WRITE_OK)

    async def _get_detection(self, request: web.Request) -> web.Response:
        order = ("motion", "vehicle", "person")
        flags = (_flag(self.detection[name]) for name in order)
        return _xml(_DETECTION_XML.format(*flags, self.sensitivity))

    async def _put_detection(self, request: web.Request) -> web.Response:
        root = await _read_root(request, "MotionDetection")
        fields = _children(root)
        for element, name in _DETECTION_ELEMENTS.items():
            if element in fields:
                self.detection[name] = fields[element] == "true"
        level = root.findtext(_SENSITIVITY)
        if level is not None:
            self.sensitivity = _whole(level.strip(), "sensitivityLevel")
        return _xml(_WRITE_OK)

    async def _play_audio(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "PlayAudioInfo")
        sample = _number(fields, "sampleNo")
        if not 0 <= sample < _SAMPLES:
            return _xml(_DEVICE_ERROR)
        self.sounds.append((sample, _number(fields, "action")))
        return _xml(_WRITE_OK)

    async def _get_audio(self, request: web.Request) -> web.Response:
        return _xml(_TWO_WAY_AUDIO_XML.format(self.volume))

    async def _put_audio(self, request: web.Request) -> web.Response:
        self.volume = _number(await _read_xml(request, "TwoWayAudioChannel"), "outputVolume")
        return _xml(_WRITE_OK)

    async def _get_vmd(self, request: web.Request) -> web.Response:
        links = "".join(
            "<EventTriggerNotification>"
            + "".join(f"<{tag}>{text}</{tag}>" for tag, text in link.items())
            + "</EventTriggerNotification>"
            for link in self.vmd_links
        )
        return _xml(
            "<EventTrigger><id>VMD</id><enabled>true</enabled><eventType></eventType>"
            f"<EventTriggerNotificationList>{links}</EventTriggerNotificationList></EventTrigger>"
        )

    async def _put_vmd(self, request: web.Request) -> web.Response:
        root = await _read_root(request, "EventTrigger")
        self.vmd_links = [_children(link) for link in root.iter("EventTriggerNotification")]
        return _xml(_WRITE_OK)


def _search_socket(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # a socket bound to one address never receives the multicast seek
        sock.bind(("", port))
        for group, exc in join_groups(sock, host).items():
            _log.warning("cannot join %s on UDP %d: %s", group, port, exc)
    except BaseException:
        sock.close()
        raise
    return sock


def _camera_frame(
    commands: tuple[list[str], ...], seq: int, route: str, doubled: bool
) -> bytes:
    if not commands:
        return build_command([], seq)
    first, *rest = commands
    # later commands omit the device ip and route (protocol.md, Delimiting messages)
    payload = b"".join(encode_fields(fields) for fields in [[_DEVICE_IP, route, *first], *rest])
    # alarms, idle messages and USER ACTIVATION end with the terminator twice (protocol.md)
    return pack_command(payload + TERMINATOR if doubled else payload, seq)


def _take_frame(buffer: bytearray) -> Frame | None:
    while True:
        try:
            frame, used = parse_frame(bytes(buffer))
        except ProtocolError:
            del buffer[:1]
            continue
        del buffer[:used]
        return frame


def _salted(value: str, salt: bytes) -> str:
    digest = hashlib.md5(value.encode() + salt, usedforsecurity=False).digest()
    return base64.b64encode(digest).decode("ascii")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest().upper()


def _xml(body: str) -> web.Response:
    return web.Response(text=body, content_type="application/xml", charset="utf-8")


def _flag(value: bool) -> str:
    return "true" if value else "false"


async def _read_root(request: web.Request, root: str) -> ET.Element:
    try:
        element = ET.fromstring(await request.read())
    except ET.ParseError:
        raise web.HTTPBadRequest(text="the body is not XML") from None
    if element.tag != root:
        raise web.HTTPBadRequest(text=f"expected a {root} body")
    return element


async def _read_xml(request: web.Request, root: str) -> dict[str, str]:
    return _children(await _read_root(request, root))


def _children(element: ET.Element) -> dict[str, str]:
    return {child.tag: (child.text or "").strip() for child in element}


def _number(fields: dict[str, str], name: str) -> int:
    return _whole(fields.get(name, ""), name)


def _whole(text: str, name: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise web.HTTPBadRequest(text=f"{name} is missing or not a number") from None
