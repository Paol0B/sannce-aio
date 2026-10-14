import asyncio
import base64
import contextlib
import hashlib
import io
import itertools
import logging
import re
import socket
import wave
import xml.etree.ElementTree as ET
from typing import cast

from aiohttp import web
from aiohttp.typedefs import Handler

from .audio import decode_alaw
from .discovery import (
    DiscoveredCamera,
    build_seek_reply,
    is_seek_request,
    join_groups,
)
from .errors import ProtocolError
from .protocol import Frame, build_command, parse_frame

_log = logging.getLogger(__name__)

DEFAULT_MODEL = "I91FW-SIM"
DEFAULT_SERIAL = "SIM0000000001"
# RFC 7042 documentation address, so it never matches a real device
DEFAULT_MAC = "00:00:5E:00:53:01"
MAC_SHAPE = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")

_READ_SIZE = 0x10000
_SEQ_WRAP = 0x10000
_DEVICE_IP = "192.168.1.10"
_ROUTE = "IP"
_COMMAND_ID = "1"
_OK = "0"
_FAILED = "1"
# one channel: 0 on the private protocol, 1 over HTTP (protocol.md, Channel numbering)
_TALK_CHANNEL = "0"
_TALK_RATE = 8000

# the channel is one raw byte, not a digit (protocol.md, Audio frame layout)
_AUDIO_PREFIX = b"NVR\x00\t" + bytes([int(_TALK_CHANNEL)]) + b"\t\x00\tNVS\x00"
_AUDIO_IP_SIZE = 4
_AUDIO_SUBHEADER_SIZE = 4

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
_TEMP_SESSION = "TMP"
_KEY = "K3Y"
_ROUNDS = 3
_MOTION_QUERY = "00125-MDMotionDetectionSubList"
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
_LIGHT_XML = (
    '<WhiteLight><contrltype opt="0,1,2,3">{}</contrltype>'
    "<infraredFarLampPower>100</infraredFarLampPower>"
    "<infraredLampPower>100</infraredLampPower><sunRiseTime>06:00:00</sunRiseTime>"
    "<sunSetTime>18:00:00</sunSetTime></WhiteLight>"
)
_MODE_XML = (
    "<CommonEnable><enable>true</enable><type>4120</type>"
    "<value>{}</value></CommonEnable>"
)
_DETECTION_XML = (
    "<MotionDetection><allEnabled>{}</allEnabled><carEnabled>{}</carEnabled>"
    "<enabled>{}</enabled></MotionDetection>"
)
_WRITE_OK = (
    "<ResponseStatus><statusCode>1</statusCode>"
    "<statusString>OK</statusString></ResponseStatus>"
)


def event_fields(kind: str, active: bool) -> list[str]:
    state = "1" if active else "0"
    if kind in _EVENT_NAMES:
        return ["INNER", "ALARM", _EVENT_NAMES[kind], _EVENT_CHANNEL, state]
    if kind in _VCA_RULES:
        rule = _VCA_RULES[kind]
        return ["INNER", "ALARM", "VCA", _EVENT_CHANNEL, state, "0", rule, *_VCA_TAIL]
    raise ValueError(f"unknown event kind {kind!r}")


class _Session:
    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        self.logged_in = False
        self.talking = False
        self._seq = 0
        self._lock = asyncio.Lock()

    async def send(self, inner: list[str]) -> None:
        fields = [_DEVICE_IP, _ROUTE, *inner] if inner else []
        async with self._lock:
            self.writer.write(build_command(fields, self._seq))
            self._seq = (self._seq + 1) % _SEQ_WRAP
            await self.writer.drain()


class _SeekResponder(asyncio.DatagramProtocol):
    def __init__(self, simulator: "CameraSimulator") -> None:
        self._simulator = simulator
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # on Python 3.11 the selector datagram transport is not a DatagramTransport
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # a dropped camera is rebooting, so it answers no search either
        if self._simulator._server is None:
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
        self._start_password = password
        self._restore_start_state()
        self._sessions: set[_Session] = set()
        self._handlers: set[asyncio.Task[None]] = set()
        self._server: asyncio.Server | None = None
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
        self.talk_frames: list[bytes] = []
        self.talk_seqs: list[int] = []
        self.light_control = 0
        self.light_mode = 1
        self.detection = {"person": True, "vehicle": True, "motion": False}
        self._talk_busy = False
        self._talk_audio: list[bytes] = []

    @property
    def clients(self) -> int:
        return len(self._sessions)

    @property
    def talking(self) -> bool:
        return any(session.talking for session in self._sessions)

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
        async with self._server_lock:
            if await self._cancel_reopen() and self._server is None:
                await self._open_server()
            self._restore_start_state()

    async def push_event(self, fields: list[str]) -> None:
        for session in list(self._sessions):
            if session.logged_in:
                with contextlib.suppress(OSError):
                    await session.send(fields)

    def set_talk_busy(self, busy: bool) -> None:
        self._talk_busy = busy

    def talk_wav(self) -> bytes:
        output = io.BytesIO()
        with wave.open(output, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(_TALK_RATE)
            # the library talks G.711 A-law only (connection._TALK_CODEC)
            wav.writeframes(decode_alaw(b"".join(self._talk_audio)))
        return output.getvalue()

    async def _open_server(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _close_server(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        for session in list(self._sessions):
            session.writer.close()
        # wait_closed() ignores open connections before Python 3.12.1
        await asyncio.gather(*self._handlers, return_exceptions=True)
        await server.wait_closed()

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

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        session = _Session(writer)
        task = asyncio.current_task()
        assert task is not None
        self._sessions.add(session)
        self._handlers.add(task)
        buffer = bytearray()
        try:
            while True:
                while (frame := _take_frame(buffer)) is not None:
                    await self._react(session, frame)
                chunk = await reader.read(_READ_SIZE)
                if not chunk:
                    return
                buffer += chunk
        except OSError:
            pass
        finally:
            self._sessions.discard(session)
            self._handlers.discard(task)
            # Server.wait_closed() waits for every connection, so close our own
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _react(self, session: _Session, frame: Frame) -> None:
        fields = frame.fields
        if fields is None:
            if session.talking and frame.payload is not None:
                self._record_audio(frame.payload, frame.seq)
        elif not fields:
            self.heartbeats += 1
            # the real answer is unknown; any packet resets the SDK idle counter
            # (protocol.md, Camera reply)
            await session.send([])
        elif fields[2:4] == ["USER", "LOGON"]:
            await self._logon(session, fields)
        elif session.logged_in:
            self.requests.append(fields)
            await self._command(session, fields)

    async def _logon(self, session: _Session, fields: list[str]) -> None:
        if not self._credentials_match(fields[4:6]):
            # the failure reply is undocumented (protocol.md, Open questions): hang up
            session.writer.close()
            return
        await session.send(["INNER", "CMDID", _COMMAND_ID])
        session.logged_in = True
        await session.send(["INNER", "LOGON", "FINISHED"])

    def _credentials_match(self, encoded: list[str]) -> bool:
        try:
            user, password = (
                base64.b64decode(item, validate=True).decode() for item in encoded
            )
        except ValueError:
            return False
        return (user, password) == (self.username, self.password)

    async def _command(self, session: _Session, fields: list[str]) -> None:
        match fields[1:]:
            case ["NVR", channel, "", "CMD", "TALK", action, *_]:
                await self._talk(session, channel, action)
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

    async def _talk(self, session: _Session, channel: str, action: str) -> None:
        reply = ["INNER", "NVR", channel, "", "CMD", "TALK", action]
        if action == "BEGIN":
            accepted = channel == _TALK_CHANNEL and not self._talk_busy
            if accepted:
                session.talking = True
                self._talk_audio = []
            await session.send([*reply, "OK" if accepted else "ERROR"])
        elif action == "END":
            session.talking = False
            await session.send([*reply, "OK"])

    def _record_audio(self, payload: bytes, seq: int) -> None:
        audio = _decode_audio(payload)
        if audio is None:
            _log.warning("undecodable talk audio packet of %d bytes", len(payload))
        else:
            self.talk_frames.append(audio)
            self.talk_seqs.append(seq)
            self._talk_audio.append(audio)

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
        if _MOTION_QUERY not in await request.text():
            raise web.HTTPNotFound(text="this capability query is not simulated")
        return _xml(_CAPABILITIES_XML)

    async def _get_light(self, request: web.Request) -> web.Response:
        return _xml(_LIGHT_XML.format(self.light_control))

    async def _put_light(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "WhiteLight")
        self.light_control = _number(fields, "contrltype")
        return _xml(_WRITE_OK)

    async def _get_mode(self, request: web.Request) -> web.Response:
        return _xml(_MODE_XML.format(self.light_mode))

    async def _put_mode(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "CommonEnable")
        self.light_mode = _number(fields, "value")
        return _xml(_WRITE_OK)

    async def _get_detection(self, request: web.Request) -> web.Response:
        order = ("motion", "vehicle", "person")
        return _xml(_DETECTION_XML.format(*(_flag(self.detection[n]) for n in order)))

    async def _put_detection(self, request: web.Request) -> web.Response:
        fields = await _read_xml(request, "MotionDetection")
        for element, name in _DETECTION_ELEMENTS.items():
            if element in fields:
                self.detection[name] = fields[element] == "true"
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


def _take_frame(buffer: bytearray) -> Frame | None:
    while True:
        try:
            frame, used = parse_frame(bytes(buffer))
        except ProtocolError:
            del buffer[:1]
            continue
        del buffer[:used]
        return frame


def _decode_audio(payload: bytes) -> bytes | None:
    if not payload.startswith(_AUDIO_PREFIX):
        return None
    # NVS block: byte-swapped device IP, then the sub-header 00 01 <code> 00
    start = len(_AUDIO_PREFIX) + _AUDIO_IP_SIZE
    subheader = payload[start : start + _AUDIO_SUBHEADER_SIZE]
    audio = payload[start + _AUDIO_SUBHEADER_SIZE :]
    if len(subheader) < _AUDIO_SUBHEADER_SIZE or subheader[:2] != b"\x00\x01":
        return None
    if subheader[3] != 0 or len(audio) != subheader[2] * 2:
        return None
    return audio


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest().upper()


def _xml(body: str) -> web.Response:
    return web.Response(text=body, content_type="application/xml", charset="utf-8")


def _flag(value: bool) -> str:
    return "true" if value else "false"


async def _read_xml(request: web.Request, root: str) -> dict[str, str]:
    try:
        element = ET.fromstring(await request.read())
    except ET.ParseError:
        raise web.HTTPBadRequest(text="the body is not XML") from None
    if element.tag != root:
        raise web.HTTPBadRequest(text=f"expected a {root} body")
    return {child.tag: (child.text or "").strip() for child in element}


def _number(fields: dict[str, str], name: str) -> int:
    try:
        return int(fields[name])
    except (KeyError, ValueError):
        raise web.HTTPBadRequest(text=f"{name} is missing or not a number") from None
