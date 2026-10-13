import asyncio
import base64
import contextlib
import hashlib
import logging
import xml.etree.ElementTree as ET

from aiohttp import web

from .errors import ProtocolError
from .protocol import Frame, build_command, parse_frame

_log = logging.getLogger(__name__)

_READ_SIZE = 0x10000
_SEQ_WRAP = 0x10000
_DEVICE_IP = "192.168.1.10"
_ROUTE = "IP"
_COMMAND_ID = "1"
_OK = "0"
_FAILED = "1"
# one channel: 0 on the private protocol, 1 over HTTP (protocol.md, Channel numbering)
_TALK_CHANNEL = "0"

# the channel is one raw byte, not a digit (protocol.md, Audio frame layout)
_AUDIO_PREFIX = b"NVR\x00\t" + bytes([int(_TALK_CHANNEL)]) + b"\t\x00\tNVS\x00"
_AUDIO_IP_SIZE = 4
_AUDIO_SUBHEADER_SIZE = 4

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


class CameraSimulator:
    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        username: str = "admin",
        password: str = "admin123",
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = 0
        self.http_port = 0
        self.params: dict[str, list[str]] = {}
        self.requests: list[list[str]] = []
        self.heartbeats = 0
        self.talk_frames: list[bytes] = []
        self.talk_seqs: list[int] = []
        self.light_control = 0
        self.light_mode = 1
        self.detection = {"person": True, "vehicle": True, "motion": False}
        self._talk_busy = False
        self._sessions: set[_Session] = set()
        self._handlers: set[asyncio.Task] = set()
        self._server: asyncio.Server | None = None
        self._runner: web.AppRunner | None = None
        self._http_sessions: set[str] = set()

    @property
    def clients(self) -> int:
        return len(self._sessions)

    @property
    def talking(self) -> bool:
        return any(session.talking for session in self._sessions)

    async def start(self) -> tuple[str, int, int]:
        try:
            self._server = await asyncio.start_server(self._handle, self.host, 0)
            self.port = self._server.sockets[0].getsockname()[1]
            self._runner = web.AppRunner(self._http_app(), access_log=None)
            await self._runner.setup()
            await web.TCPSite(self._runner, self.host, 0).start()
            self.http_port = self._runner.addresses[0][1]
        except BaseException:
            await self.stop()
            raise
        return self.host, self.port, self.http_port

    async def stop(self) -> None:
        server, self._server = self._server, None
        runner, self._runner = self._runner, None
        if server is not None:
            server.close()
            for session in list(self._sessions):
                session.writer.close()
            # wait_closed() ignores open connections before Python 3.12.1
            await asyncio.gather(*self._handlers, return_exceptions=True)
            await server.wait_closed()
        if runner is not None:
            await runner.cleanup()

    async def push_event(self, fields: list[str]) -> None:
        for session in list(self._sessions):
            if session.logged_in:
                with contextlib.suppress(OSError):
                    await session.send(fields)

    def set_talk_busy(self, busy: bool) -> None:
        self._talk_busy = busy

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        session = _Session(writer)
        task = asyncio.current_task()
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
            if session.talking:
                self._record_audio(frame)
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
            await session.send([*reply, "OK" if accepted else "ERROR"])
        elif action == "END":
            session.talking = False
            await session.send([*reply, "OK"])

    def _record_audio(self, frame: Frame) -> None:
        audio = _decode_audio(frame.payload)
        if audio is None:
            _log.warning(
                "undecodable talk audio packet of %d bytes", len(frame.payload)
            )
        else:
            self.talk_frames.append(audio)
            self.talk_seqs.append(frame.seq)

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
    async def _require_session(self, request: web.Request, handler):
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
            session = f"SESSION-{len(self._http_sessions) + 1}"
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
