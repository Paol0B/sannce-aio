import asyncio
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import aiohttp

from .errors import AuthError, ConnectError, ProtocolError

# same limits as the app (protocol.md, HTTP API)
_TIMEOUT = aiohttp.ClientTimeout(sock_connect=6, sock_read=60)
_XML = {"Content-Type": "application/xml; charset=utf-8"}
_DENIED = (401, 403)

_SESSION_CHECK = "/CGI/Security/SessionCheck"
_LOGON = "/CGI/Security/Logon"
_USER_CHECK = "/ISAPI/Security/userCheck"
_DEVICE_INFO = "/CGI/System/deviceInfo"
_LIGHT = "/ISAPI/Image/channels/{}/WhiteLight"
_MODE = "/CGI/System/CommonEnable/channels/{}/Type/4120"
_DETECTION = "/ISAPI/System/Video/inputs/channels/{}/motionDetection"
_CAPABILITIES = "/CGI/System/channels/{}/capabilities"

_PERSON_VEHICLE_MOTION_QUERY = (
    "<CapDiscription><capType><mainType>015-AlarmParam</mainType>"
    "<subType>00125-MDMotionDetectionSubList</subType></capType></CapDiscription>"
)

_AUTO = 0
_MANUAL_ON = 1
_MODE_VALUES = {"infrared": 1, "smart": 2, "color": 3}
# 4 is the user-defined fill: readable, not settable (protocol.md, Light mode)
_MODE_NAMES = {1: "infrared", 2: "smart", 3: "color", 4: "custom"}


@dataclass(frozen=True)
class LightState:
    control: int
    options: tuple[int, ...] = ()
    power: int | None = None
    far_power: int | None = None
    on_time: str | None = None
    off_time: str | None = None

    @property
    def on(self) -> bool:
        return self.control == _MANUAL_ON


@dataclass(frozen=True)
class Detection:
    person: bool
    vehicle: bool
    motion: bool


class HttpClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 80,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        netloc = f"[{host}]" if ":" in host else host
        self._base_url = f"http://{netloc}:{port}"
        self._username = username
        self._password = password
        self._session = session
        self._owns_session = session is None
        self._login_lock = asyncio.Lock()
        self._session_id: str | None = None
        self._digest: aiohttp.DigestAuthMiddleware | None = None

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def get_light(self, *, channel: int = 1) -> LightState:
        return _light_state(await self._request("GET", _path(_LIGHT, channel)))

    async def set_light(self, on: bool, *, channel: int = 1) -> None:
        path = _path(_LIGHT, channel)
        state = _light_state(await self._request("GET", path))
        # off returns to auto, not manual off, so smart mode can still light up
        control = _MANUAL_ON if on else _AUTO
        await self._write(path, _light_body(state, control))

    async def get_light_mode(self, *, channel: int = 1) -> str:
        raw = await self._request("GET", _path(_MODE, channel))
        value = _int(_parse(raw, "CommonEnable"), "value")
        if value not in _MODE_NAMES:
            raise ProtocolError(f"unknown light mode value {value}")
        return _MODE_NAMES[value]

    async def set_light_mode(self, mode: str, *, channel: int = 1) -> None:
        if mode not in _MODE_VALUES:
            raise ValueError(
                f"light mode must be infrared, color or smart, got {mode!r}"
            )
        body = _xml(
            "CommonEnable",
            [("enable", "true"), ("type", 4120), ("value", _MODE_VALUES[mode])],
        )
        await self._write(_path(_MODE, channel), body)

    async def get_detection(self, *, channel: int = 1) -> Detection:
        raw = await self._request("GET", _path(_DETECTION, channel))
        root = _parse(raw, "MotionDetection")
        return Detection(
            person=_flag(root, "enabled"),
            vehicle=_flag(root, "carEnabled"),
            motion=_flag(root, "allEnabled"),
        )

    async def set_detection(
        self,
        *,
        person: bool | None = None,
        vehicle: bool | None = None,
        motion: bool | None = None,
        channel: int = 1,
    ) -> None:
        path = _path(_DETECTION, channel)
        changes = {"enabled": person, "carEnabled": vehicle, "allEnabled": motion}
        changes = {name: value for name, value in changes.items() if value is not None}
        if not changes:
            return
        root = _parse(await self._request("GET", path), "MotionDetection")
        for name, value in changes.items():
            element = root.find(name)
            if element is None:
                element = ET.SubElement(root, name)
            element.text = "true" if value else "false"
        await self._write(path, _serialize(root))

    async def get_capabilities(self, *, channel: int = 1) -> dict[str, bool]:
        raw = await self._request(
            "POST", _path(_CAPABILITIES, channel), _PERSON_VEHICLE_MOTION_QUERY
        )
        root = _parse(raw, "ChanBasicCapList")
        found = {
            kind.text.strip()
            for cap in root.iter("capTypeList")
            if _flag(cap, "support")
            for kind in cap.iterfind("subCap/supportType")
            if kind.text
        }
        return {
            "person": "people" in found,
            "vehicle": "car" in found,
            "motion": "all" in found,
        }

    async def get_device_info(self) -> dict[str, str | None]:
        # the bean carries firmware only; model, serial and mac are absent on this
        # camera but kept here best-effort for devices that do send them (protocol.md)
        root = _parse(await self._request("GET", _DEVICE_INFO), "DeviceInfo")
        return {
            "model": _text(root, "model") or None,
            "serial": _text(root, "serialNumber") or None,
            "firmware": _text(root, "firmwareVersion") or None,
            "mac": _text(root, "macAddress") or None,
        }

    async def _write(self, path: str, body: str) -> None:
        _check_write(path, await self._request("PUT", path, body))

    async def _request(
        self, method: str, path: str, body: str | None = None
    ) -> bytes:
        await self._login()
        with_session = self._session_id is not None
        status, raw = await self._send(method, path, body)
        if status in _DENIED and with_session:
            self._session_id = None
            await self._login()
            status, raw = await self._send(method, path, body)
        _check_status(method, path, status)
        return raw

    async def _login(self) -> None:
        async with self._login_lock:
            if self._session_id is None and self._digest is None:
                if not await self._session_login():
                    await self._digest_login()

    async def _session_login(self) -> bool:
        status, raw = await self._send("GET", _SESSION_CHECK)
        if not 200 <= status < 300:
            return False
        try:
            check = _parse(raw, "SessionCheck")
            session = _text(check, "session")
            key = _text(check, "key")
            rounds = _int(check, "iterations")
        except ProtocolError:
            return False
        if not session or key is None or rounds is None:
            return False
        body = _xml(
            "User",
            [
                ("passwd", _logon_secret(self._username, self._password, key, rounds)),
                ("sessionTmp", session),
                ("username", self._username),
            ],
        )
        status, raw = await self._send("POST", _LOGON, body)
        _check_status("POST", _LOGON, status)
        reply = _parse(raw, "UserLogon")
        session = _text(reply, "session")
        if _text(reply, "statusString") != "OK" or not session:
            raise AuthError("the camera refused the login")
        self._session_id = session
        return True

    async def _digest_login(self) -> None:
        digest = aiohttp.DigestAuthMiddleware(self._username, self._password)
        # the app puts the credentials in the query too (protocol.md, Authentication)
        query = {"username": self._username, "passwd": self._password}
        status, raw = await self._send("GET", _USER_CHECK, query=query, digest=digest)
        _check_status("GET", _USER_CHECK, status)
        if _text(_parse(raw, "userCheck"), "statusString") != "OK":
            raise AuthError("the camera refused the login")
        self._digest = digest

    async def _send(
        self,
        method: str,
        path: str,
        body: str | None = None,
        *,
        query: dict[str, str] | None = None,
        digest: aiohttp.DigestAuthMiddleware | None = None,
    ) -> tuple[int, bytes]:
        headers = {} if body is None else dict(_XML)
        if self._session_id is not None:
            headers["HttpSession"] = self._session_id
        if self._session is None:
            self._session = aiohttp.ClientSession()
        if digest is None:
            digest = self._digest
        try:
            async with self._session.request(
                method,
                self._base_url + path,
                params=query,
                data=None if body is None else body.encode(),
                headers=headers,
                timeout=_TIMEOUT,
                middlewares=None if digest is None else (digest,),
            ) as response:
                return response.status, await response.read()
        except (aiohttp.ClientError, TimeoutError) as error:
            raise ConnectError(f"{method} {path}: {error}") from error


def _path(template: str, channel: int) -> str:
    if channel < 1:
        raise ValueError(f"HTTP channel must be 1 or more, got {channel}")
    return template.format(channel)


def _logon_secret(username: str, password: str, key: str, rounds: int) -> str:
    digest = _sha256(username + password)
    for _ in range(rounds):
        digest = _sha256(digest + key)
    return digest


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest().upper()


def _check_status(method: str, path: str, status: int) -> None:
    if status in _DENIED:
        raise AuthError(f"{method} {path}: HTTP {status}, credentials rejected")
    if not 200 <= status < 300:
        raise ProtocolError(f"{method} {path}: HTTP {status}")


def _check_write(path: str, raw: bytes) -> None:
    try:
        root = _parse(raw, "ResponseStatus")
    except ProtocolError:
        return
    fields = {
        name: text
        for name in ("statusCode", "statusString", "subStatusCode")
        if (text := _text(root, name)) is not None
    }
    if fields.get("statusCode", "1") != "1" or fields.get("statusString", "OK") != "OK":
        detail = " ".join(f"{name}={text}" for name, text in fields.items())
        raise ProtocolError(f"PUT {path} refused: {detail}")


def _parse(raw: bytes, root: str) -> ET.Element:
    try:
        element = ET.fromstring(raw)
    except ET.ParseError as error:
        raise ProtocolError(f"reply is not XML: {error}") from error
    # replies may declare a default XML namespace; match on local names
    for node in element.iter():
        node.tag = node.tag.rpartition("}")[2]
    if element.tag != root:
        raise ProtocolError(f"expected a {root} reply, got {element.tag}")
    return element


def _text(parent: ET.Element, name: str) -> str | None:
    element = parent.find(name)
    return None if element is None else (element.text or "").strip()


def _int(parent: ET.Element, name: str) -> int | None:
    text = _text(parent, name)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        raise ProtocolError(f"{name} is not a number: {text!r}") from None


def _flag(parent: ET.Element, name: str) -> bool:
    return _text(parent, name) == "true"


def _light_state(raw: bytes) -> LightState:
    root = _parse(raw, "WhiteLight")
    control = root.find("contrltype")
    if control is None:
        raise ProtocolError("WhiteLight reply has no contrltype")
    try:
        value = int(control.text or "")
        options = tuple(
            int(item) for item in control.get("opt", "").split(",") if item.strip()
        )
    except ValueError as error:
        raise ProtocolError(f"bad contrltype: {error}") from error
    return LightState(
        control=value,
        options=options,
        power=_int(root, "infraredLampPower"),
        far_power=_int(root, "infraredFarLampPower"),
        # sunSetTime switches the light on, sunRiseTime off (protocol.md, White light)
        on_time=_text(root, "sunSetTime"),
        off_time=_text(root, "sunRiseTime"),
    )


def _light_body(state: LightState, control: int) -> str:
    return _xml(
        "WhiteLight",
        [
            ("contrltype", control),
            ("infraredFarLampPower", state.far_power),
            ("infraredLampPower", state.power),
            ("sunRiseTime", state.off_time),
            ("sunSetTime", state.on_time),
        ],
    )


def _xml(tag: str, fields: list[tuple[str, object]]) -> str:
    root = ET.Element(tag)
    for name, value in fields:
        if value is not None:
            ET.SubElement(root, name).text = str(value)
    return _serialize(root)


def _serialize(root: ET.Element) -> str:
    return ET.tostring(root, encoding="unicode", short_empty_elements=False)
