import asyncio
import hashlib
import os
import random
import re
import struct
from collections.abc import AsyncIterable, Callable
from urllib.parse import urljoin

from .audio import encode_alaw, encode_ulaw
from .errors import AuthError, ConnectError, ProtocolError, TalkBusyError

SAMPLE_RATE = 8000
_FRAME_SAMPLES = 160
FRAME_BYTES = 2 * _FRAME_SAMPLES
_FRAME_SECONDS = _FRAME_SAMPLES / SAMPLE_RATE
_REQUIRE = "www.onvif.org/ver20/backchannel"
# the pair the I91FX accepted on 2026-10-15 (protocol.md, Backchannel)
_CHANNEL = 4
_PCMA, _PCMU = 8, 0
_ENCODERS: dict[int, Callable[[bytes], bytes]] = {_PCMA: encode_alaw, _PCMU: encode_ulaw}
_BUSY = frozenset({453, 454, 455, 461})
_READ_SIZE = 0x10000
_CLOSE_SECONDS = 2.0


class Backchannel:
    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        username: str,
        password: str,
        *,
        timeout: float = 10.0,
        keepalive: float = 30.0,
    ) -> None:
        netloc = f"[{host}]" if ":" in host else host
        self._host = host
        self._port = port
        self._url = f"rtsp://{netloc}:{port}{path}"
        self._username = username
        self._password = password
        self._timeout = timeout
        self._keepalive = keepalive
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._cseq = 0
        self._challenge: dict[str, str] | None = None
        self._session: str | None = None
        self._payload_type = _PCMA
        self._drain: asyncio.Task[None] | None = None

    async def has_backchannel(self) -> bool:
        await self._connect()
        try:
            headers, body = await self._request(
                "DESCRIBE", self._url, {"Accept": "application/sdp"}
            )
            return _find_track(body, headers.get("content-base", self._url)) is not None
        finally:
            await self._abort()

    async def open(self) -> None:
        await self._connect()
        try:
            headers, body = await self._request(
                "DESCRIBE", self._url, {"Accept": "application/sdp"}
            )
            track = _find_track(body, headers.get("content-base", self._url))
            if track is None:
                raise ProtocolError(f"{self._url} offers no backchannel audio track")
            control, self._payload_type = track
            transport = f"RTP/AVP/TCP;unicast;interleaved={_CHANNEL}-{_CHANNEL + 1}"
            headers, _ = await self._request("SETUP", control, {"Transport": transport})
            session = headers.get("session", "").split(";")[0].strip()
            if not session:
                raise ProtocolError("the SETUP reply has no session")
            self._session = session
            await self._request("PLAY", self._url, {"Range": "npt=0.000-"})
        except BaseException:
            await self._abort()
            raise
        self._drain = asyncio.create_task(self._discard_incoming())

    async def stream(self, pcm: AsyncIterable[bytes]) -> None:
        writer = self._writer
        if writer is None or self._session is None:
            raise ConnectError("the backchannel is not open")
        encode = _ENCODERS[self._payload_type]
        loop = asyncio.get_running_loop()
        seq = random.randrange(0x10000)
        timestamp = random.randrange(0x100000000)
        ssrc = int.from_bytes(os.urandom(4), "big")
        start: float | None = None
        last_keepalive = loop.time()
        sent = 0
        buffer = bytearray()

        async def send(frame: bytes) -> None:
            nonlocal start, sent, last_keepalive
            now = loop.time()
            if start is None:
                start = now
            delay = start + sent * _FRAME_SECONDS - now
            if delay > 0:
                await asyncio.sleep(delay)
            rtp = struct.pack(
                "!BBHII",
                0x80,
                self._payload_type,
                (seq + sent) & 0xFFFF,
                (timestamp + sent * _FRAME_SAMPLES) & 0xFFFFFFFF,
                ssrc,
            ) + encode(frame)
            packet = struct.pack("!cBH", b"$", _CHANNEL, len(rtp)) + rtp
            await self._write(packet)
            sent += 1
            if loop.time() - last_keepalive >= self._keepalive:
                last_keepalive = loop.time()
                await self._write(self._request_bytes("GET_PARAMETER", self._url, {}))

        async for chunk in pcm:
            buffer += chunk
            while len(buffer) >= FRAME_BYTES:
                await send(bytes(buffer[:FRAME_BYTES]))
                del buffer[:FRAME_BYTES]
        if buffer:
            await send(bytes(buffer) + bytes(FRAME_BYTES - len(buffer)))

    async def close(self) -> None:
        if self._writer is not None and self._session is not None:
            try:
                await self._write(
                    self._request_bytes("TEARDOWN", self._url, {}), _CLOSE_SECONDS
                )
            except ConnectError:
                pass
        await self._abort()

    async def _connect(self) -> None:
        self._challenge = None
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), self._timeout
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectError(f"cannot reach {self._url}: {exc}") from exc

    async def _request(
        self, method: str, url: str, extra: dict[str, str]
    ) -> tuple[dict[str, str], str]:
        for attempt in range(2):
            await self._write(self._request_bytes(method, url, extra))
            status, headers, body = await self._response()
            if status == 401 and attempt == 0:
                challenge = _parse_challenge(headers.get("www-authenticate", ""))
                if self._challenge is None or challenge.get("stale", "").lower() == "true":
                    self._challenge = challenge
                    continue
            if status == 401:
                raise AuthError(f"{method} {url}: the camera refused the login")
            if status in _BUSY:
                raise TalkBusyError(f"the camera refused the audio channel: RTSP {status}")
            if not 200 <= status < 300:
                raise ProtocolError(f"{method} {url}: RTSP {status}")
            return headers, body
        raise AuthError(f"{method} {url}: the camera sent no usable login challenge")

    def _request_bytes(self, method: str, url: str, extra: dict[str, str]) -> bytes:
        self._cseq += 1
        lines = [f"{method} {url} RTSP/1.0", f"CSeq: {self._cseq}", f"Require: {_REQUIRE}"]
        lines += [f"{name}: {value}" for name, value in extra.items()]
        if self._session is not None:
            lines.append(f"Session: {self._session}")
        if self._challenge is not None:
            lines.append(f"Authorization: {self._authorization(method, url)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def _authorization(self, method: str, uri: str) -> str:
        assert self._challenge is not None
        realm = self._challenge.get("realm", "")
        nonce = self._challenge.get("nonce", "")
        ha1 = _md5(f"{self._username}:{realm}:{self._password}")
        ha2 = _md5(f"{method}:{uri}")
        fields = [
            f'username="{self._username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
        ]
        if "auth" in self._challenge.get("qop", "").split(","):
            cnonce = os.urandom(8).hex()
            nc = f"{self._cseq:08x}"
            response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
            fields += [f'response="{response}"', "qop=auth", f"nc={nc}", f'cnonce="{cnonce}"']
        else:
            fields.append(f'response="{_md5(f"{ha1}:{nonce}:{ha2}")}"')
        return "Digest " + ", ".join(fields)

    async def _response(self) -> tuple[int, dict[str, str], str]:
        reader = self._reader
        if reader is None:
            raise ConnectError("the backchannel is not open")
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self._timeout)
            start, *lines = head.decode("latin-1").strip().split("\r\n")
            headers = {
                name.strip().lower(): value.strip()
                for name, _, value in (line.partition(":") for line in lines)
            }
            length = int(headers.get("content-length", "0"))
            body = await asyncio.wait_for(reader.readexactly(length), self._timeout)
        except (
            OSError,
            TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ) as exc:
            raise ConnectError(f"no RTSP reply from {self._url}: {exc}") from exc
        except ValueError as exc:
            raise ProtocolError(f"bad RTSP reply from {self._url}: {exc}") from exc
        match start.split(" ", 2):
            case ["RTSP/1.0", code, *_] if code.isdigit():
                return int(code), headers, body.decode("utf-8", "replace")
        raise ProtocolError(f"bad RTSP status line from {self._url}: {start!r}")

    async def _write(self, data: bytes, timeout: float | None = None) -> None:
        writer = self._writer
        if writer is None:
            raise ConnectError("the backchannel is not open")
        seconds = self._timeout if timeout is None else timeout
        try:
            async with asyncio.timeout(seconds):
                writer.write(data)
                await writer.drain()
        except TimeoutError as exc:
            writer.transport.abort()
            raise ConnectError(f"the camera took no data for {seconds:g} s") from exc
        except (OSError, ConnectionError) as exc:
            raise ConnectError(f"backchannel send failed: {exc}") from exc

    async def _discard_incoming(self) -> None:
        reader = self._reader
        while reader is not None:
            try:
                if not await reader.read(_READ_SIZE):
                    return
            except (OSError, ConnectionError):
                return

    async def _abort(self) -> None:
        drain, self._drain = self._drain, None
        if drain is not None:
            drain.cancel()
            await asyncio.gather(drain, return_exceptions=True)
        writer, self._writer = self._writer, None
        self._reader = None
        self._session = None
        if writer is not None:
            writer.close()
            try:
                async with asyncio.timeout(_CLOSE_SECONDS):
                    await writer.wait_closed()
            except TimeoutError:
                writer.transport.abort()
            except (OSError, ConnectionError):
                pass


def _find_track(sdp: str, base: str) -> tuple[str, int] | None:
    for section in re.split(r"\r?\n(?=m=)", sdp):
        lines = section.splitlines()
        if not lines or not lines[0].startswith("m=audio") or "a=sendonly" not in lines:
            continue
        offered = lines[0].split()[3:]
        payload_type = next((pt for pt in (_PCMA, _PCMU) if str(pt) in offered), None)
        if payload_type is None:
            raise ProtocolError(f"the backchannel offers no G.711 codec: {lines[0]!r}")
        control = next(
            (line.removeprefix("a=control:") for line in lines if line.startswith("a=control:")),
            "",
        )
        if not control.startswith("rtsp://"):
            control = urljoin(base if base.endswith("/") else base + "/", control)
        return control, payload_type
    return None


def _parse_challenge(header: str) -> dict[str, str]:
    if not header.lower().startswith("digest "):
        raise AuthError(f"the camera asks for an unsupported login: {header!r}")
    return {name.lower(): value for name, value in re.findall(r'(\w+)="?([^",]*)"?', header[7:])}


def _md5(text: str) -> str:
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
