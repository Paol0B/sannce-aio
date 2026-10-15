import asyncio
import contextlib
import hashlib
import io
import logging
import re
import struct
import wave
from collections.abc import Callable
from urllib.parse import urlsplit

from .audio import decode_alaw, decode_ulaw

_log = logging.getLogger(__name__)

_REALM = "RTSP"
_NONCE = "5e4d3c2b1a"
_BACKCHANNEL = "www.onvif.org/ver20/backchannel"
_TRACK = "trackID=bc"
_RATE = 8000
_RTP_HEADER = 12
_DECODERS: dict[int, Callable[[bytes], bytes]] = {8: decode_alaw, 0: decode_ulaw}
_BUSY = "453 Not Enough Bandwidth"
_REFUSED = "503 Service Unavailable"
_BAD_GATEWAY = "502 Bad Gateway"
_REPEATED = "455 Method Not Valid in This State"


def _backchannel_sdp(control: str) -> str:
    return (
        "m=audio 0 RTP/AVP 8 0\r\nc=IN IP4 0.0.0.0\r\na=sendonly\r\n"
        f"a=control:{control}\r\na=rtpmap:8 PCMA/8000/1\r\na=rtpmap:0 PCMU/8000/1\r\n"
    )


class _UpstreamError(Exception):
    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


class RtspFront:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        upstream_host: str,
        upstream_port: int,
        username: str,
        password: str,
    ) -> None:
        self.host = host
        self.port = port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.username = username
        self.password = password
        self._start_password = password
        self.busy = False
        self._speakers = 0
        self._audio: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._clients: set[asyncio.Task[None]] = set()

    @property
    def speaking(self) -> bool:
        return self._speakers > 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        for task in list(self._clients):
            task.cancel()
        await asyncio.gather(*self._clients, return_exceptions=True)
        await server.wait_closed()

    def reset(self) -> None:
        self.busy = False
        self.password = self._start_password
        self._audio = []

    def wav(self) -> bytes:
        output = io.BytesIO()
        with wave.open(output, "wb") as file:
            file.setnchannels(1)
            file.setsampwidth(2)
            file.setframerate(_RATE)
            file.writeframes(b"".join(self._audio))
        return output.getvalue()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._clients.add(task)
        try:
            await _Client(self, reader, writer).run()
        finally:
            self._clients.discard(task)

    def _start_speaking(self) -> None:
        self._speakers += 1
        self._audio = []

    def _stop_speaking(self) -> None:
        self._speakers -= 1

    def _record(self, packet: bytes) -> None:
        if len(packet) <= _RTP_HEADER:
            return
        decode = _DECODERS.get(packet[1] & 0x7F)
        if decode is None:
            return
        start = _RTP_HEADER + 4 * (packet[0] & 0x0F)
        self._audio.append(decode(packet[start:]))

    def authorized(self, method: str, header: str) -> bool:
        if not header.startswith("Digest "):
            return False
        parts = dict(re.findall(r'(\w+)="?([^",]*)"?', header[7:]))
        ha1 = _md5(f"{self.username}:{_REALM}:{self.password}")
        ha2 = _md5(f"{method}:{parts.get('uri', '')}")
        return parts.get("username") == self.username and parts.get("response") == _md5(
            f"{ha1}:{_NONCE}:{ha2}"
        )


class _Client:
    def __init__(
        self, front: RtspFront, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.front = front
        self.reader = reader
        self.writer = writer
        self.lock = asyncio.Lock()
        self.upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self.session = "4711"
        self.upstream_session: str | None = None
        self.channel: int | None = None
        self.tracks: set[str] = set()
        self.relay: asyncio.Task[None] | None = None

    async def run(self) -> None:
        try:
            while True:
                first = await self.reader.readexactly(1)
                if first == b"$":
                    channel, length = struct.unpack("!BH", await self.reader.readexactly(3))
                    packet = await self.reader.readexactly(length)
                    if channel == self.channel:
                        self.front._record(packet)
                    continue
                head = first + await self.reader.readuntil(b"\r\n\r\n")
                method, url, headers = _parse_request(head)
                await self.reader.readexactly(int(headers.get("content-length", "0")))
                await self._answer(method, url, headers)
        except (
            asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError
        ):
            pass
        finally:
            await self._close()

    async def _answer(self, method: str, url: str, headers: dict[str, str]) -> None:
        cseq = headers.get("cseq", "0")
        try:
            await self._dispatch(cseq, method, url, headers)
        except _UpstreamError as err:
            await self._reply(cseq, err.status, {})

    async def _dispatch(
        self, cseq: str, method: str, url: str, headers: dict[str, str]
    ) -> None:
        if not self.front.authorized(method, headers.get("authorization", "")):
            await self._reply(
                cseq, "401 Unauthorized",
                {"WWW-Authenticate": f'Digest realm="{_REALM}", nonce="{_NONCE}"'},
            )
            return
        if method == "OPTIONS":
            await self._reply(
                cseq, "200 OK",
                {"Public": "OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER, TEARDOWN"},
            )
        elif method == "DESCRIBE":
            await self._describe(cseq, url, headers)
        elif method == "SETUP" and _track(url) in self.tracks:
            await self._reply(cseq, _REPEATED, {})
        elif method == "SETUP" and url.rstrip("/").endswith(_TRACK):
            await self._setup_backchannel(cseq, url, headers)
        elif method == "PLAY" and self.upstream_session is None:
            # backchannel only: mediamtx would refuse a PLAY without a SETUP
            await self._reply(cseq, "200 OK", {"Session": self.session})
        elif method in ("SETUP", "PLAY"):
            await self._forward(cseq, method, url, headers)
        elif method == "TEARDOWN":
            await self._reply(cseq, "200 OK", {"Session": self.session})
            raise ConnectionError("teardown")
        else:
            await self._reply(cseq, "200 OK", {"Session": self.session})

    async def _describe(self, cseq: str, url: str, headers: dict[str, str]) -> None:
        status, _, body = await self._upstream("DESCRIBE", url, {"Accept": "application/sdp"})
        if not status.startswith("200"):
            await self._reply(cseq, status, {})
            return
        base = url.rstrip("/")
        body = body.replace(self._upstream_base(), self._client_base(url))
        if _BACKCHANNEL in headers.get("require", ""):
            body = body.rstrip("\r\n") + "\r\n" + _backchannel_sdp(f"{base}/{_TRACK}")
        await self._reply(
            cseq, "200 OK",
            {"Content-Type": "application/sdp", "Content-Base": f"{base}/"},
            body,
        )

    async def _setup_backchannel(
        self, cseq: str, url: str, headers: dict[str, str]
    ) -> None:
        if self.front.busy:
            await self._reply(cseq, _BUSY, {})
            return
        transport = headers.get("transport", "")
        match = re.search(r"interleaved=(\d+)", transport)
        if match is None:
            await self._reply(cseq, "461 Unsupported Transport", {})
            return
        self.front._start_speaking()
        self.channel = int(match.group(1))
        self.tracks.add(_track(url))
        await self._reply(cseq, "200 OK", {"Transport": transport, "Session": self.session})

    async def _forward(self, cseq: str, method: str, url: str, headers: dict[str, str]) -> None:
        extra: dict[str, str] = {
            name: headers[name] for name in ("transport", "range") if name in headers
        }
        status, upstream_headers, body = await self._upstream(method, url, extra)
        reply = {
            name: upstream_headers[name.lower()]
            for name in ("Transport", "Session", "RTP-Info", "Range")
            if name.lower() in upstream_headers
        }
        if "Session" in reply:
            self.upstream_session = self.session = reply["Session"].split(";")[0]
        if method == "SETUP" and status.startswith("200"):
            self.tracks.add(_track(url))
        await self._reply(cseq, status, reply, body)
        if method == "PLAY" and status.startswith("200") and self.relay is None:
            self.relay = asyncio.create_task(self._relay())

    async def _upstream(
        self, method: str, url: str, extra: dict[str, str]
    ) -> tuple[str, dict[str, str], str]:
        try:
            return await self._exchange(method, url, extra)
        except (
            OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError
        ) as err:
            _log.warning(
                "rtsp upstream %s:%s failed: %r",
                self.front.upstream_host, self.front.upstream_port, err,
            )
            self._drop_upstream()
            refused = isinstance(err, ConnectionRefusedError)
            raise _UpstreamError(_REFUSED if refused else _BAD_GATEWAY) from None

    async def _exchange(
        self, method: str, url: str, extra: dict[str, str]
    ) -> tuple[str, dict[str, str], str]:
        if self.upstream is None:
            self.upstream = await asyncio.open_connection(
                self.front.upstream_host, self.front.upstream_port
            )
        reader, writer = self.upstream
        target = self._upstream_base() + urlsplit(url).path
        lines = [f"{method} {target} RTSP/1.0", "CSeq: 1"]
        lines += [f"{name.title()}: {value}" for name, value in extra.items()]
        if self.upstream_session is not None:
            lines.append(f"Session: {self.upstream_session}")
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        start, *rest = head.decode("latin-1").strip().split("\r\n")
        status = start.partition(" ")[2]
        if not status:
            raise ValueError(f"bad status line {start!r}")
        headers = {
            name.strip().lower(): value.strip()
            for name, _, value in (line.partition(":") for line in rest)
        }
        body = await reader.readexactly(int(headers.get("content-length", "0")))
        return status, headers, body.decode("utf-8", "replace")

    def _drop_upstream(self) -> None:
        upstream, self.upstream = self.upstream, None
        self.upstream_session = None
        if upstream is not None:
            upstream[1].close()

    async def _relay(self) -> None:
        assert self.upstream is not None
        reader = self.upstream[0]
        try:
            while True:
                first = await reader.readexactly(1)
                if first != b"$":
                    await reader.readuntil(b"\r\n\r\n")
                    continue
                head = await reader.readexactly(3)
                packet = await reader.readexactly(struct.unpack("!xH", b"\0" + head[1:])[0])
                async with self.lock:
                    self.writer.write(first + head + packet)
                    await self.writer.drain()
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as err:
            _log.info(
                "rtsp upstream %s:%s ended the stream: %r",
                self.front.upstream_host, self.front.upstream_port, err,
            )
        finally:
            self.writer.close()

    async def _reply(
        self, cseq: str, status: str, headers: dict[str, str], body: str = ""
    ) -> None:
        lines = [f"RTSP/1.0 {status}", f"CSeq: {cseq}"]
        lines += [f"{name}: {value}" for name, value in headers.items()]
        payload = body.encode()
        if payload:
            lines.append(f"Content-Length: {len(payload)}")
        async with self.lock:
            self.writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + payload)
            await self.writer.drain()

    def _upstream_base(self) -> str:
        return f"rtsp://{self.front.upstream_host}:{self.front.upstream_port}"

    @staticmethod
    def _client_base(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    async def _close(self) -> None:
        if self.channel is not None:
            self.channel = None
            self.front._stop_speaking()
        if self.relay is not None:
            self.relay.cancel()
            await asyncio.gather(self.relay, return_exceptions=True)
        if self.upstream is not None:
            self.upstream[1].close()
        self.writer.close()
        with contextlib.suppress(OSError, ConnectionError):
            await self.writer.wait_closed()


def _parse_request(head: bytes) -> tuple[str, str, dict[str, str]]:
    start, *lines = head.decode("latin-1").strip().split("\r\n")
    method, url, _ = start.split(" ")
    headers = {
        name.strip().lower(): value.strip()
        for name, _, value in (line.partition(":") for line in lines)
    }
    return method, url, headers


def _track(url: str) -> str:
    return urlsplit(url).path.rstrip("/")


def _md5(text: str) -> str:
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()
