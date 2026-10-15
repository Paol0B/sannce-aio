import asyncio
import contextlib
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_log = logging.getLogger(__name__)

_READ_SIZE = 0x10000
_MAX_HEAD = 0x10000
_MAX_BODY = 0x10000
_CLOSE_SECONDS = 2.0
_HEAD_END = b"\r\n\r\n"
_FRAME = ord("$")
# go2rtc reads text with these starts as RTSP and skips other bytes up to the next frame
_TEXT_STARTS = frozenset(b"RTSP OPTI DESC SETU PLAY PAUS TEAR GET_ SET_ ANNO RECO".split())


@dataclass(frozen=True)
class _Head:
    words: list[str]
    headers: dict[str, str]
    length: int

    @property
    def is_reply(self) -> bool:
        return self.words[0].startswith("RTSP/")

    @property
    def uri(self) -> str:
        return self.words[1] if len(self.words) > 1 else ""

    @property
    def status(self) -> str:
        return self.words[1] if len(self.words) > 1 else ""


@dataclass
class _Forwarded:
    cseq: str
    track: str | None
    after: list[bytes] = field(default_factory=list)


class RtspRelay:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        listen_host: str = "127.0.0.1",
        timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._port = port
        self._listen_host = listen_host
        self._timeout = timeout
        self._server: asyncio.Server | None = None
        self._bound = 0
        self._connections: dict[asyncio.Task[None], list[asyncio.StreamWriter]] = {}

    @property
    def port(self) -> int:
        return self._bound

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._listen_host, 0)
        self._bound = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        tasks = list(self._connections)
        for task, writers in self._connections.items():
            task.cancel()
            for writer in writers:
                writer.transport.abort()
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_CLOSE_SECONDS):
                await asyncio.gather(*tasks, return_exceptions=True)
                await server.wait_closed()

    async def _handle(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        writers = [client_writer]
        self._connections[task] = writers
        task.add_done_callback(self._connections.pop)
        try:
            await self._relay(client_reader, client_writer, writers)
        finally:
            await _shut(client_writer)

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        writers: list[asyncio.StreamWriter],
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        try:
            camera_reader, camera_writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), self._timeout
            )
        except (OSError, TimeoutError) as err:
            _log.debug(
                "relay for %s cannot reach %s:%s: %r", peer, self._host, self._port, err
            )
            return
        writers.append(camera_writer)
        link = _Link(peer, client_writer, camera_writer)
        pumps = (
            asyncio.create_task(
                _pump("client to camera", client_reader, link.from_client, camera_writer)
            ),
            asyncio.create_task(
                _pump("camera to client", camera_reader, link.from_camera, client_writer)
            ),
        )
        try:
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            _log.debug(
                "relay for %s to %s:%s ended: %s",
                peer, self._host, self._port, done.pop().result(),
            )
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            await _shut(camera_writer)


class _Link:
    def __init__(
        self, peer: object, client: asyncio.StreamWriter, camera: asyncio.StreamWriter
    ) -> None:
        self._peer = peer
        self._client = client
        self._camera = camera
        self._tracks: dict[str, dict[str, str]] = {}
        self._pending: list[_Forwarded] = []

    def from_client(self, buffer: bytearray) -> int:
        sent = done = 0
        for start, end, head in _split(buffer):
            done = end
            if head is None or head.is_reply:
                continue
            reply = self._request(head)
            if reply is None:
                continue
            if start > sent:
                self._camera.write(buffer[sent:start])
            sent = end
            self._answer(reply)
        if done > sent:
            self._camera.write(buffer[sent:done])
        return done

    def from_camera(self, buffer: bytearray) -> int:
        sent = done = 0
        for _, end, head in _split(buffer):
            done = end
            if head is None or not head.is_reply:
                continue
            waiting = self._answered(head)
            if waiting:
                self._client.write(buffer[sent:end])
                self._client.writelines(waiting)
                sent = end
        if done > sent:
            self._client.write(buffer[sent:done])
        return done

    def _request(self, head: _Head) -> bytes | None:
        method = head.words[0]
        path = urlsplit(head.uri).path.rstrip("/")
        known = self._tracks.get(path) if method == "SETUP" else None
        if known is not None:
            # the camera answers 455 to a second SETUP of a track (protocol.md, Backchannel)
            _log.debug("relay for %s answered a repeated SETUP of %s", self._peer, path)
            lines = ["RTSP/1.0 200 OK", f"CSeq: {head.headers.get('cseq', '0')}"]
            lines += [f"{name}: {value}" for name, value in known.items()]
            return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        if method == "TEARDOWN":
            self._tracks.clear()
        cseq = head.headers.get("cseq")
        if cseq is not None:
            self._pending.append(_Forwarded(cseq, path if method == "SETUP" else None))
        return None

    def _answer(self, reply: bytes) -> None:
        if self._pending:
            self._pending[-1].after.append(reply)
        else:
            self._client.write(reply)

    def _answered(self, head: _Head) -> list[bytes]:
        cseq = head.headers.get("cseq")
        index = next(
            (n for n, request in enumerate(self._pending) if request.cseq == cseq), None
        )
        if index is None:
            _log.debug(
                "relay for %s passed a camera reply with unknown CSeq %s", self._peer, cseq
            )
            return []
        request = self._pending.pop(index)
        if request.track is not None and head.status == "200":
            self._tracks[request.track] = {
                name: head.headers[name.lower()]
                for name in ("Session", "Transport")
                if name.lower() in head.headers
            }
        if index:
            # a held local reply still waits for the requests sent before it
            self._pending[index - 1].after += request.after
            return []
        return request.after


async def _pump(
    direction: str,
    reader: asyncio.StreamReader,
    handle: Callable[[bytearray], int],
    destination: asyncio.StreamWriter,
) -> str:
    buffer = bytearray()
    try:
        while data := await reader.read(_READ_SIZE):
            buffer += data
            del buffer[: handle(buffer)]
            await destination.drain()
    except (OSError, ValueError) as err:
        return f"{direction}: {err!r}"
    return f"{direction}: end of stream"


def _split(buffer: bytearray) -> Iterator[tuple[int, int, _Head | None]]:
    start, size = 0, len(buffer)
    while start < size:
        head = None
        if buffer[start] == _FRAME:
            if size - start < 4:
                return
            end = start + 4 + (buffer[start + 2] << 8 | buffer[start + 3])
        elif size - start < 4:
            return
        elif bytes(buffer[start : start + 4]) in _TEXT_STARTS:
            head_end = buffer.find(_HEAD_END, start, start + _MAX_HEAD)
            if head_end < 0:
                if size - start >= _MAX_HEAD:
                    raise ValueError(f"no end of an RTSP head in {_MAX_HEAD} bytes")
                return
            head = _parse_head(buffer[start:head_end].decode("latin-1"))
            end = head_end + len(_HEAD_END) + head.length
        else:
            found = buffer.find(b"$", start)
            end = size if found < 0 else found
        if end > size:
            return
        yield start, end, head
        start = end


def _parse_head(text: str) -> _Head:
    start, *lines = text.split("\r\n")
    headers = {}
    for line in lines:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    length = headers.get("content-length", "0")
    if not (length.isascii() and length.isdigit()):
        raise ValueError(f"bad Content-Length {length!r}")
    if int(length) > _MAX_BODY:
        raise ValueError(f"Content-Length {length} is above {_MAX_BODY}")
    return _Head(start.split(), headers, int(length))


async def _shut(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        async with asyncio.timeout(_CLOSE_SECONDS):
            await writer.wait_closed()
    except TimeoutError:
        writer.transport.abort()
    except OSError:
        pass
