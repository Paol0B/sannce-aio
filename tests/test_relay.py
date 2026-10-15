import asyncio
import contextlib
import logging
import socket
import struct
from typing import NamedTuple
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

from sannce_aio import relay as relay_module
from sannce_aio.relay import RtspRelay
from sannce_aio.simulator_rtsp import RtspFront

from .rtsp_fake import FakeRtspCamera, RawClient

REQUIRE = "Require: www.onvif.org/ver20/backchannel\r\n"
TRANSPORT = "Transport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n"
SESSION = "6C7E1F0A;timeout=60"
REFUSED = "455 Method Not Valid in This State"
# more than the loopback socket buffers hold
FLOOD = struct.pack("!cBH", b"$", 0, 0xFFFF) + b"v" * 0xFFFF
FLOOD *= 512


class Frame(NamedTuple):
    channel: int
    payload: bytes


class Reply(NamedTuple):
    status: int
    headers: dict
    body: str


def frame(channel, payload):
    return struct.pack("!cBH", b"$", channel, len(payload)) + payload


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def until(predicate, timeout=2.0):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


class Peer:
    def __init__(self, writer):
        self.writer = writer
        self.requests = []
        self.frames = []
        self.tracks = set()
        self.closed = asyncio.Event()

    def send(self, data):
        self.writer.write(data)


class Camera:
    def __init__(self):
        self.peers = []
        self.port = 0
        self.hold = asyncio.Event()
        self.hold.set()
        self.held = {"GET_PARAMETER"}
        self._server = None

    @property
    def peer(self):
        return self.peers[-1]

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        self._server.close()
        for peer in self.peers:
            peer.writer.close()
        await self._server.wait_closed()

    async def _handle(self, reader, writer):
        peer = Peer(writer)
        self.peers.append(peer)
        try:
            while True:
                first = await reader.readexactly(1)
                if first == b"$":
                    channel, length = struct.unpack("!BH", await reader.readexactly(3))
                    peer.frames.append(Frame(channel, await reader.readexactly(length)))
                    continue
                head = (first + await reader.readuntil(b"\r\n\r\n")).decode()
                start, *lines = head.strip().split("\r\n")
                method, url, _ = start.split(" ")
                headers = dict(line.split(": ", 1) for line in lines)
                peer.requests.append((method, url, headers))
                if method in self.held:
                    await self.hold.wait()
                writer.write(self._reply(peer, method, url, headers).encode())
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            peer.closed.set()
            writer.close()

    @staticmethod
    def _reply(peer, method, url, headers):
        cseq = headers["CSeq"]
        path = urlsplit(url).path.rstrip("/")
        if method == "DESCRIBE":
            body = f"v=0\r\nm=audio 0 RTP/AVP 0 8\r\na=sendonly\r\na=control:{url}/trackID=3\r\n"
            return (
                f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Base: {url}/\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}"
            )
        if method == "SETUP" and path in peer.tracks:
            return f"RTSP/1.0 {REFUSED}\r\nCSeq: {cseq}\r\n\r\n"
        if method == "SETUP":
            peer.tracks.add(path)
            return (
                f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: {SESSION}\r\n"
                f"Transport: {headers['Transport']};ssrc=4B1D\r\n\r\n"
            )
        if method == "TEARDOWN":
            peer.tracks.clear()
        return f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: {SESSION}\r\n\r\n"


class Client:
    def __init__(self, reader, writer, port):
        self.reader = reader
        self.writer = writer
        self.base = f"rtsp://127.0.0.1:{port}/1/2"
        self.cseq = 0

    @classmethod
    async def connect(cls, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return cls(reader, writer, port)

    def encode(self, method, path="", extra="", url=None):
        url = url or self.base + path
        self.cseq += 1
        auth = f'Authorization: Digest username="admin", uri="{url}"\r\n'
        return f"{method} {url} RTSP/1.0\r\nCSeq: {self.cseq}\r\n{auth}{extra}\r\n".encode()

    def send(self, method, path="", extra="", url=None):
        self.writer.write(self.encode(method, path, extra, url))

    async def request(self, method, path="", extra="", url=None):
        self.send(method, path, extra, url)
        return await self.receive()

    async def receive(self):
        async with asyncio.timeout(2):
            first = await self.reader.readexactly(1)
            if first == b"$":
                channel, length = struct.unpack("!BH", await self.reader.readexactly(3))
                return Frame(channel, await self.reader.readexactly(length))
            head = (first + await self.reader.readuntil(b"\r\n\r\n")).decode()
            start, *lines = head.strip().split("\r\n")
            headers = {
                name.lower(): value for name, value in (line.split(": ", 1) for line in lines)
            }
            body = await self.reader.readexactly(int(headers.get("content-length", "0")))
        return Reply(int(start.split(" ")[1]), headers, body.decode())

    async def until_closed(self):
        return await asyncio.wait_for(self.reader.read(), 2)

    def close(self):
        self.writer.close()


@pytest_asyncio.fixture
async def camera():
    fake = Camera()
    await fake.start()
    yield fake
    await fake.stop()


@contextlib.asynccontextmanager
async def running(port, timeout=1.0):
    relay = RtspRelay("127.0.0.1", port, timeout=timeout)
    await relay.start()
    try:
        yield relay
    finally:
        await relay.close()


@pytest_asyncio.fixture
async def relay(camera):
    async with running(camera.port) as started:
        yield started


@pytest_asyncio.fixture
async def client(relay):
    connected = await Client.connect(relay.port)
    yield connected
    connected.close()


def setups(camera):
    return [url for method, url, _ in camera.peer.requests if method == "SETUP"]


async def test_a_repeated_setup_is_answered_by_the_relay(camera, client):
    described = await client.request("DESCRIBE", extra=REQUIRE)
    first = await client.request("SETUP", "/trackID=3", TRANSPORT)
    second = await client.request("SETUP", "/trackID=3", TRANSPORT)

    assert described.headers["content-base"] == client.base + "/"
    assert (first.status, second.status) == (200, 200)
    assert second.headers["cseq"] == "3"
    assert second.headers["session"] == first.headers["session"] == SESSION
    assert second.headers["transport"] == first.headers["transport"]
    assert first.headers["transport"].endswith(";ssrc=4B1D")
    assert setups(camera) == [client.base + "/trackID=3"]


async def test_requests_reach_the_camera_unchanged(camera, client):
    await client.request("DESCRIBE", extra=REQUIRE)

    method, url, headers = camera.peer.requests[0]
    assert (method, url) == ("DESCRIBE", client.base)
    assert headers["Authorization"] == f'Digest username="admin", uri="{client.base}"'
    assert headers["Require"] == "www.onvif.org/ver20/backchannel"


async def test_a_track_is_known_by_its_path_alone(camera, client):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    other_host = await client.request(
        "SETUP", extra=TRANSPORT, url="rtsp://localhost:554/1/2/trackID=3/"
    )
    other_track = await client.request("SETUP", "/trackID=1", TRANSPORT)

    assert (other_host.status, other_track.status) == (200, 200)
    assert setups(camera) == [client.base + "/trackID=3", client.base + "/trackID=1"]


async def test_a_setup_sent_before_the_first_answer_goes_to_the_camera(camera, client):
    client.send("SETUP", "/trackID=3", TRANSPORT)
    client.send("SETUP", "/trackID=3", TRANSPORT)
    first, second = await client.receive(), await client.receive()
    third = await client.request("SETUP", "/trackID=3", TRANSPORT)

    assert (first.status, second.status, third.status) == (200, 455, 200)
    assert third.headers["session"] == SESSION
    assert len(setups(camera)) == 2


async def test_a_teardown_forgets_the_tracks(camera, client):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    await client.request("TEARDOWN")
    again = await client.request("SETUP", "/trackID=3", TRANSPORT)

    assert again.status == 200
    assert [method for method, _, _ in camera.peer.requests] == ["SETUP", "TEARDOWN", "SETUP"]


async def test_requests_split_across_reads_are_still_seen(camera, client):
    for _ in range(2):
        data = client.encode("SETUP", "/trackID=3", TRANSPORT)
        for piece in (data[:2], data[2:30], data[30:]):
            client.writer.write(piece)
            await client.writer.drain()
            await asyncio.sleep(0.02)
        assert (await client.receive()).status == 200

    assert len(setups(camera)) == 1


async def test_frames_pass_both_ways_intact(camera, client):
    await client.request("OPTIONS")
    up = [Frame(4, bytes([n]) * 160) for n in range(50)] + [Frame(5, b"\xab" * 0xFFFF)]
    down = [Frame(0, bytes([n]) * 1400) for n in range(200)] + [Frame(2, b"\xcd" * 0xFFFF)]
    sent = b"".join(frame(*item) for item in up)
    pushed = b"".join(frame(*item) for item in down)

    for piece in (sent[:2], sent[2:1000], sent[1000:]):
        client.writer.write(piece)
        await client.writer.drain()
        await asyncio.sleep(0.02)
    for piece in (pushed[:3], pushed[3:5000], pushed[5000:]):
        camera.peer.send(piece)
        await camera.peer.writer.drain()
        await asyncio.sleep(0.02)
    received = [await client.receive() for _ in down]
    await until(lambda: len(camera.peer.frames) == len(up))

    assert received == down
    assert camera.peer.frames == up


async def test_talk_frames_around_a_repeated_setup_in_one_read(camera, client):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    talk = [Frame(4, bytes([n]) * 160) for n in range(4)]
    before = b"".join(frame(*item) for item in talk[:2])
    after = b"".join(frame(*item) for item in talk[2:])

    client.writer.write(before + client.encode("SETUP", "/trackID=3", TRANSPORT) + after)
    reply = await client.receive()
    await until(lambda: len(camera.peer.frames) == len(talk))

    assert (reply.status, reply.headers["cseq"], reply.headers["session"]) == (200, "2", SESSION)
    assert camera.peer.frames == talk
    assert len(setups(camera)) == 1


async def test_a_local_reply_lands_between_two_camera_frames(camera, client):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    before, after = frame(0, b"a" * 3000), frame(0, b"b" * 3000)

    camera.peer.send(before + after[:1500])
    assert await client.receive() == Frame(0, b"a" * 3000)
    reply = await client.request("SETUP", "/trackID=3", TRANSPORT)
    camera.peer.send(after[1500:])

    assert (reply.status, reply.headers["cseq"]) == (200, "2")
    assert await client.receive() == Frame(0, b"b" * 3000)


async def test_a_local_reply_waits_for_earlier_camera_replies(camera, client):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    camera.hold.clear()

    client.send("GET_PARAMETER")
    client.send("SETUP", "/trackID=3", TRANSPORT)
    await until(lambda: camera.peer.requests[-1][0] == "GET_PARAMETER")
    await asyncio.sleep(0.05)
    camera.hold.set()
    first, second = await client.receive(), await client.receive()

    assert (first.headers["cseq"], second.headers["cseq"]) == ("2", "3")
    assert "transport" in second.headers


async def test_a_reply_with_an_unknown_cseq_passes_and_releases_nothing(
    camera, client, caplog
):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    camera.hold.clear()
    client.send("GET_PARAMETER")
    client.send("SETUP", "/trackID=3", TRANSPORT)
    await until(lambda: camera.peer.requests[-1][0] == "GET_PARAMETER")
    stray = b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n"

    with caplog.at_level(logging.DEBUG, logger="sannce_aio.relay"):
        camera.peer.send(stray)
        assert await asyncio.wait_for(client.reader.readexactly(len(stray)), 2) == stray
        await asyncio.sleep(0.05)
    camera.hold.set()
    first, second = await client.receive(), await client.receive()

    assert (first.headers["cseq"], second.headers["cseq"]) == ("2", "3")
    assert any("CSeq 9" in record.getMessage() for record in caplog.records)


async def test_a_setup_is_kept_only_from_the_reply_with_its_cseq(camera, client):
    camera.held = {"SETUP"}
    camera.hold.clear()
    client.send("SETUP", "/trackID=3", TRANSPORT)
    await until(lambda: camera.peers and camera.peer.requests)
    camera.peer.send(b"RTSP/1.0 200 OK\r\nCSeq: 7\r\nSession: STRAY\r\n\r\n")
    stray = await client.receive()
    camera.hold.set()
    first = await client.receive()
    again = await client.request("SETUP", "/trackID=3", TRANSPORT)

    assert (stray.headers["cseq"], first.headers["cseq"]) == ("7", "1")
    assert (again.status, again.headers["session"]) == (200, SESSION)
    assert len(setups(camera)) == 1


async def test_a_local_reply_waits_for_replies_that_come_out_of_order(camera, client):
    await client.request("SETUP", "/trackID=3", TRANSPORT)
    camera.held = {"OPTIONS"}
    camera.hold.clear()
    client.send("OPTIONS")
    client.send("GET_PARAMETER")
    client.send("SETUP", "/trackID=3", TRANSPORT)
    await until(lambda: camera.peer.requests[-1][0] == "OPTIONS")
    camera.peer.send(b"RTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n")
    early = await client.receive()
    await asyncio.sleep(0.05)
    camera.hold.set()
    later = [await client.receive() for _ in range(3)]

    assert [reply.headers["cseq"] for reply in [early, *later]] == ["3", "2", "4", "3"]
    assert "transport" in later[1].headers


async def test_junk_from_the_camera_passes_unchanged(camera, client):
    await client.request("OPTIONS")
    junk = b"\x00garbage\r\n" + frame(0, b"x" * 100) + b"\xff\xfe" + frame(1, b"y" * 10)

    camera.peer.send(junk)

    assert await asyncio.wait_for(client.reader.readexactly(len(junk)), 2) == junk


@pytest.mark.parametrize(
    "head",
    [
        b"RTSP/1.0 200 OK\r\nX: " + b"x" * 0x11000,
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: many\r\n\r\n",
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 65537\r\n\r\n",
    ],
    ids=["endless head", "bad length", "body above 64 KiB"],
)
async def test_a_broken_camera_message_closes_both_sides(camera, client, head, caplog):
    await client.request("OPTIONS")

    with caplog.at_level(logging.DEBUG, logger="sannce_aio.relay"):
        camera.peer.send(head)
        assert await client.until_closed() == b""
        await asyncio.wait_for(camera.peer.closed.wait(), 2)

    assert any(record.levelno == logging.DEBUG for record in caplog.records)


async def test_a_body_of_64_kib_passes_intact(camera, client):
    await client.request("OPTIONS")
    body = "b" * 0x10000

    camera.peer.send(
        f"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode()
    )

    assert (await client.receive()).body == body


async def test_a_request_with_a_body_above_64_kib_closes_both_sides(camera, client, caplog):
    await client.request("OPTIONS")

    with caplog.at_level(logging.DEBUG, logger="sannce_aio.relay"):
        client.send("SET_PARAMETER", extra="Content-Length: 65537\r\n")
        assert await client.until_closed() == b""
        await asyncio.wait_for(camera.peer.closed.wait(), 2)

    assert any("65537" in record.getMessage() for record in caplog.records)


async def test_a_request_with_a_bad_url_closes_both_sides(camera, client, caplog):
    await client.request("OPTIONS")

    with caplog.at_level(logging.DEBUG):
        client.send("SETUP", url="rtsp://[::1/1/2/trackID=3")
        assert await client.until_closed() == b""
        await asyncio.wait_for(camera.peer.closed.wait(), 2)
        await asyncio.sleep(0.05)

    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING] == []
    assert any("Invalid IPv6 URL" in r.getMessage() for r in caplog.records)


async def test_the_client_closing_closes_the_camera_side(camera, client):
    await client.request("OPTIONS")

    client.close()

    await asyncio.wait_for(camera.peer.closed.wait(), 2)


async def test_a_client_reset_during_a_stream_closes_the_camera_side(camera, client):
    await client.request("OPTIONS")
    camera.peer.send(FLOOD)
    await asyncio.sleep(0.2)

    client.writer.transport.abort()

    await asyncio.wait_for(camera.peer.closed.wait(), 2)


async def test_a_client_that_stops_reading_is_cut_off(camera, relay, client, monkeypatch):
    monkeypatch.setattr(relay_module, "_CLOSE_SECONDS", 0.2)
    await client.request("OPTIONS")
    camera.peer.send(FLOOD)
    await asyncio.sleep(0.2)

    client.writer.write_eof()

    await asyncio.wait_for(camera.peer.closed.wait(), 2)
    await until(lambda: not relay._connections, timeout=1)


async def test_the_camera_closing_closes_the_client(camera, client):
    await client.request("OPTIONS")

    camera.peer.writer.close()

    assert await client.until_closed() == b""


async def test_an_unreachable_camera_closes_the_client(caplog):
    port = free_port()
    async with running(port) as relay:
        with caplog.at_level(logging.DEBUG, logger="sannce_aio.relay"):
            client = await Client.connect(relay.port)
            try:
                assert await client.until_closed() == b""
            finally:
                client.close()

    messages = [record.getMessage() for record in caplog.records]
    assert any(f"127.0.0.1:{port}" in message for message in messages), messages


@pytest_asyncio.fixture
async def silent(monkeypatch):
    port = free_port()
    connect = asyncio.open_connection

    async def hang(host, target, **kwargs):
        if target == port:
            await asyncio.Event().wait()
        return await connect(host, target, **kwargs)

    monkeypatch.setattr(asyncio, "open_connection", hang)
    return port


async def test_a_silent_camera_closes_the_client_after_the_timeout(silent, caplog):
    loop = asyncio.get_running_loop()
    async with running(silent, timeout=0.3) as relay:
        with caplog.at_level(logging.DEBUG, logger="sannce_aio.relay"):
            client = await Client.connect(relay.port)
            start = loop.time()
            try:
                assert await client.until_closed() == b""
            finally:
                client.close()

    assert 0.25 <= loop.time() - start < 1.5
    assert any(f"127.0.0.1:{silent}" in r.getMessage() for r in caplog.records)


async def test_close_ends_every_connection_within_its_bound(camera, silent):
    loop = asyncio.get_running_loop()
    relay = RtspRelay("127.0.0.1", camera.port, timeout=30)
    stuck = RtspRelay("127.0.0.1", silent, timeout=30)
    await relay.start()
    await stuck.start()
    active = await Client.connect(relay.port)
    waiting = await Client.connect(stuck.port)
    await active.request("OPTIONS")

    start = loop.time()
    await relay.close()
    await stuck.close()
    took = loop.time() - start

    assert took < 2.5
    assert await active.until_closed() == b""
    assert await waiting.until_closed() == b""
    await asyncio.wait_for(camera.peer.closed.wait(), 2)
    with pytest.raises(OSError):
        await Client.connect(relay.port)
    active.close()
    waiting.close()


async def test_close_twice_and_before_start_is_harmless(camera):
    relay = RtspRelay("127.0.0.1", camera.port)
    await relay.close()
    await relay.start()
    assert relay.port > 0
    await relay.close()
    await relay.close()


async def test_through_the_relay_the_simulator_takes_a_repeated_backchannel_setup():
    upstream = FakeRtspCamera(backchannel=False, auth=False)
    await upstream.start()
    front = RtspFront(
        host="127.0.0.1", port=0, upstream_host="127.0.0.1",
        upstream_port=upstream.port, username="admin", password="admin123",
    )
    await front.start()
    try:
        async with running(front.port) as relay:
            client = await RawClient.connect(relay.port)
            try:
                await client.request("DESCRIBE", extra=REQUIRE)
                first = await client.request("SETUP", "/trackID=bc", TRANSPORT)
                second = await client.request("SETUP", "/trackID=bc", TRANSPORT)
            finally:
                client.close()
    finally:
        await front.stop()
        await upstream.stop()

    assert first.startswith("RTSP/1.0 200")
    assert second.startswith("RTSP/1.0 200")
