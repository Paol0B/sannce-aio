import asyncio
import contextlib
import logging
import re
import socket
import struct

import pytest
import pytest_asyncio

from sannce_aio.backchannel import FRAME_BYTES, Backchannel
from sannce_aio.errors import AuthError, ProtocolError, TalkBusyError
from sannce_aio.simulator_rtsp import RtspFront

from .rtsp_fake import FakeRtspCamera, RawClient, md5


async def chunks(*parts):
    for part in parts:
        yield part


@pytest_asyncio.fixture
async def upstream():
    camera = FakeRtspCamera(backchannel=False, auth=False)
    await camera.start()
    yield camera
    await camera.stop()


@contextlib.asynccontextmanager
async def serve(upstream_port):
    proxy = RtspFront(
        host="127.0.0.1", port=0, upstream_host="127.0.0.1",
        upstream_port=upstream_port, username="admin", password="admin123",
    )
    await proxy.start()
    try:
        yield proxy
    finally:
        await proxy.stop()


@pytest_asyncio.fixture
async def front(upstream):
    async with serve(upstream.port) as proxy:
        yield proxy


def backchannel(front, password="admin123"):
    return Backchannel("127.0.0.1", front.port, "/1/1", "admin", password, timeout=2.0)


async def test_the_front_adds_a_backchannel_track(front):
    assert await backchannel(front).has_backchannel() is True


async def test_the_front_records_backchannel_audio(front):
    pcm = struct.pack("<h", 1000) * 160 * 3
    bc = backchannel(front)
    await bc.open()
    assert front.speaking is True
    await bc.stream(chunks(pcm))
    await bc.close()
    await asyncio.sleep(0.05)

    wav = front.wav()
    assert len(wav) == 44 + 3 * FRAME_BYTES
    assert front.speaking is False


async def test_a_new_session_replaces_the_recording(front):
    for frames in (3, 1):
        bc = backchannel(front)
        await bc.open()
        await bc.stream(chunks(b"\x00\x01" * 160 * frames))
        await bc.close()
        await asyncio.sleep(0.05)

    assert len(front.wav()) == 44 + FRAME_BYTES


async def test_a_busy_front_refuses_the_backchannel(front):
    front.busy = True
    with pytest.raises(TalkBusyError, match="453"):
        await backchannel(front).open()


async def test_the_front_wants_the_camera_login(front):
    with pytest.raises(AuthError):
        await backchannel(front, password="wrong").open()


async def raw_describe(front, require):
    url = f"rtsp://127.0.0.1:{front.port}/1/1"
    reader, writer = await asyncio.open_connection("127.0.0.1", front.port)
    extra = "Require: www.onvif.org/ver20/backchannel\r\n" if require else ""
    try:
        writer.write(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n{extra}\r\n".encode())
        head = (await reader.readuntil(b"\r\n\r\n")).decode()
        nonce = re.search(r'nonce="([^"]+)"', head).group(1)
        response = md5(f"{md5('admin:RTSP:admin123')}:{nonce}:{md5(f'DESCRIBE:{url}')}")
        auth = (
            f'Authorization: Digest username="admin", realm="RTSP", nonce="{nonce}", '
            f'uri="{url}", response="{response}"\r\n'
        )
        writer.write(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n{extra}{auth}\r\n".encode())
        head = (await reader.readuntil(b"\r\n\r\n")).decode()
        length = int(re.search(r"Content-Length: (\d+)", head).group(1))
        return head, (await reader.readexactly(length)).decode()
    finally:
        writer.close()


async def test_a_describe_without_the_require_header_has_no_backchannel(front):
    head, sdp = await raw_describe(front, require=False)

    assert head.startswith("RTSP/1.0 200")
    assert "a=sendonly" not in sdp
    assert f"rtsp://127.0.0.1:{front.port}/1/1/trackID=1" in sdp


async def test_a_describe_with_the_require_header_adds_the_track(front):
    _, sdp = await raw_describe(front, require=True)

    assert sdp.rstrip().endswith("a=rtpmap:0 PCMU/8000/1")
    assert f"a=control:rtsp://127.0.0.1:{front.port}/1/1/trackID=bc" in sdp


async def test_a_backchannel_only_play_stays_local(front, upstream):
    bc = backchannel(front)
    await bc.open()
    await bc.close()

    assert [method for method, _, _ in upstream.requests] == ["DESCRIBE"]


async def test_reset_clears_busy_and_audio(front):
    front.busy = True
    front.reset()
    assert front.busy is False
    assert len(front.wav()) == 44


async def test_reset_restores_the_start_password(front):
    front.password = "changed"
    front.reset()
    assert await backchannel(front).has_backchannel() is True


@contextlib.asynccontextmanager
async def scripted(*replies):
    async def handle(reader, writer):
        try:
            for reply in replies:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(reply)
                await writer.drain()
            await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


SDP = b"v=0\r\n"
DESCRIBED = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: %d\r\n\r\n%s" % (len(SDP), SDP)
SET_UP = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 1234\r\nTransport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n"
PLAYING = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 1234\r\n\r\n"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def test_a_refused_upstream_answers_503_and_logs_one_warning(caplog):
    port = free_port()
    async with serve(port) as proxy:
        with caplog.at_level(logging.INFO), pytest.raises(ProtocolError, match="503"):
            await backchannel(proxy).open()

    records = [(r.levelno, r.getMessage()) for r in caplog.records]
    assert [level for level, _ in records] == [logging.WARNING]
    assert f"127.0.0.1:{port}" in records[0][1]


async def test_a_garbled_upstream_reply_answers_502_and_logs_one_warning(caplog):
    async with scripted(b"garbage\r\n\r\n") as port, serve(port) as proxy:
        with caplog.at_level(logging.INFO), pytest.raises(ProtocolError, match="502"):
            await backchannel(proxy).open()

    assert [r.levelno for r in caplog.records] == [logging.WARNING]


async def test_a_setup_that_fails_upstream_answers_502(caplog):
    async with scripted(DESCRIBED, b"short\r\n\r\n") as port, serve(port) as proxy:
        client = await RawClient.connect(proxy.port)
        try:
            await client.request("DESCRIBE")
            setup = await client.request(
                "SETUP", "/trackID=1", "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
            )
        finally:
            client.close()

    assert setup.startswith("RTSP/1.0 502")


async def test_the_client_sees_eof_when_the_upstream_drops_mid_relay(upstream):
    async with serve(upstream.port) as proxy:
        client = await RawClient.connect(proxy.port)
        try:
            assert (await client.play_video()).startswith("RTSP/1.0 200")
            await upstream.stop()
            assert await client.until_closed() == b""
        finally:
            client.close()


async def test_the_client_sees_eof_when_the_upstream_sends_junk():
    junk = b"x" * 70000
    async with scripted(DESCRIBED, SET_UP, PLAYING + junk) as port, serve(port) as proxy:
        client = await RawClient.connect(proxy.port)
        try:
            assert (await client.play_video()).startswith("RTSP/1.0 200")
            assert await client.until_closed() == b""
        finally:
            client.close()


BACKCHANNEL_TRANSPORT = "Transport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n"
VIDEO_TRANSPORT = "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"


@pytest.mark.parametrize(
    ("track", "transport", "forwarded"),
    [("/trackID=bc", BACKCHANNEL_TRANSPORT, 0), ("/trackID=1", VIDEO_TRANSPORT, 1)],
    ids=["backchannel", "video"],
)
async def test_a_repeated_setup_of_a_track_answers_455(
    front, upstream, track, transport, forwarded
):
    client = await RawClient.connect(front.port)
    try:
        await client.request("DESCRIBE")
        first = await client.request("SETUP", track, transport)
        second = await client.request("SETUP", track + "/", transport)
    finally:
        client.close()

    assert first.startswith("RTSP/1.0 200")
    assert second.startswith("RTSP/1.0 455 Method Not Valid in This State")
    assert [method for method, _, _ in upstream.requests].count("SETUP") == forwarded


async def test_two_sessions_may_each_set_up_the_backchannel(front):
    clients = [await RawClient.connect(front.port) for _ in range(2)]
    try:
        replies = [
            await client.request("SETUP", "/trackID=bc", BACKCHANNEL_TRANSPORT)
            for client in clients
        ]
    finally:
        for client in clients:
            client.close()

    assert all(reply.startswith("RTSP/1.0 200") for reply in replies)


async def test_the_describe_reply_uses_the_host_of_the_request(front):
    base = "rtsp://127.0.0.1:18600/1/2"
    client = await RawClient.connect(front.port, base=base)
    try:
        head = await client.request(
            "DESCRIBE", extra="Require: www.onvif.org/ver20/backchannel\r\n"
        )
    finally:
        client.close()

    assert f"Content-Base: {base}/\r\n" in head
    assert f"a=control:{base}/trackID=1" in client.body
    assert f"a=control:{base}/trackID=bc" in client.body
