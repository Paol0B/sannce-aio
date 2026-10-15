import asyncio
import struct

import pytest
import pytest_asyncio

from sannce_aio import backchannel
from sannce_aio.audio import decode_alaw, decode_ulaw, encode_alaw
from sannce_aio.backchannel import FRAME_BYTES, Backchannel
from sannce_aio.errors import AuthError, ConnectError, ProtocolError, TalkBusyError

from .rtsp_fake import FakeRtspCamera


async def chunks(*parts):
    for part in parts:
        yield part


def tone(frames, value=1000):
    return struct.pack("<h", value) * (frames * FRAME_BYTES // 2)


@pytest_asyncio.fixture
async def rtsp():
    camera = FakeRtspCamera()
    await camera.start()
    yield camera
    await camera.stop()


@pytest_asyncio.fixture
async def stalled(monkeypatch):
    # unpaced, a stream fills the socket buffers in well under a second
    monkeypatch.setattr(backchannel, "_FRAME_SECONDS", 0)
    camera = FakeRtspCamera(stall_after_play=True)
    await camera.start()
    yield camera
    await camera.stop()


async def endless_tone():
    while True:
        yield tone(1)


def nonce_of(headers):
    return headers["authorization"].split('nonce="')[1].split('"')[0]


def channel(rtsp, password="admin123"):
    return Backchannel(rtsp.host, rtsp.port, "/1/1", "admin", password, timeout=2.0)


async def test_open_sets_up_the_sendonly_track_with_the_backchannel_header(rtsp):
    bc = channel(rtsp)
    await bc.open()
    await bc.close()

    methods = [
        (method, url) for method, url, headers in rtsp.requests if "authorization" in headers
    ]
    base = f"rtsp://{rtsp.host}:{rtsp.port}/1/1"
    assert methods[:3] == [
        ("DESCRIBE", base),
        ("SETUP", f"{base}/trackID=3"),
        ("PLAY", base),
    ]
    assert all(
        headers["require"] == "www.onvif.org/ver20/backchannel"
        for _, _, headers in rtsp.requests
    )
    setup = next(h for m, _, h in rtsp.requests if m == "SETUP" and "authorization" in h)
    assert setup["transport"] == "RTP/AVP/TCP;unicast;interleaved=4-5"


async def test_play_carries_the_session_from_setup(rtsp):
    bc = channel(rtsp)
    await bc.open()
    await bc.close()

    play = next(h for m, _, h in rtsp.requests if m == "PLAY" and "authorization" in h)
    assert play["session"] == "1234"


async def test_stream_sends_pcma_rtp_on_the_interleaved_channel(rtsp):
    bc = channel(rtsp)
    await bc.open()
    await bc.stream(chunks(tone(3)))
    await bc.close()

    assert [ch for ch, _ in rtsp.packets] == [4, 4, 4]
    first = rtsp.packets[0][1]
    version, payload_type, seq, timestamp, _ = struct.unpack("!BBHII", first[:12])
    assert version == 0x80
    assert payload_type == 8
    second = struct.unpack("!BBHII", rtsp.packets[1][1][:12])
    assert second[2] == (seq + 1) & 0xFFFF
    assert second[3] == timestamp + 160
    assert decode_alaw(first[12:]) == decode_alaw(encode_alaw(tone(1)))


async def test_stream_prefers_pcmu_only_when_pcma_is_missing():
    rtsp = FakeRtspCamera(payload_types=(0,))
    await rtsp.start()
    try:
        bc = channel(rtsp)
        await bc.open()
        await bc.stream(chunks(tone(1)))
        await bc.close()
    finally:
        await rtsp.stop()

    assert rtsp.packets[0][1][1] == 0
    assert len(decode_ulaw(rtsp.packets[0][1][12:])) == FRAME_BYTES


async def test_stream_rechunks_and_zero_pads_the_last_frame(rtsp):
    bc = channel(rtsp)
    await bc.open()
    await bc.stream(chunks(tone(1)[:100], tone(1)[100:] + tone(1)[:10]))
    await bc.close()

    assert len(rtsp.packets) == 2
    assert all(len(packet) == 12 + FRAME_BYTES // 2 for _, packet in rtsp.packets)


async def test_stream_is_paced_in_real_time(rtsp):
    bc = channel(rtsp)
    await bc.open()
    await bc.stream(chunks(tone(10)))
    await bc.close()

    spread = rtsp.arrivals[-1] - rtsp.arrivals[0]
    assert 0.15 <= spread <= 0.4


async def test_stream_sends_get_parameter_on_long_streams(rtsp):
    bc = Backchannel(rtsp.host, rtsp.port, "/1/1", "admin", "admin123", keepalive=0.05)
    await bc.open()
    await bc.stream(chunks(tone(10)))
    await bc.close()

    assert "GET_PARAMETER" in [method for method, _, _ in rtsp.requests]


async def test_close_sends_teardown(rtsp):
    bc = channel(rtsp)
    await bc.open()
    await bc.close()
    await asyncio.sleep(0.05)

    assert rtsp.requests[-1][0] == "TEARDOWN"


async def test_digest_with_qop_auth_is_answered():
    rtsp = FakeRtspCamera(qop=True)
    await rtsp.start()
    try:
        bc = channel(rtsp)
        await bc.open()
        await bc.close()
    finally:
        await rtsp.stop()

    assert any(method == "PLAY" for method, _, _ in rtsp.requests)


async def test_a_wrong_password_raises_auth_error(rtsp):
    with pytest.raises(AuthError, match="DESCRIBE"):
        await channel(rtsp, password="wrong").open()


async def test_a_camera_without_a_backchannel_raises_protocol_error():
    rtsp = FakeRtspCamera(backchannel=False)
    await rtsp.start()
    try:
        with pytest.raises(ProtocolError, match="no backchannel"):
            await channel(rtsp).open()
    finally:
        await rtsp.stop()


@pytest.mark.parametrize("status", [453, 455])
async def test_a_refused_setup_raises_talk_busy(status):
    rtsp = FakeRtspCamera(setup_status=status)
    await rtsp.start()
    try:
        with pytest.raises(TalkBusyError, match=f"RTSP {status}"):
            await channel(rtsp).open()
    finally:
        await rtsp.stop()


async def test_another_setup_failure_raises_protocol_error():
    rtsp = FakeRtspCamera(setup_status=500)
    await rtsp.start()
    try:
        with pytest.raises(ProtocolError, match="RTSP 500"):
            await channel(rtsp).open()
    finally:
        await rtsp.stop()


async def test_an_unreachable_camera_raises_connect_error():
    with pytest.raises(ConnectError):
        await Backchannel("127.0.0.1", 1, "/1/1", "admin", "pw", timeout=1.0).open()


async def test_has_backchannel_reports_the_track(rtsp):
    assert await channel(rtsp).has_backchannel() is True


async def test_has_backchannel_is_false_without_the_track():
    rtsp = FakeRtspCamera(backchannel=False)
    await rtsp.start()
    try:
        assert await channel(rtsp).has_backchannel() is False
    finally:
        await rtsp.stop()


async def test_stream_raises_connect_error_when_the_camera_hangs_up(rtsp):
    bc = channel(rtsp)
    await bc.open()
    streaming = asyncio.create_task(bc.stream(chunks(tone(100))))
    async with asyncio.timeout(2):
        while not rtsp.packets:
            await asyncio.sleep(0.01)
    await rtsp.stop()

    with pytest.raises(ConnectError):
        await asyncio.wait_for(streaming, 5)
    await asyncio.wait_for(bc.close(), 2)


async def test_stream_raises_connect_error_when_the_camera_stops_reading(stalled):
    bc = Backchannel(stalled.host, stalled.port, "/1/1", "admin", "admin123", timeout=0.5)
    await bc.open()

    with pytest.raises(ConnectError):
        await asyncio.wait_for(bc.stream(endless_tone()), 5)
    await asyncio.wait_for(bc.close(), 1)


async def test_close_after_a_cancel_gives_up_on_a_stalled_camera(stalled):
    bc = Backchannel(stalled.host, stalled.port, "/1/1", "admin", "admin123", timeout=60)
    await bc.open()
    streaming = asyncio.create_task(bc.stream(endless_tone()))
    async with asyncio.timeout(5):
        while not bc._writer.transport.get_write_buffer_size():
            await asyncio.sleep(0.01)
    streaming.cancel()
    with pytest.raises(asyncio.CancelledError):
        await streaming

    await asyncio.wait_for(bc.close(), 3)


async def test_close_gives_up_on_audio_a_stalled_camera_never_takes(stalled):
    bc = Backchannel(stalled.host, stalled.port, "/1/1", "admin", "admin123")
    await bc.open()

    async def until_the_socket_is_full():
        while not bc._writer.transport.get_write_buffer_size():
            yield tone(1)

    await asyncio.wait_for(bc.stream(until_the_socket_is_full()), 5)
    await asyncio.wait_for(bc.close(), 3)


@pytest.mark.parametrize(
    ("reply", "error", "message"),
    [
        (b"RTSP/1.0 200 OK\r\n", ConnectError, "no RTSP reply"),
        (b"RTSP/1.0 200 OK\r\nContent-Length: x\r\n\r\n", ProtocolError, "bad RTSP reply"),
        (b"HTTP/1.1 200 OK\r\n\r\n", ProtocolError, "bad RTSP status line"),
    ],
    ids=["cut", "bad_length", "not_rtsp"],
)
async def test_a_broken_reply_raises(reply, error, message):
    async def answer(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(reply)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(answer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        with pytest.raises(error, match=message):
            await Backchannel("127.0.0.1", port, "/1/1", "admin", "pw").has_backchannel()
    finally:
        server.close()
        await server.wait_closed()


async def test_a_new_connection_answers_a_fresh_challenge(rtsp):
    bc = channel(rtsp)
    assert await bc.has_backchannel() is True
    await bc.open()
    await bc.close()

    describes = [h for m, _, h in rtsp.requests if m == "DESCRIBE" and "authorization" in h]
    assert len({nonce_of(h) for h in describes}) == 2
    assert any(method == "PLAY" for method, _, _ in rtsp.requests)


async def test_a_stale_nonce_is_retried_once_with_the_new_one(rtsp):
    rtsp.stale_replies = 1
    bc = channel(rtsp)
    await bc.open()
    await bc.close()

    setups = [h for m, _, h in rtsp.requests if m == "SETUP"]
    assert len(setups) == 2
    assert nonce_of(setups[0]) != nonce_of(setups[1])
    assert any(method == "PLAY" for method, _, _ in rtsp.requests)


async def test_a_second_stale_reply_raises_auth_error(rtsp):
    rtsp.stale_replies = 2
    with pytest.raises(AuthError, match="SETUP"):
        await channel(rtsp).open()


async def test_close_without_open_does_nothing():
    await Backchannel("127.0.0.1", 1, "/1/1", "admin", "pw").close()
