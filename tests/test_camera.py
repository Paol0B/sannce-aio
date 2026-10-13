import asyncio
import socket
import struct
from urllib.parse import unquote, urlsplit

import aiohttp
import pytest
import pytest_asyncio

from sannce_aio import (
    AuthError,
    CameraInfo,
    ConnectError,
    Event,
    SannceCamera,
    TalkBusyError,
)
from sannce_aio.audio import SUBFRAME_PCM_BYTES, encode_alaw

pytestmark = pytest.mark.asyncio

MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
MOTION_STOP = ["INNER", "ALARM", "MOTIONDETECT", "0", "0"]
PCM = struct.pack("<240h", *range(-12000, 12000, 100))
SUBFRAMES = [
    encode_alaw(PCM[start : start + SUBFRAME_PCM_BYTES])
    for start in range(0, len(PCM), SUBFRAME_PCM_BYTES)
]
OTHER_PCM = struct.pack("<240h", *range(12000, -12000, -100))
OTHER_SUBFRAMES = [
    encode_alaw(OTHER_PCM[start : start + SUBFRAME_PCM_BYTES])
    for start in range(0, len(OTHER_PCM), SUBFRAME_PCM_BYTES)
]


async def wait_until(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met in time")


async def async_iter(chunks):
    for chunk in chunks:
        yield chunk


def talk_actions(simulator):
    return [fields[6] for fields in simulator.requests if fields[1:2] == ["NVR"]]


def unused_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def track_closed_sessions(monkeypatch):
    closed = []
    close = aiohttp.ClientSession.close

    async def spy(session):
        closed.append(session)
        await close(session)

    monkeypatch.setattr(aiohttp.ClientSession, "close", spy)
    return closed


@pytest_asyncio.fixture
async def make_camera(simulator):
    created = []

    def make(*, username=None, password=None, event_timeout=10.0, http_port=None):
        camera = SannceCamera(
            simulator.host,
            simulator.username if username is None else username,
            simulator.password if password is None else password,
            nvs_port=simulator.port,
            http_port=simulator.http_port if http_port is None else http_port,
            event_timeout=event_timeout,
        )
        created.append(camera)
        return camera

    yield make
    for camera in created:
        await camera.close()


async def test_connect_populates_info_and_caps(make_camera):
    camera = make_camera()

    await camera.connect()

    assert camera.info == CameraInfo(model=None, serial=None, firmware="1.0.0", mac=None)
    assert {
        "person",
        "vehicle",
        "motion",
        "white_light",
        "light_mode",
        "talk",
    } <= camera.caps


async def test_connect_bad_credentials_raises_auth_error(make_camera):
    camera = make_camera(password="wrong")

    with pytest.raises(AuthError):
        await camera.connect()


async def test_connect_closes_owned_http_session_when_nvs_fails(
    simulator, make_camera, monkeypatch
):
    camera = make_camera()
    captured = {}

    async def fail(*_args, **_kwargs):
        captured["session"] = camera._http._session
        raise ConnectError("nvs down")

    monkeypatch.setattr(camera._conn, "connect", fail)

    with pytest.raises(ConnectError):
        await camera.connect()

    assert captured["session"] is not None
    assert captured["session"].closed is True
    assert camera._http._session is None


async def test_connect_keeps_caller_session_when_nvs_fails(simulator, monkeypatch):
    session = aiohttp.ClientSession()
    try:
        camera = SannceCamera(
            simulator.host,
            simulator.username,
            simulator.password,
            nvs_port=simulator.port,
            http_port=simulator.http_port,
            session=session,
        )

        async def fail(*_args, **_kwargs):
            raise ConnectError("nvs down")

        monkeypatch.setattr(camera._conn, "connect", fail)

        with pytest.raises(ConnectError):
            await camera.connect()

        assert session.closed is False
    finally:
        await session.close()


async def test_connect_closes_owned_http_session_when_http_fails(
    make_camera, monkeypatch
):
    closed = track_closed_sessions(monkeypatch)
    camera = make_camera(http_port=unused_port())

    with pytest.raises(ConnectError):
        await camera.connect()

    assert len(closed) == 1


async def test_connect_keeps_caller_session_when_http_fails(simulator):
    session = aiohttp.ClientSession()
    try:
        camera = SannceCamera(
            simulator.host,
            simulator.username,
            simulator.password,
            nvs_port=simulator.port,
            http_port=unused_port(),
            session=session,
        )

        with pytest.raises(ConnectError):
            await camera.connect()

        assert session.closed is False
    finally:
        await session.close()


async def test_connect_cancelled_after_login_closes_the_connection(
    simulator, make_camera, monkeypatch
):
    camera = make_camera()
    probing = asyncio.Event()

    async def hang(*_args, **_kwargs):
        probing.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(camera._http, "get_light", hang)
    task = asyncio.create_task(camera.connect())
    await asyncio.wait_for(probing.wait(), 5.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await wait_until(lambda: simulator.clients == 0)
    assert camera._http._session is None


async def test_set_light_reaches_the_http_side(simulator, make_camera):
    camera = make_camera()
    await camera.connect()

    await camera.set_light(True)
    assert simulator.light_control == 1
    assert await camera.get_light() is True

    await camera.set_light(False)
    assert simulator.light_control == 0
    assert await camera.get_light() is False


async def test_rtsp_url_main_and_sub(simulator, make_camera):
    camera = make_camera()
    base = f"rtsp://{simulator.username}:{simulator.password}@{simulator.host}:554"

    assert camera.rtsp_url("main") == base + "/1/1"
    assert camera.rtsp_url("sub") == base + "/1/2"


async def test_rtsp_url_rejects_unknown_stream(make_camera):
    camera = make_camera()

    with pytest.raises(ValueError):
        camera.rtsp_url("high")


async def test_rtsp_url_escapes_special_characters(simulator):
    camera = SannceCamera(
        simulator.host,
        "user name",
        "p@ss:w/rd",
        nvs_port=simulator.port,
        http_port=simulator.http_port,
    )

    parts = urlsplit(camera.rtsp_url("main"))

    assert parts.scheme == "rtsp"
    assert parts.hostname == simulator.host
    assert parts.port == 554
    assert parts.path == "/1/1"
    assert unquote(parts.username) == "user name"
    assert unquote(parts.password) == "p@ss:w/rd"


@pytest.mark.parametrize("host", ["a/b", "a?b", "a#b", "user@host", ""])
async def test_constructor_rejects_bad_host(host):
    with pytest.raises(ValueError):
        SannceCamera(host, "admin", "admin123")


async def test_subscribe_receives_start_then_autoclear(simulator, make_camera):
    camera = make_camera(event_timeout=0.1)
    await camera.connect()
    seen = []
    camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    assert seen[0] == Event("motion", True, 0)

    await wait_until(lambda: len(seen) == 2)
    assert seen[1] == Event("motion", False, 0)


async def test_event_autoclear_cancelled_by_real_stop(simulator, make_camera):
    camera = make_camera(event_timeout=0.2)
    await camera.connect()
    seen = []
    camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    await simulator.push_event(MOTION_STOP)
    await wait_until(lambda: len(seen) == 2)

    assert seen == [Event("motion", True, 0), Event("motion", False, 0)]
    await asyncio.sleep(0.3)
    assert len(seen) == 2


async def test_close_cancels_pending_autoclear(simulator, make_camera):
    camera = make_camera(event_timeout=0.2)
    await camera.connect()
    seen = []
    camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    await camera.close()
    await asyncio.sleep(0.3)

    assert seen == [Event("motion", True, 0)]


async def test_unsubscribe_stops_delivery(simulator, make_camera):
    camera = make_camera()
    await camera.connect()
    seen = []
    unsub = camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    unsub()
    await simulator.push_event(MOTION_STOP)
    await asyncio.sleep(0.1)

    assert len(seen) == 1


async def test_raising_subscriber_does_not_block_others(simulator, make_camera):
    camera = make_camera()
    await camera.connect()
    good = []

    def bad(_event):
        raise RuntimeError("subscriber boom")

    camera.subscribe(bad)
    camera.subscribe(good.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: good == [Event("motion", True, 0)])


async def test_on_availability_reports_up_then_down(make_camera):
    camera = make_camera()
    states = []
    camera.on_availability(states.append)

    await camera.connect()
    await wait_until(lambda: states == [True])
    await camera.close()

    assert states == [True, False]


async def test_on_login_failed_reports_a_refused_reconnect(simulator, make_camera):
    camera = make_camera()
    failures = []
    states = []
    camera.on_login_failed(failures.append)
    camera.on_availability(states.append)
    await camera.connect()
    # the default 1 s backoff would make this test take seconds
    camera._conn._backoff_start = 0.01
    simulator.password = "changed"

    for session in list(simulator._sessions):
        session.writer.close()
    await wait_until(lambda: failures, timeout=5.0)

    assert len(failures) == 1
    assert isinstance(failures[0], AuthError)
    assert states == [True, False]


async def test_play_audio_streams_rechunked_frames_and_stops_talk(
    simulator, make_camera
):
    camera = make_camera()
    await camera.connect()

    await camera.play_audio(async_iter([PCM[:100], PCM[100:300], PCM[300:]]))

    assert simulator.talk_frames == SUBFRAMES
    assert not simulator.talking


async def test_play_audio_zero_pads_a_trailing_partial_frame(simulator, make_camera):
    camera = make_camera()
    await camera.connect()
    pcm = PCM[: SUBFRAME_PCM_BYTES + 80]

    await camera.play_audio(async_iter([pcm]))

    padded = pcm[SUBFRAME_PCM_BYTES:] + bytes(SUBFRAME_PCM_BYTES - 80)
    assert simulator.talk_frames == [
        encode_alaw(pcm[:SUBFRAME_PCM_BYTES]),
        encode_alaw(padded),
    ]
    assert not simulator.talking


async def test_play_audio_raises_busy_when_talk_is_held(simulator, make_camera):
    simulator.set_talk_busy(True)
    camera = make_camera()
    await camera.connect()

    with pytest.raises(TalkBusyError):
        await camera.play_audio(async_iter([PCM]))

    assert not simulator.talking


async def test_play_audio_stops_talk_on_producer_error(simulator, make_camera):
    camera = make_camera()
    await camera.connect()

    async def producer():
        yield PCM
        raise RuntimeError("producer boom")

    with pytest.raises(RuntimeError):
        await camera.play_audio(producer())

    await wait_until(lambda: not simulator.talking)


async def test_play_audio_stops_talk_on_cancel(simulator, make_camera):
    camera = make_camera()
    await camera.connect()
    started = asyncio.Event()

    async def producer():
        yield PCM
        started.set()
        await asyncio.sleep(10)
        yield PCM

    task = asyncio.create_task(camera.play_audio(producer()))
    await started.wait()
    await wait_until(lambda: simulator.talking)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await wait_until(lambda: not simulator.talking)


async def test_overlapping_play_audio_calls_run_one_after_the_other(
    simulator, make_camera
):
    camera = make_camera()
    await camera.connect()
    streaming = asyncio.Event()
    release = asyncio.Event()

    async def first():
        yield PCM[:SUBFRAME_PCM_BYTES]
        streaming.set()
        await release.wait()
        yield PCM[SUBFRAME_PCM_BYTES:]

    one = asyncio.create_task(camera.play_audio(first()))
    await asyncio.wait_for(streaming.wait(), 5.0)
    two = asyncio.create_task(camera.play_audio(async_iter([OTHER_PCM])))
    await asyncio.sleep(0.05)
    assert not two.done()

    release.set()
    await asyncio.wait_for(asyncio.gather(one, two), 5.0)

    assert simulator.talk_frames == SUBFRAMES + OTHER_SUBFRAMES
    assert talk_actions(simulator) == ["BEGIN", "END", "BEGIN", "END"]
    assert not simulator.talking


async def test_rejected_play_audio_does_not_end_a_running_talk(simulator, make_camera):
    camera = make_camera()
    await camera.connect()
    await camera._conn.start_talk(0)

    with pytest.raises(TalkBusyError):
        await camera.play_audio(async_iter([PCM]))

    assert simulator.talking
    assert talk_actions(simulator) == ["BEGIN"]
