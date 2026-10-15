import asyncio
import logging
import socket
from urllib.parse import unquote, urlsplit

import aiohttp
import pytest
import pytest_asyncio

from sannce_aio import (
    AuthError,
    CameraInfo,
    ConnectError,
    Event,
    Floodlight,
    ProtocolError,
    SannceCamera,
    TalkBusyError,
)

from .rtsp_fake import FakeRtspCamera

pytestmark = pytest.mark.asyncio

USER = "admin"
PASSWORD = "admin123"
MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
MOTION_STOP = ["INNER", "ALARM", "MOTIONDETECT", "0", "0"]


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
async def rtsp():
    camera = FakeRtspCamera(username=USER, password=PASSWORD)
    await camera.start()
    yield camera
    await camera.stop()


@pytest_asyncio.fixture
async def make_camera(simulator, rtsp):
    created = []

    async def make(
        *, connect=True, username=None, password=None, event_timeout=10.0, http_port=None
    ):
        camera = SannceCamera(
            simulator.host,
            simulator.username if username is None else username,
            simulator.password if password is None else password,
            nvs_port=simulator.port,
            http_port=simulator.http_port if http_port is None else http_port,
            rtsp_port=rtsp.port,
            event_timeout=event_timeout,
        )
        created.append(camera)
        if connect:
            await camera.connect()
        return camera

    yield make
    for camera in created:
        await camera.close()


async def test_connect_populates_info_and_caps(make_camera):
    camera = await make_camera(connect=False)

    await camera.connect()

    assert camera.info == CameraInfo(model=None, serial=None, firmware="1.0.0", mac=None)
    assert {
        "person",
        "vehicle",
        "motion",
        "white_light",
        "light_mode",
        "speaker",
    } <= camera.caps
    assert "talk" not in camera.caps


async def test_connect_bad_credentials_raises_auth_error(make_camera):
    camera = await make_camera(connect=False, password="wrong")

    with pytest.raises(AuthError):
        await camera.connect()


async def test_connect_closes_owned_http_session_when_nvs_fails(
    simulator, make_camera, monkeypatch
):
    camera = await make_camera(connect=False)
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
    camera = await make_camera(connect=False, http_port=unused_port())

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
    camera = await make_camera(connect=False)
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


PROBES = ["get_light", "get_light_mode", "get_volume", "get_siren_on_event", "get_sound_count"]


@pytest.mark.parametrize("probe", PROBES)
async def test_an_unreachable_cap_probe_fails_the_connect(
    simulator, make_camera, monkeypatch, probe
):
    camera = await make_camera(connect=False)

    async def unreachable(*_args, **_kwargs):
        raise ConnectError("timed out")

    monkeypatch.setattr(camera._http, probe, unreachable)

    with pytest.raises(ConnectError, match="timed out"):
        await camera.connect()
    await wait_until(lambda: simulator.clients == 0)


async def test_an_unreachable_rtsp_port_fails_the_connect(simulator):
    camera = SannceCamera(
        simulator.host, USER, PASSWORD,
        nvs_port=simulator.port, http_port=simulator.http_port, rtsp_port=unused_port(),
    )

    with pytest.raises(ConnectError):
        await camera.connect()
    await wait_until(lambda: simulator.clients == 0)


@pytest.mark.parametrize(
    ("probe", "cap"),
    [
        ("get_light", "white_light"),
        ("get_light_mode", "light_mode"),
        ("get_volume", "volume"),
        ("get_siren_on_event", "siren_on_event"),
        ("get_sound_count", "siren"),
    ],
)
async def test_a_refused_cap_probe_leaves_the_cap_out(
    make_camera, monkeypatch, caplog, probe, cap
):
    camera = await make_camera(connect=False)

    async def refuse(*_args, **_kwargs):
        raise ProtocolError("HTTP 404")

    monkeypatch.setattr(camera._http, probe, refuse)
    caplog.set_level(logging.DEBUG, logger="sannce_aio.camera")

    await camera.connect()

    assert cap not in camera.caps
    assert f"no {cap}: HTTP 404" in caplog.text


async def test_floodlight_on_switches_to_color_and_forces_the_lamp(simulator, make_camera):
    camera = await make_camera()
    simulator.light_mode = 2

    await camera.set_floodlight(True, brightness=40)

    assert simulator.light_mode == 3
    assert simulator.lamp_on is True
    assert simulator.light_power == 40
    assert await camera.get_floodlight() == Floodlight(on=True, brightness=40)


async def test_floodlight_on_keeps_custom_mode(simulator, make_camera):
    camera = await make_camera()
    simulator.light_mode = 4

    await camera.set_floodlight(True)

    assert simulator.light_mode == 4
    assert simulator.lamp_on is True


async def test_floodlight_on_without_brightness_keeps_the_power(simulator, make_camera):
    camera = await make_camera()
    simulator.light_power = 70

    await camera.set_floodlight(True)

    assert simulator.light_power == 70


@pytest.mark.parametrize("mode", [1, 2])
async def test_a_refused_force_on_restores_the_mode(simulator, make_camera, monkeypatch, mode):
    camera = await make_camera()
    simulator.light_mode = mode

    async def refuse(*_args, **_kwargs):
        raise ProtocolError("PUT refused")

    monkeypatch.setattr(camera._http, "force_light_on", refuse)

    with pytest.raises(ProtocolError, match="PUT refused"):
        await camera.set_floodlight(True)

    assert simulator.light_mode == mode
    assert simulator.lamp_on is False


async def test_a_failed_restore_keeps_the_force_on_error(make_camera, monkeypatch, caplog):
    camera = await make_camera()
    set_mode = camera._http.set_light_mode
    modes = []

    async def refuse(*_args, **_kwargs):
        raise ProtocolError("PUT refused")

    async def drop_the_second(mode, **kwargs):
        modes.append(mode)
        if len(modes) > 1:
            raise ConnectError("camera gone")
        await set_mode(mode, **kwargs)

    monkeypatch.setattr(camera._http, "force_light_on", refuse)
    monkeypatch.setattr(camera._http, "set_light_mode", drop_the_second)

    with pytest.raises(ProtocolError, match="PUT refused"):
        await camera.set_floodlight(True)

    assert modes == ["color", "smart"]
    assert "cannot restore light mode smart" in caplog.text


@pytest.mark.parametrize(
    ("base", "mode", "control"), [("smart", 2, 2), ("infrared", 1, 2), ("color", 3, 0)]
)
async def test_floodlight_off_returns_to_the_base_mode(
    simulator, make_camera, base, mode, control
):
    camera = await make_camera()
    await camera.set_floodlight(True)

    await camera.set_floodlight(False, base_mode=base)

    assert simulator.light_mode == mode
    assert simulator.light_control == control
    assert (await camera.get_floodlight()).on is False


async def test_sounds_reach_the_camera(simulator, make_camera):
    camera = await make_camera()

    await camera.play_sound(1)
    await camera.stop_sound(1)

    assert camera.sound_count == 3
    assert simulator.sounds == [(1, 1), (1, 0)]


async def test_volume_siren_link_and_sensitivity_reach_the_camera(simulator, make_camera):
    camera = await make_camera()

    await camera.set_volume(30)
    await camera.set_siren_on_event(True)
    await camera.set_sensitivity(90)

    assert simulator.volume == 30
    assert await camera.get_volume() == 30
    assert simulator.siren_on_event is True
    assert await camera.get_siren_on_event() is True
    assert (await camera.get_detection()).sensitivity == 90


async def test_connect_reports_the_new_caps(make_camera):
    camera = await make_camera()
    assert {"volume", "siren", "siren_on_event", "speaker", "white_light", "light_mode"} <= camera.caps


async def test_rtsp_url_main_and_sub(simulator, rtsp, make_camera):
    camera = await make_camera(connect=False)
    base = f"rtsp://{simulator.username}:{simulator.password}@{simulator.host}:{rtsp.port}"

    assert camera.rtsp_url("main") == base + "/1/1"
    assert camera.rtsp_url("sub") == base + "/1/2"


async def test_rtsp_url_rejects_unknown_stream(make_camera):
    camera = await make_camera(connect=False)

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
    camera = await make_camera(event_timeout=0.1)
    seen = []
    camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    assert seen[0] == Event("motion", True, 0)

    await wait_until(lambda: len(seen) == 2)
    assert seen[1] == Event("motion", False, 0)


async def test_event_autoclear_cancelled_by_real_stop(simulator, make_camera):
    camera = await make_camera(event_timeout=0.2)
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
    camera = await make_camera(event_timeout=0.2)
    seen = []
    camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    await camera.close()
    await asyncio.sleep(0.3)

    assert seen == [Event("motion", True, 0)]


async def test_unsubscribe_stops_delivery(simulator, make_camera):
    camera = await make_camera()
    seen = []
    unsub = camera.subscribe(seen.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: len(seen) == 1)
    unsub()
    await simulator.push_event(MOTION_STOP)
    await asyncio.sleep(0.1)

    assert len(seen) == 1


async def test_raising_subscriber_does_not_block_others(simulator, make_camera):
    camera = await make_camera()
    good = []

    def bad(_event):
        raise RuntimeError("subscriber boom")

    camera.subscribe(bad)
    camera.subscribe(good.append)

    await simulator.push_event(MOTION_START)
    await wait_until(lambda: good == [Event("motion", True, 0)])


async def test_on_availability_reports_up_then_down(make_camera):
    camera = await make_camera(connect=False)
    states = []
    camera.on_availability(states.append)

    await camera.connect()
    await wait_until(lambda: states == [True])
    await camera.close()

    assert states == [True, False]


async def test_on_login_failed_reports_a_refused_reconnect(simulator, make_camera):
    camera = await make_camera(connect=False)
    failures = []
    states = []
    camera.on_login_failed(failures.append)
    camera.on_availability(states.append)
    await camera.connect()
    # the default 1 s backoff would make this test take seconds
    camera._conn._backoff_start = 0.01
    simulator.password = "changed"

    for session in list(simulator._sessions):
        await session.ws.close()
    await wait_until(lambda: failures, timeout=5.0)

    assert len(failures) == 1
    assert isinstance(failures[0], AuthError)
    assert states == [True, False]


async def test_play_audio_streams_through_the_backchannel(make_camera, rtsp):
    camera = await make_camera()
    await camera.play_audio(async_iter([b"\x01\x00" * 160, b"\x01\x00" * 100]))

    await wait_until(lambda: rtsp.requests[-1][0] == "TEARDOWN")
    assert [ch for ch, _ in rtsp.packets] == [4, 4]


async def test_play_audio_raises_busy_when_the_camera_refuses(simulator, rtsp, make_camera):
    camera = await make_camera()
    rtsp.setup_status = 453
    with pytest.raises(TalkBusyError):
        await camera.play_audio(async_iter([b"\x00" * 320]))


async def test_play_audio_tears_down_on_producer_error(make_camera, rtsp):
    camera = await make_camera()

    async def failing():
        yield b"\x00" * 320
        raise RuntimeError("producer broke")

    with pytest.raises(RuntimeError):
        await camera.play_audio(failing())
    await asyncio.sleep(0.05)
    assert rtsp.requests[-1][0] == "TEARDOWN"


async def test_cancelling_play_audio_tears_down_and_frees_the_speaker(make_camera, rtsp):
    camera = await make_camera()
    started = asyncio.Event()

    async def producer():
        yield b"\x00" * 320
        started.set()
        await asyncio.sleep(10)
        yield b"\x00" * 320

    task = asyncio.create_task(camera.play_audio(producer()))
    await asyncio.wait_for(started.wait(), 5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5.0)

    await wait_until(lambda: rtsp.requests[-1][0] == "TEARDOWN")
    await asyncio.wait_for(camera.play_audio(async_iter([b"\x00" * 320])), 5.0)
    assert len(rtsp.packets) == 2


async def test_overlapping_play_audio_calls_run_one_after_the_other(make_camera, rtsp):
    camera = await make_camera()
    streaming = asyncio.Event()
    release = asyncio.Event()

    async def held():
        yield b"\x00" * 320
        streaming.set()
        await release.wait()
        yield b"\x00" * 320

    def setups():
        return [m for m, _, h in rtsp.requests if m == "SETUP" and "authorization" in h]

    first = asyncio.create_task(camera.play_audio(held()))
    await asyncio.wait_for(streaming.wait(), 5.0)
    second = asyncio.create_task(camera.play_audio(async_iter([b"\x00" * 320])))
    await asyncio.sleep(0.2)
    assert len(setups()) == 1
    assert not second.done()

    release.set()
    await asyncio.wait_for(asyncio.gather(first, second), 5.0)
    assert len(setups()) == 2


async def test_a_camera_without_a_backchannel_has_no_speaker_cap(simulator):
    rtsp = FakeRtspCamera(username=USER, password=PASSWORD, backchannel=False)
    await rtsp.start()
    camera = SannceCamera(
        simulator.host, USER, PASSWORD,
        nvs_port=simulator.port, http_port=simulator.http_port, rtsp_port=rtsp.port,
    )
    try:
        await camera.connect()
        assert "speaker" not in camera.caps
    finally:
        await camera.close()
        await rtsp.stop()
