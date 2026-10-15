import asyncio
import contextlib
import io
import json
import struct
import wave

import aiohttp
import pytest
import pytest_asyncio

from sannce_aio.audio import decode_alaw, encode_alaw
from sannce_aio.backchannel import Backchannel
from sannce_aio.connection import NvsConnection
from sannce_aio.control import start_control
from sannce_aio.errors import AuthError, TalkBusyError
from sannce_aio.events import Event
from sannce_aio.login import SaltedLogin
from sannce_aio.simulator_rtsp import RtspFront

from .rtsp_fake import FakeRtspCamera

pytestmark = pytest.mark.asyncio

DEVICE_IP = "192.168.1.10"
START_STATE = {
    "light": False,
    "light_power": 100,
    "light_mode": "smart",
    "detection": {"person": True, "vehicle": True, "motion": False, "sensitivity": 76},
    "sounds": [],
    "volume": 80,
    "siren_on_event": False,
    "clients": 0,
    "talking": False,
    "user": "admin",
    "password": "admin123",
}
POST_PATHS = ["/event", "/settings", "/password", "/drop", "/talk-busy"]


class Api:
    def __init__(self, session, url):
        self.session = session
        self.url = url

    async def post(self, path, body=None, *, data=None):
        async with self.session.post(self.url + path, json=body, data=data) as reply:
            return reply.status, await reply.text()

    async def get(self, path):
        async with self.session.get(self.url + path) as reply:
            return reply.status, reply.content_type, await reply.read()

    async def state(self):
        status, _, body = await self.get("/state")
        assert status == 200
        return json.loads(body)


@contextlib.asynccontextmanager
async def serve(simulator, front):
    runner = await start_control(simulator, "127.0.0.1", 0, front)
    try:
        async with aiohttp.ClientSession() as session:
            yield Api(session, f"http://127.0.0.1:{runner.addresses[0][1]}")
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def front():
    upstream = FakeRtspCamera(auth=False, backchannel=False)
    await upstream.start()
    proxy = RtspFront(
        host="127.0.0.1", port=0, upstream_host=upstream.host,
        upstream_port=upstream.port, username="admin", password="admin123",
    )
    await proxy.start()
    yield proxy
    await proxy.stop()
    await upstream.stop()


@pytest_asyncio.fixture
async def api(simulator, front):
    async with serve(simulator, front) as api:
        yield api


@pytest_asyncio.fixture
async def bare_api(simulator):
    async with serve(simulator, None) as api:
        yield api


@pytest_asyncio.fixture
async def connect(simulator):
    made = []

    async def connect_(events=None, password=None):
        conn = NvsConnection(
            simulator.host,
            simulator.port,
            SaltedLogin(DEVICE_IP),
            on_event=(events.append if events is not None else lambda _event: None),
            on_availability=lambda _state: None,
            login_timeout=2.0,
            request_timeout=2.0,
        )
        made.append(conn)
        await conn.connect(simulator.username, password or simulator.password)
        return conn

    yield connect_
    for conn in made:
        await conn.close()


async def test_state_starts_at_the_start_state(api):
    assert await api.state() == START_STATE


async def test_state_counts_clients(api, connect):
    await connect()

    assert (await api.state())["clients"] == 1


async def test_event_reaches_a_logged_in_connection(api, connect):
    events = []
    await connect(events)

    assert await api.post("/event", {"kind": "motion", "active": True}) == (204, "")

    await asyncio.wait_for(_until(lambda: events), 2)
    assert set(events) == {Event("motion", True, 0)}


async def test_event_off_sends_one_stop(api, connect):
    events = []
    await connect(events)

    assert await api.post("/event", {"kind": "motion", "active": False}) == (204, "")

    await asyncio.wait_for(_until(lambda: events), 2)
    await asyncio.sleep(0.2)
    assert events == [Event("motion", False, 0)]


async def test_unknown_event_kind_is_refused(api):
    status, text = await api.post("/event", {"kind": "person", "active": True})

    assert (status, text) == (400, "unknown event kind 'person'")


@pytest.mark.parametrize("active", ["yes", 1, None])
async def test_event_active_that_is_not_a_bool_is_refused(api, active):
    status, text = await api.post("/event", {"kind": "motion", "active": active})

    assert (status, text) == (400, "active is true or false")


async def test_settings_change_the_camera(simulator, api):
    body = {
        "light": True,
        "light_mode": "color",
        "detection": {"person": False, "motion": True},
        "volume": 35,
    }

    assert await api.post("/settings", body) == (204, "")

    assert (simulator.light_control, simulator.light_mode) == (3, 3)
    assert simulator.detection == {"person": False, "vehicle": True, "motion": True}
    assert simulator.volume == 35
    state = await api.state()
    assert (state["light"], state["light_mode"], state["volume"]) == (True, "color", 35)


async def test_light_settings_force_and_release_the_lamp(simulator, api):
    await api.post("/settings", {"light": True})

    assert simulator.light_mode == 3
    assert simulator.lamp_on is True
    assert (await api.state())["light"] is True

    await api.post("/settings", {"light": False})

    assert simulator.light_control == 0
    assert simulator.lamp_on is False
    assert (await api.state())["light"] is False


async def test_state_reports_what_the_camera_did(simulator, api):
    simulator.sounds.append((2, 1))
    simulator.vmd_links.append({"id": "guardsound-1", "notificationMethod": "guardsound"})
    simulator.sensitivity = 90
    simulator.light_power = 40

    state = await api.state()

    assert state["sounds"] == [[2, 1]]
    assert state["siren_on_event"] is True
    assert state["detection"]["sensitivity"] == 90
    assert state["light_power"] == 40


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"brightness": 5},
        {"light": "on"},
        {"light_mode": "custom"},
        {"light_mode": 3},
        {"volume": 101},
        {"volume": -1},
        {"volume": True},
        {"volume": "30"},
        {"volume": 30.5},
        {"light": True, "volume": None},
        {"detection": {"face": True}},
        {"detection": {"motion": 1}},
        {"detection": []},
        {"light": True, "detection": {"motion": "yes"}},
    ],
)
async def test_bad_settings_change_nothing(api, body):
    status, _ = await api.post("/settings", body)

    assert status == 400
    assert await api.state() == START_STATE


async def test_password_holds_for_new_logins(simulator, api, connect):
    assert await api.post("/password", {"password": "new-pass"}) == (204, "")

    assert (await api.state())["password"] == "new-pass"
    await connect()
    with pytest.raises(AuthError):
        await connect(password="admin123")


async def test_password_change_reaches_the_front(api, front):
    assert await api.post("/password", {"password": "new-pass"}) == (204, "")

    new = Backchannel("127.0.0.1", front.port, "/1/1", "admin", "new-pass", timeout=2.0)
    assert await new.has_backchannel() is True
    with pytest.raises(AuthError):
        await talk(front).open()

    assert await api.post("/reset") == (204, "")

    assert await talk(front).has_backchannel() is True
    with pytest.raises(AuthError):
        await new.open()


async def test_drop_refuses_connections_until_reset(simulator, api, connect):
    await connect()

    assert await api.post("/drop", {"seconds": 30}) == (204, "")

    assert (await api.state())["clients"] == 0
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection(simulator.host, simulator.port)
    assert await api.post("/reset") == (204, "")
    await connect()


def talk(front):
    return Backchannel("127.0.0.1", front.port, "/1/1", "admin", "admin123", timeout=2.0)


async def talk_once(front, pcm):
    channel = talk(front)
    await channel.open()
    await channel.stream(_chunks(pcm))
    await channel.close()
    await asyncio.wait_for(_until(lambda: not front.speaking), 2)


async def test_talk_busy_refuses_the_backchannel(api, front):
    channel = talk(front)

    assert await api.post("/talk-busy", {"busy": True}) == (204, "")
    with pytest.raises(TalkBusyError):
        await channel.open()

    assert await api.post("/talk-busy", {"busy": False}) == (204, "")
    await channel.open()
    try:
        assert (await api.state())["talking"] is True
    finally:
        await channel.close()


@pytest.mark.parametrize("busy", ["yes", 1, None])
async def test_talk_busy_that_is_not_a_bool_is_refused(api, front, busy):
    status, text = await api.post("/talk-busy", {"busy": busy})

    assert (status, text) == (400, "busy is true or false")
    assert front.busy is False


async def test_audio_is_the_last_talk_session_as_wav(api, front):
    pcm = struct.pack("<160h", *range(-8000, 8000, 100))
    await talk_once(front, pcm)

    status, content_type, body = await api.get("/audio.wav")

    assert (status, content_type) == (200, "audio/wav")
    with wave.open(io.BytesIO(body)) as wav:
        assert (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) == (1, 2, 8000)
        assert wav.readframes(wav.getnframes()) == decode_alaw(encode_alaw(pcm))


async def test_reset_clears_the_front(api, front):
    await talk_once(front, struct.pack("<160h", *range(160)))
    await api.post("/talk-busy", {"busy": True})

    assert await api.post("/reset") == (204, "")

    assert front.busy is False
    status, _, body = await api.get("/audio.wav")
    assert (status, len(body)) == (200, 44)


async def test_without_a_front_the_talk_endpoints_answer_404(bare_api):
    assert await bare_api.post("/talk-busy", {"busy": True}) == (404, "no RTSP front")
    status, _, body = await bare_api.get("/audio.wav")
    assert (status, body) == (404, b"no RTSP front")


async def test_without_a_front_nobody_is_talking(bare_api):
    assert await bare_api.state() == START_STATE
    assert await bare_api.post("/reset") == (204, "")


@pytest.mark.parametrize("seconds", [-1, 3601, "5", True, None])
async def test_bad_drop_is_refused(api, seconds):
    status, text = await api.post("/drop", {"seconds": seconds})

    assert (status, text) == (400, "seconds is a number from 0 to 3600")


async def test_reset_restores_the_start_state(api):
    await api.post("/settings", {"light": True, "light_mode": "smart", "volume": 10})
    await api.post("/password", {"password": "new-pass"})

    assert await api.post("/reset") == (204, "")

    assert await api.state() == START_STATE


@pytest.mark.parametrize("path", POST_PATHS)
async def test_a_body_that_is_not_json_is_refused(api, path):
    status, text = await api.post(path, data=b"not json")

    assert (status, text) == (400, "the body is not JSON")


@pytest.mark.parametrize("path", POST_PATHS)
async def test_a_body_that_is_not_an_object_is_refused(api, path):
    status, text = await api.post(path, [1, 2])

    assert (status, text) == (400, "the body is not a JSON object")


async def _chunks(*parts):
    for part in parts:
        yield part


async def _until(predicate):
    while not predicate():
        await asyncio.sleep(0.01)
