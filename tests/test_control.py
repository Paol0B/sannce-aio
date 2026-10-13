import asyncio
import io
import json
import struct
import wave

import aiohttp
import pytest
import pytest_asyncio

from sannce_aio.audio import decode_alaw, encode_alaw
from sannce_aio.connection import NvsConnection
from sannce_aio.control import start_control
from sannce_aio.errors import AuthError, TalkBusyError
from sannce_aio.events import Event
from sannce_aio.login import PlaintextLogin

pytestmark = pytest.mark.asyncio

DEVICE_IP = "192.168.1.10"
START_STATE = {
    "light": False,
    "light_mode": "infrared",
    "detection": {"person": True, "vehicle": True, "motion": False},
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


@pytest_asyncio.fixture
async def api(simulator):
    runner = await start_control(simulator, "127.0.0.1", 0)
    try:
        async with aiohttp.ClientSession() as session:
            yield Api(session, f"http://127.0.0.1:{runner.addresses[0][1]}")
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def connect(simulator):
    made = []

    async def connect_(events=None, password=None):
        conn = NvsConnection(
            simulator.host,
            simulator.port,
            PlaintextLogin(DEVICE_IP),
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

    assert await api.post("/event", {"kind": "vehicle", "active": True}) == (204, "")

    await asyncio.wait_for(_until(lambda: events), 2)
    assert events == [Event("vehicle", True, 0)]


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
    }

    assert await api.post("/settings", body) == (204, "")

    assert (simulator.light_control, simulator.light_mode) == (1, 3)
    assert simulator.detection == {"person": False, "vehicle": True, "motion": True}
    state = await api.state()
    assert (state["light"], state["light_mode"]) == (True, "color")


async def test_light_off_means_auto(simulator, api):
    simulator.light_control = 1

    await api.post("/settings", {"light": False})

    assert simulator.light_control == 0


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"brightness": 5},
        {"light": "on"},
        {"light_mode": "custom"},
        {"light_mode": 3},
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


async def test_drop_refuses_connections_until_reset(simulator, api, connect):
    await connect()

    assert await api.post("/drop", {"seconds": 30}) == (204, "")

    assert (await api.state())["clients"] == 0
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection(simulator.host, simulator.port)
    assert await api.post("/reset") == (204, "")
    await connect()


@pytest.mark.parametrize("seconds", [-1, 3601, "5", True, None])
async def test_bad_drop_is_refused(api, seconds):
    status, text = await api.post("/drop", {"seconds": seconds})

    assert (status, text) == (400, "seconds is a number from 0 to 3600")


async def test_talk_busy_refuses_talk(api, connect):
    conn = await connect()

    await api.post("/talk-busy", {"busy": True})
    with pytest.raises(TalkBusyError):
        await conn.start_talk(0)

    await api.post("/talk-busy", {"busy": False})
    await conn.start_talk(0)
    assert (await api.state())["talking"] is True


async def test_audio_is_the_last_talk_session_as_wav(api, connect):
    pcm = struct.pack("<160h", *range(-8000, 8000, 100))
    conn = await connect()
    await conn.start_talk(0)
    await conn.send_audio(pcm)
    await conn.stop_talk()

    status, content_type, body = await api.get("/audio.wav")

    assert (status, content_type) == (200, "audio/wav")
    with wave.open(io.BytesIO(body)) as wav:
        assert (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) == (
            1,
            2,
            8000,
        )
        assert wav.readframes(wav.getnframes()) == decode_alaw(encode_alaw(pcm))


async def test_reset_restores_the_start_state(api):
    await api.post("/settings", {"light": True, "light_mode": "smart"})
    await api.post("/password", {"password": "new-pass"})
    await api.post("/talk-busy", {"busy": True})

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


async def _until(predicate):
    while not predicate():
        await asyncio.sleep(0.01)
