import asyncio
import contextlib
import hashlib
import struct
import xml.etree.ElementTree as ET

import aiohttp
import pytest
import pytest_asyncio

from sannce_aio.audio import G711A, SUBFRAME_PCM_BYTES, encode_alaw, frame_talk_audio
from sannce_aio.connection import NvsConnection
from sannce_aio.errors import AuthError
from sannce_aio.events import Event
from sannce_aio.http import Detection, HttpClient
from sannce_aio.login import PlaintextLogin
from sannce_aio.protocol import build_command, parse_frame
from sannce_aio.simulator import CameraSimulator

pytestmark = pytest.mark.asyncio

DEVICE_IP = "192.168.1.10"
USER = "admin"
PASSWORD = "admin123"
MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
MOTION_STOP = ["INNER", "ALARM", "MOTIONDETECT", "0", "0"]
TALK_REQUEST = [DEVICE_IP, "NVR", "0", "", "CMD", "TALK"]
BAD_CREDENTIALS = pytest.mark.parametrize(
    ("user", "password"),
    [(USER, "wrong"), ("root", PASSWORD)],
    ids=["password", "user"],
)
LIGHT_PATH = "/ISAPI/Image/channels/1/WhiteLight"
MODE_PATH = "/CGI/System/CommonEnable/channels/1/Type/4120"
DETECTION_PATH = "/ISAPI/System/Video/inputs/channels/1/motionDetection"
HTTP_GET_BODIES = [
    "http_device_info_reply",
    "http_capabilities_reply",
    "http_whitelight_get_reply",
    "http_motion_detection_get_reply",
]


def camera(*inner):
    return [DEVICE_IP, "IP", *inner]


TALK_REPLY = camera("INNER", "NVR", "0", "", "CMD", "TALK")


def fields_of(examples, example_id):
    frame, _ = parse_frame(bytes.fromhex(examples[example_id]["hex"]))
    return frame.fields


def body_of(examples, example_id):
    return examples[example_id]["text"].partition("\r\n\r\n")[2]


async def wait_until(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met in time")


class RawClient:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.buffer = bytearray()
        self.seq = 0

    def send(self, fields):
        self.writer.write(build_command(fields, self.seq))
        self.seq += 1

    def send_bytes(self, data):
        self.writer.write(data)

    async def recv(self, timeout=2.0):
        while True:
            frame, used = parse_frame(bytes(self.buffer))
            if frame is not None:
                del self.buffer[:used]
                return frame.fields
            chunk = await asyncio.wait_for(self.reader.read(4096), timeout)
            if not chunk:
                return None
            self.buffer += chunk

    async def login(self):
        logon = PlaintextLogin(DEVICE_IP).build_logon(USER, PASSWORD, self.seq)
        self.seq += 1
        self.send_bytes(logon)
        return [await self.recv(), await self.recv()]

    async def barrier(self):
        # the camera handles frames in order, so its answer to a heartbeat
        # proves it has handled everything sent before
        self.send([])
        assert await self.recv() == []

    async def close(self):
        self.writer.close()
        with contextlib.suppress(OSError):
            await self.writer.wait_closed()


class Http:
    def __init__(self, session, base):
        self.session = session
        self.base = base
        self.token = None

    async def call(self, method, path, body=None, *, headers=None):
        if headers is None:
            headers = {"HttpSession": self.token}
        async with self.session.request(
            method, self.base + path, data=body, headers=headers
        ) as reply:
            return reply.status, await reply.text()

    async def login(self):
        _, text = await self.call("GET", "/CGI/Security/SessionCheck", headers={})
        check = ET.fromstring(text)
        key = check.findtext("key")
        digest = sha256(USER + PASSWORD)
        for _ in range(int(check.findtext("iterations"))):
            digest = sha256(digest + key)
        body = (
            f"<User><passwd>{digest}</passwd>"
            f"<sessionTmp>{check.findtext('session')}</sessionTmp>"
            f"<username>{USER}</username></User>"
        )
        _, text = await self.call("POST", "/CGI/Security/Logon", body, headers={})
        reply = ET.fromstring(text)
        self.token = reply.findtext("session")
        return reply.findtext("statusString")


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest().upper()


@pytest_asyncio.fixture
async def make_connection(simulator):
    made = []

    def make(events=None, availability=None, **kwargs):
        kwargs.setdefault("login_timeout", 2.0)
        kwargs.setdefault("request_timeout", 2.0)
        conn = NvsConnection(
            simulator.host,
            simulator.port,
            PlaintextLogin(DEVICE_IP),
            on_event=(events.append if events is not None else lambda _event: None),
            on_availability=(
                availability.append if availability is not None else lambda _state: None
            ),
            **kwargs,
        )
        made.append(conn)
        return conn

    yield make
    for conn in made:
        await conn.close()


@pytest_asyncio.fixture
async def open_raw(simulator):
    clients = []

    async def open_(*, login=True):
        reader, writer = await asyncio.open_connection(simulator.host, simulator.port)
        client = RawClient(reader, writer)
        clients.append(client)
        if login:
            await client.login()
        return client

    yield open_
    for client in clients:
        await client.close()


@pytest_asyncio.fixture
async def http(simulator):
    async with aiohttp.ClientSession() as session:
        client = Http(session, f"http://{simulator.host}:{simulator.http_port}")
        assert await client.login() == "OK"
        yield client


@pytest_asyncio.fixture
async def client(simulator):
    http_client = HttpClient(simulator.host, USER, PASSWORD, port=simulator.http_port)
    yield http_client
    await http_client.close()


async def test_start_returns_both_ports():
    sim = CameraSimulator()
    try:
        host, port, http_port = await sim.start()
        assert (host, port, http_port) == (sim.host, sim.port, sim.http_port)
        assert 0 not in (port, http_port) and port != http_port
        for target in (port, http_port):
            _, writer = await asyncio.open_connection(host, target)
            writer.close()
            await writer.wait_closed()
    finally:
        await sim.stop()


async def test_connection_logs_in(simulator, make_connection):
    availability = []
    conn = make_connection(availability=availability)

    await conn.connect(USER, PASSWORD)

    assert availability == [True]
    assert simulator.clients == 1


@BAD_CREDENTIALS
async def test_connection_is_refused_for_bad_credentials(
    make_connection, user, password
):
    conn = make_connection(login_timeout=0.5)

    with pytest.raises(AuthError):
        await conn.connect(user, password)


async def test_request_round_trips_paraget(simulator, make_connection):
    simulator.params["DEVICETYPE"] = ["I91FW"]
    conn = make_connection()
    await conn.connect(USER, PASSWORD)

    reply = await conn.request([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE"])

    session_id = simulator.requests[-1][-1]
    assert reply[2:] == ["INNER", "PARAGET", "DEVICETYPE", "FINISHED", session_id, "0"]


async def test_pushed_events_reach_on_event_in_order(simulator, make_connection):
    events = []
    conn = make_connection(events=events)
    await conn.connect(USER, PASSWORD)

    await simulator.push_event(MOTION_START)
    await simulator.push_event(MOTION_STOP)

    await wait_until(lambda: len(events) == 2)
    assert events == [Event("motion", True, 0), Event("motion", False, 0)]


async def test_connection_heartbeats_are_counted_and_keep_it_available(
    simulator, make_connection
):
    availability = []
    conn = make_connection(availability=availability, heartbeat_interval=0.05)
    await conn.connect(USER, PASSWORD)

    await wait_until(lambda: simulator.heartbeats >= 3)

    assert availability == [True]


async def test_login_replies_with_command_id_then_finished(examples, open_raw):
    client = await open_raw(login=False)

    command_id, finished = await client.login()

    assert command_id[2:4] == ["INNER", "CMDID"] and len(command_id) == 5
    assert finished == fields_of(examples, "logon_reply_success")


async def test_nothing_is_answered_or_pushed_before_login(simulator, open_raw):
    client = await open_raw(login=False)
    await wait_until(lambda: simulator.clients == 1)
    client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE", "5"])
    await simulator.push_event(MOTION_START)

    command_id, _ = await client.login()

    assert command_id[2:4] == ["INNER", "CMDID"]
    assert simulator.requests == []


async def test_frame_with_a_bad_payload_is_skipped(open_raw):
    bad = bytearray(build_command(["a"], 0))
    del bad[-3:]
    bad[6:8] = len(bad).to_bytes(2, "little")
    bad[18:20] = (len(bad) - 20).to_bytes(2, "little")
    client = await open_raw()

    client.send_bytes(bytes(bad))

    await client.barrier()


async def test_heartbeat_is_answered_with_an_empty_packet(simulator, open_raw):
    client = await open_raw()

    client.send([])

    assert await client.recv() == []
    assert simulator.heartbeats == 1


async def test_paraget_sends_the_values_then_finished(simulator, open_raw):
    simulator.params["DEVICETYPE"] = ["I91FW", "2"]
    client = await open_raw()

    client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE", "5"])

    head = camera("INNER", "PARAGET", "DEVICETYPE")
    assert await client.recv() == [*head, "I91FW", "2"]
    assert await client.recv() == [*head, "FINISHED", "5", "0"]


async def test_paraset_stores_the_values_paraget_returns(simulator, open_raw):
    client = await open_raw()

    client.send([DEVICE_IP, "PROXY", "PARASET", "DEVICETYPE", "X1", "X2", "3"])
    head = camera("INNER", "PARASET", "DEVICETYPE")
    assert await client.recv() == [*head, "FINISHED", "3", "0"]
    client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE", "4"])

    assert (await client.recv())[4:] == ["DEVICETYPE", "X1", "X2"]
    assert simulator.params == {"DEVICETYPE": ["X1", "X2"]}


async def test_paraget_of_an_unknown_name_fails(open_raw):
    client = await open_raw()

    client.send([DEVICE_IP, "PROXY", "PARAGET", "NOSUCH", "6"])

    assert await client.recv() == camera(
        "INNER", "PARAGET", "NOSUCH", "FINISHED", "6", "1"
    )


async def test_command_without_a_session_id_is_recorded_but_not_answered(
    simulator, open_raw
):
    client = await open_raw()
    command = [DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE"]

    client.send(command)
    await client.barrier()

    assert simulator.requests == [command]


async def test_unknown_command_fails_instead_of_hanging(simulator, open_raw):
    client = await open_raw()

    client.send([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0", "7"])

    assert await client.recv() == camera(
        "INNER", "CMD", "GETPARAM", "FINISHED", "7", "1"
    )
    assert simulator.requests[-1][2:4] == ["CMD", "GETPARAM"]


async def test_pushed_event_matches_the_documented_message(
    simulator, open_raw, examples
):
    client = await open_raw()

    await simulator.push_event(MOTION_START)

    assert await client.recv() == fields_of(examples, "event_motion_start")


async def test_push_event_skips_a_session_that_is_closing(simulator, open_raw):
    client = await open_raw()
    (session,) = simulator._sessions
    session.writer.close()

    await simulator.push_event(MOTION_START)

    assert await client.recv() is None


async def test_events_reach_every_logged_in_client(simulator, open_raw):
    first = await open_raw()
    second = await open_raw()

    await simulator.push_event(MOTION_START)

    assert await first.recv() == await second.recv()


async def test_talk_begin_is_accepted(simulator, open_raw):
    client = await open_raw()

    client.send([*TALK_REQUEST, "BEGIN"])

    assert await client.recv() == [*TALK_REPLY, "BEGIN", "OK"]
    assert simulator.talking


async def test_talk_begin_with_the_optional_audio_fields_is_accepted(
    simulator, open_raw
):
    client = await open_raw()

    client.send([*TALK_REQUEST, "BEGIN", "1", "8000"])

    assert await client.recv() == [*TALK_REPLY, "BEGIN", "OK"]
    assert simulator.talking


async def test_talk_busy_is_refused_with_the_documented_reply(
    simulator, open_raw, examples
):
    simulator.set_talk_busy(True)
    client = await open_raw()

    client.send([*TALK_REQUEST, "BEGIN"])

    assert await client.recv() == fields_of(examples, "talk_refused_busy")
    assert not simulator.talking


async def test_talk_is_accepted_again_when_no_longer_busy(simulator, open_raw):
    simulator.set_talk_busy(True)
    client = await open_raw()
    client.send([*TALK_REQUEST, "BEGIN"])
    await client.recv()

    simulator.set_talk_busy(False)
    client.send([*TALK_REQUEST, "BEGIN"])

    assert await client.recv() == [*TALK_REPLY, "BEGIN", "OK"]


async def test_talk_on_a_missing_channel_is_refused(simulator, open_raw):
    client = await open_raw()

    client.send([DEVICE_IP, "NVR", "1", "", "CMD", "TALK", "BEGIN"])

    assert await client.recv() == camera(
        "INNER", "NVR", "1", "", "CMD", "TALK", "BEGIN", "ERROR"
    )
    assert not simulator.talking


@pytest.mark.parametrize(
    "request_fields",
    [
        [DEVICE_IP, "PROXY", "0", "", "CMD", "TALK", "BEGIN"],
        [DEVICE_IP, "PROXY", "CMD", "TALK", "BEGIN"],
    ],
    ids=["channel_on_proxy", "single_talk"],
)
async def test_talk_on_another_route_is_not_answered(
    simulator, open_raw, request_fields
):
    client = await open_raw()

    client.send(request_fields)
    await client.barrier()

    assert not simulator.talking


async def test_talk_audio_is_decoded_while_talking(simulator, open_raw, examples):
    packet = bytes.fromhex(examples["talk_audio_frame_g711a"]["hex"])
    client = await open_raw()
    client.send([*TALK_REQUEST, "BEGIN"])
    await client.recv()

    client.send_bytes(packet + packet)

    await wait_until(lambda: len(simulator.talk_frames) == 2)
    assert simulator.talk_frames == [packet[-80:], packet[-80:]]


async def test_talk_audio_from_the_library_framer_is_decoded(simulator, open_raw):
    pcm = struct.pack("<320h", *range(-16000, 16000, 100))
    client = await open_raw()
    client.send([*TALK_REQUEST, "BEGIN"])
    await client.recv()

    client.send_bytes(frame_talk_audio(pcm, G711A, 0, "10.1.2.3"))

    await wait_until(lambda: len(simulator.talk_frames) == 4)
    assert simulator.talk_frames == [
        encode_alaw(pcm[start : start + SUBFRAME_PCM_BYTES])
        for start in range(0, len(pcm), SUBFRAME_PCM_BYTES)
    ]


async def test_talk_audio_outside_a_talk_is_dropped(simulator, open_raw, examples):
    packet = bytes.fromhex(examples["talk_audio_frame_g711a"]["hex"])
    client = await open_raw()

    client.send_bytes(packet)
    await client.barrier()

    assert simulator.talk_frames == []


async def test_talk_end_is_acknowledged_and_stops_the_audio(
    simulator, open_raw, examples
):
    packet = bytes.fromhex(examples["talk_audio_frame_g711a"]["hex"])
    client = await open_raw()
    client.send([*TALK_REQUEST, "BEGIN"])
    await client.recv()

    client.send([*TALK_REQUEST, "END"])
    assert await client.recv() == [*TALK_REPLY, "END", "OK"]
    client.send_bytes(packet)
    await client.barrier()

    assert not simulator.talking
    assert simulator.talk_frames == []


async def test_talk_ends_when_the_client_disconnects(simulator, open_raw):
    client = await open_raw()
    client.send([*TALK_REQUEST, "BEGIN"])
    await client.recv()
    assert simulator.talking

    await client.close()

    await wait_until(lambda: not simulator.talking)


def truncate(packet):
    del packet[-1]
    packet[14:16] = len(packet).to_bytes(2, "little")


def extend(packet):
    packet.append(0)
    packet[14:16] = len(packet).to_bytes(2, "little")


def rename_marker(packet):
    packet[20:23] = b"XYZ"


def break_subheader_start(packet):
    packet[packet.index(b"NVS\x00") + 8] = 0xFF


def break_subheader_end(packet):
    packet[packet.index(b"NVS\x00") + 11] = 0x01


@pytest.mark.parametrize(
    "damage",
    [truncate, extend, rename_marker, break_subheader_start, break_subheader_end],
    ids=lambda damage: damage.__name__,
)
async def test_malformed_talk_audio_is_dropped(simulator, open_raw, examples, damage):
    packet = bytearray(bytes.fromhex(examples["talk_audio_frame_g711a"]["hex"]))
    damage(packet)
    client = await open_raw()
    client.send([*TALK_REQUEST, "BEGIN"])
    await client.recv()

    client.send_bytes(bytes(packet))
    await client.barrier()

    assert simulator.talk_frames == []


async def test_stop_releases_both_ports(simulator):
    await simulator.stop()

    for port in (simulator.port, simulator.http_port):
        with pytest.raises(ConnectionRefusedError):
            await asyncio.open_connection(simulator.host, port)


async def test_stop_closes_open_connections(simulator, open_raw):
    client = await open_raw()

    await asyncio.wait_for(simulator.stop(), 3.0)

    assert await client.recv() is None


async def test_stop_after_a_client_left_does_not_hang(simulator, open_raw):
    client = await open_raw()
    (session,) = simulator._sessions  # keeps the server-side writer alive
    await client.close()
    await wait_until(lambda: simulator.clients == 0)

    await asyncio.wait_for(simulator.stop(), 3.0)


@pytest.mark.parametrize("example_id", HTTP_GET_BODIES)
async def test_http_serves_the_example_body(examples, http, example_id):
    fields = examples[example_id]["fields"]

    status, text = await http.call(
        fields["method"], fields["path"], fields.get("request_body")
    )

    assert (status, text) == (200, body_of(examples, example_id))


@pytest.mark.parametrize(
    ("example_id", "attribute", "field"),
    [
        ("http_whitelight_set_manual_on", "light_control", "contrltype"),
        ("http_light_mode_set_smart", "light_mode", "value"),
    ],
)
async def test_http_put_example_updates_the_state(
    examples, simulator, http, example_id, attribute, field
):
    example = examples[example_id]

    status, text = await http.call(
        "PUT", example["fields"]["path"], body_of(examples, example_id)
    )

    assert status == 200
    assert ET.fromstring(text).findtext("statusCode") == "1"
    assert getattr(simulator, attribute) == example["fields"][field]


@pytest.mark.parametrize(
    "headers", [{}, {"HttpSession": "bogus"}], ids=["none", "bogus"]
)
async def test_http_denies_a_request_without_a_valid_session(http, headers):
    status, _ = await http.call("GET", "/CGI/System/deviceInfo", headers=headers)

    assert status == 401


@pytest.mark.parametrize("channel", [0, 2])
async def test_http_has_only_channel_one(http, channel):
    status, _ = await http.call("GET", f"/ISAPI/Image/channels/{channel}/WhiteLight")

    assert status == 404


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (LIGHT_PATH, "not xml"),
        (LIGHT_PATH, "<Other><contrltype>1</contrltype></Other>"),
        (LIGHT_PATH, "<WhiteLight/>"),
        (LIGHT_PATH, "<WhiteLight><contrltype>x</contrltype></WhiteLight>"),
        (MODE_PATH, "<CommonEnable/>"),
        (DETECTION_PATH, "not xml"),
    ],
    ids=["not_xml", "wrong_root", "no_number", "bad_number", "mode", "detection"],
)
async def test_http_rejects_a_malformed_put(http, path, body):
    status, _ = await http.call("PUT", path, body)

    assert status == 400


async def test_http_does_not_simulate_other_capability_queries(http):
    query = "<CapDiscription><capType>color2graylight</capType></CapDiscription>"

    status, _ = await http.call("POST", "/CGI/System/channels/1/capabilities", query)

    assert status == 404


@BAD_CREDENTIALS
async def test_http_logon_is_refused_for_bad_credentials(simulator, user, password):
    bad = HttpClient(simulator.host, user, password, port=simulator.http_port)
    try:
        with pytest.raises(AuthError):
            await bad.get_light()
    finally:
        await bad.close()


async def test_client_reads_the_example_capabilities(examples, client):
    fields = examples["http_capabilities_reply"]["fields"]

    assert await client.get_capabilities() == {
        "person": fields["person"],
        "vehicle": fields["vehicle"],
        "motion": fields["all_motion"],
    }


async def test_client_light_writes_reach_the_simulator(simulator, client):
    await client.set_light(True)
    assert simulator.light_control == 1
    assert (await client.get_light()).on

    await client.set_light(False)
    assert simulator.light_control == 0
    assert not (await client.get_light()).on


async def test_client_light_mode_writes_reach_the_simulator(simulator, client):
    await client.set_light_mode("smart")

    assert simulator.light_mode == 2
    assert await client.get_light_mode() == "smart"


async def test_client_detection_writes_reach_the_simulator(simulator, client):
    await client.set_detection(person=False, motion=True)

    assert simulator.detection == {"person": False, "vehicle": True, "motion": True}
    assert await client.get_detection() == Detection(
        person=False, vehicle=True, motion=True
    )
