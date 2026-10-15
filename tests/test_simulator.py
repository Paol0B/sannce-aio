import asyncio
import base64
import contextlib
import errno
import gc
import hashlib
import logging
import socket
import xml.etree.ElementTree as ET

import aiohttp
import pytest
import pytest_asyncio

from sannce_aio.connection import NvsConnection
from sannce_aio.discovery import (
    DiscoveredCamera,
    build_seek_request,
    parse_discovery_reply,
)
from sannce_aio.errors import AuthError, ProtocolError
from sannce_aio.events import Event, parse_event
from sannce_aio.http import Detection, HttpClient, LightState
from sannce_aio.login import SaltedLogin
from sannce_aio.protocol import build_command, parse_frame
from sannce_aio.simulator import CameraSimulator, event_fields

pytestmark = pytest.mark.asyncio

DEVICE_IP = "192.168.1.10"
USER = "admin"
PASSWORD = "admin123"
MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
MOTION_STOP = ["INNER", "ALARM", "MOTIONDETECT", "0", "0"]
BAD_CREDENTIALS = pytest.mark.parametrize(
    ("user", "password"),
    [(USER, "wrong"), ("root", PASSWORD)],
    ids=["password", "user"],
)
LIGHT_PATH = "/ISAPI/Image/channels/1/WhiteLight"
MODE_PATH = "/CGI/System/CommonEnable/channels/1/Type/4120"
DETECTION_PATH = "/ISAPI/System/Video/inputs/channels/1/motionDetection"
# header bytes 4-5 hold the sequence number, which differs from the examples
SEQUENCE_END = 6
HTTP_GET_BODIES = [
    "http_device_info_reply",
    "http_capabilities_reply",
]


def camera(*inner):
    return [DEVICE_IP, "IP", *inner]


def fields_of(examples, example_id):
    frame, _ = parse_frame(bytes.fromhex(examples[example_id]["hex"]))
    [fields] = frame.commands
    return fields


def example_bytes(examples, example_id):
    return bytes.fromhex(examples[example_id]["hex"])


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


def salted(value, salt):
    return base64.b64encode(hashlib.md5(value.encode() + salt).digest()).decode()


class RawClient:
    def __init__(self, session, ws):
        self.session = session
        self.ws = ws
        self.buffer = bytearray()
        self.commands = []
        self.packets = []
        self.seq = 0

    async def send(self, fields):
        await self.ws.send_bytes(build_command(fields, self.seq))
        self.seq += 1

    async def send_bytes(self, data):
        await self.ws.send_bytes(data)

    async def recv(self, timeout=2.0):
        while not self.commands:
            frame, used = parse_frame(bytes(self.buffer))
            if frame is None:
                message = await self.ws.receive(timeout)
                if message.type is not aiohttp.WSMsgType.BINARY:
                    return None
                self.buffer += message.data
                continue
            self.packets.append(bytes(self.buffer[:used]))
            del self.buffer[:used]
            if not frame.commands:
                return []
            self.commands.extend(frame.commands)
        return self.commands.pop(0)

    async def login(self):
        await self.send(SaltedLogin(DEVICE_IP).first_fields(USER, PASSWORD))
        replies = [await self.recv()]
        salt = base64.b64decode(replies[0][8])
        user, password = salted(USER, salt), salted(PASSWORD, salt)
        await self.send(
            [DEVICE_IP, "IP", "USER", "LOGON", user, password, "", "3", "UTF-8", "0", "1"]
        )
        while replies[-1][2:] != ["INNER", "LOGON", "FINISHED"]:
            reply = await self.recv()
            assert reply is not None, "the camera closed the connection during login"
            replies.append(reply)
        # the camera sends more messages right after LOGON FINISHED
        return replies + await self.read_all()

    async def barrier(self):
        # the camera handles frames in order, so its answer to a heartbeat
        # proves it has handled everything sent before
        await self.send([])
        assert await self.recv() == []

    async def read_all(self):
        # the heartbeat answer comes after every frame the camera sent before it
        await self.send([])
        frames = []
        while (fields := await self.recv()) != []:
            assert fields is not None, "the camera closed the connection"
            frames.append(fields)
        return frames

    async def close(self):
        await self.ws.close()
        await self.session.close()


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
            SaltedLogin(DEVICE_IP),
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
        session = aiohttp.ClientSession()
        try:
            ws = await session.ws_connect(f"ws://{simulator.host}:{simulator.port}")
        except BaseException:
            await session.close()
            raise
        client = RawClient(session, ws)
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

    with pytest.raises(AuthError, match="reason 2"):
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


async def test_login_asks_for_md5_then_finishes(examples, open_raw):
    client = await open_raw(login=False)

    refusal, command_id, channel_data, finished, *_ = await client.login()

    assert refusal[2:8] == ["INNER", "USER", "LOGONFAILED", "3", "1", "1"]
    assert len(base64.b64decode(refusal[8], validate=True)) == 8
    assert refusal[9:] == ["0", "0"]
    assert command_id[2:4] == ["INNER", "CMDID"] and len(command_id) == 5
    assert channel_data[2:] == ["INNER", "LOGON", "CHANNELDATA", "FINISHED"]
    assert finished == fields_of(examples, "logon_reply_success")


async def test_after_login_the_camera_sends_activation_and_two_commands_in_one_frame(
    open_raw,
):
    client = await open_raw(login=False)

    *_, activation, phone, users = await client.login()

    assert activation == camera("INNER", "USER", "ACTIVATION", "1")
    assert phone == camera("INNER", "USER", "RESERVEPHONE", "2", "0", "owner@example.com", "")
    assert users == camera("INNER", "SUPER", "GETUSERNUM", "2")
    payloads = [packet[20:] for packet in client.packets]
    assert b"192.168.1.10\tIP\tINNER\tUSER\tACTIVATION\t1\n\n\n\n\n\n" in payloads
    assert (
        b"192.168.1.10\tIP\tINNER\tUSER\tRESERVEPHONE\t2\t0\towner@example.com\t\n\n\n"
        b"INNER\tSUPER\tGETUSERNUM\t2\n\n\n"
    ) in payloads


async def test_nothing_is_answered_or_pushed_before_login(simulator, open_raw):
    client = await open_raw(login=False)
    await wait_until(lambda: simulator.clients == 1)
    await client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE", "5"])
    await simulator.push_event(MOTION_START)

    refusal, command_id, *_ = await client.login()

    assert refusal[2:6] == ["INNER", "USER", "LOGONFAILED", "3"]
    assert command_id[2:4] == ["INNER", "CMDID"]
    assert simulator.requests == []


async def test_frame_with_a_bad_payload_is_skipped(open_raw):
    bad = bytearray(build_command(["a"], 0))
    del bad[-3:]
    bad[6:8] = len(bad).to_bytes(2, "little")
    bad[18:20] = (len(bad) - 20).to_bytes(2, "little")
    client = await open_raw()

    await client.send_bytes(bytes(bad))

    await client.barrier()


async def test_heartbeat_is_answered_with_an_empty_packet(simulator, open_raw):
    client = await open_raw()
    before = simulator.heartbeats

    await client.send([])

    assert await client.recv() == []
    assert simulator.heartbeats == before + 1


async def test_paraget_sends_the_values_then_finished(simulator, open_raw):
    simulator.params["DEVICETYPE"] = ["I91FW", "2"]
    client = await open_raw()

    await client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE", "5"])

    head = camera("INNER", "PARAGET", "DEVICETYPE")
    assert await client.recv() == [*head, "I91FW", "2"]
    assert await client.recv() == [*head, "FINISHED", "5", "0"]


async def test_paraset_stores_the_values_paraget_returns(simulator, open_raw):
    client = await open_raw()

    await client.send([DEVICE_IP, "PROXY", "PARASET", "DEVICETYPE", "X1", "X2", "3"])
    head = camera("INNER", "PARASET", "DEVICETYPE")
    assert await client.recv() == [*head, "FINISHED", "3", "0"]
    await client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE", "4"])

    assert (await client.recv())[4:] == ["DEVICETYPE", "X1", "X2"]
    assert simulator.params == {"DEVICETYPE": ["X1", "X2"]}


async def test_paraget_of_an_unknown_name_fails(open_raw):
    client = await open_raw()

    await client.send([DEVICE_IP, "PROXY", "PARAGET", "NOSUCH", "6"])

    assert await client.recv() == camera(
        "INNER", "PARAGET", "NOSUCH", "FINISHED", "6", "1"
    )


async def test_command_without_a_session_id_is_recorded_but_not_answered(
    simulator, open_raw
):
    client = await open_raw()
    command = [DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE"]

    await client.send(command)
    await client.barrier()

    assert simulator.requests == [command]


async def test_unknown_command_fails_instead_of_hanging(simulator, open_raw):
    client = await open_raw()

    await client.send([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0", "7"])

    assert await client.recv() == camera(
        "INNER", "CMD", "GETPARAM", "FINISHED", "7", "1"
    )
    assert simulator.requests[-1][2:4] == ["CMD", "GETPARAM"]


async def test_pushed_event_matches_the_documented_message(
    simulator, open_raw, examples
):
    client = await open_raw()

    await simulator.push_event([*MOTION_START, "0012310019100435"])

    assert await client.recv() == fields_of(examples, "event_motion_start")
    documented = example_bytes(examples, "event_motion_start")
    assert client.packets[-1][SEQUENCE_END:] == documented[SEQUENCE_END:]


@pytest.mark.parametrize(
    ("action", "example_id"),
    [("start_alarm", "event_motion_start"), ("stop_alarm", "event_motion_stop")],
)
async def test_alarms_match_the_documented_bytes(
    simulator, open_raw, examples, action, example_id
):
    client = await open_raw()

    await getattr(simulator, action)("motion")

    assert await client.recv() == fields_of(examples, example_id)
    documented = example_bytes(examples, example_id)
    assert client.packets[-1][SEQUENCE_END:] == documented[SEQUENCE_END:]


async def test_push_event_skips_a_session_that_is_closing(simulator, open_raw):
    client = await open_raw()
    (session,) = simulator._sessions
    await session.ws.close()
    # the closed handler has already dropped it; list it again as if it had not
    simulator._sessions.add(session)

    await simulator.push_event(MOTION_START)

    assert await client.recv() is None


async def test_events_reach_every_logged_in_client(simulator, open_raw):
    first = await open_raw()
    second = await open_raw()

    await simulator.push_event(MOTION_START)

    assert await first.recv() == await second.recv()


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
    (session,) = simulator._sessions  # keeps the server-side session alive
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
    [("http_light_mode_set_smart", "light_mode", "value")],
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
    await client.set_light_mode("color")
    await client.force_light_on(40)
    assert simulator.light_control == 3
    assert (simulator.light_on_time, simulator.light_off_time) == ("00:00:00", "23:59:00")
    assert simulator.light_power == 40
    assert simulator.lamp_on
    assert (await client.get_light()).forced_on

    await client.release_light()
    assert simulator.light_control == 0
    assert not simulator.lamp_on
    assert not (await client.get_light()).forced_on


async def test_manual_on_is_refused_like_the_camera(client):
    with pytest.raises(ProtocolError, match="Device Error"):
        await client._write(
            "/ISAPI/Image/channels/1/WhiteLight",
            "<WhiteLight><contrltype>1</contrltype></WhiteLight>",
        )


@pytest.mark.parametrize(("mode", "control"), [("infrared", 2), ("smart", 2), ("color", 0)])
async def test_a_mode_change_resets_the_lamp_control(simulator, client, mode, control):
    simulator.light_control = 3
    await client.set_light_mode(mode)
    assert simulator.light_control == control


async def test_the_lamp_is_on_only_in_color_or_custom(simulator, client):
    await client.force_light_on(50)
    assert simulator.lamp_on is (simulator.light_mode in (3, 4))


async def test_client_reads_the_light_and_detection_as_the_camera_sends_them(client):
    assert await client.get_light() == LightState(
        control=2,
        options=(0, 2, 3),
        power=100,
        far_power=100,
        on_time="17:00:00",
        off_time="07:00:00",
    )
    assert await client.get_detection() == Detection(
        person=True, vehicle=True, motion=False, sensitivity=76
    )


async def test_play_audio_beyond_the_samples_is_refused(client):
    with pytest.raises(ProtocolError, match="Device Error"):
        await client.play_sound(3)


async def test_the_siren_link_comes_and_goes_beside_the_lamp_link(simulator, client):
    await client.set_siren_on_event(True)
    assert [link["notificationMethod"] for link in simulator.vmd_links] == [
        "whiteLampForBody",
        "guardsound",
    ]
    assert simulator.siren_on_event

    await client.set_siren_on_event(False)
    assert [link["notificationMethod"] for link in simulator.vmd_links] == ["whiteLampForBody"]
    assert not simulator.siren_on_event


async def test_client_light_mode_writes_reach_the_simulator(simulator, client):
    await client.set_light_mode("smart")

    assert simulator.light_mode == 2
    assert await client.get_light_mode() == "smart"


async def test_client_detection_writes_reach_the_simulator(simulator, client):
    await client.set_detection(person=False, motion=True)

    assert simulator.detection == {"person": False, "vehicle": True, "motion": True}
    assert await client.get_detection() == Detection(
        person=False, vehicle=True, motion=True, sensitivity=76
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def connects(host, port):
    try:
        _, writer = await asyncio.open_connection(host, port)
    except OSError:
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


class SeekReceiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.replies.put_nowait((data, addr))


@pytest_asyncio.fixture
async def searchable():
    sim = CameraSimulator(
        search_ports=(0,),
        model="CAM-SIM",
        serial="SN-SIM",
        mac="00:00:5E:00:53:99",
    )
    await sim.start()
    yield sim
    await sim.stop()


@pytest_asyncio.fixture
async def seeker():
    loop = asyncio.get_running_loop()
    transport, receiver = await loop.create_datagram_endpoint(
        SeekReceiver, local_addr=("127.0.0.1", 0)
    )
    yield transport, receiver
    transport.close()


async def test_fixed_ports_are_used():
    nvs, http = free_port(), free_port()
    sim = CameraSimulator(port=nvs, http_port=http)
    try:
        assert await sim.start() == ("127.0.0.1", nvs, http)
    finally:
        await sim.stop()


async def test_a_taken_port_fails_the_start_and_closes_what_it_opened():
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        sim = CameraSimulator(port=free_port(), http_port=holder.getsockname()[1])

        with pytest.raises(OSError):
            await sim.start()

    assert not await connects(sim.host, sim.port)


@pytest.mark.parametrize(
    "mac", ["", "00:00:5E:00:53", "00-00-5E-00-53-01", "00:00:5E:00:53:0G"]
)
async def test_a_malformed_mac_is_refused(mac):
    with pytest.raises(ValueError, match="is not a MAC"):
        CameraSimulator(mac=mac)


async def test_seek_request_gets_the_identity_back_from_the_search_port(
    searchable, seeker
):
    transport, receiver = seeker
    (search_port,) = searchable.search_ports

    transport.sendto(build_seek_request(), (searchable.host, search_port))

    data, source = await asyncio.wait_for(receiver.replies.get(), 2)
    assert source == (searchable.host, search_port)
    assert parse_discovery_reply(data, source[0]) == DiscoveredCamera(
        ip="127.0.0.1",
        mac="00:00:5E:00:53:99",
        serial="SN-SIM",
        model="CAM-SIM",
        http_port=searchable.http_port,
        server_port=searchable.port,
        channels=1,
    )


async def test_other_datagrams_get_no_reply(searchable, seeker):
    transport, receiver = seeker
    (search_port,) = searchable.search_ports

    transport.sendto(b"hello", (searchable.host, search_port))

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(receiver.replies.get(), 0.2)
    transport.sendto(build_seek_request(), (searchable.host, search_port))
    await asyncio.wait_for(receiver.replies.get(), 2)


async def test_stop_releases_the_search_port(searchable):
    (search_port,) = searchable.search_ports

    await searchable.stop()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((searchable.host, search_port))


async def test_the_search_socket_listens_on_every_address(searchable):
    (transport,) = searchable._search

    assert transport.get_extra_info("sockname")[0] == "0.0.0.0"


async def test_the_search_joins_the_groups_on_the_host_interface(monkeypatch):
    interfaces = []

    def join_groups(sock, interface):
        interfaces.append(interface)
        return {}

    monkeypatch.setattr("sannce_aio.simulator.join_groups", join_groups)
    sim = CameraSimulator(search_ports=(0,))
    await sim.start()
    await sim.stop()

    assert interfaces == ["127.0.0.1"]


async def test_a_group_the_search_cannot_join_is_logged(monkeypatch, caplog):
    error = OSError(errno.ENODEV, "No such device")
    monkeypatch.setattr(
        "sannce_aio.simulator.join_groups",
        lambda sock, interface: {"234.56.78.9": error},
    )
    sim = CameraSimulator(search_ports=(0,))
    await sim.start()
    await sim.stop()

    [message] = caplog.messages
    assert message.startswith("cannot join 234.56.78.9 on UDP ")
    assert message.endswith(str(error))


async def test_a_dropped_camera_does_not_answer_the_search(searchable, seeker):
    transport, receiver = seeker
    (search_port,) = searchable.search_ports
    await searchable.drop(30)

    transport.sendto(build_seek_request(), (searchable.host, search_port))

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(receiver.replies.get(), 0.2)
    await searchable.reset()
    transport.sendto(build_seek_request(), (searchable.host, search_port))
    await asyncio.wait_for(receiver.replies.get(), 2)


async def test_drop_closes_sessions_and_refuses_connections(simulator, open_raw):
    client = await open_raw()

    await simulator.drop(30)

    assert await client.recv() is None
    assert simulator.clients == 0
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection(simulator.host, simulator.port)


async def test_drop_ends_the_http_sessions(simulator, http):
    dropped = http.token
    await simulator.drop(0)

    status, _ = await http.call("GET", "/CGI/System/deviceInfo")

    assert status == 401
    assert await http.login() == "OK"
    assert http.token != dropped


async def test_connection_returns_after_a_drop_without_a_login_failure(
    simulator, make_connection
):
    availability = []
    failures = []
    conn = make_connection(
        availability=availability,
        backoff_start=0.05,
        on_login_failed=failures.append,
    )
    await conn.connect(USER, PASSWORD)

    await simulator.drop(0.3)

    await wait_until(lambda: availability == [True, False, True])
    assert failures == []
    assert simulator.clients == 1


async def test_reset_reopens_a_dropped_camera(simulator):
    await simulator.drop(30)

    await simulator.reset()

    assert await connects(simulator.host, simulator.port)


async def test_stop_cancels_a_pending_reopen(simulator):
    await simulator.drop(0.1)

    await simulator.stop()
    await asyncio.sleep(0.3)

    assert not await connects(simulator.host, simulator.port)


async def test_a_failed_reopen_is_logged_and_reset_opens_the_port(simulator, caplog):
    await simulator.drop(0.1)
    with socket.socket() as holder:
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind((simulator.host, simulator.port))
        holder.listen()

        await wait_until(lambda: caplog.records)

    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert f"[Errno {errno.EADDRINUSE}]" in record.getMessage()
    await simulator.reset()
    assert await connects(simulator.host, simulator.port)


async def test_two_concurrent_drops_reopen_the_port_once(
    simulator, open_raw, monkeypatch
):
    leaks = []
    asyncio.get_running_loop().set_exception_handler(
        lambda _loop, context: leaks.append(context)
    )
    opens = 0
    open_server = simulator._open_server

    async def count_opens():
        nonlocal opens
        opens += 1
        await open_server()

    monkeypatch.setattr(simulator, "_open_server", count_opens)
    # closing a session makes the first drop wait, so the second one runs meanwhile
    await open_raw()

    await asyncio.gather(simulator.drop(0.1), simulator.drop(0.2))
    await wait_until(lambda: opens)
    await asyncio.sleep(0.3)
    await simulator.stop()
    gc.collect()

    assert opens == 1
    assert leaks == []


async def test_reset_restores_the_start_state(simulator, open_raw):
    client = await open_raw()
    await client.send([DEVICE_IP, "PROXY", "PARAGET", "DEVICETYPE"])
    await client.barrier()
    simulator.params["DEVICETYPE"] = ["I91FW"]
    assert simulator.requests and simulator.heartbeats
    simulator.light_control = 3
    simulator.light_mode = 3
    simulator.light_on_time = "00:00:00"
    simulator.light_power = 20
    simulator.sounds.append((1, 1))
    simulator.volume = 10
    simulator.vmd_links.append({"id": "guardsound-1", "notificationMethod": "guardsound"})
    simulator.detection["motion"] = True
    simulator.sensitivity = 5
    simulator.password = "changed"

    await simulator.reset()

    assert (simulator.light_control, simulator.light_mode) == (2, 2)
    assert (simulator.light_on_time, simulator.light_power) == ("17:00:00", 100)
    assert (simulator.sounds, simulator.volume) == ([], 80)
    assert simulator.siren_on_event is False
    assert simulator.detection == {"person": True, "vehicle": True, "motion": False}
    assert simulator.sensitivity == 76
    assert simulator.password == PASSWORD
    assert (simulator.requests, simulator.heartbeats) == ([], 0)
    assert simulator.params == {}
    assert simulator.clients == 1
    await client.barrier()


async def test_a_new_password_holds_for_new_logins_only(
    simulator, make_connection, open_raw
):
    logged_in = await open_raw()

    simulator.password = "changed"

    await logged_in.barrier()
    with pytest.raises(AuthError):
        await make_connection(login_timeout=0.5).connect(USER, PASSWORD)
    await make_connection().connect(USER, "changed")


@pytest.mark.parametrize(
    ("kind", "example_id", "route", "event_id"),
    [
        ("motion", "event_motion_start", "PROXY", "0012310019100435"),
        ("vehicle", "event_smart_vehicle", "IP", ""),
        ("intrusion", "event_vca_intrusion", "IP", ""),
        ("tamper", "event_video_cover", "IP", ""),
    ],
)
async def test_event_fields_match_the_documented_start(
    examples, kind, example_id, route, event_id
):
    fields = [DEVICE_IP, route, *event_fields(kind, True, event_id)]
    assert fields == fields_of(examples, example_id)


@pytest.mark.parametrize(
    "kind", ["motion", "vehicle", "intrusion", "line", "tamper", "video_loss"]
)
@pytest.mark.parametrize("active", [True, False])
async def test_event_fields_parse_back_to_the_kind(kind, active):
    assert parse_event(camera(*event_fields(kind, active))) == Event(kind, active, 0)


async def test_event_fields_reject_an_unknown_kind():
    with pytest.raises(ValueError, match="person"):
        event_fields("person", True)


async def test_an_active_alarm_repeats_until_stopped(simulator, open_raw):
    simulator.alarm_interval = 0.05
    client = await open_raw()
    await simulator.start_alarm("motion")
    await asyncio.sleep(0.2)
    await simulator.stop_alarm("motion")

    # fields: ip, route, INNER, ALARM, MOTIONDETECT, channel, state, id
    alarms = [f for f in await client.read_all() if f[3:5] == ["ALARM", "MOTIONDETECT"]]
    assert len(alarms) >= 4
    assert all(f[1] == "PROXY" and f[7] == "0012310019100435" for f in alarms)
    assert [f[6] for f in alarms[:-1]] == ["1"] * (len(alarms) - 1)
    assert alarms[-1][6] == "0"


async def test_an_idle_session_gets_keepalive_messages(open_raw, simulator):
    simulator.keepalive_interval = 0.05
    client = await open_raw()
    await asyncio.sleep(0.2)

    frames = await client.read_all()
    assert any(f[1:6] == ["PROXY", "INNER", "CMD", "EXCEPTION", "0"] for f in frames)
    keepalives = [packet for packet in client.packets if b"\tEXCEPTION\t" in packet]
    assert all(packet.endswith(b"\tEXCEPTION\t0\t0\n\n\n\n\n\n") for packet in keepalives)
