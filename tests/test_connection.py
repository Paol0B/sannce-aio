import asyncio
import base64
import hashlib
import logging

import aiohttp
import pytest
from aiohttp import WSMsgType, web

from sannce_aio.connection import NvsConnection
from sannce_aio.errors import AuthError, ConnectError
from sannce_aio.events import Event
from sannce_aio.login import SaltedLogin
from sannce_aio.protocol import build_command, encode_fields, pack_command, parse_frame
from sannce_aio.transport import WsTransport

DEVICE_IP = "192.168.1.10"
SALT = b"\x01\x02\x03\x04\x05\x06\x07\x08"


def salted(value):
    return base64.b64encode(hashlib.md5(value.encode() + SALT).digest()).decode()


def event_frame(channel):
    fields = [DEVICE_IP, "IP", "INNER", "ALARM", "MOTIONDETECT", str(channel), "1"]
    return build_command(fields, 0)


class FakeCamera:
    def __init__(
        self,
        *,
        reply_to_requests=True,
        finish_login=True,
        reject_reconnect=False,
        refuse_login=False,
        answer_md5=True,
        login_payload=None,
        reply_tail=b"",
    ):
        self._reply_to_requests = reply_to_requests
        self._finish_login = finish_login
        self._reject_reconnect = reject_reconnect
        self.refuse_login = refuse_login
        self.answer_md5 = answer_md5
        self._login_payload = login_payload
        self._reply_tail = reply_tail
        self.close_logins = 0
        self._runner = None
        self._ws = None
        self.port = None
        self.connections = 0
        self.heartbeats = 0
        self.requests = []
        self.logons = []

    async def start(self):
        app = web.Application()
        app.router.add_get("/", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, "127.0.0.1", 0).start()
        self.port = self._runner.addresses[0][1]

    async def stop(self):
        await self._runner.cleanup()

    async def drop_client(self):
        ws, self._ws = self._ws, None
        if ws is not None:
            await ws.close()

    async def send(self, fields):
        await self._ws.send_bytes(build_command(fields, 0))

    async def send_raw(self, data):
        await self._ws.send_bytes(data)

    async def _handle(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.connections += 1
        self._ws = ws
        buffer = bytearray()
        async for msg in ws:
            if msg.type is not WSMsgType.BINARY:
                continue
            buffer += msg.data
            while True:
                frame, consumed = parse_frame(bytes(buffer))
                if frame is None:
                    break
                del buffer[:consumed]
                await self._react(frame, ws)
        return ws

    async def _react(self, frame, ws):
        if not frame.commands:
            self.heartbeats += 1
            return
        [fields] = frame.commands
        if fields[2:4] == ["USER", "LOGON"]:
            await self._logon(fields, ws)
            return
        self.requests.append(fields)
        if self._reply_to_requests:
            session_id = fields[-1]
            reply = [DEVICE_IP, "IP", "INNER", "CMD", "GETPARAM", "FINISHED", session_id, "0"]
            await ws.send_bytes(pack_command(encode_fields(reply) + self._reply_tail, 0))

    async def _logon(self, fields, ws):
        self.logons.append(fields)
        if self.close_logins:
            self.close_logins -= 1
            await ws.close()
            return
        salt = base64.b64encode(SALT).decode()
        if fields[9] != "0":
            refusal = ["INNER", "USER", "LOGONFAILED", "3", "1", "1", salt, "0", "0"]
            await ws.send_bytes(build_command([DEVICE_IP, "IP", *refusal], 0))
            return
        if not self.answer_md5:
            return
        if self.refuse_login or self._should_reject():
            refusal = ["INNER", "USER", "LOGONFAILED", "2", "1", "1", salt, "1", "0"]
            await ws.send_bytes(build_command([DEVICE_IP, "IP", *refusal], 0))
            return
        if self._login_payload is not None:
            await ws.send_bytes(pack_command(self._login_payload, 0))
            return
        await ws.send_bytes(build_command([DEVICE_IP, "IP", "INNER", "CMDID", "7"], 0))
        if self._finish_login:
            await ws.send_bytes(build_command([DEVICE_IP, "IP", "INNER", "LOGON", "FINISHED"], 0))

    def _should_reject(self):
        return self._reject_reconnect and self.connections > 1


def make(camera, *, events=None, availability=None, **kwargs):
    return NvsConnection(
        "127.0.0.1",
        camera.port,
        SaltedLogin("127.0.0.1"),
        on_event=events or (lambda _event: None),
        on_availability=availability or (lambda _state: None),
        **kwargs,
    )


async def wait_until(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met in time")


async def test_feed_split_and_merged_frames():
    camera = FakeCamera()
    await camera.start()
    events = []
    conn = make(camera, events=events.append)
    try:
        await conn.connect("admin", "admin123")
        await camera.send_raw(event_frame(0) + event_frame(1))
        frame = event_frame(2)
        split = len(frame) // 2
        await camera.send_raw(frame[:split])
        await camera.send_raw(frame[split:])
        await wait_until(lambda: len(events) == 3)
    finally:
        await conn.close()
        await camera.stop()

    assert events == [
        Event("motion", True, 0),
        Event("motion", True, 1),
        Event("motion", True, 2),
    ]


async def test_reconnect_on_drop():
    camera = FakeCamera()
    await camera.start()
    availability = []
    conn = make(
        camera,
        availability=availability.append,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.05,
    )
    try:
        await conn.connect("admin", "admin123")
        assert availability == [True]
        await wait_until(lambda: camera.connections == 1)
        await camera.drop_client()
        await wait_until(lambda: availability == [True, False, True])
        assert camera.connections == 2
    finally:
        await conn.close()
        await camera.stop()


async def test_request_fails_when_disconnected():
    camera = FakeCamera(reply_to_requests=False)
    await camera.start()
    conn = make(
        camera,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.05,
        request_timeout=5.0,
    )
    try:
        await conn.connect("admin", "admin123")
        pending = asyncio.create_task(
            conn.request([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"])
        )
        await wait_until(lambda: camera.requests)
        await camera.drop_client()
        with pytest.raises(ConnectError):
            await asyncio.wait_for(pending, timeout=3.0)
    finally:
        await conn.close()
        await camera.stop()


async def test_heartbeat_sent_after_connect():
    camera = FakeCamera()
    await camera.start()
    conn = make(camera, heartbeat_interval=0.05, backoff_start=0.01, backoff_max=0.05)
    try:
        await conn.connect("admin", "admin123")
        await wait_until(lambda: camera.heartbeats >= 1, timeout=2.0)
    finally:
        await conn.close()
        await camera.stop()


async def test_request_returns_matching_reply():
    camera = FakeCamera()
    await camera.start()
    conn = make(camera, heartbeat_interval=1.0)
    try:
        await conn.connect("admin", "admin123")
        reply = await conn.request([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"])
        assert reply[2:6] == ["INNER", "CMD", "GETPARAM", "FINISHED"]
        assert reply[6] == camera.requests[0][-1]
    finally:
        await conn.close()
        await camera.stop()


async def test_request_times_out_as_connect_error():
    camera = FakeCamera(reply_to_requests=False)
    await camera.start()
    conn = make(camera, heartbeat_interval=1.0, request_timeout=30.0)
    try:
        await conn.connect("admin", "admin123")
        pending = conn.request(
            [DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"], timeout=0.2
        )
        with pytest.raises(ConnectError, match="no reply within 0.2 seconds"):
            await asyncio.wait_for(pending, timeout=3.0)
    finally:
        await conn.close()
        await camera.stop()


async def test_connect_times_out_as_connect_error():
    camera = FakeCamera(finish_login=False)
    await camera.start()
    conn = make(camera, login_timeout=0.2)
    try:
        with pytest.raises(ConnectError, match="timeout"):
            await conn.connect("admin", "admin123")
    finally:
        await conn.close()
        await camera.stop()


async def test_connect_reports_a_close_during_login_as_connect_error():
    camera = FakeCamera()
    camera.close_logins = 1
    await camera.start()
    conn = make(camera)
    try:
        with pytest.raises(ConnectError, match="closed the connection during login"):
            await conn.connect("admin", "admin123")
    finally:
        await conn.close()
        await camera.stop()


async def test_connect_rejects_oversized_credentials():
    camera = FakeCamera()
    await camera.start()
    conn = make(camera)
    try:
        with pytest.raises(AuthError):
            await conn.connect("admin", "x" * 17)
    finally:
        await conn.close()
        await camera.stop()


async def test_reconnect_gives_up_after_repeated_auth_failure():
    camera = FakeCamera(reject_reconnect=True)
    await camera.start()
    availability = []
    conn = make(
        camera,
        availability=availability.append,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.02,
        login_timeout=0.1,
        auth_failure_limit=3,
    )
    try:
        await conn.connect("admin", "admin123")
        assert availability == [True]
        await camera.drop_client()
        await wait_until(lambda: conn._run_task.done(), timeout=5.0)
        assert availability == [True, False]
        assert conn._available is False
        assert camera.connections == 4
    finally:
        await conn.close()
        await camera.stop()


async def test_reconnect_give_up_reports_the_auth_error_once():
    camera = FakeCamera(reject_reconnect=True)
    await camera.start()
    failures = []
    conn = make(
        camera,
        on_login_failed=failures.append,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.02,
        login_timeout=0.1,
        auth_failure_limit=3,
    )
    try:
        await conn.connect("admin", "admin123")
        await camera.drop_client()
        await wait_until(lambda: conn._run_task.done(), timeout=5.0)
        assert len(failures) == 1
        assert isinstance(failures[0], AuthError)
    finally:
        await conn.close()
        await camera.stop()


async def test_reconnect_keeps_retrying_after_closes_during_login():
    camera = FakeCamera()
    await camera.start()
    availability = []
    failures = []
    conn = make(
        camera,
        availability=availability.append,
        on_login_failed=failures.append,
        backoff_start=0.01,
        backoff_max=0.02,
        auth_failure_limit=3,
    )
    try:
        await conn.connect("admin", "admin123")
        camera.close_logins = 5
        await camera.drop_client()

        await wait_until(lambda: availability == [True, False, True])
        assert camera.connections == 7
        assert not conn._run_task.done()
        assert failures == []
    finally:
        await conn.close()
        await camera.stop()


async def test_reconnect_keeps_retrying_after_login_timeouts():
    camera = FakeCamera()
    await camera.start()
    failures = []
    conn = make(
        camera,
        on_login_failed=failures.append,
        backoff_start=0.01,
        backoff_max=0.02,
        login_timeout=0.1,
        auth_failure_limit=3,
    )
    try:
        await conn.connect("admin", "admin123")
        camera.answer_md5 = False
        await camera.drop_client()

        await wait_until(lambda: camera.connections >= 6, timeout=5.0)
        assert not conn._run_task.done()
        assert failures == []
    finally:
        await conn.close()
        await camera.stop()


async def test_event_callback_error_does_not_kill_receive_loop():
    camera = FakeCamera()
    await camera.start()
    received = []
    availability = []

    def on_event(event):
        received.append(event)
        raise RuntimeError("callback boom")

    conn = make(
        camera,
        events=on_event,
        availability=availability.append,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.05,
    )
    try:
        await conn.connect("admin", "admin123")
        await camera.send_raw(event_frame(0))
        await wait_until(lambda: len(received) == 1)
        await camera.send_raw(event_frame(1))
        await wait_until(lambda: len(received) == 2)
        assert received == [Event("motion", True, 0), Event("motion", True, 1)]
        await camera.drop_client()
        await wait_until(lambda: availability == [True, False, True])
    finally:
        await conn.close()
        await camera.stop()


async def test_availability_callback_error_does_not_break_connect():
    camera = FakeCamera()
    await camera.start()

    def on_availability(_state):
        raise RuntimeError("availability boom")

    conn = make(camera, availability=on_availability, heartbeat_interval=1.0)
    try:
        await conn.connect("admin", "admin123")
        assert conn._available is True
        reply = await conn.request([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"])
        assert reply[2:6] == ["INNER", "CMD", "GETPARAM", "FINISHED"]
    finally:
        await conn.close()
        await camera.stop()


def connection_log(caplog):
    return [
        (record.levelno, record.getMessage())
        for record in caplog.records
        if record.name == "sannce_aio.connection"
    ]


async def test_reconnect_retries_and_the_return_log_at_debug(caplog):
    caplog.set_level(logging.DEBUG, logger="sannce_aio.connection")
    camera = FakeCamera()
    await camera.start()
    availability = []
    conn = make(
        camera, availability=availability.append, backoff_start=0.01, backoff_max=0.02
    )
    try:
        await conn.connect("admin", "admin123")
        camera.close_logins = 3
        await camera.drop_client()
        await wait_until(lambda: availability == [True, False, True])
    finally:
        await conn.close()
        await camera.stop()

    log = connection_log(caplog)
    retries = [text for _, text in log if text.startswith("reconnect failed")]
    assert len(retries) == 3
    assert any(text.startswith("reconnected to 127.0.0.1:") for _, text in log)
    assert {level for level, _ in log} == {logging.DEBUG}


async def test_refused_reconnect_logins_log_at_debug_until_the_give_up(caplog):
    caplog.set_level(logging.DEBUG, logger="sannce_aio.connection")
    camera = FakeCamera(reject_reconnect=True)
    await camera.start()
    conn = make(
        camera,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.02,
        login_timeout=0.1,
        auth_failure_limit=3,
    )
    try:
        await conn.connect("admin", "admin123")
        await camera.drop_client()
        await wait_until(lambda: conn._run_task.done(), timeout=5.0)
    finally:
        await conn.close()
        await camera.stop()

    log = connection_log(caplog)
    attempts = [level for level, text in log if text.startswith("reconnect login")]
    assert attempts == [logging.DEBUG, logging.DEBUG]
    assert [text for level, text in log if level > logging.DEBUG] == [
        "giving up reconnect after 3 auth failures: "
        "the camera refused the login (reason 2)"
    ]


async def test_login_sends_base64_then_md5_logon():
    camera = FakeCamera()
    await camera.start()
    conn = make(camera)
    try:
        await conn.connect("admin", "secret")
    finally:
        await conn.close()
        await camera.stop()

    assert [fields[9] for fields in camera.logons] == ["805306367", "0"]
    assert camera.logons[1][4:6] == [salted("admin"), salted("secret")]


async def test_a_refused_md5_login_raises_auth_error():
    camera = FakeCamera(refuse_login=True)
    await camera.start()
    conn = make(camera)
    try:
        with pytest.raises(AuthError, match="reason 2"):
            await conn.connect("admin", "secret")
    finally:
        await conn.close()
        await camera.stop()


async def test_an_unanswered_md5_login_times_out_as_connect_error():
    camera = FakeCamera(answer_md5=False)
    await camera.start()
    conn = make(camera, login_timeout=0.3)
    try:
        with pytest.raises(ConnectError, match="timeout"):
            await asyncio.wait_for(conn.connect("admin", "secret"), 2.0)
    finally:
        await conn.close()
        await camera.stop()


async def test_a_silent_socket_is_dropped_after_the_idle_timeout():
    camera = FakeCamera()
    await camera.start()
    states = []
    conn = make(camera, availability=states.append, idle_timeout=0.3, heartbeat_interval=10)
    try:
        await conn.connect("admin", "secret")
        await wait_until(lambda: camera.connections == 2, timeout=3)
    finally:
        await conn.close()
        await camera.stop()

    assert states[:3] == [True, False, True]


async def test_heartbeat_runs_every_interval():
    camera = FakeCamera()
    await camera.start()
    conn = make(camera, heartbeat_interval=0.05)
    try:
        await conn.connect("admin", "secret")
        await asyncio.sleep(0.3)
    finally:
        await conn.close()
        await camera.stop()

    assert camera.heartbeats >= 3


async def test_proxy_route_alarm_with_an_id_reaches_on_event():
    camera = FakeCamera()
    await camera.start()
    events = []
    conn = make(camera, events=events.append)
    try:
        await conn.connect("admin", "secret")
        await camera.send([DEVICE_IP, "PROXY", "INNER", "ALARM", "MOTIONDETECT", "0", "1", "0012310019100435"])
        await camera.send([DEVICE_IP, "PROXY", "INNER", "CMD", "EXCEPTION", "0", "0"])
        await camera.send([DEVICE_IP, "PROXY", ""])
        await wait_until(lambda: events)
    finally:
        await conn.close()
        await camera.stop()

    assert events == [Event("motion", True, 0)]


async def test_an_alarm_with_the_terminator_twice_reaches_on_event():
    camera = FakeCamera()
    await camera.start()
    events = []
    conn = make(camera, events=events.append)
    try:
        await conn.connect("admin", "secret")
        await camera.send_raw(
            pack_command(
                b"192.168.1.10\tPROXY\tINNER\tALARM\tMOTIONDETECT\t0\t1\t0012310019100435"
                b"\n\n\n\n\n\n",
                0,
            )
        )
        await wait_until(lambda: events)
    finally:
        await conn.close()
        await camera.stop()

    assert events == [Event("motion", True, 0)]


async def test_two_alarms_in_one_frame_reach_on_event_in_order():
    camera = FakeCamera()
    await camera.start()
    events = []
    conn = make(camera, events=events.append)
    try:
        await conn.connect("admin", "secret")
        await camera.send_raw(
            pack_command(
                b"192.168.1.10\tPROXY\tINNER\tALARM\tMOTIONDETECT\t0\t1\t0012310019100435"
                b"\n\n\n\n\n\n"
                b"INNER\tALARM\tMOTIONDETECT\t0\t0\t0012310019100435\n\n\n\n\n\n",
                0,
            )
        )
        await wait_until(lambda: len(events) == 2)
    finally:
        await conn.close()
        await camera.stop()

    assert events == [Event("motion", True, 0), Event("motion", False, 0)]


async def test_a_reply_and_an_alarm_in_one_frame_both_arrive():
    camera = FakeCamera(reply_tail=b"INNER\tALARM\tMOTIONDETECT\t0\t1\n\n\n")
    await camera.start()
    events = []
    conn = make(camera, events=events.append, request_timeout=1.0)
    try:
        await conn.connect("admin", "secret")
        reply = await conn.request([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"])
        await wait_until(lambda: events)
    finally:
        await conn.close()
        await camera.stop()

    assert reply[2:6] == ["INNER", "CMD", "GETPARAM", "FINISHED"]
    assert events == [Event("motion", True, 0)]


async def test_a_login_frame_with_cmdid_and_logon_finished_finishes_the_login():
    camera = FakeCamera(
        login_payload=b"192.168.1.10\tIP\tINNER\tCMDID\t7\n\n\nINNER\tLOGON\tFINISHED\n\n\n"
    )
    await camera.start()
    availability = []
    conn = make(camera, availability=availability.append, login_timeout=1.0)
    try:
        await conn.connect("admin", "secret")
    finally:
        await conn.close()
        await camera.stop()

    assert availability == [True, False]


async def test_an_alarm_after_logon_finished_in_the_same_frame_reaches_on_event():
    camera = FakeCamera(
        login_payload=(
            b"192.168.1.10\tIP\tINNER\tLOGON\tFINISHED\n\n\n"
            b"INNER\tALARM\tMOTIONDETECT\t0\t1\n\n\n"
        )
    )
    await camera.start()
    events = []
    conn = make(camera, events=events.append, login_timeout=1.0)
    try:
        await conn.connect("admin", "secret")
        await wait_until(lambda: events)
    finally:
        await conn.close()
        await camera.stop()

    assert events == [Event("motion", True, 0)]


class BrokenSocket:
    async def receive(self):
        raise aiohttp.ClientConnectionError("reset by peer")

    async def send_bytes(self, data):
        raise ConnectionResetError("reset by peer")


async def test_a_failing_receive_reads_as_closed():
    assert await WsTransport(BrokenSocket()).read() == b""


async def test_a_failing_send_raises_connect_error():
    with pytest.raises(ConnectError, match="send failed: reset by peer"):
        await WsTransport(BrokenSocket()).write(b"\x00")
