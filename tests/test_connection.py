import asyncio

import pytest

from sannce_aio.connection import NvsConnection
from sannce_aio.errors import AuthError, ConnectError
from sannce_aio.events import Event
from sannce_aio.login import PlaintextLogin
from sannce_aio.protocol import build_command, parse_frame

DEVICE_IP = "192.168.1.10"


def event_frame(channel):
    fields = [DEVICE_IP, "IP", "INNER", "ALARM", "MOTIONDETECT", str(channel), "1"]
    return build_command(fields, 0)


class ChunkReader:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, _size):
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class FakeCamera:
    def __init__(self, *, reply_to_requests=True, finish_login=True, reject_reconnect=False):
        self._reply_to_requests = reply_to_requests
        self._finish_login = finish_login
        self._reject_reconnect = reject_reconnect
        self._server = None
        self._writer = None
        self._seq = 0
        self.port = None
        self.connections = 0
        self.heartbeats = 0
        self.requests = []

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def drop_client(self):
        writer = self._writer
        self._writer = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _handle(self, reader, writer):
        self.connections += 1
        self._writer = writer
        buffer = bytearray()
        try:
            while True:
                while True:
                    frame, consumed = parse_frame(bytes(buffer))
                    if frame is None:
                        break
                    del buffer[:consumed]
                    await self._react(frame, writer)
                chunk = await reader.read(0x10000)
                if not chunk:
                    break
                buffer += chunk
        except (OSError, ConnectionError):
            pass
        finally:
            writer.close()

    async def _react(self, frame, writer):
        fields = frame.fields
        if not fields:
            self.heartbeats += 1
            return
        if fields[2:4] == ["USER", "LOGON"]:
            await self._send(writer, ["INNER", "CMDID", "7"])
            if self._should_finish_login():
                await self._send(writer, ["INNER", "LOGON", "FINISHED"])
            return
        self.requests.append(fields)
        if self._reply_to_requests:
            session_id = fields[-1]
            reply = ["INNER", "CMD", "GETPARAM", "FINISHED", session_id, "0"]
            await self._send(writer, reply)

    def _should_finish_login(self):
        if not self._finish_login:
            return False
        # reconnect attempts never finish, so the client times out into AuthError
        return not (self._reject_reconnect and self.connections > 1)

    async def push_event(self, channel):
        writer = self._writer
        if writer is not None:
            await self._send(writer, ["INNER", "ALARM", "MOTIONDETECT", str(channel), "1"])

    async def _send(self, writer, inner):
        writer.write(build_command([DEVICE_IP, "IP", *inner], self._seq))
        self._seq = (self._seq + 1) % 0x10000
        await writer.drain()


def make_connection(camera, *, events=None, availability=None, **kwargs):
    return NvsConnection(
        "127.0.0.1",
        camera.port,
        PlaintextLogin(DEVICE_IP),
        on_event=(events.append if events is not None else (lambda _event: None)),
        on_availability=(
            availability.append if availability is not None else (lambda _state: None)
        ),
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


@pytest.mark.asyncio
async def test_feed_split_and_merged_frames():
    events = []
    conn = NvsConnection(
        "127.0.0.1",
        3000,
        PlaintextLogin(DEVICE_IP),
        on_event=events.append,
        on_availability=lambda _state: None,
    )
    frame_a = event_frame(0)
    split = len(frame_a) // 2
    conn._reader = ChunkReader(
        [frame_a[:split], frame_a[split:], event_frame(1) + event_frame(2)]
    )
    await conn._receive_loop()
    assert events == [
        Event("motion", True, 0),
        Event("motion", True, 1),
        Event("motion", True, 2),
    ]


@pytest.mark.asyncio
async def test_reconnect_on_drop():
    camera = FakeCamera()
    await camera.start()
    availability = []
    conn = make_connection(
        camera,
        availability=availability,
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


@pytest.mark.asyncio
async def test_request_fails_when_disconnected():
    camera = FakeCamera(reply_to_requests=False)
    await camera.start()
    conn = make_connection(
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


@pytest.mark.asyncio
async def test_heartbeat_sent_after_connect():
    camera = FakeCamera()
    await camera.start()
    conn = make_connection(
        camera, heartbeat_interval=0.05, backoff_start=0.01, backoff_max=0.05
    )
    try:
        await conn.connect("admin", "admin123")
        await wait_until(lambda: camera.heartbeats >= 1, timeout=2.0)
    finally:
        await conn.close()
        await camera.stop()


@pytest.mark.asyncio
async def test_request_returns_matching_reply():
    camera = FakeCamera()
    await camera.start()
    conn = make_connection(camera, heartbeat_interval=1.0)
    try:
        await conn.connect("admin", "admin123")
        reply = await conn.request([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"])
        assert reply[2:6] == ["INNER", "CMD", "GETPARAM", "FINISHED"]
        assert reply[6] == camera.requests[0][-1]
    finally:
        await conn.close()
        await camera.stop()


@pytest.mark.asyncio
async def test_connect_times_out_as_auth_error():
    camera = FakeCamera(finish_login=False)
    await camera.start()
    conn = make_connection(camera, login_timeout=0.2)
    try:
        with pytest.raises(AuthError):
            await conn.connect("admin", "admin123")
    finally:
        await conn.close()
        await camera.stop()


@pytest.mark.asyncio
async def test_connect_rejects_oversized_credentials():
    camera = FakeCamera()
    await camera.start()
    conn = make_connection(camera)
    try:
        with pytest.raises(AuthError):
            await conn.connect("admin", "x" * 17)
    finally:
        await conn.close()
        await camera.stop()


@pytest.mark.asyncio
async def test_reconnect_gives_up_after_repeated_auth_failure():
    camera = FakeCamera(reject_reconnect=True)
    await camera.start()
    availability = []
    conn = make_connection(
        camera,
        availability=availability,
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


@pytest.mark.asyncio
async def test_event_callback_error_does_not_kill_receive_loop():
    camera = FakeCamera()
    await camera.start()
    received = []
    availability = []

    def on_event(event):
        received.append(event)
        raise RuntimeError("callback boom")

    conn = NvsConnection(
        "127.0.0.1",
        camera.port,
        PlaintextLogin(DEVICE_IP),
        on_event=on_event,
        on_availability=availability.append,
        heartbeat_interval=0.05,
        backoff_start=0.01,
        backoff_max=0.05,
    )
    try:
        await conn.connect("admin", "admin123")
        await camera.push_event(0)
        await wait_until(lambda: len(received) == 1)
        await camera.push_event(1)
        await wait_until(lambda: len(received) == 2)
        assert received == [Event("motion", True, 0), Event("motion", True, 1)]
        await camera.drop_client()
        await wait_until(lambda: availability == [True, False, True])
    finally:
        await conn.close()
        await camera.stop()


@pytest.mark.asyncio
async def test_availability_callback_error_does_not_break_connect():
    camera = FakeCamera()
    await camera.start()

    def on_availability(_state):
        raise RuntimeError("availability boom")

    conn = NvsConnection(
        "127.0.0.1",
        camera.port,
        PlaintextLogin(DEVICE_IP),
        on_event=lambda _event: None,
        on_availability=on_availability,
        heartbeat_interval=1.0,
    )
    try:
        await conn.connect("admin", "admin123")
        assert conn._available is True
        reply = await conn.request([DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0"])
        assert reply[2:6] == ["INNER", "CMD", "GETPARAM", "FINISHED"]
    finally:
        await conn.close()
        await camera.stop()
