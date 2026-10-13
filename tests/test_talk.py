import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from sannce_aio.audio import SUBFRAME_PCM_BYTES, encode_alaw
from sannce_aio.connection import NvsConnection
from sannce_aio.errors import ConnectError, TalkBusyError
from sannce_aio.events import Event
from sannce_aio.login import PlaintextLogin
from sannce_aio.protocol import parse_frame

pytestmark = pytest.mark.asyncio

DEVICE_IP = "192.168.1.10"
USER = "admin"
PASSWORD = "admin123"
MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
BEGIN_OK = ["INNER", "NVR", "0", "", "CMD", "TALK", "BEGIN", "OK"]
END_OK = ["INNER", "NVR", "0", "", "CMD", "TALK", "END", "OK"]
PCM = struct.pack("<320h", *range(-16000, 16000, 100))
SUBFRAMES = [
    encode_alaw(PCM[start : start + SUBFRAME_PCM_BYTES])
    for start in range(0, len(PCM), SUBFRAME_PCM_BYTES)
]


def fields_of(examples, example_id):
    frame, _ = parse_frame(bytes.fromhex(examples[example_id]["hex"]))
    return frame.fields


def talk_actions(simulator):
    return [fields[6] for fields in simulator.requests if fields[1:2] == ["NVR"]]


def drop_clients(simulator):
    for session in list(simulator._sessions):
        session.writer.close()


async def wait_until(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met in time")


async def barrier(conn):
    # the camera handles frames in order, so its reply proves it saw all earlier ones
    await conn.request([DEVICE_IP, "IP", "CMD", "PING"])


@pytest_asyncio.fixture
async def connect(simulator):
    made = []

    async def make(events=None, availability=None, **kwargs):
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
        await conn.connect(USER, PASSWORD)
        return conn

    yield make
    for conn in made:
        await conn.close()


def break_drain(conn):
    writer = MagicMock(wraps=conn._writer)
    writer.drain = AsyncMock(side_effect=ConnectionResetError("boom"))
    conn._writer = writer


def silence_talk(simulator, monkeypatch):
    async def ignore(_session, _channel, _action):
        pass

    monkeypatch.setattr(simulator, "_talk", ignore)


async def test_start_talk_sends_the_documented_request(simulator, connect, examples):
    conn = await connect()

    await conn.start_talk(0)

    assert simulator.talking
    assert simulator.requests == [
        [simulator.host, *fields_of(examples, "talk_start_request")[1:]]
    ]


async def test_stop_talk_sends_the_documented_request(simulator, connect, examples):
    conn = await connect()
    await conn.start_talk(0)

    await conn.stop_talk()

    assert not simulator.talking
    assert simulator.requests[-1] == [
        simulator.host,
        *fields_of(examples, "talk_stop_request")[1:],
    ]


async def test_send_audio_delivers_frames_the_camera_decodes(simulator, connect):
    conn = await connect()
    await conn.start_talk(0)

    await conn.send_audio(PCM)
    await barrier(conn)

    assert simulator.talk_frames == SUBFRAMES


async def test_audio_sequence_runs_on_across_chunks(simulator, connect):
    conn = await connect()
    await conn.start_talk(0)

    await conn.send_audio(PCM)
    await conn.send_audio(PCM[: 2 * SUBFRAME_PCM_BYTES])
    await conn.send_audio(PCM)
    await barrier(conn)

    assert simulator.talk_seqs == list(range(10))


async def test_send_audio_rejects_a_partial_sub_frame(simulator, connect):
    conn = await connect()
    await conn.start_talk(0)

    with pytest.raises(ValueError):
        await conn.send_audio(PCM[: SUBFRAME_PCM_BYTES + 2])
    await conn.send_audio(PCM)
    await barrier(conn)

    assert simulator.talk_seqs == [0, 1, 2, 3]


@pytest.mark.parametrize(
    ("first", "seqs"),
    [
        (0xFFFFFFFC, [0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF]),
        (0xFFFFFFFD, [0, 1, 2, 3]),
    ],
    ids=["fits_exactly", "restarts"],
)
async def test_audio_sequence_restarts_before_it_overflows(
    simulator, connect, first, seqs
):
    conn = await connect()
    await conn.start_talk(0)
    conn._audio_seq = first

    await conn.send_audio(PCM)
    await barrier(conn)

    assert simulator.talk_seqs == seqs


async def test_send_audio_needs_a_started_talk(connect):
    conn = await connect()

    with pytest.raises(ConnectError):
        await conn.send_audio(PCM)
    await conn.start_talk(0)
    await conn.stop_talk()
    with pytest.raises(ConnectError):
        await conn.send_audio(PCM)


async def test_stop_talk_without_a_talk_sends_nothing(simulator, connect):
    conn = await connect()

    await conn.stop_talk()
    await barrier(conn)

    assert talk_actions(simulator) == []


@pytest.mark.parametrize("channel", [1, -1])
async def test_start_talk_supports_wire_channel_zero_only(simulator, connect, channel):
    conn = await connect()

    with pytest.raises(ValueError):
        await conn.start_talk(channel)
    await barrier(conn)

    assert talk_actions(simulator) == []


async def test_start_talk_reports_a_failed_send_as_connect_error(connect):
    conn = await connect()
    break_drain(conn)

    with pytest.raises(ConnectError, match="request send failed: boom"):
        await conn.start_talk(0)
    assert not conn._talk_pending


async def test_send_audio_reports_a_failed_send_as_connect_error(connect):
    conn = await connect()
    await conn.start_talk(0)
    break_drain(conn)

    with pytest.raises(ConnectError, match="audio send failed: boom"):
        await conn.send_audio(PCM)


async def test_talk_calls_fail_after_close(connect):
    conn = await connect()
    await conn.close()

    with pytest.raises(ConnectError):
        await conn.start_talk(0)
    with pytest.raises(ConnectError):
        await conn.send_audio(PCM)
    await conn.stop_talk()


async def test_second_start_talk_is_busy_without_a_second_request(simulator, connect):
    conn = await connect()
    await conn.start_talk(0)

    with pytest.raises(TalkBusyError):
        await conn.start_talk(0)
    await barrier(conn)

    assert talk_actions(simulator) == ["BEGIN"]


async def test_concurrent_start_talk_sends_one_begin(simulator, connect):
    conn = await connect()

    first, second = await asyncio.gather(
        conn.start_talk(0), conn.start_talk(0), return_exceptions=True
    )

    assert first is None
    assert isinstance(second, TalkBusyError)
    assert talk_actions(simulator) == ["BEGIN"]


async def test_play_audio_busy_raises(simulator, connect):
    simulator.set_talk_busy(True)
    conn = await connect(request_timeout=30.0)

    with pytest.raises(TalkBusyError):
        await asyncio.wait_for(conn.start_talk(0), 2.0)

    assert not simulator.talking


async def test_start_talk_raises_busy_on_the_documented_refusal(
    simulator, connect, monkeypatch, examples
):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=30.0)
    pending = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)
    (session,) = simulator._sessions

    await session.send(fields_of(examples, "talk_refused_busy")[2:])

    with pytest.raises(TalkBusyError):
        await asyncio.wait_for(pending, 2.0)


async def test_connection_stays_usable_after_a_busy_refusal(simulator, connect):
    simulator.set_talk_busy(True)
    conn = await connect()
    with pytest.raises(TalkBusyError):
        await conn.start_talk(0)
    with pytest.raises(ConnectError):
        await conn.send_audio(PCM)
    await barrier(conn)

    simulator.set_talk_busy(False)
    await conn.start_talk(0)
    await conn.send_audio(PCM)
    await barrier(conn)

    assert simulator.talk_frames == SUBFRAMES


async def test_start_talk_times_out_without_a_reply(simulator, connect, monkeypatch):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=0.2)

    with pytest.raises(ConnectError, match="no reply"):
        await conn.start_talk(0)
    assert not conn._talk_pending
    monkeypatch.undo()
    await conn.start_talk(0)

    assert talk_actions(simulator) == ["BEGIN", "BEGIN"]
    assert simulator.talking


async def test_stop_talk_times_out_without_a_reply_and_still_ends_the_talk(
    simulator, connect, monkeypatch
):
    conn = await connect(request_timeout=0.2)
    await conn.start_talk(0)
    silence_talk(simulator, monkeypatch)

    with pytest.raises(ConnectError, match="no reply"):
        await conn.stop_talk()
    assert not conn._talk_pending
    monkeypatch.undo()

    with pytest.raises(ConnectError):
        await conn.send_audio(PCM)
    await conn.start_talk(0)

    assert talk_actions(simulator) == ["BEGIN", "END", "BEGIN"]


async def test_start_talk_waits_for_the_begin_reply(simulator, connect, monkeypatch):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=30.0)
    pending = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)
    (session,) = simulator._sessions

    await session.send(END_OK)
    await barrier(conn)
    assert not pending.done()
    await session.send(BEGIN_OK)

    await asyncio.wait_for(pending, 2.0)


async def test_short_talk_reply_is_ignored(simulator, connect, monkeypatch):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=30.0)
    pending = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)
    (session,) = simulator._sessions

    await session.send(["INNER", "NVR", "0"])
    await barrier(conn)

    assert not pending.done()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending


async def test_stop_talk_waits_for_a_pending_start(simulator, connect, monkeypatch):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=30.0)
    starting = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)
    (session,) = simulator._sessions
    stopping = asyncio.create_task(conn.stop_talk())
    await barrier(conn)
    assert not stopping.done()

    monkeypatch.undo()
    await session.send(BEGIN_OK)
    await asyncio.wait_for(asyncio.gather(starting, stopping), 2.0)

    assert talk_actions(simulator) == ["BEGIN", "END"]


async def test_pending_start_talk_fails_when_the_connection_drops(
    simulator, connect, monkeypatch
):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=30.0, backoff_start=0.01, backoff_max=0.05)
    pending = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)

    drop_clients(simulator)

    with pytest.raises(ConnectError):
        await asyncio.wait_for(pending, 2.0)


async def test_receive_loop_keeps_running_while_talk_is_pending(
    simulator, connect, monkeypatch
):
    silence_talk(simulator, monkeypatch)
    events = []
    conn = await connect(events=events, request_timeout=30.0)
    pending = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)

    await simulator.push_event(MOTION_START)
    await barrier(conn)

    assert events == [Event("motion", True, 0)]
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending


async def test_cancelled_start_talk_leaves_the_connection_usable(
    simulator, connect, monkeypatch
):
    silence_talk(simulator, monkeypatch)
    conn = await connect(request_timeout=30.0)
    pending = asyncio.create_task(conn.start_talk(0))
    await wait_until(lambda: simulator.requests)

    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert not conn._talk_pending
    monkeypatch.undo()
    await asyncio.wait_for(conn.start_talk(0), 2.0)

    assert simulator.talking


async def test_talk_ends_when_the_connection_drops(simulator, connect):
    availability = []
    conn = await connect(
        availability=availability, backoff_start=0.01, backoff_max=0.05
    )
    await conn.start_talk(0)
    await conn.send_audio(PCM)
    await barrier(conn)

    drop_clients(simulator)
    await wait_until(lambda: availability == [True, False, True])

    with pytest.raises(ConnectError):
        await conn.send_audio(PCM)
    await conn.stop_talk()
    await conn.start_talk(0)
    await conn.send_audio(PCM)
    await barrier(conn)

    assert simulator.talking
    assert simulator.talk_seqs == [0, 1, 2, 3, 0, 1, 2, 3]
