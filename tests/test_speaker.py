import asyncio
import contextlib
import struct

import pytest
import pytest_asyncio

from sannce_aio.audio import encode_alaw
from sannce_aio.backchannel import FRAME_BYTES, Backchannel
from sannce_aio.errors import ConnectError, TalkBusyError
from sannce_aio.speaker import Speaker

from .rtsp_fake import FakeRtspCamera

TEST_LINGER = 0.2
OLDER, NEWER = 1000, -1000


def tone(frames, value=OLDER):
    return struct.pack("<h", value) * (frames * FRAME_BYTES // 2)


def sound(value):
    return encode_alaw(tone(1, value))


async def chunks(*parts):
    for part in parts:
        yield part


class Producer:
    def __init__(self, hold_at=None):
        self.hold_at = hold_at
        self.pulls = 0
        self.held = asyncio.Event()
        self.release = asyncio.Event()

    def __aiter__(self):
        return self

    async def __anext__(self):
        self.pulls += 1
        if self.pulls == self.hold_at:
            self.held.set()
            await self.release.wait()
        return tone(1)


async def until(condition, timeout=2.0):
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


def methods(rtsp):
    return [method for method, _, _ in rtsp.requests]


def authorized(rtsp, method):
    return [h for m, _, h in rtsp.requests if m == method and "authorization" in h]


def payloads(rtsp):
    return [packet[12:] for channel, packet in rtsp.packets if channel == 4]


def leftover(before):
    return [
        task
        for task in asyncio.all_tasks() - before
        if not task.get_coro().__qualname__.startswith("FakeRtspCamera.")
    ]


def make_speaker(rtsp, linger=TEST_LINGER):
    return Speaker(
        lambda: Backchannel(rtsp.host, rtsp.port, "/1/1", "admin", "admin123", timeout=2.0),
        linger=linger,
    )


@pytest_asyncio.fixture
async def rtsp():
    camera = FakeRtspCamera()
    await camera.start()
    yield camera
    await camera.stop()


@pytest_asyncio.fixture
async def speaker(rtsp):
    speaker = make_speaker(rtsp)
    yield speaker
    await speaker.close()


@contextlib.asynccontextmanager
async def camera(**options):
    rtsp = FakeRtspCamera(**options)
    await rtsp.start()
    speaker = make_speaker(rtsp)
    try:
        yield rtsp, speaker
    finally:
        await speaker.close()
        await rtsp.stop()


async def test_play_sends_every_frame_and_returns_true(rtsp, speaker):
    pcm = tone(1)[:100], tone(1)[100:] + tone(1), tone(1)[: FRAME_BYTES // 2]

    assert await speaker.play(chunks(*pcm)) is True

    await until(lambda: len(rtsp.packets) == 3)
    assert [channel for channel, _ in rtsp.packets] == [4, 4, 4]
    assert payloads(rtsp)[-1] == encode_alaw(tone(1)[: FRAME_BYTES // 2] + bytes(FRAME_BYTES // 2))
    assert speaker.owner is None


async def test_two_plays_inside_linger_share_one_session(rtsp, speaker):
    assert await speaker.play(chunks(tone(1))) is True
    assert await speaker.play(chunks(tone(1))) is True

    await until(lambda: len(rtsp.packets) == 2)
    assert "TEARDOWN" not in methods(rtsp)
    assert len(authorized(rtsp, "SETUP")) == 1


async def test_the_session_closes_after_linger(rtsp, speaker):
    loop = asyncio.get_running_loop()
    freed = []

    def on_change(owner):
        if owner is None:
            freed.append(loop.time())

    speaker.subscribe(on_change)
    assert await speaker.play(chunks(tone(1))) is True

    await until(lambda: "TEARDOWN" in methods(rtsp), TEST_LINGER + 0.5)
    assert loop.time() - freed[0] >= TEST_LINGER


async def test_a_newer_play_preempts_the_running_one(rtsp, speaker):
    held = Producer(hold_at=4)
    first = asyncio.create_task(speaker.play(held))
    await asyncio.wait_for(held.held.wait(), 2)

    second = asyncio.create_task(speaker.play(chunks(tone(5, NEWER))))
    await until(lambda: sound(NEWER) in payloads(rtsp))
    held.release.set()

    assert await asyncio.wait_for(first, 2) is False
    assert await asyncio.wait_for(second, 2) is True
    assert held.pulls == 4
    await until(lambda: payloads(rtsp).count(sound(NEWER)) == 5)
    sent = payloads(rtsp)
    assert sent[sent.index(sound(NEWER)) :].count(sound(OLDER)) <= 1
    assert len(authorized(rtsp, "SETUP")) == 1


async def test_a_play_preempted_mid_write_sends_no_further_frame(rtsp, speaker):
    older = Producer()
    pulls_at_change = []
    speaker.subscribe(lambda owner: pulls_at_change.append(older.pulls))
    first = asyncio.create_task(speaker.play(older))
    await until(lambda: len(rtsp.packets) >= 3)

    second = asyncio.create_task(speaker.play(chunks(tone(3, NEWER))))

    assert await asyncio.wait_for(first, 2) is False
    assert await asyncio.wait_for(second, 2) is True
    assert older.pulls == pulls_at_change[1]
    await until(lambda: payloads(rtsp).count(sound(NEWER)) == 3)
    sent = payloads(rtsp)
    assert sound(OLDER) not in sent[sent.index(sound(NEWER)) :]


async def test_a_play_started_while_another_opens_the_session_reuses_it():
    async with camera(setup_gate=asyncio.Event()) as (rtsp, speaker):
        owners = []
        speaker.subscribe(owners.append)
        first = asyncio.create_task(speaker.play(Producer()))
        await until(lambda: authorized(rtsp, "SETUP"))

        second = asyncio.create_task(speaker.play(chunks(tone(2, NEWER))))
        await until(lambda: owners.count("play") == 2)
        rtsp.setup_gate.set()

        assert await asyncio.wait_for(first, 2) is False
        assert await asyncio.wait_for(second, 2) is True
        await until(lambda: len(rtsp.packets) == 2)
        assert payloads(rtsp) == [sound(NEWER)] * 2
        assert len(authorized(rtsp, "SETUP")) == 1


async def test_a_refused_setup_raises_talk_busy_and_frees_the_speaker():
    async with camera(setup_status=453) as (_, speaker):
        with pytest.raises(TalkBusyError):
            await speaker.play(chunks(tone(1)))

        assert speaker.owner is None


async def test_a_camera_hangup_mid_play_raises_and_the_next_play_reopens(rtsp, speaker):
    playing = asyncio.create_task(speaker.play(Producer()))
    await until(lambda: rtsp.packets)

    rtsp.hang_up()

    with pytest.raises(ConnectError):
        await asyncio.wait_for(playing, 5)
    assert speaker.owner is None
    assert await speaker.play(chunks(tone(1))) is True
    assert len(authorized(rtsp, "SETUP")) == 2


async def test_cancelling_a_play_frees_the_speaker(rtsp, speaker):
    playing = asyncio.create_task(speaker.play(Producer()))
    await until(lambda: rtsp.packets)

    playing.cancel()

    with pytest.raises(asyncio.CancelledError):
        await playing
    assert speaker.owner is None
    assert await speaker.play(chunks(tone(1))) is True
    assert len(authorized(rtsp, "SETUP")) == 1


async def test_cancelling_a_play_while_the_session_opens_raises_cancelled():
    async with camera(setup_gate=asyncio.Event()) as (rtsp, speaker):
        playing = asyncio.create_task(speaker.play(Producer()))
        await until(lambda: authorized(rtsp, "SETUP"))

        playing.cancel()

        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(playing, 1)
        assert speaker.owner is None
        assert "PLAY" not in methods(rtsp)


async def test_close_during_a_play_ends_it_with_false_and_leaves_no_task(rtsp, speaker):
    before = asyncio.all_tasks()
    playing = asyncio.create_task(speaker.play(Producer()))
    await until(lambda: rtsp.packets)

    await asyncio.wait_for(speaker.close(), 2)

    assert await asyncio.wait_for(playing, 2) is False
    await until(lambda: "TEARDOWN" in methods(rtsp))
    assert speaker.owner is None
    assert leftover(before) == []


async def test_close_while_a_play_opens_the_session_ends_it_with_false():
    async with camera(setup_gate=asyncio.Event()) as (rtsp, speaker):
        before = asyncio.all_tasks()
        playing = asyncio.create_task(speaker.play(Producer()))
        await until(lambda: authorized(rtsp, "SETUP"))

        await asyncio.wait_for(speaker.close(), 1)

        assert await asyncio.wait_for(playing, 1) is False
        assert "PLAY" not in methods(rtsp)
        assert leftover(before) == []


async def test_close_while_a_play_waits_for_pcm_opens_no_session(rtsp, speaker):
    pcm = Producer(hold_at=1)
    playing = asyncio.create_task(speaker.play(pcm))
    await asyncio.wait_for(pcm.held.wait(), 2)

    await speaker.close()
    pcm.release.set()

    assert await asyncio.wait_for(playing, 2) is False
    assert rtsp.requests == []


async def test_close_while_lingering_tears_down_at_once_and_cancels_the_timer(
    rtsp, monkeypatch
):
    speaker = make_speaker(rtsp, linger=30)
    loop = asyncio.get_running_loop()
    call_later = loop.call_later
    timers = []

    def spy(delay, callback, *args, **kwargs):
        handle = call_later(delay, callback, *args, **kwargs)
        if getattr(callback, "__self__", None) is speaker:
            timers.append(handle)
        return handle

    monkeypatch.setattr(loop, "call_later", spy)
    before = asyncio.all_tasks()
    assert await speaker.play(chunks(tone(1))) is True

    await asyncio.wait_for(speaker.close(), 1)

    await until(lambda: "TEARDOWN" in methods(rtsp))
    assert timers
    assert all(timer.cancelled() for timer in timers)
    assert leftover(before) == []


async def test_play_after_close_returns_false_without_a_session(rtsp, speaker):
    await speaker.close()
    pcm = Producer()

    assert await speaker.play(pcm) is False

    assert pcm.pulls == 0
    assert rtsp.requests == []
    assert speaker.owner is None


async def test_subscribers_see_play_then_none(rtsp, speaker):
    seen = []
    speaker.subscribe(seen.append)

    assert await speaker.play(chunks(tone(1))) is True

    assert seen == ["play", None]


async def test_a_raising_subscriber_is_logged_and_the_others_still_run(rtsp, speaker, caplog):
    def broken(owner):
        raise RuntimeError("subscriber bug")

    seen = []
    speaker.subscribe(broken)
    speaker.subscribe(seen.append)

    assert await speaker.play(chunks(tone(1))) is True

    assert seen == ["play", None]
    errors = [r for r in caplog.records if r.name == "sannce_aio.speaker" and r.exc_info]
    assert [r.exc_info[0] for r in errors] == [RuntimeError, RuntimeError]


async def test_unsubscribe_twice_is_harmless():
    speaker = Speaker(lambda: Backchannel("127.0.0.1", 1, "/1/1", "admin", "pw"))
    seen = []
    unsubscribe = speaker.subscribe(seen.append)
    speaker.subscribe(seen.append)

    unsubscribe()
    unsubscribe()

    assert await speaker.play(chunks()) is True
    await speaker.close()
    assert seen == ["play", None]
