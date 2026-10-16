import asyncio
import contextlib
import logging
import math
import socket
import struct

import pytest
import pytest_asyncio

from sannce_aio.audio import decode_alaw, decode_ulaw, encode_alaw
from sannce_aio.backchannel import FRAME_BYTES, SAMPLE_RATE, Backchannel
from sannce_aio.errors import ConnectError, TalkBusyError
from sannce_aio.speaker import TALK_BUFFER, VOICE_LEVEL, Speaker

from .rtsp_fake import FakeRtspCamera

TEST_LINGER = 0.2
TEST_HANGOVER = 0.2
FRAME_SECONDS = FRAME_BYTES / 2 / SAMPLE_RATE
OLDER, NEWER = 1000, -1000
SSRC = 0xABCD


def tone(frames, value=OLDER):
    return struct.pack("<h", value) * (frames * FRAME_BYTES // 2)


def sound(value):
    return encode_alaw(tone(1, value))


def voice(level=3000):
    samples = [
        round(level * math.sin(2 * math.pi * 1000 * n / SAMPLE_RATE))
        for n in range(FRAME_BYTES // 2)
    ]
    return struct.pack(f"<{len(samples)}h", *samples)


def quiet():
    return bytes(FRAME_BYTES)


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


class StubChannel:
    def __init__(self, hold=None, error=None):
        self.hold = hold
        self.error = error
        self.held = asyncio.Event()
        self.release = asyncio.Event()
        self.frames = 0
        self.closed = False

    async def open(self):
        await self._pass("open")

    async def send(self, frame):
        if self.closed:
            raise ConnectError("the backchannel is not open")
        await self._pass("send")
        self.frames += 1

    async def close(self):
        self.closed = True

    async def _pass(self, call):
        if call != self.hold:
            return
        self.hold = None
        self.held.set()
        await self.release.wait()
        if self.error is not None:
            raise self.error


def stub_speaker(first, **options):
    made = []

    def open_channel():
        made.append(first if not made else StubChannel())
        return made[-1]

    return Speaker(open_channel, linger=TEST_LINGER, **options), made


async def until(condition, timeout=2.0):
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


async def say_until(speaker, condition, *voices, timeout=2.0):
    async with asyncio.timeout(timeout):
        while True:
            for ssrc, frame in voices:
                speaker.feed_talk(ssrc, frame)
            await asyncio.sleep(FRAME_SECONDS)
            if condition():
                return


async def say_for(speaker, seconds, *voices):
    loop = asyncio.get_running_loop()
    end = loop.time() + seconds
    await say_until(speaker, lambda: loop.time() >= end, *voices, timeout=seconds + 1)


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


def spy_timers(monkeypatch, speaker):
    loop = asyncio.get_running_loop()
    call_later = loop.call_later
    timers = []

    def spy(delay, callback, *args, **kwargs):
        handle = call_later(delay, callback, *args, **kwargs)
        if getattr(callback, "__self__", None) is speaker:
            timers.append(handle)
        return handle

    monkeypatch.setattr(loop, "call_later", spy)
    return timers


def pending(timers):
    now = asyncio.get_running_loop().time()
    return [timer for timer in timers if not timer.cancelled() and timer.when() > now]


def speaker_warnings(caplog):
    return [
        r for r in caplog.records if r.name == "sannce_aio.speaker" and r.levelno == logging.WARNING
    ]


def make_speaker(rtsp, linger=TEST_LINGER, hangover=TEST_HANGOVER, talk_buffer=TALK_BUFFER):
    return Speaker(
        lambda: Backchannel(rtsp.host, rtsp.port, "/1/1", "admin", "admin123", timeout=2.0),
        linger=linger,
        hangover=hangover,
        talk_buffer=talk_buffer,
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


async def test_a_preempted_play_ends_quietly_when_its_open_fails():
    broken = StubChannel(hold="open", error=TalkBusyError("busy"))
    speaker, made = stub_speaker(broken)
    owners = []
    speaker.subscribe(owners.append)
    first = asyncio.create_task(speaker.play(chunks(tone(1))))
    await asyncio.wait_for(broken.held.wait(), 1)
    second = asyncio.create_task(speaker.play(chunks(tone(1))))
    await until(lambda: owners.count("play") == 2)

    broken.release.set()

    assert await asyncio.wait_for(first, 1) is False
    assert await asyncio.wait_for(second, 1) is True
    assert made[1].frames == 1
    await speaker.close()


async def test_a_preempted_play_ends_quietly_when_its_last_write_fails():
    broken = StubChannel(hold="send", error=ConnectError("hung up"))
    speaker, _ = stub_speaker(broken)
    first = asyncio.create_task(speaker.play(chunks(tone(1))))
    await asyncio.wait_for(broken.held.wait(), 1)
    newer = Producer(hold_at=1)
    second = asyncio.create_task(speaker.play(newer))
    await asyncio.wait_for(newer.held.wait(), 1)

    broken.release.set()

    assert await asyncio.wait_for(first, 1) is False
    assert broken.closed
    await speaker.close()
    newer.release.set()
    assert await asyncio.wait_for(second, 1) is False


async def test_a_new_owner_opens_its_own_session_when_the_old_owner_broke_it():
    broken = StubChannel(hold="send", error=ConnectError("hung up"))
    speaker, made = stub_speaker(broken)
    owners = []
    speaker.subscribe(owners.append)
    first = asyncio.create_task(speaker.play(chunks(tone(1))))
    await asyncio.wait_for(broken.held.wait(), 1)
    second = asyncio.create_task(speaker.play(chunks(tone(1))))
    await until(lambda: owners.count("play") == 2)

    broken.release.set()

    assert await asyncio.wait_for(first, 1) is False
    assert await asyncio.wait_for(second, 1) is True
    assert len(made) == 2
    assert made[1].frames == 1
    await speaker.close()


async def test_close_during_a_stalled_write_ends_the_play_with_false():
    stalled = StubChannel(hold="send", error=ConnectError("the camera took no data"))
    speaker, _ = stub_speaker(stalled)
    playing = asyncio.create_task(speaker.play(chunks(tone(1))))
    await asyncio.wait_for(stalled.held.wait(), 1)
    closing = asyncio.create_task(speaker.close())
    await until(lambda: speaker.owner is None)

    stalled.release.set()

    assert await asyncio.wait_for(playing, 1) is False
    await asyncio.wait_for(closing, 1)
    assert stalled.closed


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
    timers = spy_timers(monkeypatch, speaker)
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


def closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def failing_channel():
    channel = StubChannel(hold="open", error=ConnectError("refused"))
    channel.release.set()
    return channel


async def test_voice_takes_the_speaker_and_reaches_the_camera(rtsp, speaker):
    speaker.feed_talk(SSRC, voice())

    assert speaker.owner == "talk"
    await say_until(speaker, lambda: encode_alaw(voice()) in payloads(rtsp), (SSRC, voice()))
    assert {channel for channel, _ in rtsp.packets} == {4}


async def test_silent_frames_never_start_a_talk(rtsp, speaker):
    owners = []
    speaker.subscribe(owners.append)

    for _ in range(20):
        speaker.feed_talk(SSRC, quiet())
        await asyncio.sleep(0.01)

    assert owners == []
    assert "SETUP" not in methods(rtsp)


async def test_alaw_floor_counts_as_silence(speaker):
    floors = decode_alaw(b"\xd5" * 160), decode_alaw(b"\x55" * 160), decode_ulaw(b"\xfe\x7e" * 80)

    for frame in floors:
        speaker.feed_talk(SSRC, frame)

    assert speaker.owner is None


async def test_one_sample_beyond_voice_level_is_voice(speaker):
    edge = struct.pack("<2h", VOICE_LEVEL, -VOICE_LEVEL) + bytes(FRAME_BYTES - 4)
    beyond = struct.pack("<h", -VOICE_LEVEL - 1) + bytes(FRAME_BYTES - 2)

    speaker.feed_talk(SSRC, edge)
    assert speaker.owner is None
    speaker.feed_talk(SSRC, beyond)
    assert speaker.owner == "talk"


async def test_frames_of_any_even_length_are_rechunked(rtsp, speaker):
    pcm = voice() * 3

    for part in (pcm[:100], b"\x7f", pcm[100:600], pcm[600:]):
        speaker.feed_talk(SSRC, part)

    await until(lambda: len(rtsp.packets) == 3)
    assert payloads(rtsp) == [encode_alaw(voice())] * 3


async def test_silence_for_hangover_frees_the_speaker(rtsp, speaker):
    loop = asyncio.get_running_loop()
    freed = []

    def on_change(owner):
        if owner is None:
            freed.append(loop.time())

    speaker.subscribe(on_change)
    spoke = loop.time()
    speaker.feed_talk(SSRC, voice())

    await say_until(speaker, lambda: freed, (SSRC, quiet()), timeout=1)

    assert freed[0] - spoke >= TEST_HANGOVER


async def test_no_frames_for_hangover_frees_the_speaker(rtsp, speaker, monkeypatch):
    loop = asyncio.get_running_loop()
    timers = spy_timers(monkeypatch, speaker)
    before = asyncio.all_tasks()
    await say_until(speaker, lambda: payloads(rtsp), (SSRC, voice()))
    last = loop.time()
    speaker.feed_talk(SSRC, voice())

    await until(lambda: speaker.owner is None, 1)

    assert loop.time() - last >= TEST_HANGOVER
    await until(lambda: "TEARDOWN" in methods(rtsp), 1)
    assert pending(timers) == []
    await until(lambda: leftover(before) == [], 1)


async def test_silent_frames_of_the_owner_still_go_out(rtsp, speaker):
    speaker.feed_talk(SSRC, voice())
    for _ in range(3):
        speaker.feed_talk(SSRC, quiet())

    await until(lambda: len(rtsp.packets) == 4)
    assert payloads(rtsp) == [encode_alaw(voice())] + [encode_alaw(quiet())] * 3


async def test_talk_during_a_play_stops_the_play(rtsp, speaker):
    spoken = encode_alaw(voice())
    playing = asyncio.create_task(speaker.play(Producer()))
    await until(lambda: rtsp.packets)

    await say_until(speaker, lambda: spoken in payloads(rtsp), (SSRC, voice()))

    assert await asyncio.wait_for(playing, 1) is False
    assert speaker.owner == "talk"
    sent = payloads(rtsp)
    assert sound(OLDER) not in sent[sent.index(spoken) :]
    assert len(authorized(rtsp, "SETUP")) == 1


async def test_a_play_during_talk_mutes_it_until_its_next_start(rtsp, speaker):
    spoken, silence = encode_alaw(voice()), encode_alaw(quiet())
    await say_until(speaker, lambda: spoken in payloads(rtsp), (SSRC, voice()))
    playing = asyncio.create_task(speaker.play(Producer()))
    await say_until(speaker, lambda: sound(OLDER) in payloads(rtsp), (SSRC, voice()))

    await say_for(speaker, TEST_HANGOVER / 2, (SSRC, voice()))
    await say_for(speaker, TEST_HANGOVER + 0.05, (SSRC, quiet()))
    assert speaker.owner == "play"
    mark = len(payloads(rtsp))
    await say_until(speaker, lambda: spoken in payloads(rtsp)[mark:], (SSRC, voice()))

    assert await asyncio.wait_for(playing, 1) is False
    muted = payloads(rtsp)[payloads(rtsp).index(sound(OLDER)) : mark]
    assert spoken not in muted
    assert silence not in muted


async def test_a_muted_talk_with_voice_takes_a_freed_speaker(rtsp, speaker):
    owners = []
    speaker.subscribe(owners.append)
    spoken = encode_alaw(voice())
    await say_until(speaker, lambda: spoken in payloads(rtsp), (SSRC, voice()))
    playing = asyncio.create_task(speaker.play(chunks(tone(3))))
    await say_until(speaker, playing.done, (SSRC, voice(2500)))
    mark = len(payloads(rtsp))

    await say_until(speaker, lambda: spoken in payloads(rtsp)[mark:], (SSRC, voice()))

    assert playing.result() is True
    assert owners == ["talk", "play", None, "talk"]
    assert encode_alaw(voice(2500)) not in payloads(rtsp)


async def test_the_newer_of_two_talkers_wins(rtsp, speaker):
    first, second = encode_alaw(voice()), encode_alaw(voice(2000))
    await say_until(speaker, lambda: first in payloads(rtsp), (1, voice()))

    await say_until(
        speaker, lambda: payloads(rtsp).count(second) >= 3, (1, voice()), (2, voice(2000))
    )

    assert speaker.owner == "talk"
    sent = payloads(rtsp)
    assert first not in sent[sent.index(second) :]


async def test_a_muted_talker_stays_muted_when_its_frames_keep_coming(rtsp, speaker):
    owners = []
    speaker.subscribe(owners.append)
    first, second = encode_alaw(voice()), encode_alaw(voice(2000))
    await say_until(speaker, lambda: first in payloads(rtsp), (1, voice()))
    await say_until(speaker, lambda: second in payloads(rtsp), (1, voice()), (2, voice(2000)))
    await asyncio.sleep(TEST_HANGOVER / 4)
    mark = len(payloads(rtsp))

    await say_until(
        speaker, lambda: payloads(rtsp)[mark:].count(second) >= 3, (1, voice()), (2, voice(2000))
    )

    assert first not in payloads(rtsp)[mark:]
    assert owners == ["talk", "talk"]


async def test_frames_sent_while_the_session_opens_are_kept():
    async with camera(setup_gate=asyncio.Event()) as (rtsp, speaker):
        held = [voice(level) for level in (1000, 1500, 2000, 2500, 3500)]
        speaker.feed_talk(SSRC, held[0])
        await until(lambda: authorized(rtsp, "SETUP"))
        for frame in held[1:]:
            speaker.feed_talk(SSRC, frame)

        rtsp.setup_gate.set()

        await say_until(speaker, lambda: len(payloads(rtsp)) > len(held), (SSRC, voice()))
        assert payloads(rtsp)[: len(held)] == [encode_alaw(frame) for frame in held]


async def test_a_burst_keeps_only_the_newest_talk_buffer(rtsp):
    speaker = make_speaker(rtsp, hangover=2.0, talk_buffer=1.0)
    older, newer = voice(1000), voice(3000)

    for frame in [older] * 100 + [newer] * 50:
        speaker.feed_talk(SSRC, frame)

    await until(lambda: payloads(rtsp).count(encode_alaw(newer)) == 50, 3)
    await speaker.close()
    assert payloads(rtsp) == [encode_alaw(newer)] * 50


async def test_an_unreachable_camera_warns_once_per_streak(caplog):
    port = closed_port()
    opened = []

    def open_channel():
        opened.append(Backchannel("127.0.0.1", port, "/1/1", "admin", "pw", timeout=1.0))
        return opened[-1]

    speaker = Speaker(open_channel, linger=TEST_LINGER, hangover=TEST_HANGOVER)
    for start in range(1, 4):
        speaker.feed_talk(SSRC, voice())
        assert speaker.owner == "talk"
        await until(lambda: speaker.owner is None, 1)
        speaker.feed_talk(SSRC, voice())
        assert speaker.owner is None
        assert len(opened) == start
        await say_for(speaker, TEST_HANGOVER + 0.05, (SSRC, quiet()))

    await speaker.close()
    assert len(speaker_warnings(caplog)) == 1


async def test_a_successful_open_ends_the_failure_streak(caplog):
    channels = iter([failing_channel(), StubChannel(), failing_channel()])
    opened = []

    def open_channel():
        opened.append(next(channels))
        return opened[-1]

    speaker = Speaker(open_channel, linger=0.05, hangover=TEST_HANGOVER)
    speaker.feed_talk(1, voice())
    await until(lambda: speaker.owner is None, 1)
    speaker.feed_talk(2, voice())
    await until(lambda: len(opened) == 2 and opened[1].closed, 1)

    speaker.feed_talk(3, voice())
    await until(lambda: speaker.owner is None, 1)

    await speaker.close()
    assert opened[1].frames == 1
    assert len(speaker_warnings(caplog)) == 2


async def test_a_camera_hangup_mid_talk_frees_the_speaker_until_the_next_start(
    rtsp, speaker, caplog
):
    await say_until(speaker, lambda: rtsp.packets, (SSRC, voice()))

    rtsp.hang_up()

    await say_until(speaker, lambda: speaker.owner is None, (SSRC, voice()), timeout=5)
    assert len(speaker_warnings(caplog)) == 1
    speaker.feed_talk(SSRC, voice())
    assert speaker.owner is None
    await say_for(speaker, TEST_HANGOVER + 0.05, (SSRC, quiet()))
    assert len(authorized(rtsp, "SETUP")) == 1
    speaker.feed_talk(SSRC, voice())
    assert speaker.owner == "talk"
    await until(lambda: len(authorized(rtsp, "SETUP")) == 2)


async def test_a_play_started_after_a_talk_in_one_turn_wins(rtsp, speaker):
    for _ in range(10):
        speaker.feed_talk(SSRC, voice(1000))
    playing = asyncio.create_task(speaker.play(chunks(tone(3))))

    assert await asyncio.wait_for(playing, 1) is True

    await say_until(speaker, lambda: encode_alaw(voice()) in payloads(rtsp), (SSRC, voice()))
    assert payloads(rtsp)[:3] == [sound(OLDER)] * 3
    assert encode_alaw(voice(1000)) not in payloads(rtsp)
    assert len(authorized(rtsp, "SETUP")) == 1


async def test_a_talk_start_while_a_play_opens_the_session_uses_one_session():
    async with camera(setup_gate=asyncio.Event()) as (rtsp, speaker):
        playing = asyncio.create_task(speaker.play(Producer()))
        await until(lambda: authorized(rtsp, "SETUP"))
        speaker.feed_talk(SSRC, voice())
        assert speaker.owner == "talk"

        rtsp.setup_gate.set()

        assert await asyncio.wait_for(playing, 1) is False
        await say_until(speaker, lambda: encode_alaw(voice()) in payloads(rtsp), (SSRC, voice()))
        assert sound(OLDER) not in payloads(rtsp)
        assert len(authorized(rtsp, "SETUP")) == 1


async def test_close_while_the_session_opens_leaves_no_task(monkeypatch):
    async with camera(setup_gate=asyncio.Event()) as (rtsp, speaker):
        timers = spy_timers(monkeypatch, speaker)
        before = asyncio.all_tasks()
        speaker.feed_talk(SSRC, voice())
        await until(lambda: authorized(rtsp, "SETUP"))

        await asyncio.wait_for(speaker.close(), 1)

        assert speaker.owner is None
        assert "PLAY" not in methods(rtsp)
        assert leftover(before) == []
        assert pending(timers) == []


async def test_close_during_talk_leaves_no_task(rtsp, speaker, monkeypatch):
    timers = spy_timers(monkeypatch, speaker)
    before = asyncio.all_tasks()
    await say_until(speaker, lambda: payloads(rtsp), (SSRC, voice()))

    await asyncio.wait_for(speaker.close(), 1)

    assert speaker.owner is None
    await until(lambda: "TEARDOWN" in methods(rtsp))
    assert leftover(before) == []
    assert pending(timers) == []


async def test_close_during_a_stalled_talk_write_returns_at_once():
    stalled = StubChannel(hold="send")
    speaker, _ = stub_speaker(stalled)
    before = asyncio.all_tasks()
    speaker.feed_talk(SSRC, voice())
    await asyncio.wait_for(stalled.held.wait(), 1)

    await asyncio.wait_for(speaker.close(), 1)

    assert stalled.closed
    assert leftover(before) == []


async def test_an_open_failing_after_the_talk_ended_still_warns(caplog):
    slow = StubChannel(hold="open", error=ConnectError("timed out"))
    speaker, _ = stub_speaker(slow, hangover=TEST_HANGOVER)
    speaker.feed_talk(SSRC, voice())
    await asyncio.wait_for(slow.held.wait(), 1)
    await until(lambda: speaker.owner is None, 1)

    slow.release.set()

    await until(lambda: speaker_warnings(caplog), 1)
    await speaker.close()


async def test_a_write_failing_after_the_talk_ended_still_warns(caplog):
    stalled = StubChannel(hold="send", error=ConnectError("the camera took no data"))
    speaker, _ = stub_speaker(stalled, hangover=TEST_HANGOVER)
    speaker.feed_talk(SSRC, voice())
    await asyncio.wait_for(stalled.held.wait(), 1)
    await until(lambda: speaker.owner is None, 1)

    stalled.release.set()

    await until(lambda: speaker_warnings(caplog), 1)
    assert stalled.closed
    await speaker.close()


async def test_an_open_failing_after_a_newer_talk_took_over_is_quiet(caplog):
    slow = StubChannel(hold="open", error=ConnectError("timed out"))
    speaker, made = stub_speaker(slow, hangover=TEST_HANGOVER)
    speaker.feed_talk(1, voice())
    await asyncio.wait_for(slow.held.wait(), 1)
    speaker.feed_talk(2, voice(2000))

    slow.release.set()

    await until(lambda: len(made) == 2 and made[1].frames == 1, 1)
    assert speaker_warnings(caplog) == []
    await speaker.close()


async def test_close_right_after_the_open_finishes_closes_the_session():
    opening = StubChannel(hold="open")
    speaker, made = stub_speaker(opening)
    speaker.feed_talk(SSRC, voice())
    await asyncio.wait_for(opening.held.wait(), 1)

    opening.release.set()
    await asyncio.sleep(0)
    await asyncio.wait_for(speaker.close(), 1)

    assert opening.closed
    assert len(made) == 1


async def test_a_play_cancelled_right_after_the_open_finishes_keeps_the_session():
    opening = StubChannel(hold="open")
    speaker, made = stub_speaker(opening)
    playing = asyncio.create_task(speaker.play(Producer()))
    await asyncio.wait_for(opening.held.wait(), 1)

    opening.release.set()
    await asyncio.sleep(0)
    playing.cancel()

    with pytest.raises(asyncio.CancelledError):
        await playing
    assert await speaker.play(chunks(tone(1))) is True
    assert len(made) == 1
    assert opening.frames == 1
    await speaker.close()
    assert opening.closed


async def test_feed_after_close_is_ignored(rtsp, speaker, monkeypatch):
    timers = spy_timers(monkeypatch, speaker)
    before = asyncio.all_tasks()
    await speaker.close()

    speaker.feed_talk(SSRC, voice())

    assert speaker.owner is None
    assert timers == []
    assert leftover(before) == []
    assert rtsp.requests == []
