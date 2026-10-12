import struct

import pytest

from sannce_aio.audio import G711A, G711U, encode_alaw, encode_ulaw, frame_talk_audio
from sannce_aio.protocol import DATA_MAGIC, parse_frame

DEVICE_IP = "192.168.1.10"

# ITU-T G.711 A-law: 13-bit magnitude, 8 chords of 16 steps, code XOR 0x55
ALAW_VECTOR = [
    (0, 0xD5),
    (7, 0xD5),
    (8, 0xD5),
    (15, 0xD5),
    (16, 0xD4),
    (248, 0xDA),
    (255, 0xDA),
    (256, 0xC5),
    (504, 0xCA),
    (511, 0xCA),
    (512, 0xF5),
    (1016, 0xFA),
    (1024, 0xE5),
    (2040, 0xEA),
    (2048, 0x95),
    (4088, 0x9A),
    (4096, 0x85),
    (8184, 0x8A),
    (8192, 0xB5),
    (16376, 0xBA),
    (16384, 0xA5),
    (32767, 0xAA),
    (-1, 0x55),
    (-8, 0x55),
    (-9, 0x55),
    (-16, 0x55),
    (-17, 0x54),
    (-256, 0x5A),
    (-257, 0x45),
    (-1000, 0x7A),
    (-16384, 0x3A),
    (-32767, 0x2A),
    (-32768, 0x2A),
]

# ITU-T G.711 mu-law: bias 33 on the 14-bit magnitude. Negative samples follow
# audioop and sox, so some edges sit one code away from the ITU reference code
ULAW_VECTOR = [
    (0, 0xFF),
    (3, 0xFF),
    (4, 0xFE),
    (11, 0xFE),
    (12, 0xFD),
    (123, 0xF0),
    (124, 0xEF),
    (1000, 0xCE),
    (8000, 0xA0),
    (16000, 0x90),
    (32124, 0x80),
    (32767, 0x80),
    (-1, 0x7E),
    (-4, 0x7E),
    (-5, 0x7E),
    (-9, 0x7D),
    (-1000, 0x4E),
    (-8000, 0x20),
    (-32768, 0x00),
]


def pcm16(samples):
    return struct.pack(f"<{len(samples)}h", *samples)


def split_packets(data):
    frames = []
    while data:
        frame, used = parse_frame(data)
        frames.append(frame)
        data = data[used:]
    return frames


def nvs_block(frame):
    return frame.payload.split(b"NVS\x00", 1)[1]


def audio_of(frame):
    return nvs_block(frame)[8:]


def test_codec_ids():
    assert (G711A, G711U) == (1, 2)


def test_encode_alaw_matches_itu_vector():
    samples, codes = zip(*ALAW_VECTOR)
    assert encode_alaw(pcm16(samples)) == bytes(codes)


def test_encode_ulaw_matches_reference_vector():
    samples, codes = zip(*ULAW_VECTOR)
    assert encode_ulaw(pcm16(samples)) == bytes(codes)


@pytest.mark.parametrize("encode", [encode_alaw, encode_ulaw])
def test_encode_empty_input(encode):
    assert encode(b"") == b""


@pytest.mark.parametrize("encode", [encode_alaw, encode_ulaw])
def test_encode_rejects_half_a_sample(encode):
    with pytest.raises(ValueError, match="odd"):
        encode(b"\x00\x00\x00")


def test_frame_talk_audio_matches_talk_audio_frame(examples):
    example = examples["talk_audio_frame_g711a"]
    silence = bytes(160)
    built = frame_talk_audio(
        silence, G711A, example["fields"]["data_sequence"], DEVICE_IP
    )
    assert built == bytes.fromhex(example["hex"])


def test_frame_talk_audio_sends_one_packet_per_80_sample_sub_frame():
    pcm = pcm16([(n * 101) % 20000 - 10000 for n in range(320)])
    assert len(pcm) == 640

    frames = split_packets(frame_talk_audio(pcm, G711A, 40, DEVICE_IP))

    assert [frame.seq for frame in frames] == [40, 41, 42, 43]
    assert {frame.magic for frame in frames} == {DATA_MAGIC}
    assert [len(audio_of(frame)) for frame in frames] == [80, 80, 80, 80]
    assert b"".join(audio_of(frame) for frame in frames) == encode_alaw(pcm)


def test_frame_talk_audio_g711u_uses_mulaw_with_the_same_sub_header():
    pcm = pcm16([n * 400 - 16000 for n in range(80)])

    (frame,) = split_packets(frame_talk_audio(pcm, G711U, 0, DEVICE_IP))

    assert nvs_block(frame)[4:8] == b"\x00\x01\x28\x00"
    assert audio_of(frame) == encode_ulaw(pcm)


def test_frame_talk_audio_reverses_the_ip_in_the_payload_only():
    data = frame_talk_audio(bytes(160), G711A, 0, "10.20.30.40")

    (frame,) = split_packets(data)
    assert data[8:12] == bytes([10, 20, 30, 40])
    assert nvs_block(frame)[:4] == bytes([40, 30, 20, 10])


@pytest.mark.parametrize("size", [1, 159, 161, 639])
def test_frame_talk_audio_rejects_a_partial_sub_frame(size):
    with pytest.raises(ValueError, match="multiple of 160"):
        frame_talk_audio(bytes(size), G711A, 0, DEVICE_IP)


@pytest.mark.parametrize("codec", [0, 3, 0x24, 0x15])
def test_frame_talk_audio_rejects_a_codec_it_cannot_encode(codec):
    with pytest.raises(ValueError, match="unsupported codec"):
        frame_talk_audio(bytes(160), codec, 0, DEVICE_IP)


def test_frame_talk_audio_of_no_audio_is_empty():
    assert frame_talk_audio(b"", G711A, 0, DEVICE_IP) == b""
