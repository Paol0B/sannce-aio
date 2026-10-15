import struct

import pytest

from sannce_aio.audio import decode_alaw, decode_ulaw, encode_alaw, encode_ulaw

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

# ITU-T G.711 A-law decoding: each code reads as the middle of its step
ALAW_DECODE_VECTOR = [
    (0xD5, 8),
    (0xD4, 24),
    (0xC5, 264),
    (0xF5, 528),
    (0xE5, 1056),
    (0x95, 2112),
    (0x85, 4224),
    (0xB5, 8448),
    (0xA5, 16896),
    (0xAA, 32256),
    (0x55, -8),
    (0x7A, -1008),
    (0x2A, -32256),
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


def test_decode_alaw_matches_itu_vector():
    codes, samples = zip(*ALAW_DECODE_VECTOR)
    assert decode_alaw(bytes(codes)) == pcm16(samples)


def test_every_alaw_code_survives_decode_then_encode():
    codes = bytes(range(256))
    assert encode_alaw(decode_alaw(codes)) == codes


def test_decode_alaw_of_no_audio_is_empty():
    assert decode_alaw(b"") == b""


def test_decode_ulaw_matches_itu_extremes():
    codes = bytes([0x00, 0x80, 0xFF, 0xFE, 0x7E])
    assert decode_ulaw(codes) == pcm16([-32124, 32124, 0, 8, -8])


def test_every_ulaw_code_survives_decode_then_encode():
    codes = bytes(range(256))
    # 0x7F and 0xFF both decode to zero; encode picks 0xFF
    assert encode_ulaw(decode_ulaw(codes)) == codes.replace(b"\x7f", b"\xff")


def test_decode_ulaw_of_no_audio_is_empty():
    assert decode_ulaw(b"") == b""
