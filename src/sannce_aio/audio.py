import struct
from bisect import bisect_left
from collections.abc import Callable

_ALAW_SEGMENT_END = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
_ULAW_SEGMENT_END = (0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF)
_ULAW_BIAS = 33


def _alaw(sample: int) -> int:
    value = sample >> 3
    if value >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        value = -value - 1
    segment = bisect_left(_ALAW_SEGMENT_END, value)
    shift = 1 if segment < 2 else segment
    return ((segment << 4) | ((value >> shift) & 0x0F)) ^ mask


def _ulaw(sample: int) -> int:
    value = sample >> 2
    if value < 0:
        # negated, not complemented: same codes as audioop and sox
        value = -value
        mask = 0x7F
    else:
        mask = 0xFF
    value = min(value + _ULAW_BIAS, _ULAW_SEGMENT_END[-1])
    segment = bisect_left(_ULAW_SEGMENT_END, value)
    return ((segment << 4) | ((value >> (segment + 1)) & 0x0F)) ^ mask


def _encode(pcm: bytes, encode_sample: Callable[[int], int]) -> bytes:
    if len(pcm) % 2:
        raise ValueError(f"pcm length {len(pcm)} is odd")
    return bytes(encode_sample(sample) for (sample,) in struct.iter_unpack("<h", pcm))


def encode_alaw(pcm: bytes) -> bytes:
    return _encode(pcm, _alaw)


def encode_ulaw(pcm: bytes) -> bytes:
    return _encode(pcm, _ulaw)


def _alaw_sample(code: int) -> int:
    code ^= 0x55
    segment = (code >> 4) & 0x07
    value = (code & 0x0F) << 4
    # the middle of the code's step, as in the ITU-T G.711 reference decoder
    if segment == 0:
        value += 8
    else:
        value = (value + 0x108) << (segment - 1)
    return value if code & 0x80 else -value


_ALAW_SAMPLES = [_alaw_sample(code) for code in range(256)]


def decode_alaw(data: bytes) -> bytes:
    return struct.pack(f"<{len(data)}h", *(_ALAW_SAMPLES[code] for code in data))


def _ulaw_sample(code: int) -> int:
    code = ~code & 0xFF
    value = (((code & 0x0F) << 1) + _ULAW_BIAS) << ((code & 0x70) >> 4)
    value -= _ULAW_BIAS
    return (-value if code & 0x80 else value) << 2


_ULAW_SAMPLES = [_ulaw_sample(code) for code in range(256)]


def decode_ulaw(data: bytes) -> bytes:
    return struct.pack(f"<{len(data)}h", *(_ULAW_SAMPLES[code] for code in data))
