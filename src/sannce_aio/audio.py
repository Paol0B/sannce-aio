import ipaddress
import struct
from bisect import bisect_left
from collections.abc import Callable

from .protocol import build_data

G711A = 1
G711U = 2

# 4 per 640-byte app frame (protocol.md, Codecs, sample rate, frame size and pacing)
_SUBFRAME_SAMPLES = 80
SUBFRAME_PCM_BYTES = 2 * _SUBFRAME_SAMPLES

_ALAW_SEGMENT_END = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
_ULAW_SEGMENT_END = (0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF)
_ULAW_BIAS = 33

_CHANNEL = 0
_TALK_HEAD = b"NVR\x00\t" + bytes([_CHANNEL]) + b"\t\x00\tNVS\x00"
# the code is half the audio byte count (protocol.md, Audio frame layout)
_SUBHEADER = bytes([0x00, 0x01, _SUBFRAME_SAMPLES // 2, 0x00])


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


_ENCODERS = {G711A: encode_alaw, G711U: encode_ulaw}


def frame_talk_audio(pcm: bytes, codec: int, seq: int, ip: str) -> bytes:
    encode = _ENCODERS.get(codec)
    if encode is None:
        raise ValueError(f"unsupported codec {codec}")
    if len(pcm) % SUBFRAME_PCM_BYTES:
        raise ValueError(
            f"pcm length {len(pcm)} is not a multiple of {SUBFRAME_PCM_BYTES}"
        )
    # NVS block IP is byte-reversed, header IP is not (protocol.md, Audio frame layout)
    head = _TALK_HEAD + ipaddress.IPv4Address(ip).packed[::-1] + _SUBHEADER
    packets = []
    for index, start in enumerate(range(0, len(pcm), SUBFRAME_PCM_BYTES)):
        audio = encode(pcm[start : start + SUBFRAME_PCM_BYTES])
        packets.append(build_data(head + audio, seq + index, ip))
    return b"".join(packets)
