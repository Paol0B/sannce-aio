import ipaddress
import struct
from dataclasses import dataclass

from .errors import ProtocolError

COMMAND_MAGIC = 0xF5EAF5F1
DATA_MAGIC = 0xF9EAF5F1

HEADER_SIZE = 20
MAX_PACKET = 2048
MAX_COMMAND_PAYLOAD = 1440
MAX_DATA_PAYLOAD = 1448
TERMINATOR = b"\n\n\n"

_COMMAND_HEADER = struct.Struct("<IHH10xH")
_DATA_HEADER = struct.Struct("<II4s2xH4x")


@dataclass(frozen=True)
class Frame:
    magic: int
    seq: int
    fields: list[str] | None = None
    payload: bytes | None = None


def encode_fields(fields: list[str]) -> bytes:
    # heartbeat: no fields, no terminator (protocol.md, Heartbeat message and sender)
    if not fields:
        return b""
    for index, field in enumerate(fields):
        if "\t" in field:
            raise ProtocolError(f"field {index} contains a tab")
    payload = "\t".join(fields).encode("utf-8") + TERMINATOR
    # a terminator inside a value ends the command early (protocol.md, Field lists)
    if payload.find(TERMINATOR) != len(payload) - len(TERMINATOR):
        raise ProtocolError("field list contains the terminator")
    return payload


def decode_fields(payload: bytes) -> list[str]:
    if not payload:
        return []
    end = payload.find(TERMINATOR)
    if end < 0:
        raise ProtocolError("payload has no terminator")
    if end != len(payload) - len(TERMINATOR):
        raise ProtocolError("payload holds more than one command")
    try:
        text = payload[:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"payload is not UTF-8: {exc}") from exc
    return text.split("\t")


def build_command(fields: list[str], seq: int) -> bytes:
    payload = encode_fields(fields)
    _check_size(payload, MAX_COMMAND_PAYLOAD)
    header = _COMMAND_HEADER.pack(
        COMMAND_MAGIC, seq, HEADER_SIZE + len(payload), len(payload)
    )
    return header + payload


def build_data(payload: bytes, seq: int, ip: str) -> bytes:
    _check_size(payload, MAX_DATA_PAYLOAD)
    peer = ipaddress.IPv4Address(ip).packed
    header = _DATA_HEADER.pack(DATA_MAGIC, seq, peer, HEADER_SIZE + len(payload))
    return header + payload


def parse_frame(buf: bytes) -> tuple[Frame | None, int]:
    start = 0
    while len(buf) - start >= HEADER_SIZE:
        header = _read_header(buf, start)
        if header is not None:
            magic, seq, total = header
            end = start + total
            if end > len(buf):
                return None, 0
            # the SDK ignores offset 18 on receive (protocol.md, Packet header)
            body = bytes(buf[start + HEADER_SIZE : end])
            if magic == COMMAND_MAGIC:
                return Frame(magic, seq, fields=decode_fields(body)), end
            return Frame(magic, seq, payload=body), end
        # resync: skip one byte (protocol.md, Delimiting messages in a TCP stream)
        start += 1
    return None, 0


def _read_header(buf: bytes, start: int) -> tuple[int, int, int] | None:
    (magic,) = struct.unpack_from("<I", buf, start)
    if magic == COMMAND_MAGIC:
        seq, total = struct.unpack_from("<HH", buf, start + 4)
    elif magic == DATA_MAGIC:
        (seq,) = struct.unpack_from("<I", buf, start + 4)
        (total,) = struct.unpack_from("<H", buf, start + 14)
    else:
        return None
    if not (HEADER_SIZE <= total <= MAX_PACKET):
        return None
    return magic, seq, total


def _check_size(payload: bytes, limit: int) -> None:
    if len(payload) > limit:
        raise ProtocolError(f"payload is {len(payload)} bytes, the limit is {limit}")
