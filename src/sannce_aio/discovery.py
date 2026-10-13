import asyncio
import ipaddress
import logging
import socket
import struct
from collections.abc import AsyncIterator, Iterable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from .errors import ProtocolError
from .protocol import TERMINATOR, encode_fields

_LOG = logging.getLogger(__name__)

SOURCE_PORT = 6001
TARGETS = (
    ("234.56.78.9", 3000),
    ("234.56.78.9", 4000),
    ("239.255.255.250", 3000),
    ("239.255.255.250", 4000),
)
SEARCH_PORTS = tuple(sorted({port for _, port in TARGETS}))

_MAGIC = 0xE5E5BEBE
_ENVELOPE = struct.Struct("<IHHH")
_PROTOCOL = "NEWM4V00"
_MARKER = f"{_PROTOCOL}\t".encode()
_MULTICAST_TTL = 64
# nine digits stay inside a 32-bit int
_MAX_DIGITS = 9

# field positions after the marker (protocol.md, Seek reply)
_MAC = 2
_CHANNELS = 6
_SERVER_PORT = 7
_HTTP_PORT = 10
_MODEL = 22
_SERIAL = 24
_IP = 32


@dataclass(frozen=True)
class DiscoveredCamera:
    ip: str
    mac: str
    serial: str
    model: str
    http_port: int
    server_port: int
    channels: int


def build_seek_request() -> bytes:
    payload = encode_fields(["IP", "IP", _PROTOCOL, "CMD", "SEEKNVSS"])
    return _ENVELOPE.pack(_MAGIC, 0, 0, len(payload)) + payload


def is_seek_request(datagram: bytes) -> bool:
    if len(datagram) < _ENVELOPE.size or _ENVELOPE.unpack_from(datagram)[0] != _MAGIC:
        return False
    return any(
        fields[:2] == ["CMD", "SEEKNVSS"]
        for fields in _units(datagram[_ENVELOPE.size :])
    )


def build_seek_reply(camera: DiscoveredCamera) -> bytes:
    fields = [""] * (_IP + 1)
    fields[:2] = ["CMD", "NVSS"]
    fields[_MAC] = _reverse_mac(camera.mac)
    fields[_CHANNELS] = str(camera.channels)
    fields[_SERVER_PORT] = str(camera.server_port)
    fields[_HTTP_PORT] = str(camera.http_port)
    fields[_MODEL] = camera.model
    fields[_SERIAL] = camera.serial
    fields[_IP] = camera.ip
    payload = encode_fields([_PROTOCOL, *fields])
    return _ENVELOPE.pack(_MAGIC, 0, 0, len(payload)) + payload


def parse_discovery_reply(datagram: bytes, source_ip: str = "") -> DiscoveredCamera:
    if len(datagram) < _ENVELOPE.size:
        raise ProtocolError(
            f"datagram has {len(datagram)} bytes, the envelope needs {_ENVELOPE.size}"
        )
    magic, *_ = _ENVELOPE.unpack_from(datagram)
    if magic != _MAGIC:
        raise ProtocolError(f"datagram magic is {magic:#010x}")
    for fields in _units(datagram[_ENVELOPE.size :]):
        if fields[:2] == ["CMD", "NVSS"]:
            return _camera(fields, source_ip)
    raise ProtocolError("datagram holds no NVSS reply")


async def discover(timeout: float = 3.0) -> list[DiscoveredCamera]:
    async with _search(TARGETS) as collector:
        await asyncio.sleep(timeout)
    return list(collector.cameras.values())


async def find_camera(ip: str, timeout: float = 2.0) -> DiscoveredCamera | None:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    # the vendor client asks one address too (protocol.md)
    targets = (*TARGETS, *((ip, port) for port in SEARCH_PORTS))
    async with _search(targets, ip) as collector:
        try:
            return await asyncio.wait_for(collector.match, timeout)
        except TimeoutError:
            return None


class _Collector(asyncio.DatagramProtocol):
    def __init__(self, wanted: str = "") -> None:
        self.cameras: dict[str, DiscoveredCamera] = {}
        self.match: asyncio.Future[DiscoveredCamera] = (
            asyncio.get_running_loop().create_future()
        )
        self._wanted = wanted

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            camera = parse_discovery_reply(data, addr[0])
        except ProtocolError as exc:
            _LOG.debug("ignored datagram from %s: %s", addr[0], exc)
            return
        self.cameras.setdefault(_identity(camera), camera)
        if camera.ip == self._wanted and not self.match.done():
            self.match.set_result(camera)

    def error_received(self, exc: Exception) -> None:
        _LOG.debug("send failed: %s", exc)


@asynccontextmanager
async def _search(
    targets: Iterable[tuple[str, int]], wanted: str = ""
) -> AsyncIterator[_Collector]:
    loop = asyncio.get_running_loop()
    transport, collector = await loop.create_datagram_endpoint(
        lambda: _Collector(wanted), sock=_open_socket()
    )
    try:
        request = build_seek_request()
        for target in targets:
            transport.sendto(request, target)
        yield collector
    finally:
        transport.close()
        # the loop closes the socket on its next turn; yield so port 6001 is free
        await asyncio.sleep(0)


def _open_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # TTL 64 and both groups joined, as the app does (protocol.md, Ports and groups)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, _MULTICAST_TTL)
        _bind(sock)
        join_groups(sock)
    except BaseException:
        sock.close()
        raise
    return sock


def _bind(sock: socket.socket) -> None:
    # no SO_REUSEADDR, unlike the app: a shared port could send our replies elsewhere
    try:
        sock.bind(("", SOURCE_PORT))
    except OSError as exc:
        # assumes the camera answers to the source port (protocol.md, Ports and groups)
        _LOG.info("port %d is busy, using another source port: %s", SOURCE_PORT, exc)
        sock.bind(("", 0))


def join_groups(sock: socket.socket, interface: str = "0.0.0.0") -> dict[str, OSError]:
    failed = {}
    groups = {host for host, _ in TARGETS if ipaddress.ip_address(host).is_multicast}
    for group in sorted(groups):
        membership = socket.inet_aton(group) + socket.inet_aton(interface)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        except OSError as exc:
            failed[group] = exc
    return failed


def _units(body: bytes) -> Iterator[list[str]]:
    start = body.find(_MARKER)
    while start >= 0:
        start += len(_MARKER)
        end = body.find(TERMINATOR, start)
        if end < 0:
            return
        yield body[start:end].decode("utf-8", "replace").split("\t")
        start = body.find(_MARKER, end + len(TERMINATOR))


def _camera(fields: list[str], source_ip: str) -> DiscoveredCamera:
    ip = _field(fields, _IP) or source_ip
    if not ip:
        raise ProtocolError("reply has no ip and no source address")
    return DiscoveredCamera(
        ip=ip,
        mac=_reverse_mac(_field(fields, _MAC)),
        serial=_field(fields, _SERIAL),
        model=_field(fields, _MODEL),
        http_port=_decimal(_field(fields, _HTTP_PORT)),
        server_port=_decimal(_field(fields, _SERVER_PORT)),
        channels=_decimal(_field(fields, _CHANNELS)),
    )


def _field(fields: list[str], index: int) -> str:
    return fields[index] if index < len(fields) else ""


def _decimal(text: str) -> int:
    if text.isascii() and text.isdigit() and len(text) <= _MAX_DIGITS:
        return int(text)
    return 0


def _reverse_mac(text: str) -> str:
    octets = text.split(":")
    if len(octets) != 6 or any(len(octet) != 2 for octet in octets):
        return ""
    # the camera sends the octets in reverse order (protocol.md, Seek reply)
    return ":".join(reversed(octets))


def _identity(camera: DiscoveredCamera) -> str:
    # one camera answers up to four times; MAC identifies it, then serial, then ip
    return camera.mac or camera.serial or camera.ip
