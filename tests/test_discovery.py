import asyncio
import contextlib
import dataclasses
import errno
import logging
import socket
import struct

import pytest
import pytest_asyncio

from sannce_aio import discovery
from sannce_aio.discovery import (
    DiscoveredCamera,
    build_seek_reply,
    build_seek_request,
    discover,
    find_camera,
    is_seek_request,
    parse_discovery_reply,
)
from sannce_aio.errors import ProtocolError

REQUEST = "discovery_seek_request"
REPLY = "discovery_reply"
SOURCE_PORT = 6001
WAIT = 0.15
LATE = 0.05


def raw(examples, example_id):
    return bytes.fromhex(examples[example_id]["hex"])


def datagram(fields, *, prefix=b""):
    payload = prefix + b"NEWM4V00\t" + "\t".join(fields).encode() + b"\n\n\n"
    return struct.pack("<IHHH", 0xE5E5BEBE, 0, 0, len(payload)) + payload


def edit(fields, changes):
    edited = list(fields)
    for index, value in changes.items():
        edited[index] = value
    return edited


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(("", port))
        except OSError:
            return False
    return True


@pytest.fixture
def reply_fields(examples):
    return examples[REPLY]["fields"]["payload"]


@pytest.fixture
def camera(examples):
    host = examples[REPLY]["fields"]["parsed"]
    return DiscoveredCamera(
        ip=host["ip"],
        mac=host["mac"],
        serial=host["serial"],
        model=host["model"],
        http_port=host["http_port"],
        server_port=host["server_port"],
        channels=host["channels"],
    )


def test_seek_request_matches_example(examples):
    assert build_seek_request() == raw(examples, REQUEST)


def test_targets_match_example(examples):
    fields = examples[REQUEST]["fields"]
    targets = [f"{host}:{port}" for host, port in discovery.TARGETS]
    assert targets == fields["destinations"]
    assert discovery.SOURCE_PORT == fields["source_port"] == SOURCE_PORT


def test_datagram_helper_rebuilds_example(examples, reply_fields):
    assert datagram(reply_fields) == raw(examples, REPLY)


def test_parse_reply_matches_example(examples, camera):
    assert parse_discovery_reply(raw(examples, REPLY)) == camera


def test_parse_reply_maps_each_field(reply_fields):
    fields = edit(
        reply_fields,
        {
            2: "FF:EE:DD:CC:BB:AA",
            6: "16",
            7: "3100",
            8: "4100",
            9: "12",
            10: "8080",
            20: "2",
            22: "CAM-2",
            24: "SN2",
            32: "10.1.2.3",
        },
    )

    assert parse_discovery_reply(datagram(fields)) == DiscoveredCamera(
        ip="10.1.2.3",
        mac="AA:BB:CC:DD:EE:FF",
        serial="SN2",
        model="CAM-2",
        http_port=8080,
        server_port=3100,
        channels=16,
    )


def test_mac_keeps_letter_case(reply_fields):
    fields = edit(reply_fields, {2: "aa:bb:CC:dd:ee:0F"})
    assert parse_discovery_reply(datagram(fields)).mac == "0F:ee:dd:CC:bb:aa"


@pytest.mark.parametrize(
    "wire",
    [
        "",
        "2A53005E0000",
        "2A:53:00:5E:00",
        "2A:53:00:5E:00:00:11",
        "2A-53-00-5E-00-00",
        "2A:53:0:5E:00:000",
    ],
)
def test_mac_with_wrong_shape_is_empty(reply_fields, wire):
    fields = edit(reply_fields, {2: wire})
    assert parse_discovery_reply(datagram(fields)).mac == ""


def test_ip_field_wins_over_source_address(examples):
    camera = parse_discovery_reply(raw(examples, REPLY), "10.9.9.9")
    assert camera.ip == "192.168.1.10"


def test_ip_falls_back_to_source_address(reply_fields):
    data = datagram(edit(reply_fields, {32: ""}))
    assert parse_discovery_reply(data, "192.168.1.77").ip == "192.168.1.77"


def test_reply_without_any_ip_is_rejected(reply_fields):
    data = datagram(edit(reply_fields, {32: ""}))
    with pytest.raises(ProtocolError):
        parse_discovery_reply(data)


def test_missing_trailing_fields_read_as_empty(reply_fields):
    camera = parse_discovery_reply(datagram(reply_fields[:11]), "192.168.1.5")

    assert camera == DiscoveredCamera(
        ip="192.168.1.5",
        mac="00:00:5E:00:53:2A",
        serial="",
        model="",
        http_port=80,
        server_port=3000,
        channels=1,
    )


@pytest.mark.parametrize(
    "text",
    ["", "abc", "-1", "+80", " 80", "80 ", "8 0", "8.0", "\u0668\u0660", "\u00b2"],
)
def test_decimal_fields_read_zero_unless_digits(reply_fields, text):
    fields = edit(reply_fields, {6: text, 7: text, 10: text})

    camera = parse_discovery_reply(datagram(fields))

    assert (camera.channels, camera.server_port, camera.http_port) == (0, 0, 0)


def test_oversized_decimal_reads_zero(reply_fields):
    fields = edit(reply_fields, {10: "9" * 5000})
    assert parse_discovery_reply(datagram(fields)).http_port == 0


def test_invalid_utf8_is_replaced(examples):
    data = raw(examples, REPLY).replace(b"MODEL-X", b"MODEL-\xff")
    assert parse_discovery_reply(data).model == "MODEL-\ufffd"


def test_bytes_before_marker_are_ignored(reply_fields, camera):
    data = datagram(reply_fields, prefix=b"\x01junk\x00")
    assert parse_discovery_reply(data) == camera


def test_reply_after_another_unit_is_found(reply_fields, camera):
    data = datagram(reply_fields, prefix=b"NEWM4V00\tCMD\tOTHER\n\n\n")
    assert parse_discovery_reply(data) == camera


@pytest.mark.parametrize(
    ("offset", "value"),
    [(4, b"\x07\x00"), (6, b"\x01\x00"), (8, b"\xff\xff")],
    ids=["id", "flag", "length"],
)
def test_envelope_id_flag_and_length_are_not_checked(
    examples, camera, offset, value
):
    data = bytearray(raw(examples, REPLY))
    data[offset : offset + 2] = value
    assert parse_discovery_reply(bytes(data)) == camera


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "short",
        "wrong_magic",
        "ack",
        "no_marker",
        "no_terminator",
        "seek_request",
        "other_verb",
        "other_class",
    ],
)
def test_parse_rejects_bad_datagram(examples, reply_fields, case):
    good = raw(examples, REPLY)
    bad = {
        "empty": b"",
        "short": good[:9],
        "wrong_magic": b"\x00" + good[1:],
        "ack": good[:6] + bytes(4),
        "no_marker": good[:10] + b"hello\n\n\n",
        "no_terminator": good[:-3],
        "seek_request": raw(examples, REQUEST),
        "other_verb": datagram(edit(reply_fields, {1: "OTHER"})),
        "other_class": datagram(edit(reply_fields, {0: "XXX"})),
    }[case]

    with pytest.raises(ProtocolError):
        parse_discovery_reply(bad)


def test_seek_reply_round_trips(camera):
    assert parse_discovery_reply(build_seek_reply(camera)) == camera


def test_seek_reply_puts_each_field_where_the_example_has_it(camera, reply_fields):
    payload = build_seek_reply(camera)[10:].decode()
    fields = payload.removesuffix("\n\n\n").split("\t")[1:]

    assert len(fields) == len(reply_fields)
    for index in (0, 1, 2, 6, 7, 10, 22, 24, 32):
        assert fields[index] == reply_fields[index]


def test_seek_reply_without_an_ip_reads_the_source_address(camera):
    reply = build_seek_reply(dataclasses.replace(camera, ip=""))

    assert parse_discovery_reply(reply, "10.0.0.5").ip == "10.0.0.5"


def test_seek_request_is_recognised(examples):
    request = raw(examples, REQUEST)

    assert is_seek_request(request)
    assert not is_seek_request(raw(examples, REPLY))
    assert not is_seek_request(request[:9])
    assert not is_seek_request(b"\x00" + request[1:])
    assert not is_seek_request(datagram(["CMD", "OTHER"]))


class Responder(asyncio.DatagramProtocol):
    def __init__(self, replies, late):
        self.replies = replies
        self.late = late
        self.requests = []
        self.sources = []
        self.transport = None
        self.address = None

    def connection_made(self, transport):
        self.transport = transport
        self.address = transport.get_extra_info("sockname")

    def datagram_received(self, data, addr):
        self.requests.append(data)
        self.sources.append(addr)
        for reply in self.replies:
            self.transport.sendto(reply, addr)
        loop = asyncio.get_running_loop()
        for reply in self.late:
            loop.call_later(LATE, self.transport.sendto, reply, addr)


@pytest_asyncio.fixture
async def serve():
    loop = asyncio.get_running_loop()
    transports = []
    loop_errors = []
    loop.set_exception_handler(lambda _, context: loop_errors.append(context))

    async def start(*replies, late=()):
        transport, responder = await loop.create_datagram_endpoint(
            lambda: Responder(replies, late), local_addr=("127.0.0.1", 0)
        )
        transports.append(transport)
        return responder

    yield start
    for transport in transports:
        transport.close()
    assert loop_errors == []


@pytest.fixture
def aim(monkeypatch):
    def set_targets(*addresses):
        monkeypatch.setattr(discovery, "TARGETS", addresses)

    return set_targets


@pytest.mark.asyncio
async def test_discover_finds_camera_and_sends_example_request(
    serve, aim, examples, camera
):
    responder = await serve(raw(examples, REPLY))
    aim(responder.address)

    found = await discover(timeout=WAIT)

    assert found == [camera]
    assert responder.requests == [raw(examples, REQUEST)]


@pytest.mark.asyncio
async def test_discover_sends_from_port_6001(serve, aim, examples):
    if not port_free(SOURCE_PORT):
        pytest.skip("port 6001 is in use")
    responder = await serve(raw(examples, REPLY))
    aim(responder.address)

    await discover(timeout=WAIT)

    assert [port for _, port in responder.sources] == [SOURCE_PORT]
    assert port_free(SOURCE_PORT)


@pytest.mark.asyncio
async def test_discover_falls_back_when_port_6001_is_taken(
    serve, aim, examples, camera
):
    responder = await serve(raw(examples, REPLY))
    aim(responder.address)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
        # if another process holds the port, it is taken all the same
        with contextlib.suppress(OSError):
            holder.bind(("", SOURCE_PORT))

        found = await discover(timeout=WAIT)

    assert found == [camera]
    assert [port for _, port in responder.sources] != [SOURCE_PORT]


@pytest.mark.asyncio
async def test_discover_returns_empty_without_replies(serve, aim):
    responder = await serve()
    aim(responder.address)

    assert await discover(timeout=WAIT) == []
    assert len(responder.requests) == 1


@pytest.mark.asyncio
async def test_discover_deduplicates_repeated_replies(serve, aim, examples, camera):
    reply = raw(examples, REPLY)
    responder = await serve(reply, reply)
    aim(responder.address, responder.address)

    assert await discover(timeout=WAIT) == [camera]
    assert len(responder.requests) == 2


@pytest.mark.asyncio
async def test_discover_returns_every_camera(
    serve, aim, examples, reply_fields, camera
):
    other_fields = edit(
        reply_fields, {2: "2B:53:00:5E:00:00", 24: "SN0000000002", 32: "192.168.1.11"}
    )
    other = dataclasses.replace(
        camera, mac="00:00:5E:00:53:2B", serial="SN0000000002", ip="192.168.1.11"
    )
    responder = await serve(
        raw(examples, REPLY), datagram(other_fields), raw(examples, REPLY)
    )
    aim(responder.address)

    found = await discover(timeout=WAIT)

    assert sorted(found, key=lambda item: item.serial) == [camera, other]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first", "second", "count"),
    [
        ({}, {24: "SN2", 32: "192.168.1.11"}, 1),
        ({}, {2: "2B:53:00:5E:00:00"}, 2),
        ({2: ""}, {2: "", 32: "192.168.1.11"}, 1),
        ({2: ""}, {2: "", 24: "SN2"}, 2),
        ({2: "", 24: ""}, {2: "", 24: ""}, 1),
        ({2: "", 24: ""}, {2: "", 24: "", 32: "192.168.1.11"}, 2),
    ],
    ids=[
        "same_mac",
        "other_mac",
        "no_mac_same_serial",
        "no_mac_other_serial",
        "no_mac_no_serial_same_ip",
        "no_mac_no_serial_other_ip",
    ],
)
async def test_discover_identity_is_mac_then_serial_then_ip(
    serve, aim, reply_fields, first, second, count
):
    responder = await serve(
        datagram(edit(reply_fields, first)), datagram(edit(reply_fields, second))
    )
    aim(responder.address)

    assert len(await discover(timeout=WAIT)) == count


@pytest.mark.asyncio
async def test_discover_collects_replies_until_timeout(
    serve, aim, examples, reply_fields
):
    other_fields = edit(reply_fields, {2: "2B:53:00:5E:00:00", 24: "SN0000000002"})
    responder = await serve(raw(examples, REPLY), late=[datagram(other_fields)])
    aim(responder.address)

    found = await discover(timeout=LATE * 6)

    assert sorted(item.serial for item in found) == ["SN0000000001", "SN0000000002"]


@pytest.mark.asyncio
async def test_discover_skips_malformed_replies(
    serve, aim, examples, reply_fields, camera
):
    junk = [
        b"hello",
        b"\x00" * 50,
        raw(examples, REPLY)[:20],
        raw(examples, REQUEST),
        datagram(edit(reply_fields, {1: "OTHER"})),
    ]
    responder = await serve(*junk, raw(examples, REPLY))
    aim(responder.address)

    assert await discover(timeout=WAIT) == [camera]


@pytest.mark.asyncio
async def test_discover_fills_ip_from_source_address(serve, aim, reply_fields):
    responder = await serve(datagram(edit(reply_fields, {32: ""})))
    aim(responder.address)

    [found] = await discover(timeout=WAIT)

    assert found.ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_discover_survives_unreachable_target(
    serve, aim, examples, camera, caplog
):
    responder = await serve(raw(examples, REPLY))
    aim(("::1", 3000), responder.address)
    caplog.set_level(logging.DEBUG, logger="sannce_aio.discovery")

    assert await discover(timeout=WAIT) == [camera]
    assert "send failed" in caplog.text


class OptionRecorder:
    def __init__(self, error=None):
        self.options = []
        self.error = error

    def setsockopt(self, level, option, value):
        if self.error is not None:
            raise self.error
        self.options.append((level, option, value))


def membership(group, interface):
    value = socket.inet_aton(group) + socket.inet_aton(interface)
    return (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, value)


def test_join_groups_joins_each_multicast_target_once_on_the_interface(aim):
    aim(("234.56.78.9", 3000), ("234.56.78.9", 4000), ("192.168.1.10", 3000))
    sock = OptionRecorder()

    assert discovery.join_groups(sock, "10.0.0.5") == {}
    assert sock.options == [membership("234.56.78.9", "10.0.0.5")]


def test_join_groups_uses_any_interface_by_default():
    sock = OptionRecorder()

    discovery.join_groups(sock)

    assert sock.options == [
        membership("234.56.78.9", "0.0.0.0"),
        membership("239.255.255.250", "0.0.0.0"),
    ]


def test_join_groups_returns_the_groups_it_cannot_join():
    error = OSError(errno.ENODEV, "No such device")

    failed = discovery.join_groups(OptionRecorder(error))

    assert failed == {"234.56.78.9": error, "239.255.255.250": error}


@pytest.mark.asyncio
async def test_discover_closes_socket_when_cancelled(serve, aim):
    if not port_free(SOURCE_PORT):
        pytest.skip("port 6001 is in use")
    responder = await serve()
    aim(responder.address)

    task = asyncio.create_task(discover(timeout=30))
    await asyncio.sleep(WAIT)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert port_free(SOURCE_PORT)


@pytest.fixture
def ask(monkeypatch):
    def set_ports(*ports):
        monkeypatch.setattr(discovery, "SEARCH_PORTS", ports)

    return set_ports


@pytest.mark.asyncio
async def test_find_camera_asks_the_address_itself(
    serve, aim, ask, examples, reply_fields
):
    responder = await serve(datagram(edit(reply_fields, {32: ""})))
    aim()
    ask(responder.address[1])

    found = await find_camera("127.0.0.1", timeout=WAIT)

    assert found is not None
    assert (found.ip, found.serial) == ("127.0.0.1", reply_fields[24])
    assert responder.requests == [raw(examples, REQUEST)]


@pytest.mark.asyncio
async def test_find_camera_also_searches_the_groups(serve, aim, ask, reply_fields):
    responder = await serve(datagram(edit(reply_fields, {32: "127.0.0.1"})))
    aim(responder.address)
    ask()

    found = await find_camera("127.0.0.1", timeout=WAIT)

    assert found is not None
    assert found.ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_find_camera_returns_at_the_first_answer(serve, aim, ask, reply_fields):
    responder = await serve(datagram(edit(reply_fields, {32: ""})))
    aim()
    ask(responder.address[1])
    loop = asyncio.get_running_loop()
    started = loop.time()

    assert await find_camera("127.0.0.1", timeout=5) is not None
    assert loop.time() - started < 1


@pytest.mark.asyncio
async def test_find_camera_ignores_other_cameras(serve, aim, ask, reply_fields):
    responder = await serve(datagram(edit(reply_fields, {32: "192.168.1.11"})))
    aim(responder.address)
    ask()

    assert await find_camera("127.0.0.1", timeout=WAIT) is None


@pytest.mark.asyncio
async def test_find_camera_skips_a_host_name(monkeypatch):
    def refuse():
        raise AssertionError("a host name needs no socket")

    monkeypatch.setattr(discovery, "_open_socket", refuse)

    assert await find_camera("camera.local") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [True, False], ids=["match", "timeout"])
async def test_find_camera_frees_port_6001(serve, aim, ask, reply_fields, answer):
    if not port_free(SOURCE_PORT):
        pytest.skip("port 6001 is in use")
    replies = [datagram(edit(reply_fields, {32: ""}))] if answer else []
    responder = await serve(*replies)
    aim()
    ask(responder.address[1])

    found = await find_camera("127.0.0.1", timeout=WAIT)

    assert (found is not None) is answer
    assert [port for _, port in responder.sources] == [SOURCE_PORT]
    assert port_free(SOURCE_PORT)


@pytest.mark.asyncio
async def test_find_camera_frees_port_6001_when_cancelled(serve, aim, ask):
    if not port_free(SOURCE_PORT):
        pytest.skip("port 6001 is in use")
    responder = await serve()
    aim()
    ask(responder.address[1])

    search = asyncio.create_task(find_camera("127.0.0.1", timeout=30))
    await asyncio.sleep(WAIT)
    assert not port_free(SOURCE_PORT)
    search.cancel()
    with pytest.raises(asyncio.CancelledError):
        await search

    assert port_free(SOURCE_PORT)
