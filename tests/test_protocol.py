import pytest

from sannce_aio.errors import ProtocolError
from sannce_aio.protocol import (
    COMMAND_MAGIC,
    DATA_MAGIC,
    TERMINATOR,
    Frame,
    build_command,
    build_data,
    decode_commands,
    encode_fields,
    pack_command,
    parse_frame,
)

DEVICE_IP = "192.168.1.10"
FRAME_EXAMPLES = ["framing_parameter_get_request", "talk_audio_frame_g711a"]


def raw(examples, example_id):
    return bytes.fromhex(examples[example_id]["hex"])


def commands_of(payload):
    frame, _ = parse_frame(pack_command(payload, 0))
    return frame.commands


def test_build_command_matches_parameter_get_request(examples):
    fields = examples["framing_parameter_get_request"]["fields"]
    built = build_command(fields["payload"], fields["sequence"])
    assert built == raw(examples, "framing_parameter_get_request")


def test_parse_frame_two_messages_in_one_read(examples):
    fields = examples["framing_two_messages_one_read"]["fields"]
    data = raw(examples, "framing_two_messages_one_read")

    first, used = parse_frame(data)
    assert first == Frame(COMMAND_MAGIC, 0, commands=[fields["message_1"]["payload"]])
    assert used == fields["message_2"]["offset"]

    second, used_second = parse_frame(data[used:])
    assert second == Frame(COMMAND_MAGIC, 1, commands=[fields["message_2"]["payload"]])
    assert used + used_second == fields["read_length"]


def test_command_examples_round_trip(examples):
    magic = COMMAND_MAGIC.to_bytes(4, "little")
    checked = 0
    for example_id, example in examples.items():
        data = bytes.fromhex(example.get("hex", ""))
        if not data.startswith(magic):
            continue
        frame, used = parse_frame(data)
        assert frame is not None, example_id
        [fields] = frame.commands or [[]]
        extra = TERMINATOR * (example.get("fields", {}).get("terminators", 1) - 1)
        assert pack_command(encode_fields(fields) + extra, frame.seq) == data[:used], example_id
        checked += 1
    assert checked


def test_empty_command_is_heartbeat(examples):
    data = raw(examples, "heartbeat_request")
    sequence = examples["heartbeat_request"]["fields"]["sequence"]
    assert build_command([], sequence) == data
    assert parse_frame(data) == (Frame(COMMAND_MAGIC, sequence, commands=[]), len(data))


def test_a_doubled_terminator_ends_one_command():
    payload = b"192.168.1.10\tPROXY\tINNER\tALARM\tVIDEOLOST\t0\t0\n\n\n\n\n\n"
    assert commands_of(payload) == [[DEVICE_IP, "PROXY", "INNER", "ALARM", "VIDEOLOST", "0", "0"]]


def test_later_commands_take_the_ip_and_route_of_the_first():
    payload = (
        b"192.168.1.10\tIP\tINNER\tUSER\tRESERVEPHONE\t2\t0\towner@example.com\t\n\n\n"
        b"INNER\tSUPER\tGETUSERNUM\t2\n\n\n"
    )
    assert commands_of(payload) == [
        [DEVICE_IP, "IP", "INNER", "USER", "RESERVEPHONE", "2", "0", "owner@example.com", ""],
        [DEVICE_IP, "IP", "INNER", "SUPER", "GETUSERNUM", "2"],
    ]


@pytest.mark.parametrize("route", ["IP", "PROXY"])
def test_a_later_command_with_its_own_ip_and_route_keeps_them(route):
    payload = (
        b"192.168.1.10\tIP\tINNER\tCMDID\t7\n\n\n"
        + f"{DEVICE_IP}\t{route}\tINNER\tLOGON\tFINISHED\n\n\n".encode()
    )
    assert commands_of(payload) == [
        [DEVICE_IP, "IP", "INNER", "CMDID", "7"],
        [DEVICE_IP, route, "INNER", "LOGON", "FINISHED"],
    ]


def test_empty_commands_are_dropped():
    payload = (
        b"192.168.1.10\tIP\tINNER\tCMDID\t7\n\n\n\n\n\n"
        b"INNER\tLOGON\tFINISHED\n\n\n\n\n\n"
    )
    assert commands_of(payload) == [
        [DEVICE_IP, "IP", "INNER", "CMDID", "7"],
        [DEVICE_IP, "IP", "INNER", "LOGON", "FINISHED"],
    ]
    assert commands_of(b"\n\n\n\n\n\n") == []


def test_an_unterminated_last_command_is_dropped():
    payload = b"192.168.1.10\tIP\tINNER\tCMDID\t7\n\n\nINNER\tLOGON"
    assert commands_of(payload) == [[DEVICE_IP, "IP", "INNER", "CMDID", "7"]]


def test_build_data_matches_talk_audio_frame(examples):
    data = raw(examples, "talk_audio_frame_g711a")
    sequence = examples["talk_audio_frame_g711a"]["fields"]["data_sequence"]
    assert build_data(data[20:], sequence, DEVICE_IP) == data


def test_parse_frame_reads_data_packet(examples):
    data = raw(examples, "talk_audio_frame_g711a")
    expected = Frame(DATA_MAGIC, 0, payload=data[20:])
    assert parse_frame(data) == (expected, len(data))


@pytest.mark.parametrize(
    "fields",
    [
        ["a", ""],
        ["", "a"],
        ["a", "", "b"],
        [DEVICE_IP, "PROXY", "CMD", "GETPARAM", "20", "0", "2"],
        ["name", "caf\u00e9"],
    ],
)
def test_fields_round_trip(fields):
    assert decode_commands(encode_fields(fields)) == [fields]


def test_encode_fields_uses_utf8():
    assert encode_fields(["caf\u00e9"]) == b"caf\xc3\xa9\n\n\n"
    assert decode_commands(b"caf\xc3\xa9\n\n\n") == [["caf\u00e9"]]


def test_field_list_rejects_raw_tab():
    with pytest.raises(ProtocolError):
        encode_fields([DEVICE_IP, "IP", "ad\tmin"])
    with pytest.raises(ProtocolError):
        build_command([DEVICE_IP, "IP", "ad\tmin"], 0)


def test_field_list_rejects_terminator_inside_value():
    for value in ("a\n\n\nb", "a\n"):
        with pytest.raises(ProtocolError):
            encode_fields(["x", value])


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        pytest.param(b"a\tb", "no terminator", id="no_terminator"),
        pytest.param(b"\xff\xfe\n\n\n", "not UTF-8", id="not_utf8"),
    ],
)
def test_decode_commands_rejects_malformed_payload(payload, reason):
    with pytest.raises(ProtocolError, match=reason):
        decode_commands(payload)


def test_sequence_is_little_endian_and_sized_per_packet_kind():
    command = build_command(["a"], 0x0102)
    assert command[4:6] == b"\x02\x01"
    assert parse_frame(command)[0].seq == 0x0102

    data = build_data(b"x", 0x01020304, DEVICE_IP)
    assert data[4:8] == b"\x04\x03\x02\x01"
    assert parse_frame(data)[0].seq == 0x01020304


def test_build_enforces_sdk_payload_limits():
    assert len(build_command(["x" * 1437], 0)) == 20 + 1440
    with pytest.raises(ProtocolError):
        build_command(["x" * 1438], 0)
    assert len(build_data(bytes(1448), 0, DEVICE_IP)) == 20 + 1448
    with pytest.raises(ProtocolError):
        build_data(bytes(1449), 0, DEVICE_IP)


@pytest.mark.parametrize("example_id", FRAME_EXAMPLES)
def test_parse_frame_waits_for_more_bytes(examples, example_id):
    data = raw(examples, example_id)
    for cut in range(len(data)):
        assert parse_frame(data[:cut]) == (None, 0)


@pytest.mark.parametrize("example_id", FRAME_EXAMPLES)
def test_parse_frame_skips_bytes_before_magic(examples, example_id):
    data = raw(examples, example_id)
    junk = b"\x00\x01\x02"
    frame, used = parse_frame(junk + data)
    assert frame == parse_frame(data)[0]
    assert used == len(junk) + len(data)


@pytest.mark.parametrize("example_id", FRAME_EXAMPLES)
def test_parse_frame_keeps_junk_while_frame_is_incomplete(examples, example_id):
    data = raw(examples, example_id)
    assert parse_frame(b"\x00\x01\x02" + data[:-1]) == (None, 0)


@pytest.mark.parametrize("total", [19, 2049])
def test_parse_frame_skips_header_with_bad_length(examples, total):
    data = raw(examples, "framing_parameter_get_request")
    bad = COMMAND_MAGIC.to_bytes(4, "little") + bytes(2) + total.to_bytes(2, "little")
    bad += bytes(12)
    frame, used = parse_frame(bad + data)
    assert frame == parse_frame(data)[0]
    assert used == len(bad) + len(data)


def test_parse_frame_ignores_zero_bytes_and_payload_length(examples):
    data = raw(examples, "framing_parameter_get_request")
    noisy = data[:8] + b"\xff" * 10 + b"\x01\x00" + data[20:]
    assert parse_frame(noisy) == parse_frame(data)
