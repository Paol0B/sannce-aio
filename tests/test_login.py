import pytest

from sannce_aio.errors import ProtocolError
from sannce_aio.login import LoginResult, LoginStep, PlaintextLogin
from sannce_aio.protocol import parse_frame

DEVICE_IP = "192.168.1.10"
LOGON_EXAMPLES = ["logon_request", "logon_request_password_with_tab"]


def raw(examples, example_id):
    return bytes.fromhex(examples[example_id]["hex"])


class ExternalStep:
    def build_logon(self, username, password, seq):
        return b""

    def interpret_reply(self, fields):
        return LoginResult(success=False)


class StepWithoutReply:
    def build_logon(self, username, password, seq):
        return b""


@pytest.mark.parametrize("example_id", LOGON_EXAMPLES)
def test_build_logon_matches_example(examples, example_id):
    fields = examples[example_id]["fields"]
    step = PlaintextLogin(fields["payload"][0])
    built = step.build_logon(fields["username"], fields["password"], fields["sequence"])
    assert built == raw(examples, example_id)


def test_build_logon_writes_sequence_number(examples):
    expected = raw(examples, "logon_request")
    built = PlaintextLogin(DEVICE_IP).build_logon("admin", "admin123", 7)
    assert built == expected[:4] + b"\x07\x00" + expected[6:]


def test_build_logon_writes_device_ip():
    built = PlaintextLogin("10.0.0.9").build_logon("admin", "admin123", 0)
    frame, _ = parse_frame(built)
    assert frame.fields[0] == "10.0.0.9"


def test_build_logon_uses_standard_base64_alphabet():
    built = PlaintextLogin(DEVICE_IP).build_logon("admin", ">>>???", 0)
    frame, _ = parse_frame(built)
    assert frame.fields[5] == "Pj4+Pz8/"


def test_build_logon_encodes_non_ascii_credentials_as_utf8():
    step = PlaintextLogin(DEVICE_IP)
    built = step.build_logon("ut\u00e8nte", "p\u00e4ssw\u00f6rd", 0)
    frame, _ = parse_frame(built)
    assert frame.fields[4:6] == ["dXTDqG50ZQ==", "cMOkc3N3w7ZyZA=="]


def test_build_logon_accepts_credentials_of_exactly_16_bytes():
    built = PlaintextLogin(DEVICE_IP).build_logon("x" * 16, "\u00e9" * 8, 0)
    frame, _ = parse_frame(built)
    assert frame.fields[4:6] == ["eHh4eHh4eHh4eHh4eHh4eA==", "w6nDqcOpw6nDqcOpw6nDqQ=="]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("x" * 17, id="17_ascii_bytes"),
        pytest.param("\u00e9" * 9, id="9_chars_18_bytes"),
    ],
)
@pytest.mark.parametrize("field", ["username", "password"])
def test_build_logon_rejects_credential_over_16_bytes(field, value):
    credentials = {"username": "admin", "password": "admin123", field: value}
    with pytest.raises(ProtocolError) as excinfo:
        PlaintextLogin(DEVICE_IP).build_logon(
            credentials["username"], credentials["password"], 0
        )
    assert value not in str(excinfo.value)


def test_login_step_needs_both_methods():
    assert isinstance(PlaintextLogin(DEVICE_IP), LoginStep)
    assert isinstance(ExternalStep(), LoginStep)
    assert not isinstance(StepWithoutReply(), LoginStep)


def test_interpret_reply_accepts_logon_finished(examples):
    frame, _ = parse_frame(raw(examples, "logon_reply_success"))
    result = PlaintextLogin(DEVICE_IP).interpret_reply(frame.fields)
    assert result.success is True
    assert result.device == {}


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param(
            ["10.0.0.9", "IP", "INNER", "LOGON", "FINISHED"], id="other_first_field"
        ),
        pytest.param(
            [DEVICE_IP, "PROXY", "INNER", "LOGON", "FINISHED"], id="proxy_route"
        ),
        pytest.param(
            [DEVICE_IP, "IP", "INNER", "LOGON", "FINISHED", "x"], id="trailing_field"
        ),
    ],
)
def test_interpret_reply_reads_only_the_command_tokens(fields):
    assert PlaintextLogin(DEVICE_IP).interpret_reply(fields).success


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param([DEVICE_IP, "IP", "INNER", "CMDID", "7"], id="command_id"),
        pytest.param([DEVICE_IP, "IP", "INNER", "LOGON", "X"], id="other_logon_token"),
        pytest.param([DEVICE_IP, "IP", "INNER", "LOGON"], id="partial_command"),
        pytest.param([], id="empty_packet"),
    ],
)
def test_interpret_reply_is_not_success_for_other_messages(fields):
    result = PlaintextLogin(DEVICE_IP).interpret_reply(fields)
    assert result == LoginResult(success=False)


def test_interpret_reply_is_not_success_for_event_push(examples):
    frame, _ = parse_frame(raw(examples, "event_motion_start"))
    result = PlaintextLogin(DEVICE_IP).interpret_reply(frame.fields)
    assert result == LoginResult(success=False)
