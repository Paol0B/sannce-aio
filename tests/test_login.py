import base64
import hashlib

import pytest

from sannce_aio.errors import AuthError, ProtocolError
from sannce_aio.login import LoginResult, LoginStep, SaltedLogin
from sannce_aio.protocol import parse_frame

DEVICE_IP = "192.168.1.10"
SALT_B64 = "vslPOg8PDw8="
SALT = base64.b64decode(SALT_B64)[:8]


def md5_b64(value, salt=SALT):
    return base64.b64encode(hashlib.md5(value.encode() + salt).digest()).decode()


def fields_of(examples, example_id):
    frame, _ = parse_frame(bytes.fromhex(examples[example_id]["hex"]))
    [fields] = frame.commands
    return fields


def refusal(reason, salt=SALT_B64, count="0"):
    return [DEVICE_IP, "IP", "INNER", "USER", "LOGONFAILED", reason, "1", "1", salt, count, "0"]


def test_salted_login_starts_with_the_web_player_base64_logon():
    fields = SaltedLogin(DEVICE_IP).first_fields("Admin", "Pass*word1")

    assert fields == [
        DEVICE_IP, "IP", "USER", "LOGON",
        "QWRtaW4=", "UGFzcyp3b3JkMQ==",
        "", "3", "UTF-8", "805306367", "1",
    ]


def test_salted_login_answers_reason_3_with_the_md5_logon():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("Admin", "secret")

    result = step.interpret_reply(refusal("3"))

    assert result.success is False
    assert result.next_fields == [
        DEVICE_IP, "IP", "USER", "LOGON",
        md5_b64("Admin"), md5_b64("secret"),
        "", "3", "UTF-8", "0", "1",
    ]


def test_salted_login_uses_only_the_first_8_salt_bytes():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")
    long_salt = base64.b64encode(bytes(range(12))).decode()

    result = step.interpret_reply(refusal("3", salt=long_salt))

    assert result.next_fields[5] == md5_b64("pw", bytes(range(8)))


def test_salted_login_finishes_on_logon_finished():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")

    assert step.interpret_reply([DEVICE_IP, "IP", "INNER", "LOGON", "FINISHED"]).success


def test_salted_login_ignores_channel_data_finished():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")

    result = step.interpret_reply([DEVICE_IP, "IP", "INNER", "LOGON", "CHANNELDATA", "FINISHED"])

    assert result == LoginResult(success=False)


@pytest.mark.parametrize("reason", ["2", "4", "7"])
def test_salted_login_refusal_raises_auth_error(reason):
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")

    with pytest.raises(AuthError, match=f"reason {reason}"):
        step.interpret_reply(refusal(reason))


def test_a_second_reason_3_raises_auth_error():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")
    step.interpret_reply(refusal("3"))

    with pytest.raises(AuthError):
        step.interpret_reply(refusal("3"))


def test_first_fields_resets_the_md5_phase():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")
    step.interpret_reply(refusal("3"))

    step.first_fields("admin", "pw")

    assert step.interpret_reply(refusal("3")).next_fields is not None


def test_a_salt_that_is_not_base64_raises_auth_error():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")

    with pytest.raises(AuthError, match="salt"):
        step.interpret_reply(refusal("3", salt="***"))


def test_a_refusal_without_a_salt_raises_auth_error():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")

    with pytest.raises(AuthError):
        step.interpret_reply([DEVICE_IP, "IP", "INNER", "USER", "LOGONFAILED", "3"])


def test_salted_login_rejects_oversized_credentials():
    with pytest.raises(ProtocolError, match="password is 17 bytes"):
        SaltedLogin(DEVICE_IP).first_fields("admin", "x" * 17)


def test_unrelated_replies_do_not_finish_the_login():
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "pw")

    assert step.interpret_reply([DEVICE_IP, "IP", "INNER", "CMDID", "7"]) == LoginResult(success=False)


def test_salted_login_is_a_login_step():
    assert isinstance(SaltedLogin(DEVICE_IP), LoginStep)


def test_login_messages_match_the_examples(examples):
    request = examples["logon_request"]["fields"]
    first = fields_of(examples, "logon_request")
    step = SaltedLogin(first[0])

    assert step.first_fields(request["username"], request["password"]) == first
    result = step.interpret_reply(fields_of(examples, "logon_reply_needs_md5"))
    assert result.next_fields == fields_of(examples, "logon_md5_request")


def test_the_refused_example_raises_auth_error(examples):
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "admin123")

    with pytest.raises(AuthError, match="reason 2"):
        step.interpret_reply(fields_of(examples, "logon_reply_refused"))


def test_the_success_example_finishes_the_login(examples):
    step = SaltedLogin(DEVICE_IP)
    step.first_fields("admin", "admin123")

    assert step.interpret_reply(fields_of(examples, "logon_reply_success")).success
