import base64
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .errors import ProtocolError
from .protocol import build_command

_ROUTE = "IP"
_NO_SESSION_TOKEN = ""
_SDK_STATE = "0"
_CHARSET = "UTF-8"
_LOGON_CONSTANT = str(0x2FFFFFFF)
_NEW_CLIENT_SUPPORT = "1"
_NO_SECOND_CREDENTIAL = ""
_MAX_CREDENTIAL_BYTES = 16


@dataclass(frozen=True)
class LoginResult:
    success: bool
    device: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class LoginStep(Protocol):
    def build_logon(self, username: str, password: str, seq: int) -> bytes: ...

    def interpret_reply(self, fields: list[str]) -> LoginResult: ...


# first USER LOGON phase only; the second phase is deferred (protocol.md, Login)
class PlaintextLogin(LoginStep):
    def __init__(self, device_ip: str) -> None:
        self._device_ip = device_ip

    def build_logon(self, username: str, password: str, seq: int) -> bytes:
        return build_command(
            [
                self._device_ip,
                _ROUTE,
                "USER",
                "LOGON",
                _credential_field("user name", username),
                _credential_field("password", password),
                _NO_SESSION_TOKEN,
                _SDK_STATE,
                _CHARSET,
                _LOGON_CONSTANT,
                _NEW_CLIENT_SUPPORT,
                _NO_SECOND_CREDENTIAL,
            ],
            seq,
        )

    def interpret_reply(self, fields: list[str]) -> LoginResult:
        # failure replies are undocumented (protocol.md, Open questions),
        # so every other reply only means "not finished"
        match fields:
            case [_, _, "INNER", "LOGON", "FINISHED", *_]:
                return LoginResult(success=True)
        return LoginResult(success=False)


def _credential_field(label: str, value: str) -> str:
    raw = value.encode(_CHARSET)
    if len(raw) > _MAX_CREDENTIAL_BYTES:
        raise ProtocolError(
            f"{label} is {len(raw)} bytes, the limit is {_MAX_CREDENTIAL_BYTES}"
        )
    return base64.b64encode(raw).decode("ascii")
