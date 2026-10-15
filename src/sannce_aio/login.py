import base64
import hashlib
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .errors import AuthError, ProtocolError

_ROUTE = "IP"
_NO_SESSION_TOKEN = ""
_CHARSET = "UTF-8"
_MAX_CREDENTIAL_BYTES = 16


@dataclass(frozen=True)
class LoginResult:
    success: bool
    device: dict[str, str] = field(default_factory=dict)
    next_fields: list[str] | None = None


@runtime_checkable
class LoginStep(Protocol):
    def first_fields(self, username: str, password: str) -> list[str]: ...

    def interpret_reply(self, fields: list[str]) -> LoginResult: ...


def _credential_field(label: str, value: str) -> str:
    raw = value.encode(_CHARSET)
    if len(raw) > _MAX_CREDENTIAL_BYTES:
        raise ProtocolError(
            f"{label} is {len(raw)} bytes, the limit is {_MAX_CREDENTIAL_BYTES}"
        )
    return base64.b64encode(raw).decode("ascii")


_CLIENT_TYPE = "3"
_BASE64_FLAGS = str(0x2FFFFFFF)
_PASSWORD_LOGIN = "1"
_MD5_FLAGS = "0"
_SALT_BYTES = 8
_SALT_INDEX = 2
# reason 3 asks for the salted MD5 login; any other reason refuses the credentials
# (camera web player /external/noplugin-master/h5player.js.gz, protocol.md, Login)
_NEEDS_MD5 = "3"


class SaltedLogin(LoginStep):
    def __init__(self, device_ip: str) -> None:
        self._device_ip = device_ip
        self._username = ""
        self._password = ""
        self._salted = False

    def first_fields(self, username: str, password: str) -> list[str]:
        self._username = username
        self._password = password
        self._salted = False
        return self._logon(
            _credential_field("user name", username),
            _credential_field("password", password),
            _BASE64_FLAGS,
        )

    def interpret_reply(self, fields: list[str]) -> LoginResult:
        match fields:
            case [_, _, "INNER", "LOGON", "FINISHED", *_]:
                return LoginResult(success=True)
            case [_, _, "INNER", "USER", "LOGONFAILED", reason, *rest]:
                if reason == _NEEDS_MD5 and not self._salted and len(rest) > _SALT_INDEX:
                    self._salted = True
                    return LoginResult(
                        success=False, next_fields=self._salted_logon(rest[_SALT_INDEX])
                    )
                raise AuthError(f"the camera refused the login (reason {reason})")
        return LoginResult(success=False)

    def _salted_logon(self, salt_text: str) -> list[str]:
        try:
            salt = base64.b64decode(salt_text, validate=True)[:_SALT_BYTES]
        except ValueError as exc:
            raise AuthError(f"the login salt is not base64: {salt_text!r}") from exc
        return self._logon(
            _salted_md5(self._username, salt),
            _salted_md5(self._password, salt),
            _MD5_FLAGS,
        )

    def _logon(self, user: str, password: str, flags: str) -> list[str]:
        return [
            self._device_ip,
            _ROUTE,
            "USER",
            "LOGON",
            user,
            password,
            _NO_SESSION_TOKEN,
            _CLIENT_TYPE,
            _CHARSET,
            flags,
            _PASSWORD_LOGIN,
        ]


def _salted_md5(value: str, salt: bytes) -> str:
    digest = hashlib.md5(value.encode(_CHARSET) + salt, usedforsecurity=False).digest()
    return base64.b64encode(digest).decode("ascii")
