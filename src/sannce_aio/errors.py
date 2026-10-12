class SannceError(Exception):
    pass


class ConnectError(SannceError):
    pass


class AuthError(SannceError):
    pass


class ProtocolError(SannceError):
    pass


class TalkBusyError(SannceError):
    pass
