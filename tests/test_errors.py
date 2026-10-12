from sannce_aio.errors import SannceError, ConnectError, AuthError, TalkBusyError, ProtocolError

def test_all_subclass_base():
    for cls in (ConnectError, AuthError, TalkBusyError, ProtocolError):
        assert issubclass(cls, SannceError)
