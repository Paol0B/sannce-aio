from .camera import CameraInfo, SannceCamera
from .discovery import DiscoveredCamera, discover
from .errors import (
    AuthError,
    ConnectError,
    ProtocolError,
    SannceError,
    TalkBusyError,
)
from .events import Event
from .http import Detection

__all__ = [
    "AuthError",
    "CameraInfo",
    "ConnectError",
    "Detection",
    "DiscoveredCamera",
    "Event",
    "ProtocolError",
    "SannceCamera",
    "SannceError",
    "TalkBusyError",
    "discover",
]
