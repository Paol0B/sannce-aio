from dataclasses import dataclass

_HEAD_FIELDS = 2  # device IP and route

_KIND_BY_NAME = {
    "MOTIONDETECT": "motion",
    "MOTIONDETECT_CAR": "vehicle",
    "VIDEOCOVER": "tamper",
    "VIDEOLOST": "video_loss",
}
# only the A4 values decoded so far (protocol.md, Event push)
_KIND_BY_VCA_RULE = {0: "line", 2: "intrusion"}
_KIND_BY_NOTIFY_SUBTYPE = {0: "video_loss", 2: "motion", 3: "tamper"}


@dataclass(frozen=True)
class Event:
    kind: str
    active: bool
    channel: int


def parse_event(fields: list[str]) -> Event | None:
    match fields[_HEAD_FIELDS:]:
        case ["INNER", "ALARM", name, *args]:
            try:
                return _alarm_event(name, args)
            except ValueError:
                return None
    return None


def _alarm_event(name: str, args: list[str]) -> Event | None:
    match name, args:
        case "VCA", [channel, state, _, rule, *_]:
            kind = _KIND_BY_VCA_RULE.get(int(rule))
        case "NOTIFY", [sub_type, channel, state, *_]:
            kind = _KIND_BY_NOTIFY_SUBTYPE.get(int(sub_type))
        case _, [channel, state, *_]:
            kind = _KIND_BY_NAME.get(name)
        case _:
            return None
    if kind is None:
        return None
    return Event(kind, int(state) != 0, int(channel))
