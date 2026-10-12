import dataclasses

import pytest

from sannce_aio.events import Event, parse_event
from sannce_aio.protocol import parse_frame

DEVICE_IP = "192.168.1.10"
VCA_TAIL = ["0", "0", "0:0:0:0", "0", "0", "0,0,0,0,0,0,0", "0", "0", "0", "", ""]


def fields_of(examples, example_id):
    frame, _ = parse_frame(bytes.fromhex(examples[example_id]["hex"]))
    return frame.fields


def alarm(name, *args):
    return [DEVICE_IP, "IP", "INNER", "ALARM", name, *args]


def vca(rule, channel="0", state="1"):
    return alarm("VCA", channel, state, "0", rule, *VCA_TAIL)


def notify(sub_type, channel, state):
    return alarm("NOTIFY", sub_type, channel, state, "0", "0", "0", "0", "", "")


@pytest.mark.parametrize(
    ("example_id", "event"),
    [
        ("event_motion_start", Event("motion", True, 0)),
        ("event_motion_stop", Event("motion", False, 0)),
        ("event_smart_vehicle", Event("vehicle", True, 0)),
        ("event_vca_intrusion", Event("intrusion", True, 0)),
        ("event_video_cover", Event("tamper", True, 0)),
    ],
)
def test_example_maps_to_event(examples, example_id, event):
    assert parse_event(fields_of(examples, example_id)) == event


def test_person_example_reads_as_motion(examples):
    assert parse_event(fields_of(examples, "event_smart_person")) == Event(
        "motion", True, 0
    )


def test_builders_match_examples(examples):
    assert alarm("MOTIONDETECT", "0", "1") == fields_of(examples, "event_motion_start")
    assert alarm("VIDEOCOVER", "0", "1") == fields_of(examples, "event_video_cover")
    assert vca("2") == fields_of(examples, "event_vca_intrusion")


@pytest.mark.parametrize(
    ("fields", "event"),
    [
        pytest.param(
            alarm("VIDEOLOST", "0", "1"), Event("video_loss", True, 0), id="lost_start"
        ),
        pytest.param(
            alarm("VIDEOLOST", "0", "0"), Event("video_loss", False, 0), id="lost_stop"
        ),
        pytest.param(
            alarm("MOTIONDETECT_CAR", "0", "0"),
            Event("vehicle", False, 0),
            id="vehicle_stop",
        ),
        pytest.param(
            alarm("VIDEOCOVER", "0", "0"), Event("tamper", False, 0), id="cover_stop"
        ),
        pytest.param(
            alarm("MOTIONDETECT", "3", "1"), Event("motion", True, 3), id="channel_3"
        ),
        pytest.param(
            alarm("MOTIONDETECT", "0", "2"),
            Event("motion", True, 0),
            id="nonzero_state_is_active",
        ),
        pytest.param(
            alarm("MOTIONDETECT", "0", "1", "person"),
            Event("motion", True, 0),
            id="third_field_ignored",
        ),
        pytest.param(
            ["any", "PROXY", "INNER", "ALARM", "MOTIONDETECT", "0", "1"],
            Event("motion", True, 0),
            id="first_field_and_route_ignored",
        ),
        pytest.param(vca("0"), Event("line", True, 0), id="vca_line"),
        pytest.param(
            vca("2", channel="1", state="0"),
            Event("intrusion", False, 1),
            id="vca_intrusion_stop",
        ),
        pytest.param(
            notify("0", "1", "1"), Event("video_loss", True, 1), id="notify_video_loss"
        ),
        pytest.param(
            notify("2", "3", "0"), Event("motion", False, 3), id="notify_motion_stop"
        ),
        pytest.param(
            notify("3", "0", "1"), Event("tamper", True, 0), id="notify_video_cover"
        ),
    ],
)
def test_message_maps_to_event(fields, event):
    assert parse_event(fields) == event


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param([], id="heartbeat"),
        pytest.param(alarm("NOSUCHKIND", "0", "1"), id="unknown_alarm"),
        pytest.param(alarm("INPORT", "0", "1", "2147483647", ""), id="alarm_input"),
        pytest.param(vca("1"), id="vca_unmapped_rule"),
        pytest.param(notify("1", "0", "1"), id="notify_exception"),
        pytest.param(notify("5", "0", "1"), id="notify_alarm_input"),
        pytest.param(
            [DEVICE_IP, "IP", "INNER", "CMD", "ALARM", "ALERT", "0", "0:0:0:0"],
            id="smart_alert",
        ),
        pytest.param(
            [DEVICE_IP, "IP", "INNER", "ONVIF", "VCAALARM", "0"], id="onvif_vca"
        ),
        pytest.param(
            [DEVICE_IP, "IP", "CMD", "ALARM", "MOTIONDETECT", "0", "1"], id="not_inner"
        ),
        pytest.param(
            [DEVICE_IP, "IP", "INNER", "STATUS", "MOTIONDETECT", "0", "1"],
            id="not_alarm",
        ),
        pytest.param(alarm("MOTIONDETECT"), id="no_channel"),
        pytest.param(alarm("MOTIONDETECT", "0"), id="no_state"),
        pytest.param(alarm("MOTIONDETECT", "x", "1"), id="channel_not_a_number"),
        pytest.param(alarm("MOTIONDETECT", "0", "on"), id="state_not_a_number"),
        pytest.param(alarm("VCA", "0", "1", "0"), id="vca_without_rule"),
        pytest.param(alarm("VCA", "0", "1", "0", "x"), id="vca_rule_not_a_number"),
        pytest.param(alarm("NOTIFY", "2", "0"), id="notify_without_state"),
    ],
)
def test_unmapped_message_is_none(fields):
    assert parse_event(fields) is None


def test_logon_reply_is_not_an_event(examples):
    assert parse_event(fields_of(examples, "logon_reply_success")) is None


def test_event_is_frozen():
    event = Event("motion", True, 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.active = False
